// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"ranet3.com/pkgs/ranet3/internal/bubble"
	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/egress/egresstest"
	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/logtest"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/schema"
)

// fakeBackend stands in for a kernel. Everything above the backend seam is
// portable, so the diff, the readiness rule and the withdrawal are all
// reachable without a packet filter to write into.
type fakeBackend struct {
	mu   sync.Mutex
	held []Installed
	// decoys is rules another writer put in the chains under the translator's
	// comments that do something else, which a listing reads back after held
	decoys    []Installed
	conflicts []string
	applied   int
	withdrawn int
	// failApply makes a host that will not take the rules, which is the
	// condition an exit has to refuse to advertise over, failStop one that will
	// not take a stopped translator's alone, and loseStop one that takes them
	// and answers with an error, as one whose acknowledgments overflow the
	// socket does
	failApply, failStop, loseStop bool
	// unsentStop makes a stop's write fail before it is sent, as a failed read
	// of the table or a label probe that answers neither way makes it
	unsentStop bool
	// overflowStop makes a host that refuses a stopped translator's rules and
	// whose acknowledgments of the refusal overflow the socket. Its answer is
	// then no refusal.
	overflowStop bool
	// failWithdraw makes a host that will not let its chains go
	failWithdraw bool
	// flows is added to each counted rule's counter on every readback, so a
	// test can tell a rule the pass rewrote from one it left alone.
	flows uint64
	// changed stands for another writer's changes to its chains and missed
	// for notifications lost, nil for none
	changed, missed chan struct{}
	// failRules makes a host whose rules cannot be listed, and failReadback one
	// whose rules cannot be listed right after an apply, which readback is due
	// for
	failRules, failReadback, readback bool
	// faults is how a family's chains or objects differ from what Apply writes.
	// An apply clears it unless stuck holds it, or remake names the family and
	// the apply does not delete the stale objects first.
	faults map[uint8]string
	remake map[uint8]bool
	stuck  bool
	// refusing makes each family's fault of faults its refusedOn too, as a
	// set another writer holds that the write must delete is
	refusing bool
	// dormant is the fault of a dormant flag another writer set on the table,
	// and refilled a family's set or object that a stopped rule uses read back
	// otherwise than written. A taken apply clears both unless stuck holds them.
	dormant  string
	refilled map[uint8]string
	// log records each listing, apply and withdrawal in order, beside what record adds
	log []string
	// reads counts the debug reads, and failRead makes them fail
	reads    int
	failRead bool
	// failConflicts makes a host whose other chains cannot be listed
	failConflicts bool
	// seen, where set, is read as a withdrawal begins and logged ahead of it
	seen func() string
}

// see logs what seen reads, outside f.mu, where seen is set
func (f *fakeBackend) see() {
	if f.seen != nil {
		f.record(f.seen())
	}
}

func (f *fakeBackend) record(entry string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log = append(f.log, entry)
}

func (f *fakeBackend) entries() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.log)
}

// Rules reads each family's rules against desired by comment, as the kernel's
// readback reads each line by its comment and its expressions, a decoy among
// them, and names a listing that differs, a refilled set and the dormant flag
// as the kernel's readback does
func (f *fakeBackend) Rules(desired []Rule) (map[uint8]chainReadback, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log = append(f.log, "rules")
	readback := f.readback
	f.readback = false
	if f.failRules || f.failReadback && readback {
		return nil, errors.New("no")
	}
	out := f.holding()
	for family, read := range out {
		wanted := slices.DeleteFunc(slices.Clone(desired), func(rule Rule) bool { return rule.Family != family })
		same := slices.EqualFunc(read.rules, wanted, func(held Installed, rule Rule) bool { return held.Spec == rule.String() })
		var lines string
		if !same {
			lines = fakeLines
		}
		read.fault = cmp.Or(f.dormant, read.fault, f.refilled[family], lines)
		read.dormant, read.misplaced = f.dormant, cmp.Or(lines, f.refilled[family])
		out[family] = read
	}
	return out, nil
}

// fakeLines is the fault of chains a listing reads back otherwise than desired
// writes them
const fakeLines = "its chains read back other than they were written"

// Read is Rules for a debug read, which logs no listing and leaves a readback
// an apply made due as it is
func (f *fakeBackend) Read([]Rule) (map[uint8]chainReadback, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	if f.failRead {
		return nil, errors.New("no")
	}
	return f.holding(), nil
}

// holding is the host's chains as a listing reads them, under f.mu: each rule
// of held, and the decoys after them
func (f *fakeBackend) holding() map[uint8]chainReadback {
	out := map[uint8]chainReadback{}
	for _, family := range []uint8{egress.FamilyIPv4, egress.FamilyIPv6} {
		read := chainReadback{fault: f.faults[family], remake: f.faults[family] != "" && f.remake[family]}
		if f.refusing {
			read.refusedOn = f.faults[family]
		}
		for _, rule := range f.held {
			if rule.Family == family {
				if rule.Counted {
					rule.Packets += f.flows
				}
				read.rules = append(read.rules, rule)
			}
		}
		for _, rule := range f.decoys {
			if rule.Family == family {
				read.rules = append(read.rules, rule)
			}
		}
		out[family] = read
	}
	return out
}

// Apply stores the rules grouped by family, as the nftables backend reads them
// back: each rule placed in its family. A fake that kept the order it was
// handed would hide a desired list ordered any other way, which never compares
// equal to its own readback. It logs remake for an apply that deletes stale
// objects first, and reads seen first for a stopped translator's rules.
func (f *fakeBackend) Apply(rules []Rule, remake bool) error {
	stopping := slices.ContainsFunc(rules, func(rule Rule) bool { return rule.Stopped != Running })
	if stopping {
		f.see()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	entry := "apply"
	if remake {
		entry = "remake"
	}
	f.log = append(f.log, entry)
	if stopping && f.unsentStop {
		return errUnsent
	}
	if stopping && f.overflowStop {
		return errOverflow
	}
	if f.failApply || stopping && f.failStop {
		return errRefused
	}
	f.applied++
	f.readback = true
	for family := range f.faults {
		if !f.stuck && (!f.remake[family] || remake) {
			delete(f.faults, family)
		}
	}
	f.held, f.decoys = placed(rules), nil
	if !f.stuck {
		f.dormant, f.refilled = "", nil
	}
	if stopping && f.loseStop {
		return errLost
	}
	return nil
}

// placed is rules as a listing reads them back, each placed in its family
func placed(rules []Rule) []Installed {
	var out []Installed
	for _, family := range []uint8{egress.FamilyIPv4, egress.FamilyIPv6} {
		for _, rule := range rules {
			if rule.Family == family {
				out = append(out, Installed{Spec: rule.String(), Family: family, Chain: rule.chain(), Counted: rule.kind().counted()})
			}
		}
	}
	return out
}

func (f *fakeBackend) Conflicts() ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failConflicts {
		return nil, errors.New("no")
	}
	return slices.Clone(f.conflicts), nil
}

func (f *fakeBackend) Withdraw() error {
	f.see()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log = append(f.log, "withdraw")
	if f.failWithdraw {
		return errors.New("no")
	}
	f.withdrawn++
	f.held = nil
	return nil
}

func (f *fakeBackend) Close() error { return nil }

func (f *fakeBackend) Changed() <-chan struct{} { return f.changed }

func (f *fakeBackend) Missed() <-chan struct{} { return f.missed }

func (f *fakeBackend) where() string { return "a fake host" }

func (f *fakeBackend) unlabelled() string { return "" }

// errRefused is the fake host's refusal of a write, errUnsent a write that
// failed before it was sent, and errLost the answers to a write it committed
// lost. errOverflow is the acknowledgments of a refusal lost. Each reads "no",
// as the tests' errors read it.
var errRefused, errUnsent, errLost, errOverflow = errors.New("no"), errors.New("no"), errors.New("no"), errors.New("no")

func (f *fakeBackend) refused(err error) bool { return errors.Is(err, errRefused) }

func (f *fakeBackend) written(rules []Rule) []Rule { return rules }

func (f *fakeBackend) specs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.held))
	for _, rule := range f.held {
		out = append(out, rule.Spec)
	}
	return out
}

// translations is specs without the timeout rules, the limit's chain's, the
// drops and the refusals, for a test of what each rule translates to.
// TestClassesAreWrittenLongestFromFirst holds where the others go.
func (f *fakeBackend) translations() []string {
	return slices.DeleteFunc(f.specs(), func(spec string) bool {
		return strings.Contains(spec, " timeouts ") || strings.Contains(spec, " limit ") || dropsRefusesOrPasses(spec)
	})
}

// dropsRefusesOrPasses is whether the rule spelled spec ends in a drop, a
// refusal or a pass: an ICMP drop, a refusal of a protocol or its pass under
// none, or a rule taking what no flow is tracked for
func dropsRefusesOrPasses(spec string) bool {
	return strings.HasSuffix(spec, " dropped") || strings.HasSuffix(spec, " refused") || strings.HasSuffix(spec, " passed")
}

// translator builds one around a fake backend, bypassing New so that a test
// does not need a packet filter to reach the portable half.
func translator(t *testing.T, cfg egress.Egress, rt Runtime, be backend) *Translator {
	t.Helper()
	if rt.Forwarding == nil {
		rt.Forwarding = func() (bool, bool) { return true, true }
	}
	if rt.Interface == "" {
		rt.Interface = "ranet0"
	}
	if rt.Lookup == nil {
		rt.Lookup = holdsEvery
	}
	if rt.Sysctl == nil {
		rt.Sysctl = readsNothing
	}
	if rt.Ready == nil {
		rt.Ready = unheard.Ready
	}
	if rt.Republish == nil {
		rt.Republish = unheard.Republish
	}
	return newTranslator(cfg, meshGone(rt), be)
}

// unheard is the hooks of a test that reads no report through them
var unheard = egress.Hooks{Ready: func(bool, bool, bool) {}, Republish: func() {}}

// meshGone is rt with each read of the mesh it leaves nil reading a mesh
// that has closed, whose device went with it
func meshGone(rt Runtime) Runtime {
	if rt.Done == nil {
		rt.Done = egresstest.Closed
	}
	if rt.Present == nil {
		rt.Present = func() (bool, error) { return false, nil }
	}
	return rt
}

// endedAtOnce is tr's Run under a context that has already ended, which runs
// no turn of the loop, so what it does is the shutdown's alone
func endedAtOnce(tr *Translator) error {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return tr.Run(ctx)
}

// stopTurn is a turn of tr's loop while it is down, which answers the stop's
// error
func stopTurn(tr *Translator) error {
	_, err := tr.stop()
	return err
}

// readsNothing is a Runtime.Sysctl that reads no setting, as on a host whose
// conntrack has not loaded
func readsNothing(string) string { return "" }

// holdsEvery answers a pass's lookups as a host holding every address a class
// translates to does: a lookup from no source finds its local route. A lookup
// from a member fails, since a runtime it answers for holds none
func holdsEvery(lookups []Lookup) ([]Answer, error) {
	answers := make([]Answer, len(lookups))
	for i, lookup := range lookups {
		answers[i] = Answer{Route: Route{Type: "local", Hops: []Hop{{Device: "lo"}}}}
		if lookup.Source.IsValid() {
			answers[i] = Answer{Err: errors.New("a lookup from " + lookup.Source.String() + ", a member of a runtime holding none")}
		}
	}
	return answers, nil
}

func prefixes(t *testing.T, raw ...string) []schema.Prefix {
	t.Helper()
	out := make([]schema.Prefix, 0, len(raw))
	for _, one := range raw {
		prefix, err := schema.ParsePrefix(one)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, prefix)
	}
	return out
}

// plain is the file's spelling of a prefix list as the announcement carries it.
func plain(entries []schema.Prefix) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(entries))
	for _, entry := range entries {
		out = append(out, entry.Prefix)
	}
	return out
}

// An exit node translates the mesh's traffic on the way out and never on the
// way through: a packet that arrives on the mesh device and leaves by it again
// is somebody else's transit, and rewriting its source would put this node's
// address on a packet it is only relaying.
func TestRulesMatchBothInterfacesSoTransitIsNotTranslated(t *testing.T) {
	cfg := egress.Egress{Advertise: prefixes(t, "0.0.0.0/0", "::/0")}
	be := &fakeBackend{}
	tr := translator(t, cfg, Runtime{}, be)
	if err := tr.reconcile(); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"out via ranet0 ipv4 masquerade",
		"out via ranet0 ipv6 masquerade",
	}
	if got := be.translations(); !slices.Equal(got, want) {
		t.Errorf("installed %q, want %q", got, want)
	}
}

// A class from every source to an address is used unchanged, which is how a
// deployment that owns an address block pins the address return traffic comes
// back to.
func TestConfiguredSourceReplacesTheHostsOwnChoice(t *testing.T) {
	cfg := egress.Egress{
		Translate: []egress.Class{{From: schema.MustPrefix("0.0.0.0/0"), To: egress.Translation{Addr: netip.MustParseAddr("198.51.100.7")}}},
		Advertise: prefixes(t, "0.0.0.0/0"),
	}
	be := &fakeBackend{}
	if err := translator(t, cfg, Runtime{}, be).reconcile(); err != nil {
		t.Fatal(err)
	}
	want := []string{"out via ranet0 ipv4 source 198.51.100.7"}
	if got := be.translations(); !slices.Equal(got, want) {
		t.Errorf("installed %q, want %q", got, want)
	}
}

// Each family's rules open, in IPv4, with the drops of Source Quench and
// Information Request and Reply out of the mesh and into it. The pass of the
// sources whose class is none follows, then from every source the rule taking
// what no flow is tracked for, the refusals of DCCP and UDP-Lite and the
// limit. Each class's translation rules come together, the longest From first
// since the first translation ends the chain.
// A class that translates attaches the exit's timeouts first, by a rule for
// UDP, for TCP and for the family's ICMP, keyed as its translation is, and a
// class of none binds its sources to themselves alone, so its flows keep the
// host's timeouts. A family no class covers whole ends in the rules of auto.
// Each of this node's own mesh addresses but the link-local one takes the class
// it falls in, in rules after those a leaf's packet meets.
func TestClassesAreWrittenLongestFromFirst(t *testing.T) {
	cfg := egress.Egress{
		Advertise: prefixes(t, "0.0.0.0/0", "::/0"),
		Translate: []egress.Class{
			{From: schema.MustPrefix("192.0.2.0/24"), To: egress.Translation{None: true}},
			{From: schema.MustPrefix("0.0.0.0/0"), To: egress.Translation{Addr: netip.MustParseAddr("198.51.100.7")}},
			{From: schema.MustPrefix("192.0.2.128/25"), To: egress.Translation{Auto: true}},
			{From: schema.MustPrefix("3fff::/20"), To: egress.Translation{Addr: netip.MustParseAddr("2001:db8::7")}},
		},
	}
	rt := Runtime{MeshAddresses: []netip.Addr{
		netip.MustParseAddr("192.0.2.200"), netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("3fff::1"), netip.MustParseAddr("fe80::1"),
	}}
	be := &fakeBackend{}
	if err := translator(t, cfg, rt, be).reconcile(); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"out via ranet0 ipv4 icmp source quench dropped",
		"out via ranet0 ipv4 icmp information dropped",
		"in via ranet0 ipv4 icmp source quench dropped",
		"in via ranet0 ipv4 icmp information dropped",
		"out via ranet0 ipv4 untranslated passed",
		"out via ranet0 ipv4 untracked dropped",
		"out via ranet0 ipv4 dccp refused",
		"out via ranet0 ipv4 udplite refused",
		"out via ranet0 ipv4 limit 4096",
		"out via ranet0 ipv4 from 192.0.2.128/25 timeouts udp",
		"out via ranet0 ipv4 from 192.0.2.128/25 timeouts tcp",
		"out via ranet0 ipv4 from 192.0.2.128/25 timeouts icmp",
		"out via ranet0 ipv4 from 192.0.2.128/25 masquerade",
		"out via ranet0 ipv4 from 192.0.2.0/24 untranslated",
		"out via ranet0 ipv4 timeouts udp",
		"out via ranet0 ipv4 timeouts tcp",
		"out via ranet0 ipv4 timeouts icmp",
		"out via ranet0 ipv4 source 198.51.100.7",
		"local via ranet0 ipv4 from 192.0.2.1/32 untranslated",
		"local via ranet0 ipv4 from 192.0.2.200/32 timeouts udp",
		"local via ranet0 ipv4 from 192.0.2.200/32 timeouts tcp",
		"local via ranet0 ipv4 from 192.0.2.200/32 timeouts icmp",
		"local via ranet0 ipv4 from 192.0.2.200/32 masquerade",
		"out via ranet0 ipv6 untracked dropped",
		"out via ranet0 ipv6 dccp refused",
		"out via ranet0 ipv6 udplite refused",
		"out via ranet0 ipv6 limit 4096",
		"out via ranet0 ipv6 from 3fff::/20 timeouts udp",
		"out via ranet0 ipv6 from 3fff::/20 timeouts tcp",
		"out via ranet0 ipv6 from 3fff::/20 timeouts icmpv6",
		"out via ranet0 ipv6 from 3fff::/20 source 2001:db8::7",
		"out via ranet0 ipv6 timeouts udp",
		"out via ranet0 ipv6 timeouts tcp",
		"out via ranet0 ipv6 timeouts icmpv6",
		"out via ranet0 ipv6 masquerade",
		"local via ranet0 ipv6 from 3fff::1/128 timeouts udp",
		"local via ranet0 ipv6 from 3fff::1/128 timeouts tcp",
		"local via ranet0 ipv6 from 3fff::1/128 timeouts icmpv6",
		"local via ranet0 ipv6 from 3fff::1/128 source 2001:db8::7",
	}
	if got := be.specs(); !slices.Equal(got, want) {
		t.Errorf("installed %q, want %q", got, want)
	}
}

// The limit counts the flows of a class that translates alone. The pass takes
// the sources of a class of none ahead of every screen, less those of the
// classes that translate inside it, one inside another that translates inside
// it among them, which count their flows at the limit from every source.
func TestOnlyTranslatedClassesCountAgainstTheLimit(t *testing.T) {
	cfg := egress.Egress{
		Advertise: prefixes(t, "0.0.0.0/0"),
		Translate: []egress.Class{
			{From: schema.MustPrefix("192.0.2.0/24"), To: egress.Translation{None: true}},
			{From: schema.MustPrefix("192.0.2.0/26"), To: egress.Translation{Auto: true}},
			{From: schema.MustPrefix("192.0.2.128/25"), To: egress.Translation{Auto: true}},
			{From: schema.MustPrefix("192.0.2.192/26"), To: egress.Translation{Addr: netip.MustParseAddr("203.0.113.8")}},
			{From: schema.MustPrefix("198.51.100.0/25"), To: egress.Translation{Addr: netip.MustParseAddr("203.0.113.7")}},
		},
	}
	be := &fakeBackend{}
	tr := translator(t, cfg, Runtime{}, be)
	if err := tr.reconcile(); err != nil {
		t.Fatal(err)
	}
	for _, rule := range tr.desired() {
		if want := PrefixSet("192.0.2.64/26"); rule.Passes && rule.Sources != want {
			t.Errorf("the pass %s takes the sources %q, want %q", rule, rule.Sources, want)
		}
	}
	want := map[string][]string{
		LimitChain: {
			"out via ranet0 ipv4 untranslated passed",
			"out via ranet0 ipv4 untracked dropped",
			"out via ranet0 ipv4 dccp refused",
			"out via ranet0 ipv4 udplite refused",
			"out via ranet0 ipv4 limit 4096",
		},
	}
	got := map[string][]string{}
	for _, rule := range be.held {
		if rule.Chain != ChainName && !strings.Contains(rule.Spec, " icmp ") {
			got[rule.Chain] = append(got[rule.Chain], rule.Spec)
		}
	}
	if !maps.EqualFunc(got, want, slices.Equal) {
		t.Errorf("installed the limit's chain %q, want %q", got, want)
	}
}

// Each family's limit is the share cap.egress flows_per_source names, the
// default where it names none, and Status reports it as the limit in force
func TestEachFamilysLimitIsTheShareTheCapabilityNames(t *testing.T) {
	for name, one := range map[string]struct {
		named uint32
		want  int
	}{
		"named":     {300, 300},
		"left out":  {0, egress.DefaultFlowsPerSource},
		"the least": {1, 1},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := egress.Egress{Advertise: prefixes(t, "0.0.0.0/0", "::/0"), FlowsPerSource: one.named}
			be := &fakeBackend{}
			tr := translator(t, cfg, Runtime{}, be)
			if err := tr.reconcile(); err != nil {
				t.Fatal(err)
			}
			limits := slices.DeleteFunc(be.specs(), func(spec string) bool { return !strings.Contains(spec, " limit ") })
			want := []string{fmt.Sprintf("out via ranet0 ipv4 limit %d", one.want), fmt.Sprintf("out via ranet0 ipv6 limit %d", one.want)}
			if !slices.Equal(limits, want) {
				t.Errorf("installed the limits %q, want %q", limits, want)
			}
			if got := tr.Status().FlowsPerSource; got != one.want {
				t.Errorf("Status reads a limit of %d flows a source, want %d", got, one.want)
			}
		})
	}
}

// A subnet router also translates the other way, under the one mesh address
// this node holds, or the address its class from every source names, and
// narrows that rule to the prefixes it claimed rather than to every packet
// that happens to reach the mesh device. What it sends from that address
// itself out of another link leaves under its class.
func TestReturnDirectionTranslatesUnderTheMeshAddress(t *testing.T) {
	rt := Runtime{MeshAddresses: []netip.Addr{netip.MustParseAddr("192.0.2.2")}}
	for _, c := range []struct {
		name      string
		translate []egress.Class
		want      []string
	}{
		{"under auto", nil, []string{
			"out via ranet0 ipv4 masquerade",
			"in via ranet0 ipv4 from 198.51.100.0/24 source 192.0.2.2",
			"in via ranet0 ipv4 from 192.0.2.5/32 source 192.0.2.2",
			"local via ranet0 ipv4 from 192.0.2.2/32 masquerade",
		}},
		{"under an address from every source", []egress.Class{{From: schema.MustPrefix("0.0.0.0/0"), To: egress.Translation{Addr: netip.MustParseAddr("198.51.100.7")}}}, []string{
			"out via ranet0 ipv4 source 198.51.100.7",
			"in via ranet0 ipv4 from 198.51.100.0/24 source 198.51.100.7",
			"in via ranet0 ipv4 from 192.0.2.5/32 source 198.51.100.7",
			"local via ranet0 ipv4 from 192.0.2.2/32 source 198.51.100.7",
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			cfg := egress.Egress{Return: true, Advertise: prefixes(t, "198.51.100.0/24", "192.0.2.5/32"), Translate: c.translate}
			be := &fakeBackend{}
			if err := translator(t, cfg, rt, be).reconcile(); err != nil {
				t.Fatal(err)
			}
			if got := be.translations(); !slices.Equal(got, c.want) {
				t.Errorf("installed %q, want %q", got, c.want)
			}
		})
	}
}

// A prefix covering every address narrows nothing, so the rule that would
// carry it selects on the direction alone rather than on a mask no packet
// fails.
func TestReturnRuleForADefaultCarriesNoPrefixMatch(t *testing.T) {
	cfg := egress.Egress{Return: true, Advertise: prefixes(t, "0.0.0.0/0")}
	rt := Runtime{MeshAddresses: []netip.Addr{netip.MustParseAddr("192.0.2.2")}}
	be := &fakeBackend{}
	if err := translator(t, cfg, rt, be).reconcile(); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"out via ranet0 ipv4 masquerade",
		"in via ranet0 ipv4 source 192.0.2.2",
		"local via ranet0 ipv4 from 192.0.2.2/32 masquerade",
	}
	if got := be.translations(); !slices.Equal(got, want) {
		t.Errorf("installed %q, want %q", got, want)
	}
}

// The return direction translates a LAN's flows into the mesh, a NAT as a
// class's is, so the rule of each advertised prefix attaches the exit's
// timeouts first, by a rule for UDP, for TCP and for the family's ICMP keyed as
// it is.
func TestReturnDirectionAttachesTheExitsTimeouts(t *testing.T) {
	cfg := egress.Egress{Return: true, Advertise: prefixes(t, "198.51.100.0/24", "2001:db8:1::/48")}
	rt := Runtime{MeshAddresses: []netip.Addr{netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("3fff::2")}}
	be := &fakeBackend{}
	if err := translator(t, cfg, rt, be).reconcile(); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"in via ranet0 ipv4 from 198.51.100.0/24 timeouts udp",
		"in via ranet0 ipv4 from 198.51.100.0/24 timeouts tcp",
		"in via ranet0 ipv4 from 198.51.100.0/24 timeouts icmp",
		"in via ranet0 ipv4 from 198.51.100.0/24 source 192.0.2.2",
		"in via ranet0 ipv6 from 2001:db8:1::/48 timeouts udp",
		"in via ranet0 ipv6 from 2001:db8:1::/48 timeouts tcp",
		"in via ranet0 ipv6 from 2001:db8:1::/48 timeouts icmpv6",
		"in via ranet0 ipv6 from 2001:db8:1::/48 source 3fff::2",
	}
	inbound := slices.DeleteFunc(be.specs(), func(spec string) bool {
		return !strings.HasPrefix(spec, "in ") || dropsRefusesOrPasses(spec)
	})
	if !slices.Equal(inbound, want) {
		t.Errorf("installed the In rules %q, want %q", inbound, want)
	}
}

// Under return the limit's chain drops a packet into the mesh no flow is
// tracked for from each advertised prefix, since the In rules translate
// whatever they take, after the rules out of the mesh, the limit among them,
// and Status counts what it drops with them
func TestReturnDropsWhatNoFlowIsTrackedForIntoTheMesh(t *testing.T) {
	cfg := egress.Egress{Return: true, Advertise: prefixes(t, "198.51.100.0/24", "0.0.0.0/0", "2001:db8:1::/48")}
	rt := Runtime{MeshAddresses: []netip.Addr{netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("3fff::2")}}
	be := &fakeBackend{flows: 3}
	tr := translator(t, cfg, rt, be)
	if err := tr.reconcile(); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"out via ranet0 ipv4 untracked dropped",
		"out via ranet0 ipv4 limit 4096",
		"in via ranet0 ipv4 from 198.51.100.0/24 untracked dropped",
		"in via ranet0 ipv4 untracked dropped",
		"out via ranet0 ipv6 untracked dropped",
		"out via ranet0 ipv6 limit 4096",
		"in via ranet0 ipv6 from 2001:db8:1::/48 untracked dropped",
	}
	forward := slices.DeleteFunc(be.specs(), func(spec string) bool {
		return !strings.Contains(spec, " untracked ") && !strings.Contains(spec, " limit ")
	})
	if !slices.Equal(forward, want) {
		t.Errorf("installed the limit's chains %q, want %q", forward, want)
	}
	if s := tr.Status(); s.Dropped4 != 9 || s.Dropped6 != 6 {
		t.Errorf("Status counts %d and %d packets dropped, want the fake host's three for each drop rule, 9 and 6", s.Dropped4, s.Dropped6)
	}
}

// an exit serving only the traffic steered to its egress segment advertises nothing and translates what arrives on the tun in both families, since End.DT46 delivers either
func TestSIDOnlyExitTranslatesTheTunInBothFamilies(t *testing.T) {
	var announced [][]netip.Prefix
	var tr *Translator
	rt := Runtime{Steered: true, Republish: func() { announced = append(announced, tr.Announce()) }}
	be := &fakeBackend{}
	tr = translator(t, egress.Egress{}, rt, be)
	if err := tr.reconcile(); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"out via ranet0 ipv4 masquerade",
		"out via ranet0 ipv6 masquerade",
	}
	if got := be.translations(); !slices.Equal(got, want) {
		t.Errorf("installed %q, want %q", got, want)
	}
	if len(announced) != 1 || len(announced[0]) != 0 {
		t.Errorf("published %v, want one empty announcement", announced)
	}
}

// an exit that advertises and holds an egress segment keys one Out rule per family on the tun, under the class from every source
// a family it does not advertise is translated all the same, with no return rule however return is set
func TestSteeredExitKeysOneRulePerFamilyOnTheTun(t *testing.T) {
	cfg := egress.Egress{
		Return:    true,
		Advertise: prefixes(t, "198.51.100.0/24"),
		Translate: []egress.Class{{From: schema.MustPrefix("0.0.0.0/0"), To: egress.Translation{Addr: netip.MustParseAddr("198.51.100.7")}}},
	}
	rt := Runtime{Steered: true, MeshAddresses: []netip.Addr{netip.MustParseAddr("192.0.2.2")}}
	be := &fakeBackend{}
	tr := translator(t, cfg, rt, be)
	for range 2 {
		if err := tr.reconcile(); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{
		"out via ranet0 ipv4 source 198.51.100.7",
		"in via ranet0 ipv4 from 198.51.100.0/24 source 198.51.100.7",
		"local via ranet0 ipv4 from 192.0.2.2/32 source 198.51.100.7",
		"out via ranet0 ipv6 masquerade",
	}
	if got := be.translations(); !slices.Equal(got, want) {
		t.Errorf("installed %q, want %q", got, want)
	}
	if be.applied != 1 {
		t.Errorf("wrote the ruleset %d times over two passes, want once", be.applied)
	}
	if got := tr.Announce(); !slices.Equal(got, plain(cfg.Advertise)) {
		t.Errorf("announced %v, want %v", got, cfg.Advertise)
	}
}

// Each family's rules are read back apart from the other's, so the rules a
// pass asks for have to be grouped by family. A list ordered any other way
// never compares equal to its own readback, and the ruleset is rewritten on
// every pass for the life of the node.
func TestRulesAreGroupedByFamilyAsTheyAreReadBack(t *testing.T) {
	cfg := egress.Egress{Return: true, Advertise: prefixes(t, "198.51.100.0/24", "2001:db8:1::/48")}
	rt := Runtime{MeshAddresses: []netip.Addr{
		netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("3fff::2"),
	}}
	be := &fakeBackend{}
	tr := translator(t, cfg, rt, be)
	want := []string{
		"out via ranet0 ipv4 masquerade",
		"in via ranet0 ipv4 from 198.51.100.0/24 source 192.0.2.2",
		"local via ranet0 ipv4 from 192.0.2.2/32 masquerade",
		"out via ranet0 ipv6 masquerade",
		"in via ranet0 ipv6 from 2001:db8:1::/48 source 3fff::2",
		"local via ranet0 ipv6 from 3fff::2/128 masquerade",
	}
	for range 3 {
		if err := tr.reconcile(); err != nil {
			t.Fatal(err)
		}
	}
	if got := be.translations(); !slices.Equal(got, want) {
		t.Errorf("installed %q, want %q", got, want)
	}
	if be.applied != 1 {
		t.Errorf("wrote the ruleset %d times over three passes, want once", be.applied)
	}
}

// A pass whose rules are already there writes nothing. The counters move on
// every packet, so a diff that read them would rewrite the ruleset whenever
// the node was carrying traffic, and each rewrite would drop the counters it
// had just read.
func TestUnchangedRulesAreNotRewritten(t *testing.T) {
	cfg := egress.Egress{Advertise: prefixes(t, "0.0.0.0/0")}
	be := &fakeBackend{flows: 11}
	tr := translator(t, cfg, Runtime{}, be)
	for range 3 {
		if err := tr.reconcile(); err != nil {
			t.Fatal(err)
		}
	}
	if be.applied != 1 {
		t.Errorf("wrote the ruleset %d times, want once", be.applied)
	}
	if got := tr.lastPass().Flows; got != 11 {
		t.Errorf("reported %d flows, want the counter the host holds", got)
	}
}

// An exit that cannot install its rule must not advertise. Babel gives a peer
// no way to learn that a node it selected will drop the traffic, so the only
// end that can act on it is this one.
func TestNothingIsAnnouncedWhileTheRuleWillNotInstall(t *testing.T) {
	cfg := egress.Egress{Advertise: prefixes(t, "0.0.0.0/0", "::/0")}
	be := &fakeBackend{failApply: true}
	var announced [][]netip.Prefix
	var tr *Translator
	rt := Runtime{Republish: func() { announced = append(announced, tr.Announce()) }}
	tr = translator(t, cfg, rt, be)
	if err := tr.reconcile(); err == nil {
		t.Fatal("a pass that could not install reported success")
	}
	if got := tr.Announce(); len(got) != 0 {
		t.Errorf("announced %v with no rule installed", got)
	}
	if len(announced) != 1 || len(announced[0]) != 0 {
		t.Errorf("published %v, want one empty announcement", announced)
	}

	// And it comes back by itself once the host takes the rules, without a
	// restart and without anything else asking.
	be.mu.Lock()
	be.failApply = false
	be.mu.Unlock()
	if err := tr.reconcile(); err != nil {
		t.Fatal(err)
	}
	if got := tr.Announce(); !slices.Equal(got, plain(cfg.Advertise)) {
		t.Errorf("announced %v after the rules installed, want %v", got, cfg.Advertise)
	}
}

// A counted rule in the translator's chain that no desired rule spells, such
// as another writer's, which a failed apply leaves held, counts as no flow,
// refusal or drop
func TestHeldRuleNoDesiredRuleSpellsCountsAsNothing(t *testing.T) {
	cfg := egress.Egress{Advertise: prefixes(t, "0.0.0.0/0", "::/0")}
	be := &fakeBackend{failApply: true, flows: 7}
	be.held = []Installed{{Spec: "", Family: egress.FamilyIPv4, Chain: ChainName, Counted: true, Bytes: 420}}
	tr := translator(t, cfg, Runtime{}, be)
	if err := tr.reconcile(); err == nil {
		t.Fatal("a pass that could not install reported success")
	}
	status := tr.Status()
	if status.Rules.Flows != 0 || status.Rules.Bytes != 0 || status.Refused4 != 0 || status.Dropped4 != 0 {
		t.Errorf("a rule no desired rule spells counted %d flows, %d bytes, %d refused and %d dropped, want none",
			status.Rules.Flows, status.Rules.Bytes, status.Refused4, status.Dropped4)
	}
}

// Readiness is per family, because a host can forward one and not the other
// and an exit that withheld both would take away a working half.
func TestOnlyTheForwardableFamilyIsAnnounced(t *testing.T) {
	cfg := egress.Egress{Advertise: prefixes(t, "0.0.0.0/0", "::/0")}
	rt := Runtime{Forwarding: func() (bool, bool) { return false, true }}
	tr := translator(t, cfg, rt, &fakeBackend{})
	if err := tr.reconcile(); err != nil {
		t.Fatal(err)
	}
	want := prefixes(t, "::/0")
	if got := tr.Announce(); !slices.Equal(got, plain(want)) {
		t.Errorf("announced %v, want %v", got, want)
	}
}

// A rule somebody removed under a running node is reinstalled by the next
// sweep, and the advertisement is withheld for as long as it is missing.
func TestRemovedRuleIsReinstalledAndTheAdvertisementWaits(t *testing.T) {
	cfg := egress.Egress{Advertise: prefixes(t, "0.0.0.0/0")}
	be := &fakeBackend{}
	tr := translator(t, cfg, Runtime{}, be)
	if err := tr.reconcile(); err != nil {
		t.Fatal(err)
	}
	be.mu.Lock()
	be.held = nil
	be.failApply = true
	be.mu.Unlock()
	if err := tr.reconcile(); err == nil {
		t.Fatal("a pass that could not reinstall reported success")
	}
	if got := tr.Announce(); len(got) != 0 {
		t.Errorf("kept announcing %v after the rule went away", got)
	}
}

// A pass that cannot read the chains back, before it writes them or after,
// reads neither family ready and announces nothing, since it cannot tell what
// the chains do
func TestUnreadChainsHoldBothFamiliesNotReady(t *testing.T) {
	cfg := egress.Egress{Advertise: prefixes(t, "0.0.0.0/0", "::/0")}
	for _, c := range []struct {
		name string
		be   *fakeBackend
	}{
		{"a listing that fails", &fakeBackend{failRules: true}},
		{"a listing that fails after the rewrite", &fakeBackend{failReadback: true}},
	} {
		tr := translator(t, cfg, Runtime{}, c.be)
		if err := tr.reconcile(); err == nil {
			t.Errorf("%s: the pass reported no error", c.name)
		}
		if s := tr.lastPass(); s.Ready4 || s.Ready6 || s.Unready != "its chains could not be read back" || len(tr.Announce()) != 0 {
			t.Errorf("%s: the pass reads ready %v and %v (%q) and announces %v, want neither family ready for its chains", c.name, s.Ready4, s.Ready6, s.Unready, tr.Announce())
		}
	}
}

// Another writer's rule the read of one family alone finds at the head of the
// chain, which a host refusing the rewrite leaves there, holds that family not
// ready and its prefixes withheld although every rule the translator wrote
// still reads back, since the chain no longer does to a packet what was
// written. The pass that rewrites the chain makes the family ready again, and
// the other family, whose read finds the chain as written, stays ready
// throughout.
func TestAnotherWritersRuleInAChainHoldsItsFamilyNotReady(t *testing.T) {
	cfg := egress.Egress{Advertise: prefixes(t, "0.0.0.0/0", "::/0")}
	tr, be := readyLog(t, cfg, events.New())
	if err := tr.reconcile(); err != nil {
		t.Fatal(err)
	}
	written := be.specs()
	be.mu.Lock()
	be.held = append([]Installed{{Family: egress.FamilyIPv4}}, be.held...)
	be.failApply = true
	be.mu.Unlock()
	if err := tr.reconcile(); err == nil {
		t.Fatal("a pass the host refused the rewrite of reported no error")
	}
	if got := be.specs(); !slices.Equal(got, append([]string{""}, written...)) {
		t.Fatalf("the host holds %q, want another writer's rule ahead of every rule the translator wrote, %q", got, written)
	}
	if stats := tr.lastPass(); stats.Ready4 || !stats.Ready6 || stats.Unready != "its chains read back other than they were written" {
		t.Errorf("with another writer's rule in the IPv4 read the pass reports ready %v and %v with the reason %q, want IPv4 alone not ready for its chain",
			stats.Ready4, stats.Ready6, stats.Unready)
	}
	if got, want := tr.Announce(), plain(prefixes(t, "::/0")); !slices.Equal(got, want) {
		t.Errorf("with another writer's rule in the IPv4 read the translator announces %v, want %v", got, want)
	}
	be.mu.Lock()
	be.failApply = false
	be.mu.Unlock()
	if err := tr.reconcile(); err != nil {
		t.Fatal(err)
	}
	if got := be.specs(); !slices.Equal(got, written) {
		t.Errorf("the pass the host took left %q, want %q", got, written)
	}
	if stats := tr.lastPass(); !stats.Ready4 || !stats.Ready6 {
		t.Errorf("once the chain was rewritten the pass reports ready %v and %v, want both", stats.Ready4, stats.Ready6)
	}
	if got, want := tr.Announce(), plain(cfg.Advertise); !slices.Equal(got, want) {
		t.Errorf("once the chain was rewritten the translator announces %v, want %v", got, want)
	}
	var moved []string
	for _, entry := range be.entries() {
		if strings.HasPrefix(entry, "ready") {
			moved = append(moved, entry)
		}
	}
	if want := []string{"ready true true sid true", "ready false true sid false", "ready true true sid true"}; !slices.Equal(moved, want) {
		t.Errorf("Ready was told %q, want %q", moved, want)
	}
}

// A family's timeout object deleted, or its set made again where nf_tables
// will not change it in place, makes the pass rewrite it, deleting the stale
// set first in the second case, after which both families read ready. A fault
// of one family's the rewrite cannot put back holds that family alone not
// ready, named, and its prefixes withheld.
func TestTranslatorRewritesAnObjectReadingBackOtherThanWritten(t *testing.T) {
	cfg := egress.Egress{Advertise: prefixes(t, "0.0.0.0/0", "::/0")}
	be := &fakeBackend{}
	tr := translator(t, cfg, Runtime{Interface: "ranet0", Steered: true, Forwarding: func() (bool, bool) { return true, true }}, be)
	if err := tr.reconcile(); err != nil {
		t.Fatal(err)
	}
	const missing = "its ct timeout udp6 is missing"
	for _, change := range []struct {
		name   string
		faults map[uint8]string
		remake map[uint8]bool
		pass   []string
	}{
		{"an ip6 timeout object deleted", map[uint8]string{egress.FamilyIPv6: missing}, nil, []string{"rules", "apply", "rules"}},
		{"the ip set made again under another share", map[uint8]string{egress.FamilyIPv4: `its set flows4 reads back with comment "limit 2"`}, map[uint8]bool{egress.FamilyIPv4: true}, []string{"rules", "remake", "rules"}},
	} {
		be.mu.Lock()
		be.faults, be.remake, be.log = change.faults, change.remake, nil
		be.mu.Unlock()
		if err := tr.reconcile(); err != nil {
			t.Fatalf("%s: %v", change.name, err)
		}
		if got, stats := be.entries(), tr.lastPass(); !slices.Equal(got, change.pass) || !stats.Ready4 || !stats.Ready6 {
			t.Errorf("%s: the pass went %q and left ready %v and %v, want %q and both ready", change.name, got, stats.Ready4, stats.Ready6, change.pass)
		}
	}
	be.mu.Lock()
	be.faults, be.stuck = map[uint8]string{egress.FamilyIPv6: missing}, true
	be.mu.Unlock()
	if err := tr.reconcile(); err != nil {
		t.Fatal(err)
	}
	if stats := tr.lastPass(); !stats.Ready4 || stats.Ready6 || stats.Unready != missing {
		t.Errorf("an ip6 object the rewrite leaves missing reads ready %v and %v, unready %q", stats.Ready4, stats.Ready6, stats.Unready)
	}
	if got, want := tr.Announce(), plain(prefixes(t, "0.0.0.0/0")); !slices.Equal(got, want) {
		t.Errorf("with the ip6 object left missing the translator announces %v, want %v", got, want)
	}
}

// A translator that stops retracts before it withdraws. A peer still selecting
// this node while its chains come down is a peer whose traffic leaves
// untranslated, and the retraction is the only thing that tells it otherwise.
func TestShutdownRetractsBeforeItWithdraws(t *testing.T) {
	cfg := egress.Egress{Advertise: prefixes(t, "0.0.0.0/0")}
	be := &fakeBackend{}
	tr := translator(t, cfg, Runtime{}, be)
	withdrawnWhenRetracted := -1
	tr.rt.Republish = func() {
		if len(tr.Announce()) == 0 {
			withdrawnWhenRetracted = be.withdrawn
		}
	}
	if err := tr.reconcile(); err != nil {
		t.Fatal(err)
	}
	if len(tr.Announce()) != 1 {
		t.Fatal("the first pass announced nothing to retract")
	}
	if err := endedAtOnce(tr); err != nil {
		t.Fatal(err)
	}
	if got := tr.Announce(); len(got) != 0 {
		t.Errorf("the advertisement survived shutdown as %v", got)
	}
	if be.withdrawn != 1 {
		t.Errorf("withdrew %d times, want once", be.withdrawn)
	}
	if withdrawnWhenRetracted != 0 {
		t.Errorf("its chains were already down when the advertisement was retracted, after %d withdrawals", withdrawnWhenRetracted)
	}
}

// readyLog is a translator beside an egress segment whose Ready and Republish
// calls go into its backend's log between the listings, applies and
// withdrawals, and whose egress.ready events go to bus
func readyLog(t *testing.T, cfg egress.Egress, bus *events.Bus) (*Translator, *fakeBackend) {
	t.Helper()
	be := &fakeBackend{changed: make(chan struct{}, 1), missed: make(chan struct{}, 1)}
	var tr *Translator
	rt := Runtime{
		Steered: true,
		Events:  bus,
		Ready:   func(v4, v6, serves bool) { be.record(fmt.Sprintf("ready %v %v sid %v", v4, v6, serves)) },
		Republish: func() {
			if len(tr.Announce()) == 0 {
				be.record("retract")
			}
		},
	}
	tr = translator(t, cfg, rt, be)
	return tr, be
}

// A translator beside an egress segment that stops, or is stopped, tells the
// mesh to stop egressing before it retracts, and records the stop's reason for
// every family before the rules change, so Status says why from the moment a
// stop begins. `ranet3 down` writes the stopped translator's rules in place of
// its own in one write. At shutdown the translator waits for the mesh's done
// channel after the record and withdraws only once it has closed. Either logs
// each family not ready and the advertisement's change at info, since neither
// is a fault of the exit.
func TestStoppingReportsTheEgressSegmentsNotReadyFirst(t *testing.T) {
	count := func(lines, level, message string) int {
		return strings.Count(lines, "level="+level+" msg=\""+message+"\"")
	}
	for name, stop := range map[string]struct {
		run func(*Translator) error
		// waits gives the translator a mesh's done channel the test closes
		// once Run waits on it alone
		waits bool
		ends  []string
	}{
		"shutdown":    {endedAtOnce, true, []string{"withdraw"}},
		"ranet3 down": {stopTurn, false, []string{"apply"}},
	} {
		t.Run(name, bubble.Run(func(t *testing.T) {
			var lines strings.Builder
			logtest.SetDefault(t, slog.New(slog.NewTextHandler(&lines, nil)))
			bus := events.New()
			tr, be := readyLog(t, egress.Egress{Advertise: prefixes(t, "0.0.0.0/0")}, bus)
			be.seen = func() string {
				s := tr.Status()
				return fmt.Sprintf("status %v %v %s", s.Ready4, s.Ready6, s.Unready)
			}
			closed := make(chan struct{})
			if stop.waits {
				tr.rt.Done = closed
			}
			if err := tr.reconcile(); err != nil {
				t.Fatal(err)
			}
			passed := len(be.entries())
			ended := make(chan error, 1)
			go func() { ended <- stop.run(tr) }()
			if stop.waits {
				// every goroutine of the bubble is blocked, Run on the mesh's done
				// channel alone
				synctest.Wait()
				got, s := be.entries(), tr.Status()
				switch {
				case slices.Contains(got, "withdraw"):
					t.Errorf("with the mesh open the translator went %q, want no withdrawal before it closed", got)
				case !slices.Contains(got, "retract") || s.Ready4 || s.Ready6 || s.Unready != "the translator is stopping":
					t.Errorf("with the mesh open the translator went %q and Status read ready %v %v, %q, want the stop retracted and recorded before it waits", got, s.Ready4, s.Ready6, s.Unready)
				}
				close(closed)
			}
			if err := <-ended; err != nil {
				t.Fatal(err)
			}
			var order []string
			for i, entry := range be.entries() {
				if entry != "rules" && (entry != "apply" || i >= passed) {
					order = append(order, entry)
				}
			}
			if want := append([]string{"ready true true sid true", "ready false false sid false", "retract", "status false false the translator is stopping"}, stop.ends...); !slices.Equal(order, want) {
				t.Errorf("the translator went %q, want %q", order, want)
			}
			var recorded []string
			for _, event := range bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "egress.ready" }, 0) {
				recorded = append(recorded, event.Attrs["ipv4"]+" "+event.Attrs["ipv6"]+" "+event.Attrs["sid"])
			}
			if want := []string{"true true true", "false false false"}; !slices.Equal(recorded, want) {
				t.Errorf("recorded egress.ready %q, want %q", recorded, want)
			}
			if got := lines.String(); count(got, "INFO", "egress not ready") != 2 || count(got, "INFO", "egress advertisement changed") != 1 ||
				count(got, "WARN", "egress not ready") != 0 || count(got, "WARN", "egress advertisement changed") != 0 {
				t.Errorf("the %s logged other than both families not ready and the advertisement's change at info:\n%s", name, got)
			}
		}))
	}
}

// `ranet3 down` holds, for each family it translates, a rule in place of the
// family's limit that drops every packet out of the mesh the limit would
// meet. So whatever the classes
// and their order, a packet out of the mesh of a flow with no label is dropped
// exactly where the translation's chain translates its flow and passed where
// that chain binds the flow to its own source, and the translation's chain
// stays as a pass writes it. A packet of either family, translated or not,
// leaving by another link is dropped where its flow carries the translation's
// label, whatever link it came in by and under a class of none among them,
// and one that did not come in by the mesh device is passed where it does
// not. No packet of a family the exit translates, of a tracked flow or of
// none, meets more rules at the forward hook than the running translator's
// give it but one out of the mesh under a class of none, and one out of the
// mesh of no tracked flow in a family with a class of none, which each meet at
// most one more, the labelled drop ahead of the family's pass, and one of a
// family it does not translate meets exactly one more, the labelled drop.
func TestStopDropsWhereTheTranslationTranslates(t *testing.T) {
	none, auto := egress.Translation{None: true}, egress.Translation{Auto: true}
	to := func(raw string) egress.Translation { return egress.Translation{Addr: netip.MustParseAddr(raw)} }
	class := func(from string, to egress.Translation) egress.Class {
		return egress.Class{From: schema.MustPrefix(from), To: to}
	}
	both := []string{"0.0.0.0/0", "::/0"}
	for name, c := range map[string]struct {
		advertise []string
		translate []egress.Class
	}{
		"under auto":    {both, nil},
		"in ipv4 alone": {both[:1], nil},
		"in ipv6 alone": {both[1:], nil},
		"classes inside one another": {both, []egress.Class{
			class("192.0.2.0/24", none), class("0.0.0.0/0", to("198.51.100.7")), class("192.0.2.128/25", auto),
			class("3fff::/20", to("2001:db8::7")),
		}},
		"a class of none from every source": {both, []egress.Class{class("::/0", none), class("3fff::/20", auto)}},
		"classes alternating four deep": {both, []egress.Class{
			class("0.0.0.0/0", to("198.51.100.7")), class("10.0.0.0/8", none), class("10.1.0.0/16", auto), class("10.1.2.0/24", none),
			class("::/0", auto), class("3fff::/20", none), class("3fff:100::/24", to("2001:db8::7")), class("3fff:100::/32", none),
		}},
		"classes side by side": {both, []egress.Class{
			class("192.0.2.0/25", none), class("192.0.2.128/25", none), class("192.0.2.64/26", auto), class("192.0.2.192/27", to("198.51.100.7")),
			class("3fff::/21", none), class("3fff:800::/21", auto),
		}},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := egress.Egress{Advertise: prefixes(t, c.advertise...), Translate: c.translate, Return: true}
			mesh := []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("3fff::1")}
			tr := translator(t, cfg, Runtime{MeshAddresses: mesh}, &fakeBackend{})
			running, stopped := tr.desired(), tr.stopped()
			translation := func(rules []Rule) []Rule {
				return slices.DeleteFunc(slices.Clone(rules), func(rule Rule) bool { return rule.chain() != ChainName })
			}
			if got, want := translation(stopped), translation(running); !slices.Equal(got, want) {
				t.Errorf("the stop writes the translation's chain as %v, want it as a pass writes it, %v", got, want)
			}
			for _, family := range []uint8{egress.FamilyIPv4, egress.FamilyIPv6} {
				translatedFamily := slices.Contains(cfg.Translated(false), family)
				// passes is whether the family has a pass of untranslated sources,
				// which the stop's labelled drop stands ahead of
				passes := slices.ContainsFunc(running, func(rule Rule) bool { return rule.Family == family && rule.Passes })
				// bound holds the walk of what to the rules it meets, stopped and
				// running, one more where extra holds
				bound := func(what string, extra bool, stopped, running int) {
					t.Helper()
					more := 0
					if extra {
						more = 1
					}
					switch {
					case translatedFamily && stopped > running+more:
						t.Errorf("while stopped %s meets %d rules at the forward hook, more than the %d it meets while running and %d", what, stopped, running, more)
					case !translatedFamily && stopped != running+1:
						t.Errorf("while stopped %s, of a family the exit does not translate, meets %d rules at the forward hook, want the %d it meets while running and the labelled drop", what, stopped, running)
					}
				}
				for _, source := range edges(c.translate, family) {
					translated, class := translates(running, family, source), cfg.ClassOf(source)
					if translatedFamily && translated == class.To.None {
						t.Errorf("the translation's chain translates %s %v, under the class %v", source, translated, class)
					}
					dropped, met := heldWalk(stopped, family, source, true, false, false)
					if dropped != translated {
						t.Errorf("while stopped a packet out of the mesh from %s is dropped %v, want %v as the translation's chain translates it", source, dropped, translated)
					}
					_, runs := heldWalk(running, family, source, true, false, false)
					bound(fmt.Sprintf("a packet out of the mesh from %s", source), class.To.None, met, runs)
					_, met = heldWalk(stopped, family, source, true, true, false)
					_, runs = heldWalk(running, family, source, true, true, false)
					bound(fmt.Sprintf("a packet out of the mesh from %s with no tracked flow", source), class.To.None || passes, met, runs)
					if dropped, met = heldWalk(stopped, family, source, true, false, true); !dropped {
						t.Errorf("while stopped a packet out of the mesh from %s, under %v, of a flow the translation's label marks is passed, want it dropped", source, class)
					}
					_, runs = heldWalk(running, family, source, true, false, true)
					bound(fmt.Sprintf("a packet out of the mesh from %s of a labelled flow", source), class.To.None, met, runs)
				}
				for _, labelled := range []bool{false, true} {
					dropped, met := heldWalk(stopped, family, netip.Addr{}, false, false, labelled)
					if dropped != labelled {
						t.Errorf("while stopped an %s packet that did not come in by the mesh device, of a flow labelled %v, is dropped %v, want %v", egress.FamilyName(family), labelled, dropped, labelled)
					}
					_, runs := heldWalk(running, family, netip.Addr{}, false, false, labelled)
					bound(fmt.Sprintf("an %s packet that did not come in by the mesh device, of a flow labelled %v", egress.FamilyName(family), labelled), false, met, runs)
				}
			}
		})
	}
}

// heldWalk walks the forward hook under rules as nftables runs them for a UDP
// packet of family from source, of a flow conntrack tracks below its limit or,
// where untracked is set, of none, carrying the translation's label where
// labelled is set, in by the mesh device where fromMesh is set and by another
// link where it is not, and out by another link: forward's first line, which
// sends IPv6 on to IPv6's chain, then the rules of the family's chain in
// order, a pass accepting the packet, and the end of the chain passing it. It
// answers whether a rule dropped the packet and how many rules it met, that
// first line among them.
func heldWalk(rules []Rule, family uint8, source netip.Addr, fromMesh, untracked, labelled bool) (dropped bool, met int) {
	chain := familyChain(family)
	met = 1
	for _, rule := range rules {
		if rule.chain() != chain {
			continue
		}
		met++
		takes := (!rule.From.IsValid() || rule.From.Contains(source)) && (rule.Sources == "" || rule.Sources.Contains(source))
		switch kind := rule.kind(); {
		case kind == leaving && labelled && (rule.Sources == "" || fromMesh && takes):
			return true, met
		case kind == leaving, !fromMesh, rule.Direction != Out, !takes:
			continue
		case kind == passing:
			return false, met
		case kind == holding, kind == dropping && untracked:
			return true, met
		}
	}
	return false, met
}

// translates is whether the translation's chain of rules translates the first
// packet of a flow of family from source out of the mesh: the first rule
// taking the source that translates it or binds it to its own decides, and a
// source no such rule takes leaves as it came
func translates(rules []Rule, family uint8, source netip.Addr) bool {
	for _, rule := range rules {
		if rule.Family == family && rule.chain() == ChainName && rule.Direction == Out && rule.kind() == translating &&
			(!rule.From.IsValid() || rule.From.Contains(source)) {
			return !rule.None
		}
	}
	return false
}

// edges is the first and the last address of family and of each class of it,
// with those just outside each class
func edges(classes []egress.Class, family uint8) []netip.Addr {
	every := netip.PrefixFrom(netip.IPv4Unspecified(), 0)
	if family == egress.FamilyIPv6 {
		every = netip.PrefixFrom(netip.IPv6Unspecified(), 0)
	}
	ranges := []netip.Prefix{every}
	for _, class := range classes {
		if egress.AddressFamily(class.From.Addr()) == family {
			ranges = append(ranges, class.From.Masked())
		}
	}
	var out []netip.Addr
	for _, prefix := range ranges {
		raw := prefix.Addr().AsSlice()
		for bit := prefix.Bits(); bit < len(raw)*8; bit++ {
			raw[bit/8] |= 0x80 >> (bit % 8)
		}
		last, _ := netip.AddrFromSlice(raw)
		out = append(out, prefix.Addr(), last, prefix.Addr().Prev(), last.Next())
	}
	return slices.DeleteFunc(out, func(address netip.Addr) bool { return !address.IsValid() })
}

// A translator started down writes a stopped translator's rules from its first
// turn, the translation's chain as a pass writes it among them, and reads them
// back at every turn of its loop, writing them again where they no longer read
// back as written, as a pass does its own: a stop the host refused is tried
// again at the next wake, logged at warn, and the rules another writer took
// away are put back, each write logged at info, with no pass between. Status
// reads the stop in effect, neither family ready and the stopped rules counted,
// once they read back. Its first pass after `ranet3 up` puts its own in their
// place.
func TestStartedDownHoldsItsStoppedRulesUntilTheFirstPass(t *testing.T) {
	var lines strings.Builder
	logtest.SetDefault(t, slog.New(slog.NewTextHandler(&lines, nil)))
	be := &fakeBackend{changed: make(chan struct{}, 1), failStop: true}
	tr := translator(t, egress.Egress{Advertise: prefixes(t, "0.0.0.0/0"), Sweep: schema.Duration(lateSweep)}, Runtime{Events: events.New()}, be)
	tr.Enabled.Store(false)
	want := specsOf(tr.stopped())
	if !slices.Contains(want, "out via ranet0 ipv4 dropped while stopped") || !slices.Contains(want, "out via ranet0 ipv4 masquerade") {
		t.Fatalf("a stopped translator's rules are %q, want the hold and the translation among them", want)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- tr.Run(ctx) }()
	end := sync.OnceFunc(func() {
		cancel()
		<-done
	})
	t.Cleanup(end)
	await := awaiting(t, be, tr)
	stopped := func() bool {
		s := tr.Status()
		return !s.Ready4 && !s.Ready6 && s.Unready == "the translator is stopped" && s.Err == "" && s.Rules.Installed == len(want) && slices.Equal(be.specs(), want)
	}
	await("the refused stop", func() bool { return tr.Status().Err != "" })
	be.mu.Lock()
	if be.withdrawn != 0 || len(be.held) != 0 {
		t.Errorf("the refused stop left %d rules after %d withdrawals, want none of either, as it found the host", len(be.held), be.withdrawn)
	}
	be.failStop = false
	be.mu.Unlock()
	be.changed <- struct{}{}
	await("the stop tried again", stopped)
	be.mu.Lock()
	be.held = be.held[1:]
	be.mu.Unlock()
	be.changed <- struct{}{}
	await("the rules another writer took away put back", stopped)
	tr.SetEnabled(true)
	await("the first pass", func() bool { return slices.Equal(be.specs(), specsOf(tr.desired())) })
	end()
	got := lines.String()
	if passes, refused, wrote := strings.Count(got, `msg="egress rules installed"`), strings.Count(got, `level=WARN msg="egress could not stop its chains, retrying"`),
		strings.Count(got, `level=INFO msg="egress translator stopped"`); passes != 1 || refused == 0 || wrote != 2 {
		t.Errorf("the translator started down ran %d passes, logged %d refusals at warn and %d writes at info, want the one after up, at least 1 and 2:\n%s", passes, refused, wrote, got)
	}
}

// awaiting is a wait of up to PassWait for ok, failing t with what be holds
// and what Status of tr reads where ok never held
func awaiting(t *testing.T, be *fakeBackend, tr *Translator) func(what string, ok func() bool) {
	return func(what string, ok func() bool) {
		t.Helper()
		for deadline := time.Now().Add(PassWait); !ok(); time.Sleep(passPoll) {
			if time.Now().After(deadline) {
				s := tr.Status()
				t.Fatalf("timed out waiting for %s, the host holding %q, Status reading %q and the error %q", what, be.specs(), s.Unready, s.Err)
			}
		}
	}
}

// specsOf is the spec of each of rules
func specsOf(rules []Rule) []string {
	out := make([]string, 0, len(rules))
	for _, rule := range rules {
		out = append(out, rule.String())
	}
	return out
}

// A start that finds the rules of a run that died brings the host to its own
// first turn's in one write over them: a start down over a running
// translator's rules writes a stopped translator's, and a start up over a
// stopped translator's writes its own, and either over a stopped translator's
// of another file, its translation's chain kept, writes that chain as its own
// file has it. A start that finds its first turn's rules as written writes
// nothing.
func TestStartOverTheRulesOfARunThatDied(t *testing.T) {
	cfg := egress.Egress{Advertise: prefixes(t, "0.0.0.0/0", "::/0")}
	died := translator(t, cfg, Runtime{}, &fakeBackend{})
	other := translator(t, egress.Egress{Advertise: cfg.Advertise,
		Translate: []egress.Class{{From: schema.MustPrefix("0.0.0.0/0"), To: egress.Translation{Addr: netip.MustParseAddr("198.51.100.7")}}},
	}, Runtime{}, &fakeBackend{})
	for name, c := range map[string]struct {
		kept   []Rule
		down   bool
		writes int
	}{
		"down over a running translator's":                 {died.desired(), true, 1},
		"up over a stopped translator's":                   {died.stopped(), false, 1},
		"down over a stopped translator's of another file": {other.stopped(), true, 1},
		"up over a stopped translator's of another file":   {other.stopped(), false, 1},
		"down over a stopped translator's":                 {died.stopped(), true, 0},
		"up over a running translator's":                   {died.desired(), false, 0},
	} {
		t.Run(name, func(t *testing.T) {
			be := &fakeBackend{}
			if err := be.Apply(c.kept, false); err != nil {
				t.Fatal(err)
			}
			mark := len(be.entries())
			tr := translator(t, cfg, Runtime{}, be)
			turn, wanted, status := tr.reconcile, tr.desired(), ""
			if c.down {
				tr.Enabled.Store(false)
				turn, wanted, status = func() error { return stopTurn(tr) }, tr.stopped(), "the translator is stopped"
			}
			if err := turn(); err != nil {
				t.Fatal(err)
			}
			writes := 0
			for _, entry := range be.entries()[mark:] {
				if entry == "apply" {
					writes++
				}
			}
			if got, want := be.specs(), specsOf(wanted); !slices.Equal(got, want) || writes != c.writes {
				t.Errorf("the start left %q after %d writes, want %q after %d", got, writes, want, c.writes)
			}
			if s := tr.Status(); s.Unready != status || s.Err != "" {
				t.Errorf("the start reads unready %q with the error %q, want %q and none", s.Unready, s.Err, status)
			}
		})
	}
}

// A stop whose write the host takes but whose rules then read back other than
// written, or cannot be read back, reads the translator stopping, why as a pass
// names it and the error, the rules it read counted, or none where it read
// none, and is an error, so it is tried again. Once they read back as written
// Status reads the stop in effect, with the flows the kept translation's chain
// counts.
func TestStopReadsInEffectOnlyOnceItsRulesReadBack(t *testing.T) {
	be := &fakeBackend{}
	tr := translator(t, egress.Egress{Advertise: prefixes(t, "0.0.0.0/0", "::/0")}, Runtime{}, be)
	if err := tr.reconcile(); err != nil {
		t.Fatal(err)
	}
	fault := "its chain none_x is not one the translator writes, and chain other holds a rule going to it, so it stays until that rule goes"
	be.faults, be.stuck = map[uint8]string{egress.FamilyIPv6: fault}, true
	_, err := tr.stop()
	if s := tr.Status(); err == nil || !strings.Contains(err.Error(), fault) || s.Ready4 || s.Ready6 || s.Unready != "the translator is stopping: "+fault ||
		s.Err != err.Error() || s.Rules.Installed != len(tr.stopped()) {
		t.Errorf("a stop whose rules read back with a fault returned %v and reads ready %v %v, %q, the error %q and %d installed, want the fault named and %d", err, s.Ready4, s.Ready6, s.Unready, s.Err, s.Rules.Installed, len(tr.stopped()))
	}
	be.faults, be.stuck = map[uint8]string{egress.FamilyIPv6: fault}, false
	be.failReadback = true
	_, err = tr.stop()
	if s := tr.Status(); err == nil || s.Unready != "the translator is stopping: its chains could not be read back" || s.Err != err.Error() || s.Rules.Installed != 0 {
		t.Errorf("a stop whose rules could not be read back returned %v and reads %q, the error %q and %d installed, want them said unread and none", err, s.Unready, s.Err, s.Rules.Installed)
	}
	be.failReadback, be.flows = false, 3
	if err := stopTurn(tr); err != nil {
		t.Fatal(err)
	}
	// the kept translation's chain counts on while down, each of its counters
	// at 3
	var flows uint64
	for _, rule := range tr.stopped() {
		if rule.kind() == translating && !rule.None {
			flows += be.flows
		}
	}
	if s := tr.Status(); s.Unready != "the translator is stopped" || s.Err != "" || s.Rules.Installed != len(tr.stopped()) || flows == 0 || s.Rules.Flows != flows {
		t.Errorf("the stop whose rules read back reads %q, the error %q, %d installed and %d flows, want it in effect with %d and %d", s.Unready, s.Err, s.Rules.Installed, s.Rules.Flows, len(tr.stopped()), flows)
	}
}

// A write of the stopped rules the host answers with an error, as it answers a
// transaction it commits whose acknowledgments overflow the socket, is judged
// by the readback after it. Where the rules read back as written the stop
// reports the write taken, logs that the translator stopped, reads in effect
// and is no error. Where they cannot be read back after it, the stop reports
// no write taken, reads the translator stopping with none counted, and is an
// error naming the write's and the readback's.
func TestStopJudgesAWriteAnsweredWithAnErrorByItsReadback(t *testing.T) {
	for name, unread := range map[string]bool{"read back as written": false, "not read back": true} {
		t.Run(name, func(t *testing.T) {
			var lines strings.Builder
			logtest.SetDefault(t, slog.New(slog.NewTextHandler(&lines, nil)))
			be := &fakeBackend{loseStop: true}
			tr := translator(t, egress.Egress{Advertise: prefixes(t, "0.0.0.0/0", "::/0")}, Runtime{}, be)
			if err := tr.reconcile(); err != nil {
				t.Fatal(err)
			}
			be.failReadback = unread
			wrote, err := tr.stop()
			s, logged := tr.Status(), strings.Contains(lines.String(), `msg="egress translator stopped"`)
			switch {
			case !unread && (!wrote || err != nil || !logged || s.Unready != "the translator is stopped" || s.Rules.Installed != len(tr.stopped())):
				t.Errorf("the stop reported the write taken %v, returned %v, logged its stop %v and reads %q with %d installed, want it taken, in effect with %d and logged", wrote, err, logged, s.Unready, s.Rules.Installed, len(tr.stopped()))
			case unread && (wrote || err == nil || err.Error() != "install rules: no, then list rules: no" || logged || s.Unready != "the translator is stopping: its chains could not be read back" || s.Rules.Installed != 0):
				t.Errorf("the stop reported the write taken %v, returned %v, logged its stop %v and reads %q with %d installed, want none taken, both errors, no stop logged and none counted", wrote, err, logged, s.Unready, s.Rules.Installed)
			}
		})
	}
}

// A stop the host refuses whose rules then read back with a fault, as those of
// a table another writer gave a flag do, names the fault beside the refusal:
// Status reads the translator stopping, the refusal, that the stopped rules are
// not in place and then the fault and the running rules it found in place of
// the stopped ones, as a pass's reason names a fault, with the rules the host
// holds counted, and the error, which the egress.pass event carries too, reads
// the refusal and then the same faults
func TestRefusedStopNamesHowItsRulesReadBack(t *testing.T) {
	bus := events.New()
	be := &fakeBackend{}
	tr := translator(t, egress.Egress{Advertise: prefixes(t, "0.0.0.0/0", "::/0")}, Runtime{Events: bus}, be)
	if err := tr.reconcile(); err != nil {
		t.Fatal(err)
	}
	const fault = "its table carries flags 0x4, where none are written and 0x1 is dormant, and only nft delete table inet ranet3 clears another"
	be.faults, be.failStop = map[uint8]string{egress.FamilyIPv4: fault, egress.FamilyIPv6: fault}, true
	held := be.specs()
	taken, err := tr.stop()
	want := "install rules: no, then the stopped rules read back other than written: " + fault + ", and " + fakeLines
	const stopping = "the translator is stopping: the host refused the stopped rules, which are not in place: " + fault + ", and " + fakeLines
	if s := tr.Status(); taken || err == nil || err.Error() != want || s.Unready != stopping || s.Err != want || s.Rules.Installed != len(held) {
		t.Errorf("the refused stop reported the write taken %v, returned %v and reads %q, the error %q and %d installed, want none taken, %q, %q and the %d rules the host holds",
			taken, err, s.Unready, s.Err, s.Rules.Installed, stopping, want, len(held))
	}
	var errs []string
	for _, event := range bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "egress.pass" }, 0) {
		errs = append(errs, event.Attrs["err"])
	}
	if len(errs) == 0 || errs[len(errs)-1] != want {
		t.Errorf("the egress.pass events carry the errors %q, want the last %q", errs, want)
	}
}

// A stop names no refusal in Status's reason where the host refused nothing of
// its write and its rules read back with a fault, a chain of an earlier
// version's another writer holds, which leaves the stopped rules in place. One
// such write failed before it was sent. Its reason says the stopped rules are
// not in place, ahead of the fault and the running rules it found. The host
// committed another, and its answers were lost. Its reason names the fault
// alone. The error names the write's answer and then what the reason names
// after its colon. The host holds what it held in the first case and the
// stopped rules in the second.
func TestStopNamesNoRefusalWhereTheHostRefusedNothing(t *testing.T) {
	const fault = "its chain forward4 is not one the translator writes, and chain other holds a rule going to it, so it stays until that rule goes"
	for _, c := range []struct {
		name         string
		unsent, lost bool
		read         string
		stopping     string
	}{
		{"a write that failed before it was sent", true, false, fault + ", and " + fakeLines, "the translator is stopping: the stopped rules are not in place: " + fault + ", and " + fakeLines},
		{"a write whose answers were lost", false, true, fault, "the translator is stopping: " + fault},
	} {
		t.Run(c.name, func(t *testing.T) {
			be := &fakeBackend{}
			tr := translator(t, egress.Egress{Advertise: prefixes(t, "0.0.0.0/0", "::/0")}, Runtime{}, be)
			if err := tr.reconcile(); err != nil {
				t.Fatal(err)
			}
			held := be.specs()
			if c.lost {
				held = specsOf(tr.stopped())
			}
			be.faults, be.stuck = map[uint8]string{egress.FamilyIPv4: fault}, true
			be.unsentStop, be.loseStop = c.unsent, c.lost
			taken, err := tr.stop()
			want := "install rules: no, then the stopped rules read back other than written: " + c.read
			if s := tr.Status(); taken || err == nil || err.Error() != want || s.Unready != c.stopping || s.Err != want {
				t.Errorf("the stop reported the write taken %v, returned %v and reads %q and the error %q, want none taken, %q and %q", taken, err, s.Unready, s.Err, c.stopping, want)
			}
			if got := be.specs(); !slices.Equal(got, held) {
				t.Errorf("the host holds %q, want %q", got, held)
			}
		})
	}
}

// A stop's write the host refuses, whose acknowledgments of the refusal
// overflow the socket, has an answer that is no refusal. Status's reason names
// no refusal then. It says the stopped rules are not in place, ahead of the
// fault and the running rules the readback finds in their place. The error
// names the answer and then the same faults. The host holds the running rules.
func TestRefusedStopWhoseAnswersOverflowSaysItsRulesAreNotInPlace(t *testing.T) {
	be := &fakeBackend{}
	tr := translator(t, egress.Egress{Advertise: prefixes(t, "0.0.0.0/0", "::/0")}, Runtime{}, be)
	if err := tr.reconcile(); err != nil {
		t.Fatal(err)
	}
	const fault = "its set untranslated4 reads back with flags 0x0, where flags 0x4 were written, and chain other holds a rule using it, so it stays until that rule goes"
	be.faults, be.stuck, be.overflowStop = map[uint8]string{egress.FamilyIPv4: fault}, true, true
	held := be.specs()
	taken, err := tr.stop()
	want := "install rules: no, then the stopped rules read back other than written: " + fault + ", and " + fakeLines
	const stopping = "the translator is stopping: the stopped rules are not in place: " + fault + ", and " + fakeLines
	if s := tr.Status(); taken || err == nil || err.Error() != want || s.Unready != stopping || s.Err != want {
		t.Errorf("the stop reported the write taken %v, returned %v and reads %q and the error %q, want none taken, %q and %q", taken, err, s.Unready, s.Err, stopping, want)
	}
	if got := be.specs(); !slices.Equal(got, held) {
		t.Errorf("the host holds %q, want the running rules %q", got, held)
	}
}

// A stop the host refuses over the stopped rules it already holds, as a stop
// tried again after another writer's change meets, finds every stopped rule in
// its readback. Status's reason names the refusal and then the fault, without
// the words that the stopped rules are not in place. The error names the
// refusal and then the fault. The host holds the stopped rules.
func TestRefusedStopOverTheStoppedRulesItHoldsSaysNothingOfThemOutOfPlace(t *testing.T) {
	be := &fakeBackend{}
	tr := translator(t, egress.Egress{Advertise: prefixes(t, "0.0.0.0/0", "::/0")}, Runtime{}, be)
	if err := tr.reconcile(); err != nil {
		t.Fatal(err)
	}
	if taken, err := tr.stop(); !taken || err != nil {
		t.Fatalf("the first stop reported the write taken %v and returned %v, want it taken", taken, err)
	}
	const fault = "its set untranslated6 reads back with flags 0x0, where flags 0x4 were written, and chain other holds a rule using it, so it stays until that rule goes"
	be.faults, be.stuck, be.failStop = map[uint8]string{egress.FamilyIPv6: fault}, true, true
	held := be.specs()
	taken, err := tr.stop()
	want := "install rules: no, then the stopped rules read back other than written: " + fault
	const stopping = "the translator is stopping: the host refused the stopped rules: " + fault
	if s := tr.Status(); taken || err == nil || err.Error() != want || s.Unready != stopping || s.Err != want {
		t.Errorf("the stop tried again reported the write taken %v, returned %v and reads %q and the error %q, want none taken, %q and %q", taken, err, s.Unready, s.Err, stopping, want)
	}
	if got := be.specs(); !slices.Equal(got, held) || !slices.Equal(got, specsOf(tr.stopped())) {
		t.Errorf("the host holds %q, want the stopped rules %q", got, specsOf(tr.stopped()))
	}
}

// A stop the host refuses over the stopped rules it holds in a table another
// writer made dormant, which runs none of its chains, reads them not in place.
// Status's reason names the refusal, the words that the stopped rules are not
// in place, the held set and then the dormant flag, and the error names the
// refusal, the set and the flag. The host holds the stopped rules.
func TestRefusedStopInADormantTableSaysItsRulesAreNotInPlace(t *testing.T) {
	be := &fakeBackend{}
	tr := translator(t, egress.Egress{Advertise: prefixes(t, "0.0.0.0/0", "::/0")}, Runtime{}, be)
	if err := tr.reconcile(); err != nil {
		t.Fatal(err)
	}
	if taken, err := tr.stop(); !taken || err != nil {
		t.Fatalf("the first stop reported the write taken %v and returned %v, want it taken", taken, err)
	}
	const (
		held    = "its set untranslated6 reads back with flags 0x0, where flags 0x4 were written, and chain other holds a rule using it, so it stays until that rule goes"
		dormant = "its table carries flags 0x1, where none are written and 0x1 is dormant"
	)
	be.faults, be.refusing, be.stuck, be.failStop, be.dormant = map[uint8]string{egress.FamilyIPv6: held}, true, true, true, dormant
	taken, err := tr.stop()
	want := "install rules: no, then the stopped rules read back other than written: " + held + ", and " + dormant
	const stopping = "the translator is stopping: the host refused the stopped rules, which are not in place: " + held + ", and " + dormant
	if s := tr.Status(); taken || err == nil || err.Error() != want || s.Unready != stopping || s.Err != want {
		t.Errorf("the stop tried again reported the write taken %v, returned %v and reads %q and the error %q, want none taken, %q and %q", taken, err, s.Unready, s.Err, stopping, want)
	}
	if got := be.specs(); !slices.Equal(got, specsOf(tr.stopped())) {
		t.Errorf("the host holds %q, want the stopped rules %q", got, specsOf(tr.stopped()))
	}
}

// A stop the host refuses over the stopped rules it holds beside a line
// another writer put in a family's chains, IPv4's or IPv6's alone, reads them
// not in place: Status's reason names the refusal, the words that they are
// not in place, the held set and then how the chains read back.
func TestRefusedStopBesideAnotherWritersLineSaysItsRulesAreNotInPlace(t *testing.T) {
	const held = "its set untranslated4 reads back with flags 0x0, where flags 0x4 were written, and chain other holds a rule using it, so it stays until that rule goes"
	for _, c := range []struct {
		name   string
		family uint8
		chain  string
	}{
		{"a line in IPv4's chain", egress.FamilyIPv4, LimitChain},
		{"a line in IPv6's chain alone", egress.FamilyIPv6, familyChain(egress.FamilyIPv6)},
	} {
		t.Run(c.name, func(t *testing.T) {
			be := &fakeBackend{}
			tr := translator(t, egress.Egress{Advertise: prefixes(t, "0.0.0.0/0", "::/0")}, Runtime{}, be)
			if err := tr.reconcile(); err != nil {
				t.Fatal(err)
			}
			if taken, err := tr.stop(); !taken || err != nil {
				t.Fatalf("the first stop reported the write taken %v and returned %v, want it taken", taken, err)
			}
			be.decoys = []Installed{{Family: c.family, Chain: c.chain, Counted: true}}
			be.faults, be.refusing, be.stuck, be.failStop = map[uint8]string{egress.FamilyIPv4: held}, true, true, true
			taken, err := tr.stop()
			want := "install rules: no, then the stopped rules read back other than written: " + held + ", and " + fakeLines
			const stopping = "the translator is stopping: the host refused the stopped rules, which are not in place: " + held + ", and " + fakeLines
			if s := tr.Status(); taken || err == nil || err.Error() != want || s.Unready != stopping || s.Err != want {
				t.Errorf("the stop tried again reported the write taken %v, returned %v and reads %q and the error %q, want none taken, %q and %q", taken, err, s.Unready, s.Err, stopping, want)
			}
		})
	}
}

// A stop the host refuses over the stopped rules it holds, where a set of
// untranslated sources a stopped rule looks up reads back with elements
// another writer added, IPv4's or IPv6's, reads them not in place: Status's
// reason names the refusal, the words that they are not in place, the other
// family's held set and then the refilled one.
func TestRefusedStopOverARefilledSetSaysItsRulesAreNotInPlace(t *testing.T) {
	for _, c := range []struct {
		name           string
		refilled, held uint8
		refill, fault  string
	}{
		{"IPv4's set refilled", egress.FamilyIPv4, egress.FamilyIPv6, "its set untranslated4 holds { 192.0.2.2, 198.51.100.0/24 }, where { 198.51.100.0/24 } was written",
			"its set untranslated6 reads back with flags 0x0, where flags 0x4 were written, and chain other holds a rule using it, so it stays until that rule goes"},
		{"IPv6's set refilled", egress.FamilyIPv6, egress.FamilyIPv4, "its set untranslated6 holds { 3fff::2, 2001:db8::/32 }, where { 2001:db8::/32 } was written",
			"its set untranslated4 reads back with flags 0x0, where flags 0x4 were written, and chain other holds a rule using it, so it stays until that rule goes"},
	} {
		t.Run(c.name, func(t *testing.T) {
			be := &fakeBackend{}
			tr := translator(t, egress.Egress{Advertise: prefixes(t, "0.0.0.0/0", "::/0")}, Runtime{}, be)
			if err := tr.reconcile(); err != nil {
				t.Fatal(err)
			}
			if taken, err := tr.stop(); !taken || err != nil {
				t.Fatalf("the first stop reported the write taken %v and returned %v, want it taken", taken, err)
			}
			be.refilled = map[uint8]string{c.refilled: c.refill}
			be.faults, be.refusing, be.stuck, be.failStop = map[uint8]string{c.held: c.fault}, true, true, true
			taken, err := tr.stop()
			want := "install rules: no, then the stopped rules read back other than written: " + c.fault + ", and " + c.refill
			stopping := "the translator is stopping: the host refused the stopped rules, which are not in place: " + c.fault + ", and " + c.refill
			if s := tr.Status(); taken || err == nil || err.Error() != want || s.Unready != stopping || s.Err != want {
				t.Errorf("the stop tried again reported the write taken %v, returned %v and reads %q and the error %q, want none taken, %q and %q", taken, err, s.Unready, s.Err, stopping, want)
			}
		})
	}
}

// Rules another writer put in the translator's chains under the comments of
// the stopped rules a running translator lacks, which do something else, are
// none of the stopped rules. A stop whose write must delete a set another
// writer holds beside them, and which the host refuses, says the stopped rules
// are not in place, after the refusal where the answer read as one and alone
// where the refusal's acknowledgments overflowed the socket, and names the set
// and then the chains holding the decoys. The host holds the running rules and
// those decoys.
func TestStopFindsTheStoppedRulesByWhatTheyDoNotByTheirComments(t *testing.T) {
	const fault = "its set untranslated4 reads back with flags 0x0, where flags 0x4 were written, and chain other holds a rule using it, so it stays until that rule goes"
	for _, c := range []struct {
		name     string
		overflow bool
		stopping string
	}{
		{"a refusal acknowledged", false, "the translator is stopping: the host refused the stopped rules, which are not in place: " + fault + ", and " + fakeLines},
		{"a refusal whose acknowledgments overflowed", true, "the translator is stopping: the stopped rules are not in place: " + fault + ", and " + fakeLines},
	} {
		t.Run(c.name, func(t *testing.T) {
			be := &fakeBackend{}
			tr := translator(t, egress.Egress{Advertise: prefixes(t, "0.0.0.0/0", "::/0")}, Runtime{}, be)
			if err := tr.reconcile(); err != nil {
				t.Fatal(err)
			}
			running := be.specs()
			for _, rule := range placed(tr.stopped()) {
				if !slices.Contains(running, rule.Spec) {
					rule.Counted = true
					be.decoys = append(be.decoys, rule)
				}
			}
			if len(be.decoys) == 0 {
				t.Fatal("every stopped rule carries a running rule's comment, so no decoy can stand in for one")
			}
			be.faults, be.stuck, be.failStop, be.overflowStop = map[uint8]string{egress.FamilyIPv4: fault}, true, !c.overflow, c.overflow
			taken, err := tr.stop()
			want := "install rules: no, then the stopped rules read back other than written: " + fault + ", and " + fakeLines
			if s := tr.Status(); taken || err == nil || err.Error() != want || s.Unready != c.stopping || s.Err != want {
				t.Errorf("the stop reported the write taken %v, returned %v and reads %q and the error %q, want none taken, %q and %q", taken, err, s.Unready, s.Err, c.stopping, want)
			}
			if got := be.specs(); !slices.Equal(got, running) || len(be.decoys) == 0 {
				t.Errorf("the host holds %q and %d decoys, want the running rules %q and the decoys", got, len(be.decoys), running)
			}
		})
	}
}

// A stop names the fault of a family's set or object that its write is
// refused on ahead of any family's lines, IPv6's among them. A flag of the
// table's that the write is refused for stays first. A stray chain or an
// object of an earlier version that every family's fault starts with comes
// after any family's set or object the write is refused on, held or not. Where
// no family has a held one, IPv4's fault goes first. IPv4's stale set that
// nothing holds comes after IPv6's held one. After that cause come the table's
// dormant flag and then the first family's misplaced chain, set or object,
// IPv4's then IPv6's, each where it is not the cause or already named.
func TestStopFaultNamesAHeldObjectAheadOfTheLines(t *testing.T) {
	const (
		lines    = "its chain forward holds the running lines where the stopped ones were written"
		held     = "its set untranslated6 reads back with flags 0x0, where flags 0x4 were written, and chain other holds a rule using it, so it stays until that rule goes"
		table    = "its table carries flags 0x4, where none are written and 0x1 is dormant"
		stale    = "its set untranslated4 reads back with flags 0x0, where flags 0x4 were written"
		stray    = "its chain forward4 is not one the translator writes"
		leftover = "its ct timeout translated-udp4 is not one the translator writes, and chain other holds a rule using it, so it stays until that rule goes"
		held4    = "its set untranslated4 reads back with flags 0x0, where flags 0x4 were written, and chain other holds a rule using it, so it stays until that rule goes"
		dormant  = "its table carries flags 0x1, where none are written and 0x1 is dormant"
		both     = "its table carries flags 0x5, where none are written and 0x1 is dormant, and only nft delete table inet ranet3 clears another"
		lines6   = "its chain forward6 holds the stopped lines after a line with no comment"
		refill6  = "its set untranslated6 holds { 3fff::2 }, where { } was written"
	)
	for _, c := range []struct {
		name string
		read map[uint8]chainReadback
		want string
	}{
		{"IPv6's held set", map[uint8]chainReadback{egress.FamilyIPv4: {fault: lines}, egress.FamilyIPv6: {fault: held, refusedOn: held}}, held},
		{"the table's flag", map[uint8]chainReadback{egress.FamilyIPv4: {fault: table, flag: table}, egress.FamilyIPv6: {fault: table, flag: table, refusedOn: held}}, table},
		{"lines alone", map[uint8]chainReadback{egress.FamilyIPv4: {fault: lines}, egress.FamilyIPv6: {fault: "its chain forward6 is missing"}}, lines},
		{"IPv4's stale set beside IPv6's held one", map[uint8]chainReadback{egress.FamilyIPv4: {fault: stale}, egress.FamilyIPv6: {fault: held, refusedOn: held}}, held},
		{"a stray chain beside IPv6's held set", map[uint8]chainReadback{egress.FamilyIPv4: {fault: stray}, egress.FamilyIPv6: {fault: stray, refusedOn: held}}, held},
		{"a held timeout of an earlier version beside IPv4's held set", map[uint8]chainReadback{egress.FamilyIPv4: {fault: leftover, refusedOn: held4}, egress.FamilyIPv6: {fault: leftover}}, held4},
		{"a stray chain alone", map[uint8]chainReadback{egress.FamilyIPv4: {fault: stray}, egress.FamilyIPv6: {fault: stray}}, stray},
		{"the dormant flag beside IPv6's held set", map[uint8]chainReadback{egress.FamilyIPv4: {fault: dormant, dormant: dormant}, egress.FamilyIPv6: {fault: dormant, dormant: dormant, refusedOn: held}}, held + ", and " + dormant},
		{"the dormant flag beside another flag", map[uint8]chainReadback{egress.FamilyIPv4: {fault: both, flag: both, dormant: both}, egress.FamilyIPv6: {fault: both, flag: both, dormant: both, refusedOn: held}}, both},
		{"the dormant flag beside a stray chain", map[uint8]chainReadback{egress.FamilyIPv4: {fault: stray, dormant: dormant}, egress.FamilyIPv6: {fault: stray, dormant: dormant}}, stray + ", and " + dormant},
		{"the dormant flag alone", map[uint8]chainReadback{egress.FamilyIPv4: {fault: dormant, dormant: dormant}, egress.FamilyIPv6: {fault: dormant, dormant: dormant}}, dormant},
		{"lines beside IPv6's held set", map[uint8]chainReadback{egress.FamilyIPv4: {fault: lines, misplaced: lines}, egress.FamilyIPv6: {fault: held, refusedOn: held, misplaced: lines}}, held + ", and " + lines},
		{"IPv6's lines alone beside IPv4's held set", map[uint8]chainReadback{egress.FamilyIPv4: {fault: held4, refusedOn: held4}, egress.FamilyIPv6: {fault: lines6, misplaced: lines6}}, held4 + ", and " + lines6},
		{"IPv6's refilled set beside IPv4's held set", map[uint8]chainReadback{egress.FamilyIPv4: {fault: held4, refusedOn: held4}, egress.FamilyIPv6: {fault: refill6, misplaced: refill6}}, held4 + ", and " + refill6},
		{"the dormant flag and lines beside IPv6's held set", map[uint8]chainReadback{egress.FamilyIPv4: {fault: dormant, dormant: dormant, misplaced: lines}, egress.FamilyIPv6: {fault: dormant, dormant: dormant, refusedOn: held, misplaced: lines}}, held + ", and " + dormant + ", and " + lines},
		{"a held set the stopped rules use", map[uint8]chainReadback{egress.FamilyIPv4: {fault: held4, refusedOn: held4, misplaced: held4}}, held4},
	} {
		if got := stopFault(c.read); got != c.want {
			t.Errorf("%s: the stop names %q, want %q", c.name, got, c.want)
		}
	}
}

// At shutdown the translator waits for the mesh to close, then reads whether
// the mesh device is still there and withdraws only where it has gone. Where
// it outlives the mesh, or whether it does cannot be read, the shutdown ends as
// a down does, the stopped rules written or left in place and nothing
// withdrawn, and says why at warn, with the error of a stop whose rules read
// back with a fault, which Run returns. A write the host answers with an error
// after it took it, as one whose acknowledgments overflow the socket, is the
// same where its rules read back as written. A stop the host refuses there
// leaves what the host held, and one answered with an error whose rules cannot
// be read back after it what the host took or held: either warns of no
// stopped rules, and Run returns why, a refusal beside how the rules read
// back. The warning says the stopped rules hold the exit only where the stop
// read them in place, and otherwise that they did not read back in place,
// Run's error naming how.
func TestShutdownWithdrawsOnlyWhereTheMeshDeviceIsGone(t *testing.T) {
	unread := errors.New("no")
	const (
		fault  = "its chains read back other than they were written"
		refill = "its set untranslated4 holds { 192.0.2.2 }, where { } was written"
	)
	for name, c := range map[string]struct {
		down, present bool
		absent        error
		// faulted makes the stop's rules read back with a fault, refilled with
		// a set they use read back otherwise than written, refused the host
		// refuse them, lost the host answer their write with an error after it
		// took it, and unlisted then fail their readback
		faulted, refilled, refused, lost, unlisted bool
		// keeps is the warning's reason for the stopped rules, empty for a
		// withdrawal, and fails what Run's error holds, empty for none
		keeps, fails string
	}{
		"the device gone with the mesh":            {},
		"the device outliving the mesh":            {present: true, keeps: "the mesh device ranet0 outlives the mesh"},
		"down, the device outliving the mesh":      {down: true, present: true, keeps: "the mesh device ranet0 outlives the mesh"},
		"the device's presence unread":             {absent: unread, keeps: "whether the mesh device ranet0 outlives the mesh could not be read: no"},
		"the stopped rules read back with faults":  {present: true, faulted: true, keeps: "the mesh device ranet0 outlives the mesh", fails: fault},
		"the stopped rules read back out of place": {present: true, refilled: true, keeps: "the mesh device ranet0 outlives the mesh", fails: refill},
		"the stop's answer lost":                   {present: true, lost: true, keeps: "the mesh device ranet0 outlives the mesh"},
		"the stop taken, not read back":            {present: true, unlisted: true, keeps: "the mesh device ranet0 outlives the mesh", fails: "list rules: no"},
		"the stop refused":                         {present: true, refused: true, fails: "the shutdown saw no write of the stopped rules taken: install rules: no, then the stopped rules read back other than written: " + fault},
		"the stop's answer lost, not read back":    {present: true, lost: true, unlisted: true, fails: "the shutdown saw no write of the stopped rules taken: install rules: no, then list rules: no"},
	} {
		t.Run(name, bubble.Run(func(t *testing.T) {
			var lines strings.Builder
			logtest.SetDefault(t, slog.New(slog.NewTextHandler(&lines, nil)))
			be := &fakeBackend{}
			var reads atomic.Int32
			closed := make(chan struct{})
			rt := Runtime{Done: closed, Present: func() (bool, error) { reads.Add(1); return c.present, c.absent }}
			tr := translator(t, egress.Egress{Advertise: prefixes(t, "0.0.0.0/0", "::/0")}, rt, be)
			turn := tr.reconcile
			if c.down {
				tr.Enabled.Store(false)
				turn = func() error { return stopTurn(tr) }
			}
			if err := turn(); err != nil {
				t.Fatal(err)
			}
			held := be.specs()
			be.failStop, be.loseStop, be.failReadback = c.refused, c.lost, c.unlisted
			if c.faulted {
				be.faults, be.stuck = map[uint8]string{egress.FamilyIPv6: fault}, true
			}
			if c.refilled {
				be.refilled, be.stuck = map[uint8]string{egress.FamilyIPv4: refill}, true
			}
			ran := make(chan error, 1)
			go func() { ran <- endedAtOnce(tr) }()
			// every goroutine of the bubble is blocked, Run on the mesh's done
			// channel alone
			synctest.Wait()
			select {
			case <-ran:
				t.Fatal("Run returned before the mesh closed")
			default:
			}
			if n := reads.Load(); n != 0 {
				t.Errorf("the device's presence was read %d times before the mesh closed, want none", n)
			}
			close(closed)
			err := <-ran
			got := lines.String()
			left := strings.Count(got, `level=WARN msg="egress left its stopped rules at shutdown"`)
			misplaced := strings.Count(got, `level=WARN msg="egress left its stopped rules at shutdown, which did not read back in place"`)
			hold := strings.Contains(got, "they hold the exit as ranet3 down does")
			inPlace := !c.refilled && !c.unlisted
			if !inPlace {
				left, misplaced = misplaced, left
			}
			if misplaced != 0 || c.keeps != "" && hold != inPlace {
				t.Errorf("the shutdown warned %d times with the other line and said the stopped rules hold the exit %v, want neither where they did not read back in place and only the latter where they did:\n%s", misplaced, hold, got)
			}
			want, withdrawals := specsOf(tr.stopped()), 0
			switch {
			case c.keeps == "" && c.fails == "":
				want, withdrawals = nil, 1
			case c.refused:
				want = held
			}
			if c.fails == "" && err != nil || c.fails != "" && (err == nil || !strings.Contains(err.Error(), c.fails)) {
				t.Errorf("Run returned %v, want an error holding %q, or none where that is empty", err, c.fails)
			}
			if be.withdrawn != withdrawals || !slices.Equal(be.specs(), want) {
				t.Errorf("the shutdown withdrew %d times and left %q, want %d withdrawals and %q", be.withdrawn, be.specs(), withdrawals, want)
			}
			switch {
			case c.keeps == "" && left != 0:
				t.Errorf("the shutdown warned %d times that it left the stopped rules, want none:\n%s", left, got)
			case c.keeps != "" && (left != 1 || !strings.Contains(got, c.keeps) || c.faulted && !strings.Contains(got, fault)):
				t.Errorf("the shutdown warned %d times that it left the stopped rules, want once, naming %q and the fault where they read back with one:\n%s", left, c.keeps, got)
			}
			if c.keeps != "" && c.fails != "" && !inPlace {
				// the line's err alone tells rules read back otherwise from rules not read
				var carries bool
				for line := range strings.Lines(got) {
					_, attrs, warned := strings.Cut(line, `level=WARN msg="egress left its stopped rules at shutdown, which did not read back in place"`)
					_, cause, ok := strings.Cut(attrs, " err=")
					carries = carries || warned && ok && strings.Contains(cause, c.fails)
				}
				if !carries {
					t.Errorf("the shutdown's warning carries no err holding %q:\n%s", c.fails, got)
				}
			}
		}))
	}
}

// A running translator taken down while the host refuses the stop leaves what
// the host held as it was, withdrawing nothing, and Status reads at every try,
// each retry's among them, that the stop has not taken effect: both families
// not ready for the stop under way, from the first refusal on with how the
// rules the host holds read back, those rules, and the last refusal beside how
// they read back. The retry the refusal takes writes the stopped rules once
// the host takes them, and Status reads the stop in effect with them counted.
// Taken up and down again it records its second stop as its first, and each up
// logs that the translator started again once, whatever passes follow it.
func TestRefusedStopIsRetried(t *testing.T) {
	var lines strings.Builder
	logtest.SetDefault(t, slog.New(slog.NewTextHandler(&lines, nil)))
	be := &fakeBackend{changed: make(chan struct{}, 1)}
	tr := translator(t, egress.Egress{Advertise: prefixes(t, "0.0.0.0/0", "::/0"), Sweep: schema.Duration(lateSweep)}, Runtime{Events: events.New()}, be)
	be.seen = func() string {
		s := tr.Status()
		return fmt.Sprintf("status %v %v %s, %d installed, error %q", s.Ready4, s.Ready6, s.Unready, s.Rules.Installed, s.Err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- tr.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	await := awaiting(t, be, tr)
	ready := func() bool { s := tr.Status(); return s.Ready4 && s.Ready6 }
	stopped := func() bool {
		s := tr.Status()
		return s.Unready == "the translator is stopped" && s.Err == "" && s.Rules.Installed == len(tr.stopped()) && slices.Equal(be.specs(), specsOf(tr.stopped()))
	}
	refused := func() bool { return tr.Status().Err != "" }
	failStop := func(fail bool) {
		be.mu.Lock()
		be.failStop = fail
		be.mu.Unlock()
	}
	await("the first pass", ready)
	held := be.specs()
	stopping := fmt.Sprintf("status false false the translator is stopping, %d installed, error ", len(held))
	// the running translator's rules a refusal leaves read back other than a
	// stopped one's
	const differ = "its chains read back other than they were written"
	refusal := fmt.Sprintf("status false false the translator is stopping: the host refused the stopped rules, which are not in place: %s, %d installed, error %q", differ, len(held), "install rules: no, then the stopped rules read back other than written: "+differ)
	// first holds the Status read at each stop's first write
	var first []string
	for range 2 {
		failStop(true)
		mark := len(be.entries())
		tr.SetEnabled(false)
		await("the refused stop", refused)
		be.mu.Lock()
		withdrawn := be.withdrawn
		be.mu.Unlock()
		if got := be.specs(); !slices.Equal(got, held) || withdrawn != 0 {
			t.Errorf("a refused stop left %q after %d withdrawals, want %q as it was and none", got, withdrawn, held)
		}
		// the sweep is out past the wait and nothing else wakes the run, so
		// only the retry the refusal takes can write the stopped rules
		failStop(false)
		await("the retry to write the stopped rules", stopped)
		var tries []string
		for _, entry := range be.entries()[mark:] {
			if strings.HasPrefix(entry, "status ") {
				tries = append(tries, entry)
			}
		}
		if len(tries) < 2 {
			t.Fatalf("the stop wrote %d times, want a refusal and its retry", len(tries))
		}
		if tries[0] != stopping+`""` || slices.ContainsFunc(tries[1:], func(entry string) bool { return entry != refusal }) {
			t.Errorf("Status read at each try %q, want %q at the first and %q at each after it", tries, stopping+`""`, refusal)
		}
		first = append(first, tries[0])
		tr.SetEnabled(true)
		await("the pass after up", ready)
		// a pass more after up, which logs nothing of the stop
		at := tr.Status().PassAt
		be.changed <- struct{}{}
		await("the pass after another writer's change", func() bool { return ready() && tr.Status().PassAt.After(at) })
	}
	if first[0] != first[1] {
		t.Errorf("Status read at each stop's first write %q, want the second stop's as the first's", first)
	}
	if again := strings.Count(lines.String(), `msg="egress translator started again"`); again != 2 {
		t.Errorf("two ups logged the translator started again %d times, want 2:\n%s", again, lines.String())
	}
}

// Another writer's change logs the families not ready at warn, where a stop
// logs them at info (TestStoppingReportsTheEgressSegmentsNotReadyFirst)
func TestAnotherWritersChangeLogsNotReadyAtWarn(t *testing.T) {
	cfg := egress.Egress{Advertise: prefixes(t, "0.0.0.0/0", "::/0")}
	count := func(lines, level, message string) int {
		return strings.Count(lines, "level="+level+" msg=\""+message+"\"")
	}
	var lines strings.Builder
	logtest.SetDefault(t, slog.New(slog.NewTextHandler(&lines, nil)))
	ctx, cancel := context.WithCancel(context.Background())
	be := &fakeBackend{changed: make(chan struct{}, 1)}
	be.changed <- struct{}{}
	// the change reports both families not ready, which ends the run, so Run
	// returns on this goroutine
	rt := Runtime{Ready: func(v4, v6, _ bool) {
		if !v4 && !v6 {
			cancel()
		}
	}}
	cfg.Sweep = schema.Duration(lateSweep)
	tr := translator(t, cfg, rt, be)
	if err := tr.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := lines.String(); count(got, "WARN", "egress not ready") != 2 || count(got, "INFO", "egress not ready") != 0 {
		t.Errorf("another writer's change logged other than both families not ready at warn:\n%s", got)
	}
}

// readyRecorded is each egress.ready bus recorded but those of a stop for
// stopped, as its ipv4, ipv6 and reason
func readyRecorded(bus *events.Bus, stopped string) []string {
	var out []string
	for _, event := range bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "egress.ready" }, 0) {
		if event.Attrs["reason"] != stopped {
			out = append(out, event.Attrs["ipv4"]+" "+event.Attrs["ipv6"]+" "+event.Attrs["reason"])
		}
	}
	return out
}

// A translator started down that another writer's change wakes before
// `ranet3 up`, a firewall reload flushing the shared table for one, logs no
// family while it is down, and its first pass after `ranet3 up` logs each
// family not ready at warn once and records egress.ready for that pass
func TestChangeWhileStartedDownLeavesTheFirstPassFirst(t *testing.T) {
	var lines strings.Builder
	logtest.SetDefault(t, slog.New(slog.NewTextHandler(&lines, nil)))
	bus := events.New()
	ctx, cancel := context.WithCancel(context.Background())
	be := &fakeBackend{changed: make(chan struct{}, 1)}
	// the first pass publishes the empty announcement, which ends the run, so
	// the log is read once Run has returned
	rt := Runtime{Events: bus, Forwarding: func() (bool, bool) { return false, false }, Republish: cancel}
	tr := translator(t, egress.Egress{Advertise: prefixes(t, "0.0.0.0/0", "::/0"), Sweep: schema.Duration(lateSweep)}, rt, be)
	tr.Enabled.Store(false)
	var runErr error
	ended := make(chan struct{})
	go func() {
		runErr = tr.Run(ctx)
		close(ended)
	}()
	t.Cleanup(func() {
		cancel()
		<-ended
	})
	await := awaiting(t, be, tr)
	await("the stop", func() bool { return tr.Status().Unready == "the translator is stopped" })
	be.changed <- struct{}{}
	await("the change taken", func() bool { return len(be.changed) == 0 })
	tr.SetEnabled(true)
	select {
	case <-ended:
	case <-time.After(PassWait):
		t.Fatalf("the translator ran no pass after ranet3 up, it went %q", be.entries())
	}
	if runErr != nil {
		t.Fatal(runErr)
	}
	got := lines.String()
	if strings.Contains(got, "another writer changed its table") {
		t.Errorf("the change logged readiness for an exit that is down:\n%s", got)
	}
	for _, family := range []string{"ipv4", "ipv6"} {
		want := `level=WARN msg="egress not ready" family=` + family + ` detail="the kernel does not forward ` + family + `"`
		if n := strings.Count(got, want); n != 1 {
			t.Errorf("the first pass logged %s not ready %d times at warn, want once:\n%s", family, n, got)
		}
	}
	want := []string{"false false ipv4 the kernel does not forward ipv4, ipv6 the kernel does not forward ipv6"}
	if got := readyRecorded(bus, "the translator is stopping"); !slices.Equal(got, want) {
		t.Errorf("recorded egress.ready %q, want %q", got, want)
	}
}

// A first pass that fails, on a host whose chains cannot be listed, still
// judged the exit, so it logs each family not ready at warn with the failure's
// reason and records egress.ready once
func TestFailedFirstPassLogsEachFamilyAtWarn(t *testing.T) {
	var lines strings.Builder
	logtest.SetDefault(t, slog.New(slog.NewTextHandler(&lines, nil)))
	bus := events.New()
	tr := translator(t, egress.Egress{Advertise: prefixes(t, "0.0.0.0/0", "::/0")}, Runtime{Events: bus}, &fakeBackend{failRules: true})
	if err := tr.reconcile(); err == nil {
		t.Fatal("the pass reported no error")
	}
	const why = "its chains could not be read back"
	for _, family := range []string{"ipv4", "ipv6"} {
		want := `level=WARN msg="egress not ready" family=` + family + ` detail="` + why + `"`
		if n := strings.Count(lines.String(), want); n != 1 {
			t.Errorf("the failed first pass logged %s not ready %d times at warn, want once:\n%s", family, n, lines.String())
		}
	}
	if got, want := readyRecorded(bus, ""), []string{"false false " + why}; !slices.Equal(got, want) {
		t.Errorf("the failed first pass recorded egress.ready %q, want %q", got, want)
	}
}

// A pass that narrows the announcement, a family the host stopped forwarding,
// logs the advertisement's change at warn, since a prefix leaving it is an
// exit going away
func TestNarrowerAnnouncementLogsAtWarn(t *testing.T) {
	var lines strings.Builder
	logtest.SetDefault(t, slog.New(slog.NewTextHandler(&lines, nil)))
	forwards6 := true
	rt := Runtime{Forwarding: func() (bool, bool) { return true, forwards6 }}
	tr := translator(t, egress.Egress{Advertise: prefixes(t, "0.0.0.0/0", "::/0")}, rt, &fakeBackend{})
	if err := tr.reconcile(); err != nil {
		t.Fatal(err)
	}
	forwards6 = false
	if err := tr.reconcile(); err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(lines.String(), `level=WARN msg="egress advertisement changed"`); got != 1 {
		t.Errorf("the narrower announcement logged the change %d times at warn, want once:\n%s", got, lines.String())
	}
}

// Another writer changing the translator's chains, a firewall reload flushing
// the ruleset for one, wakes the translator, which reports the egress segments
// not ready before the pass that puts the rules back and ready again after
// it, with no sweep due
func TestAnotherWritersChangeStopsTheMeshUntilThePassRestoresIt(t *testing.T) {
	bus := events.New()
	tr, be := readyLog(t, egress.Egress{Sweep: schema.Duration(lateSweep)}, bus)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- tr.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	ready := func(times int) {
		t.Helper()
		for deadline := time.Now().Add(PassWait); ; time.Sleep(passPoll) {
			if strings.Count(strings.Join(be.entries(), ","), "ready true true sid true") >= times {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("the translator went %q, want ready %d times", be.entries(), times)
			}
		}
	}
	ready(1)
	be.mu.Lock()
	be.held = nil
	be.mu.Unlock()
	mark := len(be.entries())
	be.changed <- struct{}{}
	ready(2)
	after := be.entries()[mark:]
	if want := []string{"ready false false sid false", "rules", "apply", "rules", "ready true true sid true"}; !slices.Equal(after, want) {
		t.Errorf("after the change the translator went %q, want %q", after, want)
	}
	if triggers, named := passTriggers(bus, "changed"); !named {
		t.Errorf("the passes were woken by %q, none by the change", triggers)
	}
}

// passTriggers reads the trigger of each pass bus recorded, and whether one names want within PassWait
// a pass records its event after its last call of the backend, and a backend's log can hold a pass that bus does not yet
func passTriggers(bus *events.Bus, want string) ([]string, bool) {
	for deadline := time.Now().Add(PassWait); ; time.Sleep(passPoll) {
		var triggers []string
		for _, event := range bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "egress.pass" }, 0) {
			triggers = append(triggers, event.Attrs["trigger"])
		}
		if named := slices.Contains(triggers, want); named || time.Now().After(deadline) {
			return triggers, named
		}
	}
}

// Notifications the backend lost, which another table's large transaction
// overflows the socket with as readily as a flush of this one, wake a pass
// with no sweep due and leave the egress segments ready, since that pass reads
// the rules back and finds whatever a lost deletion took
func TestMissedNotificationsWakeAPassAndLeaveReadinessAlone(t *testing.T) {
	bus := events.New()
	tr, be := readyLog(t, egress.Egress{Sweep: schema.Duration(lateSweep)}, bus)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- tr.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	settled := func(mark int, entries ...string) []string {
		t.Helper()
		for deadline := time.Now().Add(PassWait); ; time.Sleep(passPoll) {
			if after := be.entries()[mark:]; slices.Equal(after, entries) {
				return after
			}
			if time.Now().After(deadline) {
				t.Fatalf("the translator went %q, want %q", be.entries()[mark:], entries)
			}
		}
	}
	settled(0, "rules", "apply", "rules", "ready true true sid true", "retract")
	be.mu.Lock()
	be.held = nil
	be.mu.Unlock()
	mark := len(be.entries())
	be.missed <- struct{}{}
	settled(mark, "rules", "apply", "rules")
	if triggers, named := passTriggers(bus, "missed"); !named {
		t.Errorf("the passes were woken by %q, none by the lost notifications", triggers)
	}
}

// A host that stops forwarding a family whose egress segments are already not
// ready, its table here left dormant, leaves the readiness pair as it was, and
// the translator still hands Ready the SID decision that the change moved,
// both ways
func TestForwardingMovingAloneHandsReadyTheSIDDecision(t *testing.T) {
	tr, be := readyLog(t, egress.Egress{}, events.New())
	forwards4 := true
	tr.rt.Forwarding = func() (bool, bool) { return forwards4, true }
	be.faults, be.stuck = map[uint8]string{egress.FamilyIPv4: "its table carries flags 0x1, where none are written and 0x1 is dormant"}, true
	for _, step := range []struct {
		forwards4 bool
		want      string
	}{
		{true, "ready false true sid false"},
		{false, "ready false true sid true"},
		{false, ""},
		{true, "ready false true sid false"},
	} {
		forwards4 = step.forwards4
		mark := len(be.entries())
		if err := tr.reconcile(); err != nil {
			t.Fatal(err)
		}
		var moved []string
		for _, entry := range be.entries()[mark:] {
			if strings.HasPrefix(entry, "ready") {
				moved = append(moved, entry)
			}
		}
		if step.want != "" && !slices.Equal(moved, []string{step.want}) || step.want == "" && len(moved) != 0 {
			t.Errorf("a pass with IPv4 forwarding %v handed Ready %q, want %q", step.forwards4, moved, step.want)
		}
	}
}

// Another writer's translation is named rather than removed. Several chains
// coexist at the same hook and the first to claim a connection keeps it, so a
// tool that deleted its neighbors' rules would break whatever installed them.
func TestConflictsAreReportedRatherThanRemoved(t *testing.T) {
	cfg := egress.Egress{Advertise: prefixes(t, "0.0.0.0/0")}
	be := &fakeBackend{conflicts: []string{"ip table nat chain POSTROUTING at priority 100"}}
	tr := translator(t, cfg, Runtime{}, be)
	if err := tr.reconcile(); err != nil {
		t.Fatal(err)
	}
	if got := tr.lastPass().Conflicts; !slices.Equal(got, be.conflicts) {
		t.Errorf("reported %q, want %q", got, be.conflicts)
	}
	if got := tr.Announce(); len(got) != 1 {
		t.Errorf("a conflict withheld the advertisement: %v", got)
	}
}

// A pass whose listing of other chains fails between two that list the same
// conflict reports it once, the warning of the first pass standing
func TestConflictsAreReportedOnceAcrossAFailedListing(t *testing.T) {
	var lines strings.Builder
	logtest.SetDefault(t, slog.New(slog.NewTextHandler(&lines, nil)))
	be := &fakeBackend{conflicts: []string{"ip table nat chain POSTROUTING at priority 100"}}
	tr := translator(t, egress.Egress{Advertise: prefixes(t, "0.0.0.0/0")}, Runtime{}, be)
	for _, fails := range []bool{false, true, false} {
		be.mu.Lock()
		be.failConflicts = fails
		be.mu.Unlock()
		if err := tr.reconcile(); (err != nil) != fails {
			t.Fatalf("a pass whose listing fails %v answered %v", fails, err)
		}
	}
	if got := strings.Count(lines.String(), "level=WARN msg=\"egress is sharing the source translation hook with another writer\""); got != 1 {
		t.Errorf("the conflict was warned of %d times, want once:\n%s", got, lines.String())
	}
}

// Status is the last pass beside the capability's translation and the limit on
// each source's flows, with the packets the limit refused and those dropped
// with no tracked flow in each family, and
// with the rules the host holds, their counters, the host's connection table
// and the conflicts as the backend's detail. The flows a class of none carries
// are counted apart from those translated.
func TestStatusIsTheLastPassWithTheRulesAsItsDetail(t *testing.T) {
	cfg := egress.Egress{
		Return:    true,
		Advertise: prefixes(t, "198.51.100.0/24", "::/0"),
		Translate: []egress.Class{
			{From: schema.MustPrefix("0.0.0.0/0"), To: egress.Translation{Addr: netip.MustParseAddr("198.51.100.7")}},
			{From: schema.MustPrefix("192.0.2.0/24"), To: egress.Translation{None: true}},
		},
	}
	be := &fakeBackend{flows: 3, conflicts: []string{"ip table nat chain POSTROUTING at priority 100"}}
	settings := map[string]string{"net/netfilter/nf_conntrack_count": "12", "net/netfilter/nf_conntrack_max": "262144"}
	rt := Runtime{
		MeshAddresses: []netip.Addr{netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("3fff::2")},
		Forwarding:    func() (bool, bool) { return true, false },
		Sysctl:        func(path string) string { return settings[path] },
	}
	tr := translator(t, cfg, rt, be)
	if got := tr.Status(); got.Backend != "nftables" || got.Where != "a fake host" || !got.PassAt.IsZero() || got.Ready4 || got.Ready6 || len(got.Announced) != 0 {
		t.Errorf("before the first pass Status is %+v, want the backend named and nothing ready or announced", got)
	}
	if err := tr.reconcile(); err != nil {
		t.Fatal(err)
	}
	stats := tr.lastPass()
	count, most := uint64(12), uint64(262144)
	want := egress.Status{
		Backend: "nftables", Where: "a fake host",
		Ready4: true, Unready: stats.Unready, Skipped: stats.Skipped,
		Advertise: plain(cfg.Advertise), Announced: plain(cfg.Advertise[:1]),
		Translate: cfg.Translate, Return: true,
		FlowsPerSource: egress.DefaultFlowsPerSource, Refused4: 3, Refused6: 3, Dropped4: 6, Dropped6: 6,
		PassAt: stats.At,
		// in each family the drops of what no flow is tracked for out of the mesh,
		// after ip's pass of none's, and into it, and the limit, in ip the two
		// classes, the address's with its three timeout rules, the return with its
		// three and the own address under none, in ip6 the catch-all, the return
		// and the own address, each with its three timeout rules, each rule but a
		// timeout rule and the pass, which have no counter, read back with the
		// three flows the fake host counts. The counts of ip's ICMP drops and of
		// each family's refusals of DCCP and UDP-Lite reach no field.
		Rules: &egress.Rules{Installed: 41, Flows: 15, Untranslated: 6, ConntrackCount: &count, ConntrackMax: &most, Conflicts: be.conflicts},
	}
	if got := tr.Status(); !reflect.DeepEqual(got, want) {
		t.Errorf("Status is\n%+v\nwant\n%+v", got, want)
	}
	if stats.Unready == "" {
		t.Error("the family the host does not forward is not ready with no reason given")
	}
	clear(settings)
	if err := tr.reconcile(); err != nil {
		t.Fatal(err)
	}
	if got := tr.Status().Rules; got.ConntrackCount != nil || got.ConntrackMax != nil {
		t.Errorf("with conntrack's settings unread Status reads its table at %v of %v, want neither", got.ConntrackCount, got.ConntrackMax)
	}
}

// Egress hands the frames, headroom and all, to the mesh's tun writer as they came, with the hold on their storage, which the writer's lanes keep until they have written them
func TestEgressHandsTheFramesToTheTunWriter(t *testing.T) {
	var written [][][]byte
	var holds []netstack.Hold
	rt := Runtime{Write: func(frames [][]byte, hold netstack.Hold) {
		written, holds = append(written, frames), append(holds, hold)
	}}
	tr := translator(t, egress.Egress{Advertise: prefixes(t, "0.0.0.0/0")}, rt, &fakeBackend{})
	frames := [][]byte{{1, 2, 3}, {4, 5}}
	hold := new(markedHold)
	tr.Egress(frames, hold)
	if len(written) != 1 || len(written[0]) != 2 || &written[0][0][0] != &frames[0][0] || &written[0][1][0] != &frames[1][0] {
		t.Errorf("the writer took %v, want the two frames as Egress was handed them", written)
	}
	if len(holds) != 1 || holds[0] != netstack.Hold(hold) {
		t.Errorf("the writer took the holds %v, want the one Egress was handed", holds)
	}
}

// markedHold is a hold told apart from another by its address, which a field of nonzero size gives it
type markedHold struct{ _ byte }

func (*markedHold) Retain()  {}
func (*markedHold) Release() {}
