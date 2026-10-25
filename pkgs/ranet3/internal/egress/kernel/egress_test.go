// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/schema"
)

// fakeBackend stands in for a kernel. Everything above the backend seam is
// portable, so the diff, the readiness rule and the withdrawal are all
// reachable without a packet filter to write into.
type fakeBackend struct {
	mu        sync.Mutex
	held      []Installed
	conflicts []string
	applied   int
	withdrawn int
	// failApply makes a host that will not take the rules, which is the
	// condition an exit has to refuse to advertise over.
	failApply bool
	// failWithdraw makes a host that will not let the tables go, which a stop tries again rather than records as done
	failWithdraw bool
	// flows is added to each rule's counter on every readback, so a test can
	// tell a rule the pass rewrote from one it left alone.
	flows uint64
	// changed stands for another writer's changes to the tables and missed
	// for notifications lost, nil for none
	changed, missed chan struct{}
	// failRules makes a host whose rules cannot be listed
	failRules bool
	// faults is how a family's table or chain differs from what Apply writes.
	// An apply clears it unless stuck holds it, or remake names the family and
	// the apply does not delete its table first.
	faults map[uint8]string
	remake map[uint8]bool
	stuck  bool
	// log records each listing, apply and withdrawal in order, beside what record adds
	log []string
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

func (f *fakeBackend) Rules() (map[uint8]chainReadback, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log = append(f.log, "rules")
	if f.failRules {
		return nil, errors.New("no")
	}
	out := map[uint8]chainReadback{}
	for _, family := range []uint8{egress.FamilyIPv4, egress.FamilyIPv6} {
		read := chainReadback{fault: f.faults[family], remake: f.faults[family] != "" && f.remake[family]}
		for _, rule := range f.held {
			if rule.Family == family {
				rule.Packets += f.flows
				read.rules = append(read.rules, rule)
			}
		}
		out[family] = read
	}
	return out, nil
}

// Apply stores the rules grouped by family, as the nftables backend does: each
// family is a table of its own, written and read back one at a time. A fake
// that kept the order it was handed would hide a desired list ordered any other
// way, which never compares equal to its own readback. It logs remake and the
// families for an apply that deletes tables first.
func (f *fakeBackend) Apply(rules []Rule, remake []uint8) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	entry := "apply"
	if len(remake) != 0 {
		entry = fmt.Sprint("remake ", remake)
	}
	f.log = append(f.log, entry)
	if f.failApply {
		return errors.New("no")
	}
	f.applied++
	for family := range f.faults {
		if !f.stuck && (!f.remake[family] || slices.Contains(remake, family)) {
			delete(f.faults, family)
		}
	}
	f.held = nil
	for _, family := range []uint8{egress.FamilyIPv4, egress.FamilyIPv6} {
		for _, rule := range rules {
			if rule.Family == family {
				f.held = append(f.held, Installed{Spec: rule.String(), Family: family})
			}
		}
	}
	return nil
}

func (f *fakeBackend) Conflicts() ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.conflicts), nil
}

func (f *fakeBackend) Withdraw() error {
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

func (f *fakeBackend) where(egress.Egress) string { return "a fake host" }

func (f *fakeBackend) specs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.held))
	for _, rule := range f.held {
		out = append(out, rule.Spec)
	}
	return out
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
	return newTranslator(cfg, rt, be)
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
	if got := be.specs(); !slices.Equal(got, want) {
		t.Errorf("installed %q, want %q", got, want)
	}
}

// A configured source is used unchanged, which is how a deployment that owns
// an address block pins the address return traffic comes back to.
func TestConfiguredSourceReplacesTheHostsOwnChoice(t *testing.T) {
	cfg := egress.Egress{
		Source4:   egress.Source{Addr: netip.MustParseAddr("198.51.100.7")},
		Advertise: prefixes(t, "0.0.0.0/0"),
	}
	be := &fakeBackend{}
	if err := translator(t, cfg, Runtime{}, be).reconcile(); err != nil {
		t.Fatal(err)
	}
	want := []string{"out via ranet0 ipv4 source 198.51.100.7"}
	if got := be.specs(); !slices.Equal(got, want) {
		t.Errorf("installed %q, want %q", got, want)
	}
}

// A subnet router also translates the other way, under the one mesh address
// this node holds, and narrows that rule to the prefixes it claimed rather
// than to every packet that happens to reach the mesh device.
func TestReturnDirectionTranslatesUnderTheMeshAddress(t *testing.T) {
	cfg := egress.Egress{Return: true, Advertise: prefixes(t, "198.51.100.0/24", "192.0.2.5/32")}
	rt := Runtime{MeshAddresses: []netip.Addr{netip.MustParseAddr("10.88.0.2")}}
	be := &fakeBackend{}
	if err := translator(t, cfg, rt, be).reconcile(); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"out via ranet0 ipv4 masquerade",
		"in via ranet0 ipv4 from 198.51.100.0/24 source 10.88.0.2",
		"in via ranet0 ipv4 from 192.0.2.5/32 source 10.88.0.2",
	}
	if got := be.specs(); !slices.Equal(got, want) {
		t.Errorf("installed %q, want %q", got, want)
	}
}

// A prefix covering every address narrows nothing, so the rule that would
// carry it selects on the direction alone rather than on a mask no packet
// fails.
func TestReturnRuleForADefaultCarriesNoPrefixMatch(t *testing.T) {
	cfg := egress.Egress{Return: true, Advertise: prefixes(t, "0.0.0.0/0")}
	rt := Runtime{MeshAddresses: []netip.Addr{netip.MustParseAddr("10.88.0.2")}}
	be := &fakeBackend{}
	if err := translator(t, cfg, rt, be).reconcile(); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"out via ranet0 ipv4 masquerade",
		"in via ranet0 ipv4 source 10.88.0.2",
	}
	if got := be.specs(); !slices.Equal(got, want) {
		t.Errorf("installed %q, want %q", got, want)
	}
}

// an exit serving only the traffic steered to its egress segment advertises nothing and translates what arrives on the tun in both families, since End.DT46 delivers either
func TestSIDOnlyExitTranslatesTheTunInBothFamilies(t *testing.T) {
	var announced [][]netip.Prefix
	rt := Runtime{Steered: true, Announce: func(p []netip.Prefix) { announced = append(announced, p) }}
	be := &fakeBackend{}
	tr := translator(t, egress.Egress{}, rt, be)
	if err := tr.reconcile(); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"out via ranet0 ipv4 masquerade",
		"out via ranet0 ipv6 masquerade",
	}
	if got := be.specs(); !slices.Equal(got, want) {
		t.Errorf("installed %q, want %q", got, want)
	}
	if len(announced) != 1 || len(announced[0]) != 0 {
		t.Errorf("published %v, want one empty announcement", announced)
	}
}

// an exit that advertises and holds an egress segment keys one Out rule per family on the tun, under the configured source
// a family it does not advertise is translated all the same, with no return rule however return is set
func TestSteeredExitKeysOneRulePerFamilyOnTheTun(t *testing.T) {
	cfg := egress.Egress{
		Return:    true,
		Advertise: prefixes(t, "198.51.100.0/24"),
		Source4:   egress.Source{Addr: netip.MustParseAddr("198.51.100.7")},
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
		"out via ranet0 ipv6 masquerade",
	}
	if got := be.specs(); !slices.Equal(got, want) {
		t.Errorf("installed %q, want %q", got, want)
	}
	if be.applied != 1 {
		t.Errorf("wrote the ruleset %d times over two passes, want once", be.applied)
	}
	if got := tr.Announce(); !slices.Equal(got, plain(cfg.Advertise)) {
		t.Errorf("announced %v, want %v", got, cfg.Advertise)
	}
}

// An empty advertise list is an exit serving only steered traffic, which only
// a node holding an egress segment can be. Without one the capability would
// translate nothing and offer nothing, and New refuses it before it opens
// anything.
func TestEmptyAdvertiseNeedsAnEgressSegment(t *testing.T) {
	if err := (egress.Egress{}).Validate(); err != nil {
		t.Fatalf("a capability advertising nothing was refused on its own: %v", err)
	}
	if err := (egress.Egress{}).Serves(true); err != nil {
		t.Errorf("an exit with an egress segment was refused: %v", err)
	}
	if err := (egress.Egress{}).Serves(false); err == nil || !strings.Contains(err.Error(), "advertise is empty") {
		t.Errorf("an exit with nothing to carry was refused with %v", err)
	}
	_, err := New(egress.Egress{}, Runtime{Interface: "ranet0", Forwarding: func() (bool, bool) { return true, true }})
	if err == nil || !strings.Contains(err.Error(), "advertise is empty") {
		t.Fatalf("New returned %v, want the refusal of a capability carrying nothing", err)
	}
	if errors.Is(err, egress.ErrUnsupported) {
		t.Error("the platform was consulted before the capability was judged")
	}
}

// Each family is a table of its own, written and read back one at a time, so
// the rules a pass asks for have to be grouped by family. A list ordered any
// other way never compares equal to its own readback, and the ruleset is
// rewritten on every pass for the life of the node.
func TestRulesAreGroupedByFamilyAsTheyAreReadBack(t *testing.T) {
	cfg := egress.Egress{Return: true, Advertise: prefixes(t, "198.51.100.0/24", "2001:db8:1::/48")}
	rt := Runtime{MeshAddresses: []netip.Addr{
		netip.MustParseAddr("10.88.0.2"), netip.MustParseAddr("2001:db8::2"),
	}}
	be := &fakeBackend{}
	tr := translator(t, cfg, rt, be)
	want := []string{
		"out via ranet0 ipv4 masquerade",
		"in via ranet0 ipv4 from 198.51.100.0/24 source 10.88.0.2",
		"out via ranet0 ipv6 masquerade",
		"in via ranet0 ipv6 from 2001:db8:1::/48 source 2001:db8::2",
	}
	for range 3 {
		if err := tr.reconcile(); err != nil {
			t.Fatal(err)
		}
	}
	if got := be.specs(); !slices.Equal(got, want) {
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
	if got := tr.Stats().Flows; got != 11 {
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
	rt := Runtime{Announce: func(p []netip.Prefix) { announced = append(announced, p) }}
	tr := translator(t, cfg, rt, be)
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

// Another writer's rule at the head of a family's chain, which a host refusing
// the rewrite leaves there, holds that family not ready and its prefixes
// withheld although every rule the translator wrote still reads back, since
// the chain no longer does to a packet what was written. The pass that
// rewrites the chain makes the family ready again, and the other family,
// whose chain reads back as written, stays ready throughout.
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
	if stats := tr.Stats(); stats.Ready4 || !stats.Ready6 || stats.Unready != "its chain does not read back as written" {
		t.Errorf("with another writer's rule in the ip chain the pass reports ready %v and %v with the reason %q, want IPv4 alone not ready for its chain",
			stats.Ready4, stats.Ready6, stats.Unready)
	}
	if got, want := tr.Announce(), plain(prefixes(t, "::/0")); !slices.Equal(got, want) {
		t.Errorf("with another writer's rule in the ip chain the translator announces %v, want %v", got, want)
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
	if stats := tr.Stats(); !stats.Ready4 || !stats.Ready6 {
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

// A family's table set dormant, or its chain made again where nf_tables will
// not change it in place, makes the pass rewrite it, deleting that family's
// table first in the second case, after which both families read ready. A
// setting the rewrite cannot put back holds that family alone not ready,
// named, and its prefixes withheld.
func TestTranslatorRewritesATableOrChainReadingBackOtherThanWritten(t *testing.T) {
	cfg := egress.Egress{Advertise: prefixes(t, "0.0.0.0/0", "::/0")}
	be := &fakeBackend{}
	tr := translator(t, cfg, Runtime{Interface: "ranet0", Steered: true, Forwarding: func() (bool, bool) { return true, true }}, be)
	if err := tr.reconcile(); err != nil {
		t.Fatal(err)
	}
	const dormant = "its table carries flags 0x1, where none are written and 0x1 is dormant"
	for _, change := range []struct {
		name   string
		faults map[uint8]string
		remake map[uint8]bool
		pass   []string
	}{
		{"an ip6 table set dormant", map[uint8]string{egress.FamilyIPv6: dormant}, nil, []string{"rules", "apply", "rules"}},
		{"the ip chain made again at another priority", map[uint8]string{egress.FamilyIPv4: "its chain reads back at priority 0"}, map[uint8]bool{egress.FamilyIPv4: true}, []string{"rules", fmt.Sprint("remake ", []uint8{egress.FamilyIPv4}), "rules"}},
	} {
		be.mu.Lock()
		be.faults, be.remake, be.log = change.faults, change.remake, nil
		be.mu.Unlock()
		if err := tr.reconcile(); err != nil {
			t.Fatalf("%s: %v", change.name, err)
		}
		if got, stats := be.entries(), tr.Stats(); !slices.Equal(got, change.pass) || !stats.Ready4 || !stats.Ready6 {
			t.Errorf("%s: the pass went %q and left ready %v and %v, want %q and both ready", change.name, got, stats.Ready4, stats.Ready6, change.pass)
		}
	}
	be.mu.Lock()
	be.faults, be.stuck = map[uint8]string{egress.FamilyIPv6: dormant}, true
	be.mu.Unlock()
	if err := tr.reconcile(); err != nil {
		t.Fatal(err)
	}
	if stats := tr.Stats(); !stats.Ready4 || stats.Ready6 || stats.Unready != dormant {
		t.Errorf("an ip6 table the rewrite leaves dormant reads ready %v and %v, unready %q", stats.Ready4, stats.Ready6, stats.Unready)
	}
	if got, want := tr.Announce(), plain(prefixes(t, "0.0.0.0/0")); !slices.Equal(got, want) {
		t.Errorf("with the ip6 table left dormant the translator announces %v, want %v", got, want)
	}
}

// A translator that stops retracts before it withdraws. A peer still selecting
// this node while the table comes down is a peer whose traffic leaves
// untranslated, and the retraction is the only thing that tells it otherwise.
func TestShutdownRetractsBeforeItWithdraws(t *testing.T) {
	cfg := egress.Egress{Advertise: prefixes(t, "0.0.0.0/0")}
	be := &fakeBackend{}
	tr := translator(t, cfg, Runtime{}, be)
	withdrawnWhenRetracted := -1
	tr.rt.Announce = func(p []netip.Prefix) {
		if len(p) == 0 {
			withdrawnWhenRetracted = be.withdrawn
		}
	}
	if err := tr.reconcile(); err != nil {
		t.Fatal(err)
	}
	if len(tr.Announce()) != 1 {
		t.Fatal("the first pass announced nothing to retract")
	}
	// Canceled before Run is entered, so the loop body never runs and the
	// order under test is the shutdown's alone.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := tr.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := tr.Announce(); len(got) != 0 {
		t.Errorf("the advertisement survived shutdown as %v", got)
	}
	if be.withdrawn != 1 {
		t.Errorf("withdrew %d times, want once", be.withdrawn)
	}
	if withdrawnWhenRetracted != 0 {
		t.Errorf("the tables were already down when the advertisement was retracted, after %d withdrawals", withdrawnWhenRetracted)
	}
}

// readyLog is a translator beside an egress segment whose Ready and Announce
// calls go into its backend's log between the listings, applies and
// withdrawals, and whose egress.ready events go to bus
func readyLog(t *testing.T, cfg egress.Egress, bus *events.Bus) (*Translator, *fakeBackend) {
	t.Helper()
	be := &fakeBackend{changed: make(chan struct{}, 1), missed: make(chan struct{}, 1)}
	rt := Runtime{
		Steered: true,
		Events:  bus,
		Ready:   func(v4, v6, serves bool) { be.record(fmt.Sprintf("ready %v %v sid %v", v4, v6, serves)) },
		Announce: func(p []netip.Prefix) {
			if len(p) == 0 {
				be.record("retract")
			}
		},
	}
	return translator(t, cfg, rt, be), be
}

// A translator beside an egress segment that stops, or is stopped, tells the
// mesh to stop egressing before it retracts and before the rules go, since a
// packet written after them leaves untranslated
func TestStoppingReportsTheEgressSegmentsNotReadyFirst(t *testing.T) {
	for name, stop := range map[string]func(*Translator) error{
		"shutdown": func(tr *Translator) error {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return tr.Run(ctx)
		},
		"ranet3 down": func(tr *Translator) error { return tr.stop() },
	} {
		t.Run(name, func(t *testing.T) {
			bus := events.New()
			tr, be := readyLog(t, egress.Egress{Advertise: prefixes(t, "0.0.0.0/0")}, bus)
			if err := tr.reconcile(); err != nil {
				t.Fatal(err)
			}
			if err := stop(tr); err != nil {
				t.Fatal(err)
			}
			var order []string
			for _, entry := range be.entries() {
				if entry != "rules" && entry != "apply" {
					order = append(order, entry)
				}
			}
			if want := []string{"ready true true sid true", "ready false false sid false", "retract", "withdraw"}; !slices.Equal(order, want) {
				t.Errorf("the translator went %q, want %q", order, want)
			}
			var recorded []string
			for _, event := range bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "egress.ready" }, 0) {
				recorded = append(recorded, event.Attrs["ipv4"]+" "+event.Attrs["ipv6"]+" "+event.Attrs["sid"])
			}
			if want := []string{"true true true", "false false false"}; !slices.Equal(recorded, want) {
				t.Errorf("recorded egress.ready %q, want %q", recorded, want)
			}
		})
	}
}

// Another writer changing the translator's table, a firewall reload flushing
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
		for deadline := time.Now().Add(passWait); ; time.Sleep(passPoll) {
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
	var triggers []string
	for _, event := range bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "egress.pass" }, 0) {
		triggers = append(triggers, event.Attrs["trigger"])
	}
	if !slices.Contains(triggers, "changed") {
		t.Errorf("the passes were woken by %q, none by the change", triggers)
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
		for deadline := time.Now().Add(passWait); ; time.Sleep(passPoll) {
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
	var triggers []string
	for _, event := range bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "egress.pass" }, 0) {
		triggers = append(triggers, event.Attrs["trigger"])
	}
	if !slices.Contains(triggers, "missed") {
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
	if got := tr.Stats().Conflicts; !slices.Equal(got, be.conflicts) {
		t.Errorf("reported %q, want %q", got, be.conflicts)
	}
	if got := tr.Announce(); len(got) != 1 {
		t.Errorf("a conflict withheld the advertisement: %v", got)
	}
}

// New refuses before it opens anything, so a capability that names a source
// the return direction cannot resolve fails with nothing to clean up.
func TestNewRefusesAnUnresolvableReturnBeforeOpeningTheBackend(t *testing.T) {
	cfg := egress.Egress{Return: true, Advertise: prefixes(t, "198.51.100.0/24")}
	_, err := New(cfg, Runtime{Interface: "ranet0", Forwarding: func() (bool, bool) { return true, true }})
	if err == nil || !strings.Contains(err.Error(), "egress.source4") {
		t.Fatalf("New returned %v, want a refusal naming the field that settles it", err)
	}
	if errors.Is(err, egress.ErrUnsupported) {
		t.Error("the platform was consulted before the capability was judged")
	}
}
