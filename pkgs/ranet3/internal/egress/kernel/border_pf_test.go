// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/logtest"
	"ranet3.com/pkgs/ranet3/internal/pf"
)

// fakePF is pf under the backend: one anchor's rules with their counters and
// tables, the references pf lists, whether the main ruleset calls com.apple's
// children and the interfaces pf skips
type fakePF struct {
	mu       sync.Mutex
	rules    []pf.Counted
	tables   []pf.Table
	enablers []pf.Enabler
	uncalled bool
	skipped  []string
	// off is pf stopped, as pfctl -d or the last reference's release leaves
	// it, until a renewal takes a reference, and reads counts the reads of
	// whether pf runs, which failRunning fails
	off         bool
	reads       int
	failRunning bool
	// failRead makes an anchor pfctl cannot read
	failRead bool
	// unreadable makes an anchor holding a rule the parsers cannot read, as
	// pf.Ctl's Read returns one, until the next load or withdrawal
	unreadable bool
	// log records each load and withdrawal
	log []string
}

func (f *fakePF) Load(anchor string, rs pf.Ruleset) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, err := rs.Render(); err != nil {
		return err
	}
	f.log = append(f.log, "load "+anchor)
	f.unreadable = false
	f.rules, f.tables = nil, slices.Clone(rs.Tables)
	for _, rule := range rs.Rules {
		f.rules = append(f.rules, pf.Counted{Rule: rule})
	}
	return nil
}

// LoadTables replaces the tables it names and keeps the rules, their counters
// and every other table, as pf did under probe P14 (b)
func (f *fakePF) LoadTables(anchor string, tables []pf.Table) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	var names []string
	for _, table := range tables {
		for _, prefix := range table.Prefixes {
			if err := pf.CheckPrefix(prefix); err != nil {
				return err
			}
		}
		names = append(names, table.Name)
	}
	f.log = append(f.log, "tables "+anchor+" "+strings.Join(names, " "))
	for _, table := range tables {
		i := slices.IndexFunc(f.tables, func(t pf.Table) bool { return t.Name == table.Name })
		if i < 0 {
			f.tables = append(f.tables, table)
			continue
		}
		f.tables[i] = table
	}
	return nil
}

func (f *fakePF) Withdraw(anchor string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log = append(f.log, "withdraw "+anchor)
	f.rules, f.tables, f.unreadable = nil, nil, false
	return nil
}

func (f *fakePF) Read(string) (pf.Readback, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case f.failRead:
		return pf.Readback{}, errors.New("pf: pfctl -sr -vv: exit status 1")
	case f.unreadable:
		return pf.Readback{}, fmt.Errorf("%w: pf: a pass that keeps state in %q", pf.ErrUnreadable, "pass in quick on en0 all flags S/SA keep state")
	}
	return pf.Readback{Rules: slices.Clone(f.rules), Tables: slices.Clone(f.tables)}, nil
}

func (f *fakePF) Calls() (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return !f.uncalled, nil
}

func (f *fakePF) Skipped() ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.skipped), nil
}

func (f *fakePF) References() ([]pf.Enabler, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.enablers), nil
}

func (f *fakePF) Running() (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	if f.failRunning {
		return false, errors.New("pf: pfctl -s info: exit status 1")
	}
	return !f.off, nil
}

func (f *fakePF) loads() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, entry := range f.log {
		if strings.HasPrefix(entry, "load ") {
			n++
		}
	}
	return n
}

// text is the anchor as pfctl would load it
func (f *fakePF) text(t *testing.T) string {
	t.Helper()
	read, err := f.Read("com.apple/ranet3")
	if err != nil {
		t.Fatal(err)
	}
	text, err := read.Ruleset().Render()
	if err != nil {
		t.Fatal(err)
	}
	return text
}

// fakeReference is the daemon's reference, listed in pf's references while
// held
type fakeReference struct {
	pf       *fakePF
	token    uint64
	pid      int
	renewals int
	// failRenew makes a renewal pf refuses
	failRenew bool
	// inherited is a take that found an earlier run's reference listed
	inherited bool
	released  bool
	closed    bool
}

func newFakeReference(p *fakePF) *fakeReference {
	r := &fakeReference{pf: p, token: 1 << 63, pid: 4242}
	p.enablers = append(p.enablers, pf.Enabler{PID: r.pid, Name: "ranet3", Token: r.token})
	return r
}

func (r *fakeReference) Token() uint64 { return r.token }

func (r *fakeReference) PID() int { return r.pid }

func (r *fakeReference) Inherited() bool { return r.inherited }

func (r *fakeReference) Renew() error {
	if r.failRenew {
		return errors.New("pf: take a reference: operation not permitted")
	}
	r.renewals++
	r.token++
	r.pf.mu.Lock()
	r.pf.enablers = append(r.pf.enablers, pf.Enabler{PID: r.pid, Name: "ranet3", Token: r.token})
	r.pf.off = false
	r.pf.mu.Unlock()
	return nil
}

func (r *fakeReference) Release() error {
	r.released = true
	r.pf.mu.Lock()
	r.pf.enablers = slices.DeleteFunc(r.pf.enablers, func(e pf.Enabler) bool { return e.Token == r.token })
	r.pf.mu.Unlock()
	return nil
}

func (r *fakeReference) Close() error {
	r.closed = true
	return nil
}

// drop is the fake's view of another program ending the daemon's reference
func (r *fakeReference) drop() {
	r.pf.mu.Lock()
	defer r.pf.mu.Unlock()
	r.pf.enablers = slices.DeleteFunc(r.pf.enablers, func(e pf.Enabler) bool { return e.Token == r.token })
}

// fakePFRuntime is the mesh's tun utun7 with lo0 inside, the sets as sets gives
// them
func fakePFRuntime(bus *events.Bus, sets func() egress.BorderSets) egress.BorderRuntime {
	rt := egress.BorderRuntime{Tun: "utun7", Inside: []string{"utun7", "lo0"}, Events: bus}
	if sets != nil {
		rt.Sets = func(*egress.Border) egress.BorderSets { return sets() }
	}
	return rt
}

// pfBackend is the backend over p for rt's tun, a fresh reference listed
func pfBackend(p *fakePF, rt egress.BorderRuntime) (*borderPF, *fakeReference) {
	ref := newFakeReference(p)
	return &borderPF{ctl: p, ref: ref, anchor: "com.apple/ranet3", tun: rt.Tun, inside: rt.Inside, events: rt.Events}, ref
}

// pfFilter is a filter over the pf backend on fakes for cfg, overlay of
// 192.0.2.0/24 and 3fff:10::/32 where cfg is nil, the sets as sets gives them
func pfFilter(t *testing.T, bus *events.Bus, cfg *egress.Border, sets func() egress.BorderSets) (*BorderFilter, *fakePF, *fakeReference) {
	t.Helper()
	if cfg == nil {
		cfg = overlay(t, "192.0.2.0/24", "3fff:10::/32")
	}
	p := &fakePF{}
	rt := fakePFRuntime(bus, sets)
	be, ref := pfBackend(p, rt)
	f, err := startBorderFilter(cfg, rt, be)
	if err != nil {
		t.Fatal(err)
	}
	return f, p, ref
}

// gateway is the configuration of the rendering's example: the overlay of
// 192.0.2.0/24 and 3fff:10::/32, the shared exemption 192.0.2.32/27, en1's
// 192.0.2.64/26 and en*'s 3fff:10:1::/48
func gateway(t *testing.T) *egress.Border {
	cfg := overlay(t, "192.0.2.0/24", "3fff:10::/32")
	cfg.Antispoof = egress.Antispoof{
		Exempt: prefixes(t, "192.0.2.32/27"),
		Interface: map[string]egress.AntispoofInterface{
			"en1": {Exempt: prefixes(t, "192.0.2.64/26")},
			"en*": {Exempt: prefixes(t, "3fff:10:1::/48")},
		},
	}
	return cfg
}

// gatewaySets is the example's sets: a carve-out of 192.0.2.128/25 on en0,
// the links en0, en1, lo0 and the mesh's utun7, and a mesh prefix of each
// family carved
func gatewaySets() egress.BorderSets {
	return egress.BorderSets{
		CarveOuts: []egress.CarveOut{{Link: "en0", Prefix: netip.MustParsePrefix("192.0.2.128/25")}},
		Carved:    ranges("192.0.2.160/28", "3fff:10:1:2::/64"),
		Links:     []string{"en0", "en1", "lo0", "utun7"},
	}
}

// The anchor holds the antispoof chain in the order a packet meets it, each
// rule quick: the lo0 pass of the overlay in place of lo's accept, the carved
// drops ahead of every pass by source, the carve-out's pass on its link, the
// shared exemption's pass on every interface but the tun, each interface
// exemption's pass on its link, en*'s on each link it matches, and the
// overlay's drops on every interface but the tun, into which the tun's accept
// folds. It holds no rule of the entry chain, and reads ready.
func TestPfBorderWritesTheAntispoofChain(t *testing.T) {
	f, p, _ := pfFilter(t, nil, gateway(t), gatewaySets)
	want := `table <ranet3_overlay> const { 192.0.2.0/24, 3fff:10::/32 }
table <ranet3_carved> const { 192.0.2.160/28, 3fff:10:1:2::/64 }
pass in quick on lo0 from <ranet3_overlay> to any no state label "accept via lo0"
block drop in quick on ! utun7 inet from <ranet3_carved> to any label "drop ipv4 source @carved4"
block drop in quick on ! utun7 inet6 from <ranet3_carved> to any label "drop ipv6 source @carved6"
pass in quick on en0 inet from 192.0.2.128/25 to any no state label "accept via en0 source 192.0.2.128/25"
pass in quick on ! utun7 inet from 192.0.2.32/27 to any no state label "accept exempt source 192.0.2.32/27"
pass in quick on en0 inet6 from 3fff:10:1::/48 to any no state label "accept exempt via en0 source 3fff:10:1::/48"
pass in quick on en1 inet6 from 3fff:10:1::/48 to any no state label "accept exempt via en1 source 3fff:10:1::/48"
pass in quick on en1 inet from 192.0.2.64/26 to any no state label "accept exempt via en1 source 192.0.2.64/26"
block drop in quick on ! utun7 inet from 192.0.2.0/24 to any label "drop ipv4 source 192.0.2.0/24"
block drop in quick on ! utun7 inet6 from 3fff:10::/32 to any label "drop ipv6 source 3fff:10::/32"
`
	if text := p.text(t); text != want {
		t.Errorf("the anchor holds\n%s\nwant\n%s", text, want)
	}
	if got := f.Stats(); !got.Ready || got.Installed != 10 || got.PF == nil || !got.PF.Listed || !got.PF.Called || got.PF.Anchor != "com.apple/ranet3" {
		t.Errorf("the status reads %+v, pf %+v", got, got.PF)
	}
	if f.Where() != "pf anchor com.apple/ranet3" {
		t.Errorf("the filter reads %q", f.Where())
	}
}

// Where overlay is written the filter on pf runs the antispoof chain and
// reports its carve-outs and each exemption's conflict, as on Linux
func TestPfBorderReportsCarveOutsAndConflicts(t *testing.T) {
	bus := events.New()
	conflict := egress.ExemptConflict{Exemption: egress.Exemption{Prefix: netip.MustParsePrefix("192.0.2.32/27")},
		Prefix: netip.MustParsePrefix("192.0.2.40/29"), Carved: netip.MustParsePrefix("192.0.2.40/29"), Via: "example/peer"}
	f, _, _ := pfFilter(t, bus, gateway(t), func() egress.BorderSets {
		sets := gatewaySets()
		sets.Conflicts = []egress.ExemptConflict{conflict}
		return sets
	})
	for _, kind := range []string{"antispoof.carve", "antispoof.conflict"} {
		if n := len(bus.Recorded(func(k, _ string, _ []slog.Attr) bool { return k == kind }, 0)); n != 1 {
			t.Errorf("recorded %d %s, want one", n, kind)
		}
	}
	if got := f.Stats(); !slices.Equal(got.CarveOuts, gatewaySets().CarveOuts) {
		t.Errorf("the status reads carve-outs %+v", got.CarveOuts)
	}
}

// A carve-out's label and an exemption's past 63 bytes each take the short
// form numbered by the rule's place among its class's rules, which pfctl
// holds, while one of 63 bytes keeps its String. The readback reads either
// back as the rule's String, so the status and the debug read name the rule
// whatever label pf holds. The shared exemption's String is at most 63 bytes
// over the documentation ranges, so its 63 is the one drawn here. A rule
// under another label at a place reads back by its own label, so the debug
// read lists the filter's rule there as not held, with no packets.
func TestPfBorderShortensALabelPastSixtyThreeBytes(t *testing.T) {
	long := netip.MustParsePrefix("3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff/128")
	short := netip.MustParsePrefix("3fff:abc:aaaa:bbbb::/64")
	for _, test := range []struct {
		rule  BorderRule
		size  int
		label string
	}{
		{BorderRule{Class: BorderCarveOut, Device: "e0", Source: long, IPv6: true}, 63, ""},
		{BorderRule{Class: BorderCarveOut, Device: "en0", Source: long, IPv6: true}, 64, "accept via en0 carve-out 2"},
		{BorderRule{Class: BorderExempt, Source: long, IPv6: true}, 63, ""},
		{BorderRule{Class: BorderExempt, Device: "vmenet12345678", Source: short, IPv6: true}, 63, ""},
		{BorderRule{Class: BorderExempt, Device: "vmenet123456789", Source: short, IPv6: true}, 64, "accept exempt via vmenet123456789 3"},
	} {
		if len(test.rule.String()) != test.size {
			t.Fatalf("%q is %d bytes, want %d", test.rule, len(test.rule.String()), test.size)
		}
		// the rules of its class ahead of it number it past 1
		rules := []BorderRule{
			{Class: BorderCarveOut, Device: "en1", Source: netip.MustParsePrefix("192.0.2.128/25")},
			{Class: BorderExempt, Device: "en1", Source: netip.MustParsePrefix("192.0.2.32/27")},
			{Class: BorderExempt, Source: netip.MustParsePrefix("192.0.2.64/27")},
			test.rule,
		}
		label := test.label
		if label == "" {
			label = test.rule.String()
		}
		rs, err := pfRuleset("utun7", rules, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := rs.Render(); err != nil || rs.Rules[3].Label != label {
			t.Errorf("%q is labeled %q (%v), want %q", test.rule, rs.Rules[3].Label, err, label)
		}
		var held []pf.Counted
		for _, rule := range rs.Rules {
			held = append(held, pf.Counted{Rule: rule, Packets: 3})
		}
		read := pfReadback(pf.Readback{Rules: held}, rules)
		if len(read.rules) != 4 || read.rules[3].Spec != test.rule.String() || read.rules[3].Packets != 3 {
			t.Errorf("%q reads back as %+v", test.rule, read.rules)
		}
	}

	f, p, _ := pfFilter(t, nil, gateway(t), gatewaySets)
	p.mu.Lock()
	last := &p.rules[len(p.rules)-1]
	ours := last.Rule.Label
	last.Rule.Label, last.Packets = "another writer's drop", 9
	read := pfReadback(pf.Readback{Rules: slices.Clone(p.rules)}, f.last)
	p.mu.Unlock()
	if got := read.rules[len(read.rules)-1]; got.Spec != "another writer's drop" || got.Packets != 9 {
		t.Errorf("a rule under another label at the place of %q reads back as %+v", ours, got)
	}
	chain := f.Debug().Chains[0].Rules
	if got := chain[len(chain)-1]; got.Spec != ours || got.Held || got.Packets != 0 {
		t.Errorf("the debug read lists %+v while pf holds another rule in its place", got)
	}
}

// A change of the carved sets alone loads the tables alone, so the drops keep
// their counters, a change of one family's keeps the other's in the table, and
// an emptied set leaves the table empty and the drop in place
func TestPfBorderMovesTheSetsByATableLoad(t *testing.T) {
	carved := ranges("192.0.2.160/28", "3fff:10:1:2::/64")
	f, p, _ := pfFilter(t, nil, gateway(t), func() egress.BorderSets {
		sets := gatewaySets()
		sets.Carved = carved
		return sets
	})
	p.mu.Lock()
	p.rules[1].Packets = 5
	p.mu.Unlock()
	table := func(name string) []netip.Prefix {
		p.mu.Lock()
		defer p.mu.Unlock()
		i := slices.IndexFunc(p.tables, func(held pf.Table) bool { return held.Name == name })
		if i < 0 {
			t.Fatalf("the anchor lacks <%s>: %+v", name, p.tables)
		}
		return p.tables[i].Prefixes
	}
	f.trigger = "sweep"
	p4, p6 := netip.MustParsePrefix("192.0.2.176/28"), netip.MustParsePrefix("3fff:10:1:2::/64")
	for _, step := range []struct {
		carved []egress.Range
		want   []netip.Prefix
	}{
		{ranges("192.0.2.176/28", "3fff:10:1:2::/64"), []netip.Prefix{p4, p6}},
		{ranges("192.0.2.176/28"), []netip.Prefix{p4}},
		{nil, nil},
	} {
		carved = step.carved
		if err := f.reconcile(); err != nil {
			t.Fatal(err)
		}
		p.mu.Lock()
		last, packets := p.log[len(p.log)-1], p.rules[1].Packets
		p.mu.Unlock()
		if got := table(pfCarvedTable); !slices.Equal(got, step.want) || last != "tables com.apple/ranet3 ranet3_overlay ranet3_carved" {
			t.Errorf("carving %v the anchor's <%s> holds %v after %q, want %v", step.carved, pfCarvedTable, got, last, step.want)
		}
		if p.loads() != 1 || packets != 5 || !f.Stats().Ready {
			t.Errorf("carving %v the anchor was loaded %d times, its drop counts %d, ready %v (%q)", step.carved, p.loads(), packets, f.Stats().Ready, f.Stats().Unready)
		}
	}
}

// A move of the owned or none sets, which no rule of the anchor reads, loads
// nothing and records no pass, on a wake by the mesh's table as on a sweep
func TestPfBorderLoadsNothingForASetItDoesNotHold(t *testing.T) {
	bus := events.New()
	owned, none := ranges("192.0.2.192/29"), ranges("3fff:10:9::/48")
	f, p, _ := pfFilter(t, bus, gateway(t), func() egress.BorderSets {
		sets := gatewaySets()
		sets.Owned, sets.None = owned, none
		return sets
	})
	for _, step := range []struct {
		trigger     string
		owned, none []egress.Range
	}{
		{"routes", ranges("192.0.2.200/29"), ranges("3fff:10:a::/48")},
		{"sweep", ranges("192.0.2.208/29"), ranges("3fff:10:b::/48")},
	} {
		owned, none, f.trigger = step.owned, step.none, step.trigger
		if err := f.reconcile(); err != nil {
			t.Fatal(err)
		}
	}
	p.mu.Lock()
	written := slices.Clone(p.log)
	p.mu.Unlock()
	passes := bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "antispoof.pass" }, 0)
	if !slices.Equal(written, []string{"load com.apple/ranet3"}) || len(passes) != 1 || !f.Stats().Ready {
		t.Errorf("moving the owned and none sets wrote %q, recorded %d passes in all and reads ready %v", written, len(passes), f.Stats().Ready)
	}
}

// Each way the anchor differs from what the filter writes is a fault, which
// the next pass rewrites, the anchor then reading back as written: among them
// a pass moved after the drops, an exemption's pass under the carve-out's
// label it shares a link and a prefix with, which only the label tells apart,
// and a table holding another overlay
func TestPfBorderRewritesEveryAnchorThatReadsBackOtherwise(t *testing.T) {
	for name, change := range map[string]func(p *fakePF){
		"a rule of the same label that is not quick": func(p *fakePF) {
			p.rules[0].Rule.Quick = false
		},
		"a drop naming another utun": func(p *fakePF) {
			p.rules[len(p.rules)-1].Rule.Interface = "utun3"
		},
		"a drop on the utun alone": func(p *fakePF) {
			p.rules[len(p.rules)-1].Rule.NotInterface = false
		},
		"a rule the filter does not write": func(p *fakePF) {
			p.rules = append(p.rules, pf.Counted{Rule: pf.Rule{Action: pf.Block, Quick: true, Label: "drop in"}})
		},
		"a rule gone": func(p *fakePF) {
			p.rules = p.rules[:1]
		},
		"a pass moved after the drops": func(p *fakePF) {
			pass := p.rules[3]
			p.rules = append(slices.Delete(p.rules, 3, 4), pass)
		},
		"an exemption under the carve-out's label": func(p *fakePF) {
			i := slices.IndexFunc(p.rules, func(c pf.Counted) bool { return c.Rule.Label == "accept exempt via en0 source 192.0.2.128/25" })
			p.rules[i].Rule.Label = "accept via en0 source 192.0.2.128/25"
		},
		"a table gone": func(p *fakePF) {
			p.tables = p.tables[:1]
		},
		"a table the filter does not write": func(p *fakePF) {
			p.tables = append(p.tables, pf.Table{Name: "other", Const: true})
		},
		"a table holding another overlay": func(p *fakePF) {
			p.tables[0].Prefixes = []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("3fff:10::/32")}
		},
		"a table holding another entry": func(p *fakePF) {
			p.tables[1].Prefixes = append(p.tables[1].Prefixes, netip.MustParsePrefix("198.51.100.1/32"))
		},
		"an anchor flushed": func(p *fakePF) {
			p.rules, p.tables = nil, nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := gateway(t)
			// an exemption on en0 of the carve-out's own prefix renders the carve-out's text
			cfg.Antispoof.Interface["en0"] = egress.AntispoofInterface{Exempt: prefixes(t, "192.0.2.128/25")}
			f, p, _ := pfFilter(t, nil, cfg, gatewaySets)
			written := p.text(t)
			p.mu.Lock()
			change(p)
			p.mu.Unlock()
			f.trigger = "sweep"
			rules, sets, _ := f.desired()
			read, err := f.be.Rules(rules, sets)
			if err != nil || read.fault == "" {
				t.Fatalf("the readback reads fault %q (%v), want one", read.fault, err)
			}
			if err := f.reconcile(); err != nil {
				t.Fatal(err)
			}
			if p.loads() != 2 || !f.Stats().Ready || p.text(t) != written {
				t.Errorf("the pass loaded the anchor %d times in all and reads ready %v, unready %q, holding\n%s", p.loads(), f.Stats().Ready, f.Stats().Unready, p.text(t))
			}
		})
	}
}

// the readback's fault names what it read: another interface, and a label of
// another class at a place
func TestPfBorderNamesWhatItReadOtherwise(t *testing.T) {
	f, p, _ := pfFilter(t, nil, gateway(t), gatewaySets)
	p.mu.Lock()
	p.rules[len(p.rules)-1].Rule.Interface = "utun3"
	p.rules[3].Rule.Label = "accept exempt via en0 source 192.0.2.128/25"
	p.mu.Unlock()
	rules, sets, _ := f.desired()
	read, err := f.be.Rules(rules, sets)
	if err != nil || !strings.Contains(read.fault, `its rule 4 carries the label "accept exempt via en0 source 192.0.2.128/25" where the filter writes "accept via en0 source 192.0.2.128/25"`) {
		t.Errorf("the readback reads fault %q (%v)", read.fault, err)
	}
	p.mu.Lock()
	p.rules[3].Rule.Label = "accept via en0 source 192.0.2.128/25"
	p.mu.Unlock()
	read, err = f.be.Rules(rules, sets)
	if err != nil || !strings.Contains(read.fault, `reads "block drop in quick on ! utun3 inet6 from 3fff:10::/32`) {
		t.Errorf("the readback reads fault %q (%v)", read.fault, err)
	}
}

// an anchor holding a rule the parsers cannot read, a stateful pass another
// program loaded, is a fault: the pass loads the anchor whole and reads ready,
// and so does a start that finds one
func TestPfBorderRewritesAnAnchorItCannotRead(t *testing.T) {
	f, p, _ := pfFilter(t, nil, nil, nil)
	p.mu.Lock()
	p.unreadable = true
	p.mu.Unlock()
	f.trigger = "sweep"
	if err := f.reconcile(); err != nil {
		t.Fatal(err)
	}
	if got := f.Stats(); !got.Ready || p.loads() != 2 {
		t.Errorf("the pass over an anchor it cannot read loaded it %d times in all and reads ready %v (%q)", p.loads(), got.Ready, got.Unready)
	}

	p = &fakePF{unreadable: true}
	rt := fakePFRuntime(nil, nil)
	be, _ := pfBackend(p, rt)
	started, err := startBorderFilter(overlay(t, "192.0.2.0/24", "3fff:10::/32"), rt, be)
	if err != nil || p.loads() != 1 || !started.Stats().Ready {
		t.Errorf("a start over an anchor it cannot read returned %v after %d loads", err, p.loads())
	}
}

// A stop over an anchor holding a rule the parsers cannot read, a stateful
// pass another program loaded, empties it, logs it withdrawn and gives the
// reference back
func TestPfBorderStopEmptiesAnAnchorItCannotRead(t *testing.T) {
	var lines strings.Builder
	logtest.SetDefault(t, slog.New(slog.NewTextHandler(&lines, nil)))
	f, p, ref := pfFilter(t, nil, nil, nil)
	p.mu.Lock()
	p.unreadable = true
	p.mu.Unlock()
	if err := f.finish(); err != nil {
		t.Fatalf("the stop over an anchor it cannot read failed: %v", err)
	}
	read, err := p.Read("")
	if err != nil || len(read.Rules) != 0 || len(read.Tables) != 0 || !ref.released || !strings.Contains(lines.String(), "antispoof filter withdrawn") {
		t.Errorf("after the stop the anchor holds %+v (%v), the reference released %v, and the log reads:\n%s", read, err, ref.released, lines.String())
	}
}

// an anchor pfctl cannot read fails the pass, which reads not ready and loads
// nothing
func TestPfBorderThatCannotReadItsAnchorFailsThePass(t *testing.T) {
	f, p, _ := pfFilter(t, nil, nil, nil)
	p.mu.Lock()
	p.failRead = true
	p.mu.Unlock()
	if err := f.reconcile(); err == nil {
		t.Fatal("a pass over an anchor pfctl cannot read passed")
	}
	if got := f.Stats(); got.Ready || !strings.Contains(got.Unready, "pfctl -sr -vv") || p.loads() != 1 {
		t.Errorf("the status reads ready %v, unready %q, after %d loads", got.Ready, got.Unready, p.loads())
	}
}

// A pass that finds pf no longer listing this daemon's reference under its
// pid takes a new one before it reads ready and rewrites nothing. Its warning
// and its antispoof.pf say whether pf was off, which the renewal then turned
// back on, or ran on under another holder, why the pass took the reference
// again, and that removing overlay turns the filter off. Whether pf runs is
// read on that path alone, and a read that fails leaves the renewal as it is:
// the warning then says pf's state could not be read, carrying the error,
// and the event leaves pf_off out.
func TestPfBorderRenewsAReferencePfNoLongerLists(t *testing.T) {
	var lines strings.Builder
	logtest.SetDefault(t, slog.New(slog.NewTextHandler(&lines, nil)))
	bus := events.New()
	f, p, ref := pfFilter(t, bus, nil, nil)
	// state names pf as the pass finds it: off, running, or unread where its
	// read fails
	for _, end := range []struct {
		name  string
		do    func()
		state string
	}{
		{"stopped by pfctl -d", func() {
			p.mu.Lock()
			defer p.mu.Unlock()
			p.enablers, p.off = nil, true
		}, "off"},
		{"released by another program as the last holder", func() {
			ref.drop()
			p.mu.Lock()
			defer p.mu.Unlock()
			p.off = true
		}, "off"},
		// pf runs on, so only the listing tells the pass
		{"released while another program holds pf", func() {
			ref.drop()
			p.mu.Lock()
			defer p.mu.Unlock()
			p.enablers = append(p.enablers, pf.Enabler{PID: 77, Name: "othervpn", Token: 9})
		}, "running"},
		{"listed under another pid", func() {
			p.mu.Lock()
			defer p.mu.Unlock()
			for i := range p.enablers {
				if p.enablers[i].Token == ref.token {
					p.enablers[i].PID = 31337
				}
			}
		}, "running"},
		{"stopped by pfctl -d, its state unread", func() {
			p.mu.Lock()
			defer p.mu.Unlock()
			p.enablers, p.off, p.failRunning = nil, true, true
		}, "unread"},
	} {
		renewals := ref.renewals
		lines.Reset()
		end.do()
		if err := f.reconcile(); err != nil {
			t.Fatal(err)
		}
		if got := f.Stats(); !got.Ready || ref.renewals != renewals+1 || got.PF.Token != ref.token || !got.PF.Listed || p.off {
			t.Errorf("%s: the status reads ready %v (%q), pf %+v, off %v, after %d renewals", end.name, got.Ready, got.Unready, got.PF, p.off, ref.renewals-renewals)
		}
		recorded := bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "antispoof.pf" }, 0)
		if len(recorded) != renewals+1 {
			t.Fatalf("%s: recorded %d antispoof.pf after %d renewals", end.name, len(recorded), renewals+1)
		}
		want := map[string]string{"token": fmt.Sprint(ref.token), "pid": "4242"}
		var said []string
		switch end.state {
		case "off":
			want["pf_off"] = "true"
			said = []string{"pf was off, and this daemon turned it back on", "the host's protection was off until now", "pf_off=true"}
		case "running":
			want["pf_off"] = "false"
			said = []string{"pf was not off, as another holder kept it running", "pf_off=false"}
		default:
			said = []string{"whether pf was off could not be read", `err="pf: pfctl -s info: exit status 1"`}
		}
		if event := recorded[len(recorded)-1].Attrs; !maps.Equal(event, want) {
			t.Errorf("%s: antispoof.pf carries %v, want %v", end.name, event, want)
		}
		said = append(said, "level=WARN", "since pf no longer listed", "which pfctl -d or another program's pfctl -X ends",
			"removing overlay turns the antispoof filter off", fmt.Sprintf("token=%d pid=4242", ref.token))
		for _, want := range said {
			if strings.Count(lines.String(), want) != 1 {
				t.Errorf("%s: the log does not say %q once:\n%s", end.name, want, lines.String())
			}
		}
		if end.state == "unread" && strings.Contains(lines.String(), "pf_off") {
			t.Errorf("%s: the log names pf_off, which the read did not give:\n%s", end.name, lines.String())
		}
	}
	if p.loads() != 1 || p.reads != 5 {
		t.Errorf("the renewals loaded the anchor %d times and read whether pf runs %d times, want 1 and 5", p.loads(), p.reads)
	}
	if err := f.reconcile(); err != nil || ref.renewals != 5 || p.reads != 5 {
		t.Errorf("a pass over a listed reference renewed it or read whether pf runs, %d renewals, %d reads (%v)", ref.renewals, p.reads, err)
	}
}

// A pass that fails still takes the reference again where pf no longer lists
// it, which turns pf back on after pfctl -d: one whose carved set gives an
// entry pf cannot hold, which it then fails to write, and one over an anchor
// pfctl cannot read
func TestPfBorderFailedPassRenewsTheReference(t *testing.T) {
	cfg := overlay(t, "192.0.2.0/24", "fe80::/16")
	cfg.Antispoof = egress.Antispoof{Exempt: prefixes(t, "fe80::/16")}
	for _, cause := range []string{"a carved entry pf cannot hold", "an anchor pfctl cannot read"} {
		carved := ranges("fe80::/64")
		f, p, ref := pfFilter(t, nil, cfg, func() egress.BorderSets { return egress.BorderSets{Carved: carved} })
		p.mu.Lock()
		if cause == "an anchor pfctl cannot read" {
			p.failRead = true
		} else {
			// pfctl clears the second group, so pf would hold fe80:0:2::/48
			carved = ranges("fe80:1:2::/48")
		}
		p.enablers, p.off = nil, true
		p.mu.Unlock()
		f.trigger = "sweep"
		if err := f.reconcile(); err == nil {
			t.Errorf("%s: the pass passed", cause)
		}
		if p.off || ref.renewals != 1 || !slices.ContainsFunc(p.enablers, func(e pf.Enabler) bool { return e.Token == ref.token }) {
			t.Errorf("%s: after the failed pass pf is off %v, the reference renewed %d times, pf lists %+v", cause, p.off, ref.renewals, p.enablers)
		}
	}
}

// Each fact pf holds beside the anchor reads not ready with its reason while
// the anchor reads back as written, so no pass rewrites the anchor for it, and
// all together name each. A skip of a device inside the mesh, the tun or lo0,
// leaves no drop of the filter's unevaluated and reads ready.
func TestPfBorderNotReadyForPfsOwnState(t *testing.T) {
	for name, test := range map[string]struct {
		set  func(p *fakePF, ref *fakeReference)
		want []string
	}{
		"a reference pf refuses to give again": {func(_ *fakePF, ref *fakeReference) { ref.drop(); ref.failRenew = true }, []string{"pf no longer lists this daemon's reference"}},
		"a main ruleset that calls no child of com.apple": {func(p *fakePF, _ *fakeReference) { p.uncalled = true },
			[]string{`calls neither anchor "com.apple/*" all nor anchor "com.apple/*" in all at its own depth`, "for a packet in", "inline anchor", "pfctl -f /etc/pf.conf"}},
		"a link outside the mesh pf skips": {func(p *fakePF, _ *fakeReference) { p.skipped = []string{"lo0", "en0", "utun7", "bridge100"} },
			[]string{"pf skips en0, bridge100,", "set skip", "a forged overlay source passes", "pfctl -f /etc/pf.conf"}},
		"all three": {func(p *fakePF, ref *fakeReference) {
			ref.drop()
			ref.failRenew = true
			p.uncalled = true
			p.skipped = []string{"en0"}
		},
			[]string{"pf no longer lists", `calls neither anchor "com.apple/*" all`, "pf skips en0,"}},
	} {
		t.Run(name, func(t *testing.T) {
			f, p, ref := pfFilter(t, nil, nil, nil)
			test.set(p, ref)
			if err := f.reconcile(); err != nil {
				t.Fatal(err)
			}
			got := f.Stats()
			for _, want := range test.want {
				if got.Ready || !strings.Contains(got.Unready, want) {
					t.Errorf("the status reads ready %v, unready %q, want it to say %q", got.Ready, got.Unready, want)
				}
			}
			if p.loads() != 1 {
				t.Errorf("the anchor was loaded %d times, want only the start's", p.loads())
			}
		})
	}
	f, p, _ := pfFilter(t, nil, nil, nil)
	p.skipped = []string{"lo0", "utun7"}
	if err := f.reconcile(); err != nil || !f.Stats().Ready {
		t.Errorf("a skip of the devices inside reads ready %v, unready %q (%v)", f.Stats().Ready, f.Stats().Unready, err)
	}
}

// A start over a main ruleset that calls no child of com.apple is refused,
// naming the missing line and how to put it back, as Linux refuses a first
// pass that is not ready
func TestPfBorderStartRefusesAnUncalledAnchor(t *testing.T) {
	p := &fakePF{uncalled: true}
	rt := fakePFRuntime(nil, nil)
	be, _ := pfBackend(p, rt)
	_, err := startBorderFilter(overlay(t, "192.0.2.0/24", "3fff:10::/32"), rt, be)
	if err == nil {
		t.Fatal("the start ran over a main ruleset that calls no child of com.apple")
	}
	for _, want := range []string{`egress: the antispoof filter in pf anchor com.apple/ranet3 is not ready, since pf's main ruleset calls neither anchor "com.apple/*" all`, "pfctl -f /etc/pf.conf", "needs that line"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the start's refusal %q does not say %q", err, want)
		}
	}
}

// A start refused over an anchor an earlier run left keeps that anchor and
// gives back the reference it took, so pf is as it found it, unless its take
// found the earlier run's reference listed, whose place the new one then
// keeps for the next start
func TestPfBorderRefusedStartGivesBackItsReference(t *testing.T) {
	for _, inherited := range []bool{false, true} {
		p := &fakePF{uncalled: true}
		rt := fakePFRuntime(nil, nil)
		earlier, _ := pfBackend(p, rt)
		if err := earlier.Apply([]BorderRule{{Class: BorderSource, Source: netip.MustParsePrefix("192.0.2.0/24")}}, borderSets{}); err != nil {
			t.Fatal(err)
		}
		be, ref := pfBackend(p, rt)
		ref.inherited = inherited
		if _, err := startBorderFilter(overlay(t, "192.0.2.0/24"), rt, be); err == nil {
			t.Fatal("the start ran over a main ruleset that calls no child of com.apple")
		}
		read, _ := p.Read("")
		if len(read.Rules) == 0 || ref.released == inherited || !ref.closed && inherited {
			t.Errorf("inherited %v: after the refusal the anchor holds %+v, the reference released %v, closed %v", inherited, read, ref.released, ref.closed)
		}
	}
}

// A stop empties the anchor and gives the reference back, the withdrawal
// itself giving it back where the take took an earlier run's place, which the
// backend's close then keeps, and leaving at the mesh's failure keeps both
func TestPfBorderWithdrawsOnStopAndLeavesAllOnLeave(t *testing.T) {
	for _, inherited := range []bool{false, true} {
		f, p, ref := pfFilter(t, nil, nil, nil)
		ref.inherited = inherited
		if err := f.finish(); err != nil {
			t.Fatal(err)
		}
		if read, _ := p.Read(""); len(read.Rules) != 0 || len(read.Tables) != 0 || !ref.released || slices.ContainsFunc(p.enablers, func(e pf.Enabler) bool { return e.Token == ref.token }) {
			t.Errorf("inherited %v: after the stop the anchor holds %+v, released %v, pf lists %+v", inherited, read, ref.released, p.enablers)
		}
	}
	p := &fakePF{}
	be, ref := pfBackend(p, fakePFRuntime(nil, nil))
	if err := be.Apply([]BorderRule{{Class: BorderSource, Source: netip.MustParsePrefix("192.0.2.0/24")}}, borderSets{}); err != nil {
		t.Fatal(err)
	}
	if err := be.Leave(); err != nil {
		t.Fatal(err)
	}
	if read, _ := p.Read(""); len(read.Rules) != 1 || ref.released || !ref.closed {
		t.Errorf("after leaving the anchor holds %+v, released %v, closed %v", read, ref.released, ref.closed)
	}
	if removed, err := be.Withdraw(); err != nil || !removed {
		t.Errorf("a withdrawal of a held anchor reads removed %v (%v)", removed, err)
	}
	if removed, err := be.Withdraw(); err != nil || removed {
		t.Errorf("a withdrawal of an empty anchor reads removed %v (%v)", removed, err)
	}
}

// The overlay's drops and the carved drops count by family in the status, and
// a debug read heads the one chain by its direction with no priority, lists
// each rule by its String whatever label pf holds, the carved table and every
// reference pf lists
func TestPfBorderCountsByFamilyAndDebugReadsTheAnchor(t *testing.T) {
	cfg := gateway(t)
	link := "vmenet123456789"
	cfg.Antispoof.Interface[link] = egress.AntispoofInterface{Exempt: prefixes(t, "3fff:10:aaaa:bbbb:c000::/80")}
	f, p, _ := pfFilter(t, events.New(), cfg, gatewaySets)
	count := func(label string, packets uint64) {
		i := slices.IndexFunc(p.rules, func(c pf.Counted) bool { return c.Rule.Label == label })
		if i < 0 {
			t.Fatalf("the anchor holds no rule %q", label)
		}
		p.rules[i].Packets, p.rules[i].Bytes = packets, packets*80
	}
	p.mu.Lock()
	count("drop ipv6 source 3fff:10::/32", 3)
	count("drop ipv4 source @carved4", 2)
	count("accept exempt via "+link+" 5", 7)
	p.enablers = append(p.enablers, pf.Enabler{PID: 77, Name: "othervpn", Token: 9})
	p.mu.Unlock()
	if err := f.reconcile(); err != nil {
		t.Fatal(err)
	}
	dropped := f.Stats().Dropped
	for kind, want := range map[egress.BorderDrop]uint64{
		{Reason: "overlay_source", Family: "ipv6"}: 3, {Reason: "overlay_source", Family: "ipv4"}: 0,
		{Reason: "carved_source", Family: "ipv4"}: 2, {Reason: "carved_source", Family: "ipv6"}: 0,
	} {
		if got := dropped[slices.Index(egress.BorderDropKinds[:], kind)]; got != want {
			t.Errorf("%s reads %d, want %d", kind.Name(), got, want)
		}
	}
	debug := f.Debug()
	if len(debug.Chains) != 1 || debug.Chains[0].Name != BorderChain || debug.Chains[0].Hook != "in" || debug.Chains[0].Priority != nil || len(debug.Chains[0].Rules) != 11 {
		t.Fatalf("the debug read lists %+v", debug.Chains)
	}
	exempt := debug.Chains[0].Rules[8]
	if exempt.Spec != "accept exempt via "+link+" source 3fff:10:aaaa:bbbb:c000::/80" || !exempt.Held || exempt.Packets != 7 {
		t.Errorf("the debug read lists the shortened rule as %+v", exempt)
	}
	var tables []string
	for _, set := range debug.Sets {
		tables = append(tables, set.Kind+" "+set.Name)
	}
	if !slices.Equal(tables, []string{"table " + pfCarvedTable}) || debug.PF == nil || len(debug.PF.Enablers) != 2 || debug.PF.Enablers[1] != (pf.Enabler{PID: 77, Name: "othervpn", Token: 9}) {
		t.Errorf("the debug read lists tables %q and pf %+v", tables, debug.PF)
	}
}

// an exemption's exact interface name that no pf rule can carry, as a byte
// outside the word pf.conf reads, is refused naming it, while a name ending in
// * writes only the links it matches and is not
func TestInterfaceNamePfCannotWriteIsRefused(t *testing.T) {
	cfg := overlay(t, "192.0.2.0/24")
	cfg.Antispoof = egress.Antispoof{Interface: map[string]egress.AntispoofInterface{
		"br-lan":    {Exempt: prefixes(t, "192.0.2.0/26")},
		"bridge100": {Exempt: prefixes(t, "192.0.2.64/26")},
		"br-*":      {Exempt: prefixes(t, "192.0.2.128/26")},
	}}
	err := refuseUnwritable(cfg)
	if err == nil || !strings.Contains(err.Error(), `an exemption names the interface "br-lan", which the antispoof filter's pf anchor cannot write`) ||
		strings.Contains(err.Error(), "bridge100") || strings.Contains(err.Error(), `"br-*"`) {
		t.Errorf("the refusal reads %v, want it to name br-lan alone", err)
	}
}
