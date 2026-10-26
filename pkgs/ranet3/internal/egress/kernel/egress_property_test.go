// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package kernel

import (
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/schema"
)

// exit is a capability and the runtime it runs under.
type exit struct {
	cfg egress.Egress
	rt  Runtime
}

// classFroms is the prefixes a drawn class takes its From from, nested in one
// another and beside one another in each family, and meshPool the addresses an
// exit's mesh addresses are drawn from, inside some of them and outside the
// rest, a link-local address of each family among them
var (
	classFroms = []schema.Prefix{
		schema.MustPrefix("0.0.0.0/0"), schema.MustPrefix("198.51.100.0/24"), schema.MustPrefix("198.51.100.0/25"),
		schema.MustPrefix("198.51.100.7/32"), schema.MustPrefix("192.0.2.0/24"),
		schema.MustPrefix("::/0"), schema.MustPrefix("2001:db8::/32"), schema.MustPrefix("2001:db8:1::/48"), schema.MustPrefix("3fff::/20"),
	}
	meshPool = []netip.Addr{
		netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("198.51.100.200"), netip.MustParseAddr("169.254.0.1"),
		netip.MustParseAddr("3fff::1"), netip.MustParseAddr("2001:db8:1::1"), netip.MustParseAddr("2001:db8:2::1"), netip.MustParseAddr("fe80::1"),
	}
)

// exits draws an exit: a few prefixes of each family, a default among them,
// return on or off, nested classes of each kind in any order, mesh addresses
// of each family, one now and then written twice, and an egress segment or
// none. The empty advertise list and the egress segment are each drawn
// outright half the time.
func exits() hegel.Generator[exit] {
	pool := []schema.Prefix{
		schema.MustPrefix("0.0.0.0/0"), schema.MustPrefix("198.51.100.0/24"), schema.MustPrefix("192.0.2.5/32"),
		schema.MustPrefix("::/0"), schema.MustPrefix("2001:db8:1::/48"),
	}
	return hegel.Composite(func(tc hegel.TestCase) exit {
		var cfg egress.Egress
		if hegel.Draw(tc, hegel.Booleans()) {
			for _, prefix := range hegel.Draw(tc, hegel.Lists(hegel.SampledFrom(pool)).MaxSize(4)) {
				if !slices.Contains(cfg.Advertise, prefix) {
					cfg.Advertise = append(cfg.Advertise, prefix)
				}
			}
		}
		cfg.Return = hegel.Draw(tc, hegel.Booleans())
		for _, from := range pbt.Subset(tc, classFroms, 0, 5) {
			translations := []egress.Translation{{Auto: true}, {Addr: netip.MustParseAddr("198.51.100.7")}}
			if from.Addr().Is6() {
				translations[1] = egress.Translation{Addr: netip.MustParseAddr("2001:db8::7")}
			}
			// none from every source of a family is refused
			if from.Bits() > 0 {
				translations = append(translations, egress.Translation{None: true})
			}
			cfg.Translate = append(cfg.Translate, egress.Class{From: from, To: hegel.Draw(tc, hegel.SampledFrom(translations))})
		}
		mesh := pbt.Subset(tc, meshPool, 0, 4)
		if len(mesh) > 0 && hegel.Draw(tc, hegel.WeightedBooleans(1.0/4)) {
			mesh = append(mesh, mesh[0])
		}
		rt := Runtime{
			Interface:     "ranet0",
			MeshAddresses: mesh,
			Forwarding:    func() (bool, bool) { return true, true },
			Lookup:        holdsEvery,
			Steered:       hegel.Draw(tc, hegel.Booleans()),
		}
		return exit{cfg, rt}
	})
}

// takes reports whether exit is one New takes
func (e exit) takes() bool {
	return e.cfg.Validate() == nil && e.cfg.Serves(e.rt.Steered) == nil && e.cfg.CheckReturn(e.rt.MeshAddresses) == nil
}

// crossing is a packet at postrouting as a rule reads it: the device it
// arrived on, empty for one this host sent, the one it leaves by and its
// source
type crossing struct {
	arrival, departure string
	source             netip.Addr
}

// meant is which packets a rule takes by its definition, each of its family
// and from a source its From covers where it has one: out of the mesh what
// arrives on the mesh device and leaves by another, into the mesh what arrives
// from elsewhere, not from this host, and leaves by the mesh device, and for
// this node's own address what leaves by another link
func meant(rule Rule, packet crossing) bool {
	if egress.AddressFamily(packet.source) != rule.Family || rule.From.IsValid() && !rule.From.Contains(packet.source) {
		return false
	}
	switch rule.Direction {
	case Out:
		return packet.arrival == rule.Interface && packet.departure != rule.Interface
	case In:
		return packet.arrival != "" && packet.arrival != rule.Interface && packet.departure == rule.Interface
	}
	return packet.departure != rule.Interface
}

// leavesUnder is the source a packet a rule takes leaves under: the packet's
// own under a rule of none, the rule's address, and the invalid address for
// masquerade, which the host picks per packet
func leavesUnder(rule Rule, packet crossing) netip.Addr {
	if rule.None {
		return packet.source
	}
	return rule.Source
}

// classSource is the source the class model has a packet from source leave
// under, as leavesUnder spells it
func classSource(cfg egress.Egress, source netip.Addr) netip.Addr {
	to := cfg.ClassOf(source).To
	if to.None {
		return source
	}
	return to.Addr
}

// For every capability New takes, the rules a pass installs, read top to
// bottom in each family's chain as nf_tables reads one, take each packet as
// the class model says. A packet from the mesh device out of another link, in
// a family advertised or steered, leaves under the class of its source. One
// this node sends from a mesh source of its own out of another link leaves
// under that address's class, and one from any other address is left to the
// host. With return, one entering the mesh from an advertised prefix leaves
// under the return source, and every other packet entering the mesh, or
// crossing it, is taken by no rule. A second pass writes nothing, so the host
// holds the order it reads back, and only advertised prefixes are announced.
func TestRulesFollowWhatIsAdvertisedAndSteered(t *testing.T) {
	sources := []netip.Addr{
		netip.MustParseAddr("198.51.100.7"), netip.MustParseAddr("198.51.100.8"), netip.MustParseAddr("198.51.100.200"),
		netip.MustParseAddr("192.0.2.5"), netip.MustParseAddr("203.0.113.17"),
		netip.MustParseAddr("2001:db8:1::7"), netip.MustParseAddr("2001:db8:2::7"), netip.MustParseAddr("3fff::7"),
	}
	pbt.Check(t, func(ht *hegel.T) {
		drawn := hegel.Draw(ht, exits())
		cfg, rt := drawn.cfg, drawn.rt
		ht.Assume(drawn.takes())
		be := &fakeBackend{}
		tr := newTranslator(cfg, rt, be)
		for range 2 {
			if err := tr.reconcile(); err != nil {
				ht.Fatal(err)
			}
		}
		if be.applied != 1 {
			ht.Fatalf("%+v under %+v wrote the ruleset %d times over two passes, want once", cfg, rt, be.applied)
		}
		desired := tr.desired()
		// first is the rule a packet meets first that takes it
		first := func(packet crossing) (Rule, bool) {
			for _, rule := range desired {
				if meant(rule, packet) {
					return rule, true
				}
			}
			return Rule{}, false
		}
		drawnSources := append(slices.Clone(sources), rt.MeshAddresses...)
		for range hegel.Draw(ht, pbt.Spanning(1, 4)) {
			drawnSources = append(drawnSources, hegel.Draw(ht, hegel.OneOf(hegel.IPAddresses().IPv4(), hegel.IPAddresses().IPv6())))
		}
		for _, source := range drawnSources {
			family := egress.AddressFamily(source)
			translated := slices.Contains(cfg.Translated(rt.Steered), family)
			mine := slices.Contains(egress.MeshSources(family, rt.MeshAddresses), source)
			inbound, _ := cfg.ReturnSource(family, rt.MeshAddresses)
			advertised := slices.ContainsFunc(cfg.Advertise, func(prefix schema.Prefix) bool { return prefix.Contains(source) })
			for _, c := range []struct {
				what   string
				packet crossing
				taken  bool
				want   netip.Addr
			}{
				{"out of the mesh", crossing{"ranet0", "eth0", source}, translated, classSource(cfg, source)},
				{"from this node", crossing{"", "eth0", source}, translated && mine, classSource(cfg, source)},
				{"into the mesh", crossing{"eth1", "ranet0", source}, translated && inbound.IsValid() && advertised, inbound},
				{"from this node into the mesh", crossing{"", "ranet0", source}, false, netip.Addr{}},
				{"across the mesh", crossing{"ranet0", "ranet0", source}, false, netip.Addr{}},
			} {
				rule, taken := first(c.packet)
				if taken != c.taken || taken && leavesUnder(rule, c.packet) != c.want {
					ht.Fatalf("%+v under %+v takes a packet %s from %s by %v (%v) to leave under %v, want taken %v under %v, in %v",
						cfg, rt, c.what, source, rule, taken, leavesUnder(rule, c.packet), c.taken, c.want, desired)
				}
			}
		}
		if got, want := tr.Announce(), plain(cfg.Advertise); !slices.Equal(got, want) {
			ht.Fatalf("%+v under %+v announced %v, want %v", cfg, rt, got, want)
		}
	})
}

// step is one pass of a translator beside an egress segment, on a host drawn
// for that pass
type step struct {
	enabled   bool
	failRules bool
	failApply bool
	held      []Installed
	faults    map[uint8]string
	remake    map[uint8]bool
	stuck     bool
	forward4  bool
	forward6  bool
}

// steps draws what the host holds before each pass. In each family's chain it
// holds some of the rules the translator asks for, now and then reversed, and
// now and then another writer's rule anywhere among them, with no spelling or
// one the translator never writes. A family the translator writes now and
// then reads back with its table or chain set otherwise, in a way a rewrite
// puts back in place, one only a remade table puts back, or one nothing puts
// back. Beside the chains it draws forwarding per family, a listing or an
// apply that fails, and now and then a translator stopped.
func steps(desired []Rule) hegel.Generator[step] {
	foreign := []string{"", "out via ranet1 ipv4 source 192.0.2.1"}
	faults := []string{
		"its table carries flags 0x1, where none are written and 0x1 is dormant",
		`its chain reads back as type "nat" at hook 4, priority 0, policy 1, where a nat chain at hook 4, priority 100, policy accept was written`,
	}
	return hegel.Composite(func(tc hegel.TestCase) step {
		s := step{
			enabled:   hegel.Draw(tc, hegel.WeightedBooleans(7.0/8)),
			failRules: hegel.Draw(tc, hegel.WeightedBooleans(1.0/8)),
			failApply: hegel.Draw(tc, hegel.Booleans()),
			forward4:  hegel.Draw(tc, hegel.WeightedBooleans(3.0/4)),
			forward6:  hegel.Draw(tc, hegel.WeightedBooleans(3.0/4)),
		}
		for _, family := range []uint8{egress.FamilyIPv4, egress.FamilyIPv6} {
			var chain []Installed
			for _, rule := range desired {
				if rule.Family == family && hegel.Draw(tc, hegel.WeightedBooleans(3.0/4)) {
					chain = append(chain, Installed{Spec: rule.String(), Family: family})
				}
			}
			if hegel.Draw(tc, hegel.WeightedBooleans(1.0/4)) {
				slices.Reverse(chain)
			}
			if hegel.Draw(tc, hegel.WeightedBooleans(1.0/4)) {
				other := Installed{Spec: hegel.Draw(tc, hegel.SampledFrom(foreign)), Family: family}
				chain = slices.Insert(chain, hegel.Draw(tc, hegel.Integers(0, len(chain))), other)
			}
			s.held = append(s.held, chain...)
			if slices.ContainsFunc(desired, func(rule Rule) bool { return rule.Family == family }) && hegel.Draw(tc, hegel.WeightedBooleans(1.0/4)) {
				if s.faults == nil {
					s.faults, s.remake = map[uint8]string{}, map[uint8]bool{}
				}
				s.faults[family] = hegel.Draw(tc, hegel.SampledFrom(faults))
				s.remake[family] = hegel.Draw(tc, hegel.Booleans())
				s.stuck = hegel.Draw(tc, hegel.WeightedBooleans(1.0/4))
			}
		}
		return s
	})
}

// load sets be to the host now describes
func (now step) load(be *fakeBackend) {
	be.held, be.failRules, be.failApply = slices.Clone(now.held), now.failRules, now.failApply
	be.faults, be.remake, be.stuck = maps.Clone(now.faults), now.remake, now.stuck
}

// onHost points rt's forwarding reader at the host now describes, read at each
// call
func onHost(rt *Runtime, now *step) {
	rt.Forwarding = func() (bool, bool) { return now.forward4, now.forward6 }
}

// writtenAfter is whether each family's chain reads back as the translator
// wrote it once a pass over now has run, its table and chain set as written and
// every rule asked of the family by its spelling, in order and with nothing
// else among them. A listing that failed reads back nothing, an apply that
// failed leaves what the host held, and an apply finds the host as it was asked
// to be, but for a setting nothing puts back.
func writtenAfter(now step, desired []Rule) map[uint8]bool {
	held, faults := now.held, now.faults
	switch {
	case now.failRules:
		held, faults = nil, nil
	case !now.failApply:
		held = nil
		for _, rule := range desired {
			held = append(held, Installed{Spec: rule.String(), Family: rule.Family})
		}
		if !now.stuck {
			faults = nil
		}
	}
	written := map[uint8]bool{}
	for _, family := range []uint8{egress.FamilyIPv4, egress.FamilyIPv6} {
		var got, want []string
		for _, rule := range held {
			if rule.Family == family {
				got = append(got, rule.Spec)
			}
		}
		for _, rule := range desired {
			if rule.Family == family {
				want = append(want, rule.String())
			}
		}
		written[family] = faults[family] == "" && slices.Equal(got, want)
	}
	return written
}

// readyAfter is the model's readiness per family once a pass over now has
// run: a family is ready while the pass read back its chain as written, a rule
// keyed on the tun from every source among it, and the host forwards it, and
// neither is ready once the translator is stopped
func readyAfter(rt Runtime, desired []Rule, now step) [2]bool {
	var want [2]bool
	if !now.enabled {
		return want
	}
	written := writtenAfter(now, desired)
	for i, family := range []uint8{egress.FamilyIPv4, egress.FamilyIPv6} {
		steered := slices.ContainsFunc(desired, func(rule Rule) bool {
			return rule.Family == family && rule.Direction == Out && rule.Interface == rt.Interface && !rule.From.IsValid()
		})
		forwards := []bool{now.forward4, now.forward6}[i]
		want[i] = written[family] && steered && forwards
	}
	return want
}

// Over a run of passes on a host drawn anew for each, the readiness handed to
// Ready and kept for Status is readyAfter's, and neither is ready after a
// listing that failed. The prefixes announced are those of each family whose
// chain reads back as written and which the host forwards. Ready is told only
// of a change, never what it already holds, and the pair is false in both
// whenever the tables are withdrawn.
func TestEgressSegmentsReadinessFollowsWhatThePassReadBack(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		drawn := hegel.Draw(ht, exits())
		drawn.rt.Steered = true
		ht.Assume(drawn.takes())
		cfg, rt := drawn.cfg, drawn.rt
		be := &fakeBackend{}
		var now step
		onHost(&rt, &now)
		var calls [][3]bool
		rt.Ready = func(v4, v6, serves bool) {
			calls = append(calls, [3]bool{v4, v6, serves})
			be.record("ready " + strconv.FormatBool(v4) + " " + strconv.FormatBool(v6))
		}
		tr := newTranslator(cfg, rt, be)
		desired := tr.desired()
		count := hegel.Draw(ht, pbt.Spanning(1, 5))
		for range count {
			now = hegel.Draw(ht, steps(desired))
			now.load(be)
			want := readyAfter(rt, desired, now)
			carried := map[uint8]bool{}
			if now.enabled {
				_ = tr.reconcile()
				written := writtenAfter(now, desired)
				carried[egress.FamilyIPv4] = written[egress.FamilyIPv4] && now.forward4
				carried[egress.FamilyIPv6] = written[egress.FamilyIPv6] && now.forward6
			} else {
				_ = tr.stop()
			}
			var announced []netip.Prefix
			for _, prefix := range cfg.Advertise {
				if carried[egress.AddressFamily(prefix.Addr())] {
					announced = append(announced, prefix.Prefix)
				}
			}
			if got := tr.Announce(); !slices.Equal(got, announced) {
				ht.Fatalf("after %+v the translator announces %v, want %v", now, got, announced)
			}
			got := [2]bool{}
			if len(calls) > 0 {
				got = [2]bool(calls[len(calls)-1][:2])
			}
			if got != want {
				ht.Fatalf("after %+v Ready last held %v, want %v", now, got, want)
			}
			if stats := tr.lastPass(); stats.Ready4 != want[0] || stats.Ready6 != want[1] {
				ht.Fatalf("after %+v the pass reports ready %v and %v, want %v", now, stats.Ready4, stats.Ready6, want)
			}
			if stats := tr.lastPass(); now.enabled && (stats.Unready == "") != (want == [2]bool{true, true}) {
				ht.Fatalf("after %+v the pass reports ready %v with the reason %q", now, want, stats.Unready)
			}
		}
		last := [3]bool{}
		for i, call := range calls {
			if call == last {
				ht.Fatalf("Ready was told %v twice in a row, the %d of %v", call, i, calls)
			}
			last = call
		}
		state := "ready false false"
		for _, entry := range be.entries() {
			switch {
			case strings.HasPrefix(entry, "ready"):
				state = entry
			case entry == "withdraw" && state != "ready false false":
				ht.Fatalf("the tables were withdrawn while %s, in %v", state, be.entries())
			}
		}
	})
}

// Over a run of passes on a host whose forwarding is drawn anew for each, half
// the time with nothing else changed, Ready last holds the model's word on the
// egress SIDs: served while at least one family is ready and no family the
// host forwards is not, a word a change of forwarding alone can move with the
// readiness pair left as it was.
func TestSIDIsOriginatedExactlyWhileEveryForwardedFamilyServes(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		drawn := hegel.Draw(ht, exits())
		drawn.rt.Steered = true
		ht.Assume(drawn.takes())
		cfg, rt := drawn.cfg, drawn.rt
		var now step
		onHost(&rt, &now)
		var served bool
		rt.Ready = func(_, _, serves bool) { served = serves }
		be := &fakeBackend{}
		tr := newTranslator(cfg, rt, be)
		desired := tr.desired()
		count := hegel.Draw(ht, pbt.Spanning(2, 6))
		for i := range count {
			if i > 0 && hegel.Draw(ht, hegel.Booleans()) {
				now.forward4, now.forward6 = hegel.Draw(ht, hegel.Booleans()), hegel.Draw(ht, hegel.Booleans())
			} else {
				now = hegel.Draw(ht, steps(desired))
			}
			now.load(be)
			if now.enabled {
				_ = tr.reconcile()
			} else {
				_ = tr.stop()
			}
			ready := readyAfter(rt, desired, now)
			broken := now.forward4 && !ready[0] || now.forward6 && !ready[1]
			if want := (ready[0] || ready[1]) && !broken; served != want {
				ht.Fatalf("pass %d over %+v, ready %v: Ready last held the SIDs served %v, want %v", i, now, ready, served, want)
			}
		}
	})
}
