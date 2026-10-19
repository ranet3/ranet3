// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package egress

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/schema"
)

// exit is a capability and the runtime it runs under.
type exit struct {
	cfg Egress
	rt  Runtime
}

// exits draws an exit: a few prefixes of each family, a default among them,
// return on or off, a source written or left to the host, and an egress device
// or none. The empty advertise list and the egress device are each drawn
// outright half the time.
func exits() hegel.Generator[exit] {
	pool := []schema.Prefix{
		schema.MustPrefix("0.0.0.0/0"), schema.MustPrefix("198.51.100.0/24"), schema.MustPrefix("192.0.2.5/32"),
		schema.MustPrefix("::/0"), schema.MustPrefix("2001:db8:1::/48"),
	}
	return hegel.Composite(func(tc hegel.TestCase) exit {
		var cfg Egress
		if hegel.Draw(tc, hegel.Booleans()) {
			for _, prefix := range hegel.Draw(tc, hegel.Lists(hegel.SampledFrom(pool)).MaxSize(4)) {
				if !slices.Contains(cfg.Advertise, prefix) {
					cfg.Advertise = append(cfg.Advertise, prefix)
				}
			}
		}
		cfg.Return = hegel.Draw(tc, hegel.Booleans())
		if hegel.Draw(tc, hegel.Booleans()) {
			cfg.Source4 = Source{Addr: netip.MustParseAddr("198.51.100.7")}
		}
		if hegel.Draw(tc, hegel.Booleans()) {
			cfg.Source6 = Source{Addr: netip.MustParseAddr("2001:db8::7")}
		}
		rt := Runtime{
			Interface:     "ranet0",
			MeshAddresses: []netip.Addr{netip.MustParseAddr("10.88.0.2"), netip.MustParseAddr("2001:db8::2")},
			Forwarding:    func() (bool, bool) { return true, true },
			Device:        func() (error, error) { return nil, nil },
		}
		if hegel.Draw(tc, hegel.Booleans()) {
			rt.Egress = "ranet0e"
		}
		return exit{cfg, rt}
	})
}

// For every capability New takes, the rules a pass installs follow a model
// written per family: one Out rule keyed on the mesh device where the family
// is advertised, one keyed on the egress device where there is one, whatever
// is advertised, and with return one In rule per advertised prefix of the
// family, keyed on the mesh device and excluding the egress device where there
// is one. A second pass writes nothing, so the
// host holds the order it reads back, and only advertised prefixes are
// announced.
func TestRulesFollowWhatIsAdvertisedAndTheEgressDevice(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		drawn := hegel.Draw(ht, exits())
		cfg, rt := drawn.cfg, drawn.rt
		ht.Assume(cfg.Validate() == nil && cfg.Serves(rt.Egress != "") == nil)
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
		for _, family := range []uint8{FamilyIPv4, FamilyIPv6} {
			advertised := 0
			for _, prefix := range cfg.Advertise {
				if addressFamily(prefix.Addr()) == family {
					advertised++
				}
			}
			var meshOut, egressOut, in int
			for _, rule := range desired {
				switch {
				case rule.Family != family:
				case rule.Direction == In && rule.Egress == rt.Egress:
					in++
				case rule.Direction == Out && rule.Egress == "":
					meshOut++
				case rule.Direction == Out && rule.Egress == rt.Egress:
					egressOut++
				default:
					ht.Fatalf("%+v under %+v asks for %s, which is keyed on neither device", cfg, rt, rule)
				}
			}
			wantMesh, wantEgress, wantIn := min(advertised, 1), 0, 0
			if rt.Egress != "" {
				wantEgress = 1
			}
			if cfg.Return {
				wantIn = advertised
			}
			if meshOut != wantMesh || egressOut != wantEgress || in != wantIn {
				ht.Fatalf("%+v under %+v asks in %s for %d out of the mesh, %d out of the egress device and %d in, want %d, %d and %d",
					cfg, rt, familyName(family), meshOut, egressOut, in, wantMesh, wantEgress, wantIn)
			}
		}
		if got, want := tr.Announce(), plain(cfg.Advertise); !slices.Equal(got, want) {
			ht.Fatalf("%+v under %+v announced %v, want %v", cfg, rt, got, want)
		}
	})
}

// step is one pass of a translator beside an egress device, on a host drawn
// for that pass
type step struct {
	enabled       bool
	failRules     bool
	failApply     bool
	held          []Installed
	forward4      bool
	forward6      bool
	devicePasses4 bool
	devicePasses6 bool
	deviceGone    bool
}

// steps draws what the host holds before each pass: some of the rules the
// translator asks for and now and then a rule of a spelling it never writes,
// forwarding and the egress device's state per family, a listing or an apply
// that fails, and now and then a translator stopped
func steps(desired []Rule) hegel.Generator[step] {
	return hegel.Composite(func(tc hegel.TestCase) step {
		s := step{
			enabled:       hegel.Draw(tc, hegel.WeightedBooleans(7.0/8)),
			failRules:     hegel.Draw(tc, hegel.WeightedBooleans(1.0/8)),
			failApply:     hegel.Draw(tc, hegel.Booleans()),
			forward4:      hegel.Draw(tc, hegel.WeightedBooleans(3.0/4)),
			forward6:      hegel.Draw(tc, hegel.WeightedBooleans(3.0/4)),
			devicePasses4: hegel.Draw(tc, hegel.WeightedBooleans(3.0/4)),
			devicePasses6: hegel.Draw(tc, hegel.WeightedBooleans(3.0/4)),
			deviceGone:    hegel.Draw(tc, hegel.WeightedBooleans(1.0/8)),
		}
		for _, rule := range desired {
			if hegel.Draw(tc, hegel.WeightedBooleans(3.0/4)) {
				s.held = append(s.held, Installed{Spec: rule.String()})
			}
		}
		if hegel.Draw(tc, hegel.WeightedBooleans(1.0/8)) {
			s.held = append(s.held, Installed{Spec: "out via ranet0e not ranet0 ipv4 source 192.0.2.1"})
		}
		return s
	})
}

// onHost points rt's forwarding and egress device readers at the host now
// describes, read at each call
func onHost(rt *Runtime, now *step) {
	rt.Forwarding = func() (bool, bool) { return now.forward4, now.forward6 }
	rt.Device = func() (v4, v6 error) {
		if now.deviceGone {
			gone := fmt.Errorf("ranet0e: %w", ErrDeviceGone)
			return gone, gone
		}
		if !now.devicePasses4 {
			v4 = errors.New("rp_filter")
		}
		if !now.devicePasses6 {
			v6 = errors.New("disable_ipv6")
		}
		return v4, v6
	}
}

// heldAfter names the rules the host holds once a pass over now has run:
// none it could list after a listing that failed, the ones it held where the
// pass found them right or could not apply, and the ones asked for otherwise
func heldAfter(now step, desired []Rule) map[string]bool {
	held := map[string]bool{}
	switch {
	case now.failRules:
	case sameRules(now.held, desired) || now.failApply:
		for _, rule := range now.held {
			held[rule.Spec] = true
		}
	default:
		for _, rule := range desired {
			held[rule.String()] = true
		}
	}
	return held
}

// readyAfter is the model's readiness per family once a pass over now has
// run: a family is ready while the pass read back its rule keyed on the egress
// device, the host forwards it and the device passes it, and neither is ready
// once the translator is stopped
func readyAfter(cfg Egress, rt Runtime, desired []Rule, now step) [2]bool {
	var want [2]bool
	if !now.enabled {
		return want
	}
	held := heldAfter(now, desired)
	for i, family := range []uint8{FamilyIPv4, FamilyIPv6} {
		steered := Rule{Family: family, Direction: Out, Interface: rt.Interface, Egress: rt.Egress, Source: cfg.source(family).Addr}
		forwards := []bool{now.forward4, now.forward6}[i]
		passes := []bool{now.devicePasses4, now.devicePasses6}[i]
		want[i] = held[steered.String()] && forwards && !now.deviceGone && passes
	}
	return want
}

// Over a run of passes on a host drawn anew for each, the readiness handed to
// Ready and kept in Stats is readyAfter's, and neither is ready after a
// listing that failed. Ready is told only of a change, never what it already
// holds, and the pair is false in both whenever the tables are withdrawn.
func TestEgressDeviceReadinessFollowsWhatThePassReadBack(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		drawn := hegel.Draw(ht, exits())
		cfg, rt := drawn.cfg, drawn.rt
		rt.Egress = "ranet0e"
		ht.Assume(cfg.Validate() == nil)
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
			be.held, be.failRules, be.failApply = slices.Clone(now.held), now.failRules, now.failApply
			want := readyAfter(cfg, rt, desired, now)
			whole := map[uint8]bool{}
			if now.enabled {
				_ = tr.reconcile()
				held := heldAfter(now, desired)
				for _, family := range []uint8{FamilyIPv4, FamilyIPv6} {
					whole[family] = map[uint8]bool{FamilyIPv4: now.forward4, FamilyIPv6: now.forward6}[family]
					for _, rule := range desired {
						whole[family] = whole[family] && (rule.Family != family || held[rule.String()])
					}
				}
			} else {
				_ = tr.stop()
			}
			var announced []netip.Prefix
			for _, prefix := range cfg.Advertise {
				if whole[addressFamily(prefix.Addr())] {
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
			if stats := tr.Stats(); stats.Ready4 != want[0] || stats.Ready6 != want[1] {
				ht.Fatalf("after %+v the pass reports ready %v and %v, want %v", now, stats.Ready4, stats.Ready6, want)
			}
			if stats := tr.Stats(); now.enabled && (stats.Unready == "") != (want == [2]bool{true, true}) {
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
		cfg, rt := drawn.cfg, drawn.rt
		rt.Egress = "ranet0e"
		ht.Assume(cfg.Validate() == nil)
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
			be.held, be.failRules, be.failApply = slices.Clone(now.held), now.failRules, now.failApply
			if now.enabled {
				_ = tr.reconcile()
			} else {
				_ = tr.stop()
			}
			ready := readyAfter(cfg, rt, desired, now)
			broken := now.forward4 && !ready[0] || now.forward6 && !ready[1]
			if want := (ready[0] || ready[1]) && !broken; served != want {
				ht.Fatalf("pass %d over %+v, ready %v: Ready last held the SIDs served %v, want %v", i, now, ready, served, want)
			}
		}
	})
}
