// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package egress

import (
	"net/netip"
	"slices"
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
// family, keyed on the mesh device alone. A second pass writes nothing, so the
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
				case rule.Direction == In && rule.Egress == "":
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
