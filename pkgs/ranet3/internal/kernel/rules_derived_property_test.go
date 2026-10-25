// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package kernel

import (
	"math"
	"net/netip"
	"slices"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/schema"
)

// modeOff is routing.md's table of the policy rules on Linux, rule by rule for
// each family
func modeOff(id schema.TableID, overlay, own []netip.Prefix) map[Rule]bool {
	out := map[Rule]bool{}
	for _, v4 := range []bool{true, false} {
		family, suppressed := FamilyIPv6, 15
		if v4 {
			family, suppressed = FamilyIPv4, 7
		}
		for _, rule := range []Rule{
			{Family: family, Priority: 5100, action: actionGoto, target: 5190},
			{Family: family, Priority: 5190, action: actionNop},
			{Family: family, Priority: 5400, action: actionGoto, target: 5490},
			{Family: family, Priority: 5410, Table: 254, suppress: SuppressUpTo(0)},
			{Family: family, Priority: 5420, Table: id, suppress: SuppressUpTo(suppressed)},
			{Family: family, Priority: 5490, action: actionNop},
		} {
			// each goto selects exactly the underlay's mark
			if rule.target != 0 {
				rule.FWMark = schema.UnderlayMark
			}
			out[rule] = true
		}
		for _, prefix := range overlay {
			if prefix.Addr().Is4() == v4 && prefix.Bits() > 0 {
				out[Rule{Family: family, Priority: 5110, To: schema.PrefixFrom(prefix.Masked()), Table: id}] = true
			}
		}
		for _, prefix := range own {
			if prefix.Addr().Is4() == v4 && prefix.Bits() > 0 {
				out[Rule{Family: family, Priority: 5430, From: schema.PrefixFrom(prefix.Masked()), Table: id}] = true
			}
		}
	}
	return out
}

// anyPrefixes draws prefixes of both families, host bits and zero lengths among them
func anyPrefixes() hegel.Generator[[]netip.Prefix] {
	return hegel.Lists(hegel.Composite(func(tc hegel.TestCase) netip.Prefix {
		address := hegel.Draw(tc, hegel.IPAddresses())
		return netip.PrefixFrom(address, hegel.Draw(tc, edges(0, address.BitLen())))
	})).MaxSize(5)
}

// The derivation installs exactly the rules of mode off for every table,
// overlay and set of own prefixes, each once, and lists each nop ahead of the
// goto that lands on it, so a pass adding them in order holds a goto with
// nothing to land on only where the add of its nop failed.
func TestDerivedRulesAreModeOffAndEachNopPrecedesItsGoto(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		id := schema.TableID(hegel.Draw(ht, edges[uint32](1, math.MaxUint32)))
		overlay, own := hegel.Draw(ht, anyPrefixes()), hegel.Draw(ht, anyPrefixes())
		derived := derivedRules(id, prefixes(overlay...), own)
		want := modeOff(id, overlay, own)
		got := map[Rule]bool{}
		for i, rule := range derived {
			if got[rule] {
				ht.Fatalf("%s is derived twice", rule)
			}
			got[rule] = true
			if rule.action == actionGoto && !slices.Contains(derived[:i], Rule{Family: rule.Family, Priority: rule.target, action: actionNop}) {
				ht.Fatalf("%s comes ahead of the nop it lands on in %v", rule, derived)
			}
		}
		for rule := range want {
			if !got[rule] {
				ht.Fatalf("mode off holds %s and the derivation does not, in %v", rule, derived)
			}
		}
		for rule := range got {
			if !want[rule] {
				ht.Fatalf("the derivation holds %s, which mode off does not", rule)
			}
		}
	})
}

// This node's own prefixes hold every address cap.table assigns and every
// prefix it originates that counts as no default, but for one the mesh cannot
// carry, a link-local, loopback or multicast one or the limited broadcast,
// whether assigned or originated, and a LAN cap.egress advertises, and nothing
// a peer announces or a hold carries. A prefix shorter than its family's floor
// counts unless the overlay holds it and it holds no zero address, so
// 10.0.0.0/7 is own and 2000::/3 is not.
// A source-specific announcement D from S routes D to this node only for
// packets from S (RFC 9079 section 4), so D is no source of this node's own.
func TestOwnPrefixesAreTheAssignedAndTheUncountedOriginated(t *testing.T) {
	reconciler, routes, _ := harness(t, Table{}, Runtime{
		Overlay:    prefixes(netip.MustParsePrefix("10.0.0.0/7")),
		Advertised: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
	})
	peer := &netstack.Peer{ID: "example/gateway"}
	for prefix, value := range map[string]*netstack.Peer{
		"192.0.2.0/24":     netstack.Local,
		"2001:db8:1::/48":  netstack.Local,
		"198.51.100.0/24":  netstack.Local,
		"0.0.0.0/0":        netstack.Local,
		"2000::/3":         netstack.Local,
		"10.0.0.0/7":       netstack.Local,
		"203.0.113.7/32":   netstack.Assigned,
		"2001:db8:2::/48":  netstack.Unreachable,
		"2001:db8:3::/48":  peer,
		"3fff::/20":        netstack.Local,
		"169.254.0.0/16":   netstack.Local,
		"2001:db8:4::1/48": netstack.Assigned,
	} {
		routes.Set(netip.Prefix{}, netip.MustParsePrefix(prefix), value)
	}
	routes.Set(netip.MustParsePrefix("2001:db8:a::/48"), netip.MustParsePrefix("2001:db8:5::/48"), netstack.Local)
	own := reconciler.ownPrefixes(routes.Snapshot())
	got := slices.Concat(familyPrefixes(FamilyIPv4, own), familyPrefixes(FamilyIPv6, own))
	want := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/7"), netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("203.0.113.7/32"),
		netip.MustParsePrefix("2001:db8:1::/48"), netip.MustParsePrefix("2001:db8:4::/48"), netip.MustParsePrefix("3fff::/20"),
	}
	if !slices.Equal(got, want) {
		t.Errorf("this node's own prefixes read %v, want %v", got, want)
	}
}

// A pass installs the derived rules in their order, each nop ahead of its
// goto, and a second pass over the same table moves none.
func TestRulePassInstallsTheDerivedRulesInOrderOnce(t *testing.T) {
	overlay := netip.MustParsePrefix("3fff::/20")
	reconciler, routes, fake := harness(t, Table{}, Runtime{Overlay: prefixes(overlay)})
	routes.Set(netip.Prefix{}, netip.MustParsePrefix("3fff:1::/48"), netstack.Local)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	want := derivedRules(DefaultTable, prefixes(overlay), []netip.Prefix{netip.MustParsePrefix("3fff:1::/48")})
	if !slices.Equal(fake.ruleAdded, want) {
		t.Fatalf("the pass added\n%v\nwant\n%v", fake.ruleAdded, want)
	}
	adds, dels := fake.ruleAdds, fake.ruleDels
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if fake.ruleAdds != adds || fake.ruleDels != dels {
		t.Errorf("a second pass moved %d adds and %d deletes", fake.ruleAdds-adds, fake.ruleDels-dels)
	}
}
