// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package kernel

import (
	"fmt"
	"maps"
	"math"
	"net/netip"
	"slices"
	"strings"
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

// modeTwo is mode off with the three rules mode 2 adds, rule by rule for each
// family the tun holds an overlay address of: 5405 from each address of a link
// outside the mesh, 5435 from each connected network shorter than a host
// prefix and each point-to-point far end none of those holds of a link not
// forwarded, 5440 for the host's own traffic and each forwarded link, and no
// 5405 or 5435 from a source the overlay or an own prefix 5430 selects holds.
// A family the tun holds no overlay address of keeps mode off's rules alone.
func modeTwo(id schema.TableID, overlay, own []netip.Prefix, network NetworkState, forwarded []string, unaddressed []Family) map[Rule]bool {
	out := modeOff(id, overlay, own)
	taken := slices.Clone(overlay)
	for _, prefix := range own {
		if prefix.Bits() > 0 {
			taken = append(taken, prefix)
		}
	}
	// a network and a taken prefix share an address exactly where one holds the other's first
	shares := func(network netip.Prefix) bool {
		return slices.ContainsFunc(taken, func(o netip.Prefix) bool { return o.Contains(network.Addr()) || network.Contains(o.Masked().Addr()) })
	}
	for family, links := range map[Family][]Link{FamilyIPv4: network.IPv4.Links, FamilyIPv6: network.IPv6.Links} {
		if slices.Contains(unaddressed, family) {
			continue
		}
		out[Rule{Family: family, Priority: 5440, IIF: "lo", Table: id}] = true
		for _, name := range forwarded {
			out[Rule{Family: family, Priority: 5440, IIF: name, Table: id}] = true
		}
		for _, link := range links {
			for _, prefix := range link.Prefixes {
				address := prefix.Addr()
				if !shares(netip.PrefixFrom(address, address.BitLen())) {
					out[Rule{Family: family, Priority: 5405, From: schema.PrefixFrom(netip.PrefixFrom(address, address.BitLen())), IIF: "lo", Table: 254}] = true
				}
				network := prefix.Masked()
				if !slices.Contains(forwarded, link.Name) && !shares(network) && network.Bits() < address.BitLen() {
					out[Rule{Family: family, Priority: 5435, From: schema.PrefixFrom(network), IIF: "lo", Table: 254}] = true
				}
			}
			for _, peer := range link.Peers {
				// a far end one of the link's own networks holds whole is that network's to select
				held := slices.ContainsFunc(link.Prefixes, func(prefix netip.Prefix) bool {
					network := prefix.Masked()
					return network.Bits() < prefix.Addr().BitLen() && network.Bits() <= peer.Bits() && network.Contains(peer.Masked().Addr())
				})
				if !slices.Contains(forwarded, link.Name) && !shares(peer) && !held {
					out[Rule{Family: family, Priority: 5435, From: schema.PrefixFrom(peer), IIF: "lo", Table: 254}] = true
				}
			}
		}
	}
	return out
}

// modeTwoNone is mode 2 with the two rules fallback = "none" adds, rule by
// rule for each family, one the tun holds no overlay address of included: 5445
// to each own prefix the mesh's table throws by main, and 5450 unreachable for
// the host's own traffic and each forwarded link, less 5405 and 5435 while the
// table does not hold
func modeTwoNone(id schema.TableID, overlay, own []netip.Prefix, network NetworkState, forwarded []string, unaddressed []Family, thrown []netip.Prefix, unheld bool) map[Rule]bool {
	out := modeTwo(id, overlay, own, network, forwarded, unaddressed)
	if unheld {
		maps.DeleteFunc(out, func(rule Rule, _ bool) bool { return rule.Priority == 5405 || rule.Priority == 5435 })
	}
	for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
		out[Rule{Family: family, Priority: 5450, IIF: "lo", action: actionUnreachable}] = true
		for _, name := range forwarded {
			out[Rule{Family: family, Priority: 5450, IIF: name, action: actionUnreachable}] = true
		}
	}
	for _, prefix := range thrown {
		if prefix.Bits() > 0 {
			out[Rule{Family: familyOf(prefix.Addr()), Priority: 5445, To: schema.PrefixFrom(prefix.Masked()), Table: 254}] = true
		}
	}
	return out
}

// exitAddresses are the addresses a drawn link holds per family: the overlay's
// among them, as on lo, so the filter is drawn often
var exitAddresses = map[Family][]string{
	FamilyIPv4: {"192.0.2.1", "192.0.2.200", "198.51.100.10", "198.51.100.130", "203.0.113.7"},
	FamilyIPv6: {"3fff::1", "3fff:0:0:1::1", "3fff::10", "2001:db8::10", "2001:db8:1::10"},
}

// exitLengths are the lengths a drawn address carries per family, a network
// holding the overlay among them
var exitLengths = map[Family][]int{FamilyIPv4: {16, 24, 25, 32}, FamilyIPv6: {16, 48, 64, 128}}

// exitPeers are the far ends a drawn point-to-point link reaches per family,
// one inside the overlay among them
var exitPeers = map[Family][]string{
	FamilyIPv4: {"203.0.113.128/25", "203.0.113.2/32", "192.0.2.0/25"},
	FamilyIPv6: {"2001:db8:6::/128", "3fff::6/128"},
}

// exitOverlays are the overlay prefixes a drawn overlay holds
var exitOverlays = []string{"192.0.2.0/24", "192.0.2.128/25", "3fff::/20", "3fff:0:0:1::/64"}

// exitOwn are own prefixes a drawn node announces, each holding or inside a
// drawn link's address or network, so the own filter is drawn often
var exitOwn = []string{"198.51.100.128/25", "203.0.113.7/32", "2001:db8:1::/48", "2001:db8::/32"}

// exitLinks are the names a drawn host holds its links under
var exitLinks = []string{"br-1a", "docker0", "eth0", "lo", "wlan0"}

// drawnExitLinks draws a family's links: each name of exitLinks or not, each
// with up to two of the family's addresses at drawn lengths and now and then a
// point-to-point far end
func drawnExitLinks(tc hegel.TestCase, family Family) []Link {
	var out []Link
	for _, name := range exitLinks {
		if hegel.Draw(tc, pbt.Spanning(0, 1)) == 0 {
			continue
		}
		link := Link{Name: name}
		for range hegel.Draw(tc, pbt.Spanning(0, 2)) {
			address := netip.MustParseAddr(exitAddresses[family][hegel.Draw(tc, pbt.Spanning(0, len(exitAddresses[family])-1))])
			link.Prefixes = append(link.Prefixes, netip.PrefixFrom(address, exitLengths[family][hegel.Draw(tc, pbt.Spanning(0, len(exitLengths[family])-1))]))
		}
		if hegel.Draw(tc, pbt.Spanning(0, 2)) == 2 {
			link.Peers = []netip.Prefix{netip.MustParsePrefix(exitPeers[family][hegel.Draw(tc, pbt.Spanning(0, len(exitPeers[family])-1))])}
		}
		out = append(out, link)
	}
	return out
}

// The derivation installs exactly mode 2's rules for every table, overlay, set
// of own prefixes, links, forwarded links and families the tun holds no overlay
// address of, with fallback = "none"'s two more for every set of thrown
// prefixes and its table's 5405 and 5435 out while it does not hold, each once
// with each nop ahead of its goto, and exactly mode off's
// when the mode is off, whatever the links and the fallback. No 5405 or 5435
// selects a source the overlay or an own prefix holds.
func TestDerivedRulesAreModeTwoWithTheLinksAndModeOffWithout(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		id := schema.TableID(hegel.Draw(ht, edges[uint32](1, math.MaxUint32)))
		own := hegel.Draw(ht, anyPrefixes())
		for _, written := range exitOwn {
			if hegel.Draw(ht, pbt.Spanning(0, 2)) == 2 {
				own = append(own, netip.MustParsePrefix(written))
			}
		}
		var overlay []netip.Prefix
		for _, written := range exitOverlays {
			if hegel.Draw(ht, pbt.Spanning(0, 1)) == 1 {
				overlay = append(overlay, netip.MustParsePrefix(written))
			}
		}
		network := NetworkState{IPv4: NetworkFamily{Links: drawnExitLinks(ht, FamilyIPv4)}, IPv6: NetworkFamily{Links: drawnExitLinks(ht, FamilyIPv6)}}
		var forwarded []string
		for _, name := range exitLinks {
			if name != "lo" && hegel.Draw(ht, pbt.Spanning(0, 1)) == 1 {
				forwarded = append(forwarded, name)
			}
		}
		var unaddressed []Family
		for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
			if hegel.Draw(ht, pbt.Spanning(0, 2)) == 2 {
				unaddressed = append(unaddressed, family)
			}
		}
		on := hegel.Draw(ht, pbt.Spanning(0, 1)) == 1
		none := hegel.Draw(ht, pbt.Spanning(0, 1)) == 1
		unheld := hegel.Draw(ht, pbt.Spanning(0, 1)) == 1
		thrown := hegel.Draw(ht, anyPrefixes())

		derived := derivedRules(id, prefixes(overlay...), own, exitView{on: on, network: network, forwarded: forwarded, unaddressed: unaddressed, fallback: none, own: thrown, unheld: unheld})
		want := modeOff(id, overlay, own)
		switch {
		case on && none:
			want = modeTwoNone(id, overlay, own, network, forwarded, unaddressed, thrown, unheld)
		case on:
			want = modeTwo(id, overlay, own, network, forwarded, unaddressed)
		}
		got := map[Rule]bool{}
		for i, rule := range derived {
			if got[rule] {
				ht.Fatalf("%s is derived twice", rule)
			}
			got[rule] = true
			if rule.action == actionGoto && !slices.Contains(derived[:i], Rule{Family: rule.Family, Priority: rule.target, action: actionNop}) {
				ht.Fatalf("%s comes ahead of the nop it lands on in %v", rule, derived)
			}
			if (rule.Priority == 5405 || rule.Priority == 5435) && slices.ContainsFunc(overlay, rule.From.Overlaps) {
				ht.Fatalf("%s selects a source of the overlay %v", rule, overlay)
			}
			if (rule.Priority == 5405 || rule.Priority == 5435) && slices.ContainsFunc(own, func(o netip.Prefix) bool { return o.Bits() > 0 && rule.From.Overlaps(o) }) {
				ht.Fatalf("%s selects a source of this node's own %v", rule, own)
			}
		}
		for rule := range want {
			if !got[rule] {
				ht.Fatalf("mode on %v, none %v holds %s and the derivation does not, in %v", on, none, rule, derived)
			}
		}
		for rule := range got {
			if !want[rule] {
				ht.Fatalf("the derivation in mode on %v, none %v holds %s, which the mode does not", on, none, rule)
			}
		}
	})
}

// modeTwoRules is the rules at 5405, 5435 and 5440 the derivation gives for
// view, each as its family, its priority, its source and its input link, once
// and sorted, and fails t where one looks up another table than its priority's
func modeTwoRules(t *testing.T, overlay []schema.Prefix, own []netip.Prefix, view exitView) []string {
	t.Helper()
	var out []string
	for _, rule := range derivedRules(DefaultTable, overlay, own, view) {
		lookup := schema.TableMain
		switch rule.Priority {
		case priorityUplinkSource, priorityLinkSource:
		case priorityCatchAll:
			lookup = DefaultTable
		default:
			continue
		}
		if rule.Table != lookup {
			t.Errorf("%s looks up %s, want %s", rule, rule.Table, lookup)
		}
		words := []string{string(rule.Family), fmt.Sprint(rule.Priority)}
		if rule.From.IsValid() {
			words = append(words, "from", rule.From.String())
		}
		out = append(out, strings.Join(append(words, "iif", rule.IIF), " "))
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// Mode 2 derives 5405 from each address of a link outside the mesh, 5435 from
// each connected network shorter than a host prefix and each point-to-point
// far end of a link forward leaves out, and 5440 for the host's own traffic
// and each link forward names:
//   - an overlay address on lo, as a host checking the mesh puts one there, is
//     no source 5405 or 5435 selects, so the host's packet from it meets 5430
//     and enters the mesh, and a connected network holding the overlay is left
//     out of 5435 whole while its address outside the overlay stays in 5405
//   - a subnet router's address in the LAN it announces is no source either,
//     nor is the LAN, whether or not forward names the LAN's link, so the
//     host's packet from that address meets 5430 in mode 2 as in mode off
//   - a host-length address, as a point-to-point link's /32 or a DHCPv6 /128,
//     takes 5405 alone
//   - a point-to-point link's far end is the network main routes by it, so
//     5435 selects it where forward leaves the link out, but where a network
//     of the same link holds it, whose rule answers for it already
//   - a family the tun holds no overlay address of runs mode off's rules, with
//     no 5405, 5435 or 5440
func TestModeTwoDerivesItsRulesFromTheLinks(t *testing.T) {
	p := netip.MustParsePrefix
	uplink := NetworkState{
		IPv4: NetworkFamily{Links: []Link{{Name: "eth0", Prefixes: []netip.Prefix{p("198.51.100.10/24")}}}},
		IPv6: NetworkFamily{Links: []Link{{Name: "eth0", Prefixes: []netip.Prefix{p("2001:db8::10/64")}}}},
	}
	beside := func(v4, v6 Link) NetworkState {
		return NetworkState{
			IPv4: NetworkFamily{Links: append(slices.Clone(uplink.IPv4.Links), v4)},
			IPv6: NetworkFamily{Links: append(slices.Clone(uplink.IPv6.Links), v6)},
		}
	}
	farEnd := NetworkState{IPv4: NetworkFamily{Links: []Link{{Name: "tun9", Prefixes: []netip.Prefix{p("203.0.113.1/32")}, Peers: []netip.Prefix{p("198.51.100.128/25")}}}}}
	uplinkRules := []string{"ipv4 5405 from 198.51.100.10/32 iif lo", "ipv4 5435 from 198.51.100.0/24 iif lo", "ipv6 5405 from 2001:db8::10/128 iif lo", "ipv6 5435 from 2001:db8::/64 iif lo"}
	host := []string{"ipv4 5440 iif lo", "ipv6 5440 iif lo"}
	for _, c := range []struct {
		what    string
		overlay []schema.Prefix
		own     []netip.Prefix
		view    exitView
		want    []string
	}{
		{
			what:    "an overlay address on lo and a network holding the overlay on dummy0",
			overlay: prefixes(p("192.0.2.0/24"), p("3fff:0:0:1::/64")),
			view: exitView{on: true, network: NetworkState{
				IPv4: NetworkFamily{Links: []Link{
					{Name: "eth0", Prefixes: []netip.Prefix{p("198.51.100.10/24")}},
					{Name: "lo", Prefixes: []netip.Prefix{p("192.0.2.1/32")}},
				}},
				IPv6: NetworkFamily{Links: []Link{
					{Name: "dummy0", Prefixes: []netip.Prefix{p("3fff::10/48")}},
					{Name: "eth0", Prefixes: []netip.Prefix{p("2001:db8::10/64")}},
					{Name: "lo", Prefixes: []netip.Prefix{p("3fff:0:0:1::1/128")}},
				}},
			}},
			want: slices.Concat(uplinkRules, host, []string{"ipv6 5405 from 3fff::10/128 iif lo"}),
		},
		{
			what: "a subnet router's address in the LAN it announces",
			own:  []netip.Prefix{p("203.0.113.64/26"), p("2001:db8:50::/64")},
			view: exitView{on: true, network: beside(
				Link{Name: "eth1", Prefixes: []netip.Prefix{p("203.0.113.65/26")}},
				Link{Name: "eth1", Prefixes: []netip.Prefix{p("2001:db8:50::1/64")}})},
			want: slices.Concat(uplinkRules, host),
		},
		{
			what: "a subnet router's address in the LAN it announces, forward naming the LAN's link",
			own:  []netip.Prefix{p("203.0.113.64/26"), p("2001:db8:50::/64")},
			view: exitView{on: true, forwarded: []string{"eth1"}, network: beside(
				Link{Name: "eth1", Prefixes: []netip.Prefix{p("203.0.113.65/26")}},
				Link{Name: "eth1", Prefixes: []netip.Prefix{p("2001:db8:50::1/64")}})},
			want: slices.Concat(uplinkRules, host, []string{"ipv4 5440 iif eth1", "ipv6 5440 iif eth1"}),
		},
		{
			what: "a host-length address on a link forward leaves out",
			view: exitView{on: true, network: NetworkState{
				IPv4: NetworkFamily{Links: []Link{{Name: "ppp0", Prefixes: []netip.Prefix{p("198.51.100.10/32")}}}},
				IPv6: NetworkFamily{Links: []Link{{Name: "eth0", Prefixes: []netip.Prefix{p("2001:db8::10/128")}}}},
			}},
			want: slices.Concat(host, []string{"ipv4 5405 from 198.51.100.10/32 iif lo", "ipv6 5405 from 2001:db8::10/128 iif lo"}),
		},
		{
			what: "a point-to-point far end on a link forward leaves out",
			view: exitView{on: true, network: farEnd},
			want: slices.Concat(host, []string{"ipv4 5405 from 203.0.113.1/32 iif lo", "ipv4 5435 from 198.51.100.128/25 iif lo"}),
		},
		{
			what: "a point-to-point far end on a link forward names",
			view: exitView{on: true, network: farEnd, forwarded: []string{"tun9"}},
			want: slices.Concat(host, []string{"ipv4 5405 from 203.0.113.1/32 iif lo", "ipv4 5440 iif tun9", "ipv6 5440 iif tun9"}),
		},
		{
			what: "an IPv6 far end inside its link's network and one outside it",
			view: exitView{on: true, network: NetworkState{IPv6: NetworkFamily{Links: []Link{
				{Name: "tun8", Prefixes: []netip.Prefix{p("2001:db8:7::1/64")}, Peers: []netip.Prefix{p("2001:db8:6::1/128")}},
				{Name: "tun9", Prefixes: []netip.Prefix{p("2001:db8:5::1/64")}, Peers: []netip.Prefix{p("2001:db8:5::2/128")}},
			}}}},
			want: slices.Concat(host, []string{
				"ipv6 5405 from 2001:db8:5::1/128 iif lo", "ipv6 5405 from 2001:db8:7::1/128 iif lo",
				"ipv6 5435 from 2001:db8:5::/64 iif lo", "ipv6 5435 from 2001:db8:6::1/128 iif lo", "ipv6 5435 from 2001:db8:7::/64 iif lo",
			}),
		},
		{
			what: "the tun holding no IPv4 overlay address",
			view: exitView{on: true, network: uplink, forwarded: []string{"docker0"}, unaddressed: []Family{FamilyIPv4}},
			want: []string{"ipv6 5405 from 2001:db8::10/128 iif lo", "ipv6 5435 from 2001:db8::/64 iif lo", "ipv6 5440 iif docker0", "ipv6 5440 iif lo"},
		},
		{
			what: "the tun holding no IPv6 overlay address",
			view: exitView{on: true, network: uplink, forwarded: []string{"docker0"}, unaddressed: []Family{FamilyIPv6}},
			want: []string{"ipv4 5405 from 198.51.100.10/32 iif lo", "ipv4 5435 from 198.51.100.0/24 iif lo", "ipv4 5440 iif docker0", "ipv4 5440 iif lo"},
		},
		{
			what: "the tun holding no overlay address of either family",
			view: exitView{on: true, network: uplink, forwarded: []string{"docker0"}, unaddressed: []Family{FamilyIPv4, FamilyIPv6}},
		},
	} {
		if got, want := modeTwoRules(t, c.overlay, c.own, c.view), slices.Sorted(slices.Values(c.want)); !slices.Equal(got, want) {
			t.Errorf("mode 2 with %s derives\n%s\nwant\n%s", c.what, strings.Join(got, "\n"), strings.Join(want, "\n"))
		}
	}
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
		derived := derivedRules(id, prefixes(overlay...), own, exitView{})
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
	want := derivedRules(DefaultTable, prefixes(overlay), []netip.Prefix{netip.MustParsePrefix("3fff:1::/48")}, exitView{})
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
