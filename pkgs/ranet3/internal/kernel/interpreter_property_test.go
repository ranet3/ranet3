// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package kernel

import (
	"cmp"
	"encoding/binary"
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

// fibRoute is one route of a table as the model of Linux holds it
type fibRoute struct {
	destination, source netip.Prefix
	metric              uint32
	// device is the link a unicast route leaves by, empty for a throw or an unreachable route
	device             string
	throw, unreachable bool
}

// fibPacket is one lookup: a packet's source, its destination, its mark and the
// link it arrived on, empty for the host's own lookup, which the kernel makes
// with the loopback link as its input
type fibPacket struct {
	source, destination netip.Addr
	mark                uint32
	iif                 string
}

// input is the link the kernel gives p's lookup as its input
func (p fibPacket) input() string { return cmp.Or(p.iif, loopback) }

func (p fibPacket) String() string {
	return fmt.Sprintf("from %s to %s mark %#x iif %s", p.source, p.destination, p.mark, p.input())
}

// fib is the model of Linux's policy routing: the rules in the order the
// kernel walks them, and the tables they look up
type fib struct {
	rules  []Rule
	tables map[schema.TableID][]fibRoute
}

// lookup is a table's answer for p, as fib_table_lookup and fib6_lookup give it
// the longest destination wins, then for IPv6 the longest source among the
// routes whose source holds p's, a node whose sources all miss giving way to a
// shorter destination as fib6_backtrack does, then the lowest metric
func lookup(routes []fibRoute, p fibPacket) (fibRoute, bool) {
	var best fibRoute
	found := false
	for _, route := range routes {
		if !route.destination.Contains(p.destination) || route.source.IsValid() && !route.source.Contains(p.source) {
			continue
		}
		if !found || cmp.Or(
			cmp.Compare(route.destination.Bits(), best.destination.Bits()),
			cmp.Compare(sourceBits(route), sourceBits(best)),
			cmp.Compare(best.metric, route.metric),
		) > 0 {
			best, found = route, true
		}
	}
	return best, found
}

func sourceBits(route fibRoute) int {
	if !route.source.IsValid() {
		return -1
	}
	return route.source.Bits()
}

// matches is fib_rule_match and the families' match for one rule
// a rule naming a mark and no mask matches the mark exactly, as the kernel's
// default mask of all ones does
func matches(rule Rule, p fibPacket) bool {
	if familyOf(p.destination) != rule.Family {
		return false
	}
	if rule.To.IsValid() && !rule.To.Contains(p.destination) || rule.From.IsValid() && !rule.From.Contains(p.source) {
		return false
	}
	if rule.IIF != "" && rule.IIF != p.input() {
		return false
	}
	mask := rule.FWMask
	if rule.FWMark != 0 && mask == 0 {
		mask = ^uint32(0)
	}
	return (rule.FWMark^p.mark)&mask == 0
}

// walk is fib_rules_lookup over the rules, which each name a family
// a goto continues at the first rule of its target's priority and is passed over
// while it has none, a nop continues, and a lookup that finds no route or a
// throw continues. An unreachable route ends the walk unsuppressed, and a
// unicast route ends it unless its length is at or under the rule's suppress
// length. It answers the device, "unreachable", or "none" past the last rule.
func (f fib) walk(p fibPacket) string {
	for i := 0; i < len(f.rules); i++ {
		rule := f.rules[i]
		if !matches(rule, p) {
			continue
		}
		switch rule.action {
		case actionGoto:
			if target := slices.IndexFunc(f.rules, func(r Rule) bool { return r.Family == rule.Family && r.Priority == rule.target }); target > i {
				i = target - 1
			}
			continue
		case actionNop:
			continue
		}
		route, ok := lookup(f.tables[rule.Table], p)
		switch {
		case !ok, route.throw:
			continue
		case route.unreachable:
			return "unreachable"
		}
		if bits, set := rule.suppress.Bits(); set && route.destination.Bits() <= bits {
			continue
		}
		return route.device
	}
	return "none"
}

// only is f with the rules keep takes
func (f fib) only(keep func(Rule) bool) fib {
	return fib{rules: slices.DeleteFunc(slices.Clone(f.rules), func(rule Rule) bool { return !keep(rule) }), tables: f.tables}
}

const (
	tunDevice      = "tun"
	tailnetTable   = schema.TableID(52)
	lateTable      = schema.TableID(99)
	earlyTable     = schema.TableID(300)
	ownProtocolEnd = priorityMeshEnd
)

// uplink is the host's address on its uplink, which a drawn table of the mesh
// can cover, such as by 198.51.100.0/25 or 128.0.0.0/1
var uplink = map[bool]netip.Addr{false: netip.MustParseAddr("198.51.100.10"), true: netip.MustParseAddr("2001:db8:a::10")}

// hostWith is a host with main's default and connected network through eth0,
// the routes more adds to each table, a LAN through eth1 in main, a tailnet's
// table, and two foreign tables, and the rules of each family rules gives with
// main's at 32766
func hostWith(more map[schema.TableID][]netip.Prefix, rules func(Family) []Rule) fib {
	host := fib{tables: map[schema.TableID][]fibRoute{}}
	for _, v6 := range []bool{false, true} {
		defaultRoute := netip.PrefixFrom(netip.IPv4Unspecified(), 0)
		if v6 {
			defaultRoute = netip.PrefixFrom(netip.IPv6Unspecified(), 0)
		}
		bits := map[bool]int{false: 24, true: 64}[v6]
		host.tables[schema.TableMain] = append(host.tables[schema.TableMain],
			fibRoute{destination: defaultRoute, device: "eth0"},
			fibRoute{destination: netip.PrefixFrom(uplink[v6], bits).Masked(), device: "eth0"},
		)
	}
	for table, device := range map[schema.TableID]string{schema.TableMain: "eth1", tailnetTable: "tailscale0", lateTable: "wg0", earlyTable: "eth2"} {
		for _, destination := range more[table] {
			if table == schema.TableMain && destination.Bits() == 0 {
				continue
			}
			host.tables[table] = append(host.tables[table], fibRoute{destination: destination, device: device})
		}
	}
	for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
		host.rules = append(host.rules, rules(family)...)
		host.rules = append(host.rules, Rule{Family: family, Priority: 32766, Table: schema.TableMain})
	}
	return host
}

// foreignGoto is the priority of another program's goto, after its rule at 100
// and ahead of ranet3's rules
const foreignGoto = 5050

// gotoTargets are where another program's goto may jump: a priority of
// ranet3's, one of another program's rules, and one where no rule sits, which
// the kernel passes over, as it does mode 2's priorities in mode off
var gotoTargets = []uint32{
	priorityUnderlayPastOverlay, priorityOverlay, priorityOverlayEnd, 5270, 5300, priorityUnderlayPastMesh,
	priorityUplinkSource, priorityMain, priorityMesh, priorityOwn, priorityLinkSource, priorityCatchAll, priorityMeshEnd, 5500,
}

// drawHost draws the tables and the rules another program holds beside
// ranet3's: up to two routes of each family in each table, and in each family
// a rule ahead of ranet3's at 100 selecting a destination, a goto at 5050 to
// one of gotoTargets, a tailnet's at 5270 between ranet3's two blocks, and one
// past them at 5500, each now and then
func drawHost(tc hegel.TestCase) fib {
	more := map[schema.TableID][]netip.Prefix{}
	for _, table := range []schema.TableID{schema.TableMain, tailnetTable, lateTable, earlyTable} {
		for _, v6 := range []bool{false, true} {
			more[table] = append(more[table], hegel.Draw(tc, hegel.Lists(nearPrefixes(v6)).MaxSize(2))...)
		}
	}
	return hostWith(more, func(family Family) []Rule {
		var out []Rule
		if hegel.Draw(tc, hegel.Booleans()) {
			to := hegel.Draw(tc, nearPrefixes(family == FamilyIPv6))
			out = append(out, Rule{Family: family, Priority: 100, To: schema.PrefixFrom(to), Table: earlyTable})
		}
		if hegel.Draw(tc, hegel.WeightedBooleans(0.25)) {
			out = append(out, Rule{Family: family, Priority: foreignGoto, action: actionGoto, target: hegel.Draw(tc, hegel.SampledFrom(gotoTargets))})
		}
		if hegel.Draw(tc, hegel.Booleans()) {
			out = append(out, Rule{Family: family, Priority: 5270, Table: tailnetTable})
		}
		if hegel.Draw(tc, hegel.Booleans()) {
			out = append(out, Rule{Family: family, Priority: 5500, Table: lateTable})
		}
		return out
	})
}

// addressIn draws an address of prefix, its host bits drawn
func addressIn(tc hegel.TestCase, prefix netip.Prefix) netip.Addr {
	address := prefix.Addr().AsSlice()
	var random [16]byte
	binary.BigEndian.PutUint64(random[:8], hegel.Draw(tc, hegel.Integers[uint64](0, math.MaxUint64)))
	binary.BigEndian.PutUint64(random[8:], hegel.Draw(tc, hegel.Integers[uint64](0, math.MaxUint64)))
	for i := range address {
		keep := min(max(prefix.Bits()-8*i, 0), 8)
		mask := byte(0xff << (8 - keep))
		address[i] = address[i]&mask | random[i]&^mask
	}
	out, _ := netip.AddrFromSlice(address)
	return out
}

// overlays draws cap.border's overlay: up to two prefixes, each as long as
// Border.Validate takes or longer, MinSourceBits4 or MinSourceBits6, mostly of
// mesh space and now and then one holding its family's unspecified address or
// one the mesh cannot carry, neither of which gets a hold
func overlays() hegel.Generator[[]schema.Prefix] {
	return hegel.Composite(func(tc hegel.TestCase) []schema.Prefix {
		var out []schema.Prefix
		for range hegel.Draw(tc, hegel.Integers(0, 2)) {
			v6 := hegel.Draw(tc, hegel.Booleans())
			bases, unheld, least := []string{"10.0.0.0", "192.0.2.0"}, []string{"0.0.0.0", "224.0.0.0"}, schema.MinSourceBits4
			if v6 {
				bases, unheld, least = []string{"3fff::", "2001:db8::"}, []string{"::", "fe80::"}, schema.MinSourceBits6
			}
			if hegel.Draw(tc, hegel.WeightedBooleans(0.25)) {
				bases = unheld
			}
			base := netip.MustParseAddr(hegel.Draw(tc, hegel.SampledFrom(bases)))
			out = append(out, schema.PrefixFrom(netip.PrefixFrom(base, hegel.Draw(tc, edges(least, base.BitLen()))).Masked()))
		}
		return out
	})
}

// interpreted is one drawn host: ranet3's table and runtime, the reconciler's
// gate, the host's other tables and rules, and the model holding them with
// ranet3's derived rules and mirror
type interpreted struct {
	routes *netstack.RouteTable
	rt     Runtime
	gate   bool
	exit   bool
	// own is this node's own prefixes as routing.md's policy rules name them,
	// sources every prefix of a Local or an Assigned entry, and assigned the
	// addresses cap.table assigns
	own, sources, assigned []netip.Prefix
	host                   fib
	kernel                 fib
	desired                []Route
	mode                   exitView
}

// exitInputs names each input that turns a node into an exit, drawn outright
// beside none: an egress segment, a prefix that counts which cap.egress
// advertises, and one cap.route announces
var exitInputs = []string{"none", "an egress segment", "a counted advertisement", "a counted announcement"}

// drawInterpreted draws a host and builds its kernel from the reconciler's own derivation, with the families the tun holds no
// overlay address of that the caller names
func drawInterpreted(t *testing.T, ht *hegel.T) func(unaddressed []Family) interpreted {
	overlay := hegel.Draw(ht, overlays())
	var entries []mirrorEntry
	for _, entry := range hegel.Draw(ht, mirrorEntries()) {
		if entry.value == netstack.Assigned {
			// cap.table assigns an address, which the host's local table answers before any rule
			address := addressIn(ht, entry.destination)
			entry.source, entry.destination = netip.Prefix{}, netip.PrefixFrom(address, address.BitLen())
		}
		entries = append(entries, entry)
	}
	// a learned split or default of each family now and then, which the drawn entries seldom are
	for _, v6 := range []bool{false, true} {
		if hegel.Draw(ht, hegel.Booleans()) {
			base, floor := netip.MustParseAddr("64.0.0.0"), schema.MinSubnetBits4
			if v6 {
				base, floor = netip.MustParseAddr("2000::"), schema.MinSubnetBits6
			}
			split := netip.PrefixFrom(base, hegel.Draw(ht, edges(0, floor))).Masked()
			entries = append(entries, mirrorEntry{destination: split, value: learned})
		}
	}
	// a quarter of the time an IPv6 overlay prefix of /12 to /15 with a learned route inside it no longer than 5420's
	// suppress length, which 5110 alone answers and which counts as no default for lying inside the overlay
	if hegel.Draw(ht, hegel.WeightedBooleans(0.25)) {
		bits := hegel.Draw(ht, hegel.Integers(schema.MinSourceBits6, schema.MinSubnetBits6-1))
		wide := netip.PrefixFrom(netip.MustParseAddr("3fff::"), bits).Masked()
		overlay = append(overlay, schema.PrefixFrom(wide))
		inside := netip.PrefixFrom(wide.Addr(), hegel.Draw(ht, hegel.Integers(bits, schema.MinSubnetBits6-1)))
		entries = append(entries, mirrorEntry{destination: inside, value: learned})
	}
	advertised := map[netip.Prefix]bool{}
	for _, entry := range entries {
		if entry.value == netstack.Local && !entry.source.IsValid() && hegel.Draw(ht, hegel.WeightedBooleans(0.25)) {
			advertised[entry.destination.Masked()] = true
		}
	}
	// most of the time a LAN of this node's and a learned half that counts, and half the time a LAN cap.egress
	// advertises beside them, the lookups whose way past 5430 an exit's inputs and an advertised LAN decide
	if hegel.Draw(ht, hegel.WeightedBooleans(0.75)) {
		entries = append(entries, mirrorEntry{destination: prefix("198.51.100.0/25"), value: netstack.Local}, mirrorEntry{destination: prefix("128.0.0.0/1"), value: learned})
		if hegel.Draw(ht, hegel.Booleans()) {
			entries = append(entries, mirrorEntry{destination: prefix("198.51.100.128/25"), value: netstack.Local})
			advertised[prefix("198.51.100.128/25")] = true
		}
	}
	egressSegment := false
	// a node that is no exit half the time, the one node whose 5430 sends a counted route's packets to the mesh
	input := exitInputs[0]
	if hegel.Draw(ht, hegel.Booleans()) {
		input = hegel.Draw(ht, hegel.SampledFrom(exitInputs[1:]))
	}
	switch input {
	case "an egress segment":
		egressSegment = true
	case "a counted advertisement", "a counted announcement":
		counted := hegel.Draw(ht, hegel.SampledFrom([]netip.Prefix{prefix("0.0.0.0/0"), prefix("0.0.0.0/1"), prefix("::/0"), prefix("2000::/3")}))
		entries = append(entries, mirrorEntry{destination: counted, value: netstack.Local})
		advertised[counted] = input == "a counted advertisement"
	}
	gate := hegel.Draw(ht, hegel.WeightedBooleans(0.75))
	host, mode := drawHost(ht), drawExitMode(ht, overlay)
	return func(unaddressed []Family) interpreted {
		m := mode
		m.unaddressed = unaddressed
		return interpret(t, overlay, entries, advertised, egressSegment, gate, host, m)
	}
}

// exitLink is a link outside the mesh a drawn host holds now and then, with
// its address in each family
type exitLink struct{ name, v4, v6 string }

// drawExitMode draws mode 2 half the time and mode off otherwise, over links
// drawn whatever the mode: eth0 holding the uplink's address, now and then a
// bridge, a LAN through eth1 and a point-to-point ppp0 with its far end, and
// now and then an address of the overlay on lo or on dummy0 with a network
// about it. forward names any of the bridge, the LAN, ppp0 and docker0, a
// bridge holding no address.
func drawExitMode(ht *hegel.T, overlay []schema.Prefix) exitView {
	mode := exitView{on: hegel.Draw(ht, hegel.Booleans())}
	for _, v6 := range []bool{false, true} {
		bits := map[bool]int{false: 24, true: 64}[v6]
		links := []Link{{Name: "eth0", Prefixes: []netip.Prefix{netip.PrefixFrom(uplink[v6], bits)}}}
		for _, link := range []exitLink{{"br-1a", "203.0.113.129/26", "2001:db8:17::1/64"}, {"eth1", "203.0.113.65/26", "2001:db8:50::1/64"}} {
			if hegel.Draw(ht, hegel.Booleans()) {
				links = append(links, Link{Name: link.name, Prefixes: []netip.Prefix{netip.MustParsePrefix(map[bool]string{false: link.v4, true: link.v6}[v6])}})
			}
		}
		if hegel.Draw(ht, hegel.Booleans()) {
			// a point-to-point link, as the reader gives one: IPv4 holds its address alone and routes the far end's network, IPv6 the reverse
			links = append(links, map[bool]Link{
				false: {Name: "ppp0", Prefixes: []netip.Prefix{netip.MustParsePrefix("203.0.113.1/32")}, Peers: []netip.Prefix{netip.MustParsePrefix("203.0.113.16/28")}},
				true:  {Name: "ppp0", Prefixes: []netip.Prefix{netip.MustParsePrefix("2001:db8:60::1/64")}, Peers: []netip.Prefix{netip.MustParsePrefix("2001:db8:61::1/128")}},
			}[v6])
		}
		var held []netip.Prefix
		for _, prefix := range overlay {
			if prefix.Addr().Is6() == v6 {
				held = append(held, prefix.Masked())
			}
		}
		if len(held) > 0 && hegel.Draw(ht, hegel.Booleans()) {
			within := hegel.Draw(ht, hegel.SampledFrom(held))
			address := addressIn(ht, within)
			link := Link{Name: loopback, Prefixes: []netip.Prefix{netip.PrefixFrom(address, address.BitLen())}}
			if hegel.Draw(ht, hegel.Booleans()) {
				// a network holding the overlay prefix, or one inside it
				floor := map[bool]int{false: schema.MinSubnetBits4, true: schema.MinSubnetBits6}[v6]
				link = Link{Name: "dummy0", Prefixes: []netip.Prefix{netip.PrefixFrom(address, hegel.Draw(ht, hegel.Integers(max(within.Bits()-4, floor), address.BitLen())))}}
			}
			links = append(links, link)
		}
		if v6 {
			mode.network.IPv6.Links = links
		} else {
			mode.network.IPv4.Links = links
		}
	}
	for _, name := range []string{"br-1a", "eth1", "ppp0", "docker0"} {
		if hegel.Draw(ht, hegel.Booleans()) {
			mode.forwarded = append(mode.forwarded, name)
		}
	}
	return mode
}

// interpret builds the kernel of a host holding host's rules and tables, whose
// ranet3 holds entries under overlay, advertises the prefixes of its own
// advertised names through cap.egress and announces the rest through
// cap.route, holds an egress segment where egressSegment says, whose capture
// gate is open where gate says, and which runs mode, whose links but lo's hold
// their connected networks in main
func interpret(t *testing.T, overlay []schema.Prefix, entries []mirrorEntry, advertised map[netip.Prefix]bool, egressSegment, gate bool, host fib, mode exitView) interpreted {
	routes := netstack.NewRouteTable()
	routes.SetOverlay(overlay)
	for _, entry := range entries {
		routes.Set(entry.source, entry.destination, entry.value)
	}
	rt := Runtime{Interface: "ranet0", Overlay: overlay, EgressSegment: egressSegment}
	counts := func(prefix netip.Prefix) bool { return schema.CapturesTheMachine(prefix, overlay) }
	var own, sources, assigned []netip.Prefix
	for _, entry := range routes.Snapshot() {
		destination := entry.Destination.Masked()
		switch entry.Value {
		case netstack.Assigned:
			sources, assigned = append(sources, destination), append(assigned, entry.Destination)
			if unroutable(destination) == "" {
				own = append(own, destination)
			}
		case netstack.Local:
			sources = append(sources, destination)
			if entry.Source.IsValid() {
				sources = append(sources, entry.Source.Masked())
			}
			if advertised[destination] {
				rt.Advertised = append(rt.Advertised, destination)
			} else {
				rt.Announced = append(rt.Announced, destination)
			}
			// D from S routes D to this node only from S, and a LAN cap.egress advertises holds hosts behind it
			if !entry.Source.IsValid() && !advertised[destination] && !counts(destination) && unroutable(destination) == "" {
				own = append(own, destination)
			}
		}
	}
	exit := rt.EgressSegment || slices.ContainsFunc(rt.Advertised, counts) || slices.ContainsFunc(rt.Announced, counts)
	reconciler := newReconciler(Table{}.Normalized(), rt, nil, routes, newFakeKernel(t))
	reconciler.capture = gate
	snapshot := routes.Snapshot()
	desired := reconciler.desired(snapshot)
	tables := maps.Clone(host.tables)
	mainRoutes := slices.Clone(tables[schema.TableMain])
	for _, link := range mode.links() {
		for _, prefix := range link.Prefixes {
			if link.Name != loopback {
				mainRoutes = append(mainRoutes, fibRoute{destination: prefix.Masked(), device: link.Name})
			}
		}
		for _, peer := range link.Peers {
			mainRoutes = append(mainRoutes, fibRoute{destination: peer, device: link.Name})
		}
	}
	tables[schema.TableMain] = mainRoutes
	for _, route := range desired {
		tables[DefaultTable] = append(tables[DefaultTable], fibRoute{
			destination: route.Destination, source: route.Source, metric: route.Metric,
			device: map[bool]string{false: tunDevice, true: ""}[route.Throw || route.Unreachable],
			throw:  route.Throw, unreachable: route.Unreachable,
		})
	}
	host.tables = tables
	kernel := fib{rules: slices.Concat(host.rules, derivedRules(DefaultTable, overlay, reconciler.ownPrefixes(snapshot), mode)), tables: tables}
	slices.SortStableFunc(kernel.rules, func(a, b Rule) int { return cmp.Compare(a.Priority, b.Priority) })
	return interpreted{routes: routes, rt: rt, gate: gate, exit: exit, own: own, sources: sources, assigned: assigned, host: host, kernel: kernel, desired: desired, mode: mode}
}

// links is every link of v's network, both families'
func (v exitView) links() []Link {
	return slices.Concat(v.network.IPv4.Links, v.network.IPv6.Links)
}

// unspecifiedSpace and unspecifiedSpace6 are where a route holding the
// unspecified address counts as a default at any length while 5420 suppresses
// by length alone, a space no host is numbered from though linux routes a
// packet to it, which packets leaves out
var (
	unspecifiedSpace  = netip.MustParsePrefix("0.0.0.0/8")
	unspecifiedSpace6 = netip.MustParsePrefix("::/16")
)

// packets draws lookups of either family: from a prefix of a Local or an
// Assigned entry, from the uplink's address or from anywhere near the drawn
// prefixes, to an entry of ranet3's table, a prefix of the overlay or anywhere
// near the drawn prefixes but an address of the host's own, which lookedUp
// leaves out, unmarked, under ranet3's mark or under kube-proxy's 0x4000,
// which shares bits with it, as the host's own lookup or arriving on a link,
// forwarded or not. A source is also drawn from an address of a link outside
// the mesh or its network. It adds an unmarked lookup from the uplink's
// address into each prefix of the overlay, and one from each prefix of a
// Local or an Assigned entry to each entry that counts as a default, the
// lookups whose way past 5430 an exit's inputs and an advertised LAN decide,
// which the draws seldom pair, and the same from each link's address and its
// network, the host's own and arriving on the link, which mode 2 decides.
func (h interpreted) packets(ht *hegel.T) []fibPacket {
	var out []fibPacket
	inputs := []string{"", "", "eth0", "br-1a", "eth1", "ppp0", "docker0", "dummy0"}
	for range hegel.Draw(ht, hegel.Integers(1, 24)) {
		v6 := hegel.Draw(ht, hegel.Booleans())
		// inside an entry of ranet3's table or a prefix of the overlay half the time, which near prefixes alone seldom reach
		var entries []netip.Prefix
		for _, entry := range h.routes.Snapshot() {
			if entry.Destination.Addr().Is6() == v6 && entry.Value != netstack.Assigned {
				entries = append(entries, entry.Destination)
			}
		}
		for _, prefix := range h.rt.Overlay {
			if prefix.Addr().Is6() == v6 {
				entries = append(entries, prefix.Masked())
			}
		}
		within := hegel.Draw(ht, nearPrefixes(v6))
		if len(entries) > 0 && hegel.Draw(ht, hegel.Booleans()) {
			within = hegel.Draw(ht, hegel.SampledFrom(entries))
		}
		p := fibPacket{
			destination: addressIn(ht, within),
			mark:        hegel.Draw(ht, hegel.SampledFrom([]uint32{0, 0, schema.UnderlayMark, 0x4000})),
			iif:         hegel.Draw(ht, hegel.SampledFrom(inputs)),
		}
		sources := slices.DeleteFunc(slices.Clone(h.sources), func(prefix netip.Prefix) bool { return prefix.Addr().Is6() != v6 })
		var links []netip.Prefix
		for _, link := range h.mode.links() {
			links = append(links, slices.DeleteFunc(slices.Concat(link.Prefixes, link.Peers), func(prefix netip.Prefix) bool { return prefix.Addr().Is6() != v6 })...)
		}
		switch choice := hegel.Draw(ht, hegel.Integers(0, 4)); {
		case choice <= 1 && len(sources) > 0:
			p.source = addressIn(ht, hegel.Draw(ht, hegel.SampledFrom(sources)))
		case choice == 2 && len(links) > 0:
			link := hegel.Draw(ht, hegel.SampledFrom(links))
			p.source = link.Addr()
			if hegel.Draw(ht, hegel.Booleans()) {
				p.source = addressIn(ht, link.Masked())
			}
		case choice <= 3:
			p.source = uplink[v6]
		default:
			p.source = addressIn(ht, hegel.Draw(ht, nearPrefixes(v6)))
		}
		if h.lookedUp(p) {
			out = append(out, p)
		}
	}
	for _, prefix := range h.rt.Overlay {
		if p := (fibPacket{source: uplink[prefix.Addr().Is6()], destination: addressIn(ht, prefix.Masked())}); h.lookedUp(p) {
			out = append(out, p)
		}
	}
	for _, source := range h.sources {
		for _, entry := range h.routes.Snapshot() {
			if entry.Destination.Addr().Is6() == source.Addr().Is6() && schema.CapturesTheMachine(entry.Destination, h.rt.Overlay) {
				if p := (fibPacket{source: addressIn(ht, source), destination: addressIn(ht, entry.Destination)}); h.lookedUp(p) {
					out = append(out, p)
				}
			}
		}
	}
	for _, link := range h.mode.links() {
		for _, prefix := range slices.Concat(link.Prefixes, link.Peers) {
			for _, entry := range h.routes.Snapshot() {
				if entry.Destination.Addr().Is6() != prefix.Addr().Is6() || !schema.CapturesTheMachine(entry.Destination, h.rt.Overlay) {
					continue
				}
				for _, p := range []fibPacket{
					{source: prefix.Addr(), destination: addressIn(ht, entry.Destination)},
					{source: addressIn(ht, prefix.Masked()), destination: addressIn(ht, entry.Destination)},
					{source: addressIn(ht, prefix.Masked()), destination: addressIn(ht, entry.Destination), iif: link.Name},
				} {
					if h.lookedUp(p) {
						out = append(out, p)
					}
				}
			}
		}
	}
	return out
}

// lookedUp reports a packet whose way routing.md's tables write out: no
// unroutable space, which the mirror leaves out, no unspecified space, where
// 5420 answers a route that counts by its length, and no address of the
// host's own, its uplink's, a link's or one cap.table assigns, which the
// host's local table answers and the model holds no local table for
func (h interpreted) lookedUp(p fibPacket) bool {
	return unroutable(netip.PrefixFrom(p.destination, p.destination.BitLen())) == "" && !unspecifiedSpace.Contains(p.destination) && !unspecifiedSpace6.Contains(p.destination) &&
		p.destination != uplink[p.destination.Is6()] &&
		!slices.ContainsFunc(h.assigned, func(address netip.Prefix) bool { return address.Contains(p.destination) }) &&
		!slices.ContainsFunc(h.mode.links(), func(link Link) bool {
			return slices.ContainsFunc(link.Prefixes, func(prefix netip.Prefix) bool { return prefix.Addr() == p.destination })
		})
}

// inOverlay reports address inside a prefix of the overlay
func (h interpreted) inOverlay(address netip.Addr) bool {
	return slices.ContainsFunc(h.rt.Overlay, func(prefix schema.Prefix) bool { return prefix.Contains(address) })
}

// modeTwo reports p of a family mode 2 adds its rules to, one the tun holds an
// overlay address of
func (h interpreted) modeTwo(p fibPacket) bool {
	return h.mode.on && !slices.Contains(h.mode.unaddressed, familyOf(p.destination))
}

// uplinkSource reports p the host's own lookup in mode 2 from an address of a
// link outside the mesh that neither the overlay nor an own prefix holds, which
// 5405 takes
func (h interpreted) uplinkSource(p fibPacket) bool {
	return h.modeTwo(p) && p.input() == loopback && !h.inOverlay(p.source) && !h.owns(p.source) && slices.ContainsFunc(h.mode.links(), func(link Link) bool {
		return slices.ContainsFunc(link.Prefixes, func(prefix netip.Prefix) bool { return prefix.Addr() == p.source })
	})
}

// linkSource reports p the host's own lookup in mode 2 from a connected
// network shorter than a host prefix or a point-to-point far end of a link
// forward leaves out that shares no address with the overlay or an own prefix,
// which 5435 takes
func (h interpreted) linkSource(p fibPacket) bool {
	if !h.modeTwo(p) || p.input() != loopback {
		return false
	}
	taken := slices.Clone(h.own)
	for _, prefix := range h.rt.Overlay {
		taken = append(taken, prefix.Prefix)
	}
	for _, link := range h.mode.links() {
		if slices.Contains(h.mode.forwarded, link.Name) {
			continue
		}
		var networks []netip.Prefix
		for _, prefix := range link.Prefixes {
			if prefix.Bits() < prefix.Addr().BitLen() {
				networks = append(networks, prefix.Masked())
			}
		}
		for _, network := range append(networks, link.Peers...) {
			// a network and a taken prefix share an address exactly where one holds the other's first
			shares := slices.ContainsFunc(taken, func(o netip.Prefix) bool { return o.Contains(network.Addr()) || network.Contains(o.Masked().Addr()) })
			if network.Contains(p.source) && !shares {
				return true
			}
		}
	}
	return false
}

// caughtAll reports p the host's own lookup in mode 2, or one arriving on a
// link forward expands to, which 5440 takes
func (h interpreted) caughtAll(p fibPacket) bool {
	return h.modeTwo(p) && (p.input() == loopback || slices.Contains(h.mode.forwarded, p.iif))
}

// pastOwn is where p goes past 5430: from main at 5435, from the mirror at
// 5440 where it holds a route for p, and otherwise by another program's rules
// past ranet3's
func (h interpreted) pastOwn(p fibPacket, landing, past uint32) string {
	if landing <= priorityLinkSource && h.linkSource(p) {
		if route, ok := lookup(h.host.tables[schema.TableMain], p); ok {
			return route.device
		}
	}
	if landing <= priorityCatchAll && h.caughtAll(p) {
		if route, ok := lookup(h.kernel.tables[DefaultTable], p); ok && !route.throw {
			return answer(route)
		}
	}
	return h.others(p, past, math.MaxUint32)
}

// owns reports source inside one of this node's own prefixes
func (h interpreted) owns(source netip.Addr) bool {
	return slices.ContainsFunc(h.own, func(prefix netip.Prefix) bool { return prefix.Contains(source) })
}

// others is where the rules of another program at priorities from lo up to hi
// send p, its goto left to landing
func (h interpreted) others(p fibPacket, lo, hi uint32) string {
	return h.host.only(func(rule Rule) bool { return rule.action != actionGoto && rule.Priority >= lo && rule.Priority < hi }).walk(p)
}

// landing is the priority another program's goto ahead of ranet3's rules
// lands p on, or zero where no goto takes p, or where its target holds no rule
// of p's family and the kernel passes it over
func (h interpreted) landing(p fibPacket) uint32 {
	for _, rule := range h.host.rules {
		if rule.action != actionGoto || rule.Priority >= priorityUnderlayPastOverlay || !matches(rule, p) {
			continue
		}
		if slices.ContainsFunc(h.kernel.rules, func(r Rule) bool { return r.Family == rule.Family && r.Priority == rule.target }) {
			return rule.target
		}
	}
	return 0
}

// overlayOf reports whether the overlay holds destination, and the length of
// the longest prefix holding it that gets a hold, or -1 where none does
func (h interpreted) overlayOf(destination netip.Addr) (bool, int) {
	inside, held := false, -1
	for _, prefix := range h.rt.Overlay {
		if !prefix.Contains(destination) {
			continue
		}
		inside = true
		if unroutable(prefix.Masked()) == "" && !schema.CapturesTheMachine(prefix.Masked(), h.rt.Overlay) {
			held = max(held, prefix.Bits())
		}
	}
	return inside, held
}

// answer is where a route of the mirror ends a lookup
func answer(route fibRoute) string {
	if route.unreachable {
		return "unreachable"
	}
	return route.device
}

// expected is where routing.md's tables of the routes and the policy rules the
// reconciler installs send p, written out rather than walked: at 5110 an
// overlay destination under a held overlay prefix from ranet3's own lookup and
// one under no held prefix from the mirror's longest match, every other overlay
// destination from the mirror's longest match, and a destination outside the
// overlay from ranet3's own lookup, as "Where a lookup ends on Linux" gives it.
// Mode 2, in a family the tun holds an overlay address of, sends the host's own
// lookup from a link's address to main ahead of 5410, and past 5430 one from a
// network forward leaves out to main, and the host's own and a forwarded
// link's to the mirror.
func (h interpreted) expected(p fibPacket) string {
	if before := h.others(p, 0, priorityUnderlayPastOverlay); before != "none" {
		return before
	}
	landing := h.landing(p)
	reaches := func(priority uint32) bool { return priority >= landing }
	marked := p.mark == schema.UnderlayMark
	_, verdict, match := h.routes.Resolve(p.source, p.destination)
	inside, held := h.overlayOf(p.destination)
	mirror := h.kernel.tables[DefaultTable]
	// 5100's goto takes a marked lookup past 5110, and so does another program's goto landing past it
	if inside && reaches(priorityOverlay) && !(marked && reaches(priorityUnderlayPastOverlay)) {
		if held >= 0 {
			// the overlay's hold outranks an entry wider than the overlay prefix
			if verdict == netstack.RoutePeer && !match.Counted && match.Bits >= held {
				return tunDevice
			}
			return "unreachable"
		}
		// no overlay prefix holding it gets a hold, so 5110 answers by the mirror's longest match, whatever its length
		if route, ok := lookup(mirror, p); ok && !route.throw {
			return answer(route)
		}
	}
	if between := h.others(p, max(landing, priorityUnderlayPastOverlay), priorityUnderlayPastMesh); between != "none" {
		return between
	}
	past := max(landing, ownProtocolEnd+1)
	if marked && reaches(priorityUnderlayPastMesh) {
		return h.others(p, past, math.MaxUint32)
	}
	if reaches(priorityUplinkSource) && h.uplinkSource(p) {
		if route, ok := lookup(h.host.tables[schema.TableMain], p); ok {
			return route.device
		}
	}
	if route, ok := lookup(h.host.tables[schema.TableMain], p); ok && route.destination.Bits() > 0 && reaches(priorityMain) {
		return route.device
	}
	mesh, own := reaches(priorityMesh), reaches(priorityOwn) && h.owns(p.source)
	if inside {
		// past 5110 an overlay destination meets the mirror at 5420 and 5430 as any other does, the overlay's hold among its routes
		suppress := schema.MinSubnetBits4 - 1
		if p.destination.Is6() {
			suppress = schema.MinSubnetBits6 - 1
		}
		if route, ok := lookup(mirror, p); ok && !route.throw && (mesh && (route.unreachable || route.destination.Bits() > suppress) || own) {
			return answer(route)
		}
		return h.pastOwn(p, landing, past)
	}
	installed := h.gate && !h.exit
	switch {
	case verdict == netstack.RoutePeer && (mesh && !match.Counted || own && (!match.Counted || installed)):
		return tunDevice
	case verdict == netstack.RouteHeld && !match.Counted && (mesh || own):
		return "unreachable"
	case verdict == netstack.RouteHeld && own && installed:
		if _, under, _ := h.withoutCountedHolds().Resolve(p.source, p.destination); under == netstack.RoutePeer {
			return tunDevice
		}
	}
	return h.pastOwn(p, landing, past)
}

// withoutCountedHolds is ranet3's table less every hold that counts as a default, as the mirror leaves them out
func (h interpreted) withoutCountedHolds() *netstack.RouteTable {
	out := netstack.NewRouteTable()
	out.SetOverlay(h.rt.Overlay)
	for _, entry := range h.routes.Snapshot() {
		if entry.Value == netstack.Unreachable && schema.CapturesTheMachine(entry.Destination, h.rt.Overlay) {
			continue
		}
		out.Set(entry.Source, entry.Destination, entry.Value)
	}
	return out
}

// Linux's rule walk over the derived rules, routing.md's "Policy rules on
// Linux", and the mirror's table,
// beside a host's own tables, another program's lookups ahead of, between and
// past ranet3's blocks and its goto ahead of them, sends every packet lookedUp
// keeps where routing.md's tables say, on an exit by each of its inputs and on
// a node that is none, in mode off and in mode 2, the last with the tun holding
// an overlay address of each family and holding none of either in turn
func TestRuleWalkSendsEveryPacketWhereTheRulesSay(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		build := drawInterpreted(t, ht)
		packets := build(nil).packets(ht)
		for _, unaddressed := range [][]Family{nil, {FamilyIPv4}, {FamilyIPv6}} {
			h := build(unaddressed)
			for _, p := range packets {
				if got, want := h.kernel.walk(p), h.expected(p); got != want {
					ht.Fatalf("%s went to %s, want %s\nranet3's table:\n%s\nexit %v, gate %v, own %v, mode 2 %v forwarding %v over %v, unaddressed %v\nthe mirror:\n%v\nthe rules:\n%s",
						p, got, want, strings.Join(h.routes.Debug(), "\n"), h.exit, h.gate, h.own, h.mode.on, h.mode.forwarded, h.mode.links(), h.mode.unaddressed, h.desired, rulesText(h.kernel.rules))
				}
			}
		}
	})
}

// plainHost is a host with main's default and connected network through eth0,
// and a tailnet's rule at 5270 whose table holds both defaults where tailnet says
func plainHost(tailnet bool) fib {
	if !tailnet {
		return hostWith(nil, func(Family) []Rule { return nil })
	}
	return hostWith(map[schema.TableID][]netip.Prefix{tailnetTable: {prefix("0.0.0.0/0"), prefix("::/0")}}, func(family Family) []Rule {
		return []Rule{{Family: family, Priority: 5270, Table: tailnetTable}}
	})
}

// the walk's named cases, each where both the walk and the rules written out send it
func TestRuleWalkNamedCases(t *testing.T) {
	learnedAt := func(destination string) mirrorEntry {
		return mirrorEntry{destination: prefix(destination), value: learned}
	}
	at := func(value *netstack.Peer, destination string) mirrorEntry {
		return mirrorEntry{destination: prefix(destination), value: value}
	}
	overlay := []schema.Prefix{schema.MustPrefix("192.0.2.0/24"), schema.MustPrefix("3fff::/20")}
	from := func(source, destination string) fibPacket {
		return fibPacket{source: netip.MustParseAddr(source), destination: netip.MustParseAddr(destination)}
	}
	marked := func(p fibPacket, mark uint32) fibPacket { p.mark = mark; return p }
	arriving := func(link string, p fibPacket) fibPacket { p.iif = link; return p }
	// a bridge forward names and a LAN through eth1 it leaves out, an overlay
	// address on lo, and on dummy0 a network about the overlay
	forwarding := exitView{on: true, forwarded: []string{"br-1a"}, network: NetworkState{
		IPv4: NetworkFamily{Links: []Link{
			{Name: "br-1a", Prefixes: []netip.Prefix{prefix("203.0.113.129/26")}},
			{Name: "eth0", Prefixes: []netip.Prefix{prefix("198.51.100.10/24")}},
			{Name: "eth1", Prefixes: []netip.Prefix{prefix("203.0.113.65/26")}},
			{Name: "lo", Prefixes: []netip.Prefix{prefix("192.0.2.1/32")}},
		}},
		IPv6: NetworkFamily{Links: []Link{
			{Name: "br-1a", Prefixes: []netip.Prefix{prefix("2001:db8:17::1/64")}},
			{Name: "dummy0", Prefixes: []netip.Prefix{prefix("3fff::10/48")}},
			{Name: "eth0", Prefixes: []netip.Prefix{prefix("2001:db8:a::10/64")}},
			{Name: "eth1", Prefixes: []netip.Prefix{prefix("2001:db8:50::1/64")}},
		}},
	}}
	defaultsAndSubnets := []mirrorEntry{learnedAt("0.0.0.0/0"), learnedAt("::/0"), learnedAt("203.0.113.0/27"), learnedAt("2001:db8:300::/64")}
	// a subnet router announcing the LAN through eth1 it holds an address in
	routerLinks := NetworkState{
		IPv4: NetworkFamily{Links: []Link{
			{Name: "eth0", Prefixes: []netip.Prefix{prefix("198.51.100.10/24")}},
			{Name: "eth1", Prefixes: []netip.Prefix{prefix("203.0.113.65/26")}},
		}},
		IPv6: NetworkFamily{Links: []Link{
			{Name: "eth0", Prefixes: []netip.Prefix{prefix("2001:db8:a::10/64")}},
			{Name: "eth1", Prefixes: []netip.Prefix{prefix("2001:db8:50::1/64")}},
		}},
	}
	router := append(slices.Clone(defaultsAndSubnets), at(netstack.Local, "203.0.113.64/26"), at(netstack.Local, "2001:db8:50::/64"))
	// the router's own packets from its LAN address, to another node's subnet and to the internet, which 5430 sends into the mesh
	fromTheLAN := map[fibPacket]string{
		from("203.0.113.65", "203.0.113.9"): tunDevice, from("203.0.113.65", "203.0.113.200"): tunDevice,
		from("2001:db8:50::1", "2001:db8:300::9"): tunDevice, from("2001:db8:50::1", "2001:db8:c::1"): tunDevice,
	}
	for name, c := range map[string]struct {
		entries []mirrorEntry
		tailnet bool
		// overlay stands in for the one above where it is set
		overlay       []schema.Prefix
		mode          exitView
		egressSegment bool
		packets       map[fibPacket]string
	}{
		"mode 2's lookups from the links' addresses and networks, the host's own and arriving on a link": {
			entries: defaultsAndSubnets,
			mode:    forwarding,
			packets: map[fibPacket]string{
				// 5405 ahead of 5420's subnet, so a socket bound to the uplink's address leaves by it
				from("198.51.100.10", "203.0.113.9"): "eth0", from("2001:db8:a::10", "2001:db8:300::1"): "eth0",
				// 5440 for the host's own, from the tun's address
				from("192.0.2.5", "203.0.113.40"): tunDevice, from("3fff::5", "2001:db8:c::1"): tunDevice,
				// 5435 for the reverse path of the LAN's reply by the uplink, and 5440 for the bridge's through the tun
				from("203.0.113.66", "203.0.113.40"): "eth0", from("2001:db8:50::2", "2001:db8:c::1"): "eth0",
				from("203.0.113.130", "203.0.113.40"): tunDevice, from("2001:db8:17::2", "2001:db8:c::1"): tunDevice,
				// 5440 for the forwarded bridge's packets and not the LAN's
				arriving("br-1a", from("203.0.113.130", "203.0.113.40")): tunDevice, arriving("br-1a", from("2001:db8:17::2", "2001:db8:c::1")): tunDevice,
				arriving("eth1", from("203.0.113.66", "203.0.113.40")): "eth0", arriving("eth1", from("2001:db8:50::2", "2001:db8:c::1")): "eth0",
				// 5405 and 5435 for the host's own lookups alone
				arriving("br-1a", from("198.51.100.10", "203.0.113.9")): tunDevice, arriving("br-1a", from("203.0.113.66", "203.0.113.40")): tunDevice,
			},
		},
		"an overlay address on lo and a network about the overlay on dummy0, which mode 2 sends nowhere by main": {
			entries: defaultsAndSubnets,
			mode:    forwarding,
			packets: map[fibPacket]string{
				from("192.0.2.1", "203.0.113.9"): tunDevice, from("3fff::10", "2001:db8:300::1"): tunDevice,
				from("3fff::99", "2001:db8:c::1"): tunDevice,
			},
		},
		// an unbound socket's first lookup carries no source, and a connected one's second the uplink's address the first picked
		// toward the mesh's subnet 5420 answers the second, which in a family the tun holds an overlay address of 5405 sends by main
		"mode 2 with the tun holding no IPv4 overlay address, which runs mode off's IPv4 rules": {
			entries: defaultsAndSubnets,
			mode:    exitView{on: true, network: forwarding.network, forwarded: forwarding.forwarded, unaddressed: []Family{FamilyIPv4}},
			packets: map[fibPacket]string{
				from("0.0.0.0", "203.0.113.40"): "eth0", from("198.51.100.10", "203.0.113.40"): "eth0",
				arriving("br-1a", from("203.0.113.130", "203.0.113.40")):   "eth0",
				from("198.51.100.10", "203.0.113.9"):                       tunDevice,
				from("::", "2001:db8:c::1"):                                tunDevice,
				arriving("br-1a", from("2001:db8:17::2", "2001:db8:c::1")): tunDevice,
				from("2001:db8:a::10", "2001:db8:300::1"):                  "eth0",
			},
		},
		"mode 2 with the tun holding no IPv6 overlay address, which runs mode off's IPv6 rules": {
			entries: defaultsAndSubnets,
			mode:    exitView{on: true, network: forwarding.network, forwarded: forwarding.forwarded, unaddressed: []Family{FamilyIPv6}},
			packets: map[fibPacket]string{
				from("::", "2001:db8:c::1"): "eth0", from("2001:db8:a::10", "2001:db8:c::1"): "eth0",
				arriving("br-1a", from("2001:db8:17::2", "2001:db8:c::1")): "eth0",
				from("2001:db8:a::10", "2001:db8:300::1"):                  tunDevice,
				from("0.0.0.0", "203.0.113.40"):                            tunDevice,
				arriving("br-1a", from("203.0.113.130", "203.0.113.40")):   tunDevice,
				from("198.51.100.10", "203.0.113.9"):                       "eth0",
			},
		},
		"mode 2 on an exit, whose mirror withholds the defaults, so 5440 finds none": {
			entries:       defaultsAndSubnets,
			mode:          forwarding,
			egressSegment: true,
			packets: map[fibPacket]string{
				from("192.0.2.5", "203.0.113.40"): "eth0", from("3fff::5", "2001:db8:c::1"): "eth0",
				arriving("br-1a", from("203.0.113.130", "203.0.113.40")): "eth0",
				from("192.0.2.5", "203.0.113.9"):                         tunDevice,
			},
		},
		"a subnet router's LAN address in mode 2, which 5405 leaves to 5430": {
			entries: router,
			mode:    exitView{on: true, network: routerLinks},
			packets: fromTheLAN,
		},
		"a subnet router's LAN address in mode 2 forwarding the LAN": {
			entries: router,
			mode:    exitView{on: true, network: routerLinks, forwarded: []string{"eth1"}},
			packets: fromTheLAN,
		},
		"a subnet router's LAN address in mode off": {
			entries: router,
			mode:    exitView{network: routerLinks},
			packets: fromTheLAN,
		},
		"mode off over the same links": {
			entries: defaultsAndSubnets,
			mode:    exitView{network: forwarding.network, forwarded: forwarding.forwarded},
			packets: map[fibPacket]string{
				from("198.51.100.10", "203.0.113.9"): tunDevice, from("192.0.2.5", "203.0.113.40"): "eth0",
				arriving("br-1a", from("203.0.113.130", "203.0.113.40")): "eth0",
			},
		},
		"an overlay prefix holding the unspecified address, which gets no hold": {
			entries: []mirrorEntry{learnedAt("::/0"), learnedAt("0.0.0.0/0")},
			overlay: []schema.Prefix{schema.MustPrefix("::/12"), schema.MustPrefix("0.0.0.0/8")},
			packets: map[fibPacket]string{
				from("2001:db8:a::10", "5::1"): tunDevice, from("2001:db8:a::10", "2001:db8:c::1"): "eth0",
			},
		},
		"an overlay prefix the mesh cannot carry, which gets no hold": {
			entries: []mirrorEntry{learnedAt("2000::/3")},
			overlay: []schema.Prefix{schema.MustPrefix("3fff::/20"), schema.MustPrefix("fe80::/12")},
			packets: map[fibPacket]string{from("2001:db8:a::10", "3fff::1"): "unreachable", from("2001:db8:a::10", "2001:db8:c::1"): "eth0"},
		},
		"the floors": {
			entries: []mirrorEntry{learnedAt("2.0.0.0/7"), learnedAt("4.0.0.0/8"), learnedAt("2400::/15"), learnedAt("2600::/16")},
			packets: map[fibPacket]string{
				from("198.51.100.10", "2.0.0.1"): "eth0", from("198.51.100.10", "4.0.0.1"): tunDevice,
				from("2001:db8:a::10", "2400::1"): "eth0", from("2001:db8:a::10", "2600::1"): tunDevice,
			},
		},
		"a counted route for this node's own source": {
			entries: []mirrorEntry{at(netstack.Local, "203.0.113.0/24"), learnedAt("0.0.0.0/0"), at(netstack.Local, "3fff:1::/48"), learnedAt("::/0")},
			packets: map[fibPacket]string{
				from("203.0.113.5", "198.18.0.1"): tunDevice, from("198.51.100.10", "198.18.0.1"): "eth0",
				from("3fff:1::5", "2001:db8:c::1"): tunDevice, from("2001:db8:a::10", "2001:db8:c::1"): "eth0",
			},
		},
		"a hold of a counted route": {
			entries: []mirrorEntry{at(netstack.Unreachable, "0.0.0.0/1"), at(netstack.Unreachable, "2000::/3")},
			packets: map[fibPacket]string{from("198.51.100.10", "64.0.0.1"): "eth0", from("2001:db8:a::10", "2001:db8:c::1"): "eth0"},
		},
		"the marks": {
			entries: []mirrorEntry{learnedAt("192.0.2.0/25"), learnedAt("3fff::/32")},
			packets: map[fibPacket]string{
				marked(from("198.51.100.10", "192.0.2.1"), schema.UnderlayMark): "eth0",
				marked(from("198.51.100.10", "192.0.2.1"), 0x4000):              tunDevice,
				from("198.51.100.10", "192.0.2.1"):                              tunDevice,
				marked(from("2001:db8:a::10", "3fff::1"), schema.UnderlayMark):  "eth0",
				from("2001:db8:a::10", "3fff::1"):                               tunDevice,
			},
		},
		"the overlay ahead of a tailnet": {
			entries: []mirrorEntry{learnedAt("192.0.2.0/25"), learnedAt("3fff::/32")},
			tailnet: true,
			packets: map[fibPacket]string{
				from("198.51.100.10", "192.0.2.1"): tunDevice, from("198.51.100.10", "192.0.2.200"): "unreachable",
				from("198.51.100.10", "203.0.113.9"): "tailscale0",
				from("2001:db8:a::10", "3fff::1"):    tunDevice, from("2001:db8:a::10", "3fff:f::1"): "unreachable",
			},
		},
		"a source-specific announcement of this node's": {
			entries: []mirrorEntry{{source: prefix("2001:db8:a::/48"), destination: prefix("2001:db8:5::/48"), value: netstack.Local}, learnedAt("::/0")},
			packets: map[fibPacket]string{
				from("2001:db8:5::7", "2001:db8:c::1"): "eth0", from("2001:db8:a::10", "2001:db8:5::1"): "eth0",
			},
		},
		"this node's own prefixes": {
			entries: []mirrorEntry{at(netstack.Local, "203.0.113.0/24"), at(netstack.Local, "192.0.2.128/25"), at(netstack.Local, "2001:db8:c::/48")},
			packets: map[fibPacket]string{
				from("198.51.100.10", "203.0.113.9"): "eth0", from("198.51.100.10", "192.0.2.200"): "unreachable",
				from("2001:db8:a::10", "2001:db8:c::1"): "eth0",
			},
		},
	} {
		border := overlay
		if c.overlay != nil {
			border = c.overlay
		}
		h := interpret(t, border, c.entries, nil, c.egressSegment, true, plainHost(c.tailnet), c.mode)
		for p, want := range c.packets {
			if got := h.kernel.walk(p); got != want {
				t.Errorf("%s: %s went to %s, want %s\nthe mirror:\n%v", name, p, got, want, h.desired)
			}
			if got := h.expected(p); got != want {
				t.Errorf("%s: the rules written out send %s to %s, want %s", name, p, got, want)
			}
		}
	}
}

func rulesText(rules []Rule) string {
	lines := make([]string, 0, len(rules))
	for _, rule := range rules {
		lines = append(lines, rule.String())
	}
	return strings.Join(lines, "\n")
}
