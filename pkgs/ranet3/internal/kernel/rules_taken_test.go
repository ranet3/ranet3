// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"
	"syscall"
	"testing"

	"ranet3.com/pkgs/ranet3/schema"
)

// takenTable is the mesh's table of the lab the rule finder's cases read
const takenTable = 100

// takenRules is the lab's rules in the order a dump lists them: the kernel's
// own, the derived rules for an overlay of 192.0.2.0/24 and 3fff::/48 and the
// own prefixes 192.0.2.1/32 and 3fff::1/128, an unreachable and a prohibit
// rule of another program, and with exit, mode 2's rules for the uplink
// 198.51.100.2/25 and the forwarded link lan0 at 198.51.100.130/25
func takenRules(exit bool) []DumpedRule {
	var out []DumpedRule
	for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
		out = append(out, DumpedRule{Family: family, Action: "lookup", Table: uint32(schema.TableLocal), Protocol: 2})
		unreachable, prohibit := prefix("203.0.113.64/27"), prefix("203.0.113.96/27")
		if family == FamilyIPv6 {
			unreachable, prohibit = prefix("2001:db8:dead::/48"), prefix("2001:db8:beef::/48")
		}
		out = append(out,
			DumpedRule{Family: family, Priority: 1000, To: unreachable, Action: "unreachable", Protocol: 99},
			DumpedRule{Family: family, Priority: 1001, To: prohibit, Action: "prohibit", Protocol: 99},
		)
	}
	links := func(up0, lan0 string) []Link {
		return []Link{{Name: "lan0", Prefixes: []netip.Prefix{prefix(lan0)}}, {Name: "up0", Prefixes: []netip.Prefix{prefix(up0)}}}
	}
	view := exitView{on: exit, forwarded: []string{"lan0"}, network: NetworkState{
		IPv4: NetworkFamily{Links: links("198.51.100.2/25", "198.51.100.130/25")},
		IPv6: NetworkFamily{Links: links("2001:db8:1::2/64", "2001:db8:2::1/64")},
	}}
	derived := derivedRules(takenTable, []schema.Prefix{schema.MustPrefix("192.0.2.0/24"), schema.MustPrefix("3fff::/48")},
		[]netip.Prefix{prefix("192.0.2.1/32"), prefix("3fff::1/128")}, view)
	for _, rule := range derived {
		out = append(out, rule.dumped(4))
	}
	for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
		out = append(out, DumpedRule{Family: family, Priority: 32766, Action: "lookup", Table: uint32(schema.TableMain), Protocol: 2})
	}
	out = append(out, DumpedRule{Family: FamilyIPv4, Priority: 32767, Action: "lookup", Table: uint32(schema.TableDefault), Protocol: 2})
	slices.SortStableFunc(out, func(a, b DumpedRule) int { return cmp.Compare(a.Priority, b.Priority) })
	return out
}

// takenAnswer is a route the lab's kernel answered, in table of bits
func takenAnswer(table uint32, destination string) MatchedRoute {
	return MatchedRoute{Prefix: prefix(destination), Table: table, Type: "unicast"}
}

// lookupError is an errno as RouteGet wraps it
func lookupError(errno syscall.Errno) error {
	return fmt.Errorf("kernel: look up the route: %w", errno)
}

// Each case is a packet of a namespace holding takenRules, the kernel's answer
// there as it gave it, and the rule the walk ends on, the one whose deletion
// moved the kernel's answer
func TestTakeRuleNamesTheRuleTheLabsLookupsTook(t *testing.T) {
	main, mesh := uint32(schema.TableMain), uint32(takenTable)
	cases := []struct {
		name          string
		exit          bool
		src, dst, iif string
		route         MatchedRoute
		err           syscall.Errno
		priority      uint32
		ruleIIF       string
		routeType     string
	}{
		{name: "own to the internet", dst: "203.0.113.200", route: takenAnswer(main, "0.0.0.0/0"), priority: 32766},
		{name: "own to the internet over IPv6", dst: "2001:db8:ffff::10", route: takenAnswer(main, "::/0"), priority: 32766},
		{name: "own to an overlay address", dst: "192.0.2.20", route: takenAnswer(mesh, "128.0.0.0/1"), priority: 5110},
		{name: "own to an overlay address over IPv6", dst: "3fff::20", route: takenAnswer(mesh, "::/1"), priority: 5110},
		{name: "own to the mesh subnet", dst: "203.0.113.10", route: takenAnswer(mesh, "203.0.113.0/26"), priority: 5420},
		{name: "own to the mesh subnet over IPv6", dst: "2001:db8:100::10", route: takenAnswer(mesh, "2001:db8:100::/48"), priority: 5420},
		{name: "own from the own prefix", src: "192.0.2.1", dst: "203.0.113.200", route: takenAnswer(mesh, "128.0.0.0/1"), priority: 5430},
		{name: "own from the own prefix over IPv6", src: "3fff::1", dst: "2001:db8:ffff::10", route: takenAnswer(mesh, "::/1"), priority: 5430},
		{name: "own to the unreachable rule", dst: "203.0.113.70", err: syscall.ENETUNREACH, priority: 1000},
		{name: "own to the unreachable rule over IPv6", dst: "2001:db8:dead::10", err: syscall.ENETUNREACH, priority: 1000},
		{name: "own to the prohibit rule", dst: "203.0.113.100", err: syscall.EACCES, priority: 1001, routeType: "prohibit"},
		{name: "own to the prohibit rule over IPv6", dst: "2001:db8:beef::10", err: syscall.EACCES, priority: 1001, routeType: "prohibit"},
		{name: "a link arrival", src: "198.51.100.140", dst: "203.0.113.200", iif: "lan0", route: takenAnswer(main, "0.0.0.0/0"), priority: 32766},
		{name: "a link arrival over IPv6", src: "2001:db8:2::5", dst: "2001:db8:ffff::10", iif: "lan0", route: takenAnswer(main, "::/0"), priority: 32766},
		{name: "a link arrival to the prohibit rule", src: "198.51.100.140", dst: "203.0.113.100", iif: "lan0", err: syscall.EACCES, priority: 1001, routeType: "prohibit"},
		{name: "a link arrival with forwarding off", src: "198.51.100.140", dst: "203.0.113.200", iif: "lan0", err: syscall.EHOSTUNREACH, routeType: "unreachable"},
		{name: "a link arrival under rp_filter", src: "203.0.113.50", dst: "203.0.113.200", iif: "lan0", err: syscall.EINVAL, routeType: "blackhole"},

		{name: "own to the internet in mode 2", exit: true, dst: "203.0.113.200", route: takenAnswer(mesh, "128.0.0.0/1"), priority: 5440, ruleIIF: "lo"},
		{name: "own to the internet in mode 2 over IPv6", exit: true, dst: "2001:db8:ffff::10", route: takenAnswer(mesh, "::/1"), priority: 5440, ruleIIF: "lo"},
		{name: "own to an overlay address in mode 2", exit: true, dst: "192.0.2.20", route: takenAnswer(mesh, "128.0.0.0/1"), priority: 5110},
		{name: "own to the mesh subnet in mode 2", exit: true, dst: "203.0.113.10", route: takenAnswer(mesh, "203.0.113.0/26"), priority: 5420},
		{name: "own from the own prefix in mode 2", exit: true, src: "192.0.2.1", dst: "203.0.113.200", route: takenAnswer(mesh, "128.0.0.0/1"), priority: 5430},
		{name: "a link arrival in mode 2", exit: true, src: "198.51.100.140", dst: "203.0.113.200", iif: "lan0", route: takenAnswer(mesh, "128.0.0.0/1"), priority: 5440, ruleIIF: "lan0"},
		{name: "a link arrival in mode 2 over IPv6", exit: true, src: "2001:db8:2::5", dst: "2001:db8:ffff::10", iif: "lan0", route: takenAnswer(mesh, "::/1"), priority: 5440, ruleIIF: "lan0"},
		{name: "own from the forwarded link's address in mode 2", exit: true, src: "198.51.100.130", dst: "203.0.113.200", route: takenAnswer(main, "0.0.0.0/0"), priority: 5405, ruleIIF: "lo"},
		{name: "own from the uplink's address in mode 2 over IPv6", exit: true, src: "2001:db8:1::2", dst: "2001:db8:ffff::10", route: takenAnswer(main, "::/0"), priority: 5405, ruleIIF: "lo"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var src netip.Addr
			if c.src != "" {
				src = addr(c.src)
			}
			var err error
			if c.err != 0 {
				err = lookupError(c.err)
			}
			got := TakeRule(takenRules(c.exit), src, addr(c.dst), c.iif, c.route, err)
			if c.priority == 0 {
				if got.Found || got.RouteType != c.routeType {
					t.Fatalf("named %+v, want no rule with a route type of %q", got, c.routeType)
				}
				return
			}
			if !got.Found || got.Rule.Priority != c.priority || got.Rule.IIF != c.ruleIIF || got.RouteType != c.routeType {
				t.Fatalf("named %+v, want priority %d iif %q with a route type of %q", got, c.priority, c.ruleIIF, c.routeType)
			}
		})
	}
}

// Without a rule beside the kernel's own three, IPv4 answers a local route
// from main, where the walk would have read it in local
func TestTakeRuleNamesLocalForALocalRouteOfOneTrie(t *testing.T) {
	var rules []DumpedRule
	for _, rule := range takenRules(false) {
		if rule.Family == FamilyIPv4 && rule.Protocol == 2 {
			rules = append(rules, rule)
		}
	}
	route := MatchedRoute{Prefix: prefix("198.51.100.2/32"), Table: uint32(schema.TableMain), Type: "local"}
	if got := TakeRule(rules, netip.Addr{}, addr("198.51.100.2"), "", route, nil); !got.Found || got.Rule.Priority != 0 {
		t.Fatalf("named %+v for a local route of one trie, want the lookup of local at 0", got)
	}
	route.Type = "unicast"
	if got := TakeRule(rules, netip.Addr{}, addr("198.51.100.2"), "", route, nil); !got.Found || got.Rule.Priority != 32766 {
		t.Fatalf("named %+v for a unicast route of main, want the lookup of main at 32766", got)
	}
	// the limited broadcast's type is the output path's, not its entry's
	limited := MatchedRoute{Prefix: prefix("0.0.0.0/0"), Table: uint32(schema.TableMain), Type: "broadcast"}
	if got := TakeRule(rules, netip.Addr{}, addr("255.255.255.255"), "", limited, nil); !got.Found || got.Rule.Priority != 32766 {
		t.Fatalf("named %+v for the limited broadcast by main's default, want the lookup of main at 32766", got)
	}
	route.Prefix, route.Type = prefix("198.51.100.127/32"), "broadcast"
	if got := TakeRule(rules, netip.Addr{}, addr("198.51.100.127"), "", route, nil); !got.Found || got.Rule.Priority != 0 {
		t.Fatalf("named %+v for a subnet's broadcast route of one trie, want the lookup of local at 0", got)
	}
	route.Prefix = prefix("198.51.100.2/32")
	rules = append(rules, DumpedRule{Family: FamilyIPv4, Priority: 5000, Action: "lookup", Table: 7})
	route.Type = "local"
	if got := TakeRule(rules, netip.Addr{}, addr("198.51.100.2"), "", route, nil); !got.Found || got.Rule.Priority != 32766 {
		t.Fatalf("named %+v for a local route of main beside another rule, want the lookup of main at 32766", got)
	}
}

// An l3mdev rule names no table of its own, so it is passed over and never
// named, whichever table the kernel answered with
func TestTakeRuleNeverNamesAnL3mdevRule(t *testing.T) {
	rules := append(takenRules(false),
		DumpedRule{Family: FamilyIPv4, Priority: 1000, L3mdev: true, Action: "lookup", Protocol: 2},
		DumpedRule{Family: FamilyIPv4, Priority: 999, L3mdev: true, Action: "lookup", Table: takenTable},
	)
	for _, table := range []uint32{0, takenTable} {
		got := TakeRule(rules, netip.Addr{}, addr("192.0.2.20"), "", takenAnswer(table, "128.0.0.0/1"), nil)
		if got.Found && got.Rule.L3mdev {
			t.Fatalf("named the l3mdev rule %+v for an answer of table %d", got.Rule, table)
		}
	}
}

// Where the answer is one the walk cannot end with, no rule is named, and
// least of all the nearest one
func TestTakeRuleNamesNoRuleAnAnswerContradicts(t *testing.T) {
	rules := takenRules(false)
	cases := []struct {
		name  string
		dst   string
		route MatchedRoute
		err   error
	}{
		{"a route past a prohibit rule", "203.0.113.100", takenAnswer(uint32(schema.TableMain), "0.0.0.0/0"), nil},
		{"a table no rule looks up", "203.0.113.200", takenAnswer(7, "0.0.0.0/0"), nil},
		{"a route every lookup of its table suppresses", "203.0.113.200", takenAnswer(takenTable, "0.0.0.0/0"), nil},
		{"a prohibit errno at the unreachable rule", "203.0.113.70", MatchedRoute{}, lookupError(syscall.EACCES)},
		{"an error that is no errno", "203.0.113.200", MatchedRoute{}, fmt.Errorf("kernel: the route to 203.0.113.200 was not answered")},
	}
	for _, c := range cases {
		if got := TakeRule(rules, netip.Addr{}, addr(c.dst), "", c.route, c.err); got.Found {
			t.Errorf("%s: named %+v, want none", c.name, got.Rule)
		}
	}
}

// The output lookup matches an IPv4 packet with no source as from 0.0.0.0,
// before it picks one, and an IPv6 one as from no address at all
func TestTakeRuleMatchesAPacketWithNoSource(t *testing.T) {
	for _, c := range []struct {
		from, dst, answer string
		named             uint32
	}{
		{"0.0.0.0/8", "203.0.113.200", "0.0.0.0/0", 100},
		{"::/8", "2001:db8:ffff::10", "::/0", 32766},
	} {
		family := FamilyIPv4
		if addr(c.dst).Is6() {
			family = FamilyIPv6
		}
		rules := []DumpedRule{
			{Family: family, Priority: 100, From: prefix(c.from), Action: "lookup", Table: uint32(schema.TableMain)},
			{Family: family, Priority: 32766, Action: "lookup", Table: uint32(schema.TableMain)},
		}
		got := TakeRule(rules, netip.Addr{}, addr(c.dst), "", takenAnswer(uint32(schema.TableMain), c.answer), nil)
		if !got.Found || got.Rule.Priority != c.named {
			t.Errorf("a packet with no source to %s named %+v, want priority %d", c.dst, got, c.named)
		}
	}
}

// A rule carrying a selector the finder does not read is taken as not
// matching, and listed where it matches on every other, ahead of the rule
// named or of the walk's end
func TestTakeRuleListsTheRulesOfSelectorsItDoesNotRead(t *testing.T) {
	main := takenAnswer(uint32(schema.TableMain), "0.0.0.0/0")
	uid := DumpedRule{Family: FamilyIPv4, Priority: 50, Action: "lookup", Table: uint32(schema.TableMain), Unread: SelectorUIDRange}
	elsewhere := DumpedRule{Family: FamilyIPv4, Priority: 60, To: prefix("198.51.100.0/24"), Action: "lookup", Table: 7, Unread: SelectorIPProto}
	ported := DumpedRule{Family: FamilyIPv4, Priority: 70, Action: "goto", Goto: 32766, Unread: SelectorDport | SelectorSport}
	got := TakeRule(append(takenRules(false), uid, elsewhere, ported), netip.Addr{}, addr("203.0.113.200"), "", main, nil)
	if !got.Found || got.Rule.Priority != 32766 || !slices.Equal(got.Unread, []DumpedRule{uid, ported}) {
		t.Fatalf("named %+v, want the lookup of main at 32766 behind the rules at 50 and 70", got)
	}
	unreachable := DumpedRule{Family: FamilyIPv4, Priority: 80, Action: "unreachable", Unread: SelectorTunID}
	got = TakeRule([]DumpedRule{unreachable}, netip.Addr{}, addr("203.0.113.200"), "", MatchedRoute{}, lookupError(syscall.ENETUNREACH))
	if got.Found || !slices.Equal(got.Unread, []DumpedRule{unreachable}) {
		t.Fatalf("named %+v, want none behind the unreachable rule at 80", got)
	}
}

// A route the kernel made with no table entry behind it is no lookup's, so
// no rule is named or listed for it, not even one every packet meets
func TestTakeRuleNamesNoRuleForARouteOfNoTableEntry(t *testing.T) {
	uid := DumpedRule{Family: FamilyIPv4, Priority: 50, Action: "lookup", Table: uint32(schema.TableMain), Unread: SelectorUIDRange}
	rules := append(takenRules(false), uid)
	for _, c := range []struct {
		src, dst, iif string
		route         MatchedRoute
	}{
		{"198.51.100.2", "224.0.0.251", "", MatchedRoute{Prefix: prefix("224.0.0.251/32"), Type: "multicast", NoEntry: true}},
		{"", "0.0.0.0", "", MatchedRoute{Prefix: prefix("0.0.0.0/32"), Type: "local", NoEntry: true}},
		{"198.51.100.9", "255.255.255.255", "lan0", MatchedRoute{Prefix: prefix("255.255.255.255/32"), Type: "broadcast", NoEntry: true}},
	} {
		var src netip.Addr
		if c.src != "" {
			src = addr(c.src)
		}
		if got := TakeRule(rules, src, addr(c.dst), c.iif, c.route, nil); got.Found || len(got.Unread) != 0 || got.RouteType != "" {
			t.Errorf("%s to %s on %q: named %+v for a route of no table entry, want nothing", c.src, c.dst, c.iif, got)
		}
	}
}

// An IPv4 arrival to a group or to 0.0.0.0/8 is refused or delivered before
// any rule's walk, so its EINVAL names no rule, candidate or route type, not
// even beside a blackhole rule every packet meets
func TestTakeRuleWalksNoRuleForAnArrivalToAGroupOrTheZeroNetwork(t *testing.T) {
	blackhole := DumpedRule{Family: FamilyIPv4, Priority: 50, Action: "blackhole", Protocol: 99}
	uid := DumpedRule{Family: FamilyIPv4, Priority: 40, Action: "lookup", Table: uint32(schema.TableMain), Unread: SelectorUIDRange}
	rules := append(takenRules(false), blackhole, uid)
	for _, dst := range []string{"239.1.2.4", "224.0.0.251", "0.0.0.0", "0.1.2.3"} {
		if got := TakeRule(rules, addr("198.51.100.140"), addr(dst), "lan0", MatchedRoute{}, lookupError(syscall.EINVAL)); got.Found || len(got.Unread) != 0 || got.RouteType != "" {
			t.Errorf("an arrival to %s: named %+v, want nothing", dst, got)
		}
	}
	// this host's own packet to a group walks the rules where it has no source
	if got := TakeRule(rules, netip.Addr{}, addr("239.1.2.4"), "", MatchedRoute{}, lookupError(syscall.EINVAL)); !got.Found || got.Rule != blackhole || !got.Candidate {
		t.Errorf("this host's own packet to a group named %+v, want the blackhole rule at 50 as a candidate", got)
	}
}

// IPv6's suppress reads an exception's answer as a /128, whatever the length
// of the route it hangs off, so `lookup main suppress_prefixlength 0` takes a
// destination main holds an exception for under its default, and passes over
// one it holds none for
func TestTakeRuleReadsAnExceptionAsItsDestinationAlone(t *testing.T) {
	suppressing := DumpedRule{Family: FamilyIPv6, Priority: 100, Action: "lookup", Table: uint32(schema.TableMain), Suppress: SuppressUpTo(0), Protocol: 99}
	mesh := DumpedRule{Family: FamilyIPv6, Priority: 200, Action: "lookup", Table: 100, Protocol: 99}
	rules := []DumpedRule{
		{Family: FamilyIPv6, Priority: 0, Action: "lookup", Table: uint32(schema.TableLocal), Protocol: 2},
		suppressing, mesh,
		{Family: FamilyIPv6, Priority: 32766, Action: "lookup", Table: uint32(schema.TableMain), Protocol: 2},
	}
	excepted := takenAnswer(uint32(schema.TableMain), "::/0")
	excepted.Exception = true
	if got := TakeRule(rules, netip.Addr{}, addr("2001:db8:ffff::10"), "", excepted, nil); !got.Found || got.Rule != suppressing {
		t.Fatalf("for an exception under main's default named %+v, want the rule at 100", got)
	}
	if got := TakeRule(rules, netip.Addr{}, addr("2001:db8:ffff::20"), "", takenAnswer(100, "::/0"), nil); !got.Found || got.Rule != mesh {
		t.Fatalf("for table 100's default named %+v, want the rule at 200", got)
	}
	excepted.Exception = false
	if got := TakeRule(rules, netip.Addr{}, addr("2001:db8:ffff::10"), "", excepted, nil); !got.Found || got.Rule.Priority != 32766 {
		t.Fatalf("for main's default itself named %+v, want the lookup of main at 32766", got)
	}
}

// A dumped mark compares under the mask the dump holds, so `fwmark 0x72/0`
// takes an unmarked packet, as a namespace's kernel took one to 203.0.113.9
// from table 100, ahead of a later lookup of that table, while a mark under
// every bit does not
func TestTakeRuleComparesAMarkUnderItsDumpedMask(t *testing.T) {
	route := takenAnswer(100, "203.0.113.0/24")
	dst := addr("203.0.113.9")
	marked := DumpedRule{Family: FamilyIPv4, Priority: 50, FWMark: 0x72, Action: "lookup", Table: 100}
	rules := []DumpedRule{
		{Family: FamilyIPv4, Priority: 0, Action: "lookup", Table: uint32(schema.TableLocal), Protocol: 2},
		marked,
		{Family: FamilyIPv4, Priority: 5420, Action: "lookup", Table: 100, Protocol: 4},
		{Family: FamilyIPv4, Priority: 32766, Action: "lookup", Table: uint32(schema.TableMain), Protocol: 2},
		{Family: FamilyIPv4, Priority: 32767, Action: "lookup", Table: uint32(schema.TableDefault), Protocol: 2},
	}
	if got := TakeRule(rules, netip.Addr{}, dst, "", route, nil); !got.Found || got.Rule != marked {
		t.Fatalf("named %+v, want fwmark 0x72/0 at 50", got)
	}
	rules[1].FWMask = ^uint32(0)
	if got := TakeRule(rules, netip.Addr{}, dst, "", route, nil); !got.Found || got.Rule.Priority != 5420 {
		t.Fatalf("named %+v, want fwmark 0x72/0xffffffff at 50 passed over for the lookup at 5420", got)
	}
}

// A terminal rule whose errno a check outside the walk answers for the packet
// too is named as a candidate only: IPv4's EINVAL for an arrival or this
// host's own packet, and its ENETUNREACH for this host's own packet from a
// source. Where no outside check answers that errno, the rule is taken.
func TestTakeRuleNamesACandidateForAnErrnoRaisedOutsideTheWalk(t *testing.T) {
	blackhole4 := DumpedRule{Family: FamilyIPv4, Priority: 40000, To: prefix("203.0.113.0/24"), Action: "blackhole", Protocol: 99}
	blackhole6 := DumpedRule{Family: FamilyIPv6, Priority: 40000, To: prefix("2001:db8:ffff::/48"), Action: "blackhole", Protocol: 99}
	rules := append(takenRules(false), blackhole4, blackhole6)
	// the lab's unreachable rule at 1000 selects 203.0.113.64/27
	for _, c := range []struct {
		name, src, dst, iif string
		err                 syscall.Errno
		priority            uint32
		candidate           bool
	}{
		{"an IPv4 arrival's EINVAL", "203.0.113.50", "203.0.113.200", "lan0", syscall.EINVAL, 40000, true},
		{"this host's IPv4 EINVAL", "", "203.0.113.200", "", syscall.EINVAL, 40000, true},
		{"this host's IPv4 ENETUNREACH from a source", "198.51.100.99", "203.0.113.70", "", syscall.ENETUNREACH, 1000, true},
		{"this host's IPv4 ENETUNREACH from no source", "", "203.0.113.70", "", syscall.ENETUNREACH, 1000, false},
		{"an IPv4 arrival's ENETUNREACH", "198.51.100.140", "203.0.113.70", "lan0", syscall.ENETUNREACH, 1000, false},
		{"an IPv6 arrival's EINVAL", "2001:db8:2::5", "2001:db8:ffff::10", "lan0", syscall.EINVAL, 40000, false},
		{"this host's IPv6 ENETUNREACH from a source", "3fff::1", "2001:db8:dead::10", "", syscall.ENETUNREACH, 1000, false},
	} {
		var src netip.Addr
		if c.src != "" {
			src = addr(c.src)
		}
		got := TakeRule(rules, src, addr(c.dst), c.iif, MatchedRoute{}, lookupError(c.err))
		if !got.Found || got.Rule.Priority != c.priority || got.Candidate != c.candidate {
			t.Errorf("%s: named %+v, want priority %d as a candidate %v", c.name, got, c.priority, c.candidate)
		}
	}
}

// suppress_ifgroup is no selector but a condition on a lookup's answer, so a
// lookup carrying it that the answer names is listed, its answer taken as
// suppressed, and a goto or an inverted rule carrying it is walked as one
// carrying none
func TestTakeRuleTakesSuppressIfgroupAsAConditionOnTheAnswer(t *testing.T) {
	main := takenAnswer(uint32(schema.TableMain), "0.0.0.0/0")
	grouped := DumpedRule{Family: FamilyIPv4, Priority: 50, Action: "lookup", Table: uint32(schema.TableMain), Unread: SelectorSuppressIfgroup}
	got := TakeRule(append(takenRules(false), grouped), netip.Addr{}, addr("203.0.113.200"), "", main, nil)
	if !got.Found || got.Rule.Priority != 32766 || !slices.Equal(got.Unread, []DumpedRule{grouped}) {
		t.Fatalf("named %+v, want the lookup of main at 32766 behind the rule at 50", got)
	}
	grouped.Invert = true
	got = TakeRule(append(takenRules(false), grouped), netip.Addr{}, addr("203.0.113.200"), "", main, nil)
	if !got.Found || got.Rule.Priority != 32766 || len(got.Unread) != 0 {
		t.Fatalf("named %+v, want the inverted rule at 50 passed over unlisted", got)
	}
	jump := DumpedRule{Family: FamilyIPv4, Priority: 50, Action: "goto", Goto: 32766, Unread: SelectorSuppressIfgroup}
	skipped := DumpedRule{Family: FamilyIPv4, Priority: 60, Action: "lookup", Table: uint32(schema.TableMain)}
	got = TakeRule(append(takenRules(false), jump, skipped), netip.Addr{}, addr("203.0.113.200"), "", main, nil)
	if !got.Found || got.Rule.Priority != 32766 || len(got.Unread) != 0 {
		t.Fatalf("named %+v, want the goto at 50 followed past the lookup at 60", got)
	}
}

// The kernel inverts an unread selector's match with the rest, so an inverted
// rule whose read selectors hold is listed, its match being the unread one's,
// and one whose read selectors fail matches and is walked
func TestTakeRuleWalksAnInvertedRuleOfASelectorItDoesNotRead(t *testing.T) {
	main := takenAnswer(uint32(schema.TableMain), "0.0.0.0/0")
	everywhere := DumpedRule{Family: FamilyIPv4, Priority: 50, Invert: true, Action: "lookup", Table: 77, Unread: SelectorIPProto}
	got := TakeRule(append(takenRules(false), everywhere), netip.Addr{}, addr("203.0.113.200"), "", takenAnswer(77, "203.0.113.0/24"), nil)
	if got.Found || !slices.Equal(got.Unread, []DumpedRule{everywhere}) {
		t.Fatalf("for an answer of table 77 named %+v, want none behind the inverted rule at 50", got)
	}
	elsewhere := DumpedRule{Family: FamilyIPv4, Priority: 50, To: prefix("198.51.100.0/24"), Invert: true, Action: "lookup", Table: uint32(schema.TableMain), Unread: SelectorIPProto}
	got = TakeRule(append(takenRules(false), elsewhere), netip.Addr{}, addr("203.0.113.200"), "", main, nil)
	if !got.Found || got.Rule != elsewhere || len(got.Unread) != 0 {
		t.Fatalf("named %+v, want the inverted rule at 50 taken, its selector to 198.51.100.0/24 failing", got)
	}
	elsewhere.Invert = false
	got = TakeRule(append(takenRules(false), elsewhere), netip.Addr{}, addr("203.0.113.200"), "", main, nil)
	if !got.Found || got.Rule.Priority != 32766 || len(got.Unread) != 0 {
		t.Fatalf("named %+v, want the rule at 50 passed over unlisted and the lookup of main at 32766", got)
	}
}

// A goto whose target sits nowhere is passed over as the kernel passes it, and
// one whose target sits later skips what lies between
func TestTakeRuleFollowsAGoto(t *testing.T) {
	jump := DumpedRule{Family: FamilyIPv4, Priority: 50, Action: "goto", Goto: 5300}
	skipped := DumpedRule{Family: FamilyIPv4, Priority: 60, Action: "lookup", Table: uint32(schema.TableMain)}
	main := takenAnswer(uint32(schema.TableMain), "0.0.0.0/0")
	rules := append(takenRules(false), jump, skipped)
	if got := TakeRule(rules, netip.Addr{}, addr("203.0.113.200"), "", main, nil); !got.Found || got.Rule != skipped {
		t.Fatalf("with no rule at 5300 named %+v, want the lookup at 60", got)
	}
	// the kernel holds a nop's table, which the nop never reads
	rules = append(rules, DumpedRule{Family: FamilyIPv4, Priority: 5300, Action: "nop", Table: uint32(schema.TableMain)})
	if got := TakeRule(rules, netip.Addr{}, addr("203.0.113.200"), "", main, nil); !got.Found || got.Rule.Priority != 32766 {
		t.Fatalf("with a nop at 5300 named %+v, want the lookup of main at 32766", got)
	}
}
