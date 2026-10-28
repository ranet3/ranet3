// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"syscall"
	"testing"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/kernel"
)

// routeProto is the protocol the route view's node writes its rules with
const routeProto = 155

// routeDump is a node's rules in mode off, as a dump reads them: the
// kernel's own, an unreachable rule of another program, and the mesh's
// suppressing lookups of main and of table 100
func routeDump() []kernel.DumpedRule {
	var out []kernel.DumpedRule
	for _, family := range []kernel.Family{kernel.FamilyIPv4, kernel.FamilyIPv6} {
		to, floor := netip.MustParsePrefix("203.0.113.64/27"), 7
		if family == kernel.FamilyIPv6 {
			to, floor = netip.MustParsePrefix("2001:db8:dead::/48"), 15
		}
		out = append(out,
			kernel.DumpedRule{Family: family, Priority: 0, Action: "lookup", Table: 255, Protocol: 2},
			kernel.DumpedRule{Family: family, Priority: 1000, To: to, Action: "unreachable", Protocol: 99},
			kernel.DumpedRule{Family: family, Priority: 5410, Action: "lookup", Table: 254, Suppress: kernel.SuppressUpTo(0), Protocol: routeProto},
			kernel.DumpedRule{Family: family, Priority: 5420, Action: "lookup", Table: 100, Suppress: kernel.SuppressUpTo(floor), Protocol: routeProto},
			kernel.DumpedRule{Family: family, Priority: 32766, Action: "lookup", Table: 254, Protocol: 2},
		)
	}
	return out
}

// routeClient is a client of a node whose tun is ranet0, the kernel answering
// every lookup with answer and err and holding routeDump's rules, the
// reconciler deriving the two lookups of IPv4, and each setting read as
// settings holds it, a missing one unreadable
func routeClient(t *testing.T, answer kernel.MatchedRoute, err error, settings map[string]string) (*Client, *[]string) {
	t.Helper()
	c, _, _, _ := reloadOf(t, func(cfg *config.Config) { cfg.Cap.Table = &kernel.Table{Proto: routeProto} })
	c.Mesh.Name = "ranet0"
	c.routeGet = func(netip.Addr, netip.Addr, string) (kernel.MatchedRoute, error) { return answer, err }
	c.ruleDump = func() ([]kernel.DumpedRule, error) { return routeDump(), nil }
	c.SetReconcilerRules(func() []kernel.DumpedRule { return routeDump()[2:4] })
	var read []string
	c.sysctl = func(path string) string {
		read = append(read, path)
		return settings[path]
	}
	return c, &read
}

// lookupFailed is an errno as RouteGet wraps it
func lookupFailed(errno syscall.Errno) error {
	return fmt.Errorf("kernel: look up the route: %w", errno)
}

// The tun is no arrival, an arrival carries a source, and a name that would
// leave the sysctl tree is no link
func TestDebugRouteRefusesWhatIsNoArrival(t *testing.T) {
	c, read := routeClient(t, kernel.MatchedRoute{}, nil, nil)
	for name, test := range map[string]struct {
		src string
		iif string
	}{
		"the tun":                 {"192.0.2.1", "ranet0"},
		"an arrival of no source": {"", "lan0"},
		"a path":                  {"192.0.2.1", "../lan0"},
		"the parent":              {"192.0.2.1", ".."},
	} {
		var src netip.Addr
		if test.src != "" {
			src = netip.MustParseAddr(test.src)
		}
		if info, err := c.DebugRoute(src, netip.MustParseAddr("203.0.113.200"), test.iif); err == nil {
			t.Errorf("%s was followed as %+v", name, info)
		}
	}
	if len(*read) != 0 {
		t.Errorf("a refused packet read %q", *read)
	}
}

// A route's rule is named with its owner, each hop carries the kernel's marks,
// and a route by the tun says it enters the mesh
func TestDebugRouteNamesTheRuleAndTheRoute(t *testing.T) {
	route := kernel.MatchedRoute{Prefix: netip.MustParsePrefix("203.0.113.0/26"), Table: 100, Type: "unicast", NextHops: []kernel.NextHop{
		{Device: "ranet0"}, {Device: "lan0", Gateway: netip.MustParseAddr("198.51.100.129"), Dead: true, LinkDown: true},
	}}
	c, read := routeClient(t, route, nil, nil)
	info, err := c.DebugRoute(netip.Addr{}, netip.MustParseAddr("203.0.113.10"), "")
	if err != nil {
		t.Fatal(err)
	}
	k := info.Kernel
	hops := []control.RouteNextHop{{Dev: "ranet0"}, {Dev: "lan0", Gateway: netip.MustParseAddr("198.51.100.129"), Dead: true, LinkDown: true}}
	if info.Arrival != control.ArrivalLocal || k == nil || k.Route != route.Prefix || k.Table != 100 || !slices.Equal(k.NextHops, hops) || !k.IntoTun {
		t.Fatalf("the route view reads %+v and %+v", info, k)
	}
	if k.Rule == nil || k.Rule.Priority != 5420 || !k.Rule.Owned || !k.Rule.Wanted || k.Err != "" || k.Why != "" || len(*read) != 0 {
		t.Errorf("the route view names the rule %+v, with %q, %q and settings %q", k.Rule, k.Err, k.Why, *read)
	}

	route.NextHops = route.NextHops[1:]
	c, _ = routeClient(t, route, nil, nil)
	if info, _ := c.DebugRoute(netip.Addr{}, netip.MustParseAddr("203.0.113.10"), ""); info.Kernel.IntoTun {
		t.Errorf("a route by lan0 alone reads as entering the mesh")
	}

	cached := kernel.MatchedRoute{Prefix: netip.MustParsePrefix("::/0"), Table: 254, Type: "unicast", NextHops: []kernel.NextHop{{Device: "up0"}}, Exception: true}
	c, _ = routeClient(t, cached, nil, nil)
	info, err = c.DebugRoute(netip.MustParseAddr("2001:db8:2::5"), netip.MustParseAddr("2001:db8:ffff::10"), "")
	if err != nil || !info.Kernel.Exception || info.Kernel.NoSource != !kernel.RouteGetTakesSource {
		t.Errorf("a lookup answered through an exception reads %+v, %v", info.Kernel, err)
	}
}

// A route the kernel made with no table entry behind it is shown as that,
// with no rule, route type or setting named for it, an arrival's included
func TestDebugRouteNamesNothingForARouteOfNoTableEntry(t *testing.T) {
	route := kernel.MatchedRoute{Prefix: netip.MustParsePrefix("255.255.255.255/32"), Type: "broadcast", NextHops: []kernel.NextHop{{Device: "lo"}}, NoEntry: true}
	c, read := routeClient(t, route, nil, nil)
	info, err := c.DebugRoute(netip.MustParseAddr("198.51.100.9"), netip.MustParseAddr("255.255.255.255"), "lan0")
	if err != nil {
		t.Fatal(err)
	}
	k := info.Kernel
	if !k.NoEntry || k.Route != route.Prefix || k.Type != "broadcast" || k.Rule != nil || k.Candidate != nil || k.RouteType != "" || k.Why != "" || len(k.Settings) != 0 || len(*read) != 0 {
		t.Errorf("the route view reads %+v, having read %q, want the route of no table entry alone", k, *read)
	}
}

// A rule carrying a selector the walk does not read is named ahead of the
// rule the answer takes, with that selector, rather than passed over unsaid
func TestDebugRouteNamesTheRulesItDoesNotRead(t *testing.T) {
	route := kernel.MatchedRoute{Prefix: netip.MustParsePrefix("0.0.0.0/0"), Table: 254, Type: "unicast", NextHops: []kernel.NextHop{{Device: "up0"}}}
	c, _ := routeClient(t, route, nil, nil)
	uid := kernel.DumpedRule{Family: kernel.FamilyIPv4, Priority: 300, Action: "lookup", Table: 254, Protocol: 4, Unread: kernel.SelectorUIDRange}
	c.ruleDump = func() ([]kernel.DumpedRule, error) { return append(routeDump(), uid), nil }
	info, err := c.DebugRoute(netip.Addr{}, netip.MustParseAddr("203.0.113.200"), "")
	if err != nil {
		t.Fatal(err)
	}
	k := info.Kernel
	if len(k.Unread) != 1 || k.Unread[0].Priority != 300 || !slices.Equal(k.Unread[0].Unread, []string{"uidrange"}) || k.Rule == nil || k.Rule.Priority != 32766 {
		t.Errorf("the route view names %+v behind %+v, want the lookup of main at 32766 behind the uidrange rule at 300", k.Rule, k.Unread)
	}
}

// Each errno is explained by what the answer and the arrival link's settings
// say, and by nothing a setting that is off or unread would leave a guess
func TestDebugRouteExplainsTheKernelsError(t *testing.T) {
	internet4, internet6 := netip.MustParseAddr("203.0.113.200"), netip.MustParseAddr("2001:db8:ffff::10")
	main6 := kernel.MatchedRoute{Prefix: netip.MustParsePrefix("::/0"), Table: 254, Type: "unicast", NextHops: []kernel.NextHop{{Device: "up0"}}}
	rp := func(all, link string) map[string]string {
		return map[string]string{"net/ipv4/conf/all/rp_filter": all, "net/ipv4/conf/lan0/rp_filter": link}
	}
	// IPv6's forwarding in all, on lan0 and forced on lan0, an empty one unread
	forwarding6 := func(all, link, force string) map[string]string {
		settings := map[string]string{"net/ipv6/conf/all/forwarding": all, "net/ipv6/conf/lan0/forwarding": link, "net/ipv6/conf/lan0/force_forwarding": force}
		maps.DeleteFunc(settings, func(_, value string) bool { return value == "" })
		return settings
	}
	forwarded6 := []string{"net/ipv6/conf/all/forwarding", "net/ipv6/conf/lan0/force_forwarding"}
	// an IPv4 group's route of no table entry, and mc_forwarding in all and
	// on lan0, an empty one unread
	group4 := kernel.MatchedRoute{Prefix: netip.MustParsePrefix("239.1.2.3/32"), Type: "multicast", NextHops: []kernel.NextHop{{Device: "lo"}}, NoEntry: true}
	routed4 := []string{"net/ipv4/conf/all/mc_forwarding", "net/ipv4/conf/lan0/mc_forwarding"}
	routing4 := func(all, link string) map[string]string {
		settings := map[string]string{routed4[0]: all, routed4[1]: link}
		maps.DeleteFunc(settings, func(_, value string) bool { return value == "" })
		return settings
	}
	for name, test := range map[string]struct {
		src, dst  netip.Addr
		iif       string
		answer    kernel.MatchedRoute
		err       error
		settings  map[string]string
		why       string
		read      []string
		rule      uint32
		candidate uint32
		routeType string
	}{
		"no route":             {dst: internet4, err: lookupFailed(syscall.ENETUNREACH), why: control.WhyNoRoute},
		"the unreachable rule": {dst: netip.MustParseAddr("203.0.113.70"), err: lookupFailed(syscall.ENETUNREACH), rule: 1000},
		"the unreachable rule or a source this host does not hold": {
			src: netip.MustParseAddr("192.0.2.99"), dst: netip.MustParseAddr("203.0.113.70"), err: lookupFailed(syscall.ENETUNREACH), why: control.WhyNoRoute, candidate: 1000,
		},
		"reverse path filtering on the link": {
			src: netip.MustParseAddr("203.0.113.50"), dst: internet4, iif: "lan0", err: lookupFailed(syscall.EINVAL), settings: rp("0", "1"),
			why: control.WhyReversePath, read: []string{"net/ipv4/conf/all/rp_filter", "net/ipv4/conf/lan0/rp_filter"}, routeType: "blackhole",
		},
		"loose reverse path filtering on all": {
			src: netip.MustParseAddr("203.0.113.50"), dst: internet4, iif: "lan0", err: lookupFailed(syscall.EINVAL), settings: rp("2", "0"),
			why: control.WhyReversePath, read: []string{"net/ipv4/conf/all/rp_filter", "net/ipv4/conf/lan0/rp_filter"}, routeType: "blackhole",
		},
		"reverse path filtering off": {
			src: netip.MustParseAddr("203.0.113.50"), dst: internet4, iif: "lan0", err: lookupFailed(syscall.EINVAL), settings: rp("0", "0"),
			read: []string{"net/ipv4/conf/all/rp_filter", "net/ipv4/conf/lan0/rp_filter"}, routeType: "blackhole",
		},
		"reverse path filtering unread": {
			src: netip.MustParseAddr("203.0.113.50"), dst: internet4, iif: "lan0", err: lookupFailed(syscall.EINVAL),
			settings: map[string]string{"net/ipv4/conf/all/rp_filter": "1"},
			read:     []string{"net/ipv4/conf/all/rp_filter", "net/ipv4/conf/lan0/rp_filter"}, routeType: "blackhole",
		},
		"a group not joined under reverse path filtering": {
			src: netip.MustParseAddr("198.51.100.140"), dst: netip.MustParseAddr("239.1.2.4"), iif: "lan0", err: lookupFailed(syscall.EINVAL), settings: rp("0", "1"),
			why: control.WhyReversePath, read: []string{"net/ipv4/conf/all/rp_filter", "net/ipv4/conf/lan0/rp_filter"},
		},
		"a martian destination": {
			src: netip.MustParseAddr("198.51.100.140"), dst: netip.IPv4Unspecified(), iif: "lan0", err: lookupFailed(syscall.EINVAL), settings: rp("0", "1"),
			why: control.WhyMartianDestination,
		},
		"a joined group with multicast routing off": {
			src: netip.MustParseAddr("198.51.100.140"), dst: netip.MustParseAddr("239.1.2.3"), iif: "lan0", answer: group4, settings: routing4("1", "0"), read: routed4,
		},
		"a group under multicast routing": {
			src: netip.MustParseAddr("198.51.100.140"), dst: netip.MustParseAddr("239.1.2.3"), iif: "lan0", answer: group4, settings: routing4("1", "1"),
			why: control.WhyMulticastRouting, read: routed4,
		},
		"a group with multicast routing unread": {
			src: netip.MustParseAddr("198.51.100.140"), dst: netip.MustParseAddr("239.1.2.3"), iif: "lan0", answer: group4, settings: routing4("1", ""), read: routed4,
		},
		"a group on the link": {
			src: netip.MustParseAddr("198.51.100.140"), dst: netip.MustParseAddr("224.0.0.1"), iif: "lan0", settings: routing4("1", "1"),
			answer: kernel.MatchedRoute{Prefix: netip.MustParsePrefix("224.0.0.1/32"), Type: "multicast", NextHops: []kernel.NextHop{{Device: "lo"}}, NoEntry: true},
		},
		"a group's answer multicast routing withholds": {
			src: netip.MustParseAddr("198.51.100.140"), dst: netip.MustParseAddr("239.1.2.3"), iif: "lan0", err: lookupFailed(syscall.EHOSTUNREACH),
			settings: map[string]string{routed4[0]: "1", "net/ipv4/conf/lan0/forwarding": "0"}, why: control.WhyMulticastRouting, read: routed4[:1],
		},
		"a group's answer with multicast routing unread": {
			src: netip.MustParseAddr("198.51.100.140"), dst: netip.MustParseAddr("239.1.2.3"), iif: "lan0", err: lookupFailed(syscall.EHOSTUNREACH),
			settings: map[string]string{"net/ipv4/conf/lan0/forwarding": "0"}, why: control.WhyMulticastRouting, read: routed4[:1],
		},
		"a group's answer with multicast routing read off": {
			src: netip.MustParseAddr("198.51.100.140"), dst: netip.MustParseAddr("239.1.2.3"), iif: "lan0", err: lookupFailed(syscall.EHOSTUNREACH),
			settings: map[string]string{routed4[0]: "0", "net/ipv4/conf/lan0/forwarding": "0"}, why: control.WhyMulticastRouting, read: routed4[:1],
		},
		"a group's answer on the link": {
			src: netip.MustParseAddr("198.51.100.140"), dst: netip.MustParseAddr("224.0.0.251"), iif: "lan0", err: lookupFailed(syscall.EHOSTUNREACH),
			settings: map[string]string{routed4[0]: "1", "net/ipv4/conf/lan0/forwarding": "0"}, why: control.WhyForwardingOff, read: []string{"net/ipv4/conf/lan0/forwarding"},
		},
		"forwarding off": {
			src: netip.MustParseAddr("198.51.100.140"), dst: internet4, iif: "lan0", err: lookupFailed(syscall.EHOSTUNREACH),
			settings: map[string]string{"net/ipv4/conf/lan0/forwarding": "0"}, why: control.WhyForwardingOff,
			read: []string{"net/ipv4/conf/lan0/forwarding"}, routeType: "unreachable",
		},
		"an unreachable route with forwarding on": {
			src: netip.MustParseAddr("198.51.100.140"), dst: internet4, iif: "lan0", err: lookupFailed(syscall.EHOSTUNREACH),
			settings: map[string]string{"net/ipv4/conf/lan0/forwarding": "1"}, read: []string{"net/ipv4/conf/lan0/forwarding"}, routeType: "unreachable",
		},
		"this host's own packet to an unreachable route": {dst: internet4, err: lookupFailed(syscall.EHOSTUNREACH), routeType: "unreachable"},
		"IPv6 forwarding off": {
			src: netip.MustParseAddr("2001:db8:2::5"), dst: internet6, iif: "lan0", answer: main6,
			settings: forwarding6("0", "1", "0"), why: control.WhyForwardingOff, read: forwarded6, rule: 32766,
		},
		"IPv6 forwarding off on a kernel without force_forwarding": {
			src: netip.MustParseAddr("2001:db8:2::5"), dst: internet6, iif: "lan0", answer: main6,
			settings: forwarding6("0", "1", ""), why: control.WhyForwardingOff, read: forwarded6, rule: 32766,
		},
		"IPv6 forwarding on in all": {
			src: netip.MustParseAddr("2001:db8:2::5"), dst: internet6, iif: "lan0", answer: main6,
			settings: forwarding6("1", "0", "0"), read: forwarded6, rule: 32766,
		},
		"IPv6 forwarding forced on the link": {
			src: netip.MustParseAddr("2001:db8:2::5"), dst: internet6, iif: "lan0", answer: main6,
			settings: forwarding6("0", "0", "1"), read: forwarded6, rule: 32766,
		},
		"IPv6 forwarding unread": {
			src: netip.MustParseAddr("2001:db8:2::5"), dst: internet6, iif: "lan0", answer: main6,
			settings: forwarding6("", "0", "0"), read: forwarded6, rule: 32766,
		},
		"IPv6 forwarding off beside a force_forwarding that is no number": {
			src: netip.MustParseAddr("2001:db8:2::5"), dst: internet6, iif: "lan0", answer: main6,
			settings: forwarding6("0", "1", "on"), read: forwarded6, rule: 32766,
		},
		"IPv6 delivered to this host": {
			src: netip.MustParseAddr("2001:db8:2::5"), dst: netip.MustParseAddr("2001:db8:2::1"), iif: "lan0",
			answer: kernel.MatchedRoute{Prefix: netip.MustParsePrefix("2001:db8:2::1/128"), Table: 255, Type: "local"}, rule: 0,
		},
	} {
		t.Run(name, func(t *testing.T) {
			c, read := routeClient(t, test.answer, test.err, test.settings)
			info, err := c.DebugRoute(test.src, test.dst, test.iif)
			if err != nil {
				t.Fatal(err)
			}
			k := info.Kernel
			if k.Why != test.why || !slices.Equal(*read, test.read) || k.RouteType != test.routeType {
				t.Errorf("explained as %q, route type %q, settings %+v, reading %q", k.Why, k.RouteType, k.Settings, *read)
			}
			named := test.rule != 0 || test.answer.Type == "local"
			if named != (k.Rule != nil) || k.Rule != nil && k.Rule.Priority != test.rule {
				t.Errorf("named the rule %+v, want priority %d", k.Rule, test.rule)
			}
			if (test.candidate != 0) != (k.Candidate != nil) || k.Candidate != nil && k.Candidate.Priority != test.candidate {
				t.Errorf("named the candidate %+v, want priority %d", k.Candidate, test.candidate)
			}
			if test.err != nil && (k.Err == "" || k.Errno == "") {
				t.Errorf("the error reads %q named %q", k.Err, k.Errno)
			}
			for _, setting := range k.Settings {
				if (setting.Value == "") == (setting.Err == "") {
					t.Errorf("the setting %+v reads both or neither a value and an error", setting)
				}
			}
		})
	}
}

// A platform that looks up no arrival says so and reads no rule, and one
// with no policy rules shows the route alone
func TestDebugRouteOnAPlatformWithoutRules(t *testing.T) {
	refused := fmt.Errorf("%w: darwin looks up the route of this host's own packet only, not of one arriving on en0", kernel.ErrUnsupported)
	c, _ := routeClient(t, kernel.MatchedRoute{}, refused, nil)
	dumped := false
	c.ruleDump = func() ([]kernel.DumpedRule, error) { dumped = true; return nil, kernel.ErrUnsupported }
	info, err := c.DebugRoute(netip.MustParseAddr("192.0.2.7"), netip.MustParseAddr("203.0.113.200"), "en0")
	if err != nil || info.Kernel.Why != control.WhyUnsupported || dumped || info.Kernel.Rule != nil {
		t.Errorf("an arrival darwin does not look up reads %+v, %v, the rules dumped %v", info.Kernel, err, dumped)
	}

	route := kernel.MatchedRoute{Prefix: netip.MustParsePrefix("0.0.0.0/0"), Type: "unicast", NextHops: []kernel.NextHop{{Device: "en0"}}}
	c, _ = routeClient(t, route, nil, nil)
	c.ruleDump = func() ([]kernel.DumpedRule, error) { return nil, kernel.ErrUnsupported }
	info, err = c.DebugRoute(netip.Addr{}, netip.MustParseAddr("203.0.113.200"), "")
	if err != nil || info.Kernel.RuleErr != "this platform has no policy rules" || info.Kernel.Route != route.Prefix {
		t.Errorf("this host's own packet on darwin reads %+v, %v", info.Kernel, err)
	}
	c.ruleDump = func() ([]kernel.DumpedRule, error) { return nil, errors.New("kernel: dump rules: permission denied") }
	if info, _ = c.DebugRoute(netip.Addr{}, netip.MustParseAddr("203.0.113.200"), ""); info.Kernel.RuleErr != "kernel: dump rules: permission denied" {
		t.Errorf("a failed dump reads %+v", info.Kernel)
	}
}
