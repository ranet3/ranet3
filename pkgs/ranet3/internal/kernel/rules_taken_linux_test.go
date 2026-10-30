// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"slices"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/schema"
)

// takenWait bounds how long the lab waits for the kernel to take a packet a
// test wrote, polling at takenPoll
const (
	takenWait = 2 * time.Second
	takenPoll = 20 * time.Millisecond
)

// takenLabRule is a rule the lab installed, and the message that installed it
type takenLabRule struct {
	family   Family
	priority uint32
	iif      string
	from, to netip.Prefix
	body     []byte
}

func (r takenLabRule) is(rule DumpedRule) bool {
	return r.family == rule.Family && r.priority == rule.Priority && r.iif == rule.IIF && r.from == rule.From && r.to == rule.To
}

// takenLab is a namespace of the mesh's rules in mode off and mode 2 beside
// the kernel's: an uplink up0 at 198.51.100.2/25 and
// 2001:db8:1::2/64 with main's defaults through it, a second link lan0 at
// 198.51.100.130/25 and 2001:db8:2::1/64, the tun's stand-in mesh0 with the
// own addresses 192.0.2.1 and 3fff::1, and the mesh's table holding a default,
// a /1 pair, a mesh subnet, a throw for the own address and a held prefix
type takenLab struct {
	conn  *nlConn
	rules []takenLabRule
}

func openTakenLab(t *testing.T) *takenLab {
	if os.Getuid() != 0 {
		t.Skip("the real netlink path needs root on linux")
	}
	enterThrowawayNamespace(t)
	conn, err := dialNetlink()
	if err != nil {
		t.Fatalf("dial rtnetlink: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	requireEmptyNamespace(t, conn)
	index := map[string]uint32{}
	for _, name := range []string{"up0", "lan0", "mesh0"} {
		if err := createLink(conn, name, "dummy"); err != nil {
			t.Fatalf("create the dummy %s: %v", name, err)
		}
		link, err := conn.link(0, name)
		if err != nil {
			t.Fatalf("look up %s: %v", name, err)
		}
		setLinkFlags(t, conn, link.index, unix.IFF_UP)
		index[name] = link.index
	}
	// a new namespace takes its IPv4 settings from the host's
	for _, setting := range []string{"ipv4/conf/all/rp_filter", "ipv4/conf/default/rp_filter", "ipv4/conf/lan0/rp_filter"} {
		writeBatchSysctl(t, setting, "0")
	}
	writeBatchSysctl(t, "ipv4/ip_forward", "1")
	writeBatchSysctl(t, "ipv6/conf/all/forwarding", "1")
	for name, addresses := range map[string][]string{
		"up0": {"198.51.100.2/25", "2001:db8:1::2/64"}, "lan0": {"198.51.100.130/25", "2001:db8:2::1/64"}, "mesh0": {"192.0.2.1/32", "3fff::1/128"},
	} {
		for _, address := range addresses {
			writeBatchAddress(t, conn, index[name], prefix(address))
		}
	}
	writeBatchRoute(t, conn, unix.RT_TABLE_MAIN, prefix("0.0.0.0/0"), batchHop{index: index["up0"], gateway: addr("198.51.100.1")})
	writeBatchRoute(t, conn, unix.RT_TABLE_MAIN, prefix("::/0"), batchHop{index: index["up0"], gateway: addr("2001:db8:1::1")})
	for _, destination := range []string{"0.0.0.0/0", "0.0.0.0/1", "128.0.0.0/1", "203.0.113.0/26", "::/0", "::/1", "8000::/1", "2001:db8:100::/48"} {
		writeBatchRoute(t, conn, takenTable, prefix(destination), batchHop{index: index["mesh0"]})
	}
	for destination, kind := range map[string]uint8{
		"192.0.2.1/32": unix.RTN_THROW, "3fff::1/128": unix.RTN_THROW, "203.0.113.128/26": unix.RTN_UNREACHABLE, "2001:db8:200::/48": unix.RTN_UNREACHABLE,
	} {
		route := prefix(destination)
		body := make([]byte, unix.SizeofRtMsg)
		body[0], body[1], body[4], body[5], body[6], body[7] = unix.AF_INET6, uint8(route.Bits()), takenTable, unix.RTPROT_STATIC, unix.RT_SCOPE_UNIVERSE, kind
		if route.Addr().Is4() {
			body[0] = unix.AF_INET
		}
		body = putAttr(body, unix.RTA_DST, addressBytes(route.Addr()))
		if _, err := conn.execute(unix.RTM_NEWROUTE, unix.NLM_F_CREATE|unix.NLM_F_EXCL|unix.NLM_F_ACK, body); err != nil {
			t.Fatalf("install the %d route to %s: %v", kind, route, err)
		}
	}
	lab := &takenLab{conn: conn}
	for _, rule := range takenRules(false) {
		lab.install(t, rule)
	}
	return lab
}

// install writes rule, but for one the kernel holds from the start, which
// it only keeps the message of
func (l *takenLab) install(t *testing.T, rule DumpedRule) {
	t.Helper()
	held := Rule{Family: rule.Family, Priority: rule.Priority, From: schema.PrefixFrom(rule.From), To: schema.PrefixFrom(rule.To), IIF: rule.IIF,
		FWMark: rule.FWMark, Table: schema.TableID(rule.Table), target: rule.Goto, suppress: rule.Suppress}
	action := uint8(0)
	switch rule.Action {
	case "goto":
		held.action = actionGoto
	case "nop":
		held.action = actionNop
	case "unreachable", "prohibit", "blackhole":
		// written as a nop, which carries no table, then given its own action
		held.action = actionNop
		action = map[string]uint8{"unreachable": unix.FR_ACT_UNREACHABLE, "prohibit": unix.FR_ACT_PROHIBIT, "blackhole": unix.FR_ACT_BLACKHOLE}[rule.Action]
	}
	body := (&netlinkPlatform{table: Table{Proto: rule.Protocol}}).ruleMessage(held)
	if action != 0 {
		body[7] = action
	}
	l.rules = append(l.rules, takenLabRule{family: rule.Family, priority: rule.Priority, iif: rule.IIF, from: rule.From, to: rule.To, body: body})
	if rule.Protocol == unix.RTPROT_KERNEL {
		return
	}
	if _, err := l.conn.execute(unix.RTM_NEWRULE, unix.NLM_F_CREATE|unix.NLM_F_EXCL|unix.NLM_F_ACK, body); err != nil {
		t.Fatalf("install %+v: %v", rule, err)
	}
}

// without runs read with rule deleted, then puts it back
func (l *takenLab) without(t *testing.T, rule DumpedRule, read func()) {
	t.Helper()
	at := slices.IndexFunc(l.rules, func(r takenLabRule) bool { return r.is(rule) })
	if at < 0 {
		t.Fatalf("the rule named, %+v, is none the lab installed", rule)
	}
	body := l.rules[at].body
	if _, err := l.conn.execute(unix.RTM_DELRULE, unix.NLM_F_ACK, body); err != nil {
		t.Fatalf("delete %+v: %v", rule, err)
	}
	read()
	if _, err := l.conn.execute(unix.RTM_NEWRULE, unix.NLM_F_CREATE|unix.NLM_F_EXCL|unix.NLM_F_ACK, body); err != nil {
		t.Fatalf("put back %+v: %v", rule, err)
	}
}

// The mesh's rules in takenLab, mode off then mode 2, and the packets of this
// host and of each link. For each packet the kernel answers, the rule finder
// names a rule over the kernel's own dump,
// and deleting that rule moves the kernel's answer, which shows the walk took
// it. In mode 2, 5440 looks the mesh's table up for every packet of this
// host's own, so deleting 5110, 5420 or 5430 leaves the answer where it was,
// and the finder then names 5440 for it. A packet the kernel refuses with an
// errno no action answers is named no rule, with the route type that answers
// it, and a held prefix is refused with its unreachable route's errno past
// every suppressing lookup.
func TestNetlinkRouteGetNamesTheRuleTheLookupTook(t *testing.T) {
	lab := openTakenLab(t)
	type packet struct {
		name          string
		src, dst, iif string
		priority      uint32
		ruleIIF       string
		// shadowed is a rule whose deletion leaves the answer to 5440
		shadowed  bool
		routeType string
		errno     syscall.Errno
	}
	own := func(name, src, dst string, priority uint32, ruleIIF string) packet {
		return packet{name: name, src: src, dst: dst, priority: priority, ruleIIF: ruleIIF}
	}
	arrival := func(name, src, dst string, priority uint32, ruleIIF string) packet {
		return packet{name: name, src: src, dst: dst, iif: "lan0", priority: priority, ruleIIF: ruleIIF}
	}
	modeOff := []packet{
		own("own to the internet", "", "203.0.113.200", 32766, ""),
		own("own to the internet over IPv6", "", "2001:db8:ffff::10", 32766, ""),
		own("own to an overlay address", "", "192.0.2.20", 5110, ""),
		own("own to an overlay address over IPv6", "", "3fff::20", 5110, ""),
		own("own to the mesh subnet", "", "203.0.113.10", 5420, ""),
		own("own to the mesh subnet over IPv6", "", "2001:db8:100::10", 5420, ""),
		own("own from the own prefix", "192.0.2.1", "203.0.113.200", 5430, ""),
		own("own from the own prefix over IPv6", "3fff::1", "2001:db8:ffff::10", 5430, ""),
		own("own to the unreachable rule", "", "203.0.113.70", 1000, ""),
		own("own to the unreachable rule over IPv6", "", "2001:db8:dead::10", 1000, ""),
		own("own to the prohibit rule", "", "203.0.113.100", 1001, ""),
		own("own to the prohibit rule over IPv6", "", "2001:db8:beef::10", 1001, ""),
		arrival("a link arrival", "198.51.100.140", "203.0.113.200", 32766, ""),
		arrival("a link arrival over IPv6", "2001:db8:2::5", "2001:db8:ffff::10", 32766, ""),
		arrival("a link arrival to the unreachable rule", "198.51.100.140", "203.0.113.70", 1000, ""),
		arrival("a link arrival to the prohibit rule over IPv6", "2001:db8:2::5", "2001:db8:beef::10", 1001, ""),
		{name: "own to a held prefix", dst: "203.0.113.130", routeType: "unreachable", errno: unix.EHOSTUNREACH},
		{name: "own to a held prefix over IPv6", dst: "2001:db8:200::10", routeType: "unreachable", errno: unix.EHOSTUNREACH},
	}
	modeTwo := []packet{
		own("own to the internet in mode 2", "", "203.0.113.200", 5440, "lo"),
		own("own to the internet in mode 2 over IPv6", "", "2001:db8:ffff::10", 5440, "lo"),
		{name: "own to an overlay address in mode 2", dst: "192.0.2.20", priority: 5110, shadowed: true},
		{name: "own to the mesh subnet in mode 2 over IPv6", dst: "2001:db8:100::10", priority: 5420, shadowed: true},
		{name: "own from the own prefix in mode 2", src: "192.0.2.1", dst: "203.0.113.200", priority: 5430, shadowed: true},
		own("own to the prohibit rule in mode 2", "", "203.0.113.100", 1001, ""),
		arrival("a link arrival in mode 2", "198.51.100.140", "203.0.113.200", 5440, "lan0"),
		arrival("a link arrival in mode 2 over IPv6", "2001:db8:2::5", "2001:db8:ffff::10", 5440, "lan0"),
		own("own from the forwarded link's address in mode 2", "198.51.100.130", "203.0.113.200", 5405, "lo"),
		own("own from the forwarded link's address in mode 2 over IPv6", "2001:db8:2::1", "2001:db8:ffff::10", 5405, "lo"),
	}
	type answer struct {
		route MatchedRoute
		err   error
		taken TakenRule
	}
	read := func(p packet) answer {
		t.Helper()
		var src netip.Addr
		if p.src != "" {
			src = addr(p.src)
		}
		dst := addr(p.dst)
		route, err := RouteGet(src, dst, p.iif)
		rules, dumpErr := DumpRules()
		if dumpErr != nil {
			t.Fatalf("dump the rules: %v", dumpErr)
		}
		return answer{route: route, err: err, taken: TakeRule(rules, src, dst, p.iif, route, err)}
	}
	check := func(p packet) {
		got := read(p)
		if p.priority == 0 {
			if !errors.Is(got.err, p.errno) || got.taken.Found || got.taken.RouteType != p.routeType {
				t.Errorf("%s: answered %+v, want %v and no rule with a route type of %s", p.name, got, p.errno, p.routeType)
			}
			return
		}
		if !got.taken.Found || got.taken.Rule.Priority != p.priority || got.taken.Rule.IIF != p.ruleIIF {
			t.Errorf("%s: answered %+v, want the rule at priority %d iif %q", p.name, got, p.priority, p.ruleIIF)
			return
		}
		lab.without(t, got.taken.Rule, func() {
			after := read(p)
			moved := !sameRoute(after.route, got.route) || !sameError(after.err, got.err)
			switch {
			case p.shadowed && (moved || !after.taken.Found || after.taken.Rule.Priority != 5440):
				t.Errorf("%s: without %+v answered %+v, want the answer kept and 5440 named", p.name, got.taken.Rule, after)
			case !p.shadowed && !moved:
				t.Errorf("%s: without %+v the kernel still answered %+v", p.name, got.taken.Rule, after)
			}
		})
	}
	for _, p := range modeOff {
		check(p)
	}
	writeBatchSysctl(t, "ipv4/conf/lan0/forwarding", "0")
	check(packet{name: "a link arrival with forwarding off", src: "198.51.100.140", dst: "203.0.113.200", iif: "lan0", routeType: "unreachable", errno: unix.EHOSTUNREACH})
	writeBatchSysctl(t, "ipv4/conf/lan0/forwarding", "1")
	writeBatchSysctl(t, "ipv4/conf/lan0/rp_filter", "1")
	check(packet{name: "a link arrival from a forged source", src: "203.0.113.50", dst: "203.0.113.200", iif: "lan0", routeType: "blackhole", errno: unix.EINVAL})
	writeBatchSysctl(t, "ipv4/conf/lan0/rp_filter", "0")

	for _, rule := range takenRules(true) {
		if rule.Priority == 5405 || rule.Priority == 5435 || rule.Priority == 5440 {
			lab.install(t, rule)
		}
	}
	for _, p := range modeTwo {
		check(p)
	}
}

// While a namespace holds the kernel's three rules alone, IPv4 keeps local and
// main in one trie and answers a local route from main. The first rule added
// splits the trie (fib_unmerge), and deleting it does not merge it again, so
// the kernel then answers the route from local. The finder names the lookup of
// local at 0 for both answers.
func TestNetlinkRouteGetNamesLocalForALocalRouteOfOneTrie(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("the real netlink path needs root on linux")
	}
	enterThrowawayNamespace(t)
	conn, err := dialNetlink()
	if err != nil {
		t.Fatalf("dial rtnetlink: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	requireEmptyNamespace(t, conn)
	if err := createLink(conn, "up0", "dummy"); err != nil {
		t.Fatalf("create the dummy up0: %v", err)
	}
	link, err := conn.link(0, "up0")
	if err != nil {
		t.Fatalf("look up up0: %v", err)
	}
	setLinkFlags(t, conn, link.index, unix.IFF_UP)
	local := prefix("198.51.100.2/32")
	writeBatchAddress(t, conn, link.index, local)
	read := func(step string, table uint32) {
		t.Helper()
		route, err := RouteGet(netip.Addr{}, local.Addr(), "")
		rules, dumpErr := DumpRules()
		if dumpErr != nil {
			t.Fatalf("dump the rules: %v", dumpErr)
		}
		taken := TakeRule(rules, netip.Addr{}, local.Addr(), "", route, err)
		t.Logf("%s: the kernel answered %+v %v over %d rules, and the finder %+v", step, route, err, len(rules), taken)
		if err != nil || route.Prefix != local || route.Type != "local" || route.Table != table || !taken.Found || taken.Rule.Priority != 0 {
			t.Errorf("%s: the kernel answered %+v %v and the finder %+v, want the local route in table %d and the rule at 0", step, route, err, taken, table)
		}
	}
	read("one trie", unix.RT_TABLE_MAIN)
	lab := &takenLab{conn: conn}
	split := DumpedRule{Family: FamilyIPv4, Priority: 5000, Action: "lookup", Table: 7, Protocol: 99}
	lab.install(t, split)
	lab.without(t, split, func() { read("the trie split and the rule that split it deleted", unix.RT_TABLE_LOCAL) })
}

// Under RTM_F_FIB_MATCH IPv4 answers EHOSTUNREACH for a route the kernel
// makes with no table entry behind it: this host's own multicast from a held
// source, its packet to 0.0.0.0 and an arrival to the limited broadcast on a
// link whose forwarding is off. RouteGet answers each with that route, and
// the finder names no rule for it. A table's unreachable route and an arrival
// the link's forwarding refuses keep EHOSTUNREACH, the route type naming the
// unreachable route.
func TestNetlinkRouteGetAnswersARouteOfNoTableEntryAsTheKernelsOwn(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("the real netlink path needs root on linux")
	}
	enterThrowawayNamespace(t)
	conn, err := dialNetlink()
	if err != nil {
		t.Fatalf("dial rtnetlink: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	requireEmptyNamespace(t, conn)
	if err := createLink(conn, "up0", "dummy"); err != nil {
		t.Fatalf("create the dummy up0: %v", err)
	}
	up, err := conn.link(0, "up0")
	if err != nil {
		t.Fatalf("look up up0: %v", err)
	}
	setLinkFlags(t, conn, up.index, unix.IFF_UP)
	held := prefix("198.51.100.2/24")
	writeBatchAddress(t, conn, up.index, held)
	writeBatchSysctl(t, "ipv4/conf/up0/forwarding", "0")
	unreachable := prefix("203.0.113.64/27")
	body := make([]byte, unix.SizeofRtMsg)
	body[0], body[1], body[4], body[5], body[6], body[7] = unix.AF_INET, uint8(unreachable.Bits()), unix.RT_TABLE_MAIN, unix.RTPROT_STATIC, unix.RT_SCOPE_UNIVERSE, unix.RTN_UNREACHABLE
	body = putAttr(body, unix.RTA_DST, addressBytes(unreachable.Addr()))
	if _, err := conn.execute(unix.RTM_NEWROUTE, unix.NLM_F_CREATE|unix.NLM_F_EXCL|unix.NLM_F_ACK, body); err != nil {
		t.Fatalf("install the unreachable route to %s: %v", unreachable, err)
	}
	rules, err := DumpRules()
	if err != nil {
		t.Fatalf("dump the rules: %v", err)
	}
	for _, c := range []struct {
		name     string
		src, dst netip.Addr
		iif      string
		// kind and device are the route's type and next hop, empty for one
		// refused with EHOSTUNREACH
		kind, device string
	}{
		{"own multicast from a held source", held.Addr(), addr("224.0.0.251"), "", "multicast", "up0"},
		{"own to the unspecified address", netip.Addr{}, netip.IPv4Unspecified(), "", "local", "lo"},
		{"an arrival to the limited broadcast", addr("198.51.100.9"), addr("255.255.255.255"), "up0", "broadcast", "lo"},
		{"own to an unreachable route", netip.Addr{}, addr("203.0.113.70"), "", "", ""},
		{"an arrival the link's forwarding refuses", addr("198.51.100.9"), addr("203.0.113.200"), "up0", "", ""},
	} {
		var arrival uint32
		if c.iif != "" {
			arrival = up.index
		}
		_, _, matchErr := matchedRoute(conn, c.src, c.dst, arrival, 0, 0)
		route, err := RouteGet(c.src, c.dst, c.iif)
		taken := TakeRule(rules, c.src, c.dst, c.iif, route, err)
		t.Logf("%s: under RTM_F_FIB_MATCH the kernel answered %v, and RouteGet %+v %v, the finder %+v", c.name, matchErr, route, err, taken)
		if !errors.Is(matchErr, unix.EHOSTUNREACH) {
			t.Errorf("%s: under RTM_F_FIB_MATCH the kernel answered %v, want EHOSTUNREACH", c.name, matchErr)
		}
		if c.kind == "" {
			if !errors.Is(err, unix.EHOSTUNREACH) || route.NoEntry || taken.Found || taken.RouteType != "unreachable" {
				t.Errorf("%s: RouteGet answered %+v %v and the finder %+v, want EHOSTUNREACH of an unreachable route", c.name, route, err, taken)
			}
			continue
		}
		single := netip.PrefixFrom(c.dst, 32)
		if err != nil || !route.NoEntry || route.Prefix != single || route.Type != c.kind || route.Table != 0 || route.Source.IsValid() ||
			len(route.NextHops) != 1 || route.NextHops[0].Device != c.device {
			t.Errorf("%s: RouteGet answered %+v %v, want the %s route %s by %s of no table entry", c.name, route, err, c.kind, single, c.device)
		}
		if taken.Found || len(taken.Unread) != 0 || taken.RouteType != "" {
			t.Errorf("%s: the finder answered %+v for a route of no table entry, want nothing", c.name, taken)
		}
	}
}

// takenTUN opens a tun named name and returns its descriptor
func takenTUN(t *testing.T, name string) int {
	t.Helper()
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Skipf("no /dev/net/tun: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		t.Fatalf("build an ifreq for %s: %v", name, err)
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		t.Fatalf("create tun %s: %v", name, err)
	}
	return fd
}

// takenICMPv6 is an IPv6 packet from src to dst carrying message, an ICMPv6
// message whose checksum it fills in
func takenICMPv6(src, dst netip.Addr, message []byte) []byte {
	packet := make([]byte, 40, 40+len(message))
	packet[0], packet[6], packet[7] = 0x60, unix.IPPROTO_ICMPV6, 64
	binary.BigEndian.PutUint16(packet[4:], uint16(len(message)))
	s, d := src.As16(), dst.As16()
	copy(packet[8:], s[:])
	copy(packet[24:], d[:])
	message = slices.Clone(message)
	binary.BigEndian.PutUint16(message[2:], 0)
	// the pseudo-header's addresses, length and next header, then the message
	sum := uint32(len(message)) + unix.IPPROTO_ICMPV6
	for _, b := range [][]byte{s[:], d[:], message} {
		for i := 0; i < len(b); i += 2 {
			word := uint32(b[i]) << 8
			if i+1 < len(b) {
				word |= uint32(b[i+1])
			}
			sum += word
		}
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	binary.BigEndian.PutUint16(message[2:], ^uint16(sum))
	return append(packet, message...)
}

// IPv6's suppress_prefixlength meets the route the lookup returns, which for
// an exception the kernel cached for one destination is a /128, while
// RTM_F_FIB_MATCH answers the route the exception hangs off. A packet too big
// from the uplink's router makes a PMTU exception under main's default for
// 2001:db8:ffff::10. Behind `lookup main suppress_prefixlength 0` at 100 and
// `lookup 100` at 200, the kernel takes 100 for that destination, and the
// finder names it, deleting it moving the answer to table 100. A destination
// with no exception is answered from table 100 by 200.
func TestNetlinkRouteGetNamesTheRuleAnExceptionTook(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("the real netlink path needs root on linux")
	}
	enterThrowawayNamespace(t)
	conn, err := dialNetlink()
	if err != nil {
		t.Fatalf("dial rtnetlink: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	requireEmptyNamespace(t, conn)
	fd := takenTUN(t, "up0")
	if err := createLink(conn, "mesh0", "dummy"); err != nil {
		t.Fatalf("create mesh0: %v", err)
	}
	index := map[string]uint32{}
	for _, name := range []string{"up0", "mesh0"} {
		link, err := conn.link(0, name)
		if err != nil {
			t.Fatalf("look up %s: %v", name, err)
		}
		setLinkFlags(t, conn, link.index, unix.IFF_UP)
		index[name] = link.index
	}
	local, router := addr("2001:db8:1::2"), addr("2001:db8:1::1")
	writeBatchAddress(t, conn, index["up0"], prefix("2001:db8:1::2/64"))
	writeBatchAddress(t, conn, index["mesh0"], prefix("3fff::1/128"))
	writeBatchRoute(t, conn, unix.RT_TABLE_MAIN, prefix("::/0"), batchHop{index: index["up0"], gateway: router})
	writeBatchRoute(t, conn, takenTable, prefix("::/0"), batchHop{index: index["mesh0"]})

	excepted, plain := addr("2001:db8:ffff::10"), addr("2001:db8:ffff::20")
	// a packet too big, type 2, quoting an echo request, type 128, this host
	// sent to excepted, which icmpv6_err hands to ip6_update_pmtu with no socket
	echo := takenICMPv6(local, excepted, []byte{128, 0, 0, 0, 0, 1, 0, 1})
	tooBig := append([]byte{2, 0, 0, 0}, binary.BigEndian.AppendUint32(nil, 1280)...)
	var route MatchedRoute
	for deadline := time.Now().Add(takenWait); !route.Exception && time.Now().Before(deadline); time.Sleep(takenPoll) {
		// the address has no host route until addrconf's queued work ends its
		// DAD, on a link of no DAD too (addrconf_dad_begin), so the packet goes
		// again until one lands
		if _, err := unix.Write(fd, takenICMPv6(router, local, append(tooBig, echo...))); err != nil {
			t.Fatalf("write the packet too big into up0: %v", err)
		}
		if route, err = RouteGet(netip.Addr{}, excepted, ""); err != nil {
			t.Fatalf("look up %s: %v", excepted, err)
		}
	}
	if !route.Exception {
		t.Fatalf("no exception for %s within %s: %+v", excepted, takenWait, route)
	}

	suppressing := DumpedRule{Family: FamilyIPv6, Priority: 100, Action: "lookup", Table: uint32(schema.TableMain), Suppress: SuppressUpTo(0), Protocol: 99}
	lab := &takenLab{conn: conn}
	lab.install(t, suppressing)
	lab.install(t, DumpedRule{Family: FamilyIPv6, Priority: 200, Action: "lookup", Table: takenTable, Protocol: 99})
	for _, c := range []struct {
		dst       netip.Addr
		exception bool
		table     uint32
		priority  uint32
	}{{excepted, true, unix.RT_TABLE_MAIN, 100}, {plain, false, takenTable, 200}} {
		route, err := RouteGet(netip.Addr{}, c.dst, "")
		rules, dumpErr := DumpRules()
		if dumpErr != nil {
			t.Fatalf("dump the rules: %v", dumpErr)
		}
		taken := TakeRule(rules, netip.Addr{}, c.dst, "", route, err)
		if err != nil || route.Exception != c.exception || route.Table != c.table || !taken.Found || taken.Rule.Priority != c.priority {
			t.Errorf("%s: the kernel answered %+v %v and the finder %+v, want table %d, the exception %v and the rule at %d", c.dst, route, err, taken, c.table, c.exception, c.priority)
		}
	}
	lab.without(t, suppressing, func() {
		if route, err := RouteGet(netip.Addr{}, excepted, ""); err != nil || route.Table != takenTable {
			t.Errorf("without the rule at 100 the kernel answered %+v %v for %s, want table %d", route, err, excepted, takenTable)
		}
	})
}

// A check outside the walk raises the errno a terminal rule answers too:
// ENETUNREACH for this host's packet from a source it does not hold, the
// unreachable rule's, and reverse path filtering's EINVAL for an arrival, the
// blackhole rule's. With a source the host holds and with rp_filter 0 the
// walk ends at main ahead of both rules. The finder names each rule as a
// candidate only, and deleting it leaves the errno, the walk never having
// reached it.
func TestNetlinkRouteGetNamesACandidateForAnErrnoRaisedOutsideTheWalk(t *testing.T) {
	lab := openTakenLab(t)
	internet := addr("203.0.113.200")
	read := func(src netip.Addr, iif string) (TakenRule, error) {
		t.Helper()
		route, err := RouteGet(src, internet, iif)
		rules, dumpErr := DumpRules()
		if dumpErr != nil {
			t.Fatalf("dump the rules: %v", dumpErr)
		}
		return TakeRule(rules, src, internet, iif, route, err), err
	}
	for _, c := range []struct {
		name          string
		rule          DumpedRule
		src, reaching netip.Addr
		iif           string
		errno         syscall.Errno
	}{
		{"this host's packet from a source it does not hold", DumpedRule{Family: FamilyIPv4, Priority: 40001, To: prefix("203.0.113.0/24"), Action: "unreachable", Protocol: 99},
			addr("198.51.100.99"), addr("198.51.100.2"), "", syscall.ENETUNREACH},
		{"an arrival reverse path filtering refuses", DumpedRule{Family: FamilyIPv4, Priority: 40000, To: prefix("203.0.113.0/24"), Action: "blackhole", Protocol: 99},
			addr("203.0.113.50"), addr("203.0.113.50"), "lan0", syscall.EINVAL},
	} {
		lab.install(t, c.rule)
		if taken, err := read(c.reaching, c.iif); err != nil || taken.Rule.Priority != 32766 {
			t.Fatalf("%s: from %s the kernel answered %v and the finder %+v, want main at 32766 ahead of the rule at %d", c.name, c.reaching, err, taken, c.rule.Priority)
		}
		if c.iif != "" {
			writeBatchSysctl(t, "ipv4/conf/"+c.iif+"/rp_filter", "1")
		}
		taken, err := read(c.src, c.iif)
		if !errors.Is(err, c.errno) || !taken.Found || !taken.Candidate || taken.Rule.Priority != c.rule.Priority {
			t.Errorf("%s: the kernel answered %v and the finder %+v, want %v and the rule at %d as a candidate", c.name, err, taken, c.errno, c.rule.Priority)
		}
		lab.without(t, c.rule, func() {
			if _, err := read(c.src, c.iif); !errors.Is(err, c.errno) {
				t.Errorf("%s: without the rule at %d the kernel answered %v, want %v still", c.name, c.rule.Priority, err, c.errno)
			}
		})
		if c.iif != "" {
			writeBatchSysctl(t, "ipv4/conf/"+c.iif+"/rp_filter", "0")
		}
	}
}

// The kernel inverts a selector the finder does not read with the rest. A
// route lookup asks for ipproto udp, so `not ipproto tcp lookup 77` takes each
// packet, and the finder lists it, its match being the unread selector's.
// `not to 198.51.100.0/24 ipproto tcp lookup 77` takes a packet to elsewhere
// whatever its protocol, and the finder names it. Deleting either moves the
// answer out of table 77.
func TestNetlinkRouteGetWalksAnInvertedRuleOfASelectorItDoesNotRead(t *testing.T) {
	lab := openTakenLab(t)
	up, err := lab.conn.link(0, "up0")
	if err != nil {
		t.Fatalf("look up up0: %v", err)
	}
	writeBatchRoute(t, lab.conn, 77, prefix("203.0.113.0/24"), batchHop{index: up.index, gateway: addr("198.51.100.1")})
	dst := addr("203.0.113.200")
	packets := []struct {
		name string
		src  netip.Addr
		iif  string
	}{{"own", netip.Addr{}, ""}, {"arrival", addr("198.51.100.140"), "lan0"}}
	for _, c := range []struct {
		name   string
		to     netip.Prefix
		listed bool
	}{{"not ipproto tcp lookup 77", netip.Prefix{}, true}, {"not to 198.51.100.0/24 ipproto tcp lookup 77", prefix("198.51.100.0/24"), false}} {
		body := (&netlinkPlatform{table: Table{Proto: 99}}).ruleMessage(Rule{Family: FamilyIPv4, Priority: 100, To: schema.PrefixFrom(c.to), Table: 77, invert: true})
		body = putAttr(body, unix.FRA_IP_PROTO, []byte{unix.IPPROTO_TCP})
		if _, err := lab.conn.execute(unix.RTM_NEWRULE, unix.NLM_F_CREATE|unix.NLM_F_EXCL|unix.NLM_F_ACK, body); err != nil {
			t.Fatalf("install %s: %v", c.name, err)
		}
		for _, p := range packets {
			route, routeErr := RouteGet(p.src, dst, p.iif)
			rules, err := DumpRules()
			if err != nil {
				t.Fatalf("dump the rules: %v", err)
			}
			taken := TakeRule(rules, p.src, dst, p.iif, route, routeErr)
			if routeErr != nil || route.Table != 77 {
				t.Fatalf("%s, %s: the kernel answered %+v %v, want table 77", c.name, p.name, route, routeErr)
			}
			listed := len(taken.Unread) == 1 && taken.Unread[0].Priority == 100 && taken.Unread[0].Invert
			named := taken.Found && taken.Rule.Priority == 100
			if c.listed && (!listed || taken.Found) || !c.listed && (!named || len(taken.Unread) != 0) {
				t.Errorf("%s, %s: the finder answered %+v, want the rule at 100 listed %v and named %v", c.name, p.name, taken, c.listed, !c.listed)
			}
		}
		if _, err := lab.conn.execute(unix.RTM_DELRULE, unix.NLM_F_ACK, body); err != nil {
			t.Fatalf("delete %s: %v", c.name, err)
		}
		if route, err := RouteGet(netip.Addr{}, dst, ""); err != nil || route.Table == 77 {
			t.Errorf("without %s the kernel answered %+v %v, still from table 77", c.name, route, err)
		}
	}
}
