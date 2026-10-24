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
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// the lab's devices: a dummy standing for the tun, an uplink, a second uplink
// taken down once its routes are in, which leaves each hop through it dead,
// and a third whose carrier is cut, which leaves each hop through it link-down
// and still taken by the lookup
const (
	batchTUN      = "batch0"
	batchUplink   = "batch1"
	batchDead     = "batch2"
	batchLinkDown = "batch3"
)

// batchTable is the table the lab's iif rule, at batchRulePriority, gives a
// packet arriving on the tun's stand-in. batchPrefixes is the test's count of
// prefixes a family, and batchSweepPrefixes the benchmark's
const (
	batchTable         = 1000
	batchRulePriority  = 100
	batchPrefixes      = 50
	batchSweepPrefixes = 500
)

// the ways the lab routes a family's prefixes, the i-th taking kind i modulo
// batchKinds
const (
	// main, through the uplink's gateway
	batchKindUplink = iota
	// the iif rule's table, through the uplink's gateway
	batchKindTable
	// main, through the dead uplink's gateway and then the uplink's
	batchKindDeadHop
	// main, back into the tun's stand-in
	batchKindBack
	// no route
	batchKindUnrouted
	// main, through the link-down device alone
	batchKindLinkDown
	batchKinds
)

// batchFamily is one family's addresses in the lab. Its member prefix is
// routed back into the tun's stand-in, and a member's address is the source
// of each read
type batchFamily struct {
	member               netip.Prefix
	source               netip.Addr
	uplink, dead         netip.Prefix
	gateway, deadGateway netip.Addr
	prefix               func(i int) netip.Prefix
}

var batchFamilies = []batchFamily{
	{
		member: netip.MustParsePrefix("192.0.2.0/26"), source: netip.MustParseAddr("192.0.2.1"),
		uplink: netip.MustParsePrefix("192.0.2.65/26"), gateway: netip.MustParseAddr("192.0.2.66"),
		dead: netip.MustParsePrefix("192.0.2.129/26"), deadGateway: netip.MustParseAddr("192.0.2.130"),
		// host routes, since the rest of IPv4's documentation space holds
		// batchSweepPrefixes of no wider length
		prefix: func(i int) netip.Prefix {
			address := [4]byte{203, 0, 113, byte(i)}
			if i > 0xff {
				address = [4]byte{198, 51, 100, byte(i - 0x100)}
			}
			return netip.PrefixFrom(netip.AddrFrom4(address), 32)
		},
	},
	{
		member: netip.MustParsePrefix("3fff:20::/32"), source: netip.MustParseAddr("3fff:20::1"),
		uplink: netip.MustParsePrefix("2001:db8:f::1/64"), gateway: netip.MustParseAddr("2001:db8:f::2"),
		dead: netip.MustParsePrefix("2001:db8:e::1/64"), deadGateway: netip.MustParseAddr("2001:db8:e::2"),
		prefix: func(i int) netip.Prefix {
			return netip.PrefixFrom(netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0x01, 0x00, byte(i >> 8), byte(i)}), 64)
		},
	},
}

// destination is the address the lab reads in its i-th prefix
func (f batchFamily) destination(i int) netip.Addr {
	prefix := f.prefix(i)
	if prefix.IsSingleIP() {
		return prefix.Addr()
	}
	return prefix.Addr().Next()
}

// reads is the family's sweep of its first prefixes, each read arriving on the
// tun's stand-in and asking for its reply where reply says
func (f batchFamily) reads(prefixes int, reply func(i int) bool) []RouteRead {
	reads := make([]RouteRead, prefixes)
	for i := range reads {
		reads[i] = RouteRead{Source: f.source, Destination: f.destination(i), IIF: batchTUN, Reply: reply(i)}
	}
	return reads
}

// want is the route the family's i-th prefix answers by its kind, its hops in
// device order, and the device its reply read arrives on, empty where none is
// made
func (f batchFamily) want(i int) (MatchedRoute, string) {
	route := MatchedRoute{Prefix: f.prefix(i), Table: unix.RT_TABLE_MAIN, Type: "unicast"}
	uplink := NextHop{Device: batchUplink, Gateway: f.gateway}
	switch i % batchKinds {
	case batchKindUplink:
		route.NextHops = []NextHop{uplink}
		return route, batchUplink
	case batchKindTable:
		route.Table, route.NextHops = batchTable, []NextHop{uplink}
		return route, batchUplink
	case batchKindDeadHop:
		route.NextHops = []NextHop{uplink, {Device: batchDead, Gateway: f.deadGateway, Dead: true, LinkDown: true}}
		return route, batchUplink
	case batchKindBack:
		route.NextHops = []NextHop{{Device: batchTUN}}
		return route, batchTUN
	case batchKindLinkDown:
		route.NextHops = []NextHop{{Device: batchLinkDown, LinkDown: true}}
	}
	return route, ""
}

// openBatchLab enters a namespace of its own and builds the lab there, each
// family's first prefixes routed by their kinds
func openBatchLab(tb testing.TB, prefixes int) {
	tb.Helper()
	if os.Getuid() != 0 {
		tb.Skip("the real netlink path needs root on linux")
	}
	enterThrowawayNamespace(tb)
	conn, err := dialNetlink()
	if err != nil {
		tb.Fatalf("dial rtnetlink: %v", err)
	}
	tb.Cleanup(func() { _ = conn.Close() })
	requireEmptyNamespace(tb, conn)
	// a new namespace takes its IPv4 settings from the host's, reverse path
	// filtering and the lookup's skipping of a link-down hop among them
	for _, setting := range []string{"rp_filter", "ignore_routes_with_linkdown"} {
		writeBatchSysctl(tb, "ipv4/conf/all/"+setting, "0")
		writeBatchSysctl(tb, "ipv4/conf/default/"+setting, "0")
	}
	index := make(map[string]uint32)
	for _, name := range []string{batchTUN, batchUplink, batchDead, batchLinkDown} {
		if err := createLink(conn, name, "dummy", nil); err != nil {
			tb.Fatalf("create the dummy %s: %v", name, err)
		}
		link, err := conn.link(0, name)
		if err != nil {
			tb.Fatalf("look up %s: %v", name, err)
		}
		setLinkFlags(tb, conn, link.index, unix.IFF_UP)
		index[name] = link.index
	}
	writeBatchSysctl(tb, "ipv4/ip_forward", "1")
	writeBatchSysctl(tb, "ipv6/conf/all/forwarding", "1")
	tun, uplink, dead, linkDown := index[batchTUN], index[batchUplink], index[batchDead], index[batchLinkDown]
	for _, f := range batchFamilies {
		writeBatchAddress(tb, conn, uplink, f.uplink)
		writeBatchAddress(tb, conn, dead, f.dead)
		writeBatchRule(tb, conn, f.member.Addr())
		writeBatchRoute(tb, conn, unix.RT_TABLE_MAIN, f.member, batchHop{index: tun})
		for i := range prefixes {
			switch prefix := f.prefix(i); i % batchKinds {
			case batchKindUplink:
				writeBatchRoute(tb, conn, unix.RT_TABLE_MAIN, prefix, batchHop{uplink, f.gateway})
			case batchKindTable:
				writeBatchRoute(tb, conn, batchTable, prefix, batchHop{uplink, f.gateway})
			case batchKindDeadHop:
				writeBatchRoute(tb, conn, unix.RT_TABLE_MAIN, prefix, batchHop{dead, f.deadGateway}, batchHop{uplink, f.gateway})
			case batchKindBack:
				writeBatchRoute(tb, conn, unix.RT_TABLE_MAIN, prefix, batchHop{index: tun})
			case batchKindLinkDown:
				writeBatchRoute(tb, conn, unix.RT_TABLE_MAIN, prefix, batchHop{index: linkDown})
			}
		}
	}
	changeBatchLink(tb, conn, dead, unix.IFF_UP, nil)
	changeBatchLink(tb, conn, linkDown, 0, putAttr(nil, unix.IFLA_CARRIER, []byte{0}))
	// the link watch marks a hop link-down after the carrier change is answered
	waitFor(tb, func() bool {
		for _, f := range batchFamilies {
			route, err := RouteGet(f.source, f.destination(batchKindLinkDown), batchTUN)
			if err != nil || len(route.NextHops) != 1 || !route.NextHops[0].LinkDown {
				return false
			}
		}
		return true
	})
}

func writeBatchSysctl(tb testing.TB, path, value string) {
	tb.Helper()
	if err := os.WriteFile("/proc/sys/net/"+path, []byte(value), 0); err != nil {
		tb.Fatalf("set %s to %s: %v", path, value, err)
	}
}

func writeBatchAddress(tb testing.TB, conn *nlConn, index uint32, address netip.Prefix) {
	tb.Helper()
	body := (&netlinkPlatform{index: index}).addrMessage(address)
	if _, err := conn.execute(unix.RTM_NEWADDR, unix.NLM_F_CREATE|unix.NLM_F_EXCL|unix.NLM_F_ACK, body); err != nil {
		tb.Fatalf("assign %s: %v", address, err)
	}
}

// writeBatchRule gives a packet of family's family arriving on the tun's
// stand-in batchTable
func writeBatchRule(tb testing.TB, conn *nlConn, family netip.Addr) {
	tb.Helper()
	rule := Rule{Family: FamilyIPv6, IIF: batchTUN, Table: batchTable, Priority: batchRulePriority}
	if family.Is4() {
		rule.Family = FamilyIPv4
	}
	body := (&netlinkPlatform{table: Table{Proto: unix.RTPROT_STATIC}}).ruleMessage(rule)
	if _, err := conn.execute(unix.RTM_NEWRULE, unix.NLM_F_CREATE|unix.NLM_F_EXCL|unix.NLM_F_ACK, body); err != nil {
		tb.Fatalf("install the rule from %s to table %d: %v", batchTUN, batchTable, err)
	}
}

// batchHop is a next hop of a lab route, through gateway where it is valid
type batchHop struct {
	index   uint32
	gateway netip.Addr
}

// writeBatchRoute installs a unicast route to destination in table, one of
// several hops as a multipath route
func writeBatchRoute(tb testing.TB, conn *nlConn, table uint32, destination netip.Prefix, hops ...batchHop) {
	tb.Helper()
	body := make([]byte, unix.SizeofRtMsg)
	body[0], body[6] = unix.AF_INET6, unix.RT_SCOPE_UNIVERSE
	if destination.Addr().Is4() {
		body[0] = unix.AF_INET
		if !hops[0].gateway.IsValid() {
			// fib_check_nh takes an IPv4 route out of a device with no
			// gateway at link scope, as routeMessage writes it
			body[6] = unix.RT_SCOPE_LINK
		}
	}
	body[1], body[5], body[7] = uint8(destination.Bits()), unix.RTPROT_STATIC, unix.RTN_UNICAST
	body = putAttrU32(body, unix.RTA_TABLE, table)
	body = putAttr(body, unix.RTA_DST, addressBytes(destination.Addr()))
	if len(hops) == 1 {
		body = putAttrU32(body, unix.RTA_OIF, hops[0].index)
		if hops[0].gateway.IsValid() {
			body = putAttr(body, unix.RTA_GATEWAY, addressBytes(hops[0].gateway))
		}
	} else {
		var multipath []byte
		for _, hop := range hops {
			nexthop := make([]byte, unix.SizeofRtNexthop)
			binary.NativeEndian.PutUint32(nexthop[4:], hop.index)
			nexthop = putAttr(nexthop, unix.RTA_GATEWAY, addressBytes(hop.gateway))
			binary.NativeEndian.PutUint16(nexthop, uint16(len(nexthop)))
			multipath = append(multipath, nexthop...)
		}
		body = putAttr(body, unix.RTA_MULTIPATH, multipath)
	}
	if _, err := conn.execute(unix.RTM_NEWROUTE, unix.NLM_F_CREATE|unix.NLM_F_EXCL|unix.NLM_F_ACK, body); err != nil {
		tb.Fatalf("install the route to %s in table %d: %v", destination, table, err)
	}
}

// changeBatchLink clears the flags of clear on a device and sets its
// attributes
func changeBatchLink(tb testing.TB, conn *nlConn, index, clear uint32, attributes []byte) {
	tb.Helper()
	body := make([]byte, unix.SizeofIfInfomsg)
	binary.NativeEndian.PutUint32(body[4:], index)
	binary.NativeEndian.PutUint32(body[12:], clear)
	if _, err := conn.execute(unix.RTM_NEWLINK, unix.NLM_F_ACK, append(body, attributes...)); err != nil {
		tb.Fatalf("change link %d: %v", index, err)
	}
}

func sameRoute(got, want MatchedRoute) bool {
	return got.Prefix == want.Prefix && got.Source == want.Source && got.Table == want.Table &&
		got.Type == want.Type && slices.Equal(got.NextHops, want.NextHops)
}

func sameError(got, want error) bool {
	return (got == nil) == (want == nil) && (got == nil || got.Error() == want.Error())
}

// inDeviceOrder is route with its hops ordered by device, since IPv6 answers a
// multipath route's hop it selects first
func inDeviceOrder(route MatchedRoute) MatchedRoute {
	route.NextHops = slices.SortedFunc(slices.Values(route.NextHops), func(a, b NextHop) int { return strings.Compare(a.Device, b.Device) })
	return route
}

// ownError is whether err is the batch's own, an error no kernel answered
func ownError(err error) bool {
	var errno syscall.Errno
	return err != nil && !errors.As(err, &errno)
}

// A batch answers each read of a sweep as RouteGet does: through main, through
// the table an iif rule gives the arrival device, past a dead hop, back into the
// tun's stand-in, through a link-down hop alone and where nothing routes. A
// read's reply arrives on its route's first live hop, and a read whose lookup
// failed or whose route has no live hop gives its reply read an error of its
// own. A refused read and this host's own packet are answered beside the
// others, and an arrival device nothing holds fails the batch whole
func TestNetlinkRouteGetBatchAnswersEachReadAsRouteGetDoes(t *testing.T) {
	openBatchLab(t, batchPrefixes)
	var reads []RouteRead
	for _, f := range batchFamilies {
		reads = append(reads, f.reads(batchPrefixes, func(int) bool { return true })...)
	}
	v4, v6 := batchFamilies[0], batchFamilies[1]
	others := []RouteRead{
		{Source: v4.source, Destination: v6.source, IIF: batchTUN},
		{IIF: batchTUN, Reply: true},
		{Destination: v4.gateway, Reply: true},
	}
	all := append(slices.Clone(reads), others...)
	answers, err := RouteGetBatch(all)
	if err != nil || len(answers) != len(all) {
		t.Fatalf("the batch answered %d of %d reads and %v", len(answers), len(all), err)
	}

	for n, f := range batchFamilies {
		reply := MatchedRoute{Prefix: f.member, Table: unix.RT_TABLE_MAIN, Type: "unicast", NextHops: []NextHop{{Device: batchTUN}}}
		for i := range batchPrefixes {
			read, answer := reads[n*batchPrefixes+i], answers[n*batchPrefixes+i]
			want, arrival := f.want(i)
			switch {
			case i%batchKinds == batchKindUnrouted:
				if !errors.Is(answer.Err, unix.ENETUNREACH) {
					t.Errorf("the read of %s, which nothing routes, answered %+v and %v, want ENETUNREACH", read.Destination, answer.Route, answer.Err)
				}
			case answer.Err != nil || !sameRoute(inDeviceOrder(answer.Route), want):
				t.Errorf("the read of %s answered %+v and %v, want %+v", read.Destination, answer.Route, answer.Err, want)
			}
			switch {
			case answer.ReplyIIF != arrival:
				t.Errorf("the reply read of %s arrived on %q, want %q", read.Destination, answer.ReplyIIF, arrival)
			case arrival == "" && !ownError(answer.ReplyErr):
				t.Errorf("the reply read of %s answered %+v and %v, want an error of its own", read.Destination, answer.Reply, answer.ReplyErr)
			case arrival != "" && (answer.ReplyErr != nil || !sameRoute(answer.Reply, reply)):
				t.Errorf("the reply read of %s answered %+v and %v, want %+v", read.Destination, answer.Reply, answer.ReplyErr, reply)
			}
		}
	}
	mixed, invalid, own := answers[len(reads)], answers[len(reads)+1], answers[len(reads)+2]
	if !ownError(mixed.Err) || !ownError(invalid.Err) || invalid.ReplyIIF != "" || !ownError(invalid.ReplyErr) {
		t.Errorf("the refused reads answered %v, and %v with the reply read %v on %q, want refusals", mixed.Err, invalid.Err, invalid.ReplyErr, invalid.ReplyIIF)
	}
	connected := MatchedRoute{Prefix: v4.uplink.Masked(), Table: unix.RT_TABLE_MAIN, Type: "unicast", NextHops: []NextHop{{Device: batchUplink}}}
	if own.Err != nil || !sameRoute(own.Route, connected) || own.ReplyIIF != batchUplink {
		t.Errorf("this host's own packet answered %+v and %v with its reply on %q, want %+v and %s", own.Route, own.Err, own.ReplyIIF, connected, batchUplink)
	}

	for n, read := range all {
		answer := answers[n]
		if route, err := RouteGet(read.Source, read.Destination, read.IIF); !sameRoute(answer.Route, route) || !sameError(answer.Err, err) {
			t.Errorf("the read of %s from %s on %q answered %+v and %v, where RouteGet answers %+v and %v", read.Destination, read.Source, read.IIF, answer.Route, answer.Err, route, err)
		}
		if answer.ReplyIIF == "" {
			continue
		}
		if route, err := RouteGet(read.Destination, read.Source, answer.ReplyIIF); !sameRoute(answer.Reply, route) || !sameError(answer.ReplyErr, err) {
			t.Errorf("the reply read of %s on %s answered %+v and %v, where RouteGet answers %+v and %v", read.Destination, answer.ReplyIIF, answer.Reply, answer.ReplyErr, route, err)
		}
	}

	const missing = "batch9"
	if answers, err := RouteGetBatch([]RouteRead{{Source: v4.source, Destination: v4.destination(0), IIF: missing}}); answers != nil || !errors.Is(err, unix.ENODEV) {
		t.Errorf("a read arriving on %s, which nothing holds, answered %+v and %v, want the batch failed with ENODEV", missing, answers, err)
	}
}

// A sweep of batchSweepPrefixes prefixes with the reply read of its first,
// in one batch and as RouteGet answers it a read at a time, in each family
func BenchmarkRouteGetBatch(b *testing.B) {
	for n, family := range []string{"IPv4", "IPv6"} {
		sweep := func(b *testing.B) []RouteRead {
			openBatchLab(b, batchSweepPrefixes)
			return batchFamilies[n].reads(batchSweepPrefixes, func(i int) bool { return i == 0 })
		}
		b.Run(family+"/batch", func(b *testing.B) {
			reads := sweep(b)
			for b.Loop() {
				answers, err := RouteGetBatch(reads)
				if err != nil || len(answers) != len(reads) || answers[0].ReplyErr != nil {
					b.Fatalf("the batch answered %d of %d reads and %v", len(answers), len(reads), err)
				}
			}
		})
		b.Run(family+"/RouteGet", func(b *testing.B) {
			reads := sweep(b)
			for b.Loop() {
				for _, read := range reads {
					route, err := RouteGet(read.Source, read.Destination, read.IIF)
					if !read.Reply {
						continue
					}
					live := slices.IndexFunc(route.NextHops, func(hop NextHop) bool { return !hop.Dead && !hop.LinkDown })
					if err != nil || live < 0 {
						b.Fatalf("the read of %s answered %+v and %v", read.Destination, route, err)
					}
					if _, err := RouteGet(read.Destination, read.Source, route.NextHops[live].Device); err != nil {
						b.Fatalf("the reply read of %s answered %v", read.Destination, err)
					}
				}
			}
		})
	}
}
