// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package nftables

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/netlink"
	"ranet3.com/pkgs/ranet3/internal/netnstest"
)

// The tests of this file write into a real kernel, each in a network
// namespace it made itself and refusing any other, and run as root in the
// netlink VM check and under unshare -rn.

// rootWait bounds a wait for a datagram the kernel delivers on loopback at once
const rootWait = 2 * time.Second

// filterSets is named sets of each key the switch writes, an ifname
// and an address of each family, in table, with their elements
func filterSets(table string) ([]Set, map[string][]Interval) {
	sets := []Set{
		{Table: table, Name: "forwarded", ID: 1, KeyType: TypeIfname, KeyLen: unix.IFNAMSIZ},
		{Table: table, Name: "lan4", ID: 2, KeyType: TypeIPv4Addr, KeyLen: 4, Flags: unix.NFT_SET_INTERVAL},
		{Table: table, Name: "lan6", ID: 3, KeyType: TypeIPv6Addr, KeyLen: 16, Flags: unix.NFT_SET_INTERVAL},
	}
	elements := map[string][]Interval{
		"forwarded": {Key(InterfaceName("lan1")), Key(InterfaceName("br0"))},
		"lan4":      Prefixes(prefixList("198.51.100.0/24", "203.0.113.0/25", "192.0.2.128/26")),
		"lan6":      Prefixes(prefixList("2001:db8:a:1::/64", "2001:db8:9::/64")),
	}
	return sets, elements
}

func prefixList(prefixes ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(prefixes))
	for _, p := range prefixes {
		out = append(out, netip.MustParsePrefix(p))
	}
	return out
}

// Each expression acts on the host's own datagrams on loopback as its line
// says: an address lookup in an interval set of each family, before and after
// the set is flushed and filled again, the mark, the input device a host
// packet does not have, an interface name lookup and its inversion, and the
// connection's direction, protocol and original port against a set of ports.
// A drop meets the sender as EPERM.
func TestNftablesFilterExpressionsActOnPackets(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmpty(t)
	conn := dial(t)
	const table = "acts"
	chain := Chain{Table: table, Name: "post", Type: "filter", Hook: unix.NF_INET_POST_ROUTING, Priority: 2147483646}
	set4 := Set{Table: table, Name: "set4", ID: 1, KeyType: TypeIPv4Addr, KeyLen: 4, Flags: unix.NFT_SET_INTERVAL}
	set6 := Set{Table: table, Name: "set6", ID: 2, KeyType: TypeIPv6Addr, KeyLen: 16, Flags: unix.NFT_SET_INTERVAL}
	names := Set{Table: table, Name: "names", ID: 3, KeyType: TypeIfname, KeyLen: unix.IFNAMSIZ}
	var setup []Request
	for _, s := range []Set{set4, set6, names} {
		made, err := s.Create(unix.NFPROTO_INET)
		if err != nil {
			t.Fatal(err)
		}
		setup = append(setup, made)
	}
	setup = append([]Request{NewTable(unix.NFPROTO_INET, table)}, append(setup, chain.Create(unix.NFPROTO_INET))...)
	if err := conn.Batch(setup); err != nil {
		t.Fatalf("make the table: %v", err)
	}
	// write puts rule alone in the chain and refills set, in one transaction
	write := func(set Set, intervals []Interval, rule [][]byte, extra ...Request) {
		t.Helper()
		requests := []Request{chain.Flush(unix.NFPROTO_INET), set.Flush(unix.NFPROTO_INET)}
		filled, err := set.Fill(unix.NFPROTO_INET, intervals)
		if err != nil {
			t.Fatal(err)
		}
		requests = append(append(requests, filled...), extra...)
		written, err := chain.Rule(unix.NFPROTO_INET, "rule", rule)
		if err != nil {
			t.Fatal(err)
		}
		if err := conn.Batch(append(requests, written)); err != nil {
			t.Fatalf("write the rule: %v", err)
		}
	}
	refused := func(what string, err error, want bool) {
		t.Helper()
		if got := errors.Is(err, unix.EPERM); got != want {
			t.Errorf("%s: refused %v (%v), want %v", what, got, err, want)
		}
	}
	to := func(address string) netip.AddrPort { return netip.AddrPortFrom(netip.MustParseAddr(address), 9) }

	daddr4 := slices.Concat(NFProto(unix.NFPROTO_IPV4), [][]byte{DestinationLoad(unix.NFPROTO_IPV4), Lookup(set4, false)}, CountedDrop())
	write(set4, Prefixes(prefixList("127.0.0.0/30")), daddr4)
	refused("ip daddr @set4 { 127.0.0.0/30 } drop, to 127.0.0.2", sendUDP(to("127.0.0.2"), 0), true)
	refused("ip daddr @set4 { 127.0.0.0/30 } drop, to 127.0.0.9", sendUDP(to("127.0.0.9"), 0), false)
	write(set4, Prefixes(prefixList("127.0.0.8/29")), daddr4)
	refused("ip daddr @set4 refilled { 127.0.0.8/29 } drop, to 127.0.0.2", sendUDP(to("127.0.0.2"), 0), false)
	refused("ip daddr @set4 refilled { 127.0.0.8/29 } drop, to 127.0.0.9", sendUDP(to("127.0.0.9"), 0), true)

	daddr6 := slices.Concat(NFProto(unix.NFPROTO_IPV6), [][]byte{DestinationLoad(unix.NFPROTO_IPV6), Lookup(set6, false)}, CountedDrop())
	write(set6, Prefixes(prefixList("::1/128")), daddr6)
	refused("ip6 daddr @set6 { ::1 } drop, to ::1", sendUDP(to("::1"), 0), true)
	write(set6, Prefixes(prefixList("2001:db8::/32")), daddr6)
	refused("ip6 daddr @set6 refilled { 2001:db8::/32 } drop, to ::1", sendUDP(to("::1"), 0), false)

	write(set4, nil, append(MetaCompareValue(unix.NFT_META_MARK, unix.NFT_CMP_EQ, binary.NativeEndian.AppendUint32(nil, 0x72)), CountedDrop()...))
	refused("meta mark 0x72 drop, marked 0x72", sendUDP(to("127.0.0.1"), 0x72), true)
	refused("meta mark 0x72 drop, marked 0x73", sendUDP(to("127.0.0.1"), 0x73), false)
	refused("meta mark 0x72 drop, unmarked", sendUDP(to("127.0.0.1"), 0), false)

	write(set4, nil, append(MetaCompareValue(unix.NFT_META_IIF, unix.NFT_CMP_NEQ, make([]byte, 4)), CountedDrop()...))
	refused("meta iif != 0 drop, the host's own", sendUDP(to("127.0.0.1"), 0), false)

	iifname := func(invert bool) [][]byte {
		return append([][]byte{MetaLoad(unix.NFT_META_IIFNAME), Lookup(names, invert)}, CountedDrop()...)
	}
	write(names, []Interval{Key(InterfaceName("lo"))}, iifname(true))
	refused("iifname != @names { lo } drop, the host's own with no input device", sendUDP(to("127.0.0.1"), 0), true)
	write(names, []Interval{Key(InterfaceName("lo"))}, iifname(false))
	refused("iifname @names { lo } drop, the host's own with no input device", sendUDP(to("127.0.0.1"), 0), false)

	listed, unlisted := listenUDP(t, "127.0.0.1"), listenUDP(t, "127.0.0.1")
	port := func(fd int) uint16 {
		name, err := unix.Getsockname(fd)
		if err != nil {
			t.Fatal(err)
		}
		return uint16(name.(*unix.SockaddrInet4).Port)
	}
	ports := Anonymous(table, 20, TypeInetService, 2, unix.NFT_SET_INTERVAL)
	portSet, err := ports.Create(unix.NFPROTO_INET)
	if err != nil {
		t.Fatal(err)
	}
	portElements, err := ports.Fill(unix.NFPROTO_INET, []Interval{Key(binary.BigEndian.AppendUint16(nil, port(listed)))})
	if err != nil {
		t.Fatal(err)
	}
	write(set4, nil, append([][]byte{
		CTLoad(unix.NFT_CT_DIRECTION), Expression("cmp", Compare(unix.NFT_CMP_EQ, []byte{CTReply})),
		CTLoad(unix.NFT_CT_PROTOCOL), Expression("cmp", Compare(unix.NFT_CMP_EQ, []byte{unix.IPPROTO_UDP})),
		CTLoadDirection(unix.NFT_CT_PROTO_DST, CTOriginal), Lookup(ports, false),
	}, CountedDrop()...), append([]Request{portSet}, portElements...)...)
	for _, c := range []struct {
		name   string
		server int
		reply  bool
	}{{"the listed port", listed, true}, {"another port", unlisted, false}} {
		client := listenUDP(t, "127.0.0.1")
		refused("ct direction reply ct protocol udp ct original proto-dst @ports drop, a datagram to "+c.name, sendFrom(client, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port(c.server))), false)
		peer := receive(t, c.server)
		refused("ct direction reply ct protocol udp ct original proto-dst @ports drop, the reply from "+c.name, unix.Sendto(c.server, []byte("reply"), 0, peer), c.reply)
	}
}

// Another writer's change to a set's elements wakes the owner's monitor and
// reads back as a fault naming the set until the owner fills it again, and
// the owner's own refill wakes nothing
func TestNftablesSetElementsReadBackAndWakeOnAnothersChange(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmptyLoopbackDown(t)
	conn := dial(t)
	const table = Table
	sets, elements := filterSets(table)
	contents := Contents{Sets: sets, Elements: elements}
	monitor, err := OpenMonitor(conn, contents.Scope())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = monitor.Close() })
	write := func() {
		t.Helper()
		requests := []Request{NewTable(unix.NFPROTO_INET, table)}
		for _, s := range sets {
			made, err := s.Create(unix.NFPROTO_INET)
			if err != nil {
				t.Fatal(err)
			}
			filled, err := s.Fill(unix.NFPROTO_INET, elements[s.Name])
			if err != nil {
				t.Fatal(err)
			}
			requests = append(append(requests, made, s.Flush(unix.NFPROTO_INET)), filled...)
		}
		if err := conn.Batch(requests); err != nil {
			t.Fatalf("write the sets: %v", err)
		}
	}
	read := func() string {
		t.Helper()
		tables, err := Tables(conn, table)
		if err != nil {
			t.Fatal(err)
		}
		readback, err := contents.Read(conn, tables, unix.NFPROTO_INET)
		if err != nil {
			t.Fatal(err)
		}
		return readback.Fault
	}
	quiet := func(what string) {
		t.Helper()
		select {
		case <-monitor.Changed():
			t.Fatalf("%s woke the owner", what)
		case <-time.After(rootWait):
		}
	}
	write()
	write()
	quiet("its own write and refill")
	if fault := read(); fault != "" {
		t.Fatalf("the sets read back with the fault %q", fault)
	}

	another := dial(t)
	lan4 := sets[slices.IndexFunc(sets, func(s Set) bool { return s.Name == "lan4" })]
	for _, change := range []struct {
		name    string
		request func() []Request
	}{
		{"added an element", func() []Request {
			added, err := lan4.Fill(unix.NFPROTO_INET, Prefixes(prefixList("192.0.2.0/28")))
			if err != nil {
				t.Fatal(err)
			}
			return added
		}},
		{"flushed a set", func() []Request { return []Request{lan4.Flush(unix.NFPROTO_INET)} }},
	} {
		if err := another.Batch(change.request()); err != nil {
			t.Fatalf("another writer %s: %v", change.name, err)
		}
		select {
		case <-monitor.Changed():
		case <-time.After(rootWait):
			t.Fatalf("another writer %s and the owner was not woken", change.name)
		}
		if fault := read(); !strings.Contains(fault, "its set lan4 holds") {
			t.Errorf("another writer %s and the sets read back with the fault %q, want one naming lan4's elements", change.name, fault)
		}
		write()
		quiet("its own refill after another writer " + change.name)
		if fault := read(); fault != "" {
			t.Errorf("the sets refilled after another writer %s read back with the fault %q", change.name, fault)
		}
	}
}

// Another writer's catchall element, in an interval set and in a set of names,
// has the line reading the set match a key the set does not hold, its element
// carrying a limit of no connections has the line pass a key the set holds,
// and its element carrying two counters, which the kernel dumps as a list of
// expressions, leaves the line as it was. Each wakes the owner's monitor and
// reads back as a fault naming the set, and the owner's fill behind the set's
// flush takes it out, so the line drops as written and the set reads back as
// written. A case runs only where the module of its expression is loaded or
// built in, since sending the expression would load it, and in a namespace of
// its own.
func TestNftablesElementsNoOwnerWritesReadBackUntilTheOwnerFillsAgain(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	chain := Chain{Table: Table, Name: "post", Type: "filter", Hook: unix.NF_INET_POST_ROUTING, Priority: 2147483646}
	lan4 := Set{Table: Table, Name: "lan4", ID: 1, KeyType: TypeIPv4Addr, KeyLen: 4, Flags: unix.NFT_SET_INTERVAL}
	names := Set{Table: Table, Name: "forwarded", ID: 2, KeyType: TypeIfname, KeyLen: unix.IFNAMSIZ}
	elements := func(kind int, set Set, attributes ...[]byte) Request {
		item := netlink.PutAttr(nil, unix.NFTA_LIST_ELEM|unix.NLA_F_NESTED, slices.Concat(attributes...))
		body := netlink.PutAttr(set.elementList(unix.NFPROTO_INET), unix.NFTA_SET_ELEM_LIST_ELEMENTS|unix.NLA_F_NESTED, item)
		return Request{Kind: Command(kind), Flags: unix.NLM_F_CREATE, Body: body}
	}
	// NFT_SET_ELEM_CATCHALL
	catchall := PutAttrBE32(nil, unix.NFTA_SET_ELEM_FLAGS, 0x2)
	start := netlink.PutAttr(nil, unix.NFTA_SET_ELEM_KEY|unix.NLA_F_NESTED, netlink.PutAttr(nil, unix.NFTA_DATA_VALUE, []byte{127, 0, 0, 0}))
	noConnections := netlink.PutAttr(nil, unix.NFTA_SET_ELEM_EXPR|unix.NLA_F_NESTED, expressionBody("connlimit", PutAttrBE32(nil, connlimitCount, 0)))
	// NFTA_SET_ELEM_EXPRESSIONS
	counters := netlink.PutAttr(nil, 11|unix.NLA_F_NESTED, slices.Concat(Expression("counter", nil), Expression("counter", nil)))
	daddr := slices.Concat(NFProto(unix.NFPROTO_IPV4), [][]byte{DestinationLoad(unix.NFPROTO_IPV4), Lookup(lan4, false)}, CountedDrop())
	oifname := append([][]byte{MetaLoad(unix.NFT_META_OIFNAME), Lookup(names, false)}, CountedDrop()...)
	loopback := Prefixes(prefixList("127.0.0.0/30"))
	for _, c := range []struct {
		name string
		// module is the one the change's expression needs, empty for none or one built into nf_tables
		module  string
		set     Set
		written []Interval
		rule    [][]byte
		to      netip.AddrPort
		// before and after are whether the line drops the datagram to to as the
		// owner wrote the set and with the change in place
		before, after bool
		change        []Request
		fault         string
	}{
		{
			"a catchall in an interval set", "", lan4, loopback, daddr, netip.MustParseAddrPort("127.0.0.9:9"), false, true,
			[]Request{elements(unix.NFT_MSG_NEWSETELEM, lan4, catchall)},
			"its set lan4 holds { 0.0.0.0/0 }, where { 127.0.0.0/30 } was written",
		},
		{
			"a catchall in a set of names", "", names, []Interval{Key(InterfaceName("br0"))}, oifname, netip.MustParseAddrPort("127.0.0.1:9"), false, true,
			[]Request{elements(unix.NFT_MSG_NEWSETELEM, names, catchall)},
			"its set forwarded holds { * }, where { br0 } was written",
		},
		{
			"a limit of no connections on a start", "nft_connlimit", lan4, loopback, daddr, netip.MustParseAddrPort("127.0.0.2:9"), true, false,
			[]Request{elements(unix.NFT_MSG_DELSETELEM, lan4, start), elements(unix.NFT_MSG_NEWSETELEM, lan4, start, noConnections)},
			"its set lan4 holds { 127.0.0.0/30, an element's expression }, where { 127.0.0.0/30 } was written",
		},
		{
			"two counters on a start", "", lan4, loopback, daddr, netip.MustParseAddrPort("127.0.0.2:9"), true, true,
			[]Request{elements(unix.NFT_MSG_DELSETELEM, lan4, start), elements(unix.NFT_MSG_NEWSETELEM, lan4, start, counters)},
			"its set lan4 holds { 127.0.0.0/30, an element's expression }, where { 127.0.0.0/30 } was written",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			if c.module != "" {
				requireModule(t, c.module)
			}
			netnstest.EnterEmpty(t)
			conn, another := dial(t), dial(t)
			if err := conn.Batch([]Request{NewTable(unix.NFPROTO_INET, Table), chain.Create(unix.NFPROTO_INET)}); err != nil {
				t.Fatalf("make the table: %v", err)
			}
			monitor, err := OpenMonitor(conn, Scope{Sets: []string{c.set.Name}})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = monitor.Close() })
			write := func() {
				t.Helper()
				replaced, err := c.set.Replace(unix.NFPROTO_INET, c.written)
				if err != nil {
					t.Fatal(err)
				}
				line, err := chain.Rule(unix.NFPROTO_INET, "rule", c.rule)
				if err != nil {
					t.Fatal(err)
				}
				if err := conn.Batch(slices.Concat([]Request{chain.Flush(unix.NFPROTO_INET)}, replaced, []Request{line})); err != nil {
					t.Fatalf("write the set and its line: %v", err)
				}
			}
			fault := func() string {
				t.Helper()
				tables, err := Tables(conn, Table)
				if err != nil {
					t.Fatal(err)
				}
				read, err := Contents{Sets: []Set{c.set}, Elements: map[string][]Interval{c.set.Name: c.written}}.Read(conn, tables, unix.NFPROTO_INET)
				if err != nil {
					t.Fatal(err)
				}
				return read.Fault
			}
			dropped := func() bool {
				t.Helper()
				err := sendUDP(c.to, 0)
				if err != nil && !errors.Is(err, unix.EPERM) {
					t.Fatalf("send to %s: %v", c.to, err)
				}
				return err != nil
			}
			write()
			if got := dropped(); got != c.before {
				t.Fatalf("as written the line drops the datagram to %s %v, want %v", c.to, got, c.before)
			}
			if err := another.Batch(c.change); err != nil {
				t.Fatalf("another writer's change: %v", err)
			}
			select {
			case <-monitor.Changed():
			case <-time.After(rootWait):
				t.Errorf("another writer's change did not wake the owner")
			}
			if got := dropped(); got != c.after {
				t.Errorf("with the change the line drops the datagram to %s %v, want %v", c.to, got, c.after)
			}
			if got := fault(); got != c.fault {
				t.Errorf("with the change the set reads back with the fault %q, want %q", got, c.fault)
			}
			write()
			if got := dropped(); got != c.before {
				t.Errorf("after the owner's fill the line drops the datagram to %s %v, want %v", c.to, got, c.before)
			}
			if got := fault(); got != "" {
				t.Errorf("after the owner's fill the set reads back with the fault %q", got)
			}
		})
	}
}

// Another writer's set made again under the owner's name, flags, key and
// elements, with an expression of its own or with a size where the owner wrote
// none, reads back as a fault that names the set stale, and the owner's pass,
// which deletes what is stale, makes the set again, so the line drops as
// written and the set reads back as written. A limit of no connections as the
// set's expression, which nf_tables gives each element, has the line pass a
// key the set holds, and a counter or a size leaves the line as it was. A case
// runs only where the module of its expression is loaded or built in, and in a
// namespace of its own.
func TestNftablesSetMadeAgainOtherwiseIsMadeAgainByItsOwner(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	chain := Chain{Table: Table, Name: "post", Type: "filter", Hook: unix.NF_INET_POST_ROUTING, Priority: 2147483646}
	lan4 := Set{Table: Table, Name: "lan4", ID: 1, KeyType: TypeIPv4Addr, KeyLen: 4, Flags: unix.NFT_SET_INTERVAL}
	loopback := Prefixes(prefixList("127.0.0.0/30"))
	contents := Contents{Chains: []Chain{chain}, Sets: []Set{lan4}, Elements: map[string][]Interval{lan4.Name: loopback}}
	to := netip.MustParseAddrPort("127.0.0.2:9")
	// with is lan4 made with set attributes beside the owner's, NFTA_SET_EXPR among them
	with := func(attributes ...[]byte) func() (Request, error) {
		return func() (Request, error) {
			made, err := lan4.Create(unix.NFPROTO_INET)
			made.Body = slices.Concat(made.Body, slices.Concat(attributes...))
			return made, err
		}
	}
	sized := lan4
	sized.Size = 3
	for _, c := range []struct {
		name string
		// module is the one the expression needs, empty for none or one built into nf_tables
		module string
		made   func() (Request, error)
		// after is whether the line drops the datagram to to with the set made again
		after bool
		fault string
	}{
		{
			"a limit of no connections as its expression", "nft_connlimit",
			with(netlink.PutAttr(nil, 17|unix.NLA_F_NESTED, expressionBody("connlimit", PutAttrBE32(nil, connlimitCount, 0)))), false,
			"its set lan4 reads back with key type 7 of 4 bytes, flags 0x4, size 0, comment \"\" and 1 expression, where key type 7 of 4 bytes, flags 0x4, size 0 and comment \"\" were written",
		},
		{
			"a counter as its expression", "",
			with(netlink.PutAttr(nil, 17|unix.NLA_F_NESTED, expressionBody("counter", nil))), true,
			"its set lan4 reads back with key type 7 of 4 bytes, flags 0x4, size 0, comment \"\" and 1 expression, where key type 7 of 4 bytes, flags 0x4, size 0 and comment \"\" were written",
		},
		{
			"a size", "", func() (Request, error) { return sized.Create(unix.NFPROTO_INET) }, true,
			"its set lan4 reads back with key type 7 of 4 bytes, flags 0x4, size 3 and comment \"\", where key type 7 of 4 bytes, flags 0x4, size 0 and comment \"\" were written",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			if c.module != "" {
				requireModule(t, c.module)
			}
			netnstest.EnterEmpty(t)
			conn, another := dial(t), dial(t)
			line, err := chain.Rule(unix.NFPROTO_INET, "rule", slices.Concat(NFProto(unix.NFPROTO_IPV4), [][]byte{DestinationLoad(unix.NFPROTO_IPV4), Lookup(lan4, false)}, CountedDrop()))
			if err != nil {
				t.Fatal(err)
			}
			read := func() Readback {
				t.Helper()
				tables, err := Tables(conn, Table)
				if err != nil {
					t.Fatal(err)
				}
				read, err := contents.Read(conn, tables, unix.NFPROTO_INET)
				if err != nil {
					t.Fatal(err)
				}
				return read
			}
			// pass is the owner's: the table written over what its read found stale
			pass := func() error {
				t.Helper()
				replaced, err := lan4.Replace(unix.NFPROTO_INET, loopback)
				if err != nil {
					t.Fatal(err)
				}
				return conn.Batch(slices.Concat(contents.Rewrite(unix.NFPROTO_INET, read().Stale, nil), replaced, []Request{line}))
			}
			dropped := func() bool {
				t.Helper()
				err := sendUDP(to, 0)
				if err != nil && !errors.Is(err, unix.EPERM) {
					t.Fatalf("send to %s: %v", to, err)
				}
				return err != nil
			}
			if err := pass(); err != nil {
				t.Fatalf("the owner's first pass: %v", err)
			}
			if !dropped() {
				t.Fatalf("as written the line passes the datagram to %s", to)
			}
			made, err := c.made()
			if err != nil {
				t.Fatal(err)
			}
			filled, err := lan4.Fill(unix.NFPROTO_INET, loopback)
			if err != nil {
				t.Fatal(err)
			}
			if err := another.Batch(slices.Concat([]Request{chain.Flush(unix.NFPROTO_INET), lan4.Delete(unix.NFPROTO_INET), made}, filled, []Request{line})); err != nil {
				t.Fatalf("another writer makes the set again: %v", err)
			}
			if got := dropped(); got != c.after {
				t.Errorf("with the set made again the line drops the datagram to %s %v, want %v", to, got, c.after)
			}
			if got := read(); got.Fault != c.fault || !got.Remake() {
				t.Errorf("with the set made again it reads back with the fault %q, remade %v, want %q, remade", got.Fault, got.Remake(), c.fault)
			}
			if err := pass(); err != nil {
				t.Fatalf("the owner's pass over the set made again: %v", err)
			}
			if !dropped() {
				t.Errorf("after the owner's pass the line passes the datagram to %s", to)
			}
			if got := read(); got.Fault != "" {
				t.Errorf("after the owner's pass the set reads back with the fault %q", got.Fault)
			}
		})
	}
}

// largeSetIntervals is how many intervals the large set's one transaction
// fills, two elements each
const largeSetIntervals = 10000

// A transaction filling a set with ten thousand intervals goes through as one
// batch on a socket whose send buffer starts at a fraction of it, and the set
// reads back every interval
func TestNftablesBatchFillsASetOfTenThousandIntervals(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmptyLoopbackDown(t)
	conn := dial(t)
	set := Set{Table: "large", Name: "large6", ID: 1, KeyType: TypeIPv6Addr, KeyLen: 16, Flags: unix.NFT_SET_INTERVAL}
	prefixes := make([]netip.Prefix, 0, largeSetIntervals)
	for i := range largeSetIntervals {
		// every other /64 of 2001:db8::/48, so no two intervals join
		n := 2 * i
		prefixes = append(prefixes, netip.PrefixFrom(netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 6: byte(n >> 8), 7: byte(n)}), 64))
	}
	intervals := Prefixes(prefixes)
	if len(intervals) != largeSetIntervals {
		t.Fatalf("the prefixes make %d intervals, want %d", len(intervals), largeSetIntervals)
	}
	made, err := set.Create(unix.NFPROTO_INET)
	if err != nil {
		t.Fatal(err)
	}
	filled, err := set.Fill(unix.NFPROTO_INET, intervals)
	if err != nil {
		t.Fatal(err)
	}
	requests := append([]Request{NewTable(unix.NFPROTO_INET, set.Table), made}, filled...)
	size := 0
	for _, request := range requests {
		size += unix.NLMSG_HDRLEN + (len(request.Body)+unix.NLMSG_ALIGNTO-1)&^(unix.NLMSG_ALIGNTO-1)
	}
	// a quarter of the batch, which the kernel doubles, whatever net.core.wmem_default holds
	if err := unix.SetsockoptInt(conn.link.Fd(), unix.SOL_SOCKET, unix.SO_SNDBUF, size/4); err != nil {
		t.Fatal(err)
	}
	if err := conn.Batch(requests); err != nil {
		t.Fatalf("fill %d intervals in one batch of %d bytes: %v", len(intervals), size, err)
	}
	held, err := set.Elements(conn, unix.NFPROTO_INET)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.EqualFunc(held, intervals, func(a, b Interval) bool { return bytes.Equal(a.First, b.First) && bytes.Equal(a.Last, b.Last) }) {
		t.Errorf("the set reads back %d intervals, not the %d written", len(held), len(intervals))
	}
	grown, err := unix.GetsockoptInt(conn.link.Fd(), unix.SOL_SOCKET, unix.SO_SNDBUF)
	if err != nil {
		t.Fatal(err)
	}
	path := "SO_SNDBUFFORCE"
	if err := unix.SetsockoptInt(conn.link.Fd(), unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, grown/2); err != nil {
		path = "SO_SNDBUF, SO_SNDBUFFORCE refused with " + err.Error()
	}
	most, err := os.ReadFile("/proc/sys/net/core/wmem_max")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("a batch of %d bytes went through a send buffer grown to %d bytes by %s, net.core.wmem_max %s", size, grown, path, strings.TrimSpace(string(most)))
}

func dial(t *testing.T) *Conn {
	t.Helper()
	conn, err := Dial()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func sockaddr(to netip.AddrPort) (int, unix.Sockaddr) {
	if to.Addr().Is4() {
		return unix.AF_INET, &unix.SockaddrInet4{Port: int(to.Port()), Addr: to.Addr().As4()}
	}
	return unix.AF_INET6, &unix.SockaddrInet6{Port: int(to.Port()), Addr: to.Addr().As16()}
}

// sendUDP sends one datagram to to from a socket carrying mark, none for 0
func sendUDP(to netip.AddrPort, mark int) error {
	family, address := sockaddr(to)
	fd, err := unix.Socket(family, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if mark != 0 {
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, mark); err != nil {
			return err
		}
	}
	return unix.Sendto(fd, []byte("probe"), 0, address)
}

func sendFrom(fd int, to netip.AddrPort) error {
	_, address := sockaddr(to)
	return unix.Sendto(fd, []byte("probe"), 0, address)
}

// listenUDP is a datagram socket bound to an ephemeral port of address, read
// with a timeout
func listenUDP(t *testing.T, address string) int {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	if err := unix.Bind(fd, &unix.SockaddrInet4{Addr: netip.MustParseAddr(address).As4()}); err != nil {
		t.Fatal(err)
	}
	timeout := unix.NsecToTimeval(rootWait.Nanoseconds())
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout); err != nil {
		t.Fatal(err)
	}
	return fd
}

func receive(t *testing.T, fd int) unix.Sockaddr {
	t.Helper()
	buf := make([]byte, 64)
	n, from, err := unix.Recvfrom(fd, buf, 0)
	if err != nil {
		t.Fatalf("receive a datagram: %v", err)
	}
	if !bytes.Equal(buf[:n], []byte("probe")) {
		t.Fatalf("received %q", buf[:n])
	}
	return from
}
