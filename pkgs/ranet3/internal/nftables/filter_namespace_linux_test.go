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
	"os/exec"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The tests of this file write into a real kernel, each in a network
// namespace it made itself and refusing any other, and run as root in the
// netlink VM check and under unshare -rn.

// rootWait bounds a wait for a datagram the kernel delivers on loopback at once
const rootWait = 2 * time.Second

// filterText is the switch's chain as nft spells it, written by nft into one
// table and by the encoders into another
const filterText = `table inet %s {
	set forwarded { type ifname; elements = { "lan1", "br0" } }
	set lan4 { type ipv4_addr; flags interval; elements = { 198.51.100.0/24, 203.0.113.0/25, 192.0.2.128/26 } }
	set lan6 { type ipv6_addr; flags interval; elements = { 2001:db8:a:1::/64, 2001:db8:9::/64 } }
	chain fallback {
		type filter hook postrouting priority 2147483646; policy accept;
		oifname { "lo", "ranet3" } accept
		meta mark 0x00000072 accept
		meta iif != 0 iifname != @forwarded accept
		ip daddr @lan4 accept
		ip6 daddr @lan6 accept
		ip daddr { 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255 } accept
		ip6 daddr { fe80::/10, ff00::/8 } accept
		ct direction reply ct protocol tcp ct original proto-dst { 22, 60000-61000 } accept
		counter drop
	}
}
`

// The switch's table written by the encoders lists, dumps and holds its
// elements exactly as the same text written by nft 1.1.7: each rule's
// expressions as the kernel hands them back, anonymous sets aside by name,
// each named set's elements, and `nft list table` line by line but for the
// comments the encoders write
func TestNftablesFilterEncodesAsNftsOwn(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	enterThrowawayNamespace(t)
	nft, err := exec.LookPath("nft")
	if err != nil {
		t.Fatal("the table to compare with is written through nft, which is not on the path")
	}
	conn := dial(t)
	cmd := exec.Command(nft, "-f", "-")
	cmd.Stdin = strings.NewReader(strings.ReplaceAll(filterText, "%s", "nftside"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("write the table through nft: %v\n%s", err, out)
	}
	sets, elements := filterSets("goside")
	if err := conn.Batch(filterBatch(t, "goside", sets, elements)); err != nil {
		t.Fatalf("write the table through the encoders: %v", err)
	}

	listed := func(table string) []string {
		out, err := exec.Command(nft, "list", "table", "inet", table).CombinedOutput()
		if err != nil {
			t.Fatalf("list table %s: %v\n%s", table, err, out)
		}
		text := regexp.MustCompile(` comment "[^"]*"`).ReplaceAllString(string(out), "")
		return strings.Split(strings.ReplaceAll(text, table, "TABLE"), "\n")
	}
	if got, want := listed("goside"), listed("nftside"); !slices.Equal(got, want) {
		t.Errorf("the encoders' table lists as\n%s\nwhere nft's lists as\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	expressions := func(table string) []string {
		replies, err := conn.Dump(Command(unix.NFT_MSG_GETRULE), PutNfgenmsg(nil, unix.NFPROTO_INET))
		if err != nil {
			t.Fatal(err)
		}
		anonymous := regexp.MustCompile(`1=5f5f736574[0-9a-f]*`)
		var out []string
		for _, reply := range replies {
			var held string
			var list []byte
			for kind, value := range reply.Attributes() {
				switch kind {
				case unix.NFTA_RULE_TABLE:
					held = unix.ByteSliceToString(value)
				case unix.NFTA_RULE_EXPRESSIONS:
					list = value
				}
			}
			if held != table {
				continue
			}
			var rule []string
			for _, element := range Nested(list) {
				rule = append(rule, anonymous.ReplaceAllString(rendered(t, PutAttr(nil, unix.NFTA_LIST_ELEM, element.Value)), "1=anonymous"))
			}
			out = append(out, strings.Join(rule, " | "))
		}
		return out
	}
	if got, want := expressions("goside"), expressions("nftside"); !slices.Equal(got, want) {
		t.Errorf("the encoders' rules dump as\n%s\nwhere nft's dump as\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	for _, s := range sets {
		mine, err := s.Elements(conn, unix.NFPROTO_INET)
		if err != nil {
			t.Fatal(err)
		}
		other := s
		other.Table = "nftside"
		theirs, err := other.Elements(conn, unix.NFPROTO_INET)
		if err != nil {
			t.Fatal(err)
		}
		if fault := s.elementFault(elements[s.Name], mine); fault != "" {
			t.Errorf("the encoders' table: %s", fault)
		}
		if fault := s.elementFault(elements[s.Name], theirs); fault != "" {
			t.Errorf("nft's table: %s", fault)
		}
	}
}

// filterSets is the named sets of filterText in table, with their elements
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

// filterBatch is filterText's table in one transaction through the encoders
func filterBatch(t *testing.T, table string, sets []Set, elements map[string][]Interval) []Request {
	t.Helper()
	requests := []Request{NewTable(unix.NFPROTO_INET, table)}
	fill := func(s Set, intervals []Interval) {
		made, err := s.Create(unix.NFPROTO_INET)
		if err != nil {
			t.Fatal(err)
		}
		filled, err := s.Fill(unix.NFPROTO_INET, intervals)
		if err != nil {
			t.Fatal(err)
		}
		requests = append(append(requests, made), filled...)
	}
	for _, s := range sets {
		fill(s, elements[s.Name])
	}
	chain := Chain{Table: table, Name: "fallback", Type: "filter", Hook: unix.NF_INET_POST_ROUTING, Priority: 2147483646}
	requests = append(requests, chain.Create(unix.NFPROTO_INET), chain.Flush(unix.NFPROTO_INET))
	byName := func(name string) Set { return sets[slices.IndexFunc(sets, func(s Set) bool { return s.Name == name })] }
	accept := Verdict(Accept)
	oif := Anonymous(table, 10, TypeIfname, unix.IFNAMSIZ, 0)
	fill(oif, []Interval{Key(InterfaceName("lo")), Key(InterfaceName("ranet3"))})
	link4 := Anonymous(table, 11, TypeIPv4Addr, 4, unix.NFT_SET_INTERVAL)
	fill(link4, Prefixes(prefixList("169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32")))
	link6 := Anonymous(table, 12, TypeIPv6Addr, 16, unix.NFT_SET_INTERVAL)
	fill(link6, Prefixes(prefixList("fe80::/10", "ff00::/8")))
	ports := Anonymous(table, 13, TypeInetService, 2, unix.NFT_SET_INTERVAL)
	fill(ports, []Interval{Key([]byte{0, 22}), {First: []byte{0xea, 0x60}, Last: []byte{0xee, 0x48}}})
	for spec, expressions := range map[string][][]byte{
		"1 oifname":   {MetaLoad(unix.NFT_META_OIFNAME), Lookup(oif, false), accept},
		"2 mark":      append(MetaCompareValue(unix.NFT_META_MARK, unix.NFT_CMP_EQ, binary.NativeEndian.AppendUint32(nil, 0x72)), accept),
		"3 forwarded": slices.Concat(MetaCompareValue(unix.NFT_META_IIF, unix.NFT_CMP_NEQ, make([]byte, 4)), [][]byte{MetaLoad(unix.NFT_META_IIFNAME), Lookup(byName("forwarded"), true), accept}),
		"4 lan4":      slices.Concat(NFProto(unix.NFPROTO_IPV4), [][]byte{DestinationLoad(unix.NFPROTO_IPV4), Lookup(byName("lan4"), false), accept}),
		"5 lan6":      slices.Concat(NFProto(unix.NFPROTO_IPV6), [][]byte{DestinationLoad(unix.NFPROTO_IPV6), Lookup(byName("lan6"), false), accept}),
		"6 link4":     slices.Concat(NFProto(unix.NFPROTO_IPV4), [][]byte{DestinationLoad(unix.NFPROTO_IPV4), Lookup(link4, false), accept}),
		"7 link6":     slices.Concat(NFProto(unix.NFPROTO_IPV6), [][]byte{DestinationLoad(unix.NFPROTO_IPV6), Lookup(link6, false), accept}),
		"8 inbound":   {CTLoad(unix.NFT_CT_DIRECTION), Expression("cmp", Compare(unix.NFT_CMP_EQ, []byte{CTReply})), CTLoad(unix.NFT_CT_PROTOCOL), Expression("cmp", Compare(unix.NFT_CMP_EQ, []byte{unix.IPPROTO_TCP})), CTLoadDirection(unix.NFT_CT_PROTO_DST, CTOriginal), Lookup(ports, false), accept},
		"9 drop":      CountedDrop(),
	} {
		rule, err := chain.Rule(unix.NFPROTO_INET, spec, expressions)
		if err != nil {
			t.Fatal(err)
		}
		requests = append(requests, rule)
	}
	// the map's order is random, and each rule goes in after the sets it names and in the chain's order
	rules := requests[len(requests)-9:]
	slices.SortFunc(rules, func(a, b Request) int {
		_, _, x, _, _, _ := DecodeRule(Message{Data: a.Body})
		_, _, y, _, _, _ := DecodeRule(Message{Data: b.Body})
		return strings.Compare(x, y)
	})
	return requests
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
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	enterThrowawayNamespace(t)
	loopbackUp(t)
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
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	enterThrowawayNamespace(t)
	conn := dial(t)
	const table = "owned"
	sets, elements := filterSets(table)
	contents := Contents{Sets: sets, Elements: elements}
	monitor, err := OpenMonitor(conn, Scope{Name: table, Families: []uint8{unix.NFPROTO_INET}})
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

func dial(t *testing.T) *Conn {
	t.Helper()
	conn, err := Dial()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// enterThrowawayNamespace moves this test's thread into a fresh network
// namespace. The thread is never unlocked, so the Go runtime destroys it when
// this goroutine exits and takes the namespace with it.
func enterThrowawayNamespace(t *testing.T) {
	t.Helper()
	runtime.LockOSThread()
	before := namespaceID(t)
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		t.Fatalf("unshare a network namespace: %v", err)
	}
	if namespaceID(t) == before {
		t.Fatal("refusing to continue: the network namespace did not change")
	}
}

func namespaceID(t *testing.T) uint64 {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Stat("/proc/thread-self/ns/net", &st); err != nil {
		t.Fatalf("stat this thread's network namespace: %v", err)
	}
	return st.Ino
}

func loopbackUp(t *testing.T) {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	ifr, err := unix.NewIfreq("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		t.Fatal(err)
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP)
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr); err != nil {
		t.Fatalf("bring loopback up: %v", err)
	}
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
