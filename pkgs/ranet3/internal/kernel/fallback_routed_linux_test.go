// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type routedCase struct {
	name, in, source, target, first string
	pass                            bool
}

// The packets enter the kernel through a tun and take its real forward hook.
// The egress tun captures packets that passed. No fake rule evaluator decides
// their verdict, and the namespace and devices die with the test process.
func TestNetlinkFallbackRoutedSourcesMeetTheForwardChain(t *testing.T) {
	plat, _, links, _ := routedSwitch(t)
	trace := routedTrace(t)
	tests := []routedCase{
		{"own IPv4 source outside forward", "ranetother0", "192.0.2.9", "198.51.100.200", fallbackDrop, false},
		{"other IPv4 source outside forward", "ranetother0", "192.0.2.200", "198.51.100.200", "ip saddr != @from4 accept", true},
		{"own IPv4 source on forward to LAN", "ranetfw0", "192.0.2.9", "198.51.100.20", "iifname @forwarded accept", true},
		{"own IPv4 source to LAN", "ranetother0", "192.0.2.9", "198.51.100.20", "ip daddr @lan4 accept", true},
		{"own IPv4 source to self", "ranetother0", "192.0.2.9", "203.0.113.9", "ip daddr @self4 accept", true},
		{"own IPv6 source outside forward", "ranetother0", "3fff:1::9", "2001:db8:e::9", fallbackDrop, false},
		{"other IPv6 source outside forward", "ranetother0", "3fff:2::9", "2001:db8:e::9", "ip6 saddr != @from6 accept", true},
		{"own IPv6 source on forward to LAN", "ranetfw0", "3fff:1::9", "2001:db8:a::20", "iifname @forwarded accept", true},
		{"own IPv6 source to LAN", "ranetother0", "3fff:1::9", "2001:db8:a::20", "ip6 daddr @lan6 accept", true},
	}
	for _, test := range tests {
		t.Log(test.name)
		src, dst := netip.MustParseAddr(test.source), netip.MustParseAddr(test.target)
		packet := routedDatagram(src, dst)
		before, err := plat.readFallback(fallbackSample)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := unix.Write(links[test.in], packet); err != nil {
			t.Fatal(err)
		}
		passed := routedCaptured(t, links["ranetup0"], src, dst)
		if passed != test.pass {
			t.Errorf("%s through %s to %s: egress %v, want %v", src, test.in, dst, passed, test.pass)
		}
		after, err := plat.readFallback(fallbackSample)
		if err != nil {
			t.Fatal(err)
		}
		if !test.pass && after.dropped != before.dropped+1 {
			t.Errorf("refused packet: drops changed from %d to %d, want one forward drop", before.dropped, after.dropped)
		}
	}
	routedFirstMatches(t, trace, tests)
}

// Real confirmed UDP flows in both families make the kernel classify quoted
// errors. An own-prefix server's listed reply and its RELATED errors take the
// earlier inbound exception. Its unlisted reply and error cannot pass form e
// because the quoted reply source belongs to this node. Errors about a flow
// whose two endpoints lie outside the protected set reach form e, even when
// forged by a sender inside that set.
func TestNetlinkFallbackRoutedICMPQuotesTheConnection(t *testing.T) {
	plat, conn, links, indices := routedSwitch(t)
	writeBatchRoute(t, conn, unix.RT_TABLE_MAIN, prefix("192.0.2.0/25"), batchHop{index: indices["ranetother0"]})
	writeBatchRoute(t, conn, unix.RT_TABLE_MAIN, prefix("3fff:1::/64"), batchHop{index: indices["ranetother0"]})
	trace := routedTrace(t)
	var cases []routedCase
	send := func(in, out string, packet []byte, source, target netip.Addr, pass bool) {
		t.Helper()
		if _, err := unix.Write(links[in], packet); err != nil {
			t.Fatal(err)
		}
		if got := routedCaptured(t, links[out], source, target); got != pass {
			t.Errorf("%s to %s from %s: egress on %s = %v, want %v", source, target, in, out, got, pass)
		}
	}
	probe := func(name string, source, target netip.Addr, quote []byte, kind, code byte, pass bool, first string) {
		t.Helper()
		send("ranetother0", "ranetup0", routedError(source, target, quote, kind, code), source, target, pass)
		cases = append(cases, routedCase{name, "ranetother0", source.String(), target.String(), first, pass})
	}
	for _, family := range []struct {
		client, server, router, outside, remote string
		eligible, code                          byte
	}{
		{"198.51.100.200", "192.0.2.9", "192.0.2.20", "192.0.2.200", "198.51.100.201", 3, 4},
		{"2001:db8:e::9", "3fff:1::9", "3fff:1::20", "3fff:2::9", "2001:db8:e::10", 2, 0},
	} {
		client, server := netip.MustParseAddr(family.client), netip.MustParseAddr(family.server)
		router, outside := netip.MustParseAddr(family.router), netip.MustParseAddr(family.outside)
		remote := netip.MustParseAddr(family.remote)
		sender := func(offset int) netip.Addr {
			address := router
			for range offset {
				address = address.Next()
			}
			return address
		}
		formE := "icmp errors 3/11/12 related outside from4 counter accept"
		if router.Is6() {
			formE = "icmpv6 errors 1-4 related outside from6 counter accept"
		}
		t.Logf("flow from %s to own-prefix server %s", client, server)
		listed := routedUDP(client, server, 40000, 53)
		send("ranetup0", "ranetother0", listed, client, server, true)
		send("ranetother0", "ranetup0", routedUDP(server, client, 53, 40000), server, client, true)
		cases = append(cases, routedCase{"listed inbound reply", "ranetother0", server.String(), client.String(),
			"ct direction reply ct protocol udp ct original proto-dst @udpports accept", true})
		before := routedCounters(t)
		probe("listed flow error", router, client, listed, family.eligible, family.code, true,
			"ct direction reply ct protocol udp ct original proto-dst @udpports accept")
		after := routedCounters(t)
		if after != before {
			t.Errorf("listed inbound flow's error met form e or F99: counters %+v -> %+v", before, after)
		}

		unlistedServer := server.Next()
		unlisted := routedUDP(client, unlistedServer, 40000, 4444)
		send("ranetup0", "ranetother0", unlisted, client, unlistedServer, true)
		before = routedCounters(t)
		send("ranetother0", "ranetup0", routedUDP(unlistedServer, client, 4444, 40000), unlistedServer, client, false)
		cases = append(cases, routedCase{"unlisted inbound reply", "ranetother0", unlistedServer.String(), client.String(), fallbackDrop, false})
		probe("unlisted flow error", sender(1), client, unlisted, family.eligible, family.code, false, fallbackDrop)
		after = routedCounters(t)
		if after.drop != before.drop+2 || after.icmp4 != before.icmp4 || after.icmp6 != before.icmp6 {
			t.Errorf("unlisted own-prefix reply and error: counters %+v -> %+v, want two drops", before, after)
		}

		ordinary := routedUDP(outside, remote, 40001, 4444)
		send("ranetother0", "ranetup0", ordinary, outside, remote, true)
		before = routedCounters(t)
		probe("outside endpoints", sender(2), outside, ordinary, family.eligible, family.code, true, formE)
		after = routedCounters(t)
		if after.drop != before.drop || (outside.Is4() && after.icmp4 != before.icmp4+1) ||
			(outside.Is6() && after.icmp6 != before.icmp6+1) {
			t.Errorf("RELATED outside-endpoint error: counters %+v -> %+v, want one form-e accept", before, after)
		}
		for i, kind := range []byte{4, 5} {
			if outside.Is6() {
				kind += 1 // IPv6 type 5 is unallocated; 6 is outside 1-4 too
			}
			before = routedCounters(t)
			probe("excluded type", sender(3+i), outside, ordinary, kind, 0, false, fallbackDrop)
			after = routedCounters(t)
			if after.drop != before.drop+1 {
				t.Errorf("type %d outside form e: counters %+v -> %+v, want one drop", kind, before, after)
			}
		}
		forged := routedUDP(outside, remote, 40002, 4444)
		before = routedCounters(t)
		probe("quote without a flow", sender(5), outside, forged, family.eligible, family.code, false, fallbackDrop)
		after = routedCounters(t)
		if after.drop != before.drop+1 {
			t.Errorf("an error without a confirmed quoted flow: counters %+v -> %+v, want one drop", before, after)
		}
		eligible := [][2]byte{{3, 0}, {3, 4}, {11, 0}, {12, 0}}
		if outside.Is6() {
			eligible = [][2]byte{{1, 0}, {2, 0}, {3, 0}, {4, 0}}
		}
		for i, typ := range eligible {
			before = routedCounters(t)
			probe("eligible error type", sender(6+i), outside, ordinary, typ[0], typ[1], true, formE)
			after = routedCounters(t)
			if after.drop != before.drop || (outside.Is4() && after.icmp4 != before.icmp4+1) ||
				(outside.Is6() && after.icmp6 != before.icmp6+1) {
				t.Errorf("type %d code %d: counters %+v -> %+v, want one form-e accept", typ[0], typ[1], before, after)
			}
		}
		before = routedCounters(t)
		probe("matching quote with payload", sender(10), outside, append(bytes.Clone(ordinary), 1, 2, 3, 4),
			family.eligible, family.code, true, formE)
		after = routedCounters(t)
		if after.drop != before.drop || (outside.Is4() && after.icmp4 != before.icmp4+1) ||
			(outside.Is6() && after.icmp6 != before.icmp6+1) {
			t.Errorf("quote with payload: counters %+v -> %+v, want one form-e accept", before, after)
		}
		if read, err := plat.readFallback(fallbackSample); err != nil || read.fault != "" {
			t.Errorf("the table after quoted packets reads %+v (%v)", read, err)
		}
	}
	routedFirstMatches(t, trace, cases)
}

type routedCount struct{ drop, icmp4, icmp6 uint64 }

func routedCounters(t *testing.T) (out routedCount) {
	t.Helper()
	debug, err := ReadFallback()
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range debug.Rules {
		if rule.Chain != "routed" {
			continue
		}
		switch rule.Spec {
		case fallbackDrop:
			out.drop = rule.Packets
		case "icmp errors 3/11/12 related outside from4 counter accept":
			out.icmp4 = rule.Packets
		case "icmpv6 errors 1-4 related outside from6 counter accept":
			out.icmp6 = rule.Packets
		}
	}
	return out
}

type routedTraceBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *routedTraceBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *routedTraceBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// A lower-priority test-owned forward chain marks only the probes. Monitoring
// ends before the trace is inspected and both test processes are waited for.
func routedTrace(t *testing.T) func(...routedCase) string { return routedTraceFor(t, 0) }

// A packet's delivery can precede its complete trace record. Wait for each
// requested packet and its rule before closing the monitor.
func routedTraceFor(t *testing.T, want int) func(...routedCase) string {
	t.Helper()
	script := "table inet ranettrace {\n" +
		"\tchain forward {\n\t\ttype filter hook forward priority -300; policy accept;\n" +
		"\t\tmeta l4proto { tcp, udp } meta nftrace set 1\n" +
		"\t\tmeta l4proto { icmp, ipv6-icmp } meta nftrace set 1\n\t}\n}\n"
	write := exec.Command("nft", "-f", "-")
	write.Stdin = strings.NewReader(script)
	if out, err := write.CombinedOutput(); err != nil {
		t.Fatalf("make trace chain: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		if out, err := exec.Command("nft", "delete", "table", "inet", "ranettrace").CombinedOutput(); err != nil {
			t.Errorf("delete trace chain: %v\n%s", err, out)
		}
	})
	var output routedTraceBuffer
	monitor := exec.Command("nft", "monitor", "trace")
	monitor.Stdout, monitor.Stderr = &output, &output
	if err := monitor.Start(); err != nil {
		t.Fatal(err)
	}
	stopped := false
	finish := func() {
		if stopped {
			return
		}
		stopped = true
		if err := monitor.Process.Kill(); err != nil {
			t.Errorf("stop trace reader: %v", err)
		}
		_ = monitor.Wait()
	}
	t.Cleanup(finish)
	waitFor(t, func() bool { return routedTraceSubscribed(t) })
	return func(cases ...routedCase) string {
		if !stopped && (want > 0 || len(cases) > 0) {
			deadline := time.Now().Add(waitBudget)
			for !routedTraceComplete(output.String(), want, cases) && time.Now().Before(deadline) {
				time.Sleep(waitPoll)
			}
		}
		finish()
		text := output.String()
		if (want > 0 || len(cases) > 0) && !routedTraceComplete(text, want, cases) {
			t.Errorf("the monitor missed a complete routed rule for %d packets and %d cases:\n%s", want, len(cases), text)
		}
		return text
	}
}

// routedTraceSubscribed reports whether a NETLINK_NETFILTER socket of this
// namespace, the monitor's, has joined NFNLGRP_NFTRACE, after which the kernel
// queues it every trace event. /proc/net/netlink lists the groups below 32 in
// hex (netlink_seq_show in af_netlink.c).
func routedTraceSubscribed(t *testing.T) bool {
	t.Helper()
	raw, err := os.ReadFile("/proc/thread-self/net/netlink")
	if err != nil {
		t.Fatalf("read the netlink sockets: %v", err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		// sk, Eth, Pid, Groups, then counters
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[1] != strconv.Itoa(unix.NETLINK_NETFILTER) {
			continue
		}
		if groups, err := strconv.ParseUint(fields[3], 16, 32); err == nil && groups&(1<<(unix.NFNLGRP_NFTRACE-1)) != 0 {
			return true
		}
	}
	return false
}

func routedTraceRecords(trace string) (map[string]string, map[string][]string) {
	packets, rules := map[string]string{}, map[string][]string{}
	// A write can end inside a rule while the monitor is still printing it.
	for _, line := range strings.Split(trace[:strings.LastIndexByte(trace, '\n')+1], "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[0] != "trace" || fields[1] != "id" {
			continue
		}
		switch {
		case strings.Contains(line, "inet ranet3 routed packet:"):
			packets[fields[2]] = line
		case strings.Contains(line, "inet ranet3 routed rule "):
			rules[fields[2]] = append(rules[fields[2]], line)
		}
	}
	return packets, rules
}

func routedMatchingRules(packets map[string]string, rules map[string][]string, test routedCase) []string {
	family := "ip"
	if netip.MustParseAddr(test.source).Is6() {
		family = "ip6"
	}
	var matched []string
	for id, packet := range packets {
		if strings.Contains(packet, `iif "`+test.in+`"`) &&
			strings.Contains(packet, family+" saddr "+test.source+" "+family+" daddr "+test.target+" ") {
			matched = append(matched, rules[id]...)
		}
	}
	return matched
}

func routedTraceComplete(trace string, want int, cases []routedCase) bool {
	if want == 0 && len(cases) == 0 {
		return true
	}
	packets, rules := routedTraceRecords(trace)
	if len(packets) < want {
		return false
	}
	count := 0
	for _, lines := range rules {
		count += len(lines)
	}
	if count < want {
		return false
	}
	for _, test := range cases {
		if len(routedMatchingRules(packets, rules, test)) == 0 {
			return false
		}
	}
	return true
}

// routedFirstMatches reads the trace once each case has its complete rule
// record, so no caller can inspect it before the monitor printed the last one.
func routedFirstMatches(t *testing.T, trace func(...routedCase) string, cases []routedCase) {
	t.Helper()
	text := trace(cases...)
	installed, err := exec.Command("nft", "-a", "list", "chain", "inet", "ranet3", "routed").CombinedOutput()
	if err != nil {
		t.Fatalf("list forward rules: %v\n%s", err, installed)
	}
	packets, rules := routedTraceRecords(text)
	for _, test := range cases {
		matched := routedMatchingRules(packets, rules, test)
		matchesFirst := len(matched) != 0
		for _, line := range matched {
			if !strings.Contains(line, "comment \""+test.first+"\"") {
				matchesFirst = false
			}
		}
		if !matchesFirst {
			t.Errorf("%s: first matching forward rules %v, want %q; trace:\n%s", test.name, matched, test.first, text)
			continue
		}
		found := false
		for _, line := range strings.Split(string(installed), "\n") {
			if !strings.Contains(line, "comment \""+test.first+"\" # handle ") {
				continue
			}
			parts := strings.SplitN(line, "# handle ", 2)
			if len(parts) == 2 {
				handle, err := strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 64)
				found = err == nil && handle != 0
			}
		}
		if !found {
			t.Errorf("%s: traced rule %q has no handle in the installed chain", test.name, test.first)
		}
	}
}

func TestRoutedTraceWaitsForCompleteMatchingRecords(t *testing.T) {
	cases := []routedCase{
		{in: "ranetup0", source: "192.0.2.200", target: "198.51.100.20"},
		{in: "ranetother0", source: "3fff:1::9", target: "2001:db8:e::200"},
	}
	request := "trace id 1 inet ranet3 routed packet: iif \"ranetup0\" ip saddr 192.0.2.200 ip daddr 198.51.100.20 udp\n" +
		"trace id 1 inet ranet3 routed rule comment \"ip saddr != @from4 accept\" verdict accept\n"
	retransmit := request + "trace id 2 inet ranet3 routed packet: iif \"ranetup0\" ip saddr 192.0.2.200 ip daddr 198.51.100.20 udp\n" +
		"trace id 2 inet ranet3 routed rule comment \"ip saddr != @from4 accept\" verdict accept\n"
	reply := "trace id 3 inet ranet3 routed packet: iif \"ranetother0\" ip6 saddr 3fff:1::9 ip6 daddr 2001:db8:e::200 tcp\n"
	partial := retransmit + reply + "trace id 3 inet ranet3 routed rule ct direction reply ct protocol"
	for _, test := range []struct {
		name  string
		trace string
		want  bool
	}{
		{"request alone", request, false},
		{"retransmission instead of reply", retransmit, false},
		{"reply rule without its last line", partial, false},
		{"complete reply", partial + " tcp comment \"ct direction reply ct protocol tcp ct original proto-dst @tcpports accept\"\n", true},
	} {
		if got := routedTraceComplete(test.trace, 2, cases); got != test.want {
			t.Errorf("%s: complete trace %t, want %t", test.name, got, test.want)
		}
	}
}

func routedSwitch(t *testing.T) (*netlinkPlatform, *nlConn, map[string]int, map[string]uint32) {
	t.Helper()
	plat := rootRulePlatform(t, "ranetsw0")
	conn, err := dialNetlink()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	links := make(map[string]int)
	indices := make(map[string]uint32)
	for _, name := range []string{"ranetup0", "ranetfw0", "ranetother0"} {
		links[name] = routedTUN(t, name)
		link, err := conn.link(0, name)
		if err != nil {
			t.Fatal(err)
		}
		setLinkFlags(t, conn, link.index, unix.IFF_UP)
		indices[name] = link.index
		if name == "ranetup0" {
			writeBatchAddress(t, conn, link.index, prefix("198.51.100.10/25"))
			writeBatchAddress(t, conn, link.index, prefix("2001:db8:a::10/64"))
			writeBatchRoute(t, conn, unix.RT_TABLE_MAIN, prefix("0.0.0.0/0"), batchHop{index: link.index})
			writeBatchRoute(t, conn, unix.RT_TABLE_MAIN, prefix("::/0"), batchHop{index: link.index})
		}
	}
	writeBatchSysctl(t, "ipv4/ip_forward", "1")
	writeBatchSysctl(t, "ipv6/conf/all/forwarding", "1")
	for _, name := range []string{"all", "default", "ranetup0", "ranetfw0", "ranetother0"} {
		writeBatchSysctl(t, "ipv4/conf/"+name+"/rp_filter", "0")
	}
	if err := plat.writeFallback(fallbackSample, false); err != nil {
		t.Fatal(err)
	}
	return plat, conn, links, indices
}

func routedTUN(t *testing.T, name string) int {
	t.Helper()
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Skipf("no /dev/net/tun: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		t.Fatal(err)
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		t.Fatal(err)
	}
	return fd
}

func routedDatagram(src, dst netip.Addr) []byte { return routedUDP(src, dst, 40000, 33434) }

func routedUDP(src, dst netip.Addr, sourcePort, targetPort uint16) []byte {
	length := 20
	if src.Is6() {
		length = 40
	}
	packet := make([]byte, length+8)
	if src.Is4() {
		packet[0], packet[8], packet[9] = 0x45, 64, unix.IPPROTO_UDP
		binary.BigEndian.PutUint16(packet[2:], uint16(len(packet)))
		copy(packet[12:], src.AsSlice())
		copy(packet[16:], dst.AsSlice())
		binary.BigEndian.PutUint16(packet[10:], routedChecksum(packet[:20]))
	} else {
		packet[0], packet[6], packet[7] = 0x60, unix.IPPROTO_UDP, 64
		binary.BigEndian.PutUint16(packet[4:], 8)
		copy(packet[8:], src.AsSlice())
		copy(packet[24:], dst.AsSlice())
	}
	binary.BigEndian.PutUint16(packet[length:], sourcePort)
	binary.BigEndian.PutUint16(packet[length+2:], targetPort)
	binary.BigEndian.PutUint16(packet[length+4:], 8)
	if src.Is6() {
		pseudo := make([]byte, 40+8)
		copy(pseudo, src.AsSlice())
		copy(pseudo[16:], dst.AsSlice())
		binary.BigEndian.PutUint32(pseudo[32:], 8)
		pseudo[39] = unix.IPPROTO_UDP
		copy(pseudo[40:], packet[length:])
		binary.BigEndian.PutUint16(packet[length+6:], routedChecksum(pseudo))
	}
	return packet
}

// routedError quotes a live UDP flow with the original header and transport
// ports. The network stack's conntrack must recognize it as RELATED before
// either of the last two accept rules can see it.
func routedError(src, dst netip.Addr, quote []byte, kind, code byte) []byte {
	header := 20
	if src.Is6() {
		header = 40
	}
	packet := make([]byte, header+8+len(quote))
	if src.Is4() {
		packet[0], packet[8], packet[9] = 0x45, 64, unix.IPPROTO_ICMP
		binary.BigEndian.PutUint16(packet[2:], uint16(len(packet)))
		copy(packet[12:], src.AsSlice())
		copy(packet[16:], dst.AsSlice())
		binary.BigEndian.PutUint16(packet[10:], routedChecksum(packet[:20]))
	} else {
		packet[0], packet[6], packet[7] = 0x60, unix.IPPROTO_ICMPV6, 64
		binary.BigEndian.PutUint16(packet[4:], uint16(8+len(quote)))
		copy(packet[8:], src.AsSlice())
		copy(packet[24:], dst.AsSlice())
	}
	packet[header], packet[header+1] = kind, code
	copy(packet[header+8:], quote)
	if src.Is4() {
		binary.BigEndian.PutUint16(packet[header+2:], routedChecksum(packet[header:]))
	} else {
		pseudo := make([]byte, 40+len(packet)-header)
		copy(pseudo, src.AsSlice())
		copy(pseudo[16:], dst.AsSlice())
		binary.BigEndian.PutUint32(pseudo[32:], uint32(len(packet)-header))
		pseudo[39] = unix.IPPROTO_ICMPV6
		copy(pseudo[40:], packet[header:])
		binary.BigEndian.PutUint16(packet[header+2:], routedChecksum(pseudo))
	}
	return packet
}

func routedChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i:]))
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func routedCaptured(t *testing.T, fd int, src, dst netip.Addr) bool {
	t.Helper()
	source, target := src.AsSlice(), dst.AsSlice()
	until := time.Now().Add(250 * time.Millisecond)
	for time.Now().Before(until) {
		wait := int(time.Until(until).Milliseconds())
		if wait < 1 {
			wait = 1
		}
		poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		n, err := unix.Poll(poll, wait)
		if errors.Is(err, unix.EINTR) {
			// a signal, such as the runtime's preemption, ends the wait early
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			return false
		}
		var packet [2048]byte
		count, err := unix.Read(fd, packet[:])
		if err != nil {
			t.Fatal(err)
		}
		if src.Is4() && count >= 20 && packet[0]>>4 == 4 &&
			bytes.Equal(packet[12:16], source) && bytes.Equal(packet[16:20], target) {
			return true
		}
		if src.Is6() && count >= 40 && packet[0]>>4 == 6 &&
			bytes.Equal(packet[8:24], source) && bytes.Equal(packet[24:40], target) {
			return true
		}
	}
	return false
}
