// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"cmp"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"regexp"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/netnstest"
	"ranet3.com/pkgs/ranet3/internal/nftables"
	"ranet3.com/pkgs/ranet3/schema"
)

// Datagrams written into the mesh tun, which another table's notrack leaves
// untracked, each cross their own family's lines alone. One IPv6 datagram
// from a class of none in IPv6 goes on by forward's first line to IPv6's
// chain, leaves it by its class's pass and is forwarded. A second, from
// outside the class, is dropped by IPv6's screen of untracked packets from
// every source, which counts it alone. Two IPv4 datagrams go on past that
// first line to IPv4's lines in forward and are dropped by IPv4's screen,
// which counts those two alone. Every other counter of forward and of IPv6's
// chain stays at 0. Neither screen tests a family, so a datagram of the other
// family that crossed it would be counted and dropped there.
func TestForwardTakesEachFamilyAcrossItsOwnLinesAlone(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmpty(t)
	run := nftRun(t)
	const mesh, out = "ranet0", "ranetout0"
	in := benchOpenTun(t, mesh)
	leaves := benchOpenTun(t, out)
	for _, knob := range []string{"/proc/sys/net/ipv6/conf/all/forwarding", "/proc/sys/net/ipv4/ip_forward"} {
		if err := os.WriteFile(knob, []byte("1"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	netlink, err := netnstest.OpenNetlink()
	if err != nil {
		t.Fatal(err)
	}
	defer netlink.Close()
	inLink, err := net.InterfaceByName(mesh)
	if err != nil {
		t.Fatal(err)
	}
	outLink, err := net.InterfaceByName(out)
	if err != nil {
		t.Fatal(err)
	}
	// the IPv4 source's route back by the mesh tun passes reverse path filtering, strict or loose
	for _, route := range []struct {
		index  int
		prefix string
	}{{outLink.Index, "2001:db8:99::/64"}, {outLink.Index, "198.51.100.0/24"}, {inLink.Index, "192.0.2.0/24"}} {
		if err := netlink.RouteVia(route.index, netip.MustParsePrefix(route.prefix), netip.Addr{}); err != nil {
			t.Fatalf("route %s: %v", route.prefix, err)
		}
	}
	// the datagrams are untracked by another table's notrack, as a host rule makes one
	run(fmt.Sprintf(`add table inet exempt; add chain inet exempt raw { type filter hook prerouting priority raw; }; add rule inet exempt raw iifname "%s" notrack`, mesh))

	cfg := egress.Egress{Translate: []egress.Class{{From: schema.MustPrefix("3fff:a::/32"), To: egress.Translation{None: true}}}}
	rt := Runtime{Interface: mesh, Steered: true, Forwarding: func() (bool, bool) { return true, true }, Sysctl: readsNothing}
	be, err := newBackend(cfg, rt)
	if err != nil {
		t.Fatalf("open the nftables backend: %v", err)
	}
	t.Cleanup(func() { _ = be.Close() })
	tr := newTranslator(cfg, rt, be)
	if err := tr.reconcile(); err != nil {
		t.Fatalf("the first pass: %v", err)
	}
	counters := regexp.MustCompile(`(?m)^.*counter packets (\d+) bytes \d+ .*comment "([^"]*)"$`)
	// counts reads each counted line of the chain by its comment
	counts := func(chain string) (map[string]string, string) {
		listing := run("list", "chain", "inet", nftables.Table, chain)
		out := map[string]string{}
		for _, line := range counters.FindAllStringSubmatch(listing, -1) {
			out[line[2]] = line[1]
		}
		return out, listing
	}
	screen4, screen6 := "out via "+mesh+" ipv4 untracked dropped", "out via "+mesh+" ipv6 untracked dropped"
	for chain, screen := range map[string]string{LimitChain: screen4, familyChain(egress.FamilyIPv6): screen6} {
		if held, listing := counts(chain); held[screen] == "" {
			t.Fatalf("the chain %s holds no screen %q:\n%s", chain, screen, listing)
		}
	}

	member, outside := netip.MustParseAddr("3fff:a::7"), netip.MustParseAddr("2001:db8:5::7")
	to6, from4, to4 := netip.MustParseAddr("2001:db8:99::9"), netip.MustParseAddr("192.0.2.7"), netip.MustParseAddr("198.51.100.9")
	for _, datagram := range [][]byte{
		udp6(member, to6, 4000, 5000, []byte("family")),
		udp6(outside, to6, 4001, 5000, []byte("family")),
		udp4WithOptions(from4, to4, 4002, 5000, []byte("family")),
		udp4WithOptions(from4, to4, 4003, 5000, []byte("family")),
	} {
		if _, err := unix.Write(in, datagram); err != nil {
			t.Fatalf("write a datagram into %s: %v", mesh, err)
		}
	}
	// forwarded is each source a datagram left by the other tun from
	forwarded := map[netip.Addr]bool{}
	buf := make([]byte, 2048)
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		for {
			n, err := unix.Read(leaves, buf)
			if err != nil {
				break
			}
			switch {
			case n >= 40 && buf[0]>>4 == 6:
				forwarded[netip.AddrFrom16([16]byte(buf[8:24]))] = true
			case n >= 20 && buf[0]>>4 == 4:
				forwarded[netip.AddrFrom4([4]byte(buf[12:16]))] = true
			}
		}
	}
	if !forwarded[member] || forwarded[outside] || forwarded[from4] {
		t.Errorf("of the datagrams from %s, %s and %s those from %v were forwarded, want the one from %s alone", member, outside, from4, forwarded, member)
	}
	for chain, want := range map[string]map[string]string{LimitChain: {screen4: "2"}, familyChain(egress.FamilyIPv6): {screen6: "1"}} {
		held, listing := counts(chain)
		for comment, count := range held {
			if count != cmp.Or(want[comment], "0") {
				t.Errorf("the chain %s's line %q counts %s, want %s:\n%s", chain, comment, count, cmp.Or(want[comment], "0"), listing)
			}
		}
	}
}

// Two IPv4 flows from one source, forwarded by an exit that translates IPv6
// alone under a share of 1 flow, are both forwarded and the IPv6 limit counts
// neither. Each datagram carries 4 bytes of options and both share every
// header field but the ports, so the 16 bytes from offset 8 that the IPv6
// limit line would read as a source are the same in both, and forward's first
// line, which sends IPv6 alone on to IPv6's chain, and the limit line's own
// family test each keep the second from counting past the share and being
// refused. A third IPv4 datagram, which another table's notrack leaves
// untracked, is forwarded too, and IPv6's screen of untracked packets from
// every source, which tests no family, counts 0, which forward's first line
// alone keeps so.
func TestTranslatorLineLeavesTheOtherFamilysFlowsUncounted(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmpty(t)
	run := nftRun(t)
	const mesh, out = "ranet0", "ranetout0"
	in := benchOpenTun(t, mesh)
	leaves := benchOpenTun(t, out)
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}
	netlink, err := netnstest.OpenNetlink()
	if err != nil {
		t.Fatal(err)
	}
	defer netlink.Close()
	inLink, err := net.InterfaceByName(mesh)
	if err != nil {
		t.Fatal(err)
	}
	outLink, err := net.InterfaceByName(out)
	if err != nil {
		t.Fatal(err)
	}
	// the source's route back by the mesh tun passes reverse path filtering, strict or loose,
	// and the address out lets a line that wrongly masquerades the flow send it
	sources := netip.MustParsePrefix("192.0.2.0/24")
	if err := netlink.RouteVia(inLink.Index, sources, netip.Addr{}); err != nil {
		t.Fatalf("route %s: %v", sources, err)
	}
	if err := netlink.AddAddress(outLink.Index, netip.MustParsePrefix("198.51.100.1/24")); err != nil {
		t.Fatal(err)
	}
	// the third datagram is untracked by another table's notrack, as a host rule makes one
	const untracked = 4002
	run(fmt.Sprintf(`add table inet exempt; add chain inet exempt raw { type filter hook prerouting priority raw; }; add rule inet exempt raw iifname "%s" udp sport %d notrack`, mesh, untracked))

	cfg := egress.Egress{Advertise: prefixes(t, "2001:db8:1::/48"), FlowsPerSource: 1}
	rt := Runtime{Interface: mesh, Forwarding: func() (bool, bool) { return true, true }, Sysctl: readsNothing}
	be, err := newBackend(cfg, rt)
	if err != nil {
		t.Fatalf("open the nftables backend: %v", err)
	}
	t.Cleanup(func() { _ = be.Close() })
	tr := newTranslator(cfg, rt, be)
	if err := tr.reconcile(); err != nil {
		t.Fatalf("the first pass: %v", err)
	}
	limit := regexp.MustCompile(`counter packets (\d+) bytes \d+ [^\n]*comment "out via ` + mesh + ` ipv6[^"]* limit 1"`)
	listing := run("list", "chain", "inet", nftables.Table, familyChain(egress.FamilyIPv6))
	if limit.FindStringSubmatch(listing) == nil {
		t.Fatalf("IPv6's chain holds no limit of 1 flow:\n%s", listing)
	}
	screen := regexp.MustCompile(`counter packets (\d+) bytes \d+ drop comment "out via ` + mesh + ` ipv6 untracked dropped"`)
	if screen.FindStringSubmatch(listing) == nil {
		t.Fatalf("IPv6's chain holds no screen of untracked packets from every source:\n%s", listing)
	}

	from, to := netip.MustParseAddr("192.0.2.7"), netip.MustParseAddr("198.51.100.9")
	ports := []uint16{4000, 4001, untracked}
	for _, port := range ports {
		if _, err := unix.Write(in, udp4WithOptions(from, to, port, 5000, []byte("family"))); err != nil {
			t.Fatalf("write the datagram from port %d into %s: %v", port, mesh, err)
		}
	}
	forwarded := map[uint16]bool{}
	buf := make([]byte, 2048)
	for deadline := time.Now().Add(time.Second); len(forwarded) < len(ports) && time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		for {
			n, err := unix.Read(leaves, buf)
			if err != nil {
				break
			}
			if header := int(buf[0]&0x0f) * 4; n >= header+8 && buf[0]>>4 == 4 && netip.AddrFrom4([4]byte(buf[16:20])) == to {
				forwarded[binary.BigEndian.Uint16(buf[header:])] = true
			}
		}
	}
	listing = run("list", "chain", "inet", nftables.Table, familyChain(egress.FamilyIPv6))
	count, dropped := limit.FindStringSubmatch(listing), screen.FindStringSubmatch(listing)
	if len(forwarded) != len(ports) || count == nil || count[1] != "0" || dropped == nil || dropped[1] != "0" {
		t.Errorf("of the IPv4 datagrams from ports %v those from %v were forwarded, IPv6's limit counting %v and its screen of untracked packets %v:\n%s", ports, forwarded, count, dropped, listing)
	}
}

// udp4WithOptions is an IPv4 UDP datagram from source to destination carrying
// payload, its header holding 4 bytes of options (3 no-operations and the end
// of the list) and its UDP checksum left 0, which IPv4 reads as none
func udp4WithOptions(source, destination netip.Addr, sport, dport uint16, payload []byte) []byte {
	const header = 24
	p := make([]byte, header+8+len(payload))
	p[0] = 4<<4 | header/4
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	binary.BigEndian.PutUint16(p[4:], 0x5aa5)
	p[8], p[9] = 64, unix.IPPROTO_UDP
	copy(p[12:16], source.AsSlice())
	copy(p[16:20], destination.AsSlice())
	copy(p[20:24], []byte{1, 1, 1, 0})
	var sum uint32
	for i := 0; i < header; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(p[i:]))
	}
	for sum > 0xffff {
		sum = sum&0xffff + sum>>16
	}
	binary.BigEndian.PutUint16(p[10:], ^uint16(sum))
	binary.BigEndian.PutUint16(p[header:], sport)
	binary.BigEndian.PutUint16(p[header+2:], dport)
	binary.BigEndian.PutUint16(p[header+4:], uint16(8+len(payload)))
	copy(p[header+8:], payload)
	return p
}

// udp6 is an IPv6 UDP datagram from source to destination carrying payload,
// its checksum computed over the pseudo-header
func udp6(source, destination netip.Addr, sport, dport uint16, payload []byte) []byte {
	length := 8 + len(payload)
	p := make([]byte, 40+length)
	p[0] = 6 << 4
	binary.BigEndian.PutUint16(p[4:], uint16(length))
	p[6], p[7] = unix.IPPROTO_UDP, 64
	copy(p[8:24], source.AsSlice())
	copy(p[24:40], destination.AsSlice())
	binary.BigEndian.PutUint16(p[40:], sport)
	binary.BigEndian.PutUint16(p[42:], dport)
	binary.BigEndian.PutUint16(p[44:], uint16(length))
	copy(p[48:], payload)
	var sum uint32
	pseudo := append(append(append([]byte{}, p[8:40]...), byte(length>>24), byte(length>>16), byte(length>>8), byte(length)), 0, 0, 0, unix.IPPROTO_UDP)
	for _, b := range [][]byte{pseudo, p[40:]} {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(b[i:]))
		}
		if len(b)%2 == 1 {
			sum += uint32(b[len(b)-1]) << 8
		}
	}
	for sum > 0xffff {
		sum = sum&0xffff + sum>>16
	}
	binary.BigEndian.PutUint16(p[46:], ^uint16(sum))
	return p
}
