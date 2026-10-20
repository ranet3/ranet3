// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux

package netstack

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
)

// the address the tests below give the tun, and the one they send to through it
var (
	tunAddress = netip.MustParseAddr("10.66.0.1")
	tunPeer    = netip.MustParseAddr("10.66.0.2")
)

// the IPv6 address the tests below give the tun, in a prefix the kernel then routes out of it, and the one they send to
var (
	tunAddress6 = netip.MustParsePrefix("fd66::1/64")
	tunPeer6    = netip.MustParseAddr("fd66::2")
)

// a steered packet carries its segment list inside the tunnel, the list going in front of the read in a buffer of the packet's own
// the device runs at link.mtu less the list, so a read as large as the device is steered whole into a packet of link.mtu
func TestTUNSteersAReadAsLargeAsTheDevice(t *testing.T) {
	enterEmptyNamespace(t)
	const largest = 9000
	exit := segAddr("3fff:1:69c:98d6::1")
	steering, err := srv6.NewSteerTable([]srv6.Steer{{
		From: schema.PrefixFrom(netip.PrefixFrom(tunAddress, 32)),
		Via:  []schema.Addr{schema.AddrFrom(exit)},
	}}, schema.MustAddr("3fff:1:69c:8c0::1"))
	if err != nil {
		t.Fatal(err)
	}
	device := largest - steering.Overhead()
	m, err := NewNamed(device, "mtutest0", nil)
	if err != nil {
		t.Fatalf("open the mesh: %v", err)
	}
	t.Cleanup(m.Close)
	m.SetSteering(steering)
	sent := &recordingPeer{}
	first := sent.peer(t, "exit")
	first.SetMTU(largest)
	m.Routes.Set(netip.Prefix{}, netip.PrefixFrom(exit, 128), first)
	assignPeer(t, m.Name, tunAddress, tunPeer)

	// a UDP datagram filling the device's MTU, under a 20 byte IPv4 and an 8 byte UDP header
	payload := bytes.Repeat([]byte("jumbo"), device)[:device-20-8]
	sendUDP(t, tunPeer, payload)
	waitUntil(t, "the steered packet to reach the peer of its first segment", func() bool { return len(sent.packets(t)) > 0 })
	packet := sent.packets(t)[0]
	if len(packet) != largest {
		t.Fatalf("the peer of the first segment was sent %d bytes, want the %d of a steered read as large as the device", len(packet), largest)
	}
	inner := packet[steering.Overhead():]
	if got := netip.AddrFrom4([4]byte(inner[16:20])); got != tunPeer || int(binary.BigEndian.Uint16(inner[2:4])) != device {
		t.Fatalf("the steered packet carries a %d byte packet to %s, want %d bytes to %s", binary.BigEndian.Uint16(inner[2:4]), got, device, tunPeer)
	}
	if !bytes.Equal(inner[20+8:], payload) {
		t.Error("the steered packet does not carry the datagram as it was sent")
	}
	if counters := m.SegmentCounters(); counters.Steered != 1 || counters.Unsteered != 0 {
		t.Errorf("the mesh counts %d packets steered and %d it could not steer, want one steered", counters.Steered, counters.Unsteered)
	}
}

// the kernel holds the MTU a mesh opens its tun at, on a device it creates and on one it attaches to, whose MTU was the kernel's default before
// and a reload moves it down and back up, read back from the kernel each time
func TestTUNHoldsTheMTUItWasOpenedAt(t *testing.T) {
	const jumbo = 9000
	for _, arm := range []struct {
		name  string
		setup func(t *testing.T)
	}{
		{"created", func(*testing.T) {}},
		{"attached", func(t *testing.T) { persistTUN(t, "mtutest0", unix.IFF_MULTI_QUEUE) }},
	} {
		t.Run(arm.name, func(t *testing.T) {
			enterEmptyNamespace(t)
			arm.setup(t)
			m, err := NewNamed(jumbo, "mtutest0", nil)
			if err != nil {
				t.Fatalf("open the mesh: %v", err)
			}
			t.Cleanup(m.Close)
			if got := linkMTU(t, m.Name); got != jumbo || m.MTU() != jumbo {
				t.Fatalf("the kernel holds %d for %s opened at %d, and the mesh reads %d", got, m.Name, jumbo, m.MTU())
			}
			for _, mtu := range []int{DefaultMTU, jumbo} {
				if err := m.CheckMTU(); err != nil {
					t.Fatalf("a move to %d on a mesh opened at %d was refused: %v", mtu, jumbo, err)
				}
				if err := m.SetMTU(mtu, nil); err != nil {
					t.Fatalf("set the mtu to %d: %v", mtu, err)
				}
				if got := linkMTU(t, m.Name); got != mtu {
					t.Fatalf("the kernel holds %d for %s after it was set to %d", got, m.Name, mtu)
				}
			}
		})
	}
}

// a read off the tun takes a packet as large as the slab promises, whatever MTU the mesh opened its device at
// a mesh opened at the default has its MTU raised to the most a tun takes after the open, as a reload raises it
// and a datagram of 8 KiB and one filling that MTU each cross the tun whole to the peer its route names
func TestTUNCarriesAReadAsLargeAsTheSlabHolds(t *testing.T) {
	const largest = 65535
	enterEmptyNamespace(t)
	m, err := NewNamed(0, "mtutest0", nil)
	if err != nil {
		t.Fatalf("open the mesh: %v", err)
	}
	t.Cleanup(m.Close)
	if err := m.CheckMTU(); err != nil {
		t.Fatalf("a move to %d on a mesh opened at the default was refused: %v", largest, err)
	}
	if err := m.SetMTU(largest, nil); err != nil {
		t.Fatalf("set the mtu to %d: %v", largest, err)
	}
	if got := linkMTU(t, m.Name); got != largest {
		t.Fatalf("the kernel holds %d for %s after it was set to %d", got, m.Name, largest)
	}
	sent := &recordingPeer{}
	peer := sent.peer(t, "peer")
	peer.SetMTU(largest)
	m.Routes.Set(netip.Prefix{}, netip.PrefixFrom(tunPeer, 32), peer)
	assignPeer(t, m.Name, tunAddress, tunPeer)
	for i, size := range []int{8 << 10, largest - 20 - 8} {
		payload := bytes.Repeat([]byte("whole"), size)[:size]
		sendUDP(t, tunPeer, payload)
		waitUntil(t, fmt.Sprintf("the %d byte datagram to reach the peer", size), func() bool { return len(sent.packets(t)) > i })
		if packet := sent.packets(t)[i]; len(packet) != 20+8+size || !bytes.Equal(packet[20+8:], payload) {
			t.Fatalf("the peer was sent %d bytes, want the %d byte datagram whole", len(packet), 20+8+size)
		}
	}
	if cut := m.TUNReadsTruncated(); cut != 0 {
		t.Errorf("%d reads were cut short", cut)
	}
}

// linkMTU is the MTU the kernel holds for the link name
// read through the standard library rather than through the code under test
func linkMTU(t *testing.T, name string) int {
	t.Helper()
	link, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatalf("look up %s: %v", name, err)
	}
	return link.MTU
}

// assignPeer gives the point-to-point link name the address local and the far end peer
// the kernel then routes peer out of the link, as it does for ip addr add local peer peer
func assignPeer(t *testing.T, name string, local, peer netip.Addr) {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open a socket to address %s with: %v", name, err)
	}
	defer unix.Close(fd)
	for _, step := range []struct {
		request uint
		address netip.Addr
	}{{unix.SIOCSIFADDR, local}, {unix.SIOCSIFDSTADDR, peer}} {
		ifr, err := unix.NewIfreq(name)
		if err != nil {
			t.Fatalf("build an ifreq for %s: %v", name, err)
		}
		if err := ifr.SetInet4Addr(step.address.AsSlice()); err != nil {
			t.Fatalf("put %s in an ifreq: %v", step.address, err)
		}
		if err := unix.IoctlIfreq(fd, step.request, ifr); err != nil {
			t.Fatalf("give %s the address %s: %v", name, step.address, err)
		}
	}
}

// sendUDP sends payload in one datagram to the discard port of to
func sendUDP(t *testing.T, to netip.Addr, payload []byte) {
	t.Helper()
	conn, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(to, 9)))
	if err != nil {
		t.Fatalf("dial %s: %v", to, err)
	}
	defer conn.Close()
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("send %d bytes to %s: %v", len(payload), to, err)
	}
}

// assignIPv6 gives link name the address of prefix, and the kernel routes the prefix out of the link
// the address goes in over netlink with IFA_F_NODAD, which the kernel never holds tentative
// any other new address stays tentative until the kernel's duplicate address detection work runs, on a tun as well
// and a socket that picks its source before then takes the link's link-local address
// the address's local route comes only with that work, IFA_F_NODAD or not, and the kernel answers once it has queued the work
// a packet to the address arriving before the route is not local, and a namespace that forwards nothing drops it
// assignIPv6 returns once the local table holds that route
func assignIPv6(t *testing.T, name string, prefix netip.Prefix) {
	t.Helper()
	link, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatalf("look up %s: %v", name, err)
	}
	// struct ifaddrmsg of include/uapi/linux/if_addr.h, then the address as its IFA_ADDRESS
	header := []byte{unix.AF_INET6, byte(prefix.Bits()), unix.IFA_F_NODAD, unix.RT_SCOPE_UNIVERSE, 0, 0, 0, 0}
	binary.NativeEndian.PutUint32(header[4:], uint32(link.Index))
	attribute := binary.NativeEndian.AppendUint16(binary.NativeEndian.AppendUint16(nil, unix.SizeofRtAttr+16), unix.IFA_ADDRESS)
	address := prefix.Addr().As16()
	if err := routeRequest(t, unix.RTM_NEWADDR, unix.NLM_F_CREATE|unix.NLM_F_EXCL, slices.Concat(header, attribute, address[:])); err != nil {
		t.Fatalf("give %s the address %s: %v", name, prefix, err)
	}
	waitUntil(t, "the local route of "+prefix.Addr().String(), func() bool { return hasLocalRoute(t, prefix.Addr()) })
}

// hasLocalRoute reports whether the local table holds the RTN_LOCAL host route of the IPv6 address
// the route that makes the kernel take a packet sent to the address as its own
func hasLocalRoute(t *testing.T, address netip.Addr) bool {
	t.Helper()
	rib, err := syscall.NetlinkRIB(syscall.RTM_GETROUTE, syscall.AF_INET6)
	if err != nil {
		t.Fatalf("dump the routes: %v", err)
	}
	messages, err := syscall.ParseNetlinkMessage(rib)
	if err != nil {
		t.Fatalf("parse the route dump: %v", err)
	}
	for _, message := range messages {
		// struct rtmsg of include/uapi/linux/rtnetlink.h, its dst_len at byte 1, its table at byte 4 and its type at byte 7
		if message.Header.Type != syscall.RTM_NEWROUTE || len(message.Data) < syscall.SizeofRtMsg ||
			message.Data[1] != 128 || message.Data[4] != unix.RT_TABLE_LOCAL || message.Data[7] != unix.RTN_LOCAL {
			continue
		}
		attributes, err := syscall.ParseNetlinkRouteAttr(&message)
		if err != nil {
			t.Fatalf("parse the attributes of a route: %v", err)
		}
		for _, attribute := range attributes {
			if attribute.Attr.Type == unix.RTA_DST && len(attribute.Value) == 16 && netip.AddrFrom16([16]byte(attribute.Value)) == address {
				return true
			}
		}
	}
	return false
}

// pathFamily is one family a sender behind the tun learns its path MTU in
// with the tun's address, the far end it sends to, the socket options that set DF on every datagram and read the path MTU back
// and header, the bytes in front of a UDP payload
type pathFamily struct {
	name                         string
	domain, level, option        int
	discover, discoverDo, header int
	local, peer                  netip.Addr
	assign                       func(t *testing.T, name string)
	address                      func(peer netip.Addr) unix.Sockaddr
}

var pathFamilies = []pathFamily{
	{"IPv4", unix.AF_INET, unix.IPPROTO_IP, unix.IP_MTU, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO, 20 + 8, tunAddress, tunPeer,
		func(t *testing.T, name string) { assignPeer(t, name, tunAddress, tunPeer) },
		func(peer netip.Addr) unix.Sockaddr { return &unix.SockaddrInet4{Port: 9, Addr: peer.As4()} }},
	{"IPv6", unix.AF_INET6, unix.IPPROTO_IPV6, unix.IPV6_MTU, unix.IPV6_MTU_DISCOVER, unix.IPV6_PMTUDISC_DO, 40 + 8, tunAddress6.Addr(), tunPeer6,
		func(t *testing.T, name string) { assignIPv6(t, name, tunAddress6) },
		func(peer netip.Addr) unix.Sockaddr { return &unix.SockaddrInet6{Port: 9, Addr: peer.As16()} }},
}

// dialDF connects a datagram socket of family to its far end with DF on every datagram
// pathMTU reads back the path MTU the kernel holds for it
// waitPathMTU waits for that to read want
func dialDF(t *testing.T, family pathFamily) (fd int, pathMTU func() int, waitPathMTU func(want int)) {
	t.Helper()
	fd, err := unix.Socket(family.domain, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open a socket: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	if err := unix.SetsockoptInt(fd, family.level, family.discover, family.discoverDo); err != nil {
		t.Fatalf("set DF on every datagram: %v", err)
	}
	if err := unix.Connect(fd, family.address(family.peer)); err != nil {
		t.Fatalf("connect to %s: %v", family.peer, err)
	}
	pathMTU = func() int {
		mtu, err := unix.GetsockoptInt(fd, family.level, family.option)
		if err != nil {
			t.Fatalf("read the path MTU: %v", err)
		}
		return mtu
	}
	waitPathMTU = func(want int) {
		t.Helper()
		got := pathMTU()
		for deadline := time.Now().Add(deliveryTimeout); got != want && time.Now().Before(deadline); got = pathMTU() {
			time.Sleep(deliveryPoll)
		}
		if got != want {
			t.Fatalf("the path MTU reads %d, want %d", got, want)
		}
	}
	return fd, pathMTU, waitPathMTU
}

// a packet past what its session carries teaches the kernel that sent it the session's MTU
// IPv4 with DF through fragmentation needed and IPv6 through packet too big, each written into the tun
// from the address the packet went to, whatever router-id the mesh holds
// and a connected socket under a device that let the packet through reads the session's MTU back as its path MTU
func TestTUNPacketTooBigTeachesTheKernel(t *testing.T) {
	const session = 1300
	for _, family := range pathFamilies {
		for _, held := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s with a router-id %t", family.name, held), func(t *testing.T) {
				enterEmptyNamespace(t)
				_, waitPathMTU := sendPastTheSession(t, family, "ptbtest0", held, session)
				waitPathMTU(session)
			})
		}
	}
}

// sendPastTheSession opens a mesh named name whose peer toward family's far end carries session bytes, holding the tun's own addresses as router-ids where held
// and sends that end one datagram with DF as large as the device's MTU from a socket that has learned no path MTU
// it returns the mesh and a wait for the path MTU that socket reads
func sendPastTheSession(t *testing.T, family pathFamily, name string, held bool, session int) (*Mesh, func(want int)) {
	t.Helper()
	m, err := NewNamed(DefaultMTU, name, nil)
	if err != nil {
		t.Fatalf("open the mesh: %v", err)
	}
	t.Cleanup(m.Close)
	m.SetAnswerTTL(64)
	if held {
		m.SetAnswerSources(AnswerSources{Router4: tunAddress, Router6: tunAddress6.Addr()})
	}
	sent := &recordingPeer{}
	peer := sent.peer(t, "peer")
	peer.SetMTU(session)
	m.Routes.Set(netip.Prefix{}, netip.PrefixFrom(family.peer, family.peer.BitLen()), peer)
	family.assign(t, m.Name)

	fd, pathMTU, waitPathMTU := dialDF(t, family)
	if got := pathMTU(); got != DefaultMTU {
		t.Fatalf("the path MTU reads %d before anything was sent, want the device's %d", got, DefaultMTU)
	}
	if _, err := unix.Write(fd, make([]byte, DefaultMTU-family.header)); err != nil {
		t.Fatalf("send a %d byte packet: %v", DefaultMTU, err)
	}
	return m, waitPathMTU
}

// reversePathChains are the match of the reverse path chain NixOS's firewall puts in prerouting, strict and loose
// as nixos/modules/services/networking/firewall-nftables.nix writes it for networking.firewall.checkReversePath
var reversePathChains = []struct{ name, match string }{
	{"strict", "fib saddr . mark . iif oif exists accept"},
	{"loose", "fib saddr . mark oif exists accept"},
}

// reversePathRuleset is NixOS's reverse path chain with match, its policy drop, and the empty chain it jumps to
func reversePathRuleset(match string) string {
	return "table inet nixos-fw {\n" +
		"\tchain rpfilter {\n" +
		"\t\ttype filter hook prerouting priority mangle + 10; policy drop;\n" +
		"\t\tmeta nfproto ipv4 udp sport . udp dport { 67 . 68, 68 . 67 } accept\n" +
		"\t\t" + match + "\n" +
		"\t\tjump rpfilter-allow\n" +
		"\t}\n" +
		"\tchain rpfilter-allow {\n" +
		"\t}\n" +
		"}\n"
}

// an answer written into the tun passes the reverse path check NixOS's firewall puts in prerouting, strict or loose
// and the sender's socket reads the session's MTU back as its path MTU, in either family with a router-id held or none
// a tun read's answer comes from the packet's destination, which the host routes out of the tun
// the host's own address would fail the lookup, which finds a local route and so no interface for the source
func TestTUNPacketTooBigPassesAReversePathCheck(t *testing.T) {
	const session = 1300
	for _, family := range pathFamilies {
		for _, chain := range reversePathChains {
			for _, held := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s under the %s chain with a router-id %t", family.name, chain.name, held), func(t *testing.T) {
					enterEmptyNamespace(t)
					nft, err := exec.LookPath("nft")
					if err != nil {
						t.Fatal("the reverse path chain is written through nft, which is not on the path")
					}
					load := exec.Command(nft, "-f", "-")
					load.Stdin = strings.NewReader(reversePathRuleset(chain.match))
					if out, err := load.CombinedOutput(); err != nil {
						t.Fatalf("load the %s reverse path chain: %v\n%s", chain.name, err, out)
					}
					m, waitPathMTU := sendPastTheSession(t, family, "rpftest0", held, session)
					waitUntil(t, "the answer to be written into the tun", func() bool { return m.TooBigAnswered() == 1 })
					waitPathMTU(session)
				})
			}
		}
	}
}

// a waypoint whose session to the next segment carries less than the headend's answers the sender behind the headend about its own packet
// IPv4 with DF with fragmentation needed and IPv6 with packet too big, back through the mesh into the headend's tun
// from the waypoint's router-id of the packet's family where it holds one
// else over IPv6 from the waypoint's SID, and over IPv4 from the address the packet went to
// the sender then holds the waypoint's session less the steering header as its path MTU
// and a datagram of that size crosses the waypoint whole to the exit
func TestTUNWaypointTeachesTheSenderBehindTheHeadend(t *testing.T) {
	const headendSession, waypointSession = 1500, 1400
	waypoint, exit := segAddr("3fff:1:69c:8c6::2"), segAddr("3fff:1:69c:98d6::1")
	for _, family := range pathFamilies {
		for _, held := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s with a router-id %t", family.name, held), func(t *testing.T) {
				enterEmptyNamespace(t)
				// no route of the headend's leads back to the router-id below, so the check of reverse paths would drop an answer from it
				// where the waypoint's router-id is announced, the route the headend learns passes that check
				if held {
					for _, path := range []string{"/proc/sys/net/ipv4/conf/all/rp_filter", "/proc/sys/net/ipv4/conf/default/rp_filter"} {
						if err := os.WriteFile(path, []byte("0"), 0); err != nil {
							t.Fatalf("set %s: %v", path, err)
						}
					}
				}
				steering, err := srv6.NewSteerTable([]srv6.Steer{{
					From: schema.PrefixFrom(netip.PrefixFrom(family.local, family.local.BitLen())),
					Via:  []schema.Addr{schema.AddrFrom(waypoint), schema.AddrFrom(exit)},
				}}, schema.MustAddr("3fff:1:69c:8c0::1"))
				if err != nil {
					t.Fatal(err)
				}
				device := headendSession - steering.Overhead()
				headend, err := NewNamed(device, "wpttest0", nil)
				if err != nil {
					t.Fatalf("open the mesh: %v", err)
				}
				t.Cleanup(headend.Close)
				headend.SetSteering(steering)
				family.assign(t, headend.Name)

				segments, err := srv6.NewLocalTable([]srv6.Segment{{SID: schema.AddrFrom(waypoint), Behavior: srv6.BehaviorEnd}}, everySource)
				if err != nil {
					t.Fatal(err)
				}
				transit := &Mesh{Name: "transit0", Routes: NewRouteTable(), closed: make(chan struct{})}
				transit.setDevice(&recordingDevice{writes: make(chan recordedWrite, 1)})
				transit.startSegmentReports()
				transit.SetSegments(segments)
				transit.SetAnswerTTL(64)
				if held {
					transit.SetAnswerSources(AnswerSources{Router4: netip.MustParseAddr("198.18.0.9"), Router6: netip.MustParseAddr("3fff:c::9")})
				}
				// a session hands what it carries to the mesh at its far end, as the peer decrypting it does
				session := func(id string, far *Mesh, mtu int) *Peer {
					peer := NewPeer(id, func(int) (BatchSealer, error) { return cloning, nil }, func(sealed [][]byte) error {
						for _, raw := range sealed {
							far.DeliverInbound(raw, mtu)
						}
						return nil
					}, nil)
					t.Cleanup(peer.Close)
					peer.SetMTU(mtu)
					return peer
				}
				headend.Routes.Set(netip.Prefix{}, netip.PrefixFrom(waypoint, 128), session("waypoint", transit, headendSession))
				transit.Routes.Set(netip.Prefix{}, netip.PrefixFrom(family.local, family.local.BitLen()), session("headend", headend, headendSession))
				exited := &recordingPeer{}
				toExit := exited.peer(t, "exit")
				toExit.SetMTU(waypointSession)
				transit.Routes.Set(netip.Prefix{}, netip.PrefixFrom(exit, 128), toExit)

				fd, pathMTU, waitPathMTU := dialDF(t, family)
				if got := pathMTU(); got != device {
					t.Fatalf("the path MTU reads %d before anything was sent, want the device's %d", got, device)
				}
				if _, err := unix.Write(fd, make([]byte, device-family.header)); err != nil {
					t.Fatalf("send a %d byte packet: %v", device, err)
				}
				learned := waypointSession - steering.Overhead()
				waitPathMTU(learned)
				// the answer left its error on the connected socket, which the next send would report in place of sending
				if _, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR); err != nil {
					t.Fatalf("take the error the answer left on the socket: %v", err)
				}
				payload := bytes.Repeat([]byte("crosses"), learned)[:learned-family.header]
				if _, err := unix.Write(fd, payload); err != nil {
					t.Fatalf("send a %d byte packet: %v", learned, err)
				}
				waitUntil(t, "the datagram the sender sent at its new path MTU to reach the exit", func() bool { return len(exited.packets(t)) > 0 })
				sent := exited.packets(t)
				if len(sent) != 1 || len(sent[0]) != waypointSession {
					t.Fatalf("the exit was sent %d packets, the first of %d bytes, want the one %d byte segment the sender's second datagram became", len(sent), len(sent[0]), waypointSession)
				}
				if inner := sent[0][steering.Overhead():]; !bytes.Equal(inner[family.header:], payload) {
					t.Error("the segment the exit was sent does not carry the datagram as it was sent")
				}
				if counters := transit.SegmentCounters(); counters.Forwarded != 1 || counters.Dropped != 1 || counters.Answered != 1 {
					t.Errorf("the waypoint counted %+v, want the first datagram dropped and answered and the second forwarded", counters)
				}
			})
		}
	}
}

// a SYN leaving through the tun has its MSS lowered to what the session to its peer carries, less the 60 bytes of IPv6 and TCP headers
// where the kernel offered what its 1400 byte device carries
func TestTUNClampsTheMSSOfASYN(t *testing.T) {
	const session = 1300
	enterEmptyNamespace(t)
	m, err := NewNamed(DefaultMTU, "msstest0", nil)
	if err != nil {
		t.Fatalf("open the mesh: %v", err)
	}
	t.Cleanup(m.Close)
	sent := &recordingPeer{}
	peer := sent.peer(t, "peer")
	peer.SetMTU(session)
	m.Routes.Set(netip.Prefix{}, netip.PrefixFrom(tunPeer6, 128), peer)
	assignIPv6(t, m.Name, tunAddress6)

	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open a socket: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	if err := unix.Connect(fd, &unix.SockaddrInet6{Port: 9, Addr: tunPeer6.As16()}); err != unix.EINPROGRESS {
		t.Fatalf("connect to %s: %v", tunPeer6, err)
	}
	waitUntil(t, "the SYN to reach the peer", func() bool { return len(sent.packets(t)) > 0 })
	if got, want := mssOf(t, sent.packets(t)[0]), session-40-20; got != want {
		t.Fatalf("the SYN carries an MSS of %d, want the %d a %d byte session carries", got, want, session)
	}
}

// mssOf is the MSS option of the IPv6 TCP SYN raw
func mssOf(t *testing.T, raw []byte) int {
	t.Helper()
	if len(raw) < 40+20 || raw[6] != 6 || raw[40+13]&0x02 == 0 {
		t.Fatalf("the peer was sent %x, which is no IPv6 TCP SYN", raw)
	}
	options := raw[40+20 : 40+int(raw[40+12]>>4)*4]
	for i := 0; i+1 < len(options) && options[i] != 0; {
		if options[i] == 1 {
			i++
			continue
		}
		if options[i] == 2 && options[i+1] == 4 {
			return int(binary.BigEndian.Uint16(options[i+2:]))
		}
		i += max(2, int(options[i+1]))
	}
	t.Fatalf("the SYN carries the options %x and no MSS among them", options)
	return 0
}
