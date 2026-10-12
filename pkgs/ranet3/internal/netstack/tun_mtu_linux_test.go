// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux

package netstack

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"

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

// a steered packet carries its segment list inside the tunnel, so a read off the tun grows by the list in its own buffer
// the device runs at link.mtu less the list, and every read buffer holds link.mtu, so a read as large as the device is steered whole
// past 2 KiB is where a buffer sized for the device alone would refuse it
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
	m, err := NewNamed(device, largest, "mtutest0")
	if err != nil {
		t.Fatalf("open the mesh: %v", err)
	}
	t.Cleanup(m.Close)
	m.SetSteering(steering)
	sent := &recordingPeer{}
	first := sent.peer("exit")
	first.SetMTU(largest)
	m.Routes.Set(netip.Prefix{}, netip.PrefixFrom(exit, 128), first)
	assignPeer(t, m.Name, tunAddress, tunPeer)

	// a UDP datagram filling the device's MTU, under a 20 byte IPv4 and an 8 byte UDP header
	payload := bytes.Repeat([]byte("jumbo"), device)[:device-20-8]
	sendUDP(t, tunPeer, payload)
	waitUntil(t, "the steered packet to reach the peer of its first segment", func() bool { return len(sent.packets()) > 0 })
	packet := sent.packets()[0]
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

// a reload moves the tun's MTU down and back up within the read buffers the mesh opened with, read back from the kernel each time
// a datagram as large as the raised MTU allows then crosses the tun whole to the peer its route names
// a mesh opened at the default refuses a move past its buffers, which wireguard-go copies every read into
func TestTUNTakesAnMTUSetAfterOpening(t *testing.T) {
	const jumbo = 9000
	t.Run("opened at 9000", func(t *testing.T) {
		enterEmptyNamespace(t)
		m, err := NewNamed(jumbo, jumbo, "mtutest0")
		if err != nil {
			t.Fatalf("open the mesh: %v", err)
		}
		t.Cleanup(m.Close)
		if got := linkMTU(t, m.Name); got != jumbo {
			t.Fatalf("the kernel holds %d for %s opened at %d", got, m.Name, jumbo)
		}
		for _, mtu := range []int{DefaultMTU, jumbo} {
			if err := m.CheckMTU(mtu); err != nil {
				t.Fatalf("a move to %d on a mesh opened at %d was refused: %v", mtu, jumbo, err)
			}
			if err := m.SetMTU(mtu, nil); err != nil {
				t.Fatalf("set the mtu to %d: %v", mtu, err)
			}
			if got := linkMTU(t, m.Name); got != mtu {
				t.Fatalf("the kernel holds %d for %s after it was set to %d", got, m.Name, mtu)
			}
		}

		sent := &recordingPeer{}
		peer := sent.peer("peer")
		peer.SetMTU(jumbo)
		m.Routes.Set(netip.Prefix{}, netip.PrefixFrom(tunPeer, 32), peer)
		assignPeer(t, m.Name, tunAddress, tunPeer)
		payload := bytes.Repeat([]byte("eight kib"), 1024)[:8<<10]
		sendUDP(t, tunPeer, payload)
		waitUntil(t, "the datagram to reach the peer", func() bool { return len(sent.packets()) > 0 })
		packet := sent.packets()[0]
		if len(packet) != 20+8+len(payload) || !bytes.Equal(packet[20+8:], payload) {
			t.Fatalf("the peer was sent %d bytes, want the %d byte datagram whole", len(packet), 20+8+len(payload))
		}
	})
	t.Run("opened at the default", func(t *testing.T) {
		enterEmptyNamespace(t)
		m, err := NewNamed(0, 0, "mtutest0")
		if err != nil {
			t.Fatalf("open the mesh: %v", err)
		}
		t.Cleanup(m.Close)
		err = m.CheckMTU(jumbo)
		if err == nil {
			t.Fatalf("a move to %d on a mesh whose read buffers hold %d was taken", jumbo, outboundPacketBufferSize)
		}
		for _, want := range []string{"9000", "2048", "restart to apply"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the refusal reads %q, which does not say %s", err, want)
			}
		}
		if got := linkMTU(t, m.Name); got != DefaultMTU {
			t.Errorf("the kernel holds %d for %s, want the %d it opened at", got, m.Name, DefaultMTU)
		}
	})
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
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatalf("open route netlink: %v", err)
	}
	defer unix.Close(fd)
	// struct ifaddrmsg of include/uapi/linux/if_addr.h, then the address as its IFA_ADDRESS
	header := []byte{unix.AF_INET6, byte(prefix.Bits()), unix.IFA_F_NODAD, unix.RT_SCOPE_UNIVERSE, 0, 0, 0, 0}
	binary.NativeEndian.PutUint32(header[4:], uint32(link.Index))
	attribute := binary.NativeEndian.AppendUint16(binary.NativeEndian.AppendUint16(nil, unix.SizeofRtAttr+16), unix.IFA_ADDRESS)
	address := prefix.Addr().As16()
	message := slices.Concat(make([]byte, unix.NLMSG_HDRLEN), header, attribute, address[:])
	binary.NativeEndian.PutUint32(message[0:], uint32(len(message)))
	binary.NativeEndian.PutUint16(message[4:], unix.RTM_NEWADDR)
	binary.NativeEndian.PutUint16(message[6:], unix.NLM_F_REQUEST|unix.NLM_F_ACK|unix.NLM_F_CREATE|unix.NLM_F_EXCL)
	if err := unix.Sendto(fd, message, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		t.Fatalf("give %s the address %s: %v", name, prefix, err)
	}
	reply := make([]byte, os.Getpagesize())
	got, _, err := unix.Recvfrom(fd, reply, 0)
	if err != nil {
		t.Fatalf("read the answer to the address %s on %s: %v", prefix, name, err)
	}
	// the answer is one struct nlmsgerr, whose error is the negated errno and zero for an acknowledgment
	answers, err := syscall.ParseNetlinkMessage(reply[:got])
	if err != nil || len(answers) != 1 || answers[0].Header.Type != unix.NLMSG_ERROR || len(answers[0].Data) < 4 {
		t.Fatalf("the kernel answered the address %s on %s with %x", prefix, name, reply[:got])
	}
	if errno := unix.Errno(-int32(binary.NativeEndian.Uint32(answers[0].Data))); errno != 0 {
		t.Fatalf("give %s the address %s: %v", name, prefix, errno)
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
// IPv4 with DF through fragmentation needed and IPv6 through packet too big, each written into the tun from the address the packet went to
// and a connected socket under a device that let the packet through reads the session's MTU back as its path MTU
func TestTUNPacketTooBigTeachesTheKernel(t *testing.T) {
	const session = 1300
	for _, family := range pathFamilies {
		t.Run(family.name, func(t *testing.T) {
			enterEmptyNamespace(t)
			m, err := NewNamed(DefaultMTU, DefaultMTU, "ptbtest0")
			if err != nil {
				t.Fatalf("open the mesh: %v", err)
			}
			t.Cleanup(m.Close)
			sent := &recordingPeer{}
			peer := sent.peer("peer")
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
			waitPathMTU(session)
		})
	}
}

// a waypoint whose session to the next segment carries less than the headend's answers the sender behind the headend about its own packet
// IPv4 with DF with fragmentation needed and IPv6 with packet too big, from the address the packet went to, back through the mesh into the headend's tun
// the sender then holds the waypoint's session less the steering header as its path MTU
// and a datagram of that size crosses the waypoint whole to the exit
func TestTUNWaypointTeachesTheSenderBehindTheHeadend(t *testing.T) {
	const headendSession, waypointSession = 1500, 1400
	waypoint, exit := segAddr("3fff:1:69c:8c6::2"), segAddr("3fff:1:69c:98d6::1")
	for _, family := range pathFamilies {
		t.Run(family.name, func(t *testing.T) {
			enterEmptyNamespace(t)
			steering, err := srv6.NewSteerTable([]srv6.Steer{{
				From: schema.PrefixFrom(netip.PrefixFrom(family.local, family.local.BitLen())),
				Via:  []schema.Addr{schema.AddrFrom(waypoint), schema.AddrFrom(exit)},
			}}, schema.MustAddr("3fff:1:69c:8c0::1"))
			if err != nil {
				t.Fatal(err)
			}
			device := headendSession - steering.Overhead()
			headend, err := NewNamed(device, headendSession, "wpttest0")
			if err != nil {
				t.Fatalf("open the mesh: %v", err)
			}
			t.Cleanup(headend.Close)
			headend.SetSteering(steering)
			family.assign(t, headend.Name)

			segments, err := srv6.NewLocalTable([]srv6.Segment{{SID: schema.AddrFrom(waypoint), Behavior: srv6.BehaviorEnd}})
			if err != nil {
				t.Fatal(err)
			}
			transit := &Mesh{Name: "transit0", Routes: NewRouteTable(), devs: []tun.Device{&recordingDevice{writes: make(chan recordedWrite, 1)}}, closed: make(chan struct{})}
			transit.startSegmentReports()
			transit.SetSegments(segments)
			// a session hands what it carries to the mesh at its far end, as the peer decrypting it does
			session := func(id string, far *Mesh, mtu int) *Peer {
				peer := NewPeer(id, func(raw []byte, _ byte) ([]byte, error) { return bytes.Clone(raw), nil }, func(sealed []byte) error {
					far.DeliverInbound(sealed)
					return nil
				})
				peer.SetMTU(mtu)
				return peer
			}
			headend.Routes.Set(netip.Prefix{}, netip.PrefixFrom(waypoint, 128), session("waypoint", transit, headendSession))
			transit.Routes.Set(netip.Prefix{}, netip.PrefixFrom(family.local, family.local.BitLen()), session("headend", headend, headendSession))
			exited := &recordingPeer{}
			toExit := exited.peer("exit")
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
			waitUntil(t, "the datagram the sender sent at its new path MTU to reach the exit", func() bool { return len(exited.packets()) > 0 })
			sent := exited.packets()
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

// a SYN leaving through the tun has its MSS lowered to what the session to its peer carries, less the 60 bytes of IPv6 and TCP headers
// where the kernel offered what its 1400 byte device carries
func TestTUNClampsTheMSSOfASYN(t *testing.T) {
	const session = 1300
	enterEmptyNamespace(t)
	m, err := NewNamed(DefaultMTU, DefaultMTU, "msstest0")
	if err != nil {
		t.Fatalf("open the mesh: %v", err)
	}
	t.Cleanup(m.Close)
	sent := &recordingPeer{}
	peer := sent.peer("peer")
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
	waitUntil(t, "the SYN to reach the peer", func() bool { return len(sent.packets()) > 0 })
	if got, want := mssOf(t, sent.packets()[0]), session-40-20; got != want {
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
