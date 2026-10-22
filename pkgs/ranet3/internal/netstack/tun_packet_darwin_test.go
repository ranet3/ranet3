// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin

package netstack

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// the addresses of the point-to-point link the tests below give a utun, in 198.18.0.0/15, which RFC 2544 sets aside for tests
var (
	utunLocal = netip.MustParseAddr("198.18.0.1")
	utunPeer  = netip.MustParseAddr("198.18.0.2")
)

const (
	// utunJumbo is the MTU the tests below open a utun at, and the largest packet they carry through it
	utunJumbo = 9000
	// utunSettle bounds the wait for the kernel's routes to read back as they were before the test
	utunSettle = 5 * time.Second
)

// requireUTUN skips unless the run asked for the real kernel and runs as root, which a utun and its address need
func requireUTUN(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 || os.Getenv("RANET3_DARWIN_NETTEST") != "1" {
		t.Skip("set RANET3_DARWIN_NETTEST=1 and run as root to create a utun")
	}
}

// openAddressedUTUN opens a mesh on the next free utun at utunJumbo and gives the utun utunLocal with utunPeer at its far end
// the kernel then routes utunPeer out of the utun by a host route of the address's own
// cleanup takes the address and its route off, closes the mesh, and checks that every route not on the utun reads back as it was
func openAddressedUTUN(t *testing.T) *Mesh {
	t.Helper()
	before := routesElsewhere(t, 0)
	m, err := NewNamed(utunJumbo, "", nil)
	if err != nil {
		t.Fatalf("open the mesh: %v", err)
	}
	link, err := net.InterfaceByName(m.Name)
	if err != nil {
		m.Close()
		t.Fatalf("look up %s: %v", m.Name, err)
	}
	t.Cleanup(func() {
		var after []string
		for deadline := time.Now().Add(utunSettle); ; time.Sleep(deliveryPoll) {
			if after = routesElsewhere(t, link.Index); slices.Equal(after, before) || time.Now().After(deadline) {
				break
			}
		}
		for _, gone := range missing(before, after) {
			t.Errorf("the route %s was there before the test and is not after it", gone)
		}
		for _, added := range missing(after, before) {
			t.Errorf("the route %s was not there before the test and is after it", added)
		}
	})
	t.Cleanup(m.Close)
	// struct ifaliasreq of net/if.h: the name, then the address, the far end and the mask, each a struct sockaddr_in of 16 bytes
	request := make([]byte, unix.IFNAMSIZ+3*unix.SizeofSockaddrInet4)
	copy(request, m.Name)
	for i, address := range []netip.Addr{utunLocal, utunPeer, netip.MustParseAddr("255.255.255.255")} {
		sockaddr := request[unix.IFNAMSIZ+i*unix.SizeofSockaddrInet4:]
		sockaddr[0], sockaddr[1] = unix.SizeofSockaddrInet4, unix.AF_INET
		copy(sockaddr[4:], address.AsSlice())
	}
	interfaceIoctl(t, unix.SIOCAIFADDR, request)
	t.Cleanup(func() {
		// struct ifreq: the name, then the address SIOCDIFADDR takes off with its route
		request := make([]byte, unix.IFNAMSIZ+unix.SizeofSockaddrInet4)
		copy(request, m.Name)
		request[unix.IFNAMSIZ], request[unix.IFNAMSIZ+1] = unix.SizeofSockaddrInet4, unix.AF_INET
		copy(request[unix.IFNAMSIZ+4:], utunLocal.AsSlice())
		interfaceIoctl(t, unix.SIOCDIFADDR, request)
	})
	// struct ifreq again, its union holding the interface's flags as a short
	flags := make([]byte, unix.IFNAMSIZ+unix.SizeofSockaddrInet4)
	copy(flags, m.Name)
	interfaceIoctl(t, unix.SIOCGIFFLAGS, flags)
	binary.NativeEndian.PutUint16(flags[unix.IFNAMSIZ:], binary.NativeEndian.Uint16(flags[unix.IFNAMSIZ:])|unix.IFF_UP)
	interfaceIoctl(t, unix.SIOCSIFFLAGS, flags)
	return m
}

// interfaceIoctl sends one interface request down an IPv4 datagram socket
// golang.org/x/sys/unix has no typed helper for these requests on darwin
func interfaceIoctl(t *testing.T, request uint, argument []byte) {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatalf("open a socket for an interface request: %v", err)
	}
	defer unix.Close(fd)
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(request), uintptr(unsafe.Pointer(&argument[0]))); errno != 0 {
		t.Fatalf("interface request %#x on %s: %v", request, bytes.TrimRight(argument[:unix.IFNAMSIZ], "\x00"), errno)
	}
}

// routesElsewhere is every route the kernel holds out of an interface other than index, sorted, as destination, gateway, mask and interface
// routes the kernel clones and its ARP and neighbor entries come and go on their own and are left out
func routesElsewhere(t *testing.T, index int) []string {
	t.Helper()
	rib, err := route.FetchRIB(unix.AF_UNSPEC, route.RIBTypeRoute, 0)
	if err != nil {
		t.Fatalf("dump the routing table: %v", err)
	}
	messages, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		t.Fatalf("parse the routing table: %v", err)
	}
	var routes []string
	for _, message := range messages {
		rm, ok := message.(*route.RouteMessage)
		if !ok || rm.Index == index || rm.Flags&(unix.RTF_WASCLONED|unix.RTF_LLINFO) != 0 {
			continue
		}
		entry := fmt.Sprintf("index %d", rm.Index)
		for i, addr := range rm.Addrs {
			if i > unix.RTAX_NETMASK {
				break
			}
			switch a := addr.(type) {
			case *route.Inet4Addr:
				entry += " " + netip.AddrFrom4(a.IP).String()
			case *route.Inet6Addr:
				entry += " " + netip.AddrFrom16(a.IP).String()
			case *route.LinkAddr:
				entry += fmt.Sprintf(" link#%d", a.Index)
			default:
				entry += " -"
			}
		}
		routes = append(routes, entry)
	}
	slices.Sort(routes)
	return slices.Compact(routes)
}

// missing is every entry of want that got lacks
func missing(want, got []string) []string {
	var out []string
	for _, entry := range want {
		if !slices.Contains(got, entry) {
			out = append(out, entry)
		}
	}
	return out
}

// a read off a utun hands the mesh the packet without the four-byte address family header the utun puts before it
// a datagram of one byte and one filling the utun's MTU each cross to the peer its route names whole
// creating a utun needs root, which a run does here only with RANET3_DARWIN_NETTEST=1
func TestTUNCarriesAUTUNReadWhole(t *testing.T) {
	requireUTUN(t)
	m := openAddressedUTUN(t)
	sent := &recordingPeer{}
	peer := sent.peer(t, "peer")
	peer.SetMTU(utunJumbo)
	m.Routes.Set(netip.Prefix{}, netip.PrefixFrom(utunPeer, 32), peer)
	for i, size := range []int{1, utunJumbo - 20 - 8} {
		payload := bytes.Repeat([]byte("whole"), size)[:size]
		conn, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(utunPeer, 9)))
		if err != nil {
			t.Fatalf("dial %s: %v", utunPeer, err)
		}
		_, err = conn.Write(payload)
		conn.Close()
		if err != nil {
			t.Fatalf("send %d bytes to %s: %v", size, utunPeer, err)
		}
		waitUntil(t, fmt.Sprintf("the %d byte datagram to reach the peer", size), func() bool { return len(sent.packets(t)) > i })
		packet := sent.packets(t)[i]
		if len(packet) != 20+8+size || packet[0]>>4 != 4 || netip.AddrFrom4([4]byte(packet[16:20])) != utunPeer || !bytes.Equal(packet[20+8:], payload) {
			t.Fatalf("the peer was sent %d bytes starting %x, want the %d byte datagram to %s whole", len(packet), packet[:min(len(packet), 20)], 20+8+size, utunPeer)
		}
	}
}

// a frame delivered inbound reaches a socket behind the utun with its packet whole
// the utun's write puts the four-byte address family header in the headroom before the packet, not over its first bytes
// creating a utun needs root, which a run does here only with RANET3_DARWIN_NETTEST=1
func TestTUNWritesAnInboundFrameIntoAUTUN(t *testing.T) {
	requireUTUN(t)
	m := openAddressedUTUN(t)
	m.Routes.Set(netip.Prefix{}, netip.PrefixFrom(utunLocal, 32), Local)
	socket, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(utunLocal, 0)))
	if err != nil {
		t.Fatalf("listen on %s: %v", utunLocal, err)
	}
	t.Cleanup(func() { _ = socket.Close() })
	port := socket.LocalAddr().(*net.UDPAddr).Port
	for _, size := range []int{20 + 8 + 1, utunJumbo} {
		packet := udpPacket(utunPeer, utunLocal, size, false)
		binary.BigEndian.PutUint16(packet[20+2:], uint16(port))
		m.DeliverInboundBatch(framed(packet), utunJumbo, nil)
		if err := socket.SetReadDeadline(time.Now().Add(deliveryTimeout)); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, utunJumbo)
		n, from, err := socket.ReadFromUDPAddrPort(got)
		if err != nil {
			t.Fatalf("read the %d byte packet delivered into %s: %v", size, m.Name, err)
		}
		if from.Addr() != utunPeer || !bytes.Equal(got[:n], packet[20+8:]) {
			t.Fatalf("the socket read %d bytes from %s, want the %d byte payload from %s", n, from, size-20-8, utunPeer)
		}
	}
}
