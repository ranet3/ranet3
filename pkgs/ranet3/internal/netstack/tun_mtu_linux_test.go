// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux

package netstack

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
)

// the address the tests below give the tun, and the one they send to through it
var (
	tunAddress = netip.MustParseAddr("10.66.0.1")
	tunPeer    = netip.MustParseAddr("10.66.0.2")
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
	m.Routes.Set(netip.Prefix{}, netip.PrefixFrom(exit, 128), sent.peer("exit"))
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
		m.Routes.Set(netip.Prefix{}, netip.PrefixFrom(tunPeer, 32), sent.peer("peer"))
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
