// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux

package netstack

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	gvisorChecksum "gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"ranet3.com/pkgs/ranet3/internal/netnstest"
)

func verifyPeerSegment(t *testing.T, raw []byte, version int, protocol uint8) int {
	t.Helper()
	iphLen, transportLen, checksumOffset := 20, 20, 16
	if version == 6 {
		iphLen = 40
	}
	if protocol == 17 {
		transportLen, checksumOffset = 8, 6
	}
	if len(raw) < iphLen+transportLen || int(raw[0]>>4) != version {
		t.Fatalf("peer received a malformed ipv%d segment of %d bytes", version, len(raw))
	}
	if field := binary.BigEndian.Uint16(raw[iphLen+checksumOffset:]); field == 0 {
		t.Fatal("peer received a zero transport checksum")
	}
	var src, dst tcpip.Address
	if version == 4 {
		src, dst = tcpip.AddrFromSlice(raw[12:16]), tcpip.AddrFromSlice(raw[16:20])
	} else {
		src, dst = tcpip.AddrFromSlice(raw[8:24]), tcpip.AddrFromSlice(raw[24:40])
	}
	pseudo := header.PseudoHeaderChecksum(tcpip.TransportProtocolNumber(protocol), src, dst, uint16(len(raw)-iphLen))
	if got := gvisorChecksum.Checksum(raw[iphLen:], pseudo); got != 0xffff {
		t.Fatalf("peer segment checksum verifies as %#x, want 0xffff", got)
	}
	if protocol == 6 {
		transportLen = int(raw[iphLen+12]>>4) * 4
	}
	return len(raw) - iphLen - transportLen
}

func TestSegmentsSentThroughTheTUNCarryValidChecksums(t *testing.T) {
	for _, version := range []int{4, 6} {
		for _, transport := range []string{"tcp", "udp"} {
			t.Run(fmt.Sprintf("ipv%d/%s", version, transport), func(t *testing.T) {
				testOutboundChecksum(t, version, transport)
			})
		}
	}
}

func testOutboundChecksum(t *testing.T, version int, transport string) {
	t.Helper()
	netnstest.EnterEmpty(t)
	m, err := NewNamed(DefaultMTU, "sendcsum0", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	local, farAddr := checksumAddresses(version)
	if version == 4 {
		assignPeer(t, m.Name, local, farAddr)
	} else {
		assignIPv6(t, m.Name, netip.PrefixFrom(local, 64))
	}
	bits := 32
	if version == 6 {
		bits = 128
	}
	packets := make(chan []byte, 128)
	far := NewPeer("far", func(int) (BatchSealer, error) { return cloning, nil }, func(sent [][]byte) error {
		for _, raw := range sent {
			select {
			case packets <- bytes.Clone(raw):
			default:
				return fmt.Errorf("the peer packet buffer filled")
			}
		}
		return nil
	}, nil)
	t.Cleanup(far.Close)
	m.Routes.Set(netip.Prefix{}, netip.PrefixFrom(farAddr, bits), far)
	m.Routes.Set(netip.Prefix{}, netip.PrefixFrom(local, bits), Local)
	if transport == "tcp" {
		testOutboundTCP(t, m, version, local, farAddr, packets)
	} else {
		testOutboundUDP(t, version, local, farAddr, packets)
	}
}

func nextPeerPacket(t *testing.T, packets <-chan []byte) []byte {
	t.Helper()
	select {
	case raw := <-packets:
		return raw
	case <-time.After(deliveryTimeout):
		t.Fatal("the peer received no packet")
		return nil
	}
}

func testOutboundUDP(t *testing.T, version int, local, farAddr netip.Addr, packets <-chan []byte) {
	t.Helper()
	domain := unix.AF_INET
	if version == 6 {
		domain = unix.AF_INET6
	}
	fd, err := unix.Socket(domain, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_UDP, unix.UDP_SEGMENT, 512); err != nil {
		t.Fatal(err)
	}
	if version == 4 {
		if err := unix.Bind(fd, &unix.SockaddrInet4{Addr: local.As4()}); err != nil {
			t.Fatal(err)
		}
	} else {
		if err := unix.Bind(fd, &unix.SockaddrInet6{Addr: local.As16()}); err != nil {
			t.Fatal(err)
		}
	}
	payload := bytes.Repeat([]byte{0x5a}, 3*512+7)
	var address unix.Sockaddr
	if version == 4 {
		address = &unix.SockaddrInet4{Port: checksumPort, Addr: farAddr.As4()}
	} else {
		address = &unix.SockaddrInet6{Port: checksumPort, Addr: farAddr.As16()}
	}
	if err := unix.Sendto(fd, payload, 0, address); err != nil {
		t.Fatal(err)
	}
	var received, count int
	for received < len(payload) {
		raw := nextPeerPacket(t, packets)
		received += verifyPeerSegment(t, raw, version, 17)
		count++
	}
	if received != len(payload) || count < 2 {
		t.Fatalf("peer received %d bytes in %d UDP segments, want %d in multiple segments", received, count, len(payload))
	}
}

func testOutboundTCP(t *testing.T, m *Mesh, version int, local, farAddr netip.Addr, packets <-chan []byte) {
	t.Helper()
	domain := unix.AF_INET
	var source, destination unix.Sockaddr
	if version == 4 {
		source = &unix.SockaddrInet4{Port: groPort, Addr: local.As4()}
		destination = &unix.SockaddrInet4{Port: groFarPort, Addr: farAddr.As4()}
	} else {
		domain = unix.AF_INET6
		source = &unix.SockaddrInet6{Port: groPort, Addr: local.As16()}
		destination = &unix.SockaddrInet6{Port: groFarPort, Addr: farAddr.As16()}
	}
	fd, err := unix.Socket(domain, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, source); err != nil {
		t.Fatal(err)
	}
	if err := unix.Connect(fd, destination); err != unix.EINPROGRESS {
		t.Fatalf("start TCP connection: %v", err)
	}
	syn := nextPeerPacket(t, packets)
	verifyPeerSegment(t, syn, version, 6)
	iphLen := 20
	if version == 6 {
		iphLen = 40
	}
	clientSeq := binary.BigEndian.Uint32(syn[iphLen+4:])
	stream := &tcpStream{}
	checksumDelivery(t, m, version, checksumTCPPacket(stream, version, 9000, clientSeq+1, synFlag|ackFlag, nil))
	ack := nextPeerPacket(t, packets)
	verifyPeerSegment(t, ack, version, 6)
	if errCode, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR); err != nil || errCode != 0 {
		t.Fatalf("TCP handshake: socket error %d, %v", errCode, err)
	}
	payload := bytes.Repeat([]byte{0x6b}, 4*DefaultMTU)
	if n, err := unix.Write(fd, payload); err != nil || n != len(payload) {
		t.Fatalf("write TCP payload: %d of %d bytes, %v", n, len(payload), err)
	}
	var received, count int
	for received < len(payload) {
		raw := nextPeerPacket(t, packets)
		n := verifyPeerSegment(t, raw, version, 6)
		if n == 0 {
			continue
		}
		received += n
		count++
		seq := binary.BigEndian.Uint32(raw[iphLen+4:])
		checksumDelivery(t, m, version, checksumTCPPacket(stream, version, 9001, seq+uint32(n), ackFlag, nil))
	}
	if received != len(payload) || count < 2 {
		t.Fatalf("peer received %d bytes in %d TCP segments, want %d in multiple segments", received, count, len(payload))
	}
}
