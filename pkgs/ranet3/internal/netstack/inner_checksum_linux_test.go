// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux

package netstack

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/esp"
	"ranet3.com/pkgs/ranet3/internal/netnstest"
	"ranet3.com/pkgs/ranet3/internal/packet"
)

const (
	checksumLocal4 = "192.0.2.1"
	checksumFar4   = "192.0.2.2"
	checksumLocal6 = "2001:db8:1::1"
	checksumFar6   = "2001:db8:1::2"
	checksumPort   = 5202
)

func checksumAddresses(version int) (netip.Addr, netip.Addr) {
	if version == 4 {
		return netip.MustParseAddr(checksumLocal4), netip.MustParseAddr(checksumFar4)
	}
	return netip.MustParseAddr(checksumLocal6), netip.MustParseAddr(checksumFar6)
}

func checksumSNMP(t *testing.T, protocol string, version int) uint64 {
	t.Helper()
	path := "/proc/thread-self/net/snmp"
	if protocol == "Udp" && version == 6 {
		path = "/proc/thread-self/net/snmp6"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if protocol == "Udp" && version == 6 {
		for line := range strings.Lines(string(data)) {
			fields := strings.Fields(line)
			if len(fields) == 2 && fields[0] == "Udp6InCsumErrors" {
				n, err := strconv.ParseUint(fields[1], 10, 64)
				if err != nil {
					t.Fatal(err)
				}
				return n
			}
		}
		t.Fatal("Udp6 has no InCsumErrors counter")
	}
	lines := strings.Split(string(data), "\n")
	for i := 0; i+1 < len(lines); i++ {
		names := strings.Fields(lines[i])
		values := strings.Fields(lines[i+1])
		if len(names) == len(values) && len(names) > 0 && names[0] == protocol+":" && values[0] == names[0] {
			for j, name := range names {
				if name == "InCsumErrors" {
					n, err := strconv.ParseUint(values[j], 10, 64)
					if err != nil {
						t.Fatal(err)
					}
					return n
				}
			}
		}
	}
	t.Fatalf("%s has no InCsumErrors counter", protocol)
	return 0
}

// An authenticated packet has not had its inner transport checksum checked by ESP.
func checksumDelivery(t *testing.T, mesh *Mesh, version int, raw ...[]byte) {
	t.Helper()
	key := bytes.Repeat([]byte{0x53}, 20)
	child := esp.ChildSA{EncrID: esp.ENCRAESGCM16, EncrKeyBits: 128, LocalSPI: 1, RemoteSPI: 1, InboundKey: key, OutboundKey: key}
	out, err := esp.NewOutbound(child)
	if err != nil {
		t.Fatal(err)
	}
	in, err := esp.NewInbound(child)
	if err != nil {
		t.Fatal(err)
	}
	frames := make([][]byte, 0, len(raw))
	for _, inner := range raw {
		nextHeader := byte(esp.NextHeaderIPv4)
		if version == 6 {
			nextHeader = esp.NextHeaderIPv6
		}
		ciphertext, err := out.Seal(inner, nextHeader)
		if err != nil {
			t.Fatal(err)
		}
		opened, gotHeader, err := in.Open(ciphertext)
		if err != nil || gotHeader != nextHeader || !bytes.Equal(opened, inner) {
			t.Fatalf("authenticated inner packet: header %d, error %v", gotHeader, err)
		}
		frames = append(frames, opened)
	}
	// This exercises ESP authentication and the same mesh delivery as inboundEmit, not inboundEmit's wiring.
	mesh.DeliverInboundBatch(framed(frames...), DefaultMTU, nil, nil)
}

func checksumTCPPacket(s *tcpStream, version int, seq, ack uint32, flags byte, payload []byte) []byte {
	v6 := s.segment(seq, ack, flags, nil, payload)
	if version == 6 {
		local, far := checksumAddresses(6)
		copy(v6[8:24], far.AsSlice())
		copy(v6[24:40], local.AsSlice())
		binary.BigEndian.PutUint16(v6[40+tcpChecksum:], tcpSum(v6, 40))
		return v6
	}
	raw := make([]byte, 20+len(v6)-40)
	raw[0], raw[8], raw[9] = 0x45, 64, tcpProtocol
	binary.BigEndian.PutUint16(raw[2:], uint16(len(raw)))
	local, far := checksumAddresses(4)
	copy(raw[12:16], far.AsSlice())
	copy(raw[16:20], local.AsSlice())
	binary.BigEndian.PutUint16(raw[10:], ^uint16(packet.Sum(0, raw[:20])))
	copy(raw[20:], v6[40:])
	binary.BigEndian.PutUint16(raw[20+tcpChecksum:], tcpSum(raw, 20))
	return raw
}

func checksumUDP(version, value int) []byte {
	local, far := checksumAddresses(version)
	iphLen := 20
	if version == 6 {
		iphLen = 40
	}
	raw := make([]byte, iphLen+8+8)
	if version == 4 {
		raw[0], raw[8], raw[9] = 0x45, 64, 17
		binary.BigEndian.PutUint16(raw[2:], uint16(len(raw)))
		copy(raw[12:16], far.AsSlice())
		copy(raw[16:20], local.AsSlice())
		binary.BigEndian.PutUint16(raw[10:], ^uint16(packet.Sum(0, raw[:20])))
	} else {
		raw[0], raw[6], raw[7] = 0x60, 17, 64
		binary.BigEndian.PutUint16(raw[4:], uint16(len(raw)-40))
		copy(raw[8:24], far.AsSlice())
		copy(raw[24:40], local.AsSlice())
	}
	udp := raw[iphLen:]
	binary.BigEndian.PutUint16(udp, 40002)
	binary.BigEndian.PutUint16(udp[2:], checksumPort)
	binary.BigEndian.PutUint16(udp[4:], uint16(len(udp)))
	for i := 8; i < len(udp); i++ {
		udp[i] = byte(value)
	}
	sum := ^uint16(packet.Sum(pseudoSum(raw, iphLen, 17), udp))
	if sum == 0 {
		sum = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:], sum)
	return raw
}

func TestValidUDPGROCoalescesIntoOneTUNPacket(t *testing.T) {
	for _, version := range []int{4, 6} {
		t.Run(fmt.Sprintf("ipv%d", version), func(t *testing.T) {
			m := checksumMesh(t, version)
			sock := checksumUDPListener(t, version)
			checksumUDPGROWitness(t, m, sock, version)
		})
	}
}

func TestBadInnerChecksumNeverReachesASocket(t *testing.T) {
	for _, version := range []int{4, 6} {
		for _, protocol := range []string{"Tcp", "Udp"} {
			for _, badAt := range []int{-1, 0, 1, 2} {
				t.Run(fmt.Sprintf("ipv%d/%s/bad%d", version, protocol, badAt), func(t *testing.T) {
					testBadInnerChecksum(t, version, protocol, badAt)
				})
			}
		}
	}
}

func testBadInnerChecksum(t *testing.T, version int, protocol string, badAt int) {
	t.Helper()
	m := checksumMesh(t, version)
	_, farAddr := checksumAddresses(version)
	before := checksumSNMP(t, protocol, version)
	if protocol == "Udp" {
		checksumUDPDelivery(t, m, version, badAt)
	} else {
		checksumTCPDelivery(t, m, version, badAt, farAddr)
	}
	waitUntil(t, "the bad checksum counter", func() bool { return checksumSNMP(t, protocol, version) >= before+1 })
	if got := checksumSNMP(t, protocol, version); got != before+1 {
		t.Fatalf("%s InCsumErrors rose by %d, want 1", protocol, got-before)
	}
}

func checksumMesh(t *testing.T, version int) *Mesh {
	t.Helper()
	netnstest.EnterEmpty(t)
	m, err := NewNamed(DefaultMTU, "csumtest0", false, nil)
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
	m.Routes.Set(netip.Prefix{}, netip.PrefixFrom(local, bits), Local)
	return m
}

func checksumUDPListener(t *testing.T, version int) *net.UDPConn {
	t.Helper()
	local, _ := checksumAddresses(version)
	network := "udp4"
	if version == 6 {
		network = "udp6"
	}
	sock, err := net.ListenUDP(network, net.UDPAddrFromAddrPort(netip.AddrPortFrom(local, checksumPort)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sock.Close() })
	return sock
}

func checksumUDPGROWitness(t *testing.T, m *Mesh, sock *net.UDPConn, version int) {
	t.Helper()
	before := tunPackets(t, m.Name, receivedPackets)
	checksumDelivery(t, m, version, checksumUDP(version, 81), checksumUDP(version, 82))
	buf := make([]byte, 8)
	for _, value := range []byte{81, 82} {
		if err := sock.SetReadDeadline(time.Now().Add(deliveryTimeout)); err != nil {
			t.Fatal(err)
		}
		n, _, err := sock.ReadFromUDP(buf)
		if err != nil || n != len(buf) || !bytes.Equal(buf, bytes.Repeat([]byte{value}, len(buf))) {
			t.Fatalf("good UDP control value %d: read %d bytes, %v", value, n, err)
		}
	}
	if written := tunPackets(t, m.Name, receivedPackets) - before; written != 1 {
		t.Fatalf("two valid UDP datagrams used %d TUN receive packets, want one coalesced packet", written)
	}
}

func checksumUDPDelivery(t *testing.T, m *Mesh, version, badAt int) {
	t.Helper()
	sock := checksumUDPListener(t, version)
	if badAt >= 0 {
		checksumUDPGROWitness(t, m, sock, version)
	}
	count, index := 3, badAt
	if badAt < 0 {
		count, index = 1, 0
	}
	packets := make([][]byte, count)
	for i := range packets {
		packets[i] = checksumUDP(version, i+1)
	}
	packets[index][len(packets[index])-1] ^= 1
	checksumDelivery(t, m, version, packets...)
	var received []byte
	buf := make([]byte, 32)
	for range count - 1 {
		if err := sock.SetReadDeadline(time.Now().Add(deliveryTimeout)); err != nil {
			t.Fatal(err)
		}
		n, _, err := sock.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("good datagram not received: %v", err)
		}
		received = append(received, buf[:n]...)
	}
	var want []byte
	for i := range count {
		if i != index {
			want = append(want, bytes.Repeat([]byte{byte(i + 1)}, 8)...)
		}
	}
	if !bytes.Equal(received, want) {
		t.Fatalf("socket read %x, want %x", received, want)
	}
	if err := sock.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if n, _, err := sock.ReadFromUDP(buf); err == nil {
		t.Fatalf("bad datagram reached the socket with %d bytes", n)
	} else {
		var networkError net.Error
		if !errors.As(err, &networkError) || !networkError.Timeout() {
			t.Fatalf("read the socket after the good datagrams: %v", err)
		}
	}
}

func checksumTCPDelivery(t *testing.T, m *Mesh, version, badAt int, farAddr netip.Addr) {
	t.Helper()
	local, _ := checksumAddresses(version)
	network := "tcp4"
	if version == 6 {
		network = "tcp6"
	}
	listener, err := net.ListenTCP(network, net.TCPAddrFromAddrPort(netip.AddrPortFrom(local, groPort)))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	stream := &tcpStream{}
	far := NewPeer("far", func(int) (BatchSealer, error) { return cloning, nil }, func(sent [][]byte) error {
		if version == 4 {
			for i, raw := range sent {
				if len(raw) >= 40 && raw[0]>>4 == 4 {
					v6 := make([]byte, 40+len(raw)-20)
					v6[0], v6[6] = 0x60, tcpProtocol
					copy(v6[40:], raw[20:])
					sent[i] = v6
				}
			}
		}
		stream.observe(sent)
		return nil
	}, nil)
	defer far.Close()
	bits := 32
	if version == 6 {
		bits = 128
	}
	m.Routes.Set(netip.Prefix{}, netip.PrefixFrom(farAddr, bits), far)
	const iss = 7000
	checksumDelivery(t, m, version, checksumTCPPacket(stream, version, iss, 0, synFlag, nil))
	waitUntil(t, "the kernel's SYN-ACK", func() bool { _, synAck := stream.acknowledged(); return synAck })
	stream.mu.Lock()
	ack := stream.rcvNxt
	stream.mu.Unlock()
	checksumDelivery(t, m, version, checksumTCPPacket(stream, version, iss+1, ack, ackFlag, nil))
	count, index := 3, badAt
	if badAt < 0 {
		count, index = 1, 0
	}
	read := make(chan error, 1)
	go func() { read <- readStream(listener, count*256) }()
	packets := make([][]byte, count)
	for i := range packets {
		packets[i] = checksumTCPPacket(stream, version, iss+1+uint32(i*256), ack, ackFlag, streamBytes(i*256, 256))
	}
	good := bytes.Clone(packets[index])
	packets[index][len(packets[index])-1] ^= 1
	checksumDelivery(t, m, version, packets...)
	checksumDelivery(t, m, version, good)
	waitUntil(t, "the retransmitted stream to be acknowledged", func() bool { n, _ := stream.acknowledged(); return n == uint32(iss+1+count*256) })
	select {
	case err := <-read:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(deliveryTimeout):
		t.Fatal("the socket never read the retransmitted stream")
	}
}
