// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"slices"
	"sync"
	"testing"

	"golang.zx2c4.com/wireguard/tun"

	"ranet3.com/pkgs/ranet3/internal/packet"
	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
)

// the two ends of the packets below, by family, the source being the one steering claims
var (
	tooBigSource      = map[int]netip.Addr{4: segAddr("10.1.0.1"), 6: segAddr("3fff:a::1")}
	tooBigDestination = map[int]netip.Addr{4: segAddr("10.2.0.9"), 6: segAddr("3fff:b::9")}
)

// steerBothFrom sends both families' sources above through segments waypoints, nil for none
func steerBothFrom(tb testing.TB, segments int) *srv6.SteerTable {
	tb.Helper()
	if segments == 0 {
		return nil
	}
	via := make([]schema.Addr, segments)
	for i := range via {
		via[i] = schema.AddrFrom(netip.AddrFrom16([16]byte{0x3f, 0xff, 0, 1, 15: byte(i + 1)}))
	}
	table, err := srv6.NewSteerTable([]srv6.Steer{
		{From: schema.PrefixFrom(netip.PrefixFrom(tooBigSource[4], 32)), Via: via},
		{From: schema.PrefixFrom(netip.PrefixFrom(tooBigSource[6], 128)), Via: via},
	}, schema.MustAddr("3fff:1:69c:8c0::1"))
	if err != nil {
		tb.Fatal(err)
	}
	return table
}

// udpPacket is a UDP packet of size bytes from source to destination, with DF when df is set on IPv4
// its payload counts up in bytes, and a byte out of place reads as another
func udpPacket(source, destination netip.Addr, size int, df bool) []byte {
	raw := make([]byte, size)
	header := 40
	if source.Is4() {
		header = 20
		raw[0] = 0x45
		binary.BigEndian.PutUint16(raw[2:], uint16(size))
		binary.BigEndian.PutUint16(raw[4:], 0x7e57)
		if df {
			raw[6] = 0x40
		}
		raw[8], raw[9] = 64, 17
		copy(raw[12:], source.AsSlice())
		copy(raw[16:], destination.AsSlice())
		binary.BigEndian.PutUint16(raw[10:], ^uint16(packet.Sum(0, raw[:header])))
	} else {
		raw[0] = 0x60
		binary.BigEndian.PutUint16(raw[4:], uint16(size-header))
		raw[6], raw[7] = 17, 64
		copy(raw[8:], source.AsSlice())
		copy(raw[24:], destination.AsSlice())
	}
	binary.BigEndian.PutUint16(raw[header:], 4000)
	binary.BigEndian.PutUint16(raw[header+2:], 5000)
	binary.BigEndian.PutUint16(raw[header+4:], uint16(size-header))
	for i := header + 8; i < size; i++ {
		raw[i] = byte(i)
	}
	return raw
}

// readOff runs classify over one read of raw on a mesh whose one peer carries mtu byte packets of every family
// it returns the read, the peer, and what the mesh wrote into its tun on the way
func readOff(tb testing.TB, raw []byte, steering *srv6.SteerTable, mtu int) (*outboundBatch, *Peer, [][]byte) {
	tb.Helper()
	dev := &recordingDevice{writes: make(chan recordedWrite, 1)}
	m := &Mesh{Name: "test0", Routes: NewRouteTable(), devs: []tun.Device{dev}, closed: make(chan struct{}),
		outboundBufferSize: tunOffset + len(raw) + steering.Overhead()}
	m.startSegmentReports()
	m.SetSteering(steering)
	peer := (&recordingPeer{}).peer("peer")
	peer.SetMTU(mtu)
	m.Routes.Set(netip.Prefix{}, segPrefix("::/0"), peer)
	m.Routes.Set(netip.Prefix{}, segPrefix("0.0.0.0/0"), peer)
	b := m.newOutboundBatch(1)
	b.sizes[0] = copy(b.bufs[0][tunOffset:], raw)
	b.n = 1
	m.classify(b)
	select {
	case write := <-dev.writes:
		return b, peer, write.packets
	default:
		return b, peer, nil
	}
}

// checkAnswer holds an answer to offending against what its family's error carries
// from the packet's destination back to its source, with mtu where the next link's MTU goes
func checkAnswer(tb testing.TB, answer, offending []byte, mtu int) {
	tb.Helper()
	if offending[0]>>4 == 6 {
		quoted := min(len(offending), srv6.MinimumIPv6MTU-40-8)
		if len(answer) != 40+8+quoted || answer[0]>>4 != 6 || answer[6] != 58 || int(binary.BigEndian.Uint16(answer[4:6])) != len(answer)-40 {
			tb.Fatalf("the answer is %d bytes, next header %d, quoting what should be %d bytes", len(answer), answer[6], quoted)
		}
		if !bytes.Equal(answer[8:24], offending[24:40]) || !bytes.Equal(answer[24:40], offending[8:24]) {
			tb.Fatalf("the answer goes from %x to %x, want from the packet's destination back to its source", answer[8:24], answer[24:40])
		}
		message := answer[40:]
		if message[0] != 2 || message[1] != 0 || int(binary.BigEndian.Uint32(message[4:8])) != mtu {
			tb.Fatalf("the answer is ICMPv6 type %d code %d carrying %d, want packet too big carrying %d", message[0], message[1], binary.BigEndian.Uint32(message[4:8]), mtu)
		}
		var pseudo [40]byte
		copy(pseudo[:], answer[8:40])
		binary.BigEndian.PutUint32(pseudo[32:], uint32(len(message)))
		pseudo[39] = 58
		if sum := packet.Sum(packet.Sum(0, pseudo[:]), message); sum != 0xffff {
			tb.Fatalf("the answer sums to %#04x as its receiver adds it up", sum)
		}
		if !bytes.Equal(message[8:], offending[:quoted]) {
			tb.Fatal("the answer does not quote the packet it is about")
		}
		return
	}
	headerLen := int(offending[0]&0x0f) * 4
	if len(answer) != 20+8+headerLen+8 || answer[9] != 1 || int(binary.BigEndian.Uint16(answer[2:4])) != len(answer) {
		tb.Fatalf("the answer is %d bytes of protocol %d, want fragmentation needed quoting %d", len(answer), answer[9], headerLen+8)
	}
	if !bytes.Equal(answer[12:16], offending[16:20]) || !bytes.Equal(answer[16:20], offending[12:16]) {
		tb.Fatalf("the answer goes from %x to %x, want from the packet's destination back to its source", answer[12:16], answer[16:20])
	}
	if sum := packet.Sum(0, answer[:20]); sum != 0xffff {
		tb.Fatalf("the answer's header sums to %#04x", sum)
	}
	message := answer[20:]
	if message[0] != 3 || message[1] != 4 || int(binary.BigEndian.Uint16(message[6:8])) != mtu {
		tb.Fatalf("the answer is ICMP type %d code %d carrying %d, want fragmentation needed carrying %d", message[0], message[1], binary.BigEndian.Uint16(message[6:8]), mtu)
	}
	if sum := packet.Sum(0, message); sum != 0xffff {
		tb.Fatalf("the answer's message sums to %#04x", sum)
	}
	if !bytes.Equal(message[8:], offending[:headerLen+8]) {
		tb.Fatal("the answer does not quote the packet's header and the 8 bytes after it")
	}
}

// answers are packets a peer's packets made this node send, and the bucket answerRefused draws from bounds them too
// a read full of packets past their session, IPv6 and IPv4 with DF in turn, gets the burst answered and no more, and nothing reaches the peer
func TestPacketsPastTheirSessionAreAnsweredAtABoundedRate(t *testing.T) {
	const flood = 64
	dev := &recordingDevice{writes: make(chan recordedWrite, flood)}
	m := &Mesh{Name: "test0", Routes: NewRouteTable(), devs: []tun.Device{dev}, closed: make(chan struct{}),
		outboundBufferSize: tunOffset + DefaultMTU}
	m.startSegmentReports()
	peer := (&recordingPeer{}).peer("peer")
	peer.SetMTU(srv6.MinimumIPv6MTU)
	m.Routes.Set(netip.Prefix{}, segPrefix("::/0"), peer)
	m.Routes.Set(netip.Prefix{}, segPrefix("0.0.0.0/0"), peer)
	b := m.newOutboundBatch(flood)
	for i := range flood {
		family := []int{4, 6}[i%2]
		b.sizes[i] = copy(b.bufs[i][tunOffset:], udpPacket(tooBigSource[family], tooBigDestination[family], DefaultMTU, true))
	}
	b.n = flood
	m.classify(b)
	if answered := len(dev.writes); answered == 0 || answered > icmpBurst {
		t.Errorf("%d packets past their session were answered %d times, want at least one and at most the burst of %d", flood, answered, icmpBurst)
	}
	if count := b.shares[peer].count; count != 0 {
		t.Errorf("%d of %d packets past their session went to the peer", count, flood)
	}
}

// a packet a read cut into fragments reaches its peer as those fragments, after the read's other packets to it
// in the read's one reservation for the peer, which counts every fragment and leaves none under a sequence number another holds
func TestReaderSendsTheFragmentsItCutToThePeer(t *testing.T) {
	dev := &scriptedDevice{reads: make(chan scriptedRead, 1), closed: make(chan struct{})}
	var mu sync.Mutex
	var sealed [][]byte
	reserved := 0
	peer := NewPeerReserved("peer", func(count int) (BatchSealer, error) {
		mu.Lock()
		defer mu.Unlock()
		reserved += count
		return func(raw [][]byte, _ []byte, out [][]byte) ([][]byte, error) {
			out = out[:0]
			for _, packet := range raw {
				out = append(out, bytes.Clone(packet))
			}
			return out, nil
		}, nil
	}, func(batch [][]byte) error {
		mu.Lock()
		defer mu.Unlock()
		sealed = append(sealed, batch...)
		return nil
	}, nil)
	t.Cleanup(peer.Close)
	peer.SetMTU(srv6.MinimumIPv6MTU)
	m := &Mesh{Name: "test0", Routes: NewRouteTable(), devs: []tun.Device{dev}, closed: make(chan struct{}),
		outboundBufferSize: tunOffset + outboundPacketBufferSize}
	m.Routes.Set(netip.Prefix{}, segPrefix("0.0.0.0/0"), peer)
	m.startOutboundPipeline()
	t.Cleanup(m.Close)

	source, destination := tooBigSource[4], tooBigDestination[4]
	first, cut, last := udpPacket(source, destination, 100, false), udpPacket(source, destination, 2000, false), udpPacket(source, destination, 200, false)
	dev.reads <- scriptedRead{packets: [][]byte{first, cut, last}}
	sent := func() ([][]byte, int) {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(sealed), reserved
	}
	waitUntil(t, "the read and the fragments cut from it to reach the peer", func() bool {
		got, _ := sent()
		return len(got) >= 4
	})
	got, places := sent()
	if len(got) != 4 || !bytes.Equal(got[0], first) || !bytes.Equal(got[1], last) {
		t.Fatalf("the peer was sent %d packets, want the two the read carried whole and then two fragments", len(got))
	}
	if data := append(bytes.Clone(got[2][20:]), got[3][20:]...); !bytes.Equal(data, cut[20:]) {
		t.Errorf("the fragments carry %d bytes that are not the %d of the packet they were cut from", len(data), len(cut)-20)
	}
	if places != len(got) {
		t.Errorf("the peer reserved %d places for the %d packets it was handed", places, len(got))
	}
}
