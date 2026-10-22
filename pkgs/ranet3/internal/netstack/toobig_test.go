// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"testing"

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

// withOptions is raw, an IPv4 packet, with options after its fixed header, its header length, total length and checksum following them
func withOptions(raw, options []byte) []byte {
	out := slices.Concat(raw[:20], options, raw[20:])
	headerLen := 20 + len(options)
	out[0] = 4<<4 | byte(headerLen/4)
	binary.BigEndian.PutUint16(out[2:], uint16(len(out)))
	binary.BigEndian.PutUint16(out[10:], 0)
	binary.BigEndian.PutUint16(out[10:], ^uint16(packet.Sum(0, out[:headerLen])))
	return out
}

// misframed is an IPv4 packet of DefaultMTU bytes without DF, with a Record Route claiming 9 bytes in a list of 4
// which Linux's ip_options_compile refuses at the option's type octet, octet 20 of the header
var misframed = withOptions(udpPacket(tooBigSource[4], tooBigDestination[4], DefaultMTU-4, false), []byte{7, 9, 4, 0})

var routerIDs = map[int]netip.Addr{4: segAddr("100.64.0.1"), 6: segAddr("3fff:c::1")}

func holding(held map[int]bool) AnswerSources {
	var sources AnswerSources
	if held[4] {
		sources.Router4 = routerIDs[4]
	}
	if held[6] {
		sources.Router6 = routerIDs[6]
	}
	return sources
}

// readOff runs classify over one read of raw on a mesh whose one peer carries mtu byte packets of every family, holding sources as its router-ids and answer SID
// it returns the read, the peer, and what the mesh wrote into its tun on the way
func readOff(tb testing.TB, raw []byte, steering *srv6.SteerTable, mtu int, sources AnswerSources) (*outboundBatch, *Peer, [][]byte) {
	tb.Helper()
	dev := &recordingDevice{writes: make(chan recordedWrite, 1)}
	m := &Mesh{Name: "test0", Routes: NewRouteTable(), closed: make(chan struct{})}
	m.setDevice(dev)
	m.startSegmentReports()
	m.SetSteering(steering)
	m.SetAnswerSources(sources)
	m.SetAnswerTTL(64)
	peer := (&recordingPeer{}).peer(tb, "peer")
	peer.SetMTU(mtu)
	m.Routes.Set(netip.Prefix{}, segPrefix("::/0"), peer)
	m.Routes.Set(netip.Prefix{}, segPrefix("0.0.0.0/0"), peer)
	b := newOutboundBatch(1)
	fill(b, raw)
	m.classify(b)
	select {
	case write := <-dev.writes:
		return b, peer, write.packets
	default:
		return b, peer, nil
	}
}

// checkAnswer holds an answer to offending against what its family's error carries
// from the address from back to the packet's source, with mtu where the next link's MTU goes
// quoting as much of the packet as fits 1280 bytes over IPv6, RFC 4443 section 2.4 (c), and 576 over IPv4, RFC 1812 section 4.3.2.3
func checkAnswer(tb testing.TB, answer, offending []byte, mtu int, from netip.Addr) {
	tb.Helper()
	if offending[0]>>4 == 6 {
		checkICMPv6(tb, answer, offending, from, 2, 0, uint32(mtu))
		return
	}
	// fragmentation needed, RFC 1191 section 4, carries the MTU in the low half of the word
	checkICMPv4(tb, answer, offending, from, 3, 4, uint32(mtu))
}

// checkICMPv6 holds answer to offending, an IPv6 packet, against the ICMPv6 error of kind and code carrying rest in the word after its checksum
// from the address from back to the packet's source, quoting as much of the packet as fits 1280 bytes, RFC 4443 section 2.4 (c)
func checkICMPv6(tb testing.TB, answer, offending []byte, from netip.Addr, kind, code byte, rest uint32) {
	tb.Helper()
	quoted := min(len(offending), srv6.MinimumIPv6MTU-40-8)
	if len(answer) != 40+8+quoted || answer[0]>>4 != 6 || answer[6] != 58 || int(binary.BigEndian.Uint16(answer[4:6])) != len(answer)-40 {
		tb.Fatalf("the answer is %d bytes, next header %d, quoting what should be %d bytes", len(answer), answer[6], quoted)
	}
	if !bytes.Equal(answer[8:24], from.AsSlice()) || !bytes.Equal(answer[24:40], offending[8:24]) {
		tb.Fatalf("the answer goes from %x to %x, want from %s back to the packet's source", answer[8:24], answer[24:40], from)
	}
	message := answer[40:]
	if message[0] != kind || message[1] != code || binary.BigEndian.Uint32(message[4:8]) != rest {
		tb.Fatalf("the answer is ICMPv6 type %d code %d carrying %#08x, want type %d code %d carrying %#08x", message[0], message[1], binary.BigEndian.Uint32(message[4:8]), kind, code, rest)
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
}

// checkICMPv4 holds answer to offending, an IPv4 packet, against the ICMP error of kind and code carrying rest in the word after its checksum
// from the address from back to the packet's source, quoting as much of the packet as fits 576 bytes, RFC 1812 section 4.3.2.3
func checkICMPv4(tb testing.TB, answer, offending []byte, from netip.Addr, kind, code byte, rest uint32) {
	tb.Helper()
	quoted := min(len(offending), 576-20-8)
	if len(answer) != 20+8+quoted || answer[9] != 1 || int(binary.BigEndian.Uint16(answer[2:4])) != len(answer) {
		tb.Fatalf("the answer is %d bytes of protocol %d, want ICMP type %d quoting %d", len(answer), answer[9], kind, quoted)
	}
	if !bytes.Equal(answer[12:16], from.AsSlice()) || !bytes.Equal(answer[16:20], offending[12:16]) {
		tb.Fatalf("the answer goes from %x to %x, want from %s back to the packet's source", answer[12:16], answer[16:20], from)
	}
	if sum := packet.Sum(0, answer[:20]); sum != 0xffff {
		tb.Fatalf("the answer's header sums to %#04x", sum)
	}
	message := answer[20:]
	if message[0] != kind || message[1] != code || binary.BigEndian.Uint32(message[4:8]) != rest {
		tb.Fatalf("the answer is ICMP type %d code %d carrying %#08x, want type %d code %d carrying %#08x", message[0], message[1], binary.BigEndian.Uint32(message[4:8]), kind, code, rest)
	}
	if sum := packet.Sum(0, message); sum != 0xffff {
		tb.Fatalf("the answer's message sums to %#04x", sum)
	}
	if !bytes.Equal(message[8:], offending[:quoted]) {
		tb.Fatal("the answer does not quote the packet it is about")
	}
}

// checkFragments holds the packets a session of mtu bytes was sent in place of inner, an IPv4 packet too large for it
// each fits mtu and goes behind header, empty or an IPv6 header whose payload length then counts what follows it
// each is an IPv4 packet from inner's source to its destination under inner's identification, its header summing as its receiver checks it
// and in order they carry inner's data, each at the offset its header names, with MF on all but the last, RFC 791 section 3.1
func checkFragments(tb testing.TB, sent [][]byte, header, inner []byte, mtu int) {
	tb.Helper()
	if len(sent) < 2 {
		tb.Fatalf("a %d byte packet past a %d byte session was sent as %d packets, want its fragments", len(inner), mtu, len(sent))
	}
	data, at := inner[20:], 0
	for i, raw := range sent {
		if len(raw) > mtu || len(raw) < len(header)+20 {
			tb.Fatalf("fragment %d is %d bytes behind a %d byte header, against a %d byte session", i, len(raw), len(header), mtu)
		}
		want := bytes.Clone(header)
		if len(header) != 0 {
			binary.BigEndian.PutUint16(want[4:], uint16(len(raw)-40))
		}
		if !bytes.Equal(raw[:len(header)], want) {
			tb.Fatalf("fragment %d goes behind %x, want %x", i, raw[:len(header)], want)
		}
		cut := raw[len(header):]
		if !bytes.Equal(cut[12:20], inner[12:20]) || int(binary.BigEndian.Uint16(cut[2:4])) != len(cut) {
			tb.Fatalf("fragment %d is a %d byte packet from %x claiming %d bytes", i, len(cut), cut[12:20], binary.BigEndian.Uint16(cut[2:4]))
		}
		if sum := packet.Sum(0, cut[:20]); sum != 0xffff || !bytes.Equal(cut[4:6], inner[4:6]) {
			tb.Fatalf("fragment %d carries the identification %x under a header summing to %#04x, want the packet's %x under one summing to 0xffff", i, cut[4:6], sum, inner[4:6])
		}
		// the offset counts 8 byte units, and MF is the flag below DF
		field, more := binary.BigEndian.Uint16(cut[6:8]), i < len(sent)-1
		if int(field&0x1fff)*8 != at || (field&0x2000 != 0) != more {
			tb.Fatalf("fragment %d holds the flags and offset %#04x, want offset %d with MF %t", i, field, at, more)
		}
		if end := at + len(cut) - 20; end > len(data) || !bytes.Equal(cut[20:], data[at:end]) {
			tb.Fatalf("fragment %d carries %d bytes at offset %d that are not the packet's", i, len(cut)-20, at)
		}
		at += len(cut) - 20
	}
	if at != len(data) {
		tb.Fatalf("%d fragments carry %d bytes of data, want the packet's %d", len(sent), at, len(data))
	}
}

// the segments a waypoint test sends a packet through, this node's End first, from the address the packet was steered from
var (
	thisWaypoint = segAddr("3fff:1:69c:8c6::2")
	steeredFrom  = segAddr("3fff:1:69c:8c0::1")
)

// waypointOf is a mesh acting on thisWaypoint, which sends what goes on to after through session
// sender records what goes back to the sources the packets above come from
func waypointOf(tb testing.TB, after netip.Addr, session *Peer) (*Mesh, *recordingPeer) {
	tb.Helper()
	table, err := srv6.NewLocalTable([]srv6.Segment{{SID: schema.AddrFrom(thisWaypoint), Behavior: srv6.BehaviorEnd}}, everySource)
	if err != nil {
		tb.Fatal(err)
	}
	m := &Mesh{Routes: NewRouteTable()}
	m.startSegmentReports()
	m.SetSegments(table)
	m.SetAnswerTTL(64)
	m.Routes.Set(netip.Prefix{}, netip.PrefixFrom(after, 128), session)
	sender := &recordingPeer{}
	back := sender.peer(tb, "sender")
	for _, source := range tooBigSource {
		m.Routes.Set(netip.Prefix{}, netip.PrefixFrom(source, source.BitLen()), back)
	}
	return m, sender
}

// sessionOf is a peer carrying mtu byte packets, and what it was sent
func sessionOf(tb testing.TB, mtu int) (*Peer, *recordingPeer) {
	sent := &recordingPeer{}
	peer := sent.peer(tb, "next")
	peer.SetMTU(mtu)
	return peer, sent
}

// steeredThrough is inner as the node at steeredFrom steers it through path, which starts at thisWaypoint
func steeredThrough(tb testing.TB, inner []byte, path ...netip.Addr) []byte {
	tb.Helper()
	outer, err := srv6.Encapsulate(inner, steeredFrom, append([]netip.Addr{thisWaypoint}, path...))
	if err != nil {
		tb.Fatal(err)
	}
	return outer
}

// headerShape describes the headers a segment carries around its routing header beside the segment list
// front names the extension headers in front of the routing header in order, RFC 8200 section 4.1
// and tlv is the bytes of TLVs after the segment list, a multiple of 8, RFC 8754 section 2.1
type headerShape struct {
	front []byte
	tlv   int
}

// the extension headers RFC 8200 section 4.1 allows in front of a routing header
const (
	hopByHop           = 0
	destinationOptions = 60
)

// size is the bytes the shape puts into a segment
func (s headerShape) size() int { return 8*len(s.front) + s.tlv }

// around is outer, whose routing header follows its fixed header, with the shape's headers put in and its payload length counting them
// each header in front is 8 bytes holding one PadN option, RFC 8200 section 4.2, and each TLV is a PadN of 2 bytes, RFC 8754 section 2.1.1.2
func (s headerShape) around(outer []byte) []byte {
	routing := 8 + 8*int(outer[41])
	var front []byte
	next := outer[6]
	for _, kind := range slices.Backward(s.front) {
		front = append([]byte{next, 0, 1, 4, 0, 0, 0, 0}, front...)
		next = kind
	}
	out := slices.Concat(outer[:40], front, outer[40:40+routing], bytes.Repeat([]byte{4, 2, 0, 0}, s.tlv/4), outer[40+routing:])
	out[6] = next
	out[40+len(front)+1] += byte(s.tlv / 8)
	binary.BigEndian.PutUint16(out[4:], uint16(len(out)-40))
	return out
}

// emptyBuckets spends the buckets of the sources the packets above come from, leaving the node's cap all but full
func emptyBuckets(tb testing.TB, m *Mesh) {
	tb.Helper()
	for _, source := range tooBigSource {
		for range icmpSourceBurst {
			if !m.takeICMPToken(source) {
				tb.Fatalf("a fresh bucket of %s held fewer than %d answers", source, icmpSourceBurst)
			}
		}
	}
}

// a waypoint answers the segments too large for the session to their next segment under the node's cap alone
// a flood of them, carrying IPv6 and IPv4 with DF in turn from sources whose buckets other errors emptied, gets as many answers as the cap holds, of both families
// the cap withholds the rest and no source's bucket any
// and each answer goes to the source of the packet the segment carries rather than to the node that steered it
func TestSegmentsPastTheirNextSessionAreAnsweredUnderTheCapAlone(t *testing.T) {
	const flood, left = 64, 10
	after := segAddr("3fff:1:69c:98d6::1")
	session, next := sessionOf(t, srv6.MinimumIPv6MTU+srv6.Overhead(2))
	m, sender := waypointOf(t, after, session)
	emptyBuckets(t, m)
	capHolding(m, left)
	batch := make([][]byte, flood)
	for i := range batch {
		family := []int{4, 6}[i%2]
		batch[i] = steeredThrough(t, udpPacket(tooBigSource[family], tooBigDestination[family], DefaultMTU, true), after)
	}
	if left, _ := m.applySegments(framed(batch...), DefaultMTU); len(left) != 0 {
		t.Fatalf("%d segments reached the tun", len(left))
	}
	answers := sender.packets(t)
	if len(answers) != left {
		t.Errorf("%d segments past their next session were answered %d times with %d answers left in the cap, want %d", flood, len(answers), left, left)
	}
	if source, node := m.ICMPWithheld(); source != 0 || node != flood-left {
		t.Errorf("the limits withheld %d answers by source and %d by the node's cap, want 0 and %d", source, node, flood-left)
	}
	to4 := 0
	for i, answer := range answers {
		_, to, _ := packet.Addrs(answer)
		if to != tooBigSource[4] && to != tooBigSource[6] {
			t.Errorf("answer %d goes to %s, want the source of the packet the segment carries", i, to)
		}
		if to.Is4() {
			to4++
		}
	}
	if to4 != left/2 {
		t.Errorf("%d of %d answers carry fragmentation needed, want half, since the families take turns", to4, len(answers))
	}
	if sent := next.packets(t); len(sent) != 0 {
		t.Errorf("%d of %d segments past their next session went on to it", len(sent), flood)
	}
	if counters := m.SegmentCounters(); counters.Dropped != flood || counters.Answered != uint64(len(answers)) || counters.Forwarded != 0 {
		t.Errorf("the waypoint counted %+v for %d segments it answered %d of", counters, flood, len(answers))
	}
	if got := m.TooBigAnswered(); got != uint64(len(answers)) {
		t.Errorf("the waypoint counted %d answers sent, want the %d its sources were sent", got, len(answers))
	}
}

// an answer to a segment past its next session counts as sent once the session back to the source of the packet it carries has queued it
// a waypoint with no route back, or whose session back has a full budget or has closed, builds an answer that goes nowhere and counts none
func TestTooBigAnswerCountsOnlyOnceQueued(t *testing.T) {
	after := segAddr("3fff:1:69c:98d6::1")
	source, destination := tooBigSource[6], tooBigDestination[6]
	for _, test := range []struct {
		name string
		back func(t *testing.T, m *Mesh)
	}{
		{"no route back", func(t *testing.T, m *Mesh) {
			m.Routes.Remove(netip.Prefix{}, netip.PrefixFrom(source, 128))
		}},
		{"a session back with a full budget", func(t *testing.T, m *Mesh) {
			back, _ := reservingPeer(t)
			if back.reserveBatchNow(1, peerDataBudget) == nil {
				t.Fatal("an empty budget refused a read of all of it")
			}
			m.Routes.Set(netip.Prefix{}, netip.PrefixFrom(source, 128), back)
		}},
		{"a session back that closed", func(t *testing.T, m *Mesh) {
			back, _ := reservingPeer(t)
			back.Close()
			m.Routes.Set(netip.Prefix{}, netip.PrefixFrom(source, 128), back)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			session, _ := sessionOf(t, srv6.MinimumIPv6MTU+srv6.Overhead(2))
			m, _ := waypointOf(t, after, session)
			test.back(t, m)
			m.applySegments(framed(steeredThrough(t, udpPacket(source, destination, DefaultMTU, false), after)), DefaultMTU)
			if got, counters := m.TooBigAnswered(), m.SegmentCounters(); got != 0 || counters.Answered != 0 || counters.Dropped != 1 {
				t.Errorf("the waypoint counted %d answers sent and %+v for a segment whose answer had nowhere to go", got, counters)
			}
		})
	}
}

// a segment too large for its next session is answered only about the IP packet its routing header names
// a whole packet behind a header naming none, a transport, hop-by-hop or the other family is dropped with no answer
// since nothing says those bytes are a packet with a source to tell
// and so is a tail that is no whole IP packet behind a header naming either family or hop-by-hop
// shorter than an IPv4 or an IPv6 header, or claiming a length it does not have, where reading it as a packet runs past its end
func TestSegmentPastItsNextSessionIsAnsweredOnlyAboutThePacketItsHeaderNames(t *testing.T) {
	after := segAddr("3fff:1:69c:98d6::1")
	// next is the routing header's next header, RFC 8754 section 2, and behind what follows the routing header
	// a segment steered with a whole packet carries it, and any other is steered with an IPv6 one of which only behind is left
	type carried struct {
		next   byte
		behind []byte
		whole  bool
	}
	whole := map[int][]byte{4: udpPacket(tooBigSource[4], tooBigDestination[4], DefaultMTU, true), 6: udpPacket(tooBigSource[6], tooBigDestination[6], DefaultMTU, false)}
	cases := []carried{{59, whole[6], true}, {17, whole[6], true}, {hopByHop, whole[6], true}, {4, whole[6], true}, {59, whole[4], true}, {hopByHop, whole[4], true}, {41, whole[4], true}}
	// each tail starts as its family's header does, the IPv4 ones with DF
	short4, short6 := whole[4][:16], whole[6][:32]
	claims4, claims6 := bytes.Clone(whole[4][:24]), bytes.Clone(whole[6][:48])
	binary.BigEndian.PutUint16(claims4[2:], 40)
	binary.BigEndian.PutUint16(claims6[4:], 100)
	for _, next := range []byte{hopByHop, 4, 41} {
		for _, tail := range [][]byte{short4, claims4, short6, claims6} {
			cases = append(cases, carried{next, tail, false})
		}
	}
	for _, c := range cases {
		session, sent := sessionOf(t, srv6.MinimumIPv6MTU+srv6.Overhead(2))
		m, sender := waypointOf(t, after, session)
		var outer []byte
		if c.whole {
			outer = steeredThrough(t, c.behind, after)
		} else {
			// the routing header grows by TLVs of padding until only the tail follows it, which keeps the segment past its session
			outer = steeredThrough(t, whole[6], after)
			list := 40 + 8 + 16*2
			copy(outer[list:], bytes.Repeat([]byte{4, 2, 0, 0}, (len(outer)-len(c.behind)-list)/4))
			outer[41] = byte((len(outer) - len(c.behind) - 48) / 8)
			copy(outer[len(outer)-len(c.behind):], c.behind)
		}
		outer[40] = c.next
		// no room past its end, so a read past the tail fails rather than finds spare capacity
		if left, _ := m.applySegments(framed(outer), DefaultMTU); len(left) != 0 {
			t.Fatalf("%d segments reached the tun", len(left))
		}
		if answers, forwarded := sender.packets(t), sent.packets(t); len(answers) != 0 || len(forwarded) != 0 {
			t.Errorf("a segment naming %d in front of %d bytes starting %x past its next session was answered %d times and went on as %d packets", c.next, len(c.behind), c.behind[:8], len(answers), len(forwarded))
		}
		if counters := m.SegmentCounters(); counters.Dropped != 1 || counters.Answered != 0 {
			t.Errorf("a segment naming %d in front of %d bytes starting %x counted %+v, want it dropped and nothing answered", c.next, len(c.behind), c.behind[:8], counters)
		}
	}
}

// reservingPeer is a peer whose sealer hands back every packet as itself
// it reports the places each reservation of its session asked for
func reservingPeer(t *testing.T) (*Peer, func() []int) {
	var mu sync.Mutex
	var places []int
	peer := NewPeer("peer", func(count int) (BatchSealer, error) {
		mu.Lock()
		defer mu.Unlock()
		places = append(places, count)
		return func(raw [][]byte, _ []byte, out [][]byte) ([][]byte, error) {
			out = out[:0]
			for _, plain := range raw {
				out = append(out, bytes.Clone(plain))
			}
			return out, nil
		}, nil
	}, func([][]byte) error { return nil }, nil)
	t.Cleanup(peer.Close)
	return peer, func() []int {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(places)
	}
}

// a peer every packet of a batch was answered for rather than sent to is asked for no place in its session
// a place for nothing still takes a ticket and a slot of the sender's queue, which has room only for places holding a packet
// a read off the tun and a batch of forwarded segments each go to the peer next with one packet that fits, and ask for one place
func TestPeerAnsweredForEveryPacketIsAskedForNoPlace(t *testing.T) {
	source, destination := tooBigSource[6], tooBigDestination[6]
	t.Run("read off the tun", func(t *testing.T) {
		peer, places := reservingPeer(t)
		peer.SetMTU(srv6.MinimumIPv6MTU)
		dev := &scriptedDevice{recordingDevice: recordingDevice{writes: make(chan recordedWrite, 1)}, reads: make(chan scriptedRead, 2), closed: make(chan struct{})}
		m := &Mesh{Name: "test0", Routes: NewRouteTable(), closed: make(chan struct{})}
		m.setDevice(dev)
		m.startSegmentReports()
		m.Routes.Set(netip.Prefix{}, segPrefix("::/0"), peer)
		m.startOutboundPipeline()
		t.Cleanup(m.Close)
		dev.reads <- scriptedRead{packets: [][]byte{udpPacket(source, destination, DefaultMTU, false)}}
		dev.reads <- scriptedRead{packets: [][]byte{udpPacket(source, destination, 100, false)}}
		waitUntil(t, "the packet within its session to take a place", func() bool { return slices.Contains(places(), 1) })
		if got := places(); !slices.Equal(got, []int{1}) {
			t.Errorf("the peer was asked for places %v, want one for the one packet it carries", got)
		}
		if answered := len(dev.writes); answered != 1 {
			t.Errorf("the packet past its session was answered %d times, want once", answered)
		}
	})
	t.Run("forwarded segments", func(t *testing.T) {
		after := segAddr("3fff:1:69c:98d6::1")
		peer, places := reservingPeer(t)
		peer.SetMTU(srv6.MinimumIPv6MTU + srv6.Overhead(2))
		m, sender := waypointOf(t, after, peer)
		m.applySegments(framed(steeredThrough(t, udpPacket(source, destination, DefaultMTU, false), after)), DefaultMTU)
		m.applySegments(framed(steeredThrough(t, udpPacket(source, destination, 100, false), after)), DefaultMTU)
		if got := places(); !slices.Equal(got, []int{1}) {
			t.Errorf("the peer was asked for places %v, want one for the one segment it carries", got)
		}
		if answers := sender.packets(t); len(answers) != 1 {
			t.Errorf("the segment past its next session was answered %d times, want once", len(answers))
		}
	})
}

// a peer that refuses its reservation, as a closed or a full one does, is handed none of the fragments cut for it
// they are dropped and counted by the peer, and by the waypoint for a segment it would have forwarded
// a read off the tun and a forwarded segment each cut one IPv4 packet without DF into two fragments for such a peer
func TestFragmentsForAPeerThatRefusesItsReservationAreDropped(t *testing.T) {
	source, destination := tooBigSource[4], tooBigDestination[4]
	t.Run("read off the tun", func(t *testing.T) {
		peer, _ := reservingPeer(t)
		peer.SetMTU(srv6.MinimumIPv6MTU)
		peer.Close()
		dev := &scriptedDevice{recordingDevice: recordingDevice{writes: make(chan recordedWrite, 1)}, reads: make(chan scriptedRead, 1), closed: make(chan struct{})}
		m := &Mesh{Name: "test0", Routes: NewRouteTable(), closed: make(chan struct{})}
		m.setDevice(dev)
		m.startSegmentReports()
		m.Routes.Set(netip.Prefix{}, segPrefix("0.0.0.0/0"), peer)
		m.startOutboundPipeline()
		t.Cleanup(m.Close)
		dev.reads <- scriptedRead{packets: [][]byte{udpPacket(source, destination, 2000, false)}}
		waitUntil(t, "the peer to drop the two fragments it had no place for", func() bool { return peer.Dropped() == 2 })
		// closing waits for the worker that hands the read's fragments to the batches its peers hold
		m.Close()
	})
	t.Run("forwarded segment", func(t *testing.T) {
		after := segAddr("3fff:1:69c:98d6::1")
		peer, _ := reservingPeer(t)
		peer.SetMTU(srv6.MinimumIPv6MTU + srv6.Overhead(2))
		peer.Close()
		m, _ := waypointOf(t, after, peer)
		m.applySegments(framed(steeredThrough(t, udpPacket(source, destination, DefaultMTU, false), after)), DefaultMTU)
		if counters := m.SegmentCounters(); counters.Dropped != 2 || counters.Forwarded != 0 {
			t.Errorf("the waypoint counted %+v, want the segment's two fragments dropped", counters)
		}
		if dropped := peer.Dropped(); dropped != 2 {
			t.Errorf("the session dropped %d packets, want the two fragments it had no place for", dropped)
		}
	})
}

// a batch reset for its next read keeps none of the fragments its last read cut, and cuts the next read's into the same storage
// a batch cutting a packet every read then holds as much storage after a hundred reads as after the first
func TestBatchCutsEveryReadIntoTheStorageOfItsFirst(t *testing.T) {
	const reads = 100
	m := &Mesh{Name: "test0", Routes: NewRouteTable(), closed: make(chan struct{})}
	peer := (&recordingPeer{}).peer(t, "peer")
	peer.SetMTU(srv6.MinimumIPv6MTU)
	m.Routes.Set(netip.Prefix{}, segPrefix("0.0.0.0/0"), peer)
	b := newOutboundBatch(1)
	cut := udpPacket(tooBigSource[4], tooBigDestination[4], 2000, false)
	held := 0
	for read := range reads {
		fill(b, cut)
		m.classify(b)
		if len(b.cut.fragments) != 2 {
			t.Fatalf("read %d holds %d fragments, want the two its one packet was cut into", read, len(b.cut.fragments))
		}
		if read == 0 {
			held = cap(b.cut.bytes)
		} else if cap(b.cut.bytes) != held {
			t.Fatalf("read %d holds %d bytes of fragments, want the %d the first read held", read, cap(b.cut.bytes), held)
		}
		b.reset()
	}
}

// the node's cap alone holds back the answers to packets read off the tun past their session
// a read full of them, IPv6 and IPv4 with DF in turn from sources whose buckets other errors emptied, gets as many answers as the cap holds
// the cap withholds the rest and no source's bucket any, and nothing reaches the peer
func TestPacketsPastTheirSessionAreAnsweredUnderTheCapAlone(t *testing.T) {
	const flood, left = 64, 10
	dev := &recordingDevice{writes: make(chan recordedWrite, flood)}
	m := &Mesh{Name: "test0", Routes: NewRouteTable(), closed: make(chan struct{})}
	m.setDevice(dev)
	m.startSegmentReports()
	m.SetAnswerTTL(64)
	emptyBuckets(t, m)
	capHolding(m, left)
	peer := (&recordingPeer{}).peer(t, "peer")
	peer.SetMTU(srv6.MinimumIPv6MTU)
	m.Routes.Set(netip.Prefix{}, segPrefix("::/0"), peer)
	m.Routes.Set(netip.Prefix{}, segPrefix("0.0.0.0/0"), peer)
	b := newOutboundBatch(flood)
	packets := make([][]byte, flood)
	for i := range packets {
		family := []int{4, 6}[i%2]
		packets[i] = udpPacket(tooBigSource[family], tooBigDestination[family], DefaultMTU, true)
	}
	fill(b, packets...)
	m.classify(b)
	answered := len(dev.writes)
	if answered != left {
		t.Errorf("%d packets past their session were answered %d times with %d answers left in the cap, want %d", flood, answered, left, left)
	}
	if source, node := m.ICMPWithheld(); source != 0 || node != flood-left {
		t.Errorf("the limits withheld %d answers by source and %d by the node's cap, want 0 and %d", source, node, flood-left)
	}
	if got := m.TooBigAnswered(); got != uint64(answered) {
		t.Errorf("the mesh counted %d answers, want the %d it wrote into the tun", got, answered)
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
	peer := NewPeer("peer", func(count int) (BatchSealer, error) {
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
	m := &Mesh{Name: "test0", Routes: NewRouteTable(), closed: make(chan struct{})}
	m.setDevice(dev)
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

// nextSegment is the segment after thisWaypoint that the End tests below send a packet on to
var nextSegment = segAddr("3fff:d::1")

// an IPv4 packet without DF past its session whose header fails RFC 1812 section 5.2.2's checks, by its checksum, is dropped unanswered
// rather than cut into fragments whose fresh checksums would hide the fault, on a read off the tun and at End
func TestPacketsPastTheirSessionWithABadChecksumAreDropped(t *testing.T) {
	inner := udpPacket(tooBigSource[4], tooBigDestination[4], DefaultMTU, false)
	inner[10] ^= 0x5a
	t.Run("read off the tun", func(t *testing.T) {
		b, peer, answers := readOff(t, inner, nil, srv6.MinimumIPv6MTU, holding(map[int]bool{4: true}))
		if len(answers) != 0 || len(b.cut.fragments) != 0 || b.shares[peer].count != 0 {
			t.Errorf("the packet left %d answers and %d fragments counted as %d", len(answers), len(b.cut.fragments), b.shares[peer].count)
		}
	})
	t.Run("End", func(t *testing.T) {
		after := nextSegment
		session, next := sessionOf(t, srv6.MinimumIPv6MTU+srv6.Overhead(2))
		m, sender := waypointOf(t, after, session)
		m.SetAnswerSources(holding(map[int]bool{4: true}))
		m.applySegments(framed(steeredThrough(t, inner, after)), DefaultMTU)
		if sent, answers, counters := next.packets(t), sender.packets(t), m.SegmentCounters(); len(sent) != 0 || len(answers) != 0 || counters.Dropped != 1 || counters.Answered != 0 {
			t.Errorf("the segment went on as %d packets with %d answers, counted %+v", len(sent), len(answers), counters)
		}
	})
}

// an IPv4 packet without DF past its session whose option list cannot be framed is answered with parameter problem at the option's type octet
// RFC 1812 section 4.3.3.5, and nothing of it goes on: on a read off the tun into the tun from the packet's destination
// and at End back through the mesh from the router-id, else from the destination, counted answered and not as an answer about its size
func TestPacketsPastTheirSessionWithOptionsThatDoNotFrameAreAnswered(t *testing.T) {
	for _, held := range []map[int]bool{nil, {4: true}} {
		t.Run(fmt.Sprintf("read off the tun with a router-id %t", held[4]), func(t *testing.T) {
			b, peer, answers := readOff(t, misframed, nil, srv6.MinimumIPv6MTU, holding(held))
			if len(answers) != 1 || len(b.cut.fragments) != 0 || b.shares[peer].count != 0 {
				t.Fatalf("the packet left %d answers and %d fragments counted as %d", len(answers), len(b.cut.fragments), b.shares[peer].count)
			}
			checkICMPv4(t, answers[0], misframed, tooBigDestination[4], 12, 0, 20<<24)
		})
		t.Run(fmt.Sprintf("End with a router-id %t", held[4]), func(t *testing.T) {
			after := nextSegment
			session, next := sessionOf(t, srv6.MinimumIPv6MTU+srv6.Overhead(2))
			m, sender := waypointOf(t, after, session)
			m.SetAnswerSources(holding(held))
			m.applySegments(framed(steeredThrough(t, misframed, after)), DefaultMTU)
			sent, answers, counters := next.packets(t), sender.packets(t), m.SegmentCounters()
			if len(sent) != 0 || len(answers) != 1 || counters.Dropped != 1 || counters.Answered != 1 || m.TooBigAnswered() != 0 {
				t.Fatalf("the segment went on as %d packets with %d answers, counted %+v and %d answers about its size", len(sent), len(answers), counters, m.TooBigAnswered())
			}
			from := tooBigDestination[4]
			if held[4] {
				from = routerIDs[4]
			}
			checkICMPv4(t, answers[0], misframed, from, 12, 0, 20<<24)
		})
	}
}

// a read full of IPv4 packets without DF past their session whose options do not frame, all from one source, gets the burst of that source's bucket answered and no more
// the bucket withholds the rest and the node's cap none, and none of those answers counts as one about a packet's size
func TestPacketsPastTheirSessionWithOptionsThatDoNotFrameAreAnsweredAtABoundedRate(t *testing.T) {
	const flood = 64
	dev := &recordingDevice{writes: make(chan recordedWrite, flood)}
	m := &Mesh{Name: "test0", Routes: NewRouteTable(), closed: make(chan struct{})}
	m.setDevice(dev)
	m.startSegmentReports()
	m.SetAnswerTTL(64)
	peer := (&recordingPeer{}).peer(t, "peer")
	peer.SetMTU(srv6.MinimumIPv6MTU)
	m.Routes.Set(netip.Prefix{}, segPrefix("0.0.0.0/0"), peer)
	b := newOutboundBatch(flood)
	fill(b, slices.Repeat([][]byte{misframed}, flood)...)
	m.classify(b)
	if answered := len(dev.writes); answered != icmpSourceBurst {
		t.Errorf("%d packets from one source whose options do not frame were answered %d times, want the %d its bucket holds", flood, answered, icmpSourceBurst)
	}
	if source, node := m.ICMPWithheld(); source != flood-icmpSourceBurst || node != 0 {
		t.Errorf("the limits withheld %d answers by source and %d by the node's cap, want %d and 0", source, node, flood-icmpSourceBurst)
	}
	if counted := m.TooBigAnswered(); counted != 0 {
		t.Errorf("%d answers to packets whose options do not frame were counted as answers about their size", counted)
	}
}

// the ICMPv4 errors the mesh builds carry the TTL it holds, which a node takes from its host's default as RFC 1812 section 4.2.2.9 has
// a read off the tun and End each answer an IPv4 packet with DF past its session, and one whose options do not frame, under it
// and a mesh holding none answers neither, since the same section has no router originate a TTL of 0
func TestICMPv4AnswersCarryTheTTLTheMeshHolds(t *testing.T) {
	after := nextSegment
	for _, inner := range [][]byte{udpPacket(tooBigSource[4], tooBigDestination[4], DefaultMTU, true), misframed} {
		for _, ttl := range []uint8{0, 1, 128, 255} {
			dev := &recordingDevice{writes: make(chan recordedWrite, 1)}
			m := &Mesh{Name: "test0", Routes: NewRouteTable(), closed: make(chan struct{})}
			m.setDevice(dev)
			m.startSegmentReports()
			m.SetAnswerTTL(ttl)
			peer := (&recordingPeer{}).peer(t, "peer")
			peer.SetMTU(srv6.MinimumIPv6MTU)
			m.Routes.Set(netip.Prefix{}, segPrefix("0.0.0.0/0"), peer)
			b := newOutboundBatch(1)
			fill(b, inner)
			m.classify(b)
			var answers [][]byte
			if len(dev.writes) != 0 {
				answers = (<-dev.writes).packets
			}
			session, _ := sessionOf(t, srv6.MinimumIPv6MTU+srv6.Overhead(2))
			waypoint, sender := waypointOf(t, after, session)
			waypoint.SetAnswerTTL(ttl)
			waypoint.applySegments(framed(steeredThrough(t, inner, after)), DefaultMTU)
			answers = append(answers, sender.packets(t)...)
			want := 2
			if ttl == 0 {
				want = 0
			}
			if len(answers) != want {
				t.Fatalf("a read off the tun and End under a TTL of %d answered a packet with the flags %#02x %d times, want %d", ttl, inner[6], len(answers), want)
			}
			for _, answer := range answers {
				if answer[8] != ttl {
					t.Errorf("an answer to a packet with the flags %#02x carries a TTL of %d, want the %d the mesh holds", inner[6], answer[8], ttl)
				}
			}
		}
	}
}
