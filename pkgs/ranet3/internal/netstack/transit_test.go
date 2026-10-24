// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/goldentest"
	"ranet3.com/pkgs/ranet3/internal/packet"
	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
)

// ownEverything makes every destination of either family m's own but the first /8 of IPv4 and the first /16 of IPv6, which hold the zero address
// through entries an overlay holds, so none counts as a default and every packet a session delivers that no segment takes goes to the tun
// it gives m a table where it has none
func ownEverything(m *Mesh) *Mesh {
	if m.Routes == nil {
		m.Routes = NewRouteTable()
	}
	var owned []schema.Prefix
	for _, family := range []struct {
		zero  netip.Addr
		floor int
	}{{netip.IPv4Unspecified(), schema.MinSubnetBits4}, {netip.IPv6Unspecified(), schema.MinSubnetBits6}} {
		for bits := 1; bits <= family.floor; bits++ {
			raw := family.zero.AsSlice()
			raw[(bits-1)/8] = 0x80 >> ((bits - 1) % 8)
			address, _ := netip.AddrFromSlice(raw)
			owned = append(owned, schema.PrefixFrom(netip.PrefixFrom(address, bits)))
		}
	}
	m.SetOverlay(owned)
	for _, prefix := range owned {
		m.Routes.Set(netip.Prefix{}, prefix.Prefix, Local)
	}
	return m
}

// the addresses of the decision's tests by family, inside the overlay but for nowhere
// sender is behind the session the frames come through, own is this node's router-id and an address it holds
// far is behind the peer they go on to, held a host this node holds unreachable, unrouted an overlay address no route holds
// and nowhere an address outside the overlay no route holds
var (
	transitSender   = map[int]netip.Addr{4: segAddr("192.0.2.1"), 6: segAddr("3fff::1")}
	transitOwn      = map[int]netip.Addr{4: segAddr("192.0.2.2"), 6: segAddr("3fff::2")}
	transitFar      = map[int]netip.Addr{4: segAddr("192.0.2.3"), 6: segAddr("3fff::3")}
	transitHeldHost = map[int]netip.Addr{4: segAddr("192.0.2.4"), 6: segAddr("3fff::4")}
	transitUnrouted = map[int]netip.Addr{4: segAddr("192.0.2.5"), 6: segAddr("3fff::5")}
	transitNowhere  = map[int]netip.Addr{4: segAddr("203.0.113.5"), 6: segAddr("2001:db8::5")}
	transitOverlay  = []schema.Prefix{schema.PrefixFrom(segPrefix("192.0.2.0/24")), schema.PrefixFrom(segPrefix("3fff::/20"))}
	transitSID      = segAddr("3fff:5::1")
)

// transitNode is a mesh deciding what a session delivers, with a tun of one lane recording its writes and its outbound pipeline running
// from is the peer of the session the frames come through, which the sender's address routes back to, and out the peer far's address routes to
// exit is the exit the decision egresses to
type transitNode struct {
	m         *Mesh
	tun       *scriptedDevice
	from, out *recordingPeer
	fromPeer  *Peer
	outPeer   *Peer
	exit      *recordingExit
}

// newTransitNode is a transitNode with cap.transit on, the router-id of each family held, an answer TTL of 64, the overlay above, and outMTU the largest packet out carries
func newTransitNode(tb testing.TB, outMTU int) *transitNode {
	tb.Helper()
	return newRecordingTransitNode(tb, outMTU, nil)
}

// newRecordingTransitNode is newTransitNode recording its events through events, which the mesh holds before any of its goroutines starts
func newRecordingTransitNode(tb testing.TB, outMTU int, events func(kind, peer string, attrs ...slog.Attr)) *transitNode {
	tb.Helper()
	m, dev := startTransitMesh(events)
	tb.Cleanup(m.Close)
	n := &transitNode{m: m, tun: dev, from: &recordingPeer{}, out: &recordingPeer{}, exit: &recordingExit{}}
	m.SetExit(n.exit)
	n.fromPeer = n.from.peer(tb, "from")
	n.outPeer = n.out.peer(tb, "out")
	n.outPeer.SetMTU(outMTU)
	for _, family := range []int{4, 6} {
		m.Routes.Set(netip.Prefix{}, hostPrefix(transitSender[family]), n.fromPeer)
		m.Routes.Set(netip.Prefix{}, hostPrefix(transitFar[family]), n.outPeer)
		m.Routes.Set(netip.Prefix{}, hostPrefix(transitOwn[family]), Local)
		m.Routes.Set(netip.Prefix{}, hostPrefix(transitHeldHost[family]), Unreachable)
	}
	return n
}

// startTransitMesh is a mesh with a tun of one lane recording its writes and its outbound pipeline running
// with cap.transit on, the overlay above, the router-id of each family held and an answer TTL of 64, which its caller closes
func startTransitMesh(events func(kind, peer string, attrs ...slog.Attr)) (*Mesh, *scriptedDevice) {
	dev := &scriptedDevice{recordingDevice: recordingDevice{writes: make(chan recordedWrite, 64)}, reads: make(chan scriptedRead), closed: make(chan struct{})}
	m := &Mesh{Name: "test0", Routes: NewRouteTable(), closed: make(chan struct{}), events: events}
	m.setDevice(dev)
	m.startSegmentReports()
	m.startOutboundPipeline()
	m.SetTransit(true)
	m.SetOverlay(transitOverlay)
	m.SetAnswerSources(AnswerSources{Router4: transitOwn[4], Router6: transitOwn[6]})
	m.SetAnswerTTL(64)
	return m, dev
}

func hostPrefix(address netip.Addr) netip.Prefix { return netip.PrefixFrom(address, address.BitLen()) }

func familyOf(address netip.Addr) int {
	if address.Is4() {
		return 4
	}
	return 6
}

// withTTL is raw with its TTL or hop limit set to hops, its IPv4 checksum following
func withTTL(raw []byte, hops byte) []byte {
	out := bytes.Clone(raw)
	if out[0]>>4 == 6 {
		out[7] = hops
		return out
	}
	out[8] = hops
	binary.BigEndian.PutUint16(out[10:], 0)
	binary.BigEndian.PutUint16(out[10:], ^uint16(packet.Sum(0, out[:int(out[0]&0x0f)*4])))
	return out
}

// deliver hands the mesh packets as the session to fromPeer delivers them
// and returns what reached the tun, what out was sent and what went back to the sender, each once every peer is done with it
func (n *transitNode) deliver(tb testing.TB, packets ...[]byte) (tun, out, back [][]byte) {
	tb.Helper()
	n.m.DeliverInboundBatch(framed(packets...), DefaultMTU, n.fromPeer)
	for _, write := range tunWrites(&n.tun.recordingDevice) {
		tun = append(tun, write...)
	}
	return tun, n.out.packets(tb), n.from.packets(tb)
}

// egressed is every packet the exit took since the last call, in the order it took them
func (n *transitNode) egressed() [][]byte { return slices.Concat(n.exit.taken()...) }

// icmpAnswer is an ICMP error as its receiver reads it
type icmpAnswer struct {
	from, to   netip.Addr
	kind, code byte
	rest       uint32
	quoted     []byte
	ttl        byte
}

// readAnswer reads the fields of raw, one ICMP error of either family, failing the test for what is not one IP packet carrying an ICMP message
// checkError and checkAnswer hold an answer to its sums and its quote
func readAnswer(tb testing.TB, raw []byte) icmpAnswer {
	tb.Helper()
	switch packet.Version(raw) {
	case 4:
		if len(raw) < 20+8 || raw[9] != 1 {
			tb.Fatalf("the answer %x is no ICMP message", raw)
		}
		message := raw[20:]
		return icmpAnswer{netip.AddrFrom4([4]byte(raw[12:16])), netip.AddrFrom4([4]byte(raw[16:20])), message[0], message[1], binary.BigEndian.Uint32(message[4:8]), message[8:], raw[8]}
	case 6:
		if len(raw) < 40+8 || raw[6] != 58 {
			tb.Fatalf("the answer %x is no ICMPv6 message", raw)
		}
		message := raw[40:]
		return icmpAnswer{netip.AddrFrom16([16]byte(raw[8:24])), netip.AddrFrom16([16]byte(raw[24:40])), message[0], message[1], binary.BigEndian.Uint32(message[4:8]), message[8:], raw[7]}
	}
	tb.Fatalf("the answer %x is not one IP packet", raw)
	return icmpAnswer{}
}

// checkError holds raw to the ICMP error of type kind and code with a zero word after its checksum, from from back to offending's source, as checkICMPv4 and checkICMPv6 hold it
func checkError(tb testing.TB, raw, offending []byte, from netip.Addr, kind, code byte) {
	tb.Helper()
	if offending[0]>>4 == 4 {
		checkICMPv4(tb, raw, offending, from, kind, code, 0)
		return
	}
	checkICMPv6(tb, raw, offending, from, kind, code, 0)
}

// the ICMP types and codes the decision answers with, by family
var (
	noRouteType    = map[int]byte{4: 3, 6: 1}
	expiredType    = map[int]byte{4: 11, 6: 3}
	prohibitedCode = map[int]byte{4: 13, 6: 1}
)

// forwardedAs is the packet the next hop is sent for raw, its hop limit or TTL one less and its IPv4 checksum following
func forwardedAs(raw []byte) []byte {
	if raw[0]>>4 == 6 {
		return withTTL(raw, raw[7]-1)
	}
	return withTTL(raw, raw[8]-1)
}

// a session's packet for this node's own or an address cap.table assigns is written to the tun, and one for a peer forwarded with its hop limit taken down
// no route and a hold are answered destination unreachable from the router-id, and nothing else reaches the tun or a peer
// IPv4 answers host unreachable inside the overlay and inside a hold that does not count as a default, where other hosts of the network may be reachable
// and network unreachable elsewhere, a held default and a held half of one among them
func TestDecisionActsOnEachVerdict(t *testing.T) {
	for _, family := range []int{4, 6} {
		hostCode := map[int]byte{4: 1, 6: 0}[family]
		everything := map[int]netip.Prefix{4: segPrefix("0.0.0.0/0"), 6: segPrefix("::/0")}[family]
		half := map[int]netip.Prefix{4: segPrefix("128.0.0.0/1"), 6: segPrefix("::/1")}[family]
		for _, c := range []struct {
			name     string
			to       netip.Addr
			entry    netip.Prefix
			value    *Peer
			tun, out bool
			answer   bool
			code     byte
			want     TransitCounters
		}{
			{name: "this node's own", to: transitOwn[family], tun: true, want: TransitCounters{Delivered: 1}},
			{name: "an address cap.table assigns", to: transitUnrouted[family], entry: hostPrefix(transitUnrouted[family]), value: Assigned, tun: true, want: TransitCounters{Delivered: 1}},
			{name: "a peer's", to: transitFar[family], out: true, want: TransitCounters{Forwarded: 1}},
			{name: "no route inside the overlay", to: transitUnrouted[family], answer: true, code: hostCode, want: TransitCounters{NoRoute: 1, Answered: 1}},
			{name: "no route outside the overlay", to: transitNowhere[family], answer: true, code: 0, want: TransitCounters{NoRoute: 1, Answered: 1}},
			{name: "a hold", to: transitHeldHost[family], answer: true, code: hostCode, want: TransitCounters{Held: 1, Answered: 1}},
			{name: "a held prefix outside the overlay", to: transitNowhere[family], entry: netip.PrefixFrom(transitNowhere[family], 24).Masked(), value: Unreachable, answer: true, code: hostCode, want: TransitCounters{Held: 1, Answered: 1}},
			{name: "a held default outside the overlay", to: transitNowhere[family], entry: everything, value: Unreachable, answer: true, code: 0, want: TransitCounters{Held: 1, Answered: 1}},
			{name: "a held half of a default outside the overlay", to: transitNowhere[family], entry: half, value: Unreachable, answer: true, code: 0, want: TransitCounters{Held: 1, Answered: 1}},
		} {
			t.Run(fmt.Sprintf("IPv%d %s", family, c.name), func(t *testing.T) {
				n := newTransitNode(t, DefaultMTU)
				if c.value != nil {
					n.m.Routes.Set(netip.Prefix{}, c.entry, c.value)
				}
				raw := udpPacket(transitSender[family], c.to, 200, true)
				tun, out, back := n.deliver(t, raw)
				if c.tun != (len(tun) == 1) || c.tun && !bytes.Equal(tun[0], raw) {
					t.Errorf("the tun took %x", tun)
				}
				if c.out != (len(out) == 1) || c.out && !bytes.Equal(out[0], forwardedAs(raw)) {
					t.Errorf("the next hop was sent %x, want %v", out, c.out)
				}
				if c.answer != (len(back) == 1) {
					t.Fatalf("the sender was sent %x, want an answer %v", back, c.answer)
				}
				if c.answer {
					checkError(t, back[0], raw, transitOwn[family], noRouteType[family], c.code)
				}
				if got := n.m.TransitCounters(); got != c.want {
					t.Errorf("the decision counted %+v, want %+v", got, c.want)
				}
			})
		}
	}
}

// what is not one IP packet, an IPv4 packet whose total length runs past its frame among it, is dropped and counted invalid, and nothing answers it
// RFC 1812 section 5.2.2 asks for a parameter problem about the truncation, which ip_rcv_core does not send either
func TestDecisionDropsWhatIsNotOneIPPacket(t *testing.T) {
	n := newTransitNode(t, DefaultMTU)
	truncated := udpPacket(transitSender[4], transitFar[4], 200, true)
	binary.BigEndian.PutUint16(truncated[2:], 300)
	truncated = withTTL(truncated, 64)
	short6 := udpPacket(transitSender[6], transitFar[6], 200, false)
	binary.BigEndian.PutUint16(short6[4:], 300)
	tun, out, back := n.deliver(t, []byte{0x45, 0, 0}, truncated, short6, []byte{0x10, 1, 2, 3})
	if len(tun)+len(out)+len(back) != 0 {
		t.Errorf("packets that are not one IP packet reached the tun %x, the next hop %x and the sender %x", tun, out, back)
	}
	if got := n.m.TransitCounters(); got != (TransitCounters{Invalid: 4}) {
		t.Errorf("four packets that are not one IP packet counted %+v", got)
	}
}

// a destination of IPv6 link scope, multicast or the limited broadcast goes to the tun whatever the table holds, RFC 4291 section 2.5.6
// and the mesh never forwards it
func TestDecisionWritesLinkScopeToTheTun(t *testing.T) {
	n := newTransitNode(t, DefaultMTU)
	n.m.Routes.Set(netip.Prefix{}, segPrefix("::/0"), n.outPeer)
	n.m.Routes.Set(netip.Prefix{}, segPrefix("0.0.0.0/0"), n.outPeer)
	var packets [][]byte
	for _, to := range []string{"fe80::1", "ff02::1", "ff0e::1", "224.0.0.5", "239.1.1.1", "255.255.255.255"} {
		destination := segAddr(to)
		packets = append(packets, udpPacket(transitSender[familyOf(destination)], destination, 100, false))
	}
	tun, out, back := n.deliver(t, packets...)
	if !slices.EqualFunc(tun, packets, bytes.Equal) {
		t.Errorf("the tun took %x, want every packet in its order", tun)
	}
	if len(out)+len(back) != 0 {
		t.Errorf("a packet of link scope went to the next hop %x or the sender %x", out, back)
	}
	if got := n.m.TransitCounters(); got != (TransitCounters{Delivered: uint64(len(packets))}) {
		t.Errorf("%d packets of link scope counted %+v", len(packets), got)
	}
}

// a source or destination no router forwards is dropped and counted martian, past the destinations linkScoped takes to the tun, RFC 1812 section 5.3.7, RFC 3927 section 7 and RFC 4291 sections 2.5.2, 2.5.3 and 2.5.6
// an IPv4 link-local destination among them, which never reaches the tun, as a cloud's metadata address would from a host forwarding it
// and an IPv4-mapped destination, which RFC 6890 has no router forward, whatever its IPv4 form
// an IPv6 link-local source to a wider unicast destination a router forwards is answered beyond the scope of the source, RFC 4443 section 3.1 code 2, on the session it came through
// and none of the other cases is answered, an IPv4 link-local source among them
func TestDecisionDropsMartians(t *testing.T) {
	for _, c := range []struct {
		from, to string
		answered bool
	}{
		{"0.1.2.3", "192.0.2.3", false},
		{"127.0.0.1", "192.0.2.3", false},
		{"224.0.0.1", "192.0.2.3", false},
		{"240.0.0.1", "192.0.2.3", false},
		{"255.255.255.255", "192.0.2.3", false},
		{"169.254.0.9", "192.0.2.3", false},
		{"192.0.2.1", "0.1.2.3", false},
		{"192.0.2.1", "127.0.0.1", false},
		{"192.0.2.1", "240.0.0.1", false},
		{"192.0.2.1", "169.254.0.9", false},
		{"192.0.2.1", "169.254.169.254", false},
		{"203.0.113.66", "169.254.169.254", false},
		{"::", "3fff::3", false},
		{"::1", "3fff::3", false},
		{"ff02::1", "3fff::3", false},
		{"fe80::1", "3fff::3", true},
		{"fe80::1", "::1", false},
		{"3fff::1", "::", false},
		{"3fff::1", "::1", false},
		{"3fff::1", "::ffff:169.254.169.254", false},
		{"3fff::1", "::ffff:224.0.0.1", false},
		{"3fff::1", "::ffff:192.0.2.3", false},
		{"fe80::1", "::ffff:192.0.2.3", false},
	} {
		t.Run(c.from+" to "+c.to, func(t *testing.T) {
			n := newTransitNode(t, DefaultMTU)
			n.m.Routes.Set(netip.Prefix{}, segPrefix("::/0"), n.outPeer)
			n.m.Routes.Set(netip.Prefix{}, segPrefix("0.0.0.0/0"), n.outPeer)
			raw := udpPacket(segAddr(c.from), segAddr(c.to), 100, false)
			tun, out, back := n.deliver(t, raw)
			if len(tun)+len(out) != 0 {
				t.Errorf("a martian reached the tun %x or the next hop %x", tun, out)
			}
			want := TransitCounters{Martian: 1}
			if c.answered {
				want.Answered = 1
				if len(back) != 1 {
					t.Fatalf("the session it came through was sent %x, want the answer", back)
				}
				checkError(t, back[0], raw, transitOwn[6], 1, 2)
			} else if len(back) != 0 {
				t.Errorf("a martian was answered with %x", back)
			}
			if got := n.m.TransitCounters(); got != want {
				t.Errorf("the martian counted %+v, want %+v", got, want)
			}
		})
	}
}

// the answer beyond the scope of a link-local source draws on that source's bucket and on the node's cap, as every answer of the decision does
// so a burst from one link-local source to several destinations gets its bucket's burst answered and the bucket withholds the rest
// while a packet from a second link-local source to one of those destinations is answered from a bucket of its own
// an IPv6 bucket earns 1 back every 100 milliseconds, which a slow run may let in once
func TestDecisionAnswersBeyondScopeUnderTheBucketOfTheirSource(t *testing.T) {
	n := newTransitNode(t, DefaultMTU)
	const burst = 4 * icmpSourceBurst
	destinations := []netip.Addr{transitFar[6], transitHeldHost[6], transitUnrouted[6], transitNowhere[6]}
	other := segAddr("fe80::2")
	packets := make([][]byte, burst, burst+1)
	for i := range packets {
		packets[i] = udpPacket(segAddr("fe80::1"), destinations[i%len(destinations)], 100, false)
	}
	packets = append(packets, udpPacket(other, destinations[0], 100, false))
	_, _, back := n.deliver(t, packets...)
	var first, second int
	for _, raw := range back {
		if readAnswer(t, raw).to == other {
			second++
		} else {
			first++
		}
	}
	if first < icmpSourceBurst || first > icmpSourceBurst+1 || second != 1 {
		t.Errorf("%d packets from one link-local source drew %d answers and one from another drew %d, want the %d the first's bucket holds and 1", burst, first, second, icmpSourceBurst)
	}
	if source, node := n.m.ICMPWithheld(); source != uint64(burst-first) || node != 0 {
		t.Errorf("the limits withheld %d answers by source and %d by the node's cap, want %d and 0", source, node, burst-first)
	}
	if got := n.m.TransitCounters(); got != (TransitCounters{Martian: burst + 1, Answered: uint64(len(back))}) {
		t.Errorf("%d packets and %d answers counted %+v", burst+1, len(back), got)
	}
}

// a packet of no session has no link its IPv6 link-local source could be on, so nothing answers it
func TestDecisionAnswersNoLinkLocalSourceOfNoSession(t *testing.T) {
	n := newTransitNode(t, DefaultMTU)
	n.m.Routes.Set(netip.Prefix{}, segPrefix("::/0"), n.outPeer)
	n.m.DeliverInbound(udpPacket(segAddr("fe80::1"), transitFar[6], 100, false), 0)
	tun, out, back := n.deliver(t)
	if len(tun)+len(out)+len(back) != 0 {
		t.Errorf("a link-local source of no session reached the tun %x, the next hop %x or a session %x", tun, out, back)
	}
	if got := n.m.TransitCounters(); got != (TransitCounters{Martian: 1}) {
		t.Errorf("a link-local source of no session counted %+v", got)
	}
}

// an IPv4 header failing RFC 1812 section 5.2.2's checks is dropped and counted invalid for every verdict but this node's own, which the host's kernel checks
// a packet past the next session among them is neither answered nor cut
func TestDecisionChecksTheIPv4HeaderBeforeAnyAnswer(t *testing.T) {
	for _, c := range []struct {
		name  string
		to    netip.Addr
		size  int
		df    bool
		tun   bool
		count TransitCounters
	}{
		{"forwarded", transitFar[4], 200, true, false, TransitCounters{Invalid: 1}},
		{"too big with DF", transitFar[4], 1400, true, false, TransitCounters{Invalid: 1}},
		{"too big without DF", transitFar[4], 1400, false, false, TransitCounters{Invalid: 1}},
		{"no route", transitUnrouted[4], 200, true, false, TransitCounters{Invalid: 1}},
		{"this node's own", transitOwn[4], 200, true, true, TransitCounters{Delivered: 1}},
	} {
		t.Run(c.name, func(t *testing.T) {
			n := newTransitNode(t, 1300)
			raw := udpPacket(transitSender[4], c.to, c.size, c.df)
			raw[10] ^= 0xff
			tun, out, back := n.deliver(t, raw)
			if c.tun != (len(tun) == 1) || len(out)+len(back) != 0 {
				t.Errorf("a header with a bad checksum reached the tun %x, the next hop %x and the sender %x", tun, out, back)
			}
			if got := n.m.TransitCounters(); got != c.count {
				t.Errorf("a header with a bad checksum counted %+v, want %+v", got, c.count)
			}
		})
	}
}

// with cap.transit off a packet for another node is answered administratively prohibited, RFC 4443 section 3.1 code 1 and RFC 1812 section 5.2.7.1 code 13
// and this node's own still reach the tun
func TestDecisionRefusesTransitWhenItIsOff(t *testing.T) {
	for _, family := range []int{4, 6} {
		t.Run(fmt.Sprintf("IPv%d", family), func(t *testing.T) {
			n := newTransitNode(t, DefaultMTU)
			n.m.SetTransit(false)
			refused := udpPacket(transitSender[family], transitFar[family], 200, true)
			own := udpPacket(transitSender[family], transitOwn[family], 200, true)
			tun, out, back := n.deliver(t, refused, own)
			if len(out) != 0 || len(tun) != 1 || !bytes.Equal(tun[0], own) {
				t.Errorf("with transit off the next hop was sent %x and the tun took %x", out, tun)
			}
			if len(back) != 1 {
				t.Fatalf("with transit off the sender was sent %x", back)
			}
			checkError(t, back[0], refused, transitOwn[family], noRouteType[family], prohibitedCode[family])
			if got := n.m.TransitCounters(); got != (TransitCounters{Refused: 1, Delivered: 1, Answered: 1}) {
				t.Errorf("with transit off the decision counted %+v", got)
			}
		})
	}
}

// a hop limit or TTL of 1 or 0 is answered time exceeded, RFC 4443 section 3.3 and RFC 1812 section 5.3.1, before the size is looked at
// so traceroute reads the hop and not a packet too big
func TestDecisionAnswersExpiryBeforeSize(t *testing.T) {
	for _, family := range []int{4, 6} {
		for _, hops := range []byte{1, 0} {
			for _, size := range []int{200, 1400} {
				t.Run(fmt.Sprintf("IPv%d with %d hops left in %d bytes", family, hops, size), func(t *testing.T) {
					n := newTransitNode(t, 1300)
					raw := withTTL(udpPacket(transitSender[family], transitFar[family], size, true), hops)
					_, out, back := n.deliver(t, raw)
					if len(out) != 0 || len(back) != 1 {
						t.Fatalf("an expired packet was forwarded as %x and answered with %x", out, back)
					}
					checkError(t, back[0], raw, transitOwn[family], expiredType[family], 0)
					if got := n.m.TransitCounters(); got != (TransitCounters{Expired: 1, Answered: 1}) {
						t.Errorf("an expired packet counted %+v", got)
					}
				})
			}
		}
	}
}

// a packet for this node's own reaches the tun unchanged whatever its hop limit or TTL
// RFC 1812 section 5.3.1 takes the TTL down when a router forwards, and the host's kernel delivers its own at any
func TestDecisionDeliversItsOwnAtAnyHopLimit(t *testing.T) {
	for _, family := range []int{4, 6} {
		for _, hops := range []byte{1, 0} {
			t.Run(fmt.Sprintf("IPv%d with %d hops left", family, hops), func(t *testing.T) {
				n := newTransitNode(t, DefaultMTU)
				raw := withTTL(udpPacket(transitSender[family], transitOwn[family], 200, true), hops)
				tun, out, back := n.deliver(t, raw)
				if len(tun) != 1 || !bytes.Equal(tun[0], raw) || len(out) != 0 || len(back) != 0 {
					t.Fatalf("a packet for this node with %d hops left reached the tun as %x, the next hop as %x and the sender as %x", hops, tun, out, back)
				}
				if got := n.m.TransitCounters(); got != (TransitCounters{Delivered: 1}) {
					t.Errorf("a packet for this node with %d hops left counted %+v", hops, got)
				}
			})
		}
	}
}

// withPaddedOptions is raw, an IPv4 packet, with options after its fixed header, padded to a whole word with end of list
func withPaddedOptions(raw, options []byte) []byte {
	padded := append(bytes.Clone(options), make([]byte, (4-len(options)%4)%4)...)
	out := slices.Concat(raw[:20], padded, raw[20:])
	out[0] = 0x40 | byte((20+len(padded))/4)
	binary.BigEndian.PutUint16(out[2:], uint16(len(out)))
	return withTTL(out, out[8])
}

// a forwarded IPv4 packet's options are processed as RFC 1812 sections 5.3.13.4 to 5.3.13.6 have a router process them
// a loose or strict source route is dropped and counted, Record Route records the router-id with the TTL taken down and the checksum following
// and 192.0.0.8 on a node holding no IPv4 router-id, the address its IPv4 answers come from
// and options RFC 791 cannot read are answered parameter problem, pointing at the octet at fault
func TestDecisionProcessesIPv4Options(t *testing.T) {
	plain := udpPacket(transitSender[4], transitFar[4], 100, false)
	recorded := withPaddedOptions(plain, []byte{7, 7, 4, 0, 0, 0, 0})
	for _, c := range []struct {
		name    string
		raw     []byte
		want    TransitCounters
		pointer byte
	}{
		{"loose source route", withPaddedOptions(plain, []byte{131, 7, 4, 192, 0, 2, 3}), TransitCounters{SourceRoute: 1}, 0},
		{"strict source route", withPaddedOptions(plain, []byte{137, 7, 4, 192, 0, 2, 3}), TransitCounters{SourceRoute: 1}, 0},
		{"record route", recorded, TransitCounters{Forwarded: 1}, 0},
		{"a record route pointing before its first slot", withPaddedOptions(plain, []byte{7, 7, 3, 0, 0, 0, 0}), TransitCounters{Invalid: 1, Answered: 1}, 22},
	} {
		t.Run(c.name, func(t *testing.T) {
			n := newTransitNode(t, DefaultMTU)
			raw := bytes.Clone(c.raw)
			_, out, back := n.deliver(t, raw)
			if got := n.m.TransitCounters(); got != c.want {
				t.Errorf("the options counted %+v, want %+v", got, c.want)
			}
			switch {
			case c.want.Forwarded == 1:
				want := bytes.Clone(recorded)
				copy(want[20+3:], transitOwn[4].AsSlice())
				want[20+2] = 8
				want = forwardedAs(want)
				if len(out) != 1 || !bytes.Equal(out[0], want) || len(back) != 0 {
					t.Errorf("record route went on as %x, want %x", out, want)
				}
			case c.pointer != 0:
				if len(out) != 0 || len(back) != 1 {
					t.Fatalf("options past reading went on as %x and were answered with %x", out, back)
				}
				checkICMPv4(t, back[0], c.raw, transitOwn[4], 12, 0, uint32(c.pointer)<<24)
			default:
				if len(out)+len(back) != 0 {
					t.Errorf("a source route went on as %x and was answered with %x", out, back)
				}
			}
		})
	}
	t.Run("record route with no IPv4 router-id", func(t *testing.T) {
		n := newTransitNode(t, DefaultMTU)
		n.m.SetAnswerSources(AnswerSources{Router6: transitOwn[6]})
		_, out, _ := n.deliver(t, bytes.Clone(recorded))
		want := bytes.Clone(recorded)
		copy(want[20+3:], dummyIPv4.AsSlice())
		want[20+2] = 8
		want = forwardedAs(want)
		if len(out) != 1 || !bytes.Equal(out[0], want) {
			t.Errorf("record route went on as %x, want %x with the dummy address recorded", out, want)
		}
	})
}

// a timestamp option of prespecified addresses, RFC 791's flag 3, is stamped where its next address is a host route of this node's own
// and not at another address inside a prefix of this node's, which may be another host's
func TestDecisionStampsATimestampAtItsOwnAddressAlone(t *testing.T) {
	plain := udpPacket(transitSender[4], transitFar[4], 100, false)
	for _, c := range []struct {
		name    string
		at      netip.Addr
		pointer byte
	}{
		{"its own address", transitOwn[4], 13},
		{"another address inside a prefix of its own", segAddr("192.0.2.130"), 5},
	} {
		t.Run(c.name, func(t *testing.T) {
			n := newTransitNode(t, DefaultMTU)
			n.m.Routes.Set(netip.Prefix{}, segPrefix("192.0.2.128/25"), Local)
			raw := withPaddedOptions(plain, slices.Concat([]byte{68, 12, 5, 3}, c.at.AsSlice(), []byte{0, 0, 0, 0}))
			_, out, _ := n.deliver(t, raw)
			if len(out) != 1 || out[0][20+2] != c.pointer {
				t.Errorf("the timestamp went on as %x, want its pointer at %d", out, c.pointer)
			}
		})
	}
}

// a packet larger than the session to its next hop is answered with that session's MTU over IPv6 and IPv4 with DF
// RFC 4443 section 3.2 and RFC 1191 section 4, from the router-id
// and cut into fragments over IPv4 without DF, each with the TTL taken down, RFC 791
func TestDecisionAnswersOrCutsWhatIsTooBig(t *testing.T) {
	const session = 1300
	for _, family := range []int{4, 6} {
		for _, df := range []bool{true, false} {
			if family == 6 && !df {
				continue
			}
			t.Run(fmt.Sprintf("IPv%d with DF %t", family, df), func(t *testing.T) {
				n := newTransitNode(t, session)
				raw := udpPacket(transitSender[family], transitFar[family], 1400, df)
				_, out, back := n.deliver(t, raw)
				if !df {
					if len(back) != 0 {
						t.Errorf("a packet without DF was answered with %x", back)
					}
					checkFragments(t, out, nil, raw, session)
					for i, fragment := range out {
						if fragment[8] != raw[8]-1 {
							t.Errorf("fragment %d carries the TTL %d, want %d", i, fragment[8], raw[8]-1)
						}
					}
					if got := n.m.TransitCounters(); got != (TransitCounters{Forwarded: 1}) {
						t.Errorf("a packet cut into fragments counted %+v", got)
					}
					return
				}
				if len(out) != 0 || len(back) != 1 {
					t.Fatalf("a packet past its session went on as %x and was answered with %x", out, back)
				}
				checkAnswer(t, back[0], raw, session, transitOwn[family])
				if got := n.m.TransitCounters(); got != (TransitCounters{TooBig: 1, Answered: 1}) || n.m.TooBigAnswered() != 1 {
					t.Errorf("a packet past its session counted %+v and %d too-big answers", got, n.m.TooBigAnswered())
				}
			})
		}
	}
	// the fragment offset of RFC 791 names no data past the largest datagram, so a packet whose data would end there is not cut
	t.Run("IPv4 without DF and its data past the largest datagram", func(t *testing.T) {
		n := newTransitNode(t, session)
		raw := udpPacket(transitSender[4], transitFar[4], 1400, false)
		binary.BigEndian.PutUint16(raw[6:], 8100)
		raw = withTTL(raw, raw[8])
		_, out, back := n.deliver(t, raw)
		if len(out)+len(back) != 0 {
			t.Errorf("a packet that cannot be cut went on as %x and was answered with %x", out, back)
		}
		if got := n.m.TransitCounters(); got != (TransitCounters{TooBig: 1}) {
			t.Errorf("a packet that cannot be cut counted %+v", got)
		}
	})
}

// a forwarded SYN has its MSS clamped to the session to its next hop, which the hosts at either end cannot see
func TestDecisionClampsTheMSSOfAForwardedSYN(t *testing.T) {
	const session, offered = 1300, 8800
	for _, family := range []int{4, 6} {
		t.Run(fmt.Sprintf("IPv%d", family), func(t *testing.T) {
			n := newTransitNode(t, session)
			n.m.Routes.Set(netip.Prefix{}, hostPrefix(tooBigDestination[family]), n.outPeer)
			syn := tcpPacket(family, 0, false, synFlag, binary.BigEndian.AppendUint16([]byte{optionMSS, mssLen}, offered), 0, 0)
			header := map[int]int{4: 20, 6: 40}[family]
			want := forwardedAs(syn)
			binary.BigEndian.PutUint16(want[header+tcpHeaderLen+2:], uint16(session-header-tcpHeaderLen))
			binary.BigEndian.PutUint16(want[header+tcpChecksum:], tcpSum(want, header))
			_, out, _ := n.deliver(t, syn)
			if len(out) != 1 || !bytes.Equal(out[0], want) {
				t.Errorf("the SYN went on as %x, want %x", out, want)
			}
		})
	}
}

// a frame may carry bytes past the packet its header declares, TFC padding of RFC 4303 section 2.7 or an inner packet shorter than its outer one
// the decision forwards, writes and quotes the packet alone, so an answer quotes exactly the one packet it is about
func TestDecisionTakesThePacketAndNothingPastItInItsFrame(t *testing.T) {
	for _, family := range []int{4, 6} {
		t.Run(fmt.Sprintf("IPv%d", family), func(t *testing.T) {
			n := newTransitNode(t, DefaultMTU)
			padding := bytes.Repeat([]byte{0xee}, 24)
			forwarded := udpPacket(transitSender[family], transitFar[family], 200, true)
			own := udpPacket(transitSender[family], transitOwn[family], 200, true)
			unrouted := udpPacket(transitSender[family], transitUnrouted[family], 200, true)
			expired := withTTL(udpPacket(transitSender[family], transitFar[family], 200, true), 1)
			tun, out, back := n.deliver(t, slices.Concat(forwarded, padding), slices.Concat(own, padding), slices.Concat(unrouted, padding), slices.Concat(expired, padding))
			if len(out) != 1 || !bytes.Equal(out[0], forwardedAs(forwarded)) {
				t.Errorf("the next hop was sent %x, want the packet alone", out)
			}
			if len(tun) != 1 || !bytes.Equal(tun[0], own) {
				t.Errorf("the tun took %x, want the packet alone", tun)
			}
			if len(back) != 2 {
				t.Fatalf("the sender was sent %d answers, want 2", len(back))
			}
			checkError(t, back[0], unrouted, transitOwn[family], noRouteType[family], map[int]byte{4: 1, 6: 0}[family])
			checkError(t, back[1], expired, transitOwn[family], expiredType[family], 0)
		})
	}
}

// with no router-id an answer comes from 192.0.0.8 over IPv4 and from a SID over IPv6, and with neither of them over IPv6 it is counted unanswered
// a too-big answer with no router-id comes from a SID over IPv6, and from the packet's destination over IPv4 and over IPv6 with no SID
// and the IPv6 router-id, where the node holds one, comes ahead of its SID
func TestDecisionAnswersWithoutARouterID(t *testing.T) {
	for _, c := range []struct {
		name    string
		family  int
		sources AnswerSources
		size    int
		from    netip.Addr
	}{
		{"IPv4 time exceeded", 4, AnswerSources{}, 200, dummyIPv4},
		{"IPv6 time exceeded from a SID", 6, AnswerSources{SID: transitSID}, 200, transitSID},
		{"IPv6 time exceeded with no SID", 6, AnswerSources{}, 200, netip.Addr{}},
		{"IPv4 fragmentation needed", 4, AnswerSources{}, 1400, transitFar[4]},
		{"IPv6 packet too big from a SID", 6, AnswerSources{SID: transitSID}, 1400, transitSID},
		{"IPv6 packet too big with no SID", 6, AnswerSources{}, 1400, transitFar[6]},
		{"IPv6 packet too big from the router-id with a SID", 6, AnswerSources{Router6: transitOwn[6], SID: transitSID}, 1400, transitOwn[6]},
	} {
		t.Run(c.name, func(t *testing.T) {
			n := newTransitNode(t, 1300)
			n.m.SetAnswerSources(c.sources)
			raw := udpPacket(transitSender[c.family], transitFar[c.family], c.size, true)
			if c.size < 1300 {
				raw = withTTL(raw, 1)
			}
			_, _, back := n.deliver(t, raw)
			counters := n.m.TransitCounters()
			if !c.from.IsValid() {
				if len(back) != 0 || counters.Unanswered != 1 || counters.Answered != 0 {
					t.Errorf("with no address of its family the node sent %x and counted %+v, want 1 unanswered", back, counters)
				}
				return
			}
			if len(back) != 1 {
				t.Fatalf("the node sent %x", back)
			}
			if answer := readAnswer(t, back[0]); answer.from != c.from {
				t.Errorf("the answer comes from %s, want %s", answer.from, c.from)
			}
		})
	}
}

// an answer to a packet this host or a network behind it sent goes into the tun, from the answered packet's destination
// the one source every reverse path check of the host takes, where the router-id is an address of the host itself
// the reply's route decides it, so where a peer routes the source from a source prefix holding the destination the answer goes back through the session
// and a source only an entry of this node's counting as a default reaches is no network behind this host, so it gets no answer at all and draws on neither limit
func TestDecisionAnswersThisHostIntoTheTun(t *testing.T) {
	for _, family := range []int{4, 6} {
		for _, c := range []struct {
			name              string
			fromPeer, counted bool
		}{
			{"from this host", false, false},
			{"from a source a peer routes from a source prefix holding the destination", true, false},
			{"from a source only a default of this node's reaches", false, true},
		} {
			t.Run(fmt.Sprintf("IPv%d %s", family, c.name), func(t *testing.T) {
				n := newTransitNode(t, DefaultMTU)
				source := transitSender[family]
				n.m.Routes.Set(netip.Prefix{}, hostPrefix(source), Local)
				if c.fromPeer {
					n.m.Routes.Set(map[int]netip.Prefix{4: segPrefix("192.0.2.0/24"), 6: segPrefix("3fff::/20")}[family], hostPrefix(source), n.fromPeer)
				}
				if c.counted {
					source = transitStranger[family]
					n.m.Routes.Set(netip.Prefix{}, exitShapes[0].prefixes[family][0], Local)
				}
				raw := udpPacket(source, transitUnrouted[family], 200, true)
				if c.counted {
					// one past the source's bucket, which draws nothing, so neither limit withholds the last
					packets := make([][]byte, icmpSourceBurst+1)
					for i := range packets {
						packets[i] = raw
					}
					tun, out, back := n.deliver(t, packets...)
					if len(out)+len(tun)+len(back) != 0 {
						t.Errorf("the next hop was sent %x, a session %x and the tun took %x, want nothing", out, back, tun)
					}
					if got := n.m.TransitCounters(); got != (TransitCounters{NoRoute: icmpSourceBurst + 1}) {
						t.Errorf("%d unanswered drops counted %+v", icmpSourceBurst+1, got)
					}
					if source, node := n.m.ICMPWithheld(); source+node != 0 {
						t.Errorf("%d unanswered drops drew on the limits, which withheld %d by source and %d by the cap", icmpSourceBurst+1, source, node)
					}
					return
				}
				tun, out, back := n.deliver(t, raw)
				answers, from := tun, transitUnrouted[family]
				if c.fromPeer {
					answers, from = back, transitOwn[family]
				}
				if len(out)+len(tun)+len(back) != 1 || len(answers) != 1 {
					t.Fatalf("the next hop was sent %x, a session %x and the tun took %x, want one answer through the session %v", out, back, tun, c.fromPeer)
				}
				checkError(t, answers[0], raw, from, noRouteType[family], map[int]byte{4: 1, 6: 0}[family])
				if got := n.m.TransitCounters(); got != (TransitCounters{NoRoute: 1, Answered: 1}) {
					t.Errorf("the answer counted %+v", got)
				}
			})
		}
	}
}

// every answer of the decision draws on the bucket of the answered packet's source and on the node's cap, back through a session and into the tun alike
// so a burst of expired packets from one sender gets its bucket's burst answered, the bucket withholding the rest, while another sender's is answered
// and a burst of packets too big from the first is answered whole, since packet too big and fragmentation needed draw under the cap alone
func TestDecisionAnswersDrawOnTheBucketOfTheirSource(t *testing.T) {
	const session = 1300
	other := segAddr("192.0.2.6")
	for _, intoTheTun := range []bool{false, true} {
		t.Run(fmt.Sprintf("into the tun %t", intoTheTun), func(t *testing.T) {
			n := newTransitNode(t, session)
			for _, sender := range []netip.Addr{transitSender[4], other} {
				if intoTheTun {
					n.m.Routes.Set(netip.Prefix{}, hostPrefix(sender), Local)
				} else {
					n.m.Routes.Set(netip.Prefix{}, hostPrefix(sender), n.fromPeer)
				}
			}
			const burst = 4 * icmpSourceBurst
			var packets [][]byte
			for range burst {
				packets = append(packets, withTTL(udpPacket(transitSender[4], transitFar[4], 100, true), 1))
			}
			packets = append(packets, withTTL(udpPacket(other, transitFar[4], 100, true), 1))
			for range burst {
				packets = append(packets, udpPacket(transitSender[4], transitFar[4], session+100, true))
			}
			tun, _, back := n.deliver(t, packets...)
			answers := back
			if intoTheTun {
				answers = tun
			}
			var expired, tooBig, toOther int
			for _, raw := range answers {
				answer := readAnswer(t, raw)
				switch {
				case answer.to == other:
					toOther++
				case answer.kind == expiredType[4]:
					expired++
				case answer.kind == noRouteType[4] && answer.code == 4:
					tooBig++
				}
			}
			if expired != icmpSourceBurst || toOther != 1 || tooBig != burst || len(answers) != icmpSourceBurst+1+burst {
				t.Errorf("%d answers: %d expired to the first sender, %d to the other and %d fragmentation needed, want %d, 1 and %d", len(answers), expired, toOther, tooBig, icmpSourceBurst, burst)
			}
			if source, node := n.m.ICMPWithheld(); source != burst-icmpSourceBurst || node != 0 {
				t.Errorf("the limits withheld %d answers by source and %d by the node's cap, want %d and 0", source, node, burst-icmpSourceBurst)
			}
			if got := n.m.TransitCounters(); got.Expired != burst+1 || got.TooBig != burst || got.Answered != uint64(len(answers)) || n.m.TooBigAnswered() != burst {
				t.Errorf("%d answers counted %+v and %d too-big answers", len(answers), got, n.m.TooBigAnswered())
			}
		})
	}
}

// the decision's IPv4 answers carry the TTL the mesh holds, the host's default, which RFC 1812 section 4.2.2.9 has be configurable
// each kind it sends, back through a session and into the tun alike
// and a mesh holding none sends no IPv4 answer, since the same section has no router originate a TTL of 0
func TestDecisionIPv4AnswersCarryTheTTLTheMeshHolds(t *testing.T) {
	plain := func(size int) []byte { return udpPacket(transitSender[4], transitFar[4], size, true) }
	packets := [][]byte{
		udpPacket(transitSender[4], transitUnrouted[4], 200, true),
		withTTL(plain(200), 1),
		plain(1400),
		withPaddedOptions(plain(200), []byte{7, 7, 3, 0, 0, 0, 0}),
	}
	for _, ttl := range []uint8{0, 1, 128, 255} {
		for _, intoTheTun := range []bool{false, true} {
			t.Run(fmt.Sprintf("a TTL of %d into the tun %t", ttl, intoTheTun), func(t *testing.T) {
				n := newTransitNode(t, 1300)
				n.m.SetAnswerTTL(ttl)
				if intoTheTun {
					n.m.Routes.Set(netip.Prefix{}, hostPrefix(transitSender[4]), Local)
				}
				tun, _, back := n.deliver(t, packets...)
				answers := back
				if intoTheTun {
					answers = tun
				}
				want := len(packets)
				if ttl == 0 {
					want = 0
				}
				if len(answers) != want || n.m.TransitCounters().Answered != uint64(want) {
					t.Fatalf("%d packets drew %d answers and counted %+v, want %d", len(packets), len(answers), n.m.TransitCounters(), want)
				}
				for _, raw := range answers {
					if answer := readAnswer(t, raw); answer.ttl != ttl {
						t.Errorf("an answer of type %d carries a TTL of %d, want the %d the mesh holds", answer.kind, answer.ttl, ttl)
					}
				}
			})
		}
	}
}

// a session's delivery waiting for a forward batch while every one is taken returns once the mesh closes
func TestDecisionWaitingForAForwardBatchReturnsOnClose(t *testing.T) {
	m, _ := startTransitMesh(nil)
	out := &recordingPeer{}
	m.Routes.Set(netip.Prefix{}, hostPrefix(transitFar[4]), out.peer(t, "out"))
	for range cap(m.forwardFree) {
		<-m.forwardFree
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		m.DeliverInboundBatch(framed(udpPacket(transitSender[4], transitFar[4], 100, true)), DefaultMTU, nil)
	}()
	m.Close()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("a delivery waiting for a forward batch had not returned 10 seconds after Close")
	}
}

// an End.DT46 delivering to the mesh hands its inner packet to the decision, which forwards it whatever cap.transit says
// since configuring the segment grants what arrives on it, writes one for this node to the tun, and answers one for nowhere
func TestDecisionTakesWhatAnEndDT46DeliversToTheMesh(t *testing.T) {
	table, err := srv6.NewLocalTable([]srv6.Segment{{SID: schema.AddrFrom(transitSID), Behavior: srv6.BehaviorEndDT46}}, everySource)
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range []int{4, 6} {
		t.Run(fmt.Sprintf("IPv%d", family), func(t *testing.T) {
			n := newTransitNode(t, DefaultMTU)
			n.m.SetTransit(false)
			n.m.SetSegments(table)
			forwarded := udpPacket(transitSender[family], transitFar[family], 200, true)
			own := udpPacket(transitSender[family], transitOwn[family], 200, true)
			unrouted := udpPacket(transitSender[family], transitUnrouted[family], 200, true)
			plain := udpPacket(transitSender[family], transitFar[family], 300, true)
			tun, out, back := n.deliver(t, steered(t, forwarded, transitSender[6], transitSID), steered(t, own, transitSender[6], transitSID), steered(t, unrouted, transitSender[6], transitSID), plain)
			if len(out) != 1 || !bytes.Equal(out[0], forwardedAs(forwarded)) {
				t.Errorf("the inner packet for a peer went on as %x, want it forwarded", out)
			}
			if len(tun) != 1 || !bytes.Equal(tun[0], own) {
				t.Errorf("the tun took %x, want the inner packet for this node alone", tun)
			}
			if len(back) != 2 {
				t.Fatalf("the sender was sent %d answers, want 2", len(back))
			}
			checkError(t, back[0], unrouted, transitOwn[family], noRouteType[family], map[int]byte{4: 1, 6: 0}[family])
			checkError(t, back[1], plain, transitOwn[family], noRouteType[family], prohibitedCode[family])
			if got := n.m.TransitCounters(); got != (TransitCounters{Forwarded: 1, Delivered: 1, NoRoute: 1, Refused: 1, Answered: 2}) {
				t.Errorf("the batch counted %+v", got)
			}
		})
	}
}

// a session delivering a batch of more forwarded packets than one forward batch holds sends each on, in order
func TestDecisionForwardsMoreThanOneBatchInOrder(t *testing.T) {
	n := newTransitNode(t, DefaultMTU)
	packets := make([][]byte, 3*n.tun.BatchSize()+1)
	for i := range packets {
		packets[i] = udpPacket(transitSender[6], transitFar[6], 100+i%200, false)
		binary.BigEndian.PutUint32(packets[i][48:], uint32(i))
	}
	_, out, _ := n.deliver(t, packets...)
	if len(out) != len(packets) {
		t.Fatalf("%d packets went on, want %d", len(out), len(packets))
	}
	for i := range out {
		if !bytes.Equal(out[i], forwardedAs(packets[i])) {
			t.Fatalf("packet %d went on as %x, want %x", i, out[i], forwardedAs(packets[i]))
		}
	}
}

// heldReserve is a peer whose reservations wait until release is closed, saying on entered when one starts
func heldReserve(tb testing.TB) (peer *Peer, entered chan struct{}, release chan struct{}) {
	entered, release = make(chan struct{}, 1), make(chan struct{})
	peer = NewPeer("held", func(int) (BatchSealer, error) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
		return cloning, nil
	}, func([][]byte) error { return nil }, nil)
	tb.Cleanup(peer.Close)
	return peer, entered, release
}

// Close waits for a forward batch a session's delivery is submitting, and none is submitted to the closed job queue
// a delivery after Close returns, sending nothing
func TestCloseWaitsForAForwardBatchBeingSubmitted(t *testing.T) {
	n := newTransitNode(t, DefaultMTU)
	held, entered, release := heldReserve(t)
	n.m.Routes.Set(netip.Prefix{}, hostPrefix(transitFar[6]), held)
	delivered := make(chan struct{})
	go func() {
		n.m.DeliverInboundBatch(framed(udpPacket(transitSender[6], transitFar[6], 100, false)), DefaultMTU, n.fromPeer)
		close(delivered)
	}()
	select {
	case <-entered:
	case <-time.After(deliveryTimeout):
		close(release)
		t.Fatal("the delivery never reserved, so this proves nothing")
	}
	closed := make(chan struct{})
	go func() { n.m.Close(); close(closed) }()
	select {
	case <-closed:
		close(release)
		t.Fatal("Close returned while a forward batch was being submitted")
	case <-time.After(closeHold):
	}
	close(release)
	for _, done := range []chan struct{}{delivered, closed} {
		select {
		case <-done:
		case <-time.After(deliveryTimeout):
			t.Fatal("the delivery or Close never returned")
		}
	}
	after := make(chan struct{})
	go func() {
		n.m.DeliverInboundBatch(framed(udpPacket(transitSender[6], transitFar[6], 100, false)), DefaultMTU, n.fromPeer)
		close(after)
	}()
	select {
	case <-after:
	case <-time.After(deliveryTimeout):
		t.Fatal("a delivery after Close never returned")
	}
}

// sessions delivering forwarded packets while the mesh closes all return, and so does Close
func TestForwardingRacingCloseAllReturn(t *testing.T) {
	const sessions, deliveries = 8, 2000
	n := newTransitNode(t, DefaultMTU)
	var delivering sync.WaitGroup
	for session := range sessions {
		delivering.Go(func() {
			for i := range deliveries {
				raw := udpPacket(transitSender[6], transitFar[6], 100, false)
				binary.BigEndian.PutUint32(raw[48:], uint32(session<<16|i))
				n.m.DeliverInboundBatch(framed(raw, raw, raw), DefaultMTU, n.fromPeer)
			}
		})
	}
	waitUntil(t, "a forwarded packet before Close", func() bool { return n.m.TransitCounters().Forwarded > 0 })
	closed := make(chan struct{})
	go func() { n.m.Close(); close(closed) }()
	returned := make(chan struct{})
	go func() { delivering.Wait(); close(returned) }()
	for _, done := range []chan struct{}{closed, returned} {
		select {
		case <-done:
		case <-time.After(deliveryTimeout):
			t.Fatal("Close or a delivery never returned")
		}
	}
}

// drops racing for one interval's report record it once, the one claim of the interval writing it
// a report written by each drop that sees it due shows in few trials, so there are enough of them that it shows in every run
func TestDecisionRecordsOneOfTheDropsRacingForAReport(t *testing.T) {
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer slog.SetDefault(previous)
	const trials, racers = 1000, 32
	worst := 0
	for range trials {
		var recorded atomic.Int32
		m := &Mesh{Name: "test0", Routes: NewRouteTable(), closed: make(chan struct{}), events: func(kind, _ string, _ ...slog.Attr) {
			if kind == "netstack.transit.dropped" {
				recorded.Add(1)
			}
		}}
		m.startSegmentReports()
		var start, done sync.WaitGroup
		start.Add(1)
		for range racers {
			done.Go(func() {
				start.Wait()
				m.reportTransitDrop(transitNoRoute, transitSender[6], transitNowhere[6])
			})
		}
		start.Done()
		done.Wait()
		worst = max(worst, int(recorded.Load()))
	}
	if worst != 1 {
		t.Errorf("%d drops racing for one report recorded up to %d events in a trial, want 1", racers, worst)
	}
}

// a drop is reported with a line and netstack.transit.dropped at most once an interval, the counters keeping the count
func TestDecisionReportsDropsAtMostOnceAnInterval(t *testing.T) {
	lines := logLines(t)
	var recorded []string
	var mu sync.Mutex
	n := newRecordingTransitNode(t, DefaultMTU, func(kind, _ string, attrs ...slog.Attr) {
		mu.Lock()
		defer mu.Unlock()
		if strings.HasPrefix(kind, "netstack.transit.") {
			recorded = append(recorded, fmt.Sprint(kind, attrs))
		}
	})
	for range 3 {
		n.deliver(t, udpPacket(transitSender[6], transitNowhere[6], 100, false))
	}
	mu.Lock()
	defer mu.Unlock()
	want := []string{"netstack.transit.dropped[reason=no_route src=3fff::1 dst=2001:db8::5]"}
	reported := slices.DeleteFunc(lines(), func(line string) bool { return line != "netstack transit dropped a packet" })
	if !slices.Equal(recorded, want) || len(reported) != 1 {
		t.Errorf("three drops recorded %q and wrote %q, want %q and one line", recorded, reported, want)
	}
	if got := n.m.TransitCounters().NoRoute; got != 3 {
		t.Errorf("three drops counted %d", got)
	}
}

// a drop's event names its reason, the packet's source and its destination, and renders as the golden file
func TestDecisionRecordsADropAsTheGoldenFile(t *testing.T) {
	bus := events.New()
	for _, raw := range [][]byte{
		udpPacket(transitSender[6], transitNowhere[6], 100, false),
		udpPacket(segAddr("127.0.0.1"), transitFar[4], 100, false),
		withTTL(udpPacket(transitSender[4], transitFar[4], 100, false), 1),
	} {
		n := newRecordingTransitNode(t, DefaultMTU, bus.Emit)
		n.deliver(t, raw)
	}
	var out strings.Builder
	for _, event := range bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "netstack.transit.dropped" }, 0) {
		event.Seq, event.At = 0, time.Date(2026, 10, 22, 1, 0, 0, 0, time.UTC)
		control.RenderEvent(&out, event)
	}
	goldentest.Check(t, "./internal/netstack", filepath.Join("..", "..", "control", "testdata", "debug", "events-transit.txt"), []byte(out.String()))
}

// a read off the tun to a multicast destination or the limited broadcast is dropped and counted before any route is looked up, link scope among it
// where a default would otherwise carry it to the one peer it names, RFC 1812 section 5.3.5.1
func TestReaderDropsWhatIsForAGroup(t *testing.T) {
	m := &Mesh{Name: "test0", Routes: NewRouteTable(), closed: make(chan struct{})}
	m.startSegmentReports()
	peer := (&recordingPeer{}).peer(t, "peer")
	m.Routes.Set(netip.Prefix{}, segPrefix("::/0"), peer)
	m.Routes.Set(netip.Prefix{}, segPrefix("0.0.0.0/0"), peer)
	var reads [][]byte
	for _, to := range []string{"ff02::1", "ff02::fb", "ff0e::1", "224.0.0.251", "239.1.1.1", "255.255.255.255", "3fff::3", "192.0.2.3", "192.0.2.255"} {
		destination := segAddr(to)
		reads = append(reads, udpPacket(transitSender[familyOf(destination)], destination, 100, false))
	}
	ownSources(m, reads...)
	b := newOutboundBatch(len(reads))
	fill(b, reads...)
	m.classify(b)
	for i, raw := range reads {
		_, destination, _ := packet.Addrs(raw)
		if want := !destination.IsMulticast() && destination != segAddr("255.255.255.255"); (b.peers[i] == peer) != want {
			t.Errorf("a read to %s went to the peer %t, want %t", destination, b.peers[i] == peer, want)
		}
	}
	if got := m.TransitCounters(); got != (TransitCounters{Multicast: 6}) {
		t.Errorf("a read of five packets for groups and one for the limited broadcast counted %+v", got)
	}
}

// a read to a group or the limited broadcast is counted multicast before the checks of what enters the mesh, whatever its source or headers
// so at a leaf under an exit's default a host's mDNS from a link-local address and its DHCP broadcast from no address count as the multicast reads they are
// and not as sources this node does not own, and so do one from another node's address and one behind a routing header the edge refuses
func TestReaderCountsAGroupOrTheLimitedBroadcastBeforeTheChecks(t *testing.T) {
	m, _, _ := edgeLeaf(t, "0.0.0.0/0", "::/0")
	reads := [][]byte{
		udpPacket(segAddr("fe80::1"), segAddr("ff02::fb"), 100, false),
		udpPacket(segAddr("0.0.0.0"), segAddr("255.255.255.255"), 100, false),
		udpPacket(transitSender[6], segAddr("ff0e::1"), 100, false),
		udpPacket(transitSender[4], segAddr("239.1.1.1"), 100, false),
		withRouting(udpPacket(transitOwn[6], segAddr("ff0e::1"), 100, false), 4),
	}
	for i, peer := range classifiedTo(m, reads...) {
		if peer != nil {
			_, destination, _ := packet.Addrs(reads[i])
			t.Errorf("a read to %s went to %s", destination, peer.ID)
		}
	}
	if got := m.TransitCounters(); got != (TransitCounters{Multicast: uint64(len(reads))}) {
		t.Errorf("a read of %d packets for groups and the limited broadcast counted %+v", len(reads), got)
	}
}
