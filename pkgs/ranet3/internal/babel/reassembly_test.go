// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package babel

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/netstack"
)

// handBackWait is how long a fragment not sent to the speaker may take to come back while the speaker's lock is held elsewhere
const handBackWait = 5 * time.Second

// floodRuns is how many steps of a flood an allocation count averages over
// it is past the allocations the property engine's cleanups may make meanwhile
// testing.AllocsPerRun truncates its average, which drops those
const floodRuns = 1000

// fragment cuts packet, an unfragmented IPv6 packet, into fragments of identification id at each offset of its fragmentable part cuts names
// every fragment carries the packet's IPv6 header with Fragment as its next header, as RFC 8200 section 4.5 cuts one
func fragment(packet []byte, id uint32, cuts ...int) [][]byte {
	fragmentable := packet[ipv6HeaderLen:]
	bounds := slices.Concat([]int{0}, cuts, []int{len(fragmentable)})
	out := make([][]byte, 0, len(bounds)-1)
	for i := range len(bounds) - 1 {
		from, to := bounds[i], bounds[i+1]
		f := make([]byte, ipv6HeaderLen+fragmentHeaderLen+to-from)
		copy(f, packet[:ipv6HeaderLen])
		binary.BigEndian.PutUint16(f[4:6], uint16(fragmentHeaderLen+to-from))
		f[6], f[ipv6HeaderLen] = nextHeaderFragment, packet[6]
		field := uint16(from)
		if to < len(fragmentable) {
			field |= 1
		}
		binary.BigEndian.PutUint16(f[ipv6HeaderLen+2:], field)
		binary.BigEndian.PutUint32(f[ipv6HeaderLen+4:], id)
		copy(f[ipv6HeaderLen+fragmentHeaderLen:], fragmentable[from:to])
		out = append(out, f)
	}
	return out
}

// fieldPacket is a Babel packet from src to the group carrying udp octets as UDP, its UDP header included
// it announces every prefix of prefixes under one router id and is padded out with PadN
func fieldPacket(t *testing.T, src netip.Addr, udp int, prefixes ...netip.Prefix) []byte {
	t.Helper()
	tlvs := []RawTLV{EncodeRouterID([8]byte{1, 2, 3, 4, 5, 6, 7, 8})}
	for _, prefix := range prefixes {
		tlvs = append(tlvs, EncodeUpdate(Update{AE: AEIPv6, Plen: prefix.Bits(), Interval: 6000, Seqno: 1, Metric: 96,
			Prefix: net.IP(prefix.Addr().AsSlice())}))
	}
	padding := udp - udpHeaderLen - len(EncodePacket(tlvs))
	for padding >= 2 {
		body := min(padding-2, math.MaxUint8)
		tlvs = append(tlvs, RawTLV{Type: TLVPadN, Body: make([]byte, body)})
		padding -= 2 + body
	}
	if padding == 1 {
		tlvs = append(tlvs, RawTLV{Type: TLVPad1})
	}
	packet := buildPacket(src, multicastGroup, EncodePacket(tlvs))
	if len(packet) != ipv6HeaderLen+udp {
		t.Fatalf("the packet carries %d UDP octets, want %d", len(packet)-ipv6HeaderLen, udp)
	}
	return packet
}

// fieldPrefixes is n IPv6 /64 prefixes, one for each Update a field packet carries
func fieldPrefixes(n int) []netip.Prefix {
	prefixes := make([]netip.Prefix, n)
	for i := range prefixes {
		prefixes[i] = netip.PrefixFrom(netip.AddrFrom16([16]byte{0xfd, 0, 0, byte(i)}), 64)
	}
	return prefixes
}

// helloAck is a small Babel packet from src to dst, 24 octets of UDP with its header, which cuts into three fragments at 8 and 16
func helloAck(src, dst netip.Addr, nonce uint16) []byte {
	return buildPacket(src, dst, EncodePacket([]RawTLV{EncodeHello(Hello{Seqno: 1, Interval: 400}), EncodeAck(nonce)}))
}

// the speakers of six organizations send Babel packets of 1422 to 1443 UDP octets, which their stacks cut at 1368 or 1384
// such a packet reaches the speaker in two fragments and installs every route it announces, as the packet would whole
func TestUpdateCutAsTheFieldCutsItInstallsItsRoutes(t *testing.T) {
	for _, field := range []struct{ udp, cut int }{{1443, 1384}, {1422, 1368}} {
		t.Run(fmt.Sprintf("%d UDP octets cut at %d", field.udp, field.cut), func(t *testing.T) {
			speaker, neighbor, _ := captureSpeaker(t, Config{})
			makeNeighborReachable(neighbor)
			prefixes := fieldPrefixes(64)
			fragments := fragment(fieldPacket(t, neighbor.addr, field.udp, prefixes...), 7, field.cut-ipv6HeaderLen-fragmentHeaderLen)
			if len(fragments) != 2 || len(fragments[0]) != field.cut {
				t.Fatalf("the packet was cut into %d fragments, the first of %d octets", len(fragments), len(fragments[0]))
			}
			for _, f := range fragments {
				if !speaker.Receive(neighbor.peer, f) {
					t.Fatal("the speaker handed a fragment of a Babel packet sent to it back to the caller")
				}
			}
			for _, prefix := range prefixes {
				if via, ok := speaker.mesh.Routes.Lookup(prefix.Addr(), prefix.Addr()); !ok || via != neighbor.peer {
					t.Fatalf("%s is not forwarded through the neighbor that announced it: %v", prefix, speaker.mesh.Routes.Debug())
				}
			}
		})
	}
}

// a fragment that overlaps octets another brought drops its whole datagram, RFC 5722 section 4
// the fragments still to come go with it, which leaves the datagram unread once every octet has arrived
func TestFragmentOverlappingAnotherDropsItsDatagram(t *testing.T) {
	src := netip.MustParseAddr("fe80::2")
	packet := helloAck(src, multicastGroup, 1)
	fragments := fragment(packet, 1, 8, 16)
	unlike := bytes.Clone(fragments[1])
	unlike[len(unlike)-1] ^= 0xff
	for name, sequence := range map[string][][]byte{
		"partly over octets held":       {fragments[0], fragments[1], fragment(packet, 1, 8)[1], fragments[2]},
		"over held octets, unlike them": {fragments[0], fragments[1], unlike, fragments[2]},
		"before and over octets held":   {fragments[1], fragment(packet, 1, 16)[0], fragments[0], fragments[2]},
	} {
		t.Run(name, func(t *testing.T) {
			var r reassembly
			now := time.Now()
			for _, f := range sequence {
				if whole := r.add(f, src, multicastGroup, now); whole != nil {
					t.Fatal("a datagram with overlapping fragments was read")
				}
			}
			if r.stats.Dropped != [len(FragmentDrops)]uint64{dropOverlap: 1} || r.held != 0 {
				t.Errorf("the reassembly counts %v and holds %d octets, want one overlap and nothing held", r.stats.Dropped, r.held)
			}
		})
	}
}

// a fragment whose octets the datagram already holds, byte for byte, is a copy and goes alone, RFC 8200 section 4.5
// one spanning two fragments the datagram holds is a copy too, as a sender cutting the packet anew would send it
func TestExactCopiesOfHeldOctetsGoAlone(t *testing.T) {
	src := netip.MustParseAddr("fe80::2")
	packet := helloAck(src, multicastGroup, 1)
	fragments := fragment(packet, 1, 8, 16)
	var r reassembly
	now := time.Now()
	var read [][]byte
	for _, f := range [][]byte{fragments[0], fragments[0], fragments[1], fragment(packet, 1, 16)[0], fragments[1], fragments[2], fragments[2]} {
		if whole := r.add(f, src, multicastGroup, now); whole != nil {
			read = append(read, bytes.Clone(whole))
		}
	}
	if len(read) != 1 || !bytes.Equal(read[0], packet) || r.stats.Dropped != [len(FragmentDrops)]uint64{} {
		t.Fatalf("the datagram was read %d times as %x and dropped %v, want it read once as %x", len(read), read, r.stats.Dropped, packet)
	}
}

// fragments belong to the datagram of their source, destination and identification, RFC 8200 section 4.5
// datagrams sharing two of the three, their fragments interleaved, are each read whole once
func TestFragmentsMatchOnSourceDestinationAndIdentification(t *testing.T) {
	a, b, local := netip.MustParseAddr("fe80::2"), netip.MustParseAddr("fe80::3"), netip.MustParseAddr("fe80::1")
	datagrams := []struct {
		src, dst netip.Addr
		id       uint32
	}{{a, multicastGroup, 1}, {b, multicastGroup, 1}, {a, local, 1}, {a, multicastGroup, 2}}
	packets := make([][]byte, len(datagrams))
	fragments := make([][][]byte, len(datagrams))
	for i, d := range datagrams {
		packets[i] = helloAck(d.src, d.dst, uint16(i))
		fragments[i] = fragment(packets[i], d.id, 8, 16)
	}
	var r reassembly
	now := time.Now()
	read := make([]int, len(datagrams))
	for part := range 3 {
		for i, d := range datagrams {
			whole := r.add(fragments[i][part], d.src, d.dst, now)
			if whole == nil {
				continue
			}
			if !bytes.Equal(whole, packets[i]) {
				t.Fatalf("datagram %d was read as %x, want %x", i, whole, packets[i])
			}
			read[i]++
		}
	}
	if !slices.Equal(read, []int{1, 1, 1, 1}) || r.stats.Dropped != [len(FragmentDrops)]uint64{} {
		t.Fatalf("the datagrams were read %v times and dropped %v, want each read once", read, r.stats.Dropped)
	}
}

// a datagram missing a fragment is never read, and its time after its first fragment drops it and gives its storage back, RFC 8200 section 4.5
// a later fragment does not restart that time
// a datagram read or dropped before it ends is not counted again
// the speaker's sweep drops it, and so does the neighbor's next fragment, whichever comes first
func TestDatagramMissingAFragmentIsDroppedAfterItsTime(t *testing.T) {
	t.Run("by the sweep", func(t *testing.T) {
		speaker, neighbor, _ := captureSpeaker(t, Config{})
		fragments := fragment(fieldPacket(t, neighbor.addr, 1443), 3, 640, 1280)
		before := time.Now()
		for _, f := range fragments[:2] {
			speaker.Receive(neighbor.peer, f)
		}
		after := time.Now()
		sweep := func(now time.Time) (held int, timedOut uint64) {
			speaker.mu.Lock()
			defer speaker.mu.Unlock()
			speaker.sweepExpiredLocked(now)
			return neighbor.reassembly.held, neighbor.reassembly.stats.Dropped[dropTimeout]
		}
		if held, timedOut := sweep(before.Add(maxFragmentAge - time.Millisecond)); held == 0 || timedOut != 0 {
			t.Fatalf("before its time the datagram holds %d octets and %d timed out, want it still waiting", held, timedOut)
		}
		if held, timedOut := sweep(after.Add(maxFragmentAge)); held != 0 || timedOut != 1 {
			t.Fatalf("after its time the datagram holds %d octets and %d timed out, want it dropped", held, timedOut)
		}
		if read := neighbor.reassembly.stats.Read; read != 0 || len(neighbor.reassembly.datagrams) != 0 {
			t.Fatalf("%d packets were read and %d datagrams kept, want neither", read, len(neighbor.reassembly.datagrams))
		}
	})
	t.Run("at the next fragment", func(t *testing.T) {
		src := netip.MustParseAddr("fe80::2")
		packet := helloAck(src, multicastGroup, 1)
		var r reassembly
		now := time.Now()
		// datagram 1 waits for its last fragment beside datagram 2, read, and datagram 3, dropped for an overlap
		for _, f := range [][]byte{fragment(packet, 1, 8, 16)[0], fragment(packet, 2, 8, 16)[0], fragment(packet, 2, 8, 16)[1],
			fragment(packet, 2, 8, 16)[2], fragment(packet, 3, 8, 16)[1], fragment(packet, 3, 16)[0]} {
			r.add(f, src, multicastGroup, now)
		}
		r.add(fragment(packet, 1, 8, 16)[1], src, multicastGroup, now.Add(maxFragmentAge/2))
		r.add(fragment(packet, 4, 8, 16)[0], src, multicastGroup, now.Add(maxFragmentAge))
		if dropped, datagrams := r.stats.Dropped, len(r.datagrams); dropped != [len(FragmentDrops)]uint64{dropOverlap: 1, dropTimeout: 1} || datagrams != 1 {
			t.Fatalf("after the first datagrams' time the reassembly counts %v and keeps %d datagrams, want one overlap, datagram 1 alone timed out and datagram 4 kept", dropped, datagrams)
		}
	})
}

// a first fragment must begin with the header chain up to the upper-layer header, RFC 7112 section 5, which for the speaker is UDP to its own port
// a datagram whose first fragment does not is dropped with every fragment of it, and an atomic fragment that does not is dropped alone
func TestFirstFragmentWithoutTheUDPHeaderDropsItsDatagram(t *testing.T) {
	src := netip.MustParseAddr("fe80::2")
	packet := buildPacket(src, multicastGroup, EncodePacket([]RawTLV{EncodeAck(1)}))
	// the same packet behind an 8-octet Destination Options header, which the first fragment carries without the UDP header
	options := slices.Concat(packet[:ipv6HeaderLen], []byte{nextHeaderUDP, 0, 1, 4, 0, 0, 0, 0}, packet[ipv6HeaderLen:])
	options[6] = 60
	binary.BigEndian.PutUint16(options[4:6], uint16(len(options)-ipv6HeaderLen))
	otherPort := bytes.Clone(packet)
	binary.BigEndian.PutUint16(otherPort[ipv6HeaderLen+2:], 53)
	empty := fragment(packet, 1, 8)[0][:ipv6HeaderLen+fragmentHeaderLen]
	binary.BigEndian.PutUint16(empty[4:6], fragmentHeaderLen)
	for name, sequence := range map[string][][]byte{
		"header chain past the first fragment": fragment(options, 1, 8),
		"UDP to another port":                  fragment(otherPort, 1, 8),
		"an empty first fragment":              {empty, fragment(packet, 1, 8)[1]},
		"atomic, not UDP":                      fragment(options, 1),
	} {
		t.Run(name, func(t *testing.T) {
			var r reassembly
			now := time.Now()
			for _, f := range sequence {
				if whole := r.add(f, src, multicastGroup, now); whole != nil {
					t.Fatalf("a datagram whose first fragment holds no UDP header to the Babel port was read: %x", whole)
				}
			}
			if r.stats.Dropped != [len(FragmentDrops)]uint64{dropHeader: 1} || r.held != 0 {
				t.Errorf("the reassembly counts %v and holds %d octets, want one header drop and nothing held", r.stats.Dropped, r.held)
			}
		})
	}
}

// a fragment wrong in itself, or against the end the last fragment set, drops its datagram as it arrives
// the fragments that would have completed it then read nothing
func TestMalformedFragmentDropsItsDatagram(t *testing.T) {
	src := netip.MustParseAddr("fe80::2")
	packet := helloAck(src, multicastGroup, 1)
	fragments := fragment(packet, 1, 8, 16)
	// cut is a fragment of datagram 1 carrying the octets from offset to end, with more set as named
	cut := func(offset, end int, more bool) []byte {
		f := fragment(buildPacket(src, multicastGroup, make([]byte, end)), 1, offset, end)[1]
		if !more {
			f[ipv6HeaderLen+3] &^= 1
		}
		return f
	}
	last := len(packet) - ipv6HeaderLen
	// each sequence holds the malformed fragment at malformed
	for name, test := range map[string]struct {
		sequence  [][]byte
		malformed int
	}{
		"carrying no octet":                     {[][]byte{fragments[0], cut(16, 16, true), fragments[1], fragments[2]}, 1},
		"not a multiple of 8 with more to come": {[][]byte{fragments[0], cut(8, 12, true), fragments[1], fragments[2]}, 1},
		"past the largest Babel packet":         {[][]byte{fragments[0], cut(math.MaxUint16-ipv6HeaderLen-7, math.MaxUint16-ipv6HeaderLen+1, true), fragments[1], fragments[2]}, 1},
		"past the end the last one set":         {[][]byte{fragments[2], fragments[0], cut(last, last+8, true), fragments[1]}, 2},
		"a last one ending before held octets":  {[][]byte{fragments[2], fragments[0], cut(8, 12, false), fragments[1]}, 2},
	} {
		t.Run(name, func(t *testing.T) {
			var r reassembly
			now := time.Now()
			for i, f := range test.sequence {
				if whole := r.add(f, src, multicastGroup, now); whole != nil {
					t.Fatal("a datagram with a malformed fragment was read")
				}
				if i < test.malformed {
					continue
				}
				if r.stats.Dropped != [len(FragmentDrops)]uint64{dropMalformed: 1} || r.held != 0 {
					t.Fatalf("after fragment %d the reassembly counts %v and holds %d octets, want one malformed and nothing held", i, r.stats.Dropped, r.held)
				}
			}
		})
	}
}

// the packet fragments put back together meets the checks an unfragmented one does
// one they refuse is dropped as malformed, and its fragments are the speaker's all the same
func TestPacketPutBackTogetherIsCheckedAsAWholeOne(t *testing.T) {
	speaker, neighbor, _ := captureSpeaker(t, Config{})
	packet := fieldPacket(t, neighbor.addr, 1443)
	packet[len(packet)-1] ^= 0xff // the UDP checksum no longer holds
	for _, f := range fragment(packet, 1, 1336) {
		if !speaker.Receive(neighbor.peer, f) {
			t.Fatal("the speaker handed a fragment of a Babel packet sent to it back to the caller")
		}
	}
	if got := neighbor.reassembly.stats; got.Read != 0 || got.Dropped != [len(FragmentDrops)]uint64{dropMalformed: 1} {
		t.Fatalf("a packet whose checksum fails was counted as %+v, want it dropped as malformed", got)
	}
}

// an atomic fragment is a whole packet, read at once and apart from any datagram sharing its identification, RFC 6946 section 4
func TestAtomicFragmentIsReadApartFromItsDatagram(t *testing.T) {
	src := netip.MustParseAddr("fe80::2")
	packet := helloAck(src, multicastGroup, 1)
	fragments := fragment(packet, 9, 8)
	var r reassembly
	now := time.Now()
	if whole := r.add(fragments[0], src, multicastGroup, now); whole != nil {
		t.Fatal("the first of two fragments was read as a whole packet")
	}
	if whole := r.add(fragment(packet, 9)[0], src, multicastGroup, now); !bytes.Equal(whole, packet) {
		t.Fatalf("an atomic fragment was read as %x, want the packet %x", whole, packet)
	}
	if whole := r.add(fragments[1], src, multicastGroup, now); !bytes.Equal(whole, packet) {
		t.Fatalf("the datagram sharing the atomic fragment's identification was read as %x, want the packet %x", whole, packet)
	}
}

// a fragment from a link-local address to the Babel group or to the speaker is the speaker's whatever becomes of it, a retired session's among them
// any other fragment, of ordinary traffic to a mesh address among them, goes back to the caller as it arrived, without the speaker's lock or an allocation
// so does a packet to the speaker that is neither UDP nor a fragment, ICMPv6 among them
// it leaves the neighbor's reassembly as it was
func TestOnlyFragmentsSentToTheSpeakerAreConsumed(t *testing.T) {
	speaker, neighbor, _ := captureSpeaker(t, Config{})
	// a session the neighbor's peer has since replaced
	retired := newTestPeer(t, neighbor.peer.ID, nil).Peer
	linkLocal, mesh := netip.MustParseAddr("fe80::2"), netip.MustParseAddr("fd00::1")
	for id, test := range []struct {
		name           string
		src, dst       netip.Addr
		peer           *netstack.Peer
		consumed, kept bool
		nextHeader     byte
	}{
		{"to the group", linkLocal, multicastGroup, neighbor.peer, true, true, nextHeaderFragment},
		{"to the speaker", linkLocal, speaker.linkLocal, neighbor.peer, true, true, nextHeaderFragment},
		{"to the group over a retired session", linkLocal, multicastGroup, retired, true, false, nextHeaderFragment},
		{"to another link-local address", linkLocal, netip.MustParseAddr("fe80::9"), neighbor.peer, false, false, nextHeaderFragment},
		{"to a mesh address", linkLocal, mesh, neighbor.peer, false, false, nextHeaderFragment},
		{"to the group from a mesh address", mesh, multicastGroup, neighbor.peer, false, false, nextHeaderFragment},
		{"between mesh addresses", mesh, netip.MustParseAddr("fd00::2"), neighbor.peer, false, false, nextHeaderFragment},
		{"ICMPv6 to the group", linkLocal, multicastGroup, neighbor.peer, false, false, 58},
		{"ICMPv6 to the speaker", linkLocal, speaker.linkLocal, neighbor.peer, false, false, 58},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := buildPacket(test.src, test.dst, EncodePacket([]RawTLV{EncodeAck(1)}))
			if test.nextHeader == nextHeaderFragment {
				f = fragment(f, uint32(id), 8)[0]
			} else {
				f[6] = test.nextHeader
			}
			sent, before, counted := bytes.Clone(f), len(neighbor.reassembly.datagrams), neighbor.reassembly.stats
			if !test.consumed {
				speaker.mu.Lock()
				back := make(chan bool, 1)
				go func() { back <- speaker.Receive(test.peer, f) }()
				select {
				case <-back:
					speaker.mu.Unlock()
				case <-time.After(handBackWait):
					speaker.mu.Unlock()
					t.Fatal("a packet the speaker hands back waited for the speaker's lock")
				}
				if allocations := testing.AllocsPerRun(100, func() { speaker.Receive(test.peer, f) }); allocations != 0 {
					t.Fatalf("handing back a packet the speaker does not take allocated %v times", allocations)
				}
			}
			if consumed := speaker.Receive(test.peer, f); consumed != test.consumed {
				t.Fatalf("Receive took the packet %v, want %v", consumed, test.consumed)
			}
			if kept := len(neighbor.reassembly.datagrams) > before; kept != test.kept || !bytes.Equal(f, sent) {
				t.Fatalf("the neighbor kept the fragment %v, want %v, and it reads %x where %x was sent", kept, test.kept, f, sent)
			}
			if got := neighbor.reassembly.stats; !test.consumed && got != counted {
				t.Fatalf("a packet handed back changed the neighbor's counts from %+v to %+v", counted, got)
			}
		})
	}
}

// a session's datagrams under way go with its neighbor when another session replaces it, as the rest of its state does
// the fragment that would have completed one, arriving over the new session, starts a datagram of its own
func TestReplacedSessionTakesItsDatagramsAlong(t *testing.T) {
	speaker, neighbor, _ := captureSpeaker(t, Config{})
	fragments := fragment(fieldPacket(t, neighbor.addr, 1443), 1, 1336)
	speaker.Receive(neighbor.peer, fragments[0])
	replacement := addPeer(t, speaker, newTestPeer(t, neighbor.peer.ID, nil).Peer)
	speaker.Receive(replacement.peer, fragments[1])
	if read, datagrams := replacement.reassembly.stats.Read, len(replacement.reassembly.datagrams); read != 0 || datagrams != 1 {
		t.Fatalf("the new session read %d packets and keeps %d datagrams, want none read and its own datagram under way", read, datagrams)
	}
}

// every packet a neighbor's session sends in fragments is counted with the largest of them, and the first is recorded once with its size
func TestFragmentedPacketsAreCountedAndTheFirstRecorded(t *testing.T) {
	bus := events.New()
	speaker, neighbor, _ := captureSpeaker(t, Config{}, Runtime{Events: bus})
	for id, udp := range []int{1443, 600} {
		for _, f := range fragment(fieldPacket(t, neighbor.addr, udp), uint32(id), 256) {
			speaker.Receive(neighbor.peer, f)
		}
	}
	if got := speaker.Stats().Neighbors[0].Fragments; got.Read != 2 || got.Largest != ipv6HeaderLen+1443 {
		t.Errorf("the neighbor's fragments read as %+v, want 2 read and the largest of %d octets", got, ipv6HeaderLen+1443)
	}
	recorded := bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "babel.neighbor.fragmented" }, 0)
	if len(recorded) != 1 || recorded[0].Peer != neighbor.peer.ID || recorded[0].Attrs["size"] != fmt.Sprint(ipv6HeaderLen+1443) {
		t.Errorf("the speaker recorded %+v, want one event for %s with the size of the first packet", recorded, neighbor.peer.ID)
	}
}

// one neighbor flooding fragments of datagrams that never complete holds no more datagrams and storage than its bounds
// another neighbor's packet, cut around the flood, is read whole meanwhile
func TestFloodingNeighborStaysInItsBoundsAndCrowdsOutNoOther(t *testing.T) {
	speaker, flooding, _ := captureSpeaker(t, Config{})
	quiet := addPeer(t, speaker, newTestPeer(t, "quiet", nil).Peer)
	makeNeighborReachable(quiet)
	prefixes := fieldPrefixes(64)
	fragments := fragment(fieldPacket(t, netip.MustParseAddr("fe80::3"), 1443, prefixes...), 1, 1336)
	speaker.Receive(quiet.peer, fragments[0])

	// each flooding datagram takes the most storage one may, by 8 octets at the far end of the largest Babel packet
	head := fragment(fieldPacket(t, flooding.addr, 1443), 0, 1336)[0]
	far := (math.MaxUint16 - ipv6HeaderLen - 8) &^ 7
	tail := fragment(buildPacket(flooding.addr, multicastGroup, make([]byte, far+8)), 0, far, far+8)[1]
	for id := range uint32(3 * maxFragmentedDatagrams) {
		for _, f := range [][]byte{tail, head} {
			binary.BigEndian.PutUint32(f[ipv6HeaderLen+4:], id+1)
			if !speaker.Receive(flooding.peer, f) {
				t.Fatal("the speaker handed a fragment sent to it back to the caller")
			}
			if held, datagrams := flooding.reassembly.held, len(flooding.reassembly.datagrams); held > maxFragmentOctets || datagrams > maxFragmentedDatagrams {
				t.Fatalf("after datagram %d the flooding neighbor holds %d octets in %d datagrams, past its bounds of %d and %d",
					id+1, held, datagrams, maxFragmentOctets, maxFragmentedDatagrams)
			}
		}
	}
	speaker.Receive(quiet.peer, fragments[1])
	if read := quiet.reassembly.stats.Read; read != 1 {
		t.Fatalf("the other neighbor's packet was read %d times, want once", read)
	}
	for _, prefix := range prefixes {
		if via, ok := speaker.mesh.Routes.Lookup(prefix.Addr(), prefix.Addr()); !ok || via != quiet.peer {
			t.Fatalf("%s is not forwarded through the neighbor that announced it", prefix)
		}
	}
	if dropped := flooding.reassembly.stats.Dropped; dropped[dropEvicted]+dropped[dropRefused] == 0 {
		t.Fatal("no flooding datagram was evicted or refused, so the flood never reached the bounds")
	}
}

// a newer datagram where the neighbor has no place left takes the place of the oldest one done, and failing that of the oldest under way, which it drops
// the storage a datagram grows into comes from the oldest others under way, never from the datagram itself, in powers of two
// every datagram that gives way here is past minFragmentAge
func TestNewerDatagramTakesFromTheOldestOthers(t *testing.T) {
	src := netip.MustParseAddr("fe80::2")
	packet := helloAck(src, multicastGroup, 1)
	now := time.Now()
	later := now.Add(minFragmentAge)
	// deliver hands r the fragments of the packet under identification id at each index of parts, at the time given
	// it reports whether one completed it
	deliver := func(r *reassembly, at time.Time, id uint32, parts ...int) bool {
		read := false
		for _, part := range parts {
			if whole := r.add(fragment(packet, id, 8, 16)[part], src, multicastGroup, at); whole != nil {
				read = true
			}
		}
		return read
	}
	t.Run("a place, from one done first", func(t *testing.T) {
		var r reassembly
		deliver(&r, now, 0, 0)
		for id := uint32(1); id < maxFragmentedDatagrams; id++ {
			if !deliver(&r, now, id, 0, 1, 2) {
				t.Fatalf("datagram %d was not read", id)
			}
		}
		// datagram 0 under way and the 15 read take every place, and a newer one takes the place of datagram 1
		deliver(&r, later, maxFragmentedDatagrams, 0)
		if read := deliver(&r, later, 0, 1, 2); !read || r.stats.Dropped != [len(FragmentDrops)]uint64{} {
			t.Fatalf("datagram 0 was read %v and the reassembly counts %v, want it read and nothing dropped", read, r.stats.Dropped)
		}
	})
	t.Run("a place, from the oldest under way", func(t *testing.T) {
		var r reassembly
		// datagrams 0 to 15 under way take every place, and datagram 16 takes the place of datagram 0
		for id := range uint32(maxFragmentedDatagrams) {
			deliver(&r, now, id, 0)
		}
		deliver(&r, later, maxFragmentedDatagrams, 0)
		var read []uint32
		for id := uint32(1); id <= maxFragmentedDatagrams; id++ {
			if deliver(&r, later, id, 1, 2) {
				read = append(read, id)
			}
		}
		// datagram 0's other fragments come last, as they open a datagram of their own
		if deliver(&r, later, 0, 1, 2) {
			read = append(read, 0)
		}
		if len(read) != maxFragmentedDatagrams || slices.Contains(read, 0) || r.stats.Dropped != [len(FragmentDrops)]uint64{dropEvicted: 1} {
			t.Fatalf("datagrams %v were read and the reassembly counts %v, want every one but datagram 0 read and it alone evicted", read, r.stats.Dropped)
		}
	})
	t.Run("storage, never its own", func(t *testing.T) {
		var r reassembly
		// datagram 9, read first, stands oldest and holds no storage to give
		deliver(&r, now, 9, 0, 1, 2)
		// a first fragment of a field packet opens a datagram of 2 KiB, and a fragment at the far end of the largest Babel packet one of 64 KiB
		first := fragment(fieldPacket(t, src, 1443), 0, 1336)[0]
		far := (math.MaxUint16 - ipv6HeaderLen - 8) &^ 7
		tail := fragment(buildPacket(src, multicastGroup, make([]byte, far+8)), 0, far, far+8)[1]
		// datagram 1 grows last, past the storage the other four leave it, which datagram 2 gives up as the oldest other under way
		for _, step := range []struct {
			f  []byte
			at time.Time
			id uint32
		}{{first, now, 1}, {tail, now, 2}, {tail, now, 3}, {tail, now, 4}, {first, now, 5}, {tail, later, 1}} {
			binary.BigEndian.PutUint32(step.f[ipv6HeaderLen+4:], step.id)
			r.add(step.f, src, multicastGroup, step.at)
		}
		var underWay []uint32
		held := 0
		for _, d := range r.datagrams {
			if size := cap(d.packet); size&(size-1) != 0 {
				t.Errorf("datagram %d holds %d octets, want a power of two", d.id, size)
			}
			if !d.done {
				underWay = append(underWay, d.id)
			}
			held += cap(d.packet)
		}
		if !slices.Equal(underWay, []uint32{1, 3, 4, 5}) || r.stats.Dropped != [len(FragmentDrops)]uint64{dropEvicted: 1} || r.held != held || held > maxFragmentOctets {
			t.Fatalf("datagrams %v are under way holding %d octets, counted as %d, and the reassembly counts %v, want 1, 3, 4 and 5 under way within %d octets and datagram 2 alone evicted",
				underWay, held, r.held, r.stats.Dropped, maxFragmentOctets)
		}
	})
}

// a datagram under way younger than minFragmentAge keeps its place and its storage against a newer datagram
// the newer one is refused
// one dropped keeps its place as long
// a neighbor ending its own datagrams then frees no place sooner
// one read gives its place up at once
// a datagram minFragmentAge old gives up its place or its storage to the newer one
func TestDatagramYoungerThanTheMinimumAgeKeepsItsPlaceAndStorage(t *testing.T) {
	src := netip.MustParseAddr("fe80::2")
	packet := helloAck(src, multicastGroup, 1)
	// the packet to another UDP port
	// its first fragment drops its datagram as it arrives
	otherPort := bytes.Clone(packet)
	binary.BigEndian.PutUint16(otherPort[ipv6HeaderLen+2:], 53)
	far := (math.MaxUint16 - ipv6HeaderLen - 8) &^ 7
	wide := fragment(buildPacket(src, multicastGroup, make([]byte, far+8)), 0, far, far+8)[1]
	// tail is 8 octets at the far end of the largest Babel packet under identification id
	// they open a datagram of 64 KiB
	tail := func(id uint32) []byte {
		f := bytes.Clone(wide)
		binary.BigEndian.PutUint32(f[ipv6HeaderLen+4:], id)
		return f
	}
	now := time.Now()
	young, old := now.Add(minFragmentAge-time.Nanosecond), now.Add(minFragmentAge)
	// kept lists the identifications of the datagrams r keeps, and of those under way
	kept := func(r *reassembly) (all, underWay []uint32) {
		for _, d := range r.datagrams {
			all = append(all, d.id)
			if !d.done {
				underWay = append(underWay, d.id)
			}
		}
		return all, underWay
	}
	// through is the identifications from first to last
	through := func(first, last uint32) []uint32 {
		var ids []uint32
		for id := first; id <= last; id++ {
			ids = append(ids, id)
		}
		return ids
	}
	t.Run("a place, held by one under way", func(t *testing.T) {
		var r reassembly
		for id := range uint32(maxFragmentedDatagrams) {
			r.add(fragment(packet, id, 8, 16)[0], src, multicastGroup, now)
		}
		r.add(fragment(packet, 16, 8, 16)[0], src, multicastGroup, young)
		if all, _ := kept(&r); !slices.Equal(all, through(0, 15)) || r.stats.Dropped != [len(FragmentDrops)]uint64{dropRefused: 1} {
			t.Fatalf("before minFragmentAge the reassembly keeps %v and counts %v, want datagrams 0 to 15 kept and datagram 16 refused", all, r.stats.Dropped)
		}
		r.add(fragment(packet, 17, 8, 16)[0], src, multicastGroup, old)
		if all, _ := kept(&r); !slices.Equal(all, append(through(1, 15), 17)) || r.stats.Dropped != [len(FragmentDrops)]uint64{dropEvicted: 1, dropRefused: 1} {
			t.Fatalf("at minFragmentAge the reassembly keeps %v and counts %v, want datagram 17 in the place of datagram 0, evicted", all, r.stats.Dropped)
		}
	})
	t.Run("a place, held by one dropped", func(t *testing.T) {
		var r reassembly
		for id := range uint32(maxFragmentedDatagrams) {
			r.add(fragment(otherPort, id, 8)[0], src, multicastGroup, now)
		}
		r.add(fragment(packet, 16, 8, 16)[0], src, multicastGroup, young)
		if all, _ := kept(&r); !slices.Equal(all, through(0, 15)) || r.stats.Dropped != [len(FragmentDrops)]uint64{dropHeader: maxFragmentedDatagrams, dropRefused: 1} {
			t.Fatalf("before minFragmentAge the reassembly keeps %v and counts %v, want datagrams 0 to 15 kept and datagram 16 refused", all, r.stats.Dropped)
		}
		r.add(fragment(packet, 17, 8, 16)[0], src, multicastGroup, old)
		if all, _ := kept(&r); !slices.Equal(all, append(through(1, 15), 17)) || r.stats.Dropped != [len(FragmentDrops)]uint64{dropHeader: maxFragmentedDatagrams, dropRefused: 1} {
			t.Fatalf("at minFragmentAge the reassembly keeps %v and counts %v, want datagram 17 in the place of datagram 0", all, r.stats.Dropped)
		}
	})
	t.Run("a place, held by one read", func(t *testing.T) {
		var r reassembly
		for id := range uint32(maxFragmentedDatagrams) {
			for _, f := range fragment(packet, id, 8, 16) {
				r.add(f, src, multicastGroup, now)
			}
		}
		r.add(fragment(packet, 16, 8, 16)[0], src, multicastGroup, now)
		if all, _ := kept(&r); !slices.Equal(all, through(1, 16)) || r.stats.Dropped != [len(FragmentDrops)]uint64{} {
			t.Fatalf("the reassembly keeps %v and counts %v, want datagram 16 in the place of datagram 0 at once", all, r.stats.Dropped)
		}
	})
	t.Run("storage, held by ones under way", func(t *testing.T) {
		var r reassembly
		for id := range uint32(maxFragmentOctets / (math.MaxUint16 + 1)) {
			r.add(tail(id), src, multicastGroup, now)
		}
		r.add(tail(4), src, multicastGroup, young)
		if _, underWay := kept(&r); !slices.Equal(underWay, through(0, 3)) || r.held != maxFragmentOctets || r.stats.Dropped != [len(FragmentDrops)]uint64{dropRefused: 1} {
			t.Fatalf("before minFragmentAge datagrams %v are under way holding %d octets and the reassembly counts %v, want 0 to 3 holding %d and datagram 4 refused",
				underWay, r.held, r.stats.Dropped, maxFragmentOctets)
		}
		r.add(tail(5), src, multicastGroup, old)
		if _, underWay := kept(&r); !slices.Equal(underWay, []uint32{1, 2, 3, 5}) || r.held != maxFragmentOctets || r.stats.Dropped != [len(FragmentDrops)]uint64{dropEvicted: 1, dropRefused: 1} {
			t.Fatalf("at minFragmentAge datagrams %v are under way holding %d octets and the reassembly counts %v, want datagram 5 in the storage of datagram 0, evicted",
				underWay, r.held, r.stats.Dropped)
		}
	})
}

// a neighbor flooding fragments under fresh identifications has the node allocate nothing once its places are taken and the clock stands still
// whether it leaves its datagrams under way, far ones and near ones in turn, or ends each itself with a fragment carrying nothing
// with the clock running, a newer datagram takes the place of one past minFragmentAge and allocates its own storage alone
func TestFloodingNeighborAllocatesNoMoreThanTheMinimumAgeAllows(t *testing.T) {
	src := netip.MustParseAddr("fe80::2")
	// near opens a datagram of 2 KiB, and tail one of 64 KiB
	// empty carries nothing and drops the datagram it reaches
	near := fragment(fieldPacket(t, src, 1443), 0, 1336)[0]
	far := (math.MaxUint16 - ipv6HeaderLen - 8) &^ 7
	tail := fragment(buildPacket(src, multicastGroup, make([]byte, far+8)), 0, far, far+8)[1]
	empty := fragment(helloAck(src, multicastGroup, 1), 0, 8, 8)[1]
	// deliver hands r the fragments under identification id at the time given
	deliver := func(r *reassembly, now time.Time, id uint32, fragments ...[]byte) {
		for _, f := range fragments {
			binary.BigEndian.PutUint32(f[ipv6HeaderLen+4:], id)
			r.add(f, src, multicastGroup, now)
		}
	}
	for _, test := range []struct {
		name string
		// datagrams are the fragments of each datagram a step of the flood opens, each under an identification of its own
		datagrams [][][]byte
	}{
		{"far and near ones left under way", [][][]byte{{tail}, {near}}},
		{"far ones each ended by the neighbor", [][][]byte{{tail, empty}}},
	} {
		t.Run(test.name+", the clock still", func(t *testing.T) {
			var r reassembly
			now, id := time.Now(), uint32(0)
			step := func() {
				for _, fragments := range test.datagrams {
					id++
					deliver(&r, now, id, fragments...)
				}
			}
			for range maxFragmentedDatagrams {
				step()
			}
			refused := r.stats.Dropped[dropRefused]
			if allocations := testing.AllocsPerRun(floodRuns, step); allocations != 0 {
				t.Fatalf("once the neighbor's places were taken each step of the flood allocated %v times", allocations)
			}
			if refused := r.stats.Dropped[dropRefused] - refused; refused < floodRuns {
				t.Fatalf("the reassembly refused %d fragments of the %d steps that found no place", refused, floodRuns)
			}
		})
	}
	t.Run("near ones left under way, the clock running", func(t *testing.T) {
		var r reassembly
		now, id := time.Now(), uint32(0)
		// each datagram comes an eighth of minFragmentAge after the one before
		// the oldest of 16 is then past minFragmentAge
		step := func() {
			now = now.Add(minFragmentAge / 8)
			id++
			deliver(&r, now, id, near)
		}
		for range maxFragmentedDatagrams {
			step()
		}
		evicted := r.stats.Dropped[dropEvicted]
		if allocations := testing.AllocsPerRun(floodRuns, step); allocations != 1 {
			t.Fatalf("a datagram taking the place of one past minFragmentAge allocated %v times, want once for its storage", allocations)
		}
		if evicted := r.stats.Dropped[dropEvicted] - evicted; evicted < floodRuns {
			t.Fatalf("%d datagrams past minFragmentAge gave their place to the %d newer ones", evicted, floodRuns)
		}
	})
}
