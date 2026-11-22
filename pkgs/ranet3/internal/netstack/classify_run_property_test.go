// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package netstack

import (
	"bytes"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/wireguard/tun"
)

// pairFar is a destination the second peer routes, and pairOwn a source of this node's own whose packets to transitFar a route from it carries to the second peer
// pairWide is a route to the second peer that counts as a default under transitOverlay and not under pairOverlay, which holds it
var (
	pairFar     = map[int]netip.Addr{4: segAddr("192.0.2.12"), 6: segAddr("3fff::12")}
	pairOwn     = map[int]netip.Addr{4: segAddr("192.0.2.13"), 6: segAddr("3fff::13")}
	pairWide    = segPrefix("3ff0::/12")
	pairOverlay = append(slices.Clip(transitOverlay), schema.PrefixFrom(pairWide))
)

// pairReadPackets is the most packets a read off the tun holds, and pairSecondMTU the largest packet the second peer's session carries
const (
	pairReadPackets = 128
	pairSecondMTU   = 1200
)

// pairLeaf is a hookedLeaf with the exit of its default, a second peer of a smaller MTU, the routes of pairFar, pairOwn and pairWide, and the batch its reads are classified in
type pairLeaf struct {
	m                  *Mesh
	dev                *hookDevice
	peer, exit, second *Peer
	b                  *outboundBatch
}

// newPairLeaf is a pairLeaf whose batch holds size packets
// with path, its steering also holds cap.exit via's path, whose first segment's /128 the second peer routes
// with exitless, the exit's defaults are withdrawn before the first read
func newPairLeaf(tb testing.TB, size int, path, exitless bool) *pairLeaf {
	m, dev, peer := hookedLeaf(tb)
	exit, _, _ := m.Routes.Resolve(netip.Addr{}, edgeInternet[4])
	second := (&recordingPeer{}).peer(tb, "second")
	second.SetMTU(pairSecondMTU)
	for _, family := range both {
		m.Routes.Set(netip.Prefix{}, hostPrefix(pairFar[family]), second)
		m.Routes.Set(netip.Prefix{}, hostPrefix(pairOwn[family]), Local)
		m.Routes.Set(hostPrefix(pairOwn[family]), hostPrefix(transitFar[family]), second)
	}
	m.Routes.Set(netip.Prefix{}, pairWide, second)
	if path {
		steering, err := m.Steering().WithDefault(pathSource, pathVia)
		if err != nil {
			tb.Fatal(err)
		}
		m.SetSteering(steering)
		m.Routes.Set(netip.Prefix{}, netip.PrefixFrom(pathVia[0], 128), second)
	}
	if exitless {
		m.Routes.Remove(netip.Prefix{}, segPrefix("0.0.0.0/0"))
		m.Routes.Remove(netip.Prefix{}, segPrefix("::/0"))
	}
	return &pairLeaf{m: m, dev: dev, peer: peer, exit: exit, second: second, b: newOutboundBatch(size)}
}

// pairOutcomes are readOutcomes and reads of the second peer's routes, the one from pairOwn to transitFar among them
// which shares its destination with most of readOutcomes and goes to another peer, the reads of a host on a LAN the mesh routes nothing to toward transitFar
// and reads of this node's own toward the internet, which cap.exit via's path steers where it is set
var pairOutcomes = append(slices.Clone(readOutcomes),
	readOutcome{"queued to the second", both, func(f int) []byte { return udpPacket(transitOwn[f], pairFar[f], 100, false) }, ""},
	readOutcome{"cut for the second", v4, func(f int) []byte { return udpPacket(transitOwn[f], pairFar[f], pairSecondMTU+100, false) }, ""},
	readOutcome{"too big for the second", v6, func(f int) []byte { return udpPacket(transitOwn[f], pairFar[f], pairSecondMTU+100, false) }, ""},
	readOutcome{"from the second source", both, func(f int) []byte { return udpPacket(pairOwn[f], transitFar[f], 100, false) }, ""},
	readOutcome{"from a LAN host", both, func(f int) []byte { return udpPacket(edgeLAN[f], transitFar[f], 100, false) }, ""},
	readOutcome{"too big from a LAN host", both, func(f int) []byte { return udpPacket(edgeLAN[f], transitFar[f], tracedMTU+100, f == 4) }, ""},
	readOutcome{"to the internet", both, func(f int) []byte { return udpPacket(transitOwn[f], edgeInternet[f], 100, false) }, ""},
)

// pairTargets are the routes a write rewrites, three host routes and the exit's defaults
var pairTargets = []map[int]netip.Prefix{
	{4: hostPrefix(transitFar[4]), 6: hostPrefix(transitFar[6])},
	{4: hostPrefix(pairFar[4]), 6: hostPrefix(pairFar[6])},
	{4: hostPrefix(edgeHeld[4]), 6: hostPrefix(edgeHeld[6])},
	{4: segPrefix("0.0.0.0/0"), 6: segPrefix("::/0")},
}

// pairWrites are the writes to the table a read meets between two of its packets
// a target withdrawn, moved to each peer, held as a retracted route is, or made this node's own
// the overlay changed, which makes pairWide count as a default or not, and the route from pairOwn withdrawn or written again
// every route of the second peer removed, and this node's own entry for edgeHeld flagged as an egress prefix or not
var pairWrites = []func(l *pairLeaf, target netip.Prefix, family int){
	func(l *pairLeaf, target netip.Prefix, _ int) { l.m.Routes.Remove(netip.Prefix{}, target) },
	func(l *pairLeaf, target netip.Prefix, _ int) { l.m.Routes.Set(netip.Prefix{}, target, l.peer) },
	func(l *pairLeaf, target netip.Prefix, _ int) { l.m.Routes.Set(netip.Prefix{}, target, l.second) },
	func(l *pairLeaf, target netip.Prefix, _ int) { l.m.Routes.Set(netip.Prefix{}, target, l.exit) },
	func(l *pairLeaf, target netip.Prefix, _ int) { l.m.Routes.Set(netip.Prefix{}, target, Unreachable) },
	func(l *pairLeaf, target netip.Prefix, _ int) { l.m.Routes.Set(netip.Prefix{}, target, Local) },
	func(l *pairLeaf, _ netip.Prefix, _ int) { l.m.SetOverlay(pairOverlay) },
	func(l *pairLeaf, _ netip.Prefix, _ int) { l.m.SetOverlay(transitOverlay) },
	func(l *pairLeaf, _ netip.Prefix, family int) {
		l.m.Routes.Remove(hostPrefix(pairOwn[family]), hostPrefix(transitFar[family]))
	},
	func(l *pairLeaf, _ netip.Prefix, family int) {
		l.m.Routes.Set(hostPrefix(pairOwn[family]), hostPrefix(transitFar[family]), l.second)
	},
	func(l *pairLeaf, _ netip.Prefix, _ int) { l.m.Routes.RemovePeer(l.second) },
	func(l *pairLeaf, _ netip.Prefix, family int) {
		l.m.SetEgressPrefixes([]netip.Prefix{hostPrefix(edgeHeld[family])})
	},
	func(l *pairLeaf, _ netip.Prefix, _ int) { l.m.SetEgressPrefixes(nil) },
}

// pairWrite is one write of pairWrites a read meets at its write to the host of index at
type pairWrite struct {
	at, kind, target, family int
}

// readState holds what classifying a read left, peers named by their IDs and a packet's view and next header only where it went to a peer
type readState struct {
	peers     []string
	packets   [][]byte
	headers   []byte
	shares    map[string]outboundShare
	order     []string
	fragments []string
	transit   TransitCounters
	segments  SegmentCounters
	host      [][]byte
}

// note adds what b's classification of one read left, its shares, order and fragments added to those already noted
func (s *readState) note(b *outboundBatch) {
	for i := range b.n {
		id, packet, header := "", []byte(nil), byte(0)
		if peer := b.peers[i]; peer != nil {
			id, packet, header = peer.ID, slices.Clone(b.packets[i]), b.headers[i]
		}
		s.peers = append(s.peers, id)
		s.packets = append(s.packets, packet)
		s.headers = append(s.headers, header)
	}
	for _, peer := range b.peerOrder {
		share := b.shares[peer]
		if held, seen := s.shares[peer.ID]; seen {
			share.count += held.count
			share.bytes += held.bytes
			share.mtu = held.mtu
		} else {
			s.order = append(s.order, peer.ID)
		}
		s.shares[peer.ID] = share
	}
	for _, f := range b.cut.fragments {
		s.fragments = append(s.fragments, fmt.Sprintf("%s/%d/%x", f.peer.ID, f.header, f.raw))
	}
}

func (s *readState) finish(l *pairLeaf) {
	s.transit, s.segments, s.host = l.m.TransitCounters(), l.m.SegmentCounters(), l.dev.drain()
}

func (s readState) diff(o readState) string {
	switch {
	case !slices.Equal(s.peers, o.peers):
		return fmt.Sprintf("peers %q against %q", s.peers, o.peers)
	case !slices.EqualFunc(s.packets, o.packets, bytes.Equal):
		return "packets"
	case !bytes.Equal(s.headers, o.headers):
		return fmt.Sprintf("next headers %v against %v", s.headers, o.headers)
	case !maps.Equal(s.shares, o.shares):
		return fmt.Sprintf("shares %v against %v", s.shares, o.shares)
	case !slices.Equal(s.order, o.order):
		return fmt.Sprintf("order %q against %q", s.order, o.order)
	case !slices.Equal(s.fragments, o.fragments):
		return fmt.Sprintf("%d fragments against %d", len(s.fragments), len(o.fragments))
	case s.transit != o.transit:
		return fmt.Sprintf("transit %+v against %+v", s.transit, o.transit)
	case s.segments != o.segments:
		return fmt.Sprintf("segments %+v against %+v", s.segments, o.segments)
	case !slices.EqualFunc(s.host, o.host, bytes.Equal):
		return fmt.Sprintf("%d host writes against %d", len(s.host), len(o.host))
	}
	return ""
}

// hooks are changes as l's device runs them, each at its write to the host, those of one write in their order
func (l *pairLeaf) hooks(changes []pairWrite) []func() {
	var next []func()
	for _, c := range changes {
		for len(next) <= c.at {
			next = append(next, nil)
		}
		target, earlier := pairTargets[c.target][c.family], next[c.at]
		next[c.at] = func() {
			if earlier != nil {
				earlier()
			}
			pairWrites[c.kind](l, target, c.family)
		}
	}
	return next
}

// readWhole classifies packets as one read
func (l *pairLeaf) readWhole(packets [][]byte, changes []pairWrite) readState {
	l.dev.wrote, l.dev.next = 0, l.hooks(changes)
	l.b.reset()
	fill(l.b, packets...)
	l.m.classify(l.b)
	s := readState{shares: map[string]outboundShare{}}
	s.note(l.b)
	s.finish(l)
	return s
}

// readApart classifies packets as one read of one packet each, which looks every packet up, the read's kept answers held as one read holds them
// keepFor drops them at a read's start alone
// the later packets' reads find the generation they hold, and the next read the one the first packet's read found
func (l *pairLeaf) readApart(packets [][]byte, changes []pairWrite) readState {
	l.dev.wrote, l.dev.next = 0, l.hooks(changes)
	s := readState{shares: map[string]outboundShare{}}
	var start uint64
	for i, packet := range packets {
		l.b.reset()
		fill(l.b, packet)
		if i > 0 {
			l.b.answers.generation = l.m.Routes.generation.Load()
		}
		l.m.classify(l.b)
		if i == 0 {
			start = l.b.answers.generation
		}
		s.note(l.b)
	}
	l.b.answers.generation = start
	s.finish(l)
	return s
}

// a read classified whole gives what its packets give classified one read each, which looks every packet up, with the table changed between any two packets a write to the host parts
// the same peer, view and next header for each packet, the same shares, order of peers and fragments, counters and writes to the host
// over drawn reads of runs of one pair of every outcome classify gives, pairs repeated and alternating, both families, two peers and a route chosen by source and destination
// a write of pairWrites to a target of pairTargets, at any write to the host, under steering with cap.exit via's path or without it, with the exit's defaults or without them
// and reads of one run of one pair as long as a read holds
func TestClassifyReadEqualsEachPacketLookedUp(t *testing.T) {
	checkCases(t, func(ht *propertyCase) {
		path, exitless := hegel.Draw(ht, pbt.Spanning(0, 1)) == 1, hegel.Draw(ht, pbt.Spanning(0, 1)) == 1
		whole, apart := newPairLeaf(ht, pairReadPackets, path, exitless), newPairLeaf(ht, 1, path, exitless)
		for read := range hegel.Draw(ht, pbt.Spanning(1, 3)) {
			var packets [][]byte
			giant, laid := false, tun.ReadPacketSpacing
			// add puts n packets of kind in the read, those past what the slab holds left out, as the tun leaves them for its next read
			add := func(kind readOutcome, family, n int) {
				for range n {
					if packet := kind.packet(family); len(packets) < pairReadPackets && laid+len(packet)+tun.ReadPacketSpacing <= outboundSlabSize {
						packets = append(packets, packet)
						laid += len(packet) + tun.ReadPacketSpacing
					}
				}
			}
			if hegel.Draw(ht, pbt.Spanning(0, 3)) == 0 {
				kind := pairOutcomes[hegel.Draw(ht, pbt.Spanning(0, len(pairOutcomes)-1))]
				add(kind, kind.families[hegel.Draw(ht, pbt.Spanning(0, len(kind.families)-1))], pairReadPackets)
			} else {
				for range hegel.Draw(ht, pbt.Spanning(1, 12)) {
					kind := pairOutcomes[hegel.Draw(ht, pbt.Spanning(0, len(pairOutcomes)-1))]
					// the slab of a read holds one read too large to encapsulate beside the others
					if kind.name == "unencapsulable" {
						if giant {
							continue
						}
						giant = true
					}
					add(kind, kind.families[hegel.Draw(ht, pbt.Spanning(0, len(kind.families)-1))], hegel.Draw(ht, pbt.Spanning(1, 6)))
				}
			}
			if len(packets) == 0 {
				continue
			}
			var changes []pairWrite
			for range hegel.Draw(ht, pbt.Spanning(0, 8)) {
				changes = append(changes, pairWrite{
					at:     hegel.Draw(ht, pbt.Spanning(0, len(packets)-1)),
					kind:   hegel.Draw(ht, pbt.Spanning(0, len(pairWrites)-1)),
					target: hegel.Draw(ht, pbt.Spanning(0, len(pairTargets)-1)),
					family: both[hegel.Draw(ht, pbt.Spanning(0, 1))],
				})
			}
			got, want := whole.readWhole(packets, changes), apart.readApart(packets, changes)
			if d := got.diff(want); d != "" {
				ht.Fatalf("read %d of %d packets under %d changes: whole against apart: %s", read, len(packets), len(changes), d)
			}
		}
	})
}
