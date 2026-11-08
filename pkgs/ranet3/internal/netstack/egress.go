// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"net/netip"
	"sync"
	"sync/atomic"

	"ranet3.com/pkgs/ranet3/srv6"
	"ranet3.com/pkgs/wireguard/tun"
)

// egressReadiness is the families cap.egress carries out of the mesh, as the exit and the republish last named them, and the exit carrying them
type egressReadiness struct {
	// egressReady holds egressReady4 and egressReady6 for the families SetEgressReady last named ready, none at first
	egressReady atomic.Uint32
	// advertisedReady holds the same bits for the families SetAdvertisedReady last named ready, none at first
	advertisedReady atomic.Uint32
	// exit is the one SetExit handed over, nil before, and read only once a readiness word names a family ready, which the exit's hooks set after SetExit, so it needs no lock
	exit Exit
}

// Exit is where both egress verdicts hand their batches, the one method of internal/egress's Exit the mesh calls
// it is declared here so this package imports nothing of internal/egress
type Exit interface {
	// Egress takes frames of the families whose readiness the caller read, each TUNHeadroom bytes and then the packet, on the terms DeliverInboundBatch states
	// hold covers their storage, and an exit that reads a frame after it returns retains it until then
	Egress(frames [][]byte, hold Hold)
}

// SetExit hands the mesh the exit both egress verdicts hand their batches to, once and before the exit's hooks name a family ready, since the mesh reads it only once a readiness word does
func (m *Mesh) SetExit(exit Exit) { m.exit = exit }

// SetAdvertisedReady tells the mesh which families cap.egress translates for the prefixes it advertises, those the translator reports ready and lets this node announce
// a packet egressing through such a prefix of a family that is not ready is dropped and counted not ready
func (m *Mesh) SetAdvertisedReady(v4, v6 bool) { m.advertisedReady.Store(readyBits(v4, v6)) }

func readyBits(v4, v6 bool) uint32 {
	var ready uint32
	if v4 {
		ready |= egressReady4
	}
	if v6 {
		ready |= egressReady6
	}
	return ready
}

const (
	egressReady4 uint32 = 1 << iota
	egressReady6
)

// SetEgressReady tells the mesh which families the egress segments carry out
// translated, from the translator's last pass, and an egress result of a
// family that is not ready is dropped and counted NotReady
func (m *Mesh) SetEgressReady(v4, v6 bool) { m.egressReady.Store(readyBits(v4, v6)) }

// EgressReady is the families SetEgressReady last named ready
func (m *Mesh) EgressReady() (v4, v6 bool) {
	ready := m.egressReady.Load()
	return ready&egressReady4 != 0, ready&egressReady6 != 0
}

// egressReadyFor is the bit of egressReady that family, an srv6 next header, needs
func egressReadyFor(family uint8) uint32 {
	if family == srv6.NextHeaderIPv4 {
		return egressReady4
	}
	return egressReady6
}

// each caller has read its own family's readiness first, so every frame here is of a family the exit reported ready
// a mesh with no exit holds both words at none, since only an exit's hooks move them, so no frame reaches here without one
// an empty batch, most of decide's and every one of a mesh with no exit, returns before the exit is called
func (m *Mesh) egress(frames [][]byte, hold Hold) {
	if len(frames) == 0 {
		return
	}
	m.exit.Egress(frames, hold)
}

// laneState holds the mesh's record of the exit's lanes
type laneState struct {
	// lanesMu orders a lane's opening against Close, so no lane joins
	// outboundReaderWG once Close waits on it, and lanesClosed is Close having
	// begun to wait
	lanesMu     sync.Mutex
	lanesClosed bool
}

// Lane is one of an exit's ways into the outbound path, which the mesh counts
// among its readers as it counts a tun queue. What the exit lays in it meets
// the checks a read off the tun meets, but for the drop of a source this node
// does not own under ownedOnly, since every packet an exit builds comes from
// the destination a leaf sent to.
type Lane struct {
	m       *Mesh
	answers keptAnswers
	// open is the lane counted in outboundReaderWG until Close gives it back
	open      bool
	closeOnce sync.Once
}

// OpenLane opens a lane, which the mesh's Close then waits for as it waits for
// a tun reader. A lane opened once the mesh is closing is open to nothing:
// Fill reports false at once.
func (m *Mesh) OpenLane() *Lane {
	l := &Lane{m: m, answers: keptAnswers{exit: true}}
	m.lanesMu.Lock()
	defer m.lanesMu.Unlock()
	if !m.lanesClosed {
		l.open = true
		m.outboundReaderWG.Add(1)
	}
	return l
}

// closeLanes has Close wait for the lanes open now and refuse any opened later
func (m *Mesh) closeLanes() {
	m.lanesMu.Lock()
	defer m.lanesMu.Unlock()
	m.lanesClosed = true
}

// Fill takes a free outbound batch, has fill lay packets in its slab as a tun
// read lays them and report how many, and sends them through the checks a read
// off the tun meets. It waits for a batch as a tun reader does, and reports
// false once the mesh is closing or the lane closed, having laid nothing.
func (l *Lane) Fill(fill func(slab []byte, reads []tun.ReadPacket) int) bool {
	if !l.open {
		return false
	}
	m := l.m
	// a free batch and a closed mesh both ready, the select picks either
	select {
	case <-m.closed:
		return false
	default:
	}
	var b *outboundBatch
	select {
	case b = <-m.outboundFree:
	case <-m.closed:
		return false
	}
	b.n, b.answers = fill(b.slab, b.reads), &l.answers
	m.classify(b)
	if len(b.peerOrder) == 0 {
		b.reset()
		m.outboundFree <- b
		return true
	}
	m.dispatchOutbound(b)
	return true
}

// ExitAnswer is an ICMP error an exit answers a leaf's packet with from this
// node
type ExitAnswer uint8

const (
	// ExitExpired is time exceeded, for a packet whose TTL or hop limit runs
	// out at the exit
	ExitExpired ExitAnswer = iota
	// ExitProhibited is destination unreachable, administratively prohibited:
	// code 13 over IPv4 and code 1 over IPv6, for a protocol the exit does not
	// carry and a destination the host holds
	ExitProhibited
	// ExitTooBig is fragmentation needed or packet too big, carrying the MTU
	// of the path that refused the packet
	ExitTooBig
	// ExitPastLimit answers a new flow past a source's share or the exit's
	// total: host unreachable over IPv4 and administratively prohibited over
	// IPv6, as RFC 6888 REQ-11 has a translator answer it
	ExitPastLimit
)

// answerKind is the decision's kind an exit's answer is built as over version
func (a ExitAnswer) answerKind(version byte) answerKind {
	switch a {
	case ExitExpired:
		return answerExpired
	case ExitTooBig:
		return answerTooBig
	case ExitPastLimit:
		if version == 4 {
			return answerHostUnreachable
		}
	}
	return answerProhibited
}

// Answer sends this node's ICMP error of kind about offending, one whole IP
// packet a session delivered to the exit, toward its source, within the node's
// ICMP limits and from its answer source, as the node answers a packet it does
// not forward. mtu is the path's MTU a too big carries, unread for the other
// kinds. It reports whether an answer went out.
func (l *Lane) Answer(offending []byte, kind ExitAnswer, mtu int) bool {
	if len(offending) == 0 {
		return false
	}
	version := offending[0] >> 4
	if version != 4 && version != 6 || len(offending) < ipHeaderLen(version) {
		return false
	}
	return l.m.answerTaking(offending, version, kind.answerKind(version), mtu, (*Mesh).takeICMPToken) == TraceSent
}

// ipHeaderLen is the shortest header of version
func ipHeaderLen(version byte) int {
	if version == 4 {
		return 20
	}
	return 40
}

// MTU is the largest packet the session the mesh sends a packet from source
// to destination through carries, zero where the mesh routes it to no peer
func (l *Lane) MTU(source, destination netip.Addr) int {
	peer, verdict, _ := l.m.Routes.Resolve(source, destination)
	if verdict != RoutePeer {
		return 0
	}
	return peer.MTU()
}

// SameSession is whether the mesh sends a packet from source to a and one
// from source to b through one peer's session, each by the session classify
// sends it by, a steered one by its first segment's
func (l *Lane) SameSession(source, a, b netip.Addr) bool {
	steering := l.m.steerTable.Load()
	first := l.m.sessionToward(steering, source, a)
	return first != nil && first == l.m.sessionToward(steering, source, b)
}

// Done is closed once the mesh closes
func (l *Lane) Done() <-chan struct{} { return l.m.closed }

// Close gives the lane back, after which Fill reports false, and the mesh's
// Close no longer waits for it. The lane's goroutine calls it once it fills no
// more.
func (l *Lane) Close() {
	l.closeOnce.Do(func() {
		if l.open {
			l.open = false
			l.m.outboundReaderWG.Done()
		}
	})
}
