// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package userspace

import (
	"net/netip"
	"sync"

	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/packet"
)

// action names a lane's act on a packet a session handed the exit
type action uint8

const (
	// deliver hands the packet to the stack
	deliver action = iota
	// answer sends the leaf this node's ICMP error of the judgment's kind
	answer
	// drop drops the packet and counts it by the judgment's reason
	drop
)

// judgment is a lane's decision on one packet, before any stack sees it
type judgment struct {
	act  action
	kind netstack.ExitAnswer
	// reason names what a dropped or answered packet is counted as
	reason string
}

// The reasons a judgment counts a packet as
const (
	reasonMalformed   = "malformed"
	reasonExpired     = "expired"
	reasonProtocol    = "protocol"
	reasonDestination = "held destination"
)

// judge decides what becomes of raw, one IP packet a session handed the exit,
// before any stack sees it: one that is no whole packet is dropped, one whose
// TTL or hop limit runs out here is answered with time exceeded, one of a
// protocol the exit does not carry, and one toward an address the host holds,
// with administratively prohibited, and the rest delivered. held reports an
// address the host holds. A UDP datagram toward one is delivered, since the
// relay carries it to the mapping holding its port there and refuses it
// otherwise, which only the port shows, past reassembly. So is an ICMP error
// whole in one packet about a UDP datagram, which the relay carries back to
// the mapping that hairpinned the datagram and drops otherwise.
//
// The protocol is judged on every fragment, since the stack answers a
// protocol it does not register with a protocol unreachable as the
// destination would: IPv4 names it in each fragment's header, and IPv6 in the
// fragment header's next header, which judge walks to. An IPv6 fragment whose
// fragmentable part opens with another extension header names its protocol
// only once reassembled, and is refused as one the exit cannot judge.
func judge(raw []byte, held func(netip.Addr) bool) judgment {
	var (
		protocol, ttl byte
		destination   netip.Addr
	)
	switch packet.Version(raw) {
	case 4:
		if !packet.HeaderValid(raw) {
			return judgment{act: drop, reason: reasonMalformed}
		}
		ttl, protocol, destination = raw[8], raw[9], netip.AddrFrom4([4]byte(raw[16:20]))
	case 6:
		var ok bool
		if protocol, ok = upperLayer6(raw); !ok {
			return judgment{act: drop, reason: reasonMalformed}
		}
		ttl, destination = raw[7], netip.AddrFrom16([16]byte(raw[24:40]))
	default:
		return judgment{act: drop, reason: reasonMalformed}
	}
	switch {
	case ttl <= 1:
		return judgment{act: answer, kind: netstack.ExitExpired, reason: reasonExpired}
	case !carried(protocol, destination.Is4()):
		return judgment{act: answer, kind: netstack.ExitProhibited, reason: reasonProtocol}
	case unservable(destination) || protocol != 17 && held(destination) && !fastLeafError(raw):
		return judgment{act: answer, kind: netstack.ExitProhibited, reason: reasonDestination}
	}
	return judgment{act: deliver}
}

// carried is whether the exit carries protocol, TCP, UDP and the ICMP of the
// family
func carried(protocol byte, ipv4 bool) bool {
	switch protocol {
	case 6, 17:
		return true
	case 1:
		return ipv4
	case 58:
		return !ipv4
	}
	return false
}

// unservable is a destination no socket of the exit may send to as a server:
// one no router forwards, the host's own loopback among them, and a group
func unservable(destination netip.Addr) bool {
	return packet.InvalidDestination(destination) || destination.IsMulticast() || destination == packet.LimitedBroadcast
}

// The reasons a new flow is refused past a limit: its source's share, the
// share where the source holds more closed TCP connections kept for their
// host sockets than flows open, the total, and the host ports a new TCP
// connection would take past hostPortsOf
const (
	reasonShare     = "share"
	reasonShareHeld = "share held"
	reasonTotal     = "total"
	reasonHostPorts = "host ports"
)

// flows counts the flows through the exit, TCP connections, UDP mappings and
// echo mappings alike, by the mesh source holding each and in all, a TCP
// connection kept while its host socket may pin its port (hostHolds) among
// them. A new flow is admitted while its source holds fewer than share and all
// sources fewer than total, which cap.egress's share and Limits.Flows set.
type flows struct {
	share, total int

	mu       sync.Mutex
	open     int
	bySource map[netip.Addr]int
	// held and heldBy are the flows of open and bySource kept for a host
	// socket's port
	held   int
	heldBy map[netip.Addr]int
}

func newFlows(share, total int) *flows {
	return &flows{share: share, total: total, bySource: map[netip.Addr]int{}, heldBy: map[netip.Addr]int{}}
}

// admit opens a flow for source where its share and the total allow one, and
// otherwise reports the limit it met
func (f *flows) admit(source netip.Addr) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.admitLocked(source)
}

// admitTCP opens a TCP connection's flow for source as admit does, where
// bound, the host ports hostHolds.limit allows, is also above the relay's
// connections and every flow held, and otherwise reports the limit it met
func (f *flows) admitTCP(source netip.Addr, connections, bound int) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if connections+f.held >= bound {
		return reasonHostPorts, false
	}
	return f.admitLocked(source)
}

func (f *flows) admitLocked(source netip.Addr) (string, bool) {
	n := f.bySource[source]
	switch {
	case n >= f.share && 2*f.heldBy[source] > n:
		return reasonShareHeld, false
	case n >= f.share:
		return reasonShare, false
	case f.open >= f.total:
		return reasonTotal, false
	}
	f.bySource[source]++
	f.open++
	return "", true
}

// release closes a flow admit opened for source
func (f *flows) release(source netip.Addr) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.releaseLocked(source)
}

func (f *flows) releaseLocked(source netip.Addr) {
	if f.bySource[source]--; f.bySource[source] <= 0 {
		delete(f.bySource, source)
	}
	f.open--
}

// hold keeps a TCP connection's flow for source past its relay's end, while
// its host socket may pin its port
func (f *flows) hold(source netip.Addr) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.held++
	f.heldBy[source]++
}

// heldCount is the flows hold keeps
func (f *flows) heldCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.held
}

// unhold closes a flow hold kept for source
func (f *flows) unhold(source netip.Addr) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.heldBy[source]--; f.heldBy[source] <= 0 {
		delete(f.heldBy, source)
	}
	f.held--
	f.releaseLocked(source)
}

// upperLayer6 is the protocol raw, an IPv6 packet packet.Version passed,
// carries: its next header past the hop-by-hop, routing and destination
// options headers, or past a fragment header that header's own next header.
// A routing header with segments left names a next hop rather than this
// destination, so its protocol is reported as the routing header, which no
// exit carries. It reports false where a header runs past the packet.
func upperLayer6(raw []byte) (byte, bool) {
	next, at := raw[6], 40
	for {
		switch next {
		case 0, 43, 60:
			if at+8 > len(raw) {
				return 0, false
			}
			if next == 43 && raw[at+3] != 0 {
				return 43, true
			}
			next, at = raw[at], at+(int(raw[at+1])+1)*8
		case 44:
			if at+8 > len(raw) {
				return 0, false
			}
			return raw[at], true
		default:
			return next, at <= len(raw)
		}
	}
}
