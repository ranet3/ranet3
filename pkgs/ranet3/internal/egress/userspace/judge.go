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
// address the host holds.
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
	case unservable(destination) || held(destination):
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

// The reasons a new flow is refused past a limit
const (
	reasonShare = "share"
	reasonTotal = "total"
)

// flows counts the flows open through the exit, TCP connections, UDP
// mappings and echo mappings alike, by the mesh source holding each and in
// all. A new flow is admitted while its source holds fewer than share and all
// sources fewer than total, which cap.egress's share and Limits.Flows set.
type flows struct {
	share, total int

	mu       sync.Mutex
	open     int
	bySource map[netip.Addr]int
}

func newFlows(share, total int) *flows {
	return &flows{share: share, total: total, bySource: map[netip.Addr]int{}}
}

// admit opens a flow for source where its share and the total allow one, and
// otherwise reports the limit it met
func (f *flows) admit(source netip.Addr) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case f.bySource[source] >= f.share:
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
	if f.bySource[source]--; f.bySource[source] <= 0 {
		delete(f.bySource, source)
	}
	f.open--
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
