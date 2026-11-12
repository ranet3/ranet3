// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package babel

import (
	"net"
	"net/netip"
	"time"
)

// Originate adds prefix to the set the speaker originates, see OriginateFrom
func (s *Speaker) Originate(prefix netip.Prefix) {
	s.OriginateFrom(prefix, netip.Prefix{})
}

// OriginateFrom adds dest from source to the set the speaker originates and
// hands the whole set to SetOriginated, the path a reload takes. It reads the
// set and writes it back, so it is not safe beside another writer of the set.
func (s *Speaker) OriginateFrom(dest, source netip.Prefix) {
	s.SetOriginated(append(s.Originated(), OriginatedRoute{Destination: dest, Source: source}))
}

// handlePacket hands n one Babel payload, without its IPv6 and UDP headers,
// through receive, from the address n already has
func (s *Speaker) handlePacket(n *neighborState, raw []byte) {
	s.receive(n.peer, n.addr, raw, time.Now())
}

// flushUpdates sends the periodic dump out of band with the wake an arriving
// packet takes. Unlike a pass of the run loop it leaves updatePending and
// nextUpdate alone.
func (s *Speaker) flushUpdates() {
	now := time.Now()
	s.mu.Lock()
	send := s.emitLocked(s.updateActions(now))
	s.wakeForPacketLocked()
	s.mu.Unlock()
	send()
}

// EncodeNextHop is the NextHop TLV of RFC 8966 section 4.6.8
func EncodeNextHop(addr net.IP) RawTLV {
	ae, a := uint8(AEIPv6), addr.To16()
	if v4 := addr.To4(); v4 != nil {
		ae, a = AEIPv4, v4
	}
	body := make([]byte, 2+len(a))
	body[0] = ae
	copy(body[2:], a)
	return RawTLV{Type: TLVNextHop, Body: body}
}
