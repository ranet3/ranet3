// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package userspace

import (
	"encoding/binary"
	"net/netip"

	"ranet3.com/pkgs/ranet3/internal/packet"
)

// The reasons an ICMP message an ICMP socket of the host read is dropped
const (
	// reasonNotOurs is a message about no flow of the exit's: another
	// program's echo reply or error, or an error about none of the exit's
	// sockets
	reasonNotOurs = "icmp not ours"
)

// quotedError is an ICMP error as an ICMP socket of the host reads it: the
// error, and the protocol, the source and the destination of the datagram it
// quotes, with the quoted transport payload past the first eight bytes
type quotedError struct {
	icmpError
	protocol byte
	from, to netip.AddrPort
	prefix   []byte
}

// readQuotedError reads message, one ICMP or ICMPv6 message from offender as
// an ICMP socket of family ipv6 or IPv4 hands it past any IP header of its
// own, and reports why it is no error the exit relays: an IPv4 destination
// unreachable, time exceeded or parameter problem, or an ICMPv6 one of types 1
// to 4, quoting a UDP or TCP datagram's addresses and ports whole, "" for one.
//
// It never reads the quoted IPv4 total length, which XNU hands in the host's
// byte order (23552 for a 92 byte datagram), and checks the quoted IPv4
// header's checksum with that field written back in network order (RFC 5508
// REQ-3 (a)), the one field XNU turns. A too big's MTU is the message's, else
// routeMTU of the quoted destination where the message carries none, as an
// older router sends it (RFC 1191 section 4).
func readQuotedError(message []byte, ipv6 bool, offender netip.Addr, routeMTU func(netip.Addr) int) (quotedError, string) {
	var q quotedError
	if len(message) < 8 {
		return q, reasonNotOurs
	}
	q.offender, q.kind, q.code = offender, message[0], message[1]
	quote := message[8:]
	if ipv6 {
		if q.kind < 1 || q.kind > 4 || len(quote) < 40+8 || quote[0]>>4 != 6 {
			return q, reasonNotOurs
		}
		q.protocol = quote[6]
		q.from = netip.AddrPortFrom(netip.AddrFrom16([16]byte(quote[8:24])), binary.BigEndian.Uint16(quote[40:42]))
		q.to = netip.AddrPortFrom(netip.AddrFrom16([16]byte(quote[24:40])), binary.BigEndian.Uint16(quote[42:44]))
		q.prefix = quote[48:]
		if q.kind == 2 || q.kind == 4 {
			q.info = binary.BigEndian.Uint32(message[4:8])
		}
	} else {
		if (q.kind != 3 && q.kind != 11 && q.kind != 12) || len(quote) < 20 || quote[0]>>4 != 4 {
			return q, reasonNotOurs
		}
		header := int(quote[0]&0x0f) * 4
		if header < 20 || len(quote) < header+8 || binary.BigEndian.Uint16(quote[6:8])&0x1fff != 0 {
			return q, reasonNotOurs
		}
		var written [60]byte
		copy(written[:], quote[:header])
		binary.BigEndian.PutUint16(written[2:4], binary.NativeEndian.Uint16(quote[2:4]))
		if packet.Sum(0, written[:header]) != 0xffff {
			return q, reasonQuotedChecksum
		}
		q.protocol = quote[9]
		q.from = netip.AddrPortFrom(netip.AddrFrom4([4]byte(quote[12:16])), binary.BigEndian.Uint16(quote[header:]))
		q.to = netip.AddrPortFrom(netip.AddrFrom4([4]byte(quote[16:20])), binary.BigEndian.Uint16(quote[header+2:]))
		q.prefix = quote[header+8:]
		switch {
		case q.kind == 3 && q.code == 4:
			q.info = uint32(binary.BigEndian.Uint16(message[6:8]))
			if q.info == 0 && routeMTU != nil {
				q.info = uint32(routeMTU(q.to.Addr()))
			}
		case q.kind == 12:
			q.info = uint32(message[4])
		}
	}
	if q.protocol != 6 && q.protocol != 17 {
		return q, reasonNotOurs
	}
	return q, ""
}

// relayQuoted relays q, an error about a UDP datagram, to the leaf of the
// mapping whose socket toward the quoted destination sent it from the quoted
// source, as relayErrors relays one the socket queued, and reports whether a
// socket of the exit's sent it. An error quoting a port from an address no
// mapping holds it on is about another program's socket.
func (u *udpRelay) relayQuoted(q quotedError) bool {
	if q.protocol != 17 {
		return false
	}
	u.mu.RLock()
	m := u.ports[q.from]
	u.mu.RUnlock()
	if m == nil {
		return false
	}
	m.mu.RLock()
	dst := m.destinations[q.to]
	m.mu.RUnlock()
	if dst == nil {
		return false
	}
	dst.mu.Lock()
	defer dst.mu.Unlock()
	if dst.keptLen == 0 {
		return true
	}
	if relayed := relayedError(dst.kept[:dst.keptLen], q.icmpError, q.prefix, u.x.hops(dst.to.Addr().Is6())); relayed != nil {
		u.x.link.send(relayed)
	}
	return true
}
