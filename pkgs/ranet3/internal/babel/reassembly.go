// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package babel

import (
	"bytes"
	"encoding/binary"
	"log/slog"
	"math"
	"math/bits"
	"net/netip"
	"slices"
	"time"

	"ranet3.com/pkgs/ranet3/internal/netstack"
)

// FragmentDrops names why a datagram a neighbor sent in fragments was dropped rather than read, by the reasons FragmentStats.Dropped counts
var FragmentDrops = [...]string{
	// a fragment that overlapped octets another brought, other than as an exact copy of them, RFC 5722 section 4
	dropOverlap: "overlap",
	// a first fragment that does not begin with a UDP header to the Babel port, RFC 7112 section 5
	dropHeader: "header",
	// a fragment wrong in itself or against the end the last fragment set, or a whole packet parsePacket refuses
	dropMalformed: "malformed",
	// a datagram still under way maxFragmentAge after its first fragment arrived
	dropTimeout: "timeout",
	// a datagram under way past minFragmentAge that gave its place to a newer one or its storage to another of the same neighbor
	dropEvicted: "evicted",
	// a fragment that found no place, or a datagram that found no storage, the neighbor's others all younger than minFragmentAge
	// nothing keeps a datagram refused a place
	// each of its fragments counts
	dropRefused: "refused",
}

const (
	dropOverlap = iota
	dropHeader
	dropMalformed
	dropTimeout
	dropEvicted
	dropRefused
)

// FragmentStats counts what became of the Babel packets one neighbor's session sent in fragments
type FragmentStats struct {
	// Read counts the packets put back together and read
	Read uint64
	// Largest is the largest of them, a whole IPv6 packet with its headers
	Largest int
	// Dropped counts the datagrams dropped instead, by the reasons FragmentDrops names
	Dropped [len(FragmentDrops)]uint64
}

// fragmentBlocks is how many 8-octet blocks the fragmentable part of the largest Babel packet RFC 8966 section 4 allows takes
const fragmentBlocks = (math.MaxUint16 - ipv6HeaderLen + 7) / 8

// reassembly puts back together the Babel packets one neighbor's session sends in fragments, RFC 8200 section 4.5
// Speaker.mu protects it with the rest of the neighbor's state, and it goes with the neighbor
type reassembly struct {
	// datagrams are in the order their first fragments arrived
	datagrams []*datagram
	// held is the storage the datagrams under way hold, at most maxFragmentOctets
	held  int
	stats FragmentStats
}

// datagram is one packet a neighbor sent in fragments, keyed by its source, destination and identification
type datagram struct {
	src, dst netip.Addr
	id       uint32
	// arrived is when the datagram's first fragment to arrive did
	// its time runs from then, RFC 8200 section 4.5
	arrived time.Time
	// packet is the whole packet as its fragments arrive, the first fragment's IPv6 header in its first 40 octets and the fragmentable part after it
	// it runs to the furthest octet a fragment brought, and is nil once the datagram is done
	packet []byte
	// blocks marks the 8-octet blocks of the fragmentable part a fragment brought
	blocks [(fragmentBlocks + 63) / 64]uint64
	// received counts the octets of the fragmentable part brought, each once
	received int
	// end is the length of the fragmentable part, which the last fragment sets, and zero before it arrives
	end int
	// nextHeader is the Next Header of the first fragment's Fragment header, which the whole packet's IPv6 header takes
	nextHeader byte
	// done is a datagram read or dropped
	// a fragment of it still to come goes with it, RFC 5722 section 4
	// a copy of one read is not read again
	done bool
	// read is a datagram done once its packet was put back together
	// a newer datagram may take its place at any age
	// one dropped keeps its place for minFragmentAge
	read bool
}

// receiveFragment takes an IPv6 packet whose next header is a Fragment header
// one from a link-local address to the Babel group or to this speaker is the speaker's whether it completes a packet or not, and never reaches the TUN
// any other goes back to the caller unchanged, as ordinary traffic the kernel reassembles for its own sockets
// the packet a fragment completes reaches the neighbor as an unfragmented one does
func (s *Speaker) receiveFragment(peer *netstack.Peer, raw []byte) bool {
	src, dst := netip.AddrFrom16([16]byte(raw[8:24])), netip.AddrFrom16([16]byte(raw[24:40]))
	if !forSpeaker(src, dst, s.linkLocal) {
		return false
	}
	s.mu.Lock()
	n := s.neighbors[peer.ID]
	if n == nil || n.peer != peer {
		s.mu.Unlock()
		return true // never deliver a retired session's control traffic to TUN
	}
	whole := n.reassembly.add(raw, src, dst, time.Now())
	if whole == nil {
		s.mu.Unlock()
		return true
	}
	from, payload, err := parsePacket(whole, s.linkLocal)
	if err != nil {
		n.reassembly.stats.Dropped[dropMalformed]++
		s.mu.Unlock()
		return true
	}
	stats := &n.reassembly.stats
	if stats.Read == 0 {
		s.events.Emit("babel.neighbor.fragmented", peer.ID, slog.Int("size", len(whole)))
	}
	stats.Read++
	stats.Largest = max(stats.Largest, len(whole))
	s.mu.Unlock()
	s.receive(peer, from, payload)
	return true
}

// add takes one fragment from src to dst, raw an IPv6 packet whose next header is a Fragment header
// it returns the packet the fragment completes, an IPv6 packet without its Fragment header, and nil until then
func (r *reassembly) add(raw []byte, src, dst netip.Addr, now time.Time) []byte {
	r.expire(now)
	field := binary.BigEndian.Uint16(raw[42:44])
	offset, more := int(field&^7), field&1 == 1
	data, nextHeader := raw[ipv6HeaderLen+fragmentHeaderLen:], raw[ipv6HeaderLen]
	if offset == 0 && !more {
		// an atomic fragment is a whole packet, read apart from any datagram sharing its identification, RFC 6946 section 4
		if !babelUDP(nextHeader, data) {
			r.stats.Dropped[dropHeader]++
			return nil
		}
		return unfragment(slices.Concat(raw[:ipv6HeaderLen], data), nextHeader)
	}
	d := r.place(src, dst, binary.BigEndian.Uint32(raw[44:48]), now)
	if d == nil || d.done {
		return nil
	}
	end := offset + len(data)
	switch {
	case offset == 0 && !babelUDP(nextHeader, data):
		r.drop(d, dropHeader)
		return nil
	// a fragment carries an octet at least
	// one with more to come carries a multiple of 8 octets, RFC 8200 section 4.5
	// no fragment makes a packet past the largest RFC 8966 section 4 allows, 65535 octets with its IPv6 header
	// RFC 8200 allows as many after the header
	// no fragment runs past the end the last fragment set
	// the last fragment ends after every octet the others brought
	case len(data) == 0, more && len(data)%8 != 0, ipv6HeaderLen+end > math.MaxUint16,
		d.end != 0 && end > d.end, !more && ipv6HeaderLen+end < len(d.packet):
		r.drop(d, dropMalformed)
		return nil
	}
	if !more {
		d.end = end
	}
	if held, blocks := d.held(offset, end); held != 0 {
		if held == blocks && bytes.Equal(d.packet[ipv6HeaderLen+offset:ipv6HeaderLen+end], data) {
			return nil // an exact copy of octets the datagram holds goes alone, RFC 8200 section 4.5
		}
		r.drop(d, dropOverlap)
		return nil
	}
	if !r.room(d, ipv6HeaderLen+end, now) {
		return nil
	}
	copy(d.packet[ipv6HeaderLen+offset:], data)
	d.mark(offset, end)
	d.received += len(data)
	if offset == 0 {
		copy(d.packet, raw[:ipv6HeaderLen])
		d.nextHeader = nextHeader
	}
	if d.end == 0 || d.received != d.end {
		return nil
	}
	whole := unfragment(d.packet[:ipv6HeaderLen+d.end], d.nextHeader)
	r.finish(d)
	d.read = true
	return whole
}

// place finds the datagram a fragment belongs to, or opens one
// where the neighbor has no place left, a new one takes the place of the oldest datagram done that may give it
// failing that it takes the place of the oldest under way past minFragmentAge
// it drops that one
// it reuses the datagram whose place it takes
// a fragment that finds no place is refused
// place then returns nil
func (r *reassembly) place(src, dst netip.Addr, id uint32, now time.Time) *datagram {
	for _, d := range r.datagrams {
		if d.id == id && d.src == src && d.dst == dst {
			return d
		}
	}
	if len(r.datagrams) < maxFragmentedDatagrams {
		d := &datagram{src: src, dst: dst, id: id, arrived: now}
		r.datagrams = append(r.datagrams, d)
		return d
	}
	i := slices.IndexFunc(r.datagrams, func(d *datagram) bool { return d.read || (d.done && now.Sub(d.arrived) >= minFragmentAge) })
	if i < 0 {
		i = slices.IndexFunc(r.datagrams, func(d *datagram) bool { return now.Sub(d.arrived) >= minFragmentAge })
		if i < 0 {
			r.stats.Dropped[dropRefused]++
			return nil
		}
		r.drop(r.datagrams[i], dropEvicted)
	}
	d := r.datagrams[i]
	r.datagrams = append(slices.Delete(r.datagrams, i, i+1), d)
	*d = datagram{src: src, dst: dst, id: id, arrived: now}
	return d
}

// room makes the datagram's storage run to the octet at n of its whole packet
// it reports whether it could
// it grows to the power of two at or past n, a size the Go allocator holds without rounding it up, so held counts what the storage costs
// the largest Babel packet takes 64 KiB
// where the neighbor has too little left, what the storage grows by comes from the oldest others under way past minFragmentAge
// a datagram that still finds too little is refused
func (r *reassembly) room(d *datagram, n int, now time.Time) bool {
	if n <= len(d.packet) {
		return true
	}
	if n <= cap(d.packet) {
		d.packet = d.packet[:n]
		return true
	}
	size := 1 << bits.Len(uint(n-1))
	for _, other := range r.datagrams {
		if r.held+size-cap(d.packet) <= maxFragmentOctets {
			break
		}
		if other != d && !other.done && now.Sub(other.arrived) >= minFragmentAge {
			r.drop(other, dropEvicted)
		}
	}
	if r.held+size-cap(d.packet) > maxFragmentOctets {
		r.drop(d, dropRefused)
		return false
	}
	grown := make([]byte, n, size)
	copy(grown, d.packet)
	r.held += size - cap(d.packet)
	d.packet = grown
	return true
}

// expire forgets every datagram past maxFragmentAge, dropping the ones still under way, RFC 8200 section 4.5
func (r *reassembly) expire(now time.Time) {
	r.datagrams = slices.DeleteFunc(r.datagrams, func(d *datagram) bool {
		if now.Sub(d.arrived) < maxFragmentAge {
			return false
		}
		if !d.done {
			r.drop(d, dropTimeout)
		}
		return true
	})
}

// drop ends a datagram under way, counted under reason
func (r *reassembly) drop(d *datagram, reason int) {
	r.stats.Dropped[reason]++
	r.finish(d)
}

// finish ends a datagram and gives back its storage
// the storage goes with the packet read, which the caller still reads after the lock
// it never goes to another datagram
func (r *reassembly) finish(d *datagram) {
	r.held -= cap(d.packet)
	d.packet, d.done = nil, true
}

// held counts the blocks a fragment from offset to end covers, and those of them a fragment already brought
func (d *datagram) held(offset, end int) (held, blocks int) {
	for b := offset / 8; b < (end+7)/8; b++ {
		if d.blocks[b/64]&(1<<(b%64)) != 0 {
			held++
		}
	}
	return held, (end+7)/8 - offset/8
}

func (d *datagram) mark(offset, end int) {
	for b := offset / 8; b < (end+7)/8; b++ {
		d.blocks[b/64] |= 1 << (b % 64)
	}
}

// babelUDP is whether a first fragment begins with a UDP header to the Babel port
// RFC 7112 section 5 asks the first fragment to hold the header chain up to the upper-layer header, and the speaker reads nothing but UDP to its port
func babelUDP(nextHeader byte, data []byte) bool {
	return nextHeader == nextHeaderUDP && len(data) >= udpHeaderLen && binary.BigEndian.Uint16(data[2:4]) == Port
}

// unfragment makes packet, the first fragment's IPv6 header and the whole fragmentable part after it, the packet it was cut from, RFC 8200 section 4.5
func unfragment(packet []byte, nextHeader byte) []byte {
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(packet)-ipv6HeaderLen))
	packet[6] = nextHeader
	return packet
}
