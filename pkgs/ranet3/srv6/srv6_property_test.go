// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package srv6

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"slices"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// integer is every type hegel draws integers of.
type integer interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 | ~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr
}

// spanning draws from lo to hi, with the two ends drawn outright a quarter of
// the time, so every run meets them rather than only a run whose sample
// happens to land there.
func spanning[T integer](lo, hi T) hegel.Generator[T] {
	return hegel.Composite(func(tc hegel.TestCase) T {
		if hegel.Draw(tc, hegel.WeightedBooleans(1.0/4)) {
			return hegel.Draw(tc, hegel.SampledFrom([]T{lo, hi}))
		}
		return hegel.Draw(tc, hegel.Integers(lo, hi))
	})
}

// usableAddresses draws addresses CheckPath takes as a segment or a source.
func usableAddresses() hegel.Generator[netip.Addr] {
	return hegel.Filter(hegel.IPAddresses().IPv6(), Usable)
}

// usablePaths draws a segment list CheckPath accepts, one to MaxSegments long.
func usablePaths() hegel.Generator[[]netip.Addr] {
	return hegel.Composite(func(tc hegel.TestCase) []netip.Addr {
		count := hegel.Draw(tc, spanning(1, MaxSegments))
		return hegel.Draw(tc, hegel.Lists(usableAddresses()).MinSize(count).MaxSize(count))
	})
}

// payloads draws up to limit bytes, the length drawn first so that sizes
// spread over the whole range rather than staying as short as byte strings
// are drawn by default.
func payloads(tc hegel.TestCase, limit int) string {
	size := hegel.Draw(tc, spanning(0, limit))
	return string(hegel.Draw(tc, hegel.Binary(size, size)))
}

// hopLimits draws a hop limit, with 0 and 1, which a waypoint refuses to
// forward at, 2, the last it forwards at, and 255 drawn outright.
func hopLimits() hegel.Generator[uint8] {
	return hegel.OneOf(hegel.SampledFrom([]uint8{0, 1, 2, 255}), hegel.Integers[uint8](0, 255))
}

// innerPackets draws a packet an encapsulation accepts, up to 1500 bytes and
// built by innerV4 and innerV6Hops as the table tests build theirs, with the
// header fields H.Encaps copies onto the outer header drawn as well: the
// traffic class, the flow label and the hop limit of an IPv6 packet. The TOS
// and the TTL of an IPv4 one are drawn too, the two it must not copy.
func innerPackets() hegel.Generator[[]byte] {
	return hegel.Composite(func(tc hegel.TestCase) []byte {
		if hegel.Draw(tc, hegel.Booleans()) {
			raw := innerV4(payloads(tc, 1500-ipv4HeaderLen))
			raw[1] = hegel.Draw(tc, spanning[byte](0, 0xff))
			raw[8] = hegel.Draw(tc, hopLimits())
			return raw
		}
		raw := innerV6Hops(payloads(tc, 1500-ipv6HeaderLen), hegel.Draw(tc, hopLimits()))
		binary.BigEndian.PutUint32(raw, 6<<28|hegel.Draw(tc, spanning[uint32](0, 1<<28-1)))
		return raw
	})
}

// mostly draws from usual seven times in eight, and from rare otherwise.
func mostly[T any](usual, rare hegel.Generator[T]) hegel.Generator[T] {
	return hegel.Composite(func(tc hegel.TestCase) T {
		if hegel.Draw(tc, hegel.WeightedBooleans(1.0/8)) {
			return hegel.Draw(tc, rare)
		}
		return hegel.Draw(tc, usual)
	})
}

// mangledPackets draws a well formed encapsulation, walked some way along its
// path and sometimes put behind extension headers, and then left whole or
// damaged in one of three ways: a few bytes of its headers overwritten, its
// tail cut off, or one header's length octet made to claim other than the
// header holds. Bytes drawn whole almost never get past the version and next
// header checks, and these reach every branch of the chain walk, the routing
// header read and the exit.
func mangledPackets() hegel.Generator[[]byte] {
	return hegel.Composite(func(tc hegel.TestCase) []byte {
		inner := hegel.Draw(tc, innerPackets())
		raw, err := Encapsulate(inner, hegel.Draw(tc, usableAddresses()), hegel.Draw(tc, usablePaths()))
		if err != nil {
			tc.Errorf("a packet and a path drawn to be accepted were refused: %v", err)
		}
		for range hegel.Draw(tc, hegel.Integers(0, MaxSegments)) {
			if _, err := End(raw); err != nil {
				break
			}
		}
		// Hop-by-hop and destination options headers in front of the
		// routing header, each pointing on to the next: mostly one or two,
		// and now and then the most findRouting walks past or one more than
		// that, with the odd fragment header among them, which ends the walk
		// wherever it sits. lengths is where each header's length octet
		// sits, the routing header's first.
		chain := hegel.OneOf(hegel.Integers(0, 2), hegel.SampledFrom([]int{maxExtensionHeaders - 1, maxExtensionHeaders}))
		lengths := []int{ipv6HeaderLen + 1}
		for range hegel.Draw(tc, chain) {
			kind := hegel.Draw(tc, hegel.SampledFrom([]byte{nextHeaderHopByHop, nextHeaderDestOpts}))
			if hegel.Draw(tc, hegel.WeightedBooleans(1.0/8)) {
				kind = nextHeaderFragment
			}
			units := hegel.Draw(tc, hegel.Integers(0, 2))
			header := hegel.Draw(tc, hegel.Binary(extensionUnit*(1+units), extensionUnit*(1+units)))
			header[0], header[1] = raw[6], byte(units)
			raw = slices.Concat(raw[:ipv6HeaderLen], header, raw[ipv6HeaderLen:])
			raw[6] = kind
			for i := range lengths {
				lengths[i] += len(header)
			}
			lengths = append(lengths, ipv6HeaderLen+1)
		}
		binary.BigEndian.PutUint16(raw[4:], uint16(len(raw)-ipv6HeaderLen))
		// The damage stays in the headers, the bytes the parsers read, rather
		// than in the inner packet that is most of the packet. A length
		// octet claims anything up to the 255 units it can say, those two ends
		// half the time, and 255 runs past the end of any packet. That is an
		// extension header's octet where there is one, since a header in
		// front of the routing header claiming more than the packet holds is
		// one the walk has to refuse rather than follow.
		headers := len(raw) - len(inner)
		switch hegel.Draw(tc, hegel.Integers(0, 4)) {
		case 1:
			for range hegel.Draw(tc, hegel.Integers(1, 4)) {
				raw[hegel.Draw(tc, hegel.Integers(0, headers-1))] = hegel.Draw(tc, hegel.Integers[byte](0, 255))
			}
		case 2:
			raw = raw[:hegel.Draw(tc, spanning(0, headers))]
		case 3, 4:
			at := lengths[0]
			if len(lengths) > 1 && hegel.Draw(tc, hegel.WeightedBooleans(3.0/4)) {
				at = hegel.Draw(tc, hegel.SampledFrom(lengths[1:]))
			}
			raw[at] = hegel.Draw(tc, hegel.OneOf(hegel.SampledFrom([]byte{0, 255}), hegel.Integers[byte](0, 255)))
		}
		return raw
	})
}

// lyingLengths draws an encapsulation behind none, one or two extension
// headers, one of whose length octets, the routing header's own among them,
// claims a length the packet may not hold. The claim is drawn from 0 to 255,
// and half the time from the four lengths at the end of the packet: the
// header ending one unit short of it, at or just inside it, and one and two
// units past it. Those are where findRouting and Parse decide between a
// header they can read and one they must refuse, and mangledPackets reaches
// them only now and then. Where there is an extension header, the one in
// front of the routing header is the one lying in at least half the draws,
// since only its length carries the walk on to the routing header.
func lyingLengths() hegel.Generator[[]byte] {
	return hegel.Composite(func(tc hegel.TestCase) []byte {
		inner := hegel.Draw(tc, innerPackets())
		raw, err := Encapsulate(inner, hegel.Draw(tc, usableAddresses()), hegel.Draw(tc, usablePaths()))
		if err != nil {
			tc.Errorf("a packet and a path drawn to be accepted were refused: %v", err)
		}
		// starts is where each header begins, the routing header's first
		starts := []int{ipv6HeaderLen}
		for range hegel.Draw(tc, hegel.Integers(0, 2)) {
			header := make([]byte, extensionUnit)
			header[0], header[2], header[3] = raw[6], 1, 4 // a PadN filling it
			raw = slices.Concat(raw[:ipv6HeaderLen], header, raw[ipv6HeaderLen:])
			raw[6] = hegel.Draw(tc, hegel.SampledFrom([]byte{nextHeaderHopByHop, nextHeaderDestOpts}))
			for i := range starts {
				starts[i] += extensionUnit
			}
			starts = append(starts, ipv6HeaderLen)
		}
		binary.BigEndian.PutUint16(raw[4:], uint16(len(raw)-ipv6HeaderLen))
		start := hegel.Draw(tc, hegel.SampledFrom(starts))
		if len(starts) > 1 && hegel.Draw(tc, hegel.Booleans()) {
			start = starts[1]
		}
		// the units after a header's first that would end it at the packet's end
		fits := (len(raw)-start)/extensionUnit - 1
		var near []byte
		for _, units := range []int{fits - 1, fits, fits + 1, fits + 2} {
			if units >= 0 && units <= 255 {
				near = append(near, byte(units))
			}
		}
		claim := hegel.Integers[byte](0, 255)
		if len(near) > 0 && hegel.Draw(tc, hegel.Booleans()) {
			claim = hegel.SampledFrom(near)
		}
		raw[start+1] = hegel.Draw(tc, claim)
		return raw
	})
}

// boundaryFields draws a well formed encapsulation, walked some way along its
// path, with one routing header field set just past what it says of itself:
// Segments Left one past Last Entry, which a reduced header carries, or two
// past it, Hdr Ext Len one unit short of its segments, or Last Entry one
// segment past what that length holds. Otherwise Segments Left is set to zero
// and the packet cut where the routing header ends, an exit with nothing after
// the header to deliver. Segments Left takes two draws in five, since only the
// second of its two values is one Parse refuses. An encapsulation writes the
// value on the near side of each edge, so every other shape draws those, and
// damage drawn anywhere in a header lands on the far ones only by luck.
func boundaryFields() hegel.Generator[[]byte] {
	return hegel.Composite(func(tc hegel.TestCase) []byte {
		inner := hegel.Draw(tc, innerPackets())
		raw, err := Encapsulate(inner, hegel.Draw(tc, usableAddresses()), hegel.Draw(tc, usablePaths()))
		if err != nil {
			tc.Errorf("a packet and a path drawn to be accepted were refused: %v", err)
		}
		for range hegel.Draw(tc, hegel.Integers(0, MaxSegments)) {
			if _, err := End(raw); err != nil {
				break
			}
		}
		srh := raw[ipv6HeaderLen:]
		lastEntry, units := int(srh[4]), int(srh[1])
		switch hegel.Draw(tc, hegel.Integers(0, 4)) {
		case 0, 1:
			srh[3] = byte(lastEntry + hegel.Draw(tc, hegel.Integers(1, 2)))
		case 2:
			srh[1] = byte(units - 1)
		case 3:
			srh[4] = byte(units / 2)
		default:
			srh[3] = 0
			raw = raw[:ipv6HeaderLen+srhFixedLen+extensionUnit*units]
		}
		return raw
	})
}

// Parse, End and Decap read bytes a peer chose, and a waypoint or an exit runs
// them on every packet addressed to one of its segments, so no input may make
// them panic: each answers with an error or with a value inside the packet it
// was given. A header Parse accepts describes itself, with its segment list,
// the segment it points at and the length it claims all inside the packet,
// and the segment list inside that length, since End and Decap index the
// packet by them and the payload starts where that length ends. The ICMP
// answers to a refused packet read the same bytes and are held to the same.
// Every one of them is handed the packet with no capacity past its length, so
// reading past its end panics here, where in a dataplane buffer it would read
// whatever followed the packet.
func TestParseNeverPanicsOnArbitraryBytes(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		raw := slices.Clip(hegel.Draw(ht, hegel.OneOf(
			hegel.Composite(func(tc hegel.TestCase) []byte { return []byte(payloads(tc, 1500)) }),
			mangledPackets(),
			lyingLengths(),
			boundaryFields(),
		)))

		if header, err := Parse(raw); err == nil {
			end := header.Offset + srhFixedLen + addrLen*len(header.Segments)
			switch {
			case len(header.Segments) == 0 || len(header.Segments) > MaxSegments:
				ht.Fatalf("Parse accepted %d segments", len(header.Segments))
			case int(header.SegmentsLeft) > len(header.Segments):
				ht.Fatalf("Parse accepted segments left %d past %d segments", header.SegmentsLeft, len(header.Segments))
			case header.Offset < ipv6HeaderLen || end > len(raw):
				ht.Fatalf("Parse placed %d segments at %d in a %d byte packet", len(header.Segments), header.Offset, len(raw))
			case header.Offset+srhFixedLen+extensionUnit*int(raw[header.Offset+1]) > len(raw):
				ht.Fatalf("Parse accepted a routing header at %d claiming %d units in a %d byte packet",
					header.Offset, raw[header.Offset+1], len(raw))
			case end > header.Offset+srhFixedLen+extensionUnit*int(raw[header.Offset+1]):
				ht.Fatalf("Parse accepted %d segments in a routing header claiming %d units",
					len(header.Segments), raw[header.Offset+1])
			}
		}
		End(slices.Clip(bytes.Clone(raw)))
		if inner, family, err := Decap(slices.Clip(bytes.Clone(raw))); err == nil {
			if len(inner) == 0 || family != NextHeaderIPv4 && family != NextHeaderIPv6 {
				ht.Fatalf("Decap delivered %d bytes of family %d", len(inner), family)
			}
		}
		from := addr("3fff:1:69c:8c6::2")
		TimeExceeded(raw, from)
		ParameterProblem(raw, from)
	})
}

// A packet encapsulated over any path this node accepts reads back as that
// path: Parse gives the segments in the order the packet visits them, with
// the first one active and on the outer header, and the inner packet follows
// the routing header byte for byte. Each waypoint then moves it to the next
// segment, writing that segment into the outer destination, until the exit
// hands back the inner packet and its family. The outer header copies the
// traffic class, the flow label and the hop limit of an IPv6 inner packet and
// takes none of an IPv4 one's, its TOS and TTL included, so a walk stops with
// ErrHopLimit exactly where the inner IPv6 budget runs out, and nowhere else.
// A reversal or an offset wrong in any one of these sends traffic through the
// waypoints in the wrong order, or delivers something other than what was
// sent.
func TestEncapsulationParsesBackToItsPath(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		inner := hegel.Draw(ht, innerPackets())
		source := hegel.Draw(ht, usableAddresses())
		path := hegel.Draw(ht, usablePaths())

		raw, err := Encapsulate(inner, source, path)
		if err != nil {
			ht.Fatalf("Encapsulate refused %d bytes over %v: %v", len(inner), path, err)
		}
		header, err := Parse(raw)
		if err != nil {
			ht.Fatalf("Parse refused what Encapsulate wrote: %v", err)
		}
		family, hops, word := uint8(NextHeaderIPv4), uint8(DefaultHopLimit), []byte{0x60, 0, 0, 0}
		if inner[0]>>4 == 6 {
			family, hops, word = NextHeaderIPv6, inner[7], inner[:4]
		}
		switch active, ok := header.Active(); {
		case !slices.Equal(header.Path(), path):
			ht.Fatalf("the path read back as %v, want %v", header.Path(), path)
		case int(header.SegmentsLeft) != len(path)-1:
			ht.Fatalf("segments left is %d for a path of %d", header.SegmentsLeft, len(path))
		case !ok || active != path[0]:
			ht.Fatalf("the active segment is %v, %v, want %v", active, ok, path[0])
		case header.NextHeader != family || header.Offset != ipv6HeaderLen:
			ht.Fatalf("the routing header at %d announces %d, want one at %d announcing %d",
				header.Offset, header.NextHeader, ipv6HeaderLen, family)
		case netip.AddrFrom16([16]byte(raw[24:40])) != path[0] || netip.AddrFrom16([16]byte(raw[8:24])) != source:
			ht.Fatalf("the outer header runs from %v to %v", netip.AddrFrom16([16]byte(raw[8:24])), netip.AddrFrom16([16]byte(raw[24:40])))
		case int(binary.BigEndian.Uint16(raw[4:])) != len(raw)-ipv6HeaderLen || raw[7] != hops:
			ht.Fatalf("the outer header carries payload length %d and hop limit %d, want %d and %d",
				binary.BigEndian.Uint16(raw[4:]), raw[7], len(raw)-ipv6HeaderLen, hops)
		case !bytes.Equal(raw[:4], word):
			ht.Fatalf("the outer header opens with %x, want %x", raw[:4], word)
		case !bytes.Equal(raw[header.Offset+srhFixedLen+addrLen*len(header.Segments):], inner):
			ht.Fatal("the bytes after the routing header are not the inner packet")
		}

		for step, want := range path[1:] {
			before := raw[7]
			next, err := End(raw)
			if before <= 1 {
				if !errors.Is(err, ErrHopLimit) {
					ht.Fatalf("waypoint %d with hop limit %d returned %v, %v, want ErrHopLimit", step, before, next, err)
				}
				return
			}
			destination := netip.AddrFrom16([16]byte(raw[24:40]))
			if err != nil || next != want || raw[7] != before-1 || destination != next {
				ht.Fatalf("waypoint %d returned %v, %v, leaving destination %v and hop limit %d, want %v and %d",
					step, next, err, destination, raw[7], want, before-1)
			}
		}
		delivered, got, err := Decap(raw)
		if err != nil || got != family || !bytes.Equal(delivered, inner) {
			ht.Fatalf("the exit delivered %d bytes of family %d, %v, want the %d byte inner packet of family %d",
				len(delivered), got, err, len(inner), family)
		}
	})
}

// EncapsulateInPlace writes the bytes Encapsulate returns, for the same packet,
// source and path, at the offset it was given and nowhere else. The buffer
// starts filled with a byte the expected header does not contain, so a header
// byte left as it was found shows up as a difference, rather than going on
// the wire as a stray fragment of whatever the buffer held. Both refuse the
// same inputs, the in-place one also refuses a buffer too short for the
// result, and a refusal leaves the buffer as it was.
func TestEncapsulateInPlaceWritesWhatEncapsulateReturns(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		// mostly what both accept, and now and then what both refuse
		inner := hegel.Draw(ht, mostly(innerPackets(), hegel.Binary(0, 64)))
		source := hegel.Draw(ht, mostly(usableAddresses(), hegel.Generator[netip.Addr](hegel.IPAddresses())))
		path := hegel.Draw(ht, mostly(usablePaths(), hegel.Lists(hegel.IPAddresses()).MaxSize(MaxSegments+1)))
		offset := hegel.Draw(ht, spanning(0, 64))
		// the room past the packet, now and then too little for the header
		room := Overhead(len(path)) + hegel.Draw(ht, spanning(0, 64))
		if hegel.Draw(ht, hegel.WeightedBooleans(1.0/8)) {
			room = hegel.Draw(ht, spanning(0, Overhead(len(path))-1))
		}

		want, wantErr := Encapsulate(inner, source, path)
		fill := hegel.Draw(ht, hegel.Integers[byte](0, 255))
		if wantErr == nil {
			header := want[:Overhead(len(path))]
			for tries := 0; bytes.IndexByte(header, fill) >= 0; tries++ {
				ht.Assume(tries < 256)
				fill++
			}
		}
		buf := bytes.Repeat([]byte{fill}, offset+len(inner)+room)
		copy(buf[offset:], inner)
		before := bytes.Clone(buf)

		n, err := EncapsulateInPlace(buf, offset, len(inner), source, path)
		switch {
		case wantErr != nil || room < Overhead(len(path)):
			if err == nil {
				ht.Fatalf("EncapsulateInPlace wrote %d bytes into %d of room where Encapsulate answered %v", n, room, wantErr)
			}
			if !bytes.Equal(buf, before) {
				ht.Fatalf("a refusal changed the buffer: %v", err)
			}
		case err != nil:
			ht.Fatalf("EncapsulateInPlace refused what Encapsulate wrote, with %d bytes of room: %v", room, err)
		case n != len(want) || !bytes.Equal(buf[offset:offset+n], want):
			ht.Fatalf("EncapsulateInPlace wrote\n%x\nwhere Encapsulate returned\n%x", buf[offset:offset+n], want)
		case bytes.Count(buf[:offset], []byte{fill}) != offset || bytes.Count(buf[offset+n:], []byte{fill}) != len(buf)-offset-n:
			ht.Fatalf("EncapsulateInPlace wrote outside the %d bytes at %d", n, offset)
		}
	})
}
