// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package packet

import (
	"bytes"
	"encoding/binary"
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

// bytesUpTo draws up to limit bytes, the length drawn first so that sizes
// spread over the whole range rather than staying as short as byte strings
// are drawn by default.
func bytesUpTo(tc hegel.TestCase, limit int) []byte {
	size := hegel.Draw(tc, spanning(0, limit))
	return hegel.Draw(tc, hegel.Binary(size, size))
}

// built is a packet put together from drawn fields, with what reading it
// back has to find.
type built struct {
	raw      []byte
	version  byte
	length   int // the bytes the header declares, its own included
	src, dst netip.Addr
	trailing int // bytes after the packet, the TFC padding an ESP payload may carry
}

// builtPackets draws an IPv4 or IPv6 packet up to 1500 bytes from ipv4 and
// ipv6, the helpers the table tests build with, its fields drawn: an IPv4
// header from no options to the forty bytes of them its length nibble can
// say, and an IPv6 one with any traffic class, flow label, next header and
// hop limit. Half the packets have bytes after them, as an ESP payload may.
func builtPackets() hegel.Generator[built] {
	return hegel.Composite(func(tc hegel.TestCase) built {
		var trailing []byte
		if hegel.Draw(tc, hegel.Booleans()) {
			trailing = bytesUpTo(tc, 64)
		}
		if hegel.Draw(tc, hegel.Booleans()) {
			headerLen := 4 * hegel.Draw(tc, spanning(5, 15))
			payload := bytesUpTo(tc, 1500-headerLen)
			p := built{version: 4, length: headerLen + len(payload), trailing: len(trailing),
				src: hegel.Draw(tc, hegel.IPAddresses().IPv4()), dst: hegel.Draw(tc, hegel.IPAddresses().IPv4())}
			p.raw = ipv4(p.length, p.length-20+len(trailing))
			p.raw[0] = 0x40 | byte(headerLen/4)
			p.raw[1] = hegel.Draw(tc, hegel.Integers[byte](0, 255))
			copy(p.raw[4:12], hegel.Draw(tc, hegel.Binary(8, 8)))
			copy(p.raw[12:], p.src.AsSlice())
			copy(p.raw[16:], p.dst.AsSlice())
			copy(p.raw[20:headerLen], hegel.Draw(tc, hegel.Binary(headerLen-20, headerLen-20)))
			copy(p.raw[headerLen:], payload)
			copy(p.raw[p.length:], trailing)
			return p
		}
		payload := bytesUpTo(tc, 1500-40)
		p := built{version: 6, length: 40 + len(payload), trailing: len(trailing),
			src: hegel.Draw(tc, hegel.IPAddresses().IPv6()), dst: hegel.Draw(tc, hegel.IPAddresses().IPv6())}
		p.raw = ipv6(len(payload), len(payload)+len(trailing))
		binary.BigEndian.PutUint32(p.raw, 6<<28|hegel.Draw(tc, spanning[uint32](0, 1<<28-1)))
		p.raw[6], p.raw[7] = hegel.Draw(tc, hegel.Integers[byte](0, 255)), hegel.Draw(tc, hegel.Integers[byte](0, 255))
		copy(p.raw[8:], p.src.AsSlice())
		copy(p.raw[24:], p.dst.AsSlice())
		copy(p.raw[40:], payload)
		copy(p.raw[p.length:], trailing)
		return p
	})
}

// A packet built from any fields reads back as them: Payload trims it to the
// length its header declares and names its version, Version and Addrs take it
// only when nothing follows it, and Addrs gives back the two addresses it was
// built with. The TUN reader and the ESP path decide where every packet goes
// from these, so a field read from the wrong place sends traffic to an
// address nobody wrote. An IPv6 packet declaring no payload with bytes after
// it is the jumbogram encoding, which the package documents as refused rather
// than trimmed to an empty packet.
func TestBuiltHeaderReadsBackItsFields(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		p := hegel.Draw(ht, builtPackets())

		wantPayload, wantVersion := p.raw[:p.length], p.version
		if p.version == 6 && p.length == 40 && p.trailing > 0 {
			wantPayload, wantVersion = nil, 0
		}
		payload, version := Payload(p.raw)
		if version != wantVersion || !bytes.Equal(payload, wantPayload) {
			ht.Fatalf("Payload read %d bytes of version %d out of %d, want %d of version %d",
				len(payload), version, len(p.raw), len(wantPayload), wantVersion)
		}

		whole := wantVersion != 0 && p.trailing == 0
		wantSrc, wantDst := p.src, p.dst
		if !whole {
			wantVersion, wantSrc, wantDst = 0, netip.Addr{}, netip.Addr{}
		}
		if got := Version(p.raw); got != wantVersion {
			ht.Fatalf("Version read %d for a version %d packet with %d bytes after it", got, p.version, p.trailing)
		}
		if src, dst, got := Addrs(p.raw); src != wantSrc || dst != wantDst || got != wantVersion {
			ht.Fatalf("Addrs read %v to %v, version %d, want %v to %v, version %d", src, dst, got, wantSrc, wantDst, wantVersion)
		}
	})
}

// lengthsAtTheirEdges draws a built packet with its length field set to one
// of the claims Payload's decisions turn on: the bytes there are, one past
// them and, for IPv4, the header's own length and one between a fixed header
// and it, with that header from the fixed one up to the sixty bytes its
// length nibble can say. Damage drawn anywhere lands on these only by luck.
func lengthsAtTheirEdges() hegel.Generator[[]byte] {
	return hegel.Composite(func(tc hegel.TestCase) []byte {
		p := hegel.Draw(tc, builtPackets())
		raw := p.raw
		if p.version == 6 {
			binary.BigEndian.PutUint16(raw[4:], uint16(len(raw)-40+hegel.Draw(tc, hegel.Integers(0, 1))))
			return raw
		}
		ihl := hegel.Draw(tc, spanning[byte](5, 15))
		raw[0] = 0x40 | ihl
		header := 4 * int(ihl)
		claims := []int{len(raw), len(raw) + 1, header}
		if header > 20 {
			claims = append(claims, hegel.Draw(tc, hegel.Integers(20, header-1)))
		}
		binary.BigEndian.PutUint16(raw[2:], uint16(hegel.Draw(tc, hegel.SampledFrom(claims))))
		return raw
	})
}

// Every header a node reads comes off the TUN or out of an ESP payload a peer
// sealed, so no bytes may panic the readers: each answers with a packet or
// with nothing. What Payload answers is a front part of what it was given, of
// the version it names, at least as long as that version's fixed header and,
// for IPv4, declaring a header at least that long and no longer than itself.
// Version and Addrs agree with it, taking the bytes only when that part is
// all of them. The bytes are drawn whole, built with a length at one of its
// edges as lengthsAtTheirEdges draws them, or built and then damaged: a few of
// the first sixty overwritten, where every field either header has sits, the
// tail cut off, or the header's length fields, which every decision Payload
// makes is read from, made to claim anything from zero to a little past the
// bytes there are. They are handed over with no capacity past their length,
// so reading past the end panics here, where in a read buffer it would find
// stale bytes.
func TestHeaderParsingNeverPanicsOnArbitraryBytes(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		raw := slices.Clip(hegel.Draw(ht, hegel.OneOf(
			hegel.Composite(func(tc hegel.TestCase) []byte { return bytesUpTo(tc, 1500) }),
			lengthsAtTheirEdges(),
			hegel.Composite(func(tc hegel.TestCase) []byte {
				p := hegel.Draw(tc, builtPackets())
				raw := p.raw
				switch hegel.Draw(tc, hegel.Integers(0, 3)) {
				case 1:
					for range hegel.Draw(tc, hegel.Integers(1, 4)) {
						raw[hegel.Draw(tc, hegel.Integers(0, min(60, len(raw))-1))] = hegel.Draw(tc, hegel.Integers[byte](0, 255))
					}
				case 2:
					raw = raw[:hegel.Draw(tc, spanning(0, len(raw)))]
				case 3:
					if p.version == 4 {
						raw[0] = 0x40 | hegel.Draw(tc, spanning[byte](0, 15))
						binary.BigEndian.PutUint16(raw[2:], hegel.Draw(tc, spanning[uint16](0, uint16(len(raw)+8))))
					} else {
						binary.BigEndian.PutUint16(raw[4:], hegel.Draw(tc, spanning[uint16](0, uint16(len(raw)-40+8))))
					}
				}
				return raw
			}),
		)))

		payload, version := Payload(raw)
		switch {
		case version == 0 && payload != nil:
			ht.Fatalf("Payload answered %d bytes with no version", len(payload))
		case version != 0 && version != 4 && version != 6:
			ht.Fatalf("Payload answered version %d", version)
		case version != 0 && (len(payload) > len(raw) || len(payload) > 0 && &payload[0] != &raw[0]):
			ht.Fatalf("Payload answered %d bytes that are not the front of the %d it was given", len(payload), len(raw))
		case version == 4 && (len(payload) < 20 || int(payload[0]&0xf)*4 < 20 || len(payload) < int(payload[0]&0xf)*4) ||
			version == 6 && len(payload) < 40:
			ht.Fatalf("Payload answered %d bytes of version %d, shorter than the header it declares", len(payload), version)
		}
		whole := byte(0)
		if version != 0 && len(payload) == len(raw) {
			whole = version
		}
		if got := Version(raw); got != whole {
			ht.Fatalf("Version answered %d where Payload took %d of %d bytes as version %d", got, len(payload), len(raw), version)
		}
		if src, dst, got := Addrs(raw); got != whole || (got == 0) != (!src.IsValid() && !dst.IsValid()) {
			ht.Fatalf("Addrs answered %v to %v, version %d, where Version answered %d", src, dst, got, whole)
		}
	})
}
