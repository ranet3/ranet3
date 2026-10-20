// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package packet

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"slices"
	"testing"
	"time"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// for any header bytes, every header length from 20 to 60 bytes and every TTL
// a TTL of 1 or 0 is refused with nothing changed, and any other is taken down by one
// with the checksum equal to the one a full recompute writes and every other byte as it was
func TestDecrementTTLAgreesWithAFullRecompute(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		drawn := hegel.Draw(ht, hegel.Binary(maxIPv4HeaderLen, maxIPv4HeaderLen))
		for headerLen := ipv4HeaderLen; headerLen <= maxIPv4HeaderLen; headerLen += 4 {
			for ttl := range 256 {
				header := bytes.Clone(drawn[:headerLen])
				header[0] = 4<<4 | byte(headerLen/4)
				binary.BigEndian.PutUint16(header[2:], uint16(headerLen))
				header[8] = byte(ttl)
				binary.BigEndian.PutUint16(header[10:], 0)
				binary.BigEndian.PutUint16(header[10:], ^headerSum(header))
				before := bytes.Clone(header)

				ok := DecrementTTL(header)
				if ttl <= 1 {
					if ok || !bytes.Equal(header, before) {
						ht.Fatalf("a TTL of %d was taken down to %d, reported %t", ttl, header[8], ok)
					}
					continue
				}
				if !ok || header[8] != byte(ttl-1) {
					ht.Fatalf("a TTL of %d reads %d after, reported %t", ttl, header[8], ok)
				}
				recomputed := bytes.Clone(header)
				binary.BigEndian.PutUint16(recomputed[10:], 0)
				binary.BigEndian.PutUint16(recomputed[10:], ^headerSum(recomputed))
				if !bytes.Equal(header, recomputed) {
					ht.Fatalf("a %d byte header with a TTL of %d has the checksum %#04x, a full recompute %#04x",
						headerLen, ttl, binary.BigEndian.Uint16(header[10:]), binary.BigEndian.Uint16(recomputed[10:]))
				}
				header[8], header[10], header[11] = before[8], before[10], before[11]
				if !bytes.Equal(header, before) {
					ht.Fatal("a byte other than the TTL and the checksum changed")
				}
			}
		}
	})
}

// for any bytes a link may deliver, swept in each case over the edges RFC 1812 section 5.2.2's five tests turn on
// a link of 19, 20, 24, 59 and 60 bytes and one of any length to 120, the versions 3 to 6, every header length
// a total length either side of the header and of the link and one of any value
// and a checksum that holds, holds in its other form, is one off, or is left as drawn
// HeaderValid holds exactly where fiveTests does
func TestHeaderValidIsTheFiveTests(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		drawn := hegel.Draw(ht, hegel.Binary(2*maxIPv4HeaderLen, 2*maxIPv4HeaderLen))
		anyLink := hegel.Draw(ht, pbt.Spanning(0, 2*maxIPv4HeaderLen))
		anyTotal := hegel.Draw(ht, pbt.Spanning(0, 0xffff))
		for _, link := range []int{19, 20, 24, 59, 60, anyLink} {
			for version := byte(3); version <= 6; version++ {
				for words := range byte(16) {
					headerLen := int(words) * 4
					for _, total := range []int{headerLen - 1, headerLen, link - 1, link, link + 1, anyTotal} {
						for checksum := range 4 {
							raw := bytes.Clone(drawn[:link])
							if link > 0 {
								raw[0] = version<<4 | words
							}
							if link >= 4 {
								binary.BigEndian.PutUint16(raw[2:], uint16(max(total, 0)))
							}
							if summed := min(headerLen, link); summed >= 12 {
								binary.BigEndian.PutUint16(raw[10:], 0)
								switch checksum {
								case 0:
									binary.BigEndian.PutUint16(raw[10:], ^headerSum(raw[:summed]))
								case 1:
									binary.BigEndian.PutUint16(raw[10:], ^headerSum(raw[:summed])+1)
								case 2:
									// an identification that makes the checksum zero, written in its other form, which a receiver's sum folds to 0xffff all the same
									binary.BigEndian.PutUint16(raw[4:], 0)
									binary.BigEndian.PutUint16(raw[4:], ^headerSum(raw[:summed]))
									binary.BigEndian.PutUint16(raw[10:], 0xffff)
								default:
									copy(raw[10:12], drawn[10:12])
								}
							}
							if got, want := HeaderValid(raw), fiveTests(raw); got != want {
								ht.Fatalf("HeaderValid(% x) is %t, RFC 1812's tests say %t", raw, got, want)
							}
						}
					}
				}
			}
		}
	})
}

// the four option types past END and NOP a router forwarding a header acts on, and those of other options the walk passes as it found them
// Router Alert and CIPSO among them, whose layouts Linux checks and ranet3 does not
var (
	routeKinds  = []byte{optionLooseSource, optionStrictSource, optionRecordRoute, optionTimestamp}
	passedKinds = []byte{2, 25, 82, 130, 133, 134, 136, 145, 148, 149, 150, 151, 152, 158, 205, 222}
)

// the ways an entry of the list is drawn, and the ways of each option a router acts on, valid and broken
// every case of the walker's property draws each of them once, among entries drawn any of these ways
var (
	entryWays = []string{"nop", "end", "another option", "source route", "record route", "timestamp",
		"a length under 2", "a length past the list", "a type octet last"}
	sourceRouteWays = []string{"routes", "a length of 2", "a pointer under 4"}
	recordRouteWays = []string{"records", "full", "a length of 2", "a pointer under 4", "room for less than an address"}
	timestampValid  = []string{"stamps", "stamps with the address", "stamps as this node", "is named for another node",
		"carries a flag RFC 791 does not define", "full", "full and prespecified", "full and prespecified with its overflow at 15"}
	timestampWays = append(slices.Clone(timestampValid), "full with its overflow at 15", "a length under 4", "a pointer under 5",
		"room for less than a timestamp", "room for a timestamp and no address")
)

// drawnOption is one entry of an option list as the walker's property draws it, valid or broken in the one way its name says
// and what RFC 791's layout and Linux's ip_options_compile, in the order it checks, make of it
type drawnOption struct {
	name  string
	bytes []byte
	// kind is the option's type, and for a framing fault the one its type octet carries
	kind byte
	// framing is a list the walk cannot frame at this option, its type octet the one at fault
	// a length under 2, a length past the list, or a type octet in the list's last byte
	framing bool
	// fault is the offset in the option of the octet its own layout refuses, -1 where it reads
	fault int
	// after is the option once a router forwarding the header has recorded into it, nil where it is forwarded as it came
	after []byte
	// pastList sets the option's length past the end of the list once the list is laid out, and last puts its type octet there
	pastList, last bool
	// offset is where the option sits in the list once it is laid out
	offset int
}

// optionModel draws options for a node at address, which a prespecified timestamp names or not, stamping at ms milliseconds after midnight UT
type optionModel struct {
	ht      *hegel.T
	address netip.Addr
	ms      uint32
}

// body is n bytes of anything
func (m optionModel) body(n int) []byte { return hegel.Draw(m.ht, hegel.Binary(n, n)) }

// way draws one of ways
func (m optionModel) way(ways ...string) string { return hegel.Draw(m.ht, hegel.SampledFrom(ways)) }

// sourceRouteKind draws loose or strict
func (m optionModel) sourceRouteKind() byte {
	return hegel.Draw(m.ht, hegel.SampledFrom([]byte{optionLooseSource, optionStrictSource}))
}

// stamp is the timestamp RFC 791 records, the milliseconds since midnight UT in 32 bits
func (m optionModel) stamp() []byte { return binary.BigEndian.AppendUint32(nil, m.ms) }

// layout writes kind, length and pointer in front of length-3 bytes of anything
func (m optionModel) layout(kind byte, length, pointer int) []byte {
	return append([]byte{kind, byte(length), byte(pointer)}, m.body(length-3)...)
}

// recordRoute is Record Route, RFC 791, drawn as way names: an address in the slot the pointer names, the pointer on by 4
// a pointer past the length is a full option, forwarded as it came
// Linux refuses a length under 3 at the length, a pointer under 4 at the pointer, and a slot with room for less than an address at the pointer
func (m optionModel) recordRoute(way string) drawnOption {
	switch way {
	case "records":
		length := hegel.Draw(m.ht, pbt.Spanning(7, 23))
		pointer := hegel.Draw(m.ht, pbt.Spanning(4, length-3))
		option := m.layout(optionRecordRoute, length, pointer)
		after := bytes.Clone(option)
		from := m.address.As4()
		copy(after[pointer-1:], from[:])
		after[2] += addressLen
		return drawnOption{name: "record route that " + way, kind: optionRecordRoute, bytes: option, fault: -1, after: after}
	case "full":
		length := hegel.Draw(m.ht, pbt.Spanning(3, 23))
		return drawnOption{name: "full record route", kind: optionRecordRoute,
			bytes: m.layout(optionRecordRoute, length, hegel.Draw(m.ht, pbt.Spanning(length+1, 255))), fault: -1}
	case "a length of 2":
		return drawnOption{name: "record route with " + way, kind: optionRecordRoute, bytes: []byte{optionRecordRoute, 2}, fault: 1}
	case "a pointer under 4":
		return drawnOption{name: "record route with " + way, kind: optionRecordRoute,
			bytes: m.layout(optionRecordRoute, hegel.Draw(m.ht, pbt.Spanning(3, 15)), hegel.Draw(m.ht, pbt.Spanning(0, 3))), fault: 2}
	default:
		length := hegel.Draw(m.ht, pbt.Spanning(4, 23))
		return drawnOption{name: "record route with " + way, kind: optionRecordRoute,
			bytes: m.layout(optionRecordRoute, length, hegel.Draw(m.ht, pbt.Spanning(max(4, length-2), length))), fault: 2}
	}
}

// timestamp is Timestamp, RFC 791, drawn as way names: flag 0 records the time, flag 1 the address and the time
// flag 3 the time where the slot names this node, and other flags nothing, each slot at the pointer, which moves on past what was recorded
// a full option, its pointer past its length, counts one more overflow, but under flag 3, which Linux leaves as it came
// Linux refuses a length under 4 at the length, a pointer under 5 at the pointer, a slot with room for less than its flags record at the pointer
// and a full option whose overflow is already 15 at the flags
func (m optionModel) timestamp(way string) drawnOption {
	other := []byte{2, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	notNamed := []byte{0, 1, 2, 4, 9, 15}
	stamped := func(flags byte, length, pointer int) []byte {
		option := m.layout(optionTimestamp, length, pointer)
		option[3] = byte(hegel.Draw(m.ht, pbt.Spanning(0, 15)))<<4 | flags
		return option
	}
	drawn := drawnOption{name: "timestamp that " + way, kind: optionTimestamp, fault: -1}
	switch way {
	case "stamps":
		length := hegel.Draw(m.ht, pbt.Spanning(8, 24))
		pointer := hegel.Draw(m.ht, pbt.Spanning(5, length-3))
		drawn.bytes = stamped(timestampsOnly, length, pointer)
		drawn.after = bytes.Clone(drawn.bytes)
		copy(drawn.after[pointer-1:], m.stamp())
		drawn.after[2] += timestampLen
	case "stamps with the address", "stamps as this node", "is named for another node":
		length := hegel.Draw(m.ht, pbt.Spanning(12, 24))
		pointer := hegel.Draw(m.ht, pbt.Spanning(5, length-7))
		flags, from := byte(timestampsAtNamed), m.address.As4()
		if way == "stamps with the address" {
			flags = timestampAndSource
		}
		drawn.bytes = stamped(flags, length, pointer)
		if way == "is named for another node" {
			copy(drawn.bytes[pointer-1:], []byte{198, 51, 100, 9})
			break
		}
		if flags == timestampsAtNamed {
			copy(drawn.bytes[pointer-1:], from[:])
		}
		drawn.after = bytes.Clone(drawn.bytes)
		copy(drawn.after[pointer-1:], from[:])
		copy(drawn.after[pointer+3:], m.stamp())
		drawn.after[2] += addressLen + timestampLen
	case "carries a flag RFC 791 does not define":
		length := hegel.Draw(m.ht, pbt.Spanning(8, 24))
		drawn.bytes = stamped(hegel.Draw(m.ht, hegel.SampledFrom(other)), length, hegel.Draw(m.ht, pbt.Spanning(5, length-3)))
	case "full", "full with its overflow at 15":
		length := hegel.Draw(m.ht, pbt.Spanning(4, 24))
		drawn.bytes = m.layout(optionTimestamp, length, hegel.Draw(m.ht, pbt.Spanning(length+1, 255)))
		overflow := byte(15)
		if way == "full" {
			overflow = byte(hegel.Draw(m.ht, pbt.Spanning(0, 14)))
		}
		flags := hegel.Draw(m.ht, hegel.SampledFrom(notNamed))
		drawn.bytes[3] = overflow<<4 | flags
		if way == "full" {
			drawn.after = bytes.Clone(drawn.bytes)
			drawn.after[3] = (overflow+1)<<4 | flags
		} else {
			drawn.fault = 3
		}
	case "full and prespecified", "full and prespecified with its overflow at 15":
		length := hegel.Draw(m.ht, pbt.Spanning(4, 24))
		drawn.bytes = stamped(timestampsAtNamed, length, hegel.Draw(m.ht, pbt.Spanning(length+1, 255)))
		if way != "full and prespecified" {
			drawn.bytes[3] = 15<<4 | timestampsAtNamed
		}
	case "a length under 4":
		length := hegel.Draw(m.ht, pbt.Spanning(2, 3))
		drawn.bytes, drawn.fault = append([]byte{optionTimestamp, byte(length)}, m.body(length-2)...), 1
	case "a pointer under 5":
		drawn.bytes, drawn.fault = stamped(hegel.Draw(m.ht, hegel.SampledFrom(append(notNamed, timestampsAtNamed))),
			hegel.Draw(m.ht, pbt.Spanning(4, 24)), hegel.Draw(m.ht, pbt.Spanning(0, 4))), 2
	case "room for less than a timestamp":
		length := hegel.Draw(m.ht, pbt.Spanning(5, 24))
		drawn.bytes, drawn.fault = stamped(hegel.Draw(m.ht, hegel.SampledFrom(append(notNamed, timestampsAtNamed))),
			length, hegel.Draw(m.ht, pbt.Spanning(max(5, length-2), length))), 2
	default:
		length := hegel.Draw(m.ht, pbt.Spanning(8, 24))
		drawn.bytes, drawn.fault = stamped(hegel.Draw(m.ht, hegel.SampledFrom([]byte{timestampAndSource, timestampsAtNamed})),
			length, hegel.Draw(m.ht, pbt.Spanning(max(5, length-6), length-3))), 2
	}
	return drawn
}

// sourceRoute is a loose or strict source route drawn as way names, of any length from 3 and any pointer from 4, which a router forwarding the header reports
// Linux refuses a length under 3 at the length and a pointer under 4 at the pointer, before it refuses a second source route at its type octet
func (m optionModel) sourceRoute(kind byte, way string) drawnOption {
	switch way {
	case "routes":
		return drawnOption{name: "source route", kind: kind,
			bytes: m.layout(kind, hegel.Draw(m.ht, pbt.Spanning(3, 23)), hegel.Draw(m.ht, pbt.Spanning(4, 255))), fault: -1}
	case "a length of 2":
		return drawnOption{name: "source route with " + way, kind: kind, bytes: []byte{kind, 2}, fault: 1}
	default:
		return drawnOption{name: "source route with " + way, kind: kind,
			bytes: m.layout(kind, hegel.Draw(m.ht, pbt.Spanning(3, 15)), hegel.Draw(m.ht, pbt.Spanning(0, 3))), fault: 2}
	}
}

// entry is one entry of the list drawn as way names, an option a router acts on drawn any of its own ways
func (m optionModel) entry(way string) drawnOption {
	switch way {
	case "nop":
		return drawnOption{name: way, kind: optionNOP, bytes: []byte{optionNOP}}
	case "end":
		// what follows the end of the list is padding, which the walk leaves as it is whatever it holds, where Linux writes END over it
		after := [][]byte{nil, m.body(hegel.Draw(m.ht, pbt.Spanning(1, 7))), {optionLooseSource, 7, 4, 10, 0, 0, 1}, {optionRecordRoute, 7, 4, 0, 0, 0, 0}}
		return drawnOption{name: way, kind: optionEnd, bytes: append([]byte{optionEnd}, after[hegel.Draw(m.ht, hegel.Integers(0, len(after)-1))]...)}
	case "another option":
		kind := hegel.Draw(m.ht, hegel.SampledFrom(passedKinds))
		length := hegel.Draw(m.ht, pbt.Spanning(2, 12))
		return drawnOption{name: way, kind: kind, bytes: append([]byte{kind, byte(length)}, m.body(length-2)...), fault: -1}
	case "source route":
		return m.sourceRoute(m.sourceRouteKind(), m.way(sourceRouteWays...))
	case "record route":
		return m.recordRoute(m.way(recordRouteWays...))
	case "timestamp":
		return m.timestamp(m.way(timestampWays...))
	}
	kind := hegel.Draw(m.ht, hegel.SampledFrom(append(slices.Clone(routeKinds), passedKinds...)))
	switch way {
	case "a length under 2":
		return drawnOption{name: way, kind: kind, bytes: []byte{kind, byte(hegel.Draw(m.ht, pbt.Spanning(0, 1)))}, framing: true}
	case "a length past the list":
		return drawnOption{name: way, kind: kind, bytes: append([]byte{kind, 0}, m.body(hegel.Draw(m.ht, pbt.Spanning(0, 6)))...), framing: true, pastList: true}
	default:
		return drawnOption{name: way, kind: kind, bytes: []byte{kind}, framing: true, last: true}
	}
}

// sweep is an entry drawn each way the model names, and a second option of each kind behind a first that reads
func (m optionModel) sweep() [][]drawnOption {
	var entries [][]drawnOption
	for _, way := range entryWays {
		switch way {
		case "source route":
			for _, way := range sourceRouteWays {
				entries = append(entries, []drawnOption{m.sourceRoute(m.sourceRouteKind(), way)})
			}
		case "record route":
			for _, way := range recordRouteWays {
				entries = append(entries, []drawnOption{m.recordRoute(way)})
			}
		case "timestamp":
			for _, way := range timestampWays {
				entries = append(entries, []drawnOption{m.timestamp(way)})
			}
		default:
			entries = append(entries, []drawnOption{m.entry(way)})
		}
	}
	return append(entries,
		[]drawnOption{m.sourceRoute(m.sourceRouteKind(), "routes"), m.sourceRoute(m.sourceRouteKind(), "routes")},
		[]drawnOption{m.recordRoute(m.way("records", "full")), m.recordRoute(m.way(recordRouteWays...))},
		[]drawnOption{m.timestamp(m.way(timestampValid...)), m.timestamp(m.way(timestampWays...))})
}

// list lays entries out as an option list, as many as the 40 bytes of a header's options hold, up to END
// a type octet drawn last goes in the list's last byte behind the NOPs that put it there, and the list stops with it
// a list short of a word ends with END and padding, and an option whose length runs past the list has it set once the list is laid out
func (m optionModel) list(entries []drawnOption) ([]drawnOption, []byte) {
	var options []drawnOption
	var list []byte
	for _, o := range entries {
		if o.last {
			pad := (3 - len(list)%4) % 4
			if len(list)+pad+1 > maxIPv4HeaderLen-ipv4HeaderLen {
				break
			}
			for range pad {
				options = append(options, drawnOption{name: "nop", kind: optionNOP, bytes: []byte{optionNOP}, offset: len(list)})
				list = append(list, optionNOP)
			}
		}
		if len(list)+len(o.bytes) > maxIPv4HeaderLen-ipv4HeaderLen {
			break
		}
		o.offset = len(list)
		options = append(options, o)
		list = append(list, o.bytes...)
		if o.last || o.kind == optionEnd {
			break
		}
	}
	if len(list)%4 != 0 {
		list = append(list, optionEnd)
		list = append(list, m.body((4-len(list)%4)%4)...)
	}
	for _, o := range options {
		if o.pastList {
			left := len(list) - o.offset
			list[o.offset+1] = byte(left + hegel.Draw(m.ht, pbt.Spanning(1, 255-left)))
		}
	}
	return options, list
}

// expected is the verdict, the octet at fault and each option recorded, by its offset in the list,
// of a router forwarding a header whose option list is options as drawn
// by RFC 791's layouts and the order Linux's ip_options_compile checks them in, where a refusal and a source route record nothing
// it reads no byte of the list, only what each entry was drawn as
func expected(options []drawnOption) (verdict Options, pointer int, recorded map[int][]byte) {
	recorded = make(map[int][]byte)
	seen := make(map[byte]bool)
	routed := false
	for _, o := range options {
		switch {
		case o.kind == optionEnd:
			return forwardedUnless(routed, recorded)
		case o.kind == optionNOP:
			continue
		case o.framing:
			return OptionsMalformed, ipv4HeaderLen + o.offset, nil
		case o.kind == optionLooseSource || o.kind == optionStrictSource:
			// Linux checks a source route's own layout before it looks for a second one
			if o.fault >= 0 {
				return OptionsMalformed, ipv4HeaderLen + o.offset + o.fault, nil
			}
			if routed {
				return OptionsMalformed, ipv4HeaderLen + o.offset, nil
			}
			routed = true
		case o.kind == optionRecordRoute || o.kind == optionTimestamp:
			// and a second record route or timestamp before its layout
			if seen[o.kind] {
				return OptionsMalformed, ipv4HeaderLen + o.offset, nil
			}
			if o.fault >= 0 {
				return OptionsMalformed, ipv4HeaderLen + o.offset + o.fault, nil
			}
			seen[o.kind] = true
			if o.after != nil {
				recorded[o.offset] = o.after
			}
		}
	}
	return forwardedUnless(routed, recorded)
}

// forwardedUnless is the verdict on a list that reads to its end: a source route reported with nothing recorded, else what was recorded
func forwardedUnless(routed bool, recorded map[int][]byte) (Options, int, map[int][]byte) {
	if routed {
		return OptionsSourceRouted, 0, nil
	}
	return OptionsForwarded, 0, recorded
}

// for any option list drawn as entries each valid or broken in one named way, with any data after the header or none
// into which each way the model names is drawn in turn at any point, and a second option of each kind behind a first that reads
// ForwardOptions reaches the verdict and names the octet the model above reaches and names
// a refused or source-routed header leaves as it came, and a forwarded one holds what the model recorded under a checksum that checks
// the edges the walk turns on are drawn outright: a pointer at, under and one slot short of the end, an overflow of 14 and 15
// and a type octet in the header's last byte with and without data after it
func TestForwardOptionsReadsTheListAsRFC791LaysItOut(t *testing.T) {
	address := netip.AddrFrom4([4]byte{192, 0, 2, 1})
	midnight := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	pbt.Check(t, func(ht *hegel.T) {
		m := optionModel{ht: ht, address: address, ms: uint32(hegel.Draw(ht, pbt.Spanning(0, 86400*1000-1)))}
		around := make([]drawnOption, hegel.Draw(ht, pbt.Spanning(0, 4)))
		for i := range around {
			around[i] = m.entry(m.way(entryWays...))
		}
		at := hegel.Draw(ht, pbt.Spanning(0, len(around)))
		for _, entries := range m.sweep() {
			options, list := m.list(slices.Concat(around[:at], entries, around[at:]))
			raw := ipv4Packet(list, 0, 3, hegel.Draw(ht, pbt.Spanning(0, 16)))
			if !HeaderValid(raw) {
				ht.Fatal("the packet drawn is not a valid header")
			}
			names := make([]string, len(options))
			for i, o := range options {
				names[i] = o.name
			}
			verdict, pointer, recorded := expected(options)
			want := bytes.Clone(raw)
			if verdict == OptionsForwarded && len(list) > 0 {
				for offset, after := range recorded {
					copy(want[ipv4HeaderLen+offset:], after)
				}
				binary.BigEndian.PutUint16(want[10:], 0)
				binary.BigEndian.PutUint16(want[10:], ^headerSum(want[:ipv4HeaderLen+len(list)]))
			}
			gotVerdict, gotPointer := ForwardOptions(raw, address, func(a netip.Addr) bool { return a == address }, midnight.Add(time.Duration(m.ms)*time.Millisecond))
			if gotVerdict != verdict || gotPointer != pointer {
				ht.Fatalf("the list %v, % x, is %d at octet %d, want %d at octet %d", names, list, gotVerdict, gotPointer, verdict, pointer)
			}
			if !bytes.Equal(raw, want) {
				ht.Fatalf("the list %v, % x, reads % x after, want % x", names, list, raw[ipv4HeaderLen:ipv4HeaderLen+len(list)], want[ipv4HeaderLen:ipv4HeaderLen+len(list)])
			}
		}
	})
}
