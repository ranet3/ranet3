// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package packet

import (
	"bytes"
	"encoding/binary"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// headerSum is the one's complement sum of b as a receiver adds it up, in 64 bits and folded once at the end
// it stands apart from Sum, which builds what it checks
func headerSum(b []byte) uint16 {
	var sum uint64
	for i := 0; i < len(b); i += 2 {
		word := uint64(b[i]) << 8
		if i+1 < len(b) {
			word |= uint64(b[i+1])
		}
		sum += word
	}
	for sum > 0xffff {
		sum = sum>>16 + sum&0xffff
	}
	return uint16(sum)
}

// ipv4Packet is an IPv4 packet with a valid header checksum
// options is its option list as written, padded by the caller to whole words, and field its flags and fragment offset
// the data counts up in 16 bit words from seed, and a byte out of place reads as another word
func ipv4Packet(options []byte, field uint16, seed uint16, data int) []byte {
	headerLen := ipv4HeaderLen + len(options)
	raw := make([]byte, headerLen+data)
	raw[0] = 4<<4 | byte(headerLen/4)
	raw[1] = 0x28
	binary.BigEndian.PutUint16(raw[2:], uint16(len(raw)))
	binary.BigEndian.PutUint16(raw[4:], 0x5aa5)
	binary.BigEndian.PutUint16(raw[6:], field)
	raw[8], raw[9] = 61, 17
	copy(raw[12:], []byte{192, 0, 2, 7, 198, 51, 100, 9})
	copy(raw[ipv4HeaderLen:], options)
	for i := headerLen; i < len(raw); i++ {
		word := uint16((i-headerLen)/2) + seed
		raw[i] = byte(word >> (8 * (1 - (i-headerLen)%2)))
	}
	binary.BigEndian.PutUint16(raw[10:], ^headerSum(raw[:headerLen]))
	return raw
}

// reassemble puts the fragments of original back together as RFC 791 section 3.2 reassembles a datagram, checking each on the way
// every fragment is one whole IPv4 packet of at most mtu bytes whose header sums as a receiver checks it
// and whose fields but the length, the flags, the offset and the checksum are the original's
// the first carries the original's options and every later one later, the options a later fragment carries
// the offsets count 8 byte units from the original's and follow on with no gap or overlap
// only the last may leave more fragments as the original had it, and only a lone fragment may carry no data
// the result is the first fragment's header over all the data, with the last fragment's flags and the length recomputed
func reassemble(tb testing.TB, fragments [][]byte, original, later []byte, mtu int) []byte {
	tb.Helper()
	headerLen := int(original[0]&0x0f) * 4
	field := binary.BigEndian.Uint16(original[6:8])
	next := int(field&fragmentOffset) * fragmentUnit
	var data []byte
	for i, fragment := range fragments {
		if len(fragment) > mtu || len(fragment) < headerLen {
			tb.Fatalf("fragment %d of %d is %d bytes, against an mtu of %d and a %d byte header", i, len(fragments), len(fragment), mtu, headerLen)
		}
		if fragment[0] != original[0] || int(binary.BigEndian.Uint16(fragment[2:4])) != len(fragment) {
			tb.Fatalf("fragment %d starts %#02x with total length %d over %d bytes", i, fragment[0], binary.BigEndian.Uint16(fragment[2:4]), len(fragment))
		}
		if headerSum(fragment[:headerLen]) != 0xffff {
			tb.Fatalf("fragment %d has a header that sums to %#04x", i, headerSum(fragment[:headerLen]))
		}
		for _, span := range [][2]int{{1, 2}, {4, 6}, {8, 10}, {12, 20}} {
			if !bytes.Equal(fragment[span[0]:span[1]], original[span[0]:span[1]]) {
				tb.Fatalf("fragment %d carries %x at %d where the packet carries %x", i, fragment[span[0]:span[1]], span[0], original[span[0]:span[1]])
			}
		}
		options := later
		if i == 0 {
			options = original[ipv4HeaderLen:headerLen]
		}
		if !bytes.Equal(fragment[ipv4HeaderLen:headerLen], options) {
			tb.Fatalf("fragment %d carries the options %x, want %x", i, fragment[ipv4HeaderLen:headerLen], options)
		}
		flags := binary.BigEndian.Uint16(fragment[6:8])
		if at := int(flags&fragmentOffset) * fragmentUnit; at != next {
			tb.Fatalf("fragment %d starts at byte %d of the datagram, want %d", i, at, next)
		}
		last := i == len(fragments)-1
		want := field&^fragmentOffset | moreFragments
		if last {
			want = field &^ fragmentOffset
		}
		if got := flags &^ fragmentOffset; got != want {
			tb.Fatalf("fragment %d of %d has the flags %#04x, want %#04x", i, len(fragments), got, want)
		}
		carried := fragment[headerLen:]
		if !last && (len(carried) == 0 || len(carried)%fragmentUnit != 0) {
			tb.Fatalf("fragment %d of %d carries %d bytes of data, which is no whole number of 8 byte units", i, len(fragments), len(carried))
		}
		data = append(data, carried...)
		next += len(carried)
	}
	whole := append(bytes.Clone(fragments[0][:headerLen]), data...)
	binary.BigEndian.PutUint16(whole[2:], uint16(len(whole)))
	copy(whole[6:8], fragments[len(fragments)-1][6:8])
	binary.BigEndian.PutUint16(whole[6:], binary.BigEndian.Uint16(whole[6:])&^fragmentOffset|field&fragmentOffset)
	binary.BigEndian.PutUint16(whole[10:], 0)
	binary.BigEndian.PutUint16(whole[10:], ^headerSum(whole[:headerLen]))
	return whole
}

// fragmentsOf splits what AppendFragments wrote after start into its fragments, by the total length each one carries
func fragmentsOf(tb testing.TB, out []byte, start int) [][]byte {
	tb.Helper()
	var fragments [][]byte
	for rest := out[start:]; len(rest) != 0; {
		if len(rest) < ipv4HeaderLen {
			tb.Fatalf("%d bytes trail the last fragment", len(rest))
		}
		length := int(binary.BigEndian.Uint16(rest[2:4]))
		if length < ipv4HeaderLen || length > len(rest) {
			tb.Fatalf("a fragment claims %d bytes with %d left", length, len(rest))
		}
		fragments = append(fragments, rest[:length])
		rest = rest[length:]
	}
	return fragments
}

// optionList is an IPv4 option list as drawn, and what a fragment after the first carries of it
type optionList struct{ written, later []byte }

// add puts one option on the list, which every fragment carries when copied is set and only the first one otherwise
func (o *optionList) add(kind byte, body []byte, copied bool) {
	option := append([]byte{kind, byte(2 + len(body))}, body...)
	o.written = append(o.written, option...)
	if copied {
		o.later = append(o.later, option...)
	} else {
		o.later = append(o.later, bytes.Repeat([]byte{optionNOP}, len(option))...)
	}
}

// pad ends the list and fills it to whole words, which both the first and the later fragments carry as they are
func (o *optionList) pad() {
	if len(o.written)%4 != 0 {
		o.written = append(o.written, optionEnd)
		o.later = append(o.later, optionEnd)
	}
	for len(o.written)%4 != 0 {
		o.written = append(o.written, 0)
		o.later = append(o.later, 0)
	}
}

// for any IPv4 packet without DF, fragment or not, with any option list and any mtu from 68 up
// the fragments each fit the mtu, carry offsets in 8 byte units with the copied options in every one, check their header sums
// and reassemble to the packet
// exact multiples of the data a fragment carries, and one byte either side, are tried before anything is drawn
func TestFragmentsReassembleToThePacket(t *testing.T) {
	check := func(tb testing.TB, options optionList, field, seed uint16, data, mtu int) {
		tb.Helper()
		original := ipv4Packet(options.written, field, seed, data)
		prefix := []byte("kept")
		out, ok := AppendFragments(prefix, original, mtu)
		if !ok {
			tb.Fatalf("a %d byte packet with the flags %#04x was refused at an mtu of %d", len(original), field, mtu)
		}
		if !bytes.Equal(out[:len(prefix)], []byte("kept")) {
			tb.Fatal("the fragments were not appended after what dst held")
		}
		fragments := fragmentsOf(tb, out, len(prefix))
		if got := reassemble(tb, fragments, original, options.later, mtu); !bytes.Equal(got, original) {
			tb.Fatalf("%d fragments reassemble to %d bytes that differ from the %d byte packet", len(fragments), len(got), len(original))
		}
	}
	var mixed optionList
	mixed.add(0x83, []byte{4, 192, 0, 2, 1}, true)
	mixed.add(7, []byte{4, 0, 0, 0, 0}, false)
	mixed.pad()
	for _, options := range []optionList{{}, mixed} {
		for mtu := 68; mtu < 68+fragmentUnit; mtu++ {
			chunk := (mtu - ipv4HeaderLen - len(options.written)) &^ (fragmentUnit - 1)
			for _, data := range []int{0, 1, chunk - 1, chunk, chunk + 1, 3*chunk - 1, 3 * chunk, 3*chunk + 1} {
				check(t, options, 0, 0, data, mtu)
				check(t, options, moreFragments|5, 0x1234, data, mtu)
			}
		}
	}
	pbt.Check(t, func(ht *hegel.T) {
		var options optionList
		room := hegel.Draw(ht, pbt.Spanning(0, maxIPv4HeaderLen-ipv4HeaderLen))
		for len(options.written) < room {
			left := room - len(options.written)
			if left < 2 || hegel.Draw(ht, hegel.Integers(0, 2)) == 0 {
				options.written = append(options.written, optionNOP)
				options.later = append(options.later, optionNOP)
				continue
			}
			copied := hegel.Draw(ht, hegel.Booleans())
			kind := byte(hegel.Draw(ht, hegel.Integers(2, 0x7f)))
			if copied {
				kind |= copiedOption
			}
			options.add(kind, hegel.Draw(ht, hegel.Binary(0, left-2)), copied)
		}
		options.pad()
		headerLen := ipv4HeaderLen + len(options.written)
		data := hegel.Draw(ht, pbt.Spanning(0, maxDatagram-headerLen))
		offset := hegel.Draw(ht, pbt.Spanning(0, (maxDatagram-data)/fragmentUnit))
		field := uint16(offset)
		if hegel.Draw(ht, hegel.Booleans()) {
			field |= moreFragments
		}
		if hegel.Draw(ht, hegel.Booleans()) {
			field |= reservedFlag
		}
		seed := hegel.Draw(ht, hegel.Integers[uint16](0, 0xffff))
		mtu := hegel.Draw(ht, pbt.Spanning(68, max(68, headerLen+data+fragmentUnit)))
		check(ht, options, field, seed, data, mtu)
	})
}

// what RFC 791 section 3.2 cannot cut, or a reassembly could not put back, is refused and dst comes back as it was
func TestFragmentsAreRefusedForWhatCannotBeCut(t *testing.T) {
	for _, refused := range []struct {
		name string
		raw  []byte
		mtu  int
	}{
		{"DF", ipv4Packet(nil, dontFragment, 0, 2000), 1280},
		{"an option whose length runs past the header", ipv4Packet([]byte{7, 9, 4, 0}, 0, 0, 2000), 1280},
		{"an option of length one", ipv4Packet([]byte{0x83, 1, 0, 0}, 0, 0, 2000), 1280},
		{"an option with no length", ipv4Packet([]byte{optionNOP, optionNOP, optionNOP, 0x83}, 0, 0, 2000), 1280},
		{"data past the largest datagram", ipv4Packet(nil, fragmentOffset, 0, 2000), 1280},
		{"no room for 8 bytes past the longest header", ipv4Packet(bytes.Repeat([]byte{optionNOP}, 40), 0, 0, 2000), 67},
		{"anything but IPv4", append([]byte{0x60}, make([]byte, 1999)...), 1280},
		{"a packet longer than its total length", append(ipv4Packet(nil, 0, 0, 2000), 0), 1280},
	} {
		t.Run(refused.name, func(t *testing.T) {
			out, ok := AppendFragments([]byte("kept"), refused.raw, refused.mtu)
			if ok || string(out) != "kept" {
				t.Errorf("AppendFragments took it, reporting %t with %d bytes after dst", ok, len(out)-len("kept"))
			}
		})
	}
}

// RFC 1071 section 3 sums the example bytes 00 01 f2 03 f4 f5 f6 f7 to ddf2, and an odd length counts a zero byte after the last
func TestSumIsTheOnesComplementSum(t *testing.T) {
	example := []byte{0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7}
	if got := Sum(0, example); got != 0xddf2 {
		t.Errorf("the example sums to %#04x, want 0xddf2", got)
	}
	if got := Sum(Sum(0, example[:4]), example[4:]); got != 0xddf2 {
		t.Errorf("the example summed in two parts gives %#04x, want 0xddf2", got)
	}
	if got, want := Sum(0, example[:7]), Sum(0, append(bytes.Clone(example[:7]), 0)); got != want {
		t.Errorf("seven bytes sum to %#04x and the same with a zero after them to %#04x", got, want)
	}
}
