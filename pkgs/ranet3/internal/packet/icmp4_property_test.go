// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package packet

import (
	"bytes"
	"encoding/binary"
	"math/bits"
	"net/netip"
	"slices"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// addressKinds are the IPv4 addresses RFC 1122 section 3.2.2 tells apart
// one host, this network, loopback, a multicast group, class E and the limited broadcast
var addressKinds = []func(rest [3]byte) netip.Addr{
	func(rest [3]byte) netip.Addr { return netip.AddrFrom4([4]byte{198, rest[0], rest[1], rest[2]}) },
	func(rest [3]byte) netip.Addr { return netip.AddrFrom4([4]byte{0, rest[0], rest[1], rest[2]}) },
	func(rest [3]byte) netip.Addr { return netip.AddrFrom4([4]byte{127, rest[0], rest[1], rest[2]}) },
	func(rest [3]byte) netip.Addr { return netip.AddrFrom4([4]byte{239, rest[0], rest[1], rest[2]}) },
	func(rest [3]byte) netip.Addr { return netip.AddrFrom4([4]byte{240, rest[0], rest[1], rest[2]}) },
	func([3]byte) netip.Addr { return netip.AddrFrom4([4]byte{255, 255, 255, 255}) },
}

// errorTypes are the ICMP messages RFC 792 makes errors
var errorTypes = []byte{3, 4, 5, 11, 12}

// errorBuilder is one of the errors this package answers with, the type, code and second header word it writes
// and value, the number the error carries in that word, which only some of them use
type errorBuilder struct {
	name       string
	kind, code byte
	build      func(offending []byte, source netip.Addr, value int, allow func() bool) []byte
	rest       func(value int) uint32
}

func noValue(int) uint32 { return 0 }

// errorBuilders are every IPv4 error this package builds
var errorBuilders = []errorBuilder{
	{"time exceeded", 11, 0, func(raw []byte, source netip.Addr, _ int, allow func() bool) []byte {
		return TimeExceeded(raw, source, allow)
	}, noValue},
	{"net unreachable", 3, 0, func(raw []byte, source netip.Addr, _ int, allow func() bool) []byte {
		return NetUnreachable(raw, source, allow)
	}, noValue},
	{"host unreachable", 3, 1, func(raw []byte, source netip.Addr, _ int, allow func() bool) []byte {
		return HostUnreachable(raw, source, allow)
	}, noValue},
	{"communication administratively prohibited", 3, 13, func(raw []byte, source netip.Addr, _ int, allow func() bool) []byte {
		return Prohibited(raw, source, allow)
	}, noValue},
	{"fragmentation needed", 3, 4, FragmentationNeeded, func(mtu int) uint32 { return uint32(mtu) }},
	{"parameter problem", 12, 0, ParameterProblem, func(pointer int) uint32 { return uint32(pointer) << 24 }},
}

// for any IPv4 packet and any source, each error answers exactly when RFC 1812 section 4.3.2.7 lets an error answer the packet
// its header passes the five tests of section 5.2.2, nothing follows it, and the answer comes from a source that names one host
// and allow, asked once then and never otherwise, lets it out
// the answer is one ICMP message of the error's type and code from that source to the packet's, with DF and a TTL of 64
// at precedence 6 with the packet's TOS, section 4.3.2.5, carrying the error's value in the word after the checksum
// and quoting as much of the datagram as fits 576 bytes, section 4.3.2.3
// both its sums checking as a receiver checks them
// every ICMP type is tried first under each error in a packet every other rule lets an error answer, which meets each error type in every run
func TestErrorsAnswerOnlyWhatAnErrorMayAnswer(t *testing.T) {
	oneHost := netip.AddrFrom4([4]byte{198, 51, 100, 1})
	for _, builder := range errorBuilders {
		for kind := range 256 {
			raw := ipv4Packet(nil, dontFragment, 0, icmpHeaderLen)
			raw[9], raw[ipv4HeaderLen] = icmpProtocol, byte(kind)
			resum(raw)
			asked := false
			ok := builder.build(raw, oneHost, 1280, func() bool { asked = true; return true }) != nil
			if ok == (bytes.IndexByte(errorTypes, byte(kind)) >= 0) || asked != ok {
				t.Errorf("%s answered an ICMP message of type %d %t, allow asked %t", builder.name, kind, ok, asked)
			}
		}
	}
	pbt.Check(t, func(ht *hegel.T) {
		builder := errorBuilders[hegel.Draw(ht, hegel.Integers(0, len(errorBuilders)-1))]
		// half the cases break one rule at most, which puts each rule against packets every other rule lets through
		alone := hegel.Draw(ht, hegel.Booleans())
		broken := hegel.Draw(ht, hegel.Integers(0, 7))
		breaks := func(rule int) bool {
			if alone {
				return broken == rule
			}
			return hegel.Draw(ht, hegel.WeightedBooleans(1.0/4))
		}
		address := func(rule int) (netip.Addr, bool) {
			kind := 0
			if breaks(rule) {
				kind = hegel.Draw(ht, hegel.Integers(1, len(addressKinds)-1))
			}
			var rest [3]byte
			copy(rest[:], hegel.Draw(ht, hegel.Binary(3, 3)))
			return addressKinds[kind](rest), kind == 0
		}
		source, fromOneHost := address(1)
		sender, senderIsOneHost := address(2)
		receiver, _ := address(3)
		toAGroup := receiver.IsMulticast() || receiver == netip.AddrFrom4([4]byte{255, 255, 255, 255})
		laterFragment := breaks(4)
		options := bytes.Repeat([]byte{optionNOP}, 4*hegel.Draw(ht, pbt.Spanning(0, 10)))
		data := hegel.Draw(ht, pbt.Spanning(0, 1500))
		field := uint16(0)
		if hegel.Draw(ht, hegel.Booleans()) {
			field |= dontFragment
		}
		if hegel.Draw(ht, hegel.Booleans()) {
			field |= moreFragments
		}
		if laterFragment {
			field |= uint16(hegel.Draw(ht, pbt.Spanning(1, fragmentOffset)))
		}
		raw := ipv4Packet(options, field, 0, data)
		raw[1] = byte(hegel.Draw(ht, hegel.Integers(0, 0xff)))
		copy(raw[12:16], sender.AsSlice())
		copy(raw[16:20], receiver.AsSlice())
		headerLen := ipv4HeaderLen + len(options)
		carriesError := false
		switch {
		case breaks(5):
			raw[9] = icmpProtocol
			if data > 0 {
				raw[headerLen] = errorTypes[hegel.Draw(ht, hegel.Integers(0, len(errorTypes)-1))]
				carriesError = true
			}
		case hegel.Draw(ht, hegel.Booleans()):
			raw[9] = icmpProtocol
			if data > 0 {
				raw[headerLen] = byte(hegel.Draw(ht, hegel.Integers(0, 0xff)))
				carriesError = bytes.IndexByte(errorTypes, raw[headerLen]) >= 0
			}
		}
		resum(raw)
		// a header the five tests refuse, its checksum one off, and bytes after the datagram, which is then not one whole packet
		invalid := breaks(6)
		if invalid {
			raw[11]++
		}
		trailer := 0
		if breaks(7) {
			trailer = hegel.Draw(ht, pbt.Spanning(1, 64))
		}
		raw = append(raw, bytes.Repeat([]byte{0xee}, trailer)...)
		value := hegel.Draw(ht, pbt.Spanning(0, 0xffff))
		if builder.kind == icmpParameterProblem {
			value = hegel.Draw(ht, pbt.Spanning(0, headerLen-1))
		}
		allowed := hegel.Draw(ht, hegel.Booleans())

		asked := 0
		answer := builder.build(raw, source, value, func() bool { asked++; return allowed })
		ok := answer != nil
		eligible := fromOneHost && senderIsOneHost && !toAGroup && !laterFragment && !carriesError && !invalid && trailer == 0
		if want := eligible && allowed; ok != want || (asked == 1) != eligible || asked > 1 {
			ht.Fatalf("%s for a packet from %s to %s, flags %#04x, protocol %d, its header valid %t, %d bytes after it, answered from %s was sent %t asking allow %d times, want %t asking it %t",
				builder.name, sender, receiver, field, raw[9], !invalid, trailer, source, ok, asked, want, eligible)
		}
		if !eligible {
			return
		}
		// a refusal builds nothing, so every eligible case reads its form from the answer allow would have let out
		if !allowed {
			answer = builder.build(raw, source, value, func() bool { return true })
		}
		quoted := min(headerLen+data, 576-ipv4HeaderLen-icmpHeaderLen)
		if len(answer) != ipv4HeaderLen+icmpHeaderLen+quoted {
			ht.Fatalf("the answer is %d bytes, want a header, an ICMP header and %d quoted", len(answer), quoted)
		}
		header := answer[:ipv4HeaderLen]
		if header[0] != 0x45 || header[1] != 0xc0|raw[1]&0x1e || int(binary.BigEndian.Uint16(header[2:])) != len(answer) ||
			binary.BigEndian.Uint16(header[4:]) != 0 || binary.BigEndian.Uint16(header[6:]) != 0x4000 || header[8] != 64 || header[9] != 1 {
			ht.Fatalf("the answer to a packet with TOS %#02x has the header %x", raw[1], header)
		}
		if headerSum(header) != 0xffff {
			ht.Fatalf("the answer's header sums to %#04x", headerSum(header))
		}
		if from, to := netip.AddrFrom4([4]byte(header[12:16])), netip.AddrFrom4([4]byte(header[16:20])); from != source || to != sender {
			ht.Fatalf("the answer goes from %s to %s, want %s to %s", from, to, source, sender)
		}
		message := answer[ipv4HeaderLen:]
		if message[0] != builder.kind || message[1] != builder.code || binary.BigEndian.Uint32(message[4:]) != builder.rest(value) {
			ht.Fatalf("%s carrying %d is type %d code %d with %x after its checksum", builder.name, value, message[0], message[1], message[4:8])
		}
		if headerSum(message) != 0xffff {
			ht.Fatalf("the message sums to %#04x", headerSum(message))
		}
		if !bytes.Equal(message[icmpHeaderLen:], raw[:quoted]) {
			ht.Fatalf("the message does not quote the first %d bytes of the datagram", quoted)
		}
	})
}

// for any even run of bytes under a checksum at an even offset in it, a 16 bit field at any other offset, odd ones among them, and any new value of the field
// AdjustChecksum writes the checksum a full recompute writes over the bytes once the field holds its new value
// but over bytes that are all zero, which no IP header is, where RFC 1624 section 3's equation 3 writes +0 for the -0 of a recompute
// each case also sweeps the sum of the three 16 bit words equation 3 adds to 0x1ffff, the one sum two folds bring under 16 bits, 0x10000 and 0xffff
// through the value of a word the checksum covers
func TestAdjustChecksumAgreesWithAFullRecompute(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		words := hegel.Draw(ht, pbt.Spanning(5, 30))
		drawn := hegel.Draw(ht, hegel.Binary(2*words, 2*words))
		field := hegel.Draw(ht, pbt.Spanning(0, 2*words-2))
		odd := field%2 == 1
		// the checksum and the word the sweep sets lie in words the field's bytes do not
		var free []int
		for word := range words {
			if word != field/2 && word != (field+1)/2 {
				free = append(free, word)
			}
		}
		checksum := 2 * free[hegel.Draw(ht, hegel.Integers(0, len(free)-1))]
		free = slices.DeleteFunc(free, func(word int) bool { return 2*word == checksum })
		filler := 2 * free[hegel.Draw(ht, hegel.Integers(0, len(free)-1))]
		recompute := func(b []byte) uint16 {
			summed := bytes.Clone(b)
			binary.BigEndian.PutUint16(summed[checksum:], 0)
			return ^uint16(Sum(0, summed))
		}
		// moved writes from into the field of data under the checksum a recompute writes, moves the field to to
		// and returns the sum of the three words equation 3 adds, those of the field taken as the checksum adds them
		moved := func(data []byte, from, to uint16) uint32 {
			b := bytes.Clone(data)
			binary.BigEndian.PutUint16(b[field:], from)
			before := recompute(b)
			binary.BigEndian.PutUint16(b[checksum:], before)
			binary.BigEndian.PutUint16(b[field:], to)
			got, want := AdjustChecksum(before, from, to, odd), recompute(b)
			if got != want && (got != 0x0000 || want != 0xffff) {
				ht.Fatalf("a field at offset %d of %d bytes moved from %#04x to %#04x under the checksum %#04x at offset %d takes %#04x, a full recompute %#04x",
					field, len(b), from, to, before, checksum, got, want)
			}
			if odd {
				from, to = bits.ReverseBytes16(from), bits.ReverseBytes16(to)
			}
			return uint32(^before) + uint32(^from) + uint32(to)
		}
		moved(drawn, binary.BigEndian.Uint16(drawn[field:]), uint16(hegel.Draw(ht, hegel.Integers(0, 0xffff))))

		// two values of the field as the checksum adds it, moving up to reach 0x1ffff and down to reach 0x10000 and 0xffff
		x, y := uint16(hegel.Draw(ht, hegel.Integers(0, 0xffff))), uint16(hegel.Draw(ht, hegel.Integers(0, 0xffff)))
		lo, hi := min(x, y), max(x, y)
		switch {
		case lo == hi && hi < 0xffff:
			hi++
		case lo == hi:
			lo--
		}
		// a field moved from 0xffff to 0 adds two zero words, which leave the sum under 0x10000
		toward := lo
		if hi-lo == 0xffff {
			toward = 1
		}
		for _, sweep := range []struct {
			sum      uint32
			from, to uint16
		}{{0x1ffff, lo, hi}, {0x10000, hi, toward}, {0xffff, hi, lo}} {
			from, to := sweep.from, sweep.to
			if odd {
				from, to = bits.ReverseBytes16(from), bits.ReverseBytes16(to)
			}
			// the sum of every word the checksum covers that equation 3 then adds as the complement of the checksum
			covered := sweep.sum - uint32(^sweep.from) - uint32(sweep.to)
			b := bytes.Clone(drawn)
			binary.BigEndian.PutUint16(b[field:], from)
			binary.BigEndian.PutUint16(b[checksum:], 0)
			binary.BigEndian.PutUint16(b[filler:], 0)
			binary.BigEndian.PutUint16(b[filler:], uint16(Sum(covered+uint32(^uint16(Sum(0, b))), nil)))
			if sum := moved(b, from, to); sum != sweep.sum {
				ht.Fatalf("the sweep toward %#05x moved the field under three words that sum to %#05x", sweep.sum, sum)
			}
		}
	})
}
