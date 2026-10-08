// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package packet

import (
	"bytes"
	"encoding/binary"
	"net/netip"
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

// for any IPv4 packet and any source and mtu, an answer comes exactly when RFC 1122 section 3.2.2 lets an error answer the packet
// from a source that names one host
// it is one destination unreachable, fragmentation needed, from that source to the packet's, sent with DF at precedence 6
// carrying the mtu as its next-hop MTU and the packet's header and 8 bytes of its data, both its sums checking as a receiver checks them
func TestFragmentationNeededAnswersOnlyWhatAnErrorMayAnswer(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		// half the cases break one rule at most, which puts each rule against packets every other rule lets through
		alone := hegel.Draw(ht, hegel.Booleans())
		broken := hegel.Draw(ht, hegel.Integers(0, 5))
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
		data := hegel.Draw(ht, pbt.Spanning(0, 64))
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
		binary.BigEndian.PutUint16(raw[10:], 0)
		binary.BigEndian.PutUint16(raw[10:], ^headerSum(raw[:headerLen]))
		mtu := hegel.Draw(ht, pbt.Spanning(68, maxDatagram))

		answer, ok := FragmentationNeeded(raw, source, mtu)
		want := fromOneHost && senderIsOneHost && !toAGroup && !laterFragment && !carriesError
		if ok != want {
			ht.Fatalf("a packet from %s to %s, flags %#04x, protocol %d, answered from %s was answered %t, want %t",
				sender, receiver, field, raw[9], source, ok, want)
		}
		if !ok {
			return
		}
		quoted := headerLen + min(data, quotedData)
		if len(answer) != ipv4HeaderLen+icmpHeaderLen+quoted {
			ht.Fatalf("the answer is %d bytes, want a header, an ICMP header and %d quoted", len(answer), quoted)
		}
		header := answer[:ipv4HeaderLen]
		if header[0] != 0x45 || header[1] != 0xc0 || int(binary.BigEndian.Uint16(header[2:])) != len(answer) ||
			binary.BigEndian.Uint16(header[4:]) != 0 || binary.BigEndian.Uint16(header[6:]) != 0x4000 || header[8] != 64 || header[9] != 1 {
			ht.Fatalf("the answer's header is %x", header)
		}
		if headerSum(header) != 0xffff {
			ht.Fatalf("the answer's header sums to %#04x", headerSum(header))
		}
		if from, to := netip.AddrFrom4([4]byte(header[12:16])), netip.AddrFrom4([4]byte(header[16:20])); from != source || to != sender {
			ht.Fatalf("the answer goes from %s to %s, want %s to %s", from, to, source, sender)
		}
		message := answer[ipv4HeaderLen:]
		if message[0] != 3 || message[1] != 4 || binary.BigEndian.Uint16(message[4:]) != 0 || int(binary.BigEndian.Uint16(message[6:])) != mtu {
			ht.Fatalf("the message is type %d code %d with %x where the next-hop MTU %d goes", message[0], message[1], message[4:8], mtu)
		}
		if headerSum(message) != 0xffff {
			ht.Fatalf("the message sums to %#04x", headerSum(message))
		}
		if !bytes.Equal(message[icmpHeaderLen:], raw[:quoted]) {
			ht.Fatal("the message does not quote the packet's header and the 8 bytes after it")
		}
	})
}
