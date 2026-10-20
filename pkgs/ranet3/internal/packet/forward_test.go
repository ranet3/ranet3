// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package packet

import (
	"encoding/binary"
	"testing"
)

// fiveTests is RFC 1812 section 5.2.2's tests in the order the section lists them, with the truncation check it asks for after
// the checksum holds where the 16 bit words of the header add up to a multiple of 0xffff, which RFC 1071's sum folds to 0xffff
func fiveTests(b []byte) bool {
	if len(b) < 20 {
		return false
	}
	headerLen := int(b[0]&0x0f) * 4
	if headerLen > len(b) {
		return false
	}
	words := 0
	for i := 0; i+1 < headerLen; i += 2 {
		words += int(b[i])<<8 | int(b[i+1])
	}
	total := int(b[2])<<8 | int(b[3])
	return words%0xffff == 0 && b[0]>>4 == 4 && headerLen >= 20 && total >= headerLen && total <= len(b)
}

// validHeader is a 24 byte IPv4 header with one option word, and data bytes after it
func validHeader(data int) []byte {
	return ipv4Packet([]byte{optionNOP, optionNOP, optionNOP, optionEnd}, dontFragment, 7, data)
}

// resum writes the checksum a sender writes over the header raw's own length names
func resum(raw []byte) []byte {
	headerLen := min(int(raw[0]&0x0f)*4, len(raw))
	binary.BigEndian.PutUint16(raw[10:], 0)
	binary.BigEndian.PutUint16(raw[10:], ^headerSum(raw[:headerLen]))
	return raw
}

// the seeds sit on either side of each test's edge: 19 and 20 bytes from the link, a checksum one off and in its other form,
// the versions either side of 4, a header length of 4 and 5 words and past the link, and a total length either side of the header and of the link
func FuzzHeaderValid(f *testing.F) {
	at := func(data int, edit func([]byte)) []byte {
		raw := validHeader(data)
		edit(raw)
		return raw
	}
	f.Add(validHeader(0))
	f.Add(validHeader(40))
	f.Add(ipv4Packet(nil, 0, 0, 0))
	f.Add(ipv4Packet(nil, 0, 0, 0)[:19])
	f.Add(at(8, func(raw []byte) { raw[11]++ }))
	f.Add(at(8, func(raw []byte) {
		// an identification that makes the checksum zero, written in its other form 0xffff, which a receiver's sum folds to 0xffff all the same
		binary.BigEndian.PutUint16(raw[4:], 0)
		binary.BigEndian.PutUint16(raw[10:], 0)
		binary.BigEndian.PutUint16(raw[4:], ^headerSum(raw[:24]))
		binary.BigEndian.PutUint16(raw[10:], 0xffff)
	}))
	for _, version := range []byte{3, 5, 6} {
		f.Add(at(8, func(raw []byte) { raw[0] = version<<4 | raw[0]&0x0f; resum(raw) }))
	}
	for _, words := range []byte{4, 5, 15} {
		f.Add(at(8, func(raw []byte) { raw[0] = 0x40 | words; resum(raw) }))
	}
	for _, total := range []int{23, 24, 31, 32, 33} {
		f.Add(at(8, func(raw []byte) { binary.BigEndian.PutUint16(raw[2:], uint16(total)); resum(raw) }))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if got, want := HeaderValid(b), fiveTests(b); got != want {
			t.Fatalf("HeaderValid(% x) is %t, RFC 1812's tests say %t", b, got, want)
		}
	})
}
