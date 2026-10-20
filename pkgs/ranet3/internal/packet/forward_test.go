// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package packet

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
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

// the time every timestamp below is taken at, 01:02:03.456 UT, which is 3723456 milliseconds after midnight
var stampedAt = time.Date(2026, 10, 20, 1, 2, 3, 456_000_000, time.UTC)

// recorded is the address Record Route and Timestamp record below
var recorded = netip.AddrFrom4([4]byte{192, 0, 2, 1})

// forwarded runs ForwardOptions on a packet carrying options, padded to whole words with end of list, and returns the header after it
// ours names recorded alone as this node's own
func forwarded(t *testing.T, options []byte) ([]byte, Options, int) {
	t.Helper()
	for len(options)%4 != 0 {
		options = append(options, optionEnd)
	}
	raw := ipv4Packet(options, 0, 3, 8)
	before := bytes.Clone(raw)
	verdict, pointer := ForwardOptions(raw, recorded, func(a netip.Addr) bool { return a == recorded }, stampedAt)
	if verdict != OptionsForwarded && !bytes.Equal(raw, before) {
		t.Fatalf("a header refused as %d changed", verdict)
	}
	if headerSum(raw[:ipv4HeaderLen+len(options)]) != 0xffff {
		t.Fatal("the header's checksum no longer checks")
	}
	return raw, verdict, pointer
}

// Record Route, RFC 791: the address goes into the slot the pointer names and the pointer moves on by 4
// a full option, its pointer past its length, is forwarded as it was, and one with room for less than an address is refused at its pointer
func TestRecordRouteRecordsTheAddressInItsNextSlot(t *testing.T) {
	raw, verdict, _ := forwarded(t, []byte{optionRecordRoute, 11, 4, 0, 0, 0, 0, 0, 0, 0, 0})
	want := []byte{optionRecordRoute, 11, 8, 192, 0, 2, 1, 0, 0, 0, 0}
	if verdict != OptionsForwarded || !bytes.Equal(raw[20:31], want) {
		t.Fatalf("an empty record route reads % x after, %d, want % x", raw[20:31], verdict, want)
	}
	raw, verdict, _ = forwarded(t, []byte{optionRecordRoute, 11, 8, 10, 0, 0, 1, 0, 0, 0, 0})
	want = []byte{optionRecordRoute, 11, 12, 10, 0, 0, 1, 192, 0, 2, 1}
	if verdict != OptionsForwarded || !bytes.Equal(raw[20:31], want) {
		t.Fatalf("a record route with one slot left reads % x after, %d, want % x", raw[20:31], verdict, want)
	}
	full := []byte{optionRecordRoute, 7, 8, 10, 0, 0, 1}
	raw, verdict, _ = forwarded(t, full)
	if verdict != OptionsForwarded || !bytes.Equal(raw[20:27], full) {
		t.Fatalf("a full record route reads % x after, %d, want it as it was", raw[20:27], verdict)
	}
	for _, option := range [][]byte{
		{optionRecordRoute, 10, 8, 10, 0, 0, 1, 0, 0, 0},
		{optionRecordRoute, 7, 3, 0, 0, 0, 0},
		{optionRecordRoute, 7, 0, 0, 0, 0, 0},
	} {
		if _, verdict, pointer := forwarded(t, option); verdict != OptionsMalformed || pointer != 22 {
			t.Errorf("record route % x is %d at octet %d, want refused at its pointer, octet 22", option, verdict, pointer)
		}
	}
	if _, verdict, pointer := forwarded(t, []byte{optionRecordRoute, 2}); verdict != OptionsMalformed || pointer != 21 {
		t.Errorf("a record route of 2 bytes is %d at octet %d, want refused at its length, octet 21", verdict, pointer)
	}
}

// Timestamp, RFC 791: flag 0 records the time, flag 1 the address and the time, and flag 3 the time where the slot names this node
// a full option counts one more in its overflow, whatever follows it in the list, and a count of 15 is refused at the flags
// but a full option of flag 3 passes unchanged whatever its count, as Linux's ip_options_compile leaves it
func TestTimestampRecordsWhatItsFlagsAsk(t *testing.T) {
	stamp := binary.BigEndian.AppendUint32(nil, 3723456)
	for _, c := range []struct {
		name     string
		option   []byte
		want     []byte
		verdict  Options
		pointer  int
		changing bool
	}{
		{"timestamps only", []byte{optionTimestamp, 12, 5, 0x00, 0, 0, 0, 0, 0, 0, 0, 0},
			append(append([]byte{optionTimestamp, 12, 9, 0x00}, stamp...), 0, 0, 0, 0), OptionsForwarded, 0, true},
		{"address and timestamp", []byte{optionTimestamp, 12, 5, 0x01, 0, 0, 0, 0, 0, 0, 0, 0},
			append([]byte{optionTimestamp, 12, 13, 0x01, 192, 0, 2, 1}, stamp...), OptionsForwarded, 0, true},
		{"prespecified as this node", []byte{optionTimestamp, 12, 5, 0x03, 192, 0, 2, 1, 0, 0, 0, 0},
			append([]byte{optionTimestamp, 12, 13, 0x03, 192, 0, 2, 1}, stamp...), OptionsForwarded, 0, true},
		{"prespecified as another node", []byte{optionTimestamp, 12, 5, 0x03, 192, 0, 2, 9, 0, 0, 0, 0},
			nil, OptionsForwarded, 0, false},
		{"full", []byte{optionTimestamp, 8, 9, 0x20, 0, 0, 0, 1},
			[]byte{optionTimestamp, 8, 9, 0x30, 0, 0, 0, 1}, OptionsForwarded, 0, true},
		{"full before the end of the list", []byte{optionTimestamp, 8, 9, 0x20, 0, 0, 0, 1, optionEnd, 0, 0, 0},
			[]byte{optionTimestamp, 8, 9, 0x30, 0, 0, 0, 1, optionEnd, 0, 0, 0}, OptionsForwarded, 0, true},
		{"full and prespecified", []byte{optionTimestamp, 12, 13, 0x03, 192, 0, 2, 1, 0, 0, 0, 1},
			nil, OptionsForwarded, 0, false},
		{"full and prespecified with its overflow at 15", []byte{optionTimestamp, 12, 13, 0xf3, 192, 0, 2, 1, 0, 0, 0, 1},
			nil, OptionsForwarded, 0, false},
		{"a flag RFC 791 does not define", []byte{optionTimestamp, 12, 5, 0x02, 0, 0, 0, 0, 0, 0, 0, 0},
			nil, OptionsForwarded, 0, false},
		{"full with its overflow at 15", []byte{optionTimestamp, 8, 9, 0xf0, 0, 0, 0, 1}, nil, OptionsMalformed, 23, false},
		{"room for a timestamp and no address", []byte{optionTimestamp, 8, 5, 0x01, 0, 0, 0, 0}, nil, OptionsMalformed, 22, false},
		{"room for part of a timestamp", []byte{optionTimestamp, 7, 5, 0x00, 0, 0, 0}, nil, OptionsMalformed, 22, false},
		{"a pointer under 5", []byte{optionTimestamp, 8, 4, 0x00, 0, 0, 0, 0}, nil, OptionsMalformed, 22, false},
		{"a length under 4", []byte{optionTimestamp, 3, 5}, nil, OptionsMalformed, 21, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			raw, verdict, pointer := forwarded(t, c.option)
			if verdict != c.verdict || pointer != c.pointer {
				t.Fatalf("the option is %d at octet %d, want %d at %d", verdict, pointer, c.verdict, c.pointer)
			}
			want := c.option
			if c.changing {
				want = c.want
			}
			if got := raw[20 : 20+len(want)]; !bytes.Equal(got, want) {
				t.Errorf("the option reads % x after, want % x", got, want)
			}
		})
	}
}

// an option RFC 791 cannot read is refused at its type octet: a length under 2, a length past the header, and a type octet with no length after it
// a second record route or timestamp is refused at its own type octet, and so is a second source route
func TestMalformedOptionsAreRefusedAtTheOctetAtFault(t *testing.T) {
	for _, c := range []struct {
		name    string
		options []byte
		pointer int
	}{
		{"a length of 0", []byte{148, 0, 0, 0}, 20},
		{"a length of 1", []byte{optionNOP, 148, 1, 0}, 21},
		{"a length past the header", []byte{148, 9, 0, 0}, 20},
		{"a length one past the header", []byte{optionNOP, optionNOP, 148, 3}, 22},
		{"a type octet last", []byte{optionNOP, optionNOP, optionNOP, 148}, 23},
		{"two record routes", []byte{optionRecordRoute, 3, 4, optionNOP, optionRecordRoute, 3, 4, optionEnd}, 24},
		{"two timestamps", []byte{optionTimestamp, 4, 5, 0, optionTimestamp, 4, 5, 0}, 24},
		{"two source routes", []byte{optionLooseSource, 3, 4, optionNOP, optionStrictSource, 3, 4, optionEnd}, 24},
		{"a source route under 3 bytes", []byte{optionLooseSource, 2, optionNOP, optionEnd}, 21},
		{"a source route pointer under 4", []byte{optionStrictSource, 7, 3, 0, 0, 0, 0}, 22},
		{"a source route before a malformed option", []byte{optionLooseSource, 3, 4, 148, 1, optionEnd}, 23},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, verdict, pointer := forwarded(t, c.options); verdict != OptionsMalformed || pointer != c.pointer {
				t.Errorf("% x is %d at octet %d, want refused at octet %d", c.options, verdict, pointer, c.pointer)
			}
		})
	}
	// the length octet of a type octet in the header's last byte lies past a datagram that carries nothing after its header
	raw := ipv4Packet([]byte{optionNOP, optionNOP, optionNOP, 148}, 0, 3, 0)
	before := bytes.Clone(raw)
	if verdict, pointer := ForwardOptions(raw, recorded, nil, stampedAt); verdict != OptionsMalformed || pointer != 23 || !bytes.Equal(raw, before) {
		t.Errorf("a datagram of its header alone ending in a type octet is %d at octet %d, want refused at octet 23 and unchanged", verdict, pointer)
	}
}

// a loose or strict source route is reported, with nothing changed, the record route behind it included
// an option the walker does not act on passes as it came, the end of the list stops the walk, and a header with no options is forwarded as it was
func TestSourceRoutesAreReportedAndOtherOptionsPass(t *testing.T) {
	for _, kind := range []byte{optionLooseSource, optionStrictSource} {
		if _, verdict, _ := forwarded(t, []byte{kind, 7, 4, 10, 0, 0, 1, optionRecordRoute, 7, 4, 0, 0, 0, 0}); verdict != OptionsSourceRouted {
			t.Errorf("a source route of type %d is %d, want reported", kind, verdict)
		}
	}
	raw, verdict, _ := forwarded(t, []byte{148, 4, 0, 0, optionRecordRoute, 7, 4, 0, 0, 0, 0})
	if want := []byte{148, 4, 0, 0, optionRecordRoute, 7, 8, 192, 0, 2, 1}; verdict != OptionsForwarded || !bytes.Equal(raw[20:31], want) {
		t.Errorf("a router alert ahead of a record route reads % x after, %d, want % x", raw[20:31], verdict, want)
	}
	behind := []byte{optionEnd, optionRecordRoute, 7, 4, 0, 0, 0, 0}
	if raw, verdict, _ := forwarded(t, behind); verdict != OptionsForwarded || !bytes.Equal(raw[20:28], behind) {
		t.Errorf("a record route past the end of the list reads % x after, %d, want it untouched", raw[20:28], verdict)
	}
	raw = ipv4Packet(nil, 0, 3, 8)
	before := bytes.Clone(raw)
	if verdict, _ := ForwardOptions(raw, recorded, nil, stampedAt); verdict != OptionsForwarded || !bytes.Equal(raw, before) {
		t.Errorf("a header with no options is %d and changed %t", verdict, !bytes.Equal(raw, before))
	}
}
