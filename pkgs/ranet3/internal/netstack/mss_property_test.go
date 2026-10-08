// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package netstack

import (
	"bytes"
	"encoding/binary"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/packet"
	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/srv6"
)

// clamped returns raw as ClampMSS has to leave it, read the way RFC 9293 sections 3.1 and 3.7.1 read a segment
// a SYN, flagged as either end sends it, in a TCP packet that is no fragment and has TCP right after the IP header
// whose data offset fits the packet and whose options each carry a length that fits until the end of the list
// gets every four byte MSS option before that end lowered to limit where it is above it, and its checksum computed afresh
// and every other packet comes back as it was
func clamped(raw []byte, limit int) []byte {
	offset := 40
	if raw[0]>>4 == 4 {
		offset = int(raw[0]&0x0f) * 4
		if raw[9] != tcpProtocol || binary.BigEndian.Uint16(raw[6:8])&0x3fff != 0 {
			return raw
		}
	} else if raw[6] != tcpProtocol {
		return raw
	}
	header := int(raw[offset+12]>>4) * 4
	if raw[offset+13]&synFlag == 0 || header < tcpHeaderLen || offset+header > len(raw) {
		return raw
	}
	out := bytes.Clone(raw)
	var mss []int
	options := out[offset+tcpHeaderLen : offset+header]
	for at := 0; at < len(options) && options[at] != optionEnd; {
		if options[at] == optionNOP {
			at++
			continue
		}
		if at+2 > len(options) || options[at+1] < 2 || at+int(options[at+1]) > len(options) {
			return raw
		}
		if options[at] == optionMSS && options[at+1] == mssLen {
			mss = append(mss, at+2)
		}
		at += int(options[at+1])
	}
	for _, at := range mss {
		if int(binary.BigEndian.Uint16(options[at:])) > limit {
			binary.BigEndian.PutUint16(options[at:], uint16(limit))
		}
	}
	binary.BigEndian.PutUint16(out[offset+tcpChecksum:], tcpSum(out, offset))
	return out
}

// tcpOptions draws one option of a list, of the kinds a SYN carries, the end of the list, or an MSS of a length no receiver reads
var tcpOptions = []func(ht *hegel.T, limit int) []byte{
	func(ht *hegel.T, limit int) []byte {
		value := hegel.Draw(ht, hegel.Integers(0, 0xffff))
		if hegel.Draw(ht, hegel.Booleans()) {
			value = max(0, limit+hegel.Draw(ht, hegel.Integers(-1, 1)))
		}
		return binary.BigEndian.AppendUint16([]byte{optionMSS, mssLen}, uint16(value))
	},
	func(*hegel.T, int) []byte { return []byte{optionNOP} },
	func(*hegel.T, int) []byte { return []byte{4, 2} },
	func(ht *hegel.T, _ int) []byte { return []byte{3, 3, byte(hegel.Draw(ht, hegel.Integers(0, 14)))} },
	func(ht *hegel.T, _ int) []byte { return append([]byte{8, 10}, hegel.Draw(ht, hegel.Binary(8, 8))...) },
	func(*hegel.T, int) []byte { return []byte{optionEnd} },
	func(ht *hegel.T, _ int) []byte {
		return []byte{optionMSS, 3, byte(hegel.Draw(ht, hegel.Integers(0, 0xff)))}
	},
}

// for any IPv4 or IPv6 TCP segment with any option list, an MSS anywhere in it, NOPs, SACK permitted, window scale,
// timestamps, the end of the list and a list cut short, and with any flags
// a SYN or SYN-ACK whose MSS is past the session's limit leaves with that MSS at the limit, a checksum a fresh computation agrees with
// and every other byte as it was, while anything else leaves byte for byte as it came
// the limit is the session's MTU less 40 under IPv4 and 60 under IPv6
func TestClampMSSLowersOnlyTheMSSOfASYN(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		family := 4
		if hegel.Draw(ht, hegel.Booleans()) {
			family = 6
		}
		mtu := hegel.Draw(ht, pbt.Spanning(srv6.MinimumIPv6MTU-srv6.Overhead(2), 9000))
		limit := mtu - ipv4Segment
		if family == 6 {
			limit = mtu - ipv6Segment
		}
		// half the cases are a SYN whose list describes itself and carries an MSS past the limit, broken by one rule at most
		// which puts each rule that leaves a packet alone against packets the others would let the clamp reach
		alone := hegel.Draw(ht, hegel.Booleans())
		broken := hegel.Draw(ht, hegel.Integers(0, 5))
		breaks := func(rule int, chance float64) bool {
			if alone {
				return broken == rule
			}
			return hegel.Draw(ht, hegel.WeightedBooleans(chance))
		}
		// a list cut short ends in an option whose length runs past the header, two bytes the rest of the list leaves room for
		cut := breaks(4, 1.0/8)
		most := 40
		if cut {
			most -= 2
		}
		if alone {
			most -= mssLen
		}
		room := hegel.Draw(ht, pbt.Spanning(0, most))
		var options []byte
		fill := func(room int) {
			for len(options) < room {
				option := tcpOptions[hegel.Draw(ht, hegel.Integers(0, len(tcpOptions)-1))](ht, limit)
				if alone && option[0] == optionEnd {
					option = []byte{optionNOP}
				}
				if len(options)+len(option) > room {
					return
				}
				options = append(options, option...)
			}
		}
		if alone {
			fill(hegel.Draw(ht, pbt.Spanning(0, room)))
			options = binary.BigEndian.AppendUint16(append(options, optionMSS, mssLen), uint16(limit+hegel.Draw(ht, pbt.Spanning(1, 0xffff-limit))))
			room += mssLen
		}
		fill(room)
		if cut {
			options = append(options, 8, byte(hegel.Draw(ht, hegel.Integers(41-len(options), 0xff))))
		}
		for len(options)%4 != 0 {
			options = append(options, optionEnd)
		}
		var field uint16
		extension := false
		if breaks(2, 1.0/8) {
			if family == 4 {
				field = uint16(hegel.Draw(ht, pbt.Spanning(1, 0x3fff)))
			} else {
				extension = true
			}
		}
		var offset byte
		if breaks(3, 1.0/8) {
			offset = byte(hegel.Draw(ht, hegel.Integers(1, 15)))
			if alone {
				offset = byte(hegel.Draw(ht, hegel.Integers(1, tcpHeaderLen/4-1)))
			}
		}
		flags := byte(hegel.Draw(ht, hegel.Integers(0, 0xff))) &^ synFlag
		if !breaks(5, 1.0/2) {
			flags |= synFlag
		}
		raw := tcpPacket(family, field, extension, flags, options, offset, hegel.Draw(ht, pbt.Spanning(0, 64)))
		// the same bytes under UDP are no SYN at all
		if breaks(1, 1.0/8) {
			switch {
			case family == 4:
				raw[9] = 17
				binary.BigEndian.PutUint16(raw[10:], 0)
				binary.BigEndian.PutUint16(raw[10:], ^uint16(packet.Sum(0, raw[:20])))
			case extension:
				raw[40] = 17
			default:
				raw[6] = 17
			}
		}
		want := clamped(raw, limit)
		got := bytes.Clone(raw)
		ClampMSS(got, mtu)
		if !bytes.Equal(got, want) {
			ht.Fatalf("a %d byte IPv%d packet with flags %#02x and options %x left as %x, want %x", len(raw), family, flags, options, got, want)
		}
	})
}
