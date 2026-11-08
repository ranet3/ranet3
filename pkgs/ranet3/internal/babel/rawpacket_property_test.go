// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package babel

import (
	"bytes"
	"encoding/binary"
	"io"
	"log/slog"
	"net/netip"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/logtest"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// theSpeakers is the model of what Receive consumes, read from the bytes alone: an IPv6 packet of 48 octets at least, UDP to port 6696 or a Fragment header next, from fe80::/10 to ff02::1:6 or to local
func theSpeakers(raw []byte, local [16]byte) bool {
	if len(raw) < 48 || raw[0]>>4 != 6 {
		return false
	}
	if !(raw[6] == 17 && raw[42] == 0x1a && raw[43] == 0x28) && raw[6] != 44 {
		return false
	}
	group := [16]byte{0: 0xff, 1: 0x02, 13: 0x01, 15: 0x06}
	dst := [16]byte(raw[24:40])
	return raw[8] == 0xfe && raw[9]&0xc0 == 0x80 && (dst == group || dst == local)
}

// a packet from a link-local address to the Babel group or to the speaker, UDP to the Babel port or a fragment, is consumed whatever else is wrong with it
// any other is handed back as it arrived, RFC 8966 section 4
// the packet is a well formed one with its addresses drawn across the bounds of fe80::/10 and one field of what parsePacket checks drawn across its bounds
func TestReceiveConsumesExactlyTheSpeakersPackets(t *testing.T) {
	logtest.SetDefault(t, slog.New(slog.NewTextHandler(io.Discard, nil)))
	speaker, _, _ := captureSpeaker(t, Config{})
	// a session no neighbor holds, so what the speaker consumes changes no state that a later case reads
	stranger := &netstack.Peer{ID: "stranger"}
	local := speaker.linkLocal.As16()
	addressAt := func(ht *hegel.T) [16]byte {
		var address [16]byte
		copy(address[2:], hegel.Draw(ht, hegel.Binary(14, 14)))
		var top uint16
		if hegel.Draw(ht, hegel.Booleans()) {
			// fe80::/10 runs from fe80 to febf, and the range drawn runs one past it either side
			top = hegel.Draw(ht, pbt.Spanning[uint16](0xfe7f, 0xfec0))
		} else {
			top = hegel.Draw(ht, hegel.SampledFrom([]uint16{0x0000, 0x2001, 0xff02}))
		}
		binary.BigEndian.PutUint16(address[:2], top)
		return address
	}
	pbt.Check(t, func(ht *hegel.T) {
		src := addressAt(ht)
		var dst [16]byte
		switch hegel.Draw(ht, hegel.Integers(0, 3)) {
		case 0:
			dst = multicastGroup.As16()
		case 1:
			dst = local
		default:
			dst = addressAt(ht)
		}
		payload := EncodePacket([]RawTLV{EncodeHello(Hello{Seqno: hegel.Draw(ht, uint16s()), Interval: 100})})
		raw := buildPacket(netip.AddrFrom16(src), netip.AddrFrom16(dst), payload)
		seal := false
		switch hegel.Draw(ht, hegel.Integers(0, 10)) {
		case 0:
			// well formed
		case 1:
			raw[0] = hegel.Draw(ht, pbt.Spanning[byte](0, 15))<<4 | raw[0]&0x0f
		case 2:
			raw[6] = hegel.Draw(ht, hegel.SampledFrom([]byte{0, nextHeaderUDP, nextHeaderFragment, 58}))
		case 3:
			binary.BigEndian.PutUint16(raw[4:6], uint16(len(raw)-ipv6HeaderLen+hegel.Draw(ht, pbt.Spanning(-2, 2))))
		case 4:
			binary.BigEndian.PutUint16(raw[40:42], hegel.Draw(ht, hegel.SampledFrom([]uint16{0, Port - 1, Port, Port + 1})))
			seal = true
		case 5:
			binary.BigEndian.PutUint16(raw[42:44], hegel.Draw(ht, hegel.SampledFrom([]uint16{0, Port - 1, Port, Port + 1})))
			seal = true
		case 6:
			binary.BigEndian.PutUint16(raw[44:46], uint16(len(raw)-ipv6HeaderLen+hegel.Draw(ht, pbt.Spanning(-2, 2))))
			seal = true
		case 7:
			raw[46], raw[47] = hegel.Draw(ht, pbt.Spanning[byte](0, 255)), hegel.Draw(ht, pbt.Spanning[byte](0, 255))
		case 8:
			raw[ipv6HeaderLen+udpHeaderLen] = hegel.Draw(ht, pbt.Spanning[byte](0, 255))
			seal = true
		case 9:
			raw[ipv6HeaderLen+udpHeaderLen+1] = hegel.Draw(ht, pbt.Spanning[byte](0, 255))
			seal = true
		default:
			raw = raw[:hegel.Draw(ht, pbt.Spanning(0, len(raw)))]
		}
		if seal {
			raw = edited(raw, true, func([]byte) {})
		}
		sent := bytes.Clone(raw)
		want := theSpeakers(raw, local)
		if got := speaker.Receive(stranger, raw); got != want || !bytes.Equal(raw, sent) {
			ht.Fatalf("Receive took %x as %v, want %v, and it reads %x after", sent, got, want, raw)
		}
	})
}
