// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-License-Identifier: MIT

package babel

import (
	"net/netip"
	"testing"
)

func TestRawPacketRoundTrip(t *testing.T) {
	src := netip.MustParseAddr("fe80::1")
	payload := EncodePacket([]RawTLV{EncodeAck(42)})

	pkt := buildPacket(src, multicastGroup, payload)
	gotPayload, err := parsePacket(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if gotSrc, gotDst := addresses(pkt); gotSrc != src || gotDst != multicastGroup {
		t.Fatalf("addresses = %v, %v, want %v, %v", gotSrc, gotDst, src, multicastGroup)
	}
	if string(gotPayload) != string(payload) {
		t.Fatalf("payload mismatch: got %x want %x", gotPayload, payload)
	}
}

func TestRawPacketRejectsWrongPort(t *testing.T) {
	src := netip.MustParseAddr("fe80::1")
	pkt := buildPacket(src, multicastGroup, []byte{1, 2, 3})
	// Corrupt the destination port.
	pkt[ipv6HeaderLen+2] ^= 0xff
	if _, err := parsePacket(pkt); err == nil {
		t.Fatal("expected rejection of a packet not addressed to the babel port")
	}
}

func TestRawPacketRejectsTamperedLength(t *testing.T) {
	src := netip.MustParseAddr("fe80::1")
	pkt := buildPacket(src, multicastGroup, []byte{1, 2, 3})
	pkt = pkt[:len(pkt)-1] // truncate
	if _, err := parsePacket(pkt); err == nil {
		t.Fatal("expected rejection of a truncated packet")
	}
}

func TestRawPacketRejectsInvalidEnvelope(t *testing.T) {
	src := netip.MustParseAddr("fe80::1")
	for name, mutate := range map[string]func([]byte){
		"source port":    func(packet []byte) { packet[40], packet[41] = 0, 1 },
		"payload length": func(packet []byte) { packet[5]++ },
		"UDP length":     func(packet []byte) { packet[45]++ },
		"checksum":       func(packet []byte) { packet[46] ^= 0xff },
		"no checksum":    func(packet []byte) { packet[46], packet[47] = 0, 0 },
	} {
		t.Run(name, func(t *testing.T) {
			packet := buildPacket(src, multicastGroup, EncodePacket(nil))
			mutate(packet)
			if _, err := parsePacket(packet); err == nil {
				t.Fatal("parsePacket accepted invalid envelope")
			}
		})
	}
}

// the speaker's packets come from a link-local address to the Babel group or to its own address, and no others
func TestForSpeakerTakesLinkLocalSourceToGroupOrLocal(t *testing.T) {
	linkLocal, local := netip.MustParseAddr("fe80::1"), netip.MustParseAddr("fe80::2")
	for _, test := range []struct {
		name     string
		src, dst netip.Addr
		want     bool
	}{
		{"to the group", linkLocal, multicastGroup, true},
		{"to the local address", linkLocal, local, true},
		{"from the top of fe80::/10", netip.MustParseAddr("febf:ffff::1"), multicastGroup, true},
		{"from past fe80::/10", netip.MustParseAddr("fec0::1"), multicastGroup, false},
		{"from a mesh address", netip.MustParseAddr("2001:db8::1"), multicastGroup, false},
		{"from the group", multicastGroup, multicastGroup, false},
		{"to another link-local address", linkLocal, netip.MustParseAddr("fe80::9"), false},
		{"to all nodes", linkLocal, netip.MustParseAddr("ff02::1"), false},
	} {
		if got := forSpeaker(test.src, test.dst, local); got != test.want {
			t.Errorf("%s: forSpeaker(%v, %v) = %v, want %v", test.name, test.src, test.dst, got, test.want)
		}
	}
}
