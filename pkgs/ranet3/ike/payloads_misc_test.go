// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

package ike

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"testing"
)

func TestDeleteRoundTrip(t *testing.T) {
	want := Delete{Protocol: ProtoESP, SPIs: [][]byte{{0, 0, 0, 1}, {0, 0, 0, 2}}}
	got, err := DecodeDelete(EncodeDelete(want))
	if err != nil {
		t.Fatal(err)
	}
	if got.Protocol != want.Protocol || len(got.SPIs) != len(want.SPIs) {
		t.Fatalf("decoded delete = %#v, want %#v", got, want)
	}
	for i := range want.SPIs {
		if !bytes.Equal(got.SPIs[i], want.SPIs[i]) {
			t.Fatalf("SPI %d = %x, want %x", i, got.SPIs[i], want.SPIs[i])
		}
	}
}

func TestDecodeDeleteRejectsTruncatedSPI(t *testing.T) {
	if _, err := DecodeDelete([]byte{byte(ProtoESP), 4, 0, 1, 0, 0, 0}); err == nil {
		t.Fatal("DecodeDelete accepted a truncated SPI")
	}
}

func TestDecodeDeleteEnforcesProtocolSPISize(t *testing.T) {
	for _, test := range []struct {
		name string
		body []byte
	}{
		{"IKE SPI", []byte{byte(ProtoIKE), 4, 0, 1, 0, 0, 0, 1}},
		{"IKE count", []byte{byte(ProtoIKE), 0, 0, 1}},
		{"ESP size", []byte{byte(ProtoESP), 0, 0, 0}},
		{"AH size", []byte{byte(ProtoAH), 8, 0, 0}},
		{"protocol", []byte{99, 4, 0, 0}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := DecodeDelete(test.body); err == nil {
				t.Fatal("DecodeDelete accepted invalid Delete payload")
			}
		})
	}
}

// RFC 7296 section 3.11 fixes the SPI Size by protocol, zero for IKE and four
// for AH and ESP, however many SPIs follow. Taken from the first SPI, it came
// out zero for a Child SA delete carrying none, which is the size
// DecodeDelete refuses for those protocols, as a peer should.
func TestEmptyChildSADeleteKeepsItsProtocolsSPISize(t *testing.T) {
	for _, protocol := range []ProtocolID{ProtoAH, ProtoESP} {
		body := EncodeDelete(Delete{Protocol: protocol})
		if body[1] != 4 {
			t.Errorf("a protocol %d delete with no SPIs gives SPI Size %d, want 4", protocol, body[1])
		}
		if _, err := DecodeDelete(body); err != nil {
			t.Errorf("a protocol %d delete with no SPIs does not read back: %v", protocol, err)
		}
	}
}

func TestDecodeTSRejectsUndersizedSelector(t *testing.T) {
	for _, kind := range []byte{TS_IPV4_ADDR_RANGE, TS_IPV6_ADDR_RANGE} {
		for length := 4; length < 8; length++ {
			t.Run(fmt.Sprintf("%d/%d", kind, length), func(t *testing.T) {
				// no spare capacity follows the final selector
				body := make([]byte, 4+length)
				body[0], body[4] = 1, kind
				binary.BigEndian.PutUint16(body[6:8], uint16(length))
				if _, err := DecodeTS(body); err == nil {
					t.Fatalf("DecodeTS accepted a range shorter than its fixed header: %x", body)
				}
			})
		}
	}
}

func TestUnknownTrafficSelectorExtent(t *testing.T) {
	for _, length := range []uint16{5, 0xffff} {
		body := []byte{1, 0, 0, 0, 10, 0, 0, 0}
		binary.BigEndian.PutUint16(body[6:8], length)
		if _, err := DecodeTS(body); err == nil {
			t.Errorf("accepted selector length %d in a four-octet buffer", length)
		}
	}
	for length, body := range undersizedUnknownSelectorBodies() {
		t.Run(fmt.Sprint(length), func(t *testing.T) {
			if got, err := DecodeTS(body); err == nil {
				t.Fatalf("DecodeTS accepted selector length %d in %x: %+v", length, body, got)
			}
		})
	}
}

// positive short extents overlap the next header and exhaust the bytes if the floor is ignored
// zero cannot advance to the next header
func undersizedUnknownSelectorBodies() [4][]byte {
	// a length of one becomes the high octet of the next selector's length
	one := make([]byte, 4+1+256)
	copy(one, []byte{2, 0, 0, 0, 10, 0, 0, 1})
	return [4][]byte{
		{2, 0, 0, 0, 10, 0, 0, 0, 9, 0, 0, 4},
		one,
		{2, 0, 0, 0, 10, 0, 0, 2, 0, 6, 0, 0},
		{2, 0, 0, 0, 10, 0, 0, 3, 0, 0, 4},
	}
}

func TestDecodeTSRejectsWrongSelectorCount(t *testing.T) {
	for _, body := range [][]byte{
		{2, 0, 0, 0, 10, 0, 0, 4},
		{1, 0, 0, 0, 10, 0, 0, 4, 9, 0, 0, 4},
	} {
		if got, err := DecodeTS(body); err == nil {
			t.Errorf("DecodeTS accepted a mismatched selector count in %x: %+v", body, got)
		}
	}
}

func TestUnknownTrafficSelectorRetainsItsType(t *testing.T) {
	body := []byte{1, 0, 0, 0, 10, 0, 0, 4}
	got, err := DecodeTS(body)
	if err != nil || len(got) != 1 || got[0].Type != 10 {
		t.Fatalf("unknown-only payload = %+v, %v, want one type 10 selector", got, err)
	}
}

func TestUnknownTrafficSelectorIsIgnoredInRequestsButRefusedInAnswers(t *testing.T) {
	body := []byte{3, 0, 0, 0, 10, 0, 0, 4}
	body = append(body, fullRangeSelectors()[4:]...)
	if !holdsFullRanges(body) || isFullRangeSelectors(body) {
		t.Fatal("extra unknown selector must be accepted in requests but refused in answers")
	}
}

// The selector type names the address width, and the length field says it
// again. They have to agree, because everything downstream reads the width
// from the type: isFullRangeSelectors compares a decoded selector against a
// four byte v4 range and a sixteen byte v6 one, and a v6 selector carrying a
// four byte address, or a v4 one carrying the 4-in-6 form of the same address,
// is a different selector on the wire that must not compare equal to either.
func TestTrafficSelectorAddressWidthMustMatchItsType(t *testing.T) {
	selector := func(kind byte, addrLen int) []byte {
		body := []byte{1, 0, 0, 0, kind, 0, 0, 0, 0, 0, 0xff, 0xff}
		binary.BigEndian.PutUint16(body[6:8], uint16(8+2*addrLen))
		return append(body, make([]byte, 2*addrLen)...)
	}
	for name, body := range map[string][]byte{
		"a v4 selector carrying v6 addresses": selector(TS_IPV4_ADDR_RANGE, 16),
		"a v6 selector carrying v4 addresses": selector(TS_IPV6_ADDR_RANGE, 4),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeTS(body); err == nil {
				t.Error("decoded without complaint, so the width no longer follows the type")
			}
		})
	}
	for name, body := range map[string][]byte{
		"a v4 selector": selector(TS_IPV4_ADDR_RANGE, 4),
		"a v6 selector": selector(TS_IPV6_ADDR_RANGE, 16),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeTS(body); err != nil {
				t.Errorf("a well-formed selector was refused: %v", err)
			}
		})
	}
}

// net.IPv4zero and net.IPv6zero are single slices shared by everything in the
// process that names them, and To4 returns a window into the first rather than
// a new one. A selector is handed to callers that encode it and may hold it,
// so it must not be either of those slices.
func TestFullRangeSelectorsAreNotThePackagesOwnZeroes(t *testing.T) {
	if v4 := FullRangeV4(); len(v4.StartAddr) != 0 && len(net.IPv4zero) != 0 &&
		&v4.StartAddr[0] == &net.IPv4zero[12] {
		t.Error("the IPv4 selector starts inside net.IPv4zero")
	}
	if v6 := FullRangeV6(); len(v6.StartAddr) == len(net.IPv6zero) && len(net.IPv6zero) != 0 &&
		&v6.StartAddr[0] == &net.IPv6zero[0] {
		t.Error("the IPv6 selector is net.IPv6zero itself")
	}
}
