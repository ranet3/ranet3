// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

package babel

import (
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"time"
)

// RouterID TLV, RFC 8966 section 4.6.7: Reserved(2) + 8-byte Router-Id.
func EncodeRouterID(id [8]byte) RawTLV {
	body := make([]byte, 10)
	copy(body[2:], id[:])
	return RawTLV{Type: TLVRouterID, Body: body}
}

// DecodeRouterID also reports whether the TLV is otherwise to be ignored,
// which an unknown mandatory sub-TLV makes it. The router id is returned
// either way: RFC 8966 section 4.6.7 says "This TLV sets the router-id even if
// it is otherwise ignored due to an unknown mandatory sub-TLV", and section
// 4.5 says the same generally, that "parsing a TLV MUST update the parser
// state even if the TLV is otherwise ignored". Two nodes that disagree about
// which router id an Update belongs to keep different source-table entries for
// it, and neither one's feasibility distance then bounds the other.
func DecodeRouterID(body []byte) (id [8]byte, ignore bool, err error) {
	if len(body) < 10 {
		return id, false, fmt.Errorf("babel: short Router-Id TLV")
	}
	copy(id[:], body[2:10])
	if _, err := decodeOptionalSubTLVs(body[10:]); err != nil {
		return id, true, nil
	}
	return id, false, nil
}

// NextHop TLV, RFC 8966 section 4.6.8.
func EncodeNextHop(addr net.IP) RawTLV {
	ae, a := encodeAddress(addr)
	body := make([]byte, 2+len(a))
	body[0] = ae
	copy(body[2:], a)
	return RawTLV{Type: TLVNextHop, Body: body}
}

// DecodeNextHop returns the next hop, the address encoding that named it, and
// whether the TLV is otherwise ignored. The encoding is reported rather than
// inferred from the address: RFC 8966 section 4.6.9 pairs an Update with "the
// last preceding Next Hop TLV with a matching address family (IPv4 or IPv6)",
// and an AE 2 body carrying ::ffff:a.b.c.d is an IPv6 next hop that net.IP.To4
// reports as IPv4. Taking it for one enables the AE 1 Updates behind it, which
// that section says MUST be ignored for want of a next hop.
//
// The address comes back either way, because RFC
// 8966 section 4.5 makes the parser state unconditional: "Since the parser
// state must be identical across implementations, it is updated before
// checking for mandatory sub-TLVs: parsing a TLV MUST update the parser state
// even if the TLV is otherwise ignored due to an unknown mandatory sub-TLV or
// for any other reason." A sub-TLV region this cannot parse is one of those
// other reasons, so it is an ignore rather than a failure, and only a TLV
// whose own address cannot be read returns an error. DecodeRouterID and
// PrefixDecoder.Decode, the other two that carry parser state, do the same.
func DecodeNextHop(body []byte) (addr net.IP, ae uint8, ignore bool, err error) {
	if len(body) < 2 {
		return nil, 0, false, fmt.Errorf("babel: short NextHop TLV")
	}
	ae = body[0]
	addr, err = decodeAddress(ae, body[2:])
	if err != nil {
		return nil, 0, false, err
	}
	length := len(addr)
	if ae == AEIPv6LinkLocal {
		length = 8
	}
	if _, err := decodeOptionalSubTLVs(body[2+length:]); err != nil {
		return addr, ae, true, nil
	}
	return addr, ae, false, nil
}

// AckReq and Ack, RFC 8966 sections 4.6.3 and 4.6.4
// this node answers every AckReq
// it sends one only as a path MTU probe, see Speaker.Probe
func EncodeAckReq(nonce uint16, interval uint16) RawTLV {
	body := make([]byte, 6)
	binary.BigEndian.PutUint16(body[2:4], nonce)
	binary.BigEndian.PutUint16(body[4:6], interval)
	return RawTLV{Type: TLVAckReq, Body: body}
}

func DecodeAckReq(body []byte) (nonce uint16, err error) {
	if len(body) < 6 {
		return 0, fmt.Errorf("babel: short AckReq TLV")
	}
	if _, err := decodeOptionalSubTLVs(body[6:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(body[2:4]), nil
}

func EncodeAck(nonce uint16) RawTLV {
	body := make([]byte, 2)
	binary.BigEndian.PutUint16(body, nonce)
	return RawTLV{Type: TLVAck, Body: body}
}

// DecodeAck returns the Opaque an Ack echoes, the nonce of the request it answers
func DecodeAck(body []byte) (nonce uint16, err error) {
	if len(body) < 2 {
		return 0, fmt.Errorf("babel: short Ack TLV")
	}
	if _, err := decodeOptionalSubTLVs(body[2:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(body), nil
}

// smallestProbe and largestProbe bound a probe as an inner IPv6 packet, its IPv6 and UDP headers included
// the smallest holds the babel header, the eight octets of its Ack Request and the two of one empty PadN
// the largest is the 2^16-1 octets RFC 8966 section 4 allows a babel packet with its lower-layer headers
const (
	smallestProbe = ipv6HeaderLen + udpHeaderLen + headerLen + 8 + 2
	largestProbe  = math.MaxUint16
)

// probeTLVs is an Ack Request carrying nonce, padded with PadN alone to make the inner IPv6 packet it travels in size octets long
// size runs from smallestProbe to largestProbe
func probeTLVs(nonce uint16, size int) []RawTLV {
	request := EncodeAckReq(nonce, uint16(probeInterval/(10*time.Millisecond)))
	tlvs := []RawTLV{request}
	// each TLV takes two octets of type and length ahead of its body, RFC 8966 section 4.3
	padding := size - ipv6HeaderLen - udpHeaderLen - headerLen - 2 - len(request.Body)
	zeros := make([]byte, math.MaxUint8)
	for padding > 0 {
		body := min(padding-2, math.MaxUint8)
		// a single octet left after this PadN is one no PadN fills
		if padding-2-body == 1 {
			body--
		}
		tlvs = append(tlvs, RawTLV{Type: TLVPadN, Body: zeros[:body]})
		padding -= 2 + body
	}
	return tlvs
}
