// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

package ike

import (
	"encoding/binary"
	"fmt"
)

// genericPayloadHeaderLen is the size of the Next Payload / Critical+Reserved
// / Payload Length fields shared by every payload, RFC 7296 section 3.2.
const genericPayloadHeaderLen = 4

// RawPayload is an undecoded IKE payload: a type tag plus its body bytes
// (the body does not include the generic 4-byte payload header).
type RawPayload struct {
	Type     PayloadType
	Critical bool
	Body     []byte
}

// Message is a full IKEv2 message: header plus an ordered list of payloads.
// The payload chain (Next Payload pointers) is derived from ordering on
// Encode and walked automatically on Decode.
type Message struct {
	Header   Header
	Payloads []RawPayload

	// skHeaderOffset is the offset in the message of the SK or SKF payload's generic header where the last payload decoded is one of them
	// so DecryptMessage reads the associated data, the octets through that header, as they arrived
	skHeaderOffset int
}

// Encode serializes the message. It does not encrypt: [EncryptMessage] is the
// path that does, and a caller assembling an SK payload itself passes it here
// as the sole payload after the header's cleartext ones.
func (m *Message) Encode() []byte {
	return m.encode(0)
}

func (m *Message) encode(reserveTrailer int) []byte {
	body := encodePayloadChain(m.Payloads)
	firstType := PayloadNone
	if len(m.Payloads) > 0 {
		firstType = m.Payloads[0].Type
	}
	h := m.Header
	h.NextPayload = firstType
	h.Length = uint32(HeaderLen + len(body) + reserveTrailer)
	out := make([]byte, 0, HeaderLen+len(body))
	out = append(out, h.encode()...)
	out = append(out, body...)
	return out
}

// encodePayloadChain serializes a list of payloads with Next Payload
// pointers chained in order, shared by Message.encode and the SK payload's
// inner-plaintext construction (sk.go).
func encodePayloadChain(payloads []RawPayload) []byte {
	return encodePayloadChainBefore(payloads, PayloadNone)
}

// encodePayloadChainBefore is encodePayloadChain for a chain another payload
// follows: the last payload's Next Payload names following rather than ending
// the message, RFC 7296 section 3.2. The payloads sent in the clear ahead of SK
// are such a chain.
func encodePayloadChainBefore(payloads []RawPayload, following PayloadType) []byte {
	body := make([]byte, 0, payloadChainCapacity)
	for i, p := range payloads {
		next := following
		if i+1 < len(payloads) {
			next = payloads[i+1].Type
		}
		hdr := make([]byte, genericPayloadHeaderLen)
		hdr[0] = byte(next)
		if p.Critical {
			hdr[1] = 0x80
		}
		binary.BigEndian.PutUint16(hdr[2:4], uint16(genericPayloadHeaderLen+len(p.Body)))
		body = append(body, hdr...)
		body = append(body, p.Body...)
	}
	return body
}

// decodePayloadChain walks a Next-Payload chain within a flat byte slice
// (used to parse the decrypted contents of an SK payload).
func decodePayloadChain(first PayloadType, b []byte) ([]RawPayload, error) {
	var out []RawPayload
	next := first
	rest := b
	for next != PayloadNone {
		if len(rest) < genericPayloadHeaderLen {
			return nil, fmt.Errorf("ike: truncated payload header")
		}
		plLen := binary.BigEndian.Uint16(rest[2:4])
		if int(plLen) < genericPayloadHeaderLen || int(plLen) > len(rest) {
			return nil, fmt.Errorf("ike: invalid payload length %d", plLen)
		}
		out = append(out, RawPayload{
			Type:     next,
			Critical: rest[1]&0x80 != 0,
			Body:     rest[genericPayloadHeaderLen:plLen],
		})
		next = PayloadType(rest[0])
		rest = rest[plLen:]
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("ike: %d trailing bytes after payload chain", len(rest))
	}
	return out, nil
}

// DecodeMessage parses an IKE header and its payload chain, and leaves the SK or SKF payload that ends it encrypted, its Body the IV, ciphertext and ICV, after Fragment Number and Total Fragments for SKF
func DecodeMessage(b []byte) (*Message, error) {
	h, err := decodeHeader(b)
	if err != nil {
		return nil, err
	}
	if h.Length < HeaderLen {
		return nil, fmt.Errorf("ike: header length %d is smaller than header size", h.Length)
	}
	if int(h.Length) != len(b) {
		return nil, fmt.Errorf("ike: header length %d does not match packet size %d", h.Length, len(b))
	}
	m := &Message{Header: *h}
	rest := b[HeaderLen:h.Length]
	next := h.NextPayload
	for next != PayloadNone {
		if len(rest) < genericPayloadHeaderLen {
			return nil, fmt.Errorf("ike: truncated payload header")
		}
		plLen := binary.BigEndian.Uint16(rest[2:4])
		if int(plLen) < genericPayloadHeaderLen || int(plLen) > len(rest) {
			return nil, fmt.Errorf("ike: invalid payload length %d", plLen)
		}
		p := RawPayload{
			Type:     next,
			Critical: rest[1]&0x80 != 0,
			Body:     rest[genericPayloadHeaderLen:plLen],
		}
		// RFC 7383 section 2.5: "As is the case for the Encrypted payload, the Encrypted Fragment payload, if present in a message, MUST be the last payload in the message."
		encrypted := p.Type == PayloadSK || p.Type == PayloadSKF
		if encrypted {
			m.skHeaderOffset = int(h.Length) - len(rest)
		}
		next = PayloadType(rest[0])
		m.Payloads = append(m.Payloads, p)
		rest = rest[plLen:]
		if encrypted {
			if len(rest) != 0 {
				return nil, fmt.Errorf("ike: %d trailing bytes after SK payload", len(rest))
			}
			break
		}
	}
	if next == PayloadNone && len(rest) != 0 {
		return nil, fmt.Errorf("ike: %d trailing bytes after payload chain", len(rest))
	}
	return m, nil
}

func (m *Message) find(t PayloadType) *RawPayload {
	for i := range m.Payloads {
		if m.Payloads[i].Type == t {
			return &m.Payloads[i]
		}
	}
	return nil
}
