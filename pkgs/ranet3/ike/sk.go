// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-License-Identifier: MIT

package ike

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"slices"
)

// EncryptMessage builds a full IKEv2 message wire image whose payloads
// (after any cleartext ones, of which our profile has none post-IKE_SA_INIT)
// are carried inside a single SK payload, per RFC 7296 section 3.14 / RFC 5282.
//
// key is SK_ei or SK_er (encryption key || salt) depending on direction.
func EncryptMessage(suite SASuite, key []byte, hdr Header, cleartext, inner []RawPayload) ([]byte, error) {
	var iv [8]byte
	if _, err := rand.Read(iv[:]); err != nil {
		return nil, err
	}
	return encryptMessageIV(suite, key, hdr, cleartext, inner, iv[:])
}

func (c *ikeContext) nextIV() ([]byte, error) {
	value := c.sendIV.Add(1)
	if value == 0 {
		return nil, fmt.Errorf("ike: AEAD IV space exhausted")
	}
	return binary.BigEndian.AppendUint64(nil, value), nil
}

func encryptMessageIV(suite SASuite, key []byte, hdr Header, cleartext, inner []RawPayload, iv []byte) ([]byte, error) {
	plain := encodePayloadChain(inner)
	plain = append(plain, 0) // zero-length padding + the pad-length octet itself
	innerFirst := PayloadNone
	if len(inner) > 0 {
		innerFirst = inner[0].Type
	}
	return encryptMessagePlaintextIV(suite, key, hdr, cleartext, innerFirst, plain, iv)
}

func encryptMessagePlaintextIV(suite SASuite, key []byte, hdr Header, cleartext []RawPayload, innerFirst PayloadType, plain, iv []byte) ([]byte, error) {
	return sealMessage(suite, key, hdr, cleartext, PayloadSK, []byte{byte(innerFirst), 0, 0, 0}, plain, iv)
}

// encryptFragmentIV is one IKE Fragment message, plain the padded chunk numbered number of total and next the Next Payload of its Encrypted Fragment payload
func encryptFragmentIV(suite SASuite, key []byte, hdr Header, cleartext []RawPayload, next PayloadType, number, total uint16, plain, iv []byte) ([]byte, error) {
	header := binary.BigEndian.AppendUint16(binary.BigEndian.AppendUint16([]byte{byte(next), 0, 0, 0}, number), total)
	return sealMessage(suite, key, hdr, cleartext, PayloadSKF, header, plain, iv)
}

// sealMessage is a message whose cleartext payloads come ahead of an encrypted payload of kind, its header encrypted ahead of the IV with the Payload Length filled in
// RFC 7383 section 2.5: "The cryptographic processing of the Encrypted Fragment payload is identical to that described in Section 3.14 of [RFC7296], as well as documents updating such processing for particular algorithms or modes, such as [RFC5282]."
// so an Encrypted Fragment payload's associated data runs to the end of its Total Fragments field, as an Encrypted payload's runs to the end of its generic header
func sealMessage(suite SASuite, key []byte, hdr Header, cleartext []RawPayload, kind PayloadType, encrypted, plain, iv []byte) ([]byte, error) {
	ap, err := aeadParams(suite.EncrID, suite.EncrKeyBits)
	if err != nil {
		return nil, err
	}
	if len(key) != ap.KeyLen+ap.SaltLen {
		return nil, fmt.Errorf("ike: key length %d does not match suite (want %d)", len(key), ap.KeyLen+ap.SaltLen)
	}
	aead, err := newAEAD(suite.EncrID, key[:ap.KeyLen])
	if err != nil {
		return nil, err
	}
	salt := key[ap.KeyLen:]

	if len(iv) != ap.IVLen {
		return nil, fmt.Errorf("ike: IV length %d does not match suite", len(iv))
	}
	nonce := append(append([]byte{}, salt...), iv...)

	cleartextBytes := encodePayloadChainBefore(cleartext, kind)

	skHdr := slices.Clone(encrypted)
	ciphertextLen := len(plain) + ap.ICVLen
	binary.BigEndian.PutUint16(skHdr[2:4], uint16(len(skHdr)+ap.IVLen+ciphertextLen))

	firstOuter := kind
	if len(cleartext) > 0 {
		firstOuter = cleartext[0].Type
	}
	h := hdr
	h.NextPayload = firstOuter
	h.Length = uint32(HeaderLen + len(cleartextBytes) + len(skHdr) + ap.IVLen + ciphertextLen)
	headerBytes := h.encode()

	aad := concat(headerBytes, cleartextBytes, skHdr)
	ciphertext := aead.Seal(nil, nonce, plain, aad)

	out := make([]byte, 0, int(h.Length))
	out = append(out, headerBytes...)
	out = append(out, cleartextBytes...)
	out = append(out, skHdr...)
	out = append(out, iv...)
	out = append(out, ciphertext...)
	return out, nil
}

// DecryptMessage decrypts the SK payload of an already-decoded Message
// (from DecodeMessage) and returns the inner payloads. raw must be the
// exact bytes passed to DecodeMessage. key is SK_ei or SK_er depending on
// which side sent the message.
func DecryptMessage(suite SASuite, key []byte, raw []byte, m *Message) ([]RawPayload, error) {
	innerFirst, plain, err := decryptMessagePlaintext(suite, key, raw, m)
	if err != nil {
		return nil, err
	}
	return decodeMessagePlaintext(innerFirst, plain)
}

// decryptMessagePlaintext returns once the tag authenticated and leaves the parse to the caller, which keeps an authenticated syntax error apart from a packet that does not authenticate
func decryptMessagePlaintext(suite SASuite, key []byte, raw []byte, m *Message) (PayloadType, []byte, error) {
	if len(m.Payloads) == 0 {
		return PayloadNone, nil, fmt.Errorf("ike: message has no SK payload")
	}
	// the Encrypted payload and the Encrypted Fragment payload both end a message, and the latter's Fragment Number and Total Fragments come ahead of its IV
	sk, headerLen := m.Payloads[len(m.Payloads)-1], genericPayloadHeaderLen
	switch {
	case sk.Type == PayloadSKF && len(sk.Body) >= 4:
		sk.Body, headerLen = sk.Body[4:], genericPayloadHeaderLen+4
	case sk.Type != PayloadSK:
		return PayloadNone, nil, fmt.Errorf("ike: message has no SK payload")
	}
	ap, err := aeadParams(suite.EncrID, suite.EncrKeyBits)
	if err != nil {
		return PayloadNone, nil, err
	}
	if len(key) != ap.KeyLen+ap.SaltLen {
		return PayloadNone, nil, fmt.Errorf("ike: key length %d does not match suite (want %d)", len(key), ap.KeyLen+ap.SaltLen)
	}
	if len(sk.Body) < ap.IVLen+ap.ICVLen {
		return PayloadNone, nil, fmt.Errorf("ike: SK payload too short")
	}
	aead, err := newAEAD(suite.EncrID, key[:ap.KeyLen])
	if err != nil {
		return PayloadNone, nil, err
	}
	salt := key[ap.KeyLen:]
	iv := sk.Body[:ap.IVLen]
	ciphertext := sk.Body[ap.IVLen:]
	nonce := append(append([]byte{}, salt...), iv...)

	aad := raw[:m.skHeaderOffset+headerLen]
	plain, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return PayloadNone, nil, fmt.Errorf("ike: SK payload authentication failed: %w", err)
	}
	skGenericHeader := raw[m.skHeaderOffset : m.skHeaderOffset+genericPayloadHeaderLen]
	return PayloadType(skGenericHeader[0]), plain, nil
}

func decodeMessagePlaintext(innerFirst PayloadType, plain []byte) ([]RawPayload, error) {
	inner, err := unpadded(plain)
	if err != nil {
		return nil, err
	}
	return decodeInnerPayloads(innerFirst, inner)
}

// decodeInnerPayloads reads the inner payloads of an SK plaintext that unpadded already took the Padding and Pad Length off
func decodeInnerPayloads(innerFirst PayloadType, inner []byte) ([]RawPayload, error) {
	payloads, err := decodePayloadChain(innerFirst, inner)
	if err != nil {
		return nil, err
	}
	// RFC 7296 section 3.1: "an Encrypted payload MUST NOT contain another Encrypted payload."
	if slices.ContainsFunc(payloads, func(payload RawPayload) bool { return payload.Type == PayloadSK }) {
		return nil, fmt.Errorf("ike: the SK payload carries another SK payload")
	}
	return payloads, nil
}

func unpadded(plain []byte) ([]byte, error) {
	if len(plain) == 0 {
		return nil, fmt.Errorf("ike: empty SK plaintext")
	}
	padLen := int(plain[len(plain)-1])
	if padLen+1 > len(plain) {
		return nil, fmt.Errorf("ike: invalid SK padding")
	}
	return plain[:len(plain)-1-padLen], nil
}
