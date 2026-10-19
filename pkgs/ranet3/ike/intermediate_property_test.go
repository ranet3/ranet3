// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package ike

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"slices"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// sealed is an IKE message whose Encrypted payload carries plain under suite and key, its generic header's second octet flags and its unprotected payloads cleartext
// it seals as encryptMessagePlaintextIV does with any C bit and RESERVED, which a peer may send
func sealed(t *hegel.T, suite SASuite, key []byte, hdr Header, cleartext []RawPayload, innerFirst PayloadType, flags byte, plain, iv []byte) []byte {
	params, err := aeadParams(suite.EncrID, suite.EncrKeyBits)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := newAEAD(suite.EncrID, key[:params.KeyLen])
	if err != nil {
		t.Fatal(err)
	}
	unprotected := encodePayloadChainBefore(cleartext, PayloadSK)
	sk := []byte{byte(innerFirst), flags, 0, 0}
	binary.BigEndian.PutUint16(sk[2:], uint16(genericPayloadHeaderLen+params.IVLen+len(plain)+params.ICVLen))
	hdr.NextPayload = PayloadSK
	if len(cleartext) > 0 {
		hdr.NextPayload = cleartext[0].Type
	}
	hdr.Length = uint32(HeaderLen + len(unprotected) + len(sk) + params.IVLen + len(plain) + params.ICVLen)
	head := concat(hdr.encode(), unprotected, sk)
	return concat(head, iv, aead.Seal(nil, concat(key[params.KeyLen:], iv), plain, head))
}

// the IntAuth chunks the sender takes from the octets it sent and the inner payloads it encrypted equal those the receiver takes from the octets it got and the plaintext it decrypted
// for any inner payloads, padding, unprotected payloads, C bit and RESERVED
// and the chunk is A then P, with the IKE header's Length and the Encrypted payload's Payload Length adjusted and every other octet as sent
// RFC 9242 section 3.3.2: "The IntAuth_[i/r]*A chunk consists of the sequence of octets from the first octet of the IKE Header (not including the prepended four octets of zeros, if UDP encapsulation or TCP encapsulation of ESP packets is used) to the last octet of the generic header of the Encrypted payload."
// RFC 9242 section 3.3.2: "The Initialization Vector, Padding, Pad Length, and Integrity Checksum Data fields (see Section 3.14 of [RFC7296]) are not included into the calculation."
func TestIntAuthChunkIsTheSameAtBothEnds(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 256, PRFID: PRF_HMAC_SHA2_256, DHGroup: DH_CURVE25519}
		if hegel.Draw(ht, hegel.Booleans()) {
			suite.EncrID, suite.EncrKeyBits = ENCR_CHACHA20_POLY1305, 0
		}
		params, err := aeadParams(suite.EncrID, suite.EncrKeyBits)
		if err != nil {
			ht.Fatal(err)
		}
		key := hegel.Draw(ht, hegel.Binary(params.KeyLen+params.SaltLen, params.KeyLen+params.SaltLen))
		iv := hegel.Draw(ht, hegel.Binary(params.IVLen, params.IVLen))
		drawPayloads := func(most int) []RawPayload {
			var payloads []RawPayload
			for range hegel.Draw(ht, pbt.Spanning(0, most)) {
				payloads = append(payloads, RawPayload{
					Type:     hegel.Draw(ht, hegel.SampledFrom([]PayloadType{PayloadKE, PayloadN, PayloadV, PayloadIDi})),
					Critical: hegel.Draw(ht, hegel.Booleans()),
					Body:     hegel.Draw(ht, hegel.Binary(0, 64)),
				})
			}
			return payloads
		}
		inner, cleartext := drawPayloads(3), drawPayloads(2)
		innerFirst := PayloadNone
		if len(inner) > 0 {
			innerFirst = inner[0].Type
		}
		p := encodePayloadChain(inner)
		pad := hegel.Draw(ht, pbt.Spanning(0, 16))
		plain := concat(p, make([]byte, pad), []byte{byte(pad)})
		flags := hegel.Draw(ht, hegel.Integers[byte](0, 0xff))
		hdr := Header{SPIInitiator: 1, SPIResponder: 2, ExchangeType: IKE_INTERMEDIATE, Flags: FlagInitiator, MessageID: hegel.Draw(ht, pbt.Spanning[uint32](1, 7))}
		raw := sealed(ht, suite, key, hdr, cleartext, innerFirst, flags, plain, iv)
		skOffset := HeaderLen + len(encodePayloadChainBefore(cleartext, PayloadSK))
		sent, err := intAuthChunk(raw, skOffset, p)
		if err != nil {
			ht.Fatal(err)
		}
		m, err := DecodeMessage(raw)
		if err != nil {
			ht.Fatalf("the message does not decode: %v", err)
		}
		_, decrypted, err := decryptMessagePlaintext(suite, key, raw, m)
		if err != nil {
			ht.Fatal(err)
		}
		got, err := intAuthChunk(raw, m.skHeaderOffset, decrypted[:len(decrypted)-1-int(decrypted[len(decrypted)-1])])
		if err != nil {
			ht.Fatal(err)
		}
		if !bytes.Equal(sent, got) {
			ht.Fatalf("the sender's chunk %x is not the receiver's %x", sent, got)
		}
		want := concat(raw[:skOffset+genericPayloadHeaderLen], p)
		binary.BigEndian.PutUint32(want[24:28], uint32(len(want)))
		binary.BigEndian.PutUint16(want[skOffset+2:skOffset+4], uint16(genericPayloadHeaderLen+len(p)))
		if !bytes.Equal(got, want) {
			ht.Fatalf("the chunk of %x is %x, want %x", raw, got, want)
		}
	})
}

// the keys of every generation of a setup equal the chain RFC 9370 and RFC 7296 give, computed with crypto/hmac
// RFC 7296 section 2.14: "SKEYSEED = prf(Ni | Nr, g^ir)"
// RFC 9370 section 2.2.2: "SKEYSEED(n) = prf(SK_d(n-1), SK(n) | Ni | Nr)"
// RFC 9370 section 2.2.2: "{SK_d(n) | SK_ai(n) | SK_ar(n) | SK_ei(n) | SK_er(n) | SK_pi(n) | SK_pr(n)} = prf+ (SKEYSEED(n), Ni | Nr | SPIi | SPIr)"
func TestSetupKeysFollowTheChainOfRFC9370(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: hegel.Draw(ht, hegel.SampledFrom([]uint16{128, 256})), PRFID: PRF_HMAC_SHA2_256}
		newHash := sha256.New
		if hegel.Draw(ht, hegel.Booleans()) {
			suite.PRFID, newHash = PRF_HMAC_SHA2_384, sha512.New384
		}
		keyLen := int(suite.EncrKeyBits)/8 + 4
		ni, nr := hegel.Draw(ht, hegel.Binary(16, 64)), hegel.Draw(ht, hegel.Binary(16, 64))
		spiI, spiR := hegel.Draw(ht, hegel.Integers[uint64](1, 1<<63)), hegel.Draw(ht, hegel.Integers[uint64](1, 1<<63))
		var spis [16]byte
		binary.BigEndian.PutUint64(spis[:8], spiI)
		binary.BigEndian.PutUint64(spis[8:], spiR)
		seed := concat(ni, nr, spis[:])
		prf := func(key, data []byte) []byte {
			mac := hmac.New(newHash, key)
			mac.Write(data)
			return mac.Sum(nil)
		}
		shared := hegel.Draw(ht, hegel.Binary(32, 97))
		keys, err := DeriveIKEKeys(suite, shared, ni, nr, spiI, spiR)
		if err != nil {
			ht.Fatal(err)
		}
		want := modelKeys(newHash, prf(concat(ni, nr), shared), seed, keyLen)
		for n := range hegel.Draw(ht, pbt.Spanning(0, addkeTypes)) {
			got := [5][]byte{keys.SKd, keys.SKei, keys.SKer, keys.SKpi, keys.SKpr}
			if !slices.EqualFunc(got[:], want[:], bytes.Equal) {
				ht.Fatalf("generation %d holds %x, the chain %x", n, got, want)
			}
			secret := hegel.Draw(ht, hegel.Binary(32, 32))
			if keys, err = DeriveRekeyedIKEKeys(suite.PRFID, keys.SKd, suite, secret, ni, nr, spiI, spiR); err != nil {
				ht.Fatal(err)
			}
			want = modelKeys(newHash, prf(want[0], concat(secret, ni, nr)), seed, keyLen)
		}
	})
}
