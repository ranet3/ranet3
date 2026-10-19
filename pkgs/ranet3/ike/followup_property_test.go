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
	"hash"
	"slices"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// rekeyKeyInputs holds the drawn inputs a rekey with additional key exchanges derives its keys from
type rekeyKeyInputs struct {
	prfID      uint16
	newHash    func() hash.Hash
	skD        []byte
	shared     []byte
	ni, nr     []byte
	additional [][]byte
}

func drawnRekeyKeyInputs(ht *hegel.T) rekeyKeyInputs {
	in := rekeyKeyInputs{prfID: PRF_HMAC_SHA2_256, newHash: sha256.New}
	if hegel.Draw(ht, hegel.Booleans()) {
		in.prfID, in.newHash = PRF_HMAC_SHA2_384, sha512.New384
	}
	in.skD = hegel.Draw(ht, hegel.Binary(in.newHash().Size(), in.newHash().Size()))
	in.shared = hegel.Draw(ht, hegel.Binary(32, 97))
	in.ni, in.nr = hegel.Draw(ht, hegel.Binary(16, 64)), hegel.Draw(ht, hegel.Binary(16, 64))
	// an ML-KEM shared secret is 32 octets
	for range hegel.Draw(ht, pbt.Spanning(0, addkeTypes)) {
		in.additional = append(in.additional, hegel.Draw(ht, hegel.Binary(32, 32)))
	}
	return in
}

// the chained secrets of RFC 9370 section 2.2.4, SK(0) | Ni | Nr | SK(1) | ... SK(n)
func (in rekeyKeyInputs) chained() []byte {
	return concat(slices.Concat([][]byte{in.shared, in.ni, in.nr}, in.additional)...)
}

// the keys of an IKE SA rekey with additional key exchanges equal the chain RFC 9370 and RFC 7296 give, computed with crypto/hmac
// RFC 9370 section 2.2.4: "SKEYSEED = prf(SK_d, SK(0) | Ni | Nr | SK(1) | ... SK(n))"
// RFC 7296 section 2.18: "SK_d, SK_ai, SK_ar, SK_ei, and SK_er are computed from SKEYSEED as specified in Section 2.14, using SPIi, SPIr, Ni, and Nr from the new exchange, and using the new IKE SA's PRF."
func TestRekeyedIKEKeysFollowTheChainOfRFC9370(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		in := drawnRekeyKeyInputs(ht)
		suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: hegel.Draw(ht, hegel.SampledFrom([]uint16{128, 256})), PRFID: in.prfID}
		spiI, spiR := hegel.Draw(ht, hegel.Integers[uint64](1, 1<<63)), hegel.Draw(ht, hegel.Integers[uint64](1, 1<<63))
		keys, err := DeriveRekeyedIKEKeys(in.prfID, in.skD, suite, in.shared, in.ni, in.nr, spiI, spiR, in.additional...)
		if err != nil {
			ht.Fatal(err)
		}
		mac := hmac.New(in.newHash, in.skD)
		mac.Write(in.chained())
		var spis [16]byte
		binary.BigEndian.PutUint64(spis[:8], spiI)
		binary.BigEndian.PutUint64(spis[8:], spiR)
		want := modelKeys(in.newHash, mac.Sum(nil), concat(in.ni, in.nr, spis[:]), int(suite.EncrKeyBits)/8+4)
		got := [5][]byte{keys.SKd, keys.SKei, keys.SKer, keys.SKpi, keys.SKpr}
		if !slices.EqualFunc(got[:], want[:], bytes.Equal) {
			ht.Fatalf("a rekey with %d additional key exchanges derived %x, the chain %x", len(in.additional), got, want)
		}
	})
}

// the KEYMAT of a Child SA made with additional key exchanges equals the chain RFC 9370 and RFC 7296 give, computed with crypto/hmac
// RFC 9370 section 2.2.4: "KEYMAT = prf+ (SK_d, SK(0) | Ni | Nr | SK(1) |  ... SK(n))"
// RFC 7296 section 2.17: "All keys for SAs carrying data from the initiator to the responder are taken before SAs going from the responder to the initiator."
func TestChildKeymatFollowsTheChainOfRFC9370(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		in := drawnRekeyKeyInputs(ht)
		encrID, bits := ENCR_AES_GCM_16, hegel.Draw(ht, hegel.SampledFrom([]uint16{128, 256}))
		each := int(bits)/8 + 4
		if hegel.Draw(ht, hegel.Booleans()) {
			encrID, bits, each = ENCR_CHACHA20_POLY1305, 256, 32+4
		}
		initiator, responder, err := childSAKeymat(in.prfID, in.skD, in.shared, in.ni, in.nr, encrID, bits, in.additional...)
		if err != nil {
			ht.Fatal(err)
		}
		want := modelPRFPlus(in.newHash, in.skD, in.chained(), 2*each)
		if !bytes.Equal(initiator, want[:each]) || !bytes.Equal(responder, want[each:]) {
			ht.Fatalf("a Child SA with %d additional key exchanges took %x and %x, the chain %x", len(in.additional), initiator, responder, want)
		}
	})
}
