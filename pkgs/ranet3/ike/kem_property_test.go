// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package ike

import (
	"bytes"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// a KE payload of an ML-KEM method reads back as the method and data it was built from, at the payload length of Table 1, the initiator's key and the responder's ciphertext alike
// half the time the data is a key Go drew or a ciphertext it encapsulated, which pins Go's sizes to the table
// draft-ietf-ipsecme-ikev2-mlkem-09 section 2.1 Table 1: "ML-KEM-768 | 1192 / 1096 | 36 | 1184 / 1088" and "ML-KEM-1024 | 1576 / 1576 | 37 | 1568 / 1568"
func TestMLKEMPayloadRoundTripsAtTheLengthsOfTable1(t *testing.T) {
	// payloadLengths is Table 1's Payload Length of each method, the initiator's then the responder's
	payloadLengths := map[uint16][2]int{ML_KEM_768: {1192, 1096}, ML_KEM_1024: {1576, 1576}}
	pbt.Check(t, func(ht *hegel.T) {
		method := kemMethods[hegel.Draw(ht, hegel.Integers(0, len(kemMethods)-1))]
		side := hegel.Draw(ht, pbt.Spanning(0, 1))
		size := kemSizes[method.id][side]
		data := hegel.Draw(ht, hegel.Binary(size, size))
		if hegel.Draw(ht, hegel.Booleans()) {
			pair, err := generateKEM(method.id)
			if err != nil {
				ht.Fatal(err)
			}
			data = pair.PublicBytes()
			if side == 1 {
				if _, data, err = encapsulateKEM(method.id, data); err != nil {
					ht.Fatal(err)
				}
			}
		}
		payload := encodePayloadChain([]RawPayload{{Type: PayloadKE, Body: EncodeKE(method.id, data)}})
		if want := payloadLengths[method.id][side]; len(payload) != want {
			ht.Fatalf("method %d's KE payload is %d octets, want %d", method.id, len(payload), want)
		}
		payloads, err := decodePayloadChain(PayloadKE, payload)
		if err != nil || len(payloads) != 1 {
			ht.Fatalf("the KE payload of method %d reads back as %+v, %v", method.id, payloads, err)
		}
		got, gotData, err := DecodeKE(payloads[0].Body)
		if err != nil || got != method.id || !bytes.Equal(gotData, data) {
			ht.Fatalf("method %d's KE payload reads back as method %d, %d octets, %v", method.id, got, len(gotData), err)
		}
	})
}
