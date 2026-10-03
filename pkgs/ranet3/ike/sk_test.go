// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package ike

import "testing"

// A payload sent in the clear ahead of SK is followed by SK, so its Next
// Payload names SK, RFC 7296 section 3.2. Written as zero, it ended the chain
// there and left SK behind it as trailing bytes, which DecodeMessage refuses,
// as a peer would.
func TestCleartextPayloadsAheadOfSKLeadToIt(t *testing.T) {
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128}
	key := make([]byte, 16+4)
	notify := RawPayload{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_INITIAL_CONTACT})}
	for _, test := range []struct {
		name             string
		cleartext, inner []RawPayload
	}{
		{"one payload and nothing inside", []RawPayload{{Type: 1}}, nil},
		{"two payloads and a notify inside", []RawPayload{{Type: PayloadV, Body: []byte("vendor")}, notify}, []RawPayload{notify}},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw, err := encryptMessageIV(suite, key, Header{}, test.cleartext, test.inner, make([]byte, 8))
			if err != nil {
				t.Fatal(err)
			}
			m, err := DecodeMessage(raw)
			if err != nil {
				t.Fatalf("a message with %d payloads ahead of SK does not read back: %v", len(test.cleartext), err)
			}
			if len(m.Payloads) != len(test.cleartext)+1 || m.Payloads[len(test.cleartext)].Type != PayloadSK {
				t.Fatalf("the message read back as %+v, want the %d payloads ahead of SK and then SK", m.Payloads, len(test.cleartext))
			}
			inner, err := DecryptMessage(suite, key, raw, m)
			if err != nil {
				t.Fatalf("SK does not decrypt behind %d payloads in the clear: %v", len(test.cleartext), err)
			}
			if len(inner) != len(test.inner) {
				t.Fatalf("SK held %+v, want %+v", inner, test.inner)
			}
		})
	}
}
