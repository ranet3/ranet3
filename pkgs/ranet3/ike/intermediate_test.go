// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package ike

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"testing"
)

// IntAuth chains each exchange's chunks under that exchange's SK_p onto the last, and IKE_AUTH appends both ends' results and its Message ID in four octets in network order
// with no IKE_INTERMEDIATE exchange it appends nothing
// RFC 9242 section 3.3.2: "IntAuth_i2 = prf(SK_pi2, IntAuth_i1 | IntAuth_i2A [| IntAuth_i2P])" and "IntAuth_r2 = prf(SK_pr2, IntAuth_r1 | IntAuth_r2A [| IntAuth_r2P])"
// RFC 9242 section 3.3.2: "IntAuth =  IntAuth_iN | IntAuth_rN | IKE_AUTH_MID"
func TestIntAuthChainsEveryExchangeAndEndsInTheAuthMessageID(t *testing.T) {
	var none intAuth
	if got := none.octets(1); got != nil {
		t.Errorf("IKE_AUTH with no IKE_INTERMEDIATE before it appends %x", got)
	}
	prf := func(key, data []byte) []byte {
		mac := hmac.New(sha256.New, key)
		mac.Write(data)
		return mac.Sum(nil)
	}
	keys := [][2][]byte{{[]byte("pi1"), []byte("pr1")}, {[]byte("pi2"), []byte("pr2")}}
	chunks := [][2][]byte{{[]byte("request 1"), []byte("response 1")}, {[]byte("request 2"), []byte("response 2")}}
	var chain intAuth
	var i, r []byte
	for n := range chunks {
		chain = chain.add(PRF_HMAC_SHA2_256, keys[n][0], keys[n][1], chunks[n][0], chunks[n][1])
		i, r = prf(keys[n][0], concat(i, chunks[n][0])), prf(keys[n][1], concat(r, chunks[n][1]))
	}
	want := concat(i, r, []byte{0, 0, 0, 3})
	if got := chain.octets(3); !bytes.Equal(got, want) {
		t.Errorf("IntAuth after two exchanges is %x, want %x", got, want)
	}
}
