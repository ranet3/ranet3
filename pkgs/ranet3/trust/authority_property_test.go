// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package trust

import (
	"crypto/ed25519"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

func TestAuthoritySmallOrderProperty(t *testing.T) {
	encodings := smallOrderEncodings(t)
	if len(encodings) != 14 {
		t.Fatalf("%d small-order encodings, want 14", len(encodings))
	}
	pbt.Check(t, func(ht *hegel.T) {
		at := hegel.Draw(ht, pbt.Spanning(0, len(encodings)-1))
		public := ed25519.PublicKey(encodings[at][:])
		if _, err := ParseAuthorityKey(authorityText(t, public)); err == nil {
			ht.Fatalf("accepted small-order key %x", public)
		}
	})
}
