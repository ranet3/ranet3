// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package config

import (
	"crypto/ed25519"
	"crypto/elliptic"
	"strings"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/trust"
)

func TestRevokedConfigurationProperty(t *testing.T) {
	distinct := make([]RevokedKey, 65)
	for i := range distinct {
		seed := make([]byte, ed25519.SeedSize)
		seed[0] = byte(i)
		distinct[i] = RevokedKey{Key: authorityText(t, ed25519.NewKeyFromSeed(seed).Public()), Height: 1}
	}
	pbt.Check(t, func(ht *hegel.T) {
		count := hegel.Draw(ht, pbt.Spanning(63, 65))
		if err := (Auth{Revoked: distinct[:count]}).validateTrustKeys(); (err == nil) != (count <= 64) {
			ht.Fatalf("%d distinct revoked keys: %v", count, err)
		}
	})
	valid := []string{testAuthority, authorityCurveText(t, elliptic.P256()), authorityCurveText(t, elliptic.P384())}
	invalid := []string{authorityCurveText(t, elliptic.P521()), authorityText(t, ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))), strings.TrimSuffix(testAuthority, "=")}
	pbt.Check(t, func(ht *hegel.T) {
		count := hegel.Draw(ht, pbt.Spanning(0, 4))
		keys := make([]RevokedKey, count)
		seen := make(map[string]bool, count)
		want := true
		for i := range keys {
			choice := hegel.Draw(ht, pbt.Spanning(0, len(valid)+len(invalid)-1))
			if choice < len(valid) {
				keys[i].Key = valid[choice]
				if seen[keys[i].Key] {
					want = false
				}
				seen[keys[i].Key] = true
			} else {
				keys[i].Key = invalid[choice-len(valid)]
				want = false
			}
			switch hegel.Draw(ht, pbt.Spanning(0, 3)) {
			case 0:
				keys[i].Height = 0
				want = false
			case 1:
				keys[i].Height = 1
			case 2:
				keys[i].Height = trust.MaxHeight
			case 3:
				keys[i].Height = trust.MaxHeight + 1
				want = false
			}
		}
		if count > 0 && hegel.Draw(ht, pbt.Spanning(0, 1)) == 1 {
			if seen[valid[0]] {
				want = false
			}
			if err := (Auth{Authority: []string{valid[0]}, Revoked: keys}).validateTrustKeys(); (err == nil) != want {
				ht.Fatalf("authority intersection %v, revoked %v: %v, want valid %v", valid[0], keys, err, want)
			}
		} else if err := (Auth{Revoked: keys}).validateTrustKeys(); (err == nil) != want {
			ht.Fatalf("revoked %v: %v, want valid %v", keys, err, want)
		}
	})
}
