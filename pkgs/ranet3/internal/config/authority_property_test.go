// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package config

import (
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/base64"
	"strings"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

func TestAuthorityConfigProperty(t *testing.T) {
	candidates := []struct {
		text  string
		valid bool
	}{
		{testAuthority, true},
		{authorityCurveText(t, elliptic.P256()), true},
		{authorityCurveText(t, elliptic.P384()), true},
		{authorityCurveText(t, elliptic.P521()), false},
		{authorityText(t, ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))), false},
		{strings.TrimSuffix(testAuthority, "="), false},
	}
	for _, candidate := range candidates[3:] {
		if err := (Auth{Authority: []string{candidate.text}}).validateTrustKeys(); err == nil {
			t.Fatalf("accepted unsupported or malformed authority key %q", candidate.text)
		}
	}
	pbt.Check(t, func(ht *hegel.T) {
		count := hegel.Draw(ht, pbt.Spanning(1, 5))
		keys := make([]string, 0, count)
		seen := make(map[string]bool, count)
		want := true
		for range count {
			choice := hegel.Draw(ht, pbt.Spanning(0, len(candidates)-1))
			candidate := candidates[choice]
			if !candidate.valid {
				want = false
			} else {
				der, err := base64.StdEncoding.DecodeString(candidate.text)
				if err != nil {
					ht.Fatal(err)
				}
				if seen[string(der)] {
					want = false
				}
				seen[string(der)] = true
			}
			keys = append(keys, candidate.text)
		}
		if err := (Auth{Authority: keys}).validateTrustKeys(); (err == nil) != want {
			ht.Fatalf("authority key list %v: %v, want valid %v", keys, err, want)
		}
	})
}
