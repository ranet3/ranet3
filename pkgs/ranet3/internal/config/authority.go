// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package config

import (
	"fmt"

	"ranet3.com/pkgs/ranet3/trust"
)

// RevokedKey holds canonical base64 DER authority SPKI text and its minimum recovery height.
type RevokedKey struct {
	Key    string `yaml:"key" json:"key" toml:"key"`
	Height uint64 `yaml:"height" json:"height" toml:"height"`
}

func (a Auth) validateTrustKeys() error {
	seen := make(map[string]struct{}, len(a.Authority)+len(a.Revoked))
	for i, text := range a.Authority {
		key, err := trust.ParseAuthorityKey(text)
		if err != nil {
			return fmt.Errorf("config: auth.authority[%d]: %w", i, err)
		}
		if _, duplicate := seen[string(key.DER)]; duplicate {
			return fmt.Errorf("config: auth.authority[%d] duplicates a public key", i)
		}
		seen[string(key.DER)] = struct{}{}
	}
	if len(a.Revoked) > 64 {
		return fmt.Errorf("config: auth.revoked has %d entries, at most 64 allowed", len(a.Revoked))
	}
	revoked := make(map[string]struct{}, len(a.Revoked))
	for i, entry := range a.Revoked {
		key, err := trust.ParseAuthorityKey(entry.Key)
		if err != nil {
			return fmt.Errorf("config: auth.revoked[%d].key: %w", i, err)
		}
		if entry.Height == 0 || entry.Height > trust.MaxHeight {
			return fmt.Errorf("config: auth.revoked[%d].height must be from 1 to %d", i, trust.MaxHeight)
		}
		der := string(key.DER)
		if _, duplicate := revoked[der]; duplicate {
			return fmt.Errorf("config: auth.revoked[%d] duplicates a public key", i)
		}
		if _, eligible := seen[der]; eligible {
			return fmt.Errorf("config: auth.revoked[%d] also lists an auth.authority key", i)
		}
		revoked[der] = struct{}{}
	}
	return nil
}
