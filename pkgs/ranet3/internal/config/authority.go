// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package config

import (
	"fmt"

	"ranet3.com/pkgs/ranet3/trust"
)

func (a Auth) validateAuthority() error {
	if len(a.Authority) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(a.Authority))
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
	return nil
}
