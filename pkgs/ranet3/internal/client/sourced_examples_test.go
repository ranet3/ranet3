// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"path/filepath"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/config"
)

func TestSourcedShippedExamplesRemainInactive(t *testing.T) {
	for _, format := range []string{".toml", ".yaml", ".json"} {
		t.Run(format, func(t *testing.T) {
			cfg, err := config.Load(filepath.Join("..", "..", "examples", "config"+format))
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Cap.Table != nil {
				t.Fatalf("shipped example starts the kernel reconciler: %+v", cfg.Cap.Table)
			}
			if err := refuseExitModeHere(cfg); err != nil {
				t.Fatalf("shipped example refused on this platform: %v", err)
			}
		})
	}
}
