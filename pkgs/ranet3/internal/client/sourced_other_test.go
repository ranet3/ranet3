// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !linux

package client

import (
	"runtime"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/schema"
)

func TestSourcedIsRefusedAtStartAndReload(t *testing.T) {
	setTable := func(cfg *config.Config) { cfg.Cap.Table = &kernel.Table{} }
	cfg, key, reg := runtimeFixture(t)
	setTable(cfg)
	if err := refuseExitModeHere(cfg); err != nil {
		t.Fatalf("absent key: %v", err)
	}
	platform := runtime.GOOS
	if platform == "darwin" {
		platform = "macOS"
	}
	want := "kernel: cap.table.sourced is refused on " + platform + ", where this build writes no policy rules"
	cfg.Cap.Table.Sourced = &kernel.Sourced{To: []schema.Prefix{schema.MustPrefix("2001:db8:ffff::/48")}, ID: 300}
	if err := validateRuntimeConfig(cfg, key, trust(t, reg)); err == nil || err.Error() != want {
		t.Fatalf("startup: %v", err)
	}

	c, path, reconciler, _ := reloadOf(t, setTable)
	next := *c.config()
	original := *next.Cap.Table
	original.Sourced = cfg.Cap.Table.Sourced
	next.Cap.Table = &original
	writeConfig(t, path, &next)
	if err := c.ReloadFrom(path); err == nil || err.Error() != want {
		t.Fatalf("reload: %v", err)
	}
	if len(reconciler.tables) != 0 || c.config().Cap.Table.Sourced != nil {
		t.Fatalf("refused reload reached reconciler: %+v", reconciler.tables)
	}
}
