// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux

package client

import (
	"testing"

	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/schema"
)

func TestSourcedPlatformCheckLinux(t *testing.T) {
	cfg := &config.Config{Cap: config.Caps{Table: &kernel.Table{Sourced: &kernel.Sourced{To: []schema.Prefix{schema.MustPrefix("2001:db8:ffff::/48")}}}}}
	if err := refuseExitModeHere(cfg); err != nil {
		t.Fatal(err)
	}
	cfg.Cap.Table.Sourced = nil
	if err := refuseExitModeHere(cfg); err != nil {
		t.Fatal(err)
	}
}
