// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !linux || android

package client

import (
	"runtime"
	"strings"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/schema"
)

// cap.exit is refused at the start and at a reload by its own message, naming the key and the platform, ahead of the border's
func TestExitModeIsRefusedHereAtTheStartAndAtReload(t *testing.T) {
	start := func(old *config.Config) {
		old.Cap.Table = &kernel.Table{}
		old.Cap.Border = &egress.Border{Overlay: []schema.Prefix{schema.MustPrefix("192.0.2.0/24"), schema.MustPrefix("3fff::/20")}}
	}
	cfg, privateKey, reg := runtimeFixture(t)
	start(cfg)
	cfg.Cap.Exit = &kernel.ExitMode{}
	err := validateRuntimeConfig(cfg, privateKey, trust(t, reg))
	for _, want := range []string{"cap.exit", runtime.GOOS} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("the start refused cap.exit with %v, which does not name %q", err, want)
		}
	}

	c, path, reconciler, _ := reloadOf(t, start)
	next := *c.config()
	next.Cap.Exit = &kernel.ExitMode{}
	writeConfig(t, path, &next)
	if err := c.ReloadFrom(path); err == nil || !strings.Contains(err.Error(), "cap.exit") || !strings.Contains(err.Error(), runtime.GOOS) {
		t.Errorf("a reload adding cap.exit was refused with %v", err)
	}
	if len(reconciler.tables) != 0 || c.config().Cap.Exit != nil {
		t.Errorf("a refused reload handed the reconciler %+v", reconciler.tables)
	}
}
