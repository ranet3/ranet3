// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !linux || android

package main

import (
	"runtime"
	"strings"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/schema"
)

// The capability is refused by name where this build carries no exit, rather
// than accepted and quietly carrying nothing, since a node that came up as an
// exit and carried nothing would advertise itself and drop every flow that
// took it.
func TestUnsupportedPlatformRefusesTheCapabilityByName(t *testing.T) {
	cfg := &config.Config{}
	cfg.Cap.Egress = &egress.Egress{Advertise: []schema.Prefix{schema.MustPrefix("0.0.0.0/0")}}
	exit, err := newExit(cfg, nil, nil)
	if err == nil || exit != nil {
		t.Fatalf("newExit returned %v and %v, want no exit and a refusal", exit, err)
	}
	for _, want := range []string{"cap.egress", runtime.GOOS, "carries no exit"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal %q does not name %q", err, want)
		}
	}
}
