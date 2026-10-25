// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !linux || android

package kernel

import (
	"runtime"
	"strings"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/schema"
)

// cap.border is refused by name where there is no nftables, rather than
// accepted with no chain behind it, since a node whose status read the
// border as written would carry forged mesh sources from its other links
func TestBorderIsRefusedOffLinux(t *testing.T) {
	f, err := NewBorderFilter(egress.Border{Overlay: []schema.Prefix{schema.MustPrefix("198.18.0.0/15")}}, egress.BorderRuntime{Inside: []string{"utun9", "lo0"}})
	want := "egress: cap.border is an nftables chain, which " + runtime.GOOS + " does not have"
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("NewBorderFilter returned %v, want a refusal containing %q", err, want)
	}
	if f != nil {
		t.Error("the refusal handed back a filter")
	}
}
