// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !linux || android

package kernel

import (
	"testing"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/schema"
)

// Where there is no backend the overlay loads and no filter comes back, with
// or without one, and nothing is refused, so status can say it is not enforced
func TestNoFilterRunsOffLinux(t *testing.T) {
	rt := egress.BorderRuntime{Tun: "utun9", Inside: []string{"utun9", "lo0"}}
	for _, cfg := range []*egress.Border{nil, {Overlay: []schema.Prefix{schema.MustPrefix("198.18.0.0/15")}}} {
		if f, err := NewBorderFilter(cfg, rt); f != nil || err != nil {
			t.Fatalf("NewBorderFilter with %+v returned %v and %v, want neither", cfg, f, err)
		}
	}
}
