// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !linux && !darwin

package transport

import (
	"strings"
	"testing"
)

// bind decides how darwin installs an exit's default. A platform without that
// choice must refuse the configuration rather than ignore it, because a
// setting that never takes effect is worse than an error at startup.
func TestUnderlayIsolationIsRefusedWhereItCannotBeSet(t *testing.T) {
	for name, underlay := range map[string]Underlay{
		"bind": {Bind: true},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := NewHub(":0", underlay, Runtime{})
			if err == nil {
				t.Fatal("a setting this platform cannot apply was accepted")
			}
			// Wrapped once by NewHub, so the reason has to survive without
			// repeating the package name an operator already sees.
			if got := err.Error(); strings.Count(got, "transport:") != 1 {
				t.Errorf("the refusal reads %q", got)
			}
		})
	}
	hub, err := NewHub(":0", Underlay{}, Runtime{})
	if err != nil {
		t.Fatalf("a hub asking for neither was refused: %v", err)
	}
	_ = hub.Close()
}
