// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !darwin || ios

package transport

import (
	"strings"
	"testing"
)

// a platform with no reconciler that reads link.underlay.bind refuses the key by name, and takes an underlay without it
func TestBindIsRefusedByNameWhereNothingReadsIt(t *testing.T) {
	err := Underlay{Bind: true}.refuse()
	if err == nil || !strings.Contains(err.Error(), "link.underlay.bind") || !strings.Contains(err.Error(), "macOS") {
		t.Errorf("link.underlay.bind is refused with %v, want a refusal naming the key and macOS", err)
	}
	if err := (Underlay{}).refuse(); err != nil {
		t.Errorf("an underlay without bind is refused: %v", err)
	}
}
