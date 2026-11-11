// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package egresstest

import (
	"fmt"
	"os"
	"testing"
)

// the network's leaf gives its sockets ports of the suite's range alone
func TestLeafGivesPortsOfTheSuitesRange(t *testing.T) {
	var low, high int
	if err := Namespaces(t).Leaf(func() error {
		read, err := os.ReadFile(localPortRange)
		if err != nil {
			return err
		}
		_, err = fmt.Sscan(string(read), &low, &high)
		return err
	}); err != nil {
		t.Fatalf("read the leaf's %s: %v", localPortRange, err)
	}
	if low != leafEphemeralLow || high != leafEphemeralHigh {
		t.Errorf("the leaf gives ports of %d to %d, want %d to %d", low, high, leafEphemeralLow, leafEphemeralHigh)
	}
}
