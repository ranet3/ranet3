// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !linux

package netstack

import (
	"runtime"
	"strings"
	"testing"
)

// off linux the egress device is refused by name and by the platform, before
// anything is made, since nothing would route what it carries
func TestEgressDeviceIsRefusedOffLinux(t *testing.T) {
	dev, err := NewEgressDevice("ranet3e", DefaultMTU)
	if dev != nil || err == nil {
		t.Fatalf("NewEgressDevice made %v (%v) on %s", dev, err, runtime.GOOS)
	}
	if want := "the egress device is a linux tun the kernel forwards from, which " + runtime.GOOS + " does not have"; !strings.Contains(err.Error(), want) {
		t.Errorf("refused with %q, want %q", err, want)
	}
}
