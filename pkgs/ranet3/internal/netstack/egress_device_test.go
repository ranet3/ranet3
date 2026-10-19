// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"strings"
	"testing"
)

// the egress device is named after the mesh tun the file writes, linux's
// default for none on every platform, and a name the kernel would cut short or
// number itself is refused by what to change
func TestEgressDeviceIsNamedAfterTheMeshTUN(t *testing.T) {
	for tun, want := range map[string]string{
		"":               "ranet3e",
		"ranet0":         "ranet0e",
		"utun4":          "utun4e",
		"fourteen-bytes": "fourteen-bytese",
	} {
		if got, err := EgressName(tun); err != nil || got != want {
			t.Errorf("link.tun %q names the egress device %q (%v), want %q", tun, got, err, want)
		}
	}
	for tun, says := range map[string]string{
		"fifteen-bytes-x": `link.tun "fifteen-bytes-x" is 15 bytes, and the egress device is named link.tun plus e, which the kernel caps at 15 bytes: name the tun in 14 bytes or fewer`,
		"ranet%d":         `link.tun "ranet%d" is a template the kernel numbers`,
	} {
		if _, err := EgressName(tun); err == nil || !strings.Contains(err.Error(), says) {
			t.Errorf("link.tun %q was refused with %v, want %q", tun, err, says)
		}
	}
}
