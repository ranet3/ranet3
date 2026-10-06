// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import "testing"

// darwin's utun control creates utun, its next free unit, and utun followed by a unit number
// it is sent that number plus one in 32 bits
// and a unit past that would wrap to another one
// any other name fails when the device is made
func TestUTUNNamesAreUTUNAndAUnitNumber(t *testing.T) {
	for _, name := range []string{"utun", "utun0", "utun7", "utun10", "utun4294967294"} {
		if !isUTUNName(name) {
			t.Errorf("%q was refused, and darwin creates it", name)
		}
	}
	for _, name := range []string{
		"", "ranet3", "tun0", "utu", "Utun0", "xutun0",
		"utun-1", "utun+1", "utun 1", "utun1 ", "utunx", "utun1x", "utun0x1", "utun1_0",
		"utun4294967295", "utun18446744073709551617",
	} {
		if isUTUNName(name) {
			t.Errorf("%q was taken, and darwin's utun control cannot create it", name)
		}
	}
}
