// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package babel

import "testing"

// A file spells a link quality as etx or none and nothing else. Any other
// value passed Validate, and then the speaker ran it as none while the
// marshaller wrote it as etx, so the file a node renders describes another
// speaker than the one it runs.
func TestValidateRefusesALinkQualityWithNoSpelling(t *testing.T) {
	for _, quality := range []LinkQuality{LinkQualityETX, LinkQualityNone} {
		if err := (Config{Quality: quality}).Validate(); err != nil {
			t.Errorf("quality %s was refused: %v", quality, err)
		}
	}
	for _, quality := range []LinkQuality{2, 255} {
		if err := (Config{Quality: quality}).Validate(); err == nil {
			t.Errorf("quality %d was accepted", quality)
		}
	}
}
