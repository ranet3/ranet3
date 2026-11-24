// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package trust

import (
	"fmt"

	"golang.org/x/net/idna"
)

// A name is already in its wire spelling. IDNA processing only validates it.
var hostProfile = idna.New(
	idna.MapForLookup(),
	idna.VerifyDNSLength(true),
	idna.RemoveLeadingDots(false),
	idna.BidiRule(),
)

func hostName(name string) error {
	allNumeric := true
	for i := range len(name) {
		switch c := name[i]; {
		case c >= 'a' && c <= 'z', c == '-':
			allNumeric = false
		case c >= '0' && c <= '9', c == '.':
		default:
			return fmt.Errorf("trust: host name %q is not lowercase ASCII LDH", name)
		}
	}
	if allNumeric {
		return fmt.Errorf("trust: host name %q is all-numeric", name)
	}
	canonical, err := hostProfile.ToASCII(name)
	if err != nil || canonical != name {
		return fmt.Errorf("trust: host name %q is not an IDNA ASCII name: %v", name, err)
	}
	return nil
}
