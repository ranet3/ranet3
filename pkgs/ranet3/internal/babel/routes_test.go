// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package babel

import (
	"net/netip"
	"testing"

	"ranet3.com/pkgs/ranet3/schema"
)

// An announcement carries a prefix and may carry a source. One with no prefix
// has no spelling, and neither has a prefix that is set and is not one, an
// address under a length it cannot carry, so no file can carry any of the
// three below. Validate passed all three. The speaker announced nothing for
// the first two and, for the third, the destination alone, offering every
// source the default route that was meant for one.
func TestValidateRefusesAnAnnouncementWithNoSpelling(t *testing.T) {
	notOne := schema.PrefixFrom(netip.PrefixFrom(netip.MustParseAddr("0.0.0.0"), 33))
	for name, announce := range map[string]schema.Announce{
		"no prefix":                {},
		"a prefix that is not one": {Prefix: notOne},
		"a source that is not one": {Prefix: schema.MustPrefix("::/0"), From: notOne},
	} {
		t.Run(name, func(t *testing.T) {
			if err := (Routes{Announce: []schema.Announce{announce}}).Validate(); err == nil {
				t.Errorf("%s was accepted", name)
			}
		})
	}
	// a source nobody wrote is still left out
	routes := Routes{Announce: []schema.Announce{
		{Prefix: schema.MustPrefix("2001:db8::/48")},
		{Prefix: schema.MustPrefix("::/0"), From: schema.MustPrefix("2001:db8::/48")},
	}}
	if err := routes.Validate(); err != nil {
		t.Errorf("announcements with and without a source were refused: %v", err)
	}
}
