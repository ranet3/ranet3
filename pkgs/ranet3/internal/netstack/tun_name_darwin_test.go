// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin

package netstack

import (
	"os"
	"strings"
	"testing"
)

// darwin's utun control creates nothing but utun and utun followed by a unit number
// a link.tun naming anything else is refused before the control is asked, which needs no root
// wireguard-go alone would open utun5x as utun5 and turn utun4294967295 into the next free unit
// an empty link.tun passes only once the default lookup has run
// and every node leaving link.tun out depends on that order
// a name the control creates fails at the control without root
// and as root it opens a utun, which a run does here only with RANET3_DARWIN_NETTEST=1
func TestTUNNameIsRefusedOnlyWhereDarwinCannotCreateIt(t *testing.T) {
	for _, arm := range []struct {
		label, name string
		refused     bool
	}{
		{"ranet3", "ranet3", true},
		{"utun5x", "utun5x", true},
		{"utun4294967295", "utun4294967295", true},
		{"empty", "", false},
		{"utun7", "utun7", false},
	} {
		t.Run(arm.label, func(t *testing.T) {
			if !arm.refused && os.Geteuid() == 0 && os.Getenv("RANET3_DARWIN_NETTEST") != "1" {
				t.Skip("set RANET3_DARWIN_NETTEST=1 to let a run as root create a utun")
			}
			m, err := NewNamed(0, 0, arm.name)
			if err == nil {
				t.Logf("link.tun %q opened %s", arm.name, m.Name)
				m.Close()
			}
			refusal := err != nil && strings.Contains(err.Error(), "is a name darwin cannot create")
			switch {
			case arm.refused && err == nil:
				t.Errorf("link.tun %q opened %s, and darwin's utun control cannot create that name", arm.name, m.Name)
			case arm.refused && (!refusal || !strings.Contains(err.Error(), "link.tun") || !strings.Contains(err.Error(), arm.name)):
				t.Errorf("the refusal of %q reads %q, which does not name link.tun and the name", arm.name, err)
			case !arm.refused && refusal:
				t.Errorf("link.tun %q was refused, and darwin's utun control creates it: %v", arm.name, err)
			}
		})
	}
}
