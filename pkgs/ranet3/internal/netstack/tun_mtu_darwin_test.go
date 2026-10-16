// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin

package netstack

import (
	"fmt"
	"net"
	"os"
	"testing"
)

// a utun holds the MTU the mesh opened it at, and takes one set after the open, up or down, and back
// each value read back from the kernel through the standard library
// creating a utun needs root, which a run does here only with RANET3_DARWIN_NETTEST=1
func TestTUNTakesAnMTUSetAfterOpening(t *testing.T) {
	if os.Geteuid() != 0 || os.Getenv("RANET3_DARWIN_NETTEST") != "1" {
		t.Skip("set RANET3_DARWIN_NETTEST=1 and run as root to create a utun")
	}
	const jumbo = 9000
	held := func(t *testing.T, m *Mesh) int {
		t.Helper()
		link, err := net.InterfaceByName(m.Name)
		if err != nil {
			t.Fatalf("look up %s: %v", m.Name, err)
		}
		return link.MTU
	}
	for _, arm := range []struct{ opened, moved int }{{jumbo, DefaultMTU}, {DefaultMTU, jumbo}} {
		t.Run(fmt.Sprintf("opened at %d", arm.opened), func(t *testing.T) {
			m, err := NewNamed(arm.opened, "")
			if err != nil {
				t.Fatalf("open the mesh: %v", err)
			}
			t.Cleanup(m.Close)
			if got := held(t, m); got != arm.opened {
				t.Fatalf("the kernel holds %d for %s opened at %d", got, m.Name, arm.opened)
			}
			for _, mtu := range []int{arm.moved, arm.opened} {
				if err := m.CheckMTU(); err != nil {
					t.Fatalf("a move to %d on a mesh opened at %d was refused: %v", mtu, arm.opened, err)
				}
				if err := m.SetMTU(mtu, nil); err != nil {
					t.Fatalf("set the mtu to %d: %v", mtu, err)
				}
				if got := held(t, m); got != mtu {
					t.Fatalf("the kernel holds %d for %s after it was set to %d", got, m.Name, mtu)
				}
			}
		})
	}
}
