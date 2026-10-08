// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin

package netstack

import (
	"net"
	"os"
	"strings"
	"testing"
)

// a utun takes an MTU set after the mesh opened it, down and back up within the read buffers it opened with
// each value read back from the kernel through the standard library
// a mesh opened at the default refuses a move past its buffers and keeps its MTU
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
	t.Run("opened at 9000", func(t *testing.T) {
		m, err := NewNamed(jumbo, jumbo, "")
		if err != nil {
			t.Fatalf("open the mesh: %v", err)
		}
		t.Cleanup(m.Close)
		if got := held(t, m); got != jumbo {
			t.Fatalf("the kernel holds %d for %s opened at %d", got, m.Name, jumbo)
		}
		for _, mtu := range []int{DefaultMTU, jumbo} {
			if err := m.CheckMTU(mtu); err != nil {
				t.Fatalf("a move to %d on a mesh opened at %d was refused: %v", mtu, jumbo, err)
			}
			if err := m.SetMTU(mtu, nil); err != nil {
				t.Fatalf("set the mtu to %d: %v", mtu, err)
			}
			if got := held(t, m); got != mtu {
				t.Fatalf("the kernel holds %d for %s after it was set to %d", got, m.Name, mtu)
			}
		}
	})
	t.Run("opened at the default", func(t *testing.T) {
		m, err := NewNamed(0, 0, "")
		if err != nil {
			t.Fatalf("open the mesh: %v", err)
		}
		t.Cleanup(m.Close)
		err = m.CheckMTU(jumbo)
		if err == nil {
			t.Fatalf("a move to %d on a mesh whose read buffers hold %d was taken", jumbo, outboundPacketBufferSize)
		}
		for _, want := range []string{"9000", "2048", "restart to apply"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the refusal reads %q, which does not say %s", err, want)
			}
		}
		if got := held(t, m); got != DefaultMTU {
			t.Errorf("the kernel holds %d for %s, want the %d it opened at", got, m.Name, DefaultMTU)
		}
	})
}
