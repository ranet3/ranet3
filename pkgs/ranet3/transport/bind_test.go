// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package transport

import (
	"errors"
	"net"
	"syscall"
	"testing"
)

// A daemon that cannot bind its configured port must refuse to start rather
// than take another one. strongSwan's charon does the opposite: asked for a
// port already held, it binds an ephemeral one and runs, so every unit reports
// active while nothing reaches it. That cost a fleet node twenty minutes on
// 2026-09-22, and the failure was invisible to systemctl.
func TestHubRefusesAPortSomethingElseHolds(t *testing.T) {
	held, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	addr := held.LocalAddr().(*net.UDPAddr)

	hub, err := NewHub(addr.String(), Underlay{}, Runtime{})
	if err == nil {
		hub.Close()
		t.Fatalf("the hub took %s while another socket held it", addr)
	}
	// every refusal of the bind reads "open bind"
	// and only the errno tells the held port from another cause
	if !errors.Is(err, syscall.EADDRINUSE) {
		t.Errorf("the refusal reads %q, which is not the port being in use", err)
	}
}
