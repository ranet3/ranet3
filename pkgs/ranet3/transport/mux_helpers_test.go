// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package transport

import (
	"net"
	"testing"
)

// dial is a mux to remoteIP and remotePort on a hub of its own at an ephemeral port, the hub closed when the test ends
func dial(t *testing.T, remoteIP net.IP, remotePort int) *Mux {
	t.Helper()
	hub, err := NewHub(":0", Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	m, err := hub.NewMux(remoteIP, remotePort)
	if err != nil {
		t.Fatal(err)
	}
	return m
}
