// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"testing"

	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/netstack"
)

// testClient is a client newClient built from runtimeFixture's configuration around a routes-only mesh, closed when the test ends
// a test may hand it a hub, a network watch or a mesh of its own, so the ones newClient opened close as well
func testClient(tb testing.TB) *Client {
	tb.Helper()
	cfg, privateKey, reg := runtimeFixture(tb)
	return buildTestClient(tb, cfg, privateKey, reg, netstack.NewRoutesOnly(), events.New())
}
