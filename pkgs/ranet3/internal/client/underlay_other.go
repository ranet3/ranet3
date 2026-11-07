// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build (!linux && !darwin) || android || ios

package client

import (
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/underlay"
	"ranet3.com/pkgs/ranet3/transport"
)

// underlayRuntime opens nothing here and prepares no socket. These builds
// have no way of their own to keep a socket out of the mesh, so the hub names
// no interface. The host is taken and ignored, since nothing here reads a
// routing table, and the network watch gets no watcher.
func underlayRuntime(string, kernel.Host) (transport.Runtime, kernel.Watcher, func(), error) {
	return transport.Runtime{Prepare: underlay.Unchanged}, nil, func() {}, nil
}
