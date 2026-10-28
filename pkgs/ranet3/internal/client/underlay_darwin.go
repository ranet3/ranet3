// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package client

import (
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/transport"
)

// underlayRuntime opens the selection the hub names each underlay datagram's
// interface from.
//
// mesh is this node's own tun, which no selection may answer with, and empty
// on a node without one. host is the machine it reads, nil for the one this
// process is running on.
//
// The returned close is always safe to call.
func underlayRuntime(mesh string, host kernel.Host) (transport.Runtime, func(), error) {
	selection, err := kernel.OpenSelection(host, mesh)
	if err != nil {
		return transport.Runtime{}, func() {}, err
	}
	return transport.Runtime{Selection: selection}, func() { _ = selection.Close() }, nil
}
