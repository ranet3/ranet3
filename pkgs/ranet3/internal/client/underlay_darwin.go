// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package client

import (
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/transport"
)

// underlayRuntime opens the selection the hub names each underlay datagram's
// interface from. Under link.underlay.bind the same selection answers whether
// the host holds a default of its own in each family, which a cover waits for.
//
// mesh is this node's own tun, which no selection may answer with. host is
// the machine it reads, nil for the one this process is running on.
//
// The returned close is always safe to call.
func underlayRuntime(underlay transport.Underlay, mesh string, host kernel.Host) (transport.Runtime, kernel.CaptureRoutes, func(), error) {
	selection, err := kernel.OpenSelection(host, mesh)
	if err != nil {
		return transport.Runtime{}, nil, func() {}, err
	}
	rt := transport.Runtime{Selection: selection}
	close := func() { _ = selection.Close() }
	if !underlay.Bind {
		return rt, nil, close, nil
	}
	return rt, selection, close, nil
}
