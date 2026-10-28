// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !darwin || ios

package client

import (
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/transport"
)

// underlayRuntime opens nothing here. linux keeps its underlay out of the
// mesh's routing with a socket mark and the policy rules that read it, which
// need no lookup of their own, and an iOS build opens no selection, so its hub
// names no interface. The host is taken and ignored, since nothing here reads
// a routing table.
func underlayRuntime(string, kernel.Host) (transport.Runtime, func(), error) {
	return transport.Runtime{}, func() {}, nil
}
