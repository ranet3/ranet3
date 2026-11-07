// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package client

import (
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/underlay"
	"ranet3.com/pkgs/ranet3/transport"
)

// underlayRuntime opens nothing here. linux keeps its underlay out of the
// mesh's routing with a socket mark and the policy rules that read it, which
// need no lookup of their own, so the hub names no interface. The host is
// taken and ignored, since nothing here reads a routing table, and the network
// watch gets no watcher, since linux's reads rtnetlink of its own.
func underlayRuntime(string, kernel.Host) (transport.Runtime, kernel.Watcher, func(), error) {
	return transport.Runtime{Prepare: underlay.Marked()}, nil, func() {}, nil
}
