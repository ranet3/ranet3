// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !darwin || ios

package client

import (
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/transport"
)

// underlayRuntime has nothing to open here. linux keeps its underlay out of
// the mesh's routing with a socket mark and a policy rule, which needs neither
// a lookup nor a route of its own, and every other platform refuses both
// spellings by name in transport rather than opening a socket that
// does neither. The host is taken and ignored for the same reason: this
// platform reads no routing table of its own here.
func underlayRuntime(transport.Underlay, string, kernel.Host) (transport.Runtime, kernel.CaptureRoutes, func(), error) {
	return transport.Runtime{}, nil, func() {}, nil
}
