// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !linux

package netstack

import (
	"fmt"
	"runtime"

	"ranet3.com/pkgs/wireguard/tun"
)

// NewEgressDevice refuses the egress device by name where the kernel cannot
// forward out of it, rather than make a tun whose packets nothing routes
func NewEgressDevice(string, int) (tun.Device, error) {
	return nil, fmt.Errorf("netstack: the egress device is a linux tun the kernel forwards from, which %s does not have", runtime.GOOS)
}
