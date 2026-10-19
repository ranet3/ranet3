// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-License-Identifier: MIT

//go:build !linux

package netstack

import "ranet3.com/pkgs/wireguard/tun"

// Keep the platform TUN backend's existing behavior outside Linux.
func bringTUNUp(string, uint16) error { return nil }

// darwin and the BSDs have one queue, so the count is ignored
// nothing reads the device's events, and a monitored device hands a failure of its route socket to Read
func createTUNQueues(name string, mtu, _ int) (tun.Device, string, error) {
	device, err := tun.CreateTUN(name, mtu, tun.Unmonitored())
	if err != nil {
		return nil, "", err
	}
	actualName, err := device.Name()
	if err != nil {
		_ = device.Close()
		return nil, "", err
	}
	return device, actualName, nil
}
