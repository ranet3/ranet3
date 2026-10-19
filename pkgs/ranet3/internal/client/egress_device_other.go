// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !linux

package client

// egressDeviceReader passes everything, since New refuses an egress device off linux
func egressDeviceReader(string) func() (v4, v6 error) {
	return func() (v4, v6 error) { return nil, nil }
}
