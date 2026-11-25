// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !linux || android

package kernel

import "net/netip"

func preflightSourcedStartup(t Table, _ []netip.Prefix, _ string) error {
	return RefuseSourced(t)
}
