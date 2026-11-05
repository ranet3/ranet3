// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build (!linux && !darwin) || android || ios

package kernel

// Loopback is the BSDs' and iOS's name of the loopback link, android's being lo
// no network watch runs here (platform_unsupported.go), so no link read here is compared with it
const Loopback = "lo0"
