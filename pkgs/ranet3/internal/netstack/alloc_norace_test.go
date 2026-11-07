// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !race

package netstack

// cycleAllocations is the most a batch's cycle may allocate on average, nothing once the pools hold what it needs
const cycleAllocations = 0
