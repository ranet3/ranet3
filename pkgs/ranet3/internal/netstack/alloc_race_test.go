// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build race

package netstack

// cycleAllocations is the most a batch's cycle may allocate on average under the race detector
// whose sync.Pool drops a quarter of what it is given, so a cycle now and then takes a new batch or new storage
const cycleAllocations = 1
