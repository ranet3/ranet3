// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !linux

package netstack

// tunQueueBytes is the bytes one queue of the tun holds of its own, none on a platform whose tun reads one packet at a time with no GRO table
const tunQueueBytes = 0
