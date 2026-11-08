// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux

package netstack

// maxTUNQueues is the most queues the kernel attaches to one tun, MAX_TAP_QUEUES in drivers/net/tun.c
// it refuses the next with E2BIG, so a host with more cores than this shares the queues it has
const maxTUNQueues = 256

// tunQueueBytes is the bytes one queue of the tun holds of its own, wireguard-go's TCP and UDP GRO tables and its write vectors at conn.IdealBatchSize
// P8 measured 35850 kB of them over 16 queues
const tunQueueBytes = 2240 << 10
