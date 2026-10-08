// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux

package netstack

// maxTUNQueues is the most queues the kernel attaches to one tun, MAX_TAP_QUEUES in drivers/net/tun.c
// it refuses the next with E2BIG, so a host with more cores than this shares the queues it has
const maxTUNQueues = 256
