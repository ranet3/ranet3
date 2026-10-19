// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package egress

// notificationReadSize is the read buffer of the notification socket, above
// NLMSG_GOODSIZE, the most the kernel puts in one notification datagram
const notificationReadSize = 64 << 10
