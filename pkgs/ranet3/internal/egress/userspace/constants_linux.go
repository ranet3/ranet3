// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package userspace

// sockExtendedErr is the size of Linux's struct sock_extended_err, the head
// of an IP_RECVERR message before the offender's address
const sockExtendedErr = 16
