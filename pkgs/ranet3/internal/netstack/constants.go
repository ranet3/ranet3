// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import "time"

// truncatedReadInterval is the least time between two warnings about tun reads cut short
// the counter keeps the exact count, and the line only has to point at it
const truncatedReadInterval = 30 * time.Second
