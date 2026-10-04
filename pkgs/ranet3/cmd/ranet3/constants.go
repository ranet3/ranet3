// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import "time"

const (
	// readTimeout bounds one debug read by default, the bound the control client puts on every read
	readTimeout = 10 * time.Second
)
