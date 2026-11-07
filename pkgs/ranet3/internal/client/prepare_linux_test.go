// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !android

package client

import "ranet3.com/pkgs/ranet3/internal/underlay"

// testPrepare readies a test hub's sockets as linux's daemon does, marked where the process may set the mark
func testPrepare() underlay.Prepare { return underlay.Marked() }
