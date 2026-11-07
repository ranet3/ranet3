// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !linux || android

package client

import "ranet3.com/pkgs/ranet3/internal/underlay"

// testPrepare leaves a test hub's sockets as they are, as a hub with no selection would have them
func testPrepare() underlay.Prepare { return underlay.Unchanged }
