// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package kernel

import "ranet3.com/pkgs/ranet3/schema"

// WakesAPass is wakesAPass for a test of the node's hooks, which live outside this package
var WakesAPass = wakesAPass

// DumpedDownSet is the down set of overlay a stop writes, as the kernel dumps it under DefaultProtocol
func DumpedDownSet(overlay []schema.Prefix) []DumpedRule { return dumpedDown(overlay, DefaultProtocol) }
