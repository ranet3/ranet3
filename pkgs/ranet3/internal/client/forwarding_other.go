// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !linux && !darwin

package client

// forwardingEnabled cannot be answered on a platform with no implementation,
// and a warning this node cannot substantiate is worse than silence.
func forwardingEnabled() (v4, v6 bool) { return true, true }

// Sysctl reads no setting, since the paths the egress translator names are
// linux's and the translator refuses cap.egress here
func Sysctl(string) string { return "" }

// l3mdevAccept cannot be answered here either. See forwardingEnabled.
func l3mdevAccept() bool { return true }
