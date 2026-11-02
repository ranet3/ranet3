// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !linux && !darwin

package client

// forwardingEnabled reads no setting on a platform with no implementation, so neither family is known
func forwardingEnabled() (v4, v6 *bool) { return nil, nil }

// Sysctl reads no setting, since the paths the kernel exit names are linux's
// and this build carries no exit
func Sysctl(string) string { return "" }
