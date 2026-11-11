// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !darwin || ios

package userspace

// prepareHostSocket readies nothing: only XNU refuses the linger of 0 on a
// socket shut both ways
func prepareHostSocket(int) error { return nil }
