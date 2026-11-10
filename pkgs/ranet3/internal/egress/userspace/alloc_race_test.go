// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build race

package userspace

// raceBuild is whether the race detector runs, whose sync.Pool drops a
// quarter of what it is given, so a path that takes pooled storage allocates
// an average no test can hold exactly
const raceBuild = true
