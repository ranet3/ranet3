// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !linux && !darwin

package netstack

// defaultTUNName is empty so the platform backend picks its own name.
const defaultTUNName = ""
