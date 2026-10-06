// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux

package netstack

// defaultTUNName is the device an empty link.tun opens, named after the program
// one fixed name rather than one the kernel numbers, only ever created and never attached to
const defaultTUNName = "ranet3"
