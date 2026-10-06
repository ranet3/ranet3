// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin

package netstack

// defaultTUNName asks the utun control for its next free unit
const defaultTUNName = utunName

// utunNamesOnly holds link.tun to the names the utun control creates
const utunNamesOnly = true
