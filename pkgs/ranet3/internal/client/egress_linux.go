// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package client

// carriesEgress is whether this build carries other nodes' traffic out of the mesh through cap.egress: the kernel exit, through the tun and nftables
const carriesEgress = true
