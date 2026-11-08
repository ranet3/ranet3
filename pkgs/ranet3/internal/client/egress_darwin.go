// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package client

// carriesEgress is whether this build carries other nodes' traffic out of the mesh through cap.egress: the userspace exit, from sockets of its own
const carriesEgress = true
