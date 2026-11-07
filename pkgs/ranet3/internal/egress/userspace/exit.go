// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

// Package userspace is the exit that carries other nodes' traffic out of the
// mesh with the host's ordinary sockets rather than the kernel's translation:
// it ends each leaf's TCP connection in gVisor's stack and dials the server
// itself, relays UDP and echo through sockets of its own, and sends what it
// answers back into the mesh through lanes of the outbound path. Each socket
// it opens passes the platform's Prepare, so none leaves inside the mesh, and
// it holds what it holds within limits its caller sizes from the process's
// memory.
package userspace
