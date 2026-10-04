// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !linux && !darwin

package control

import "net"

// peerCred reports nothing on a platform this tree reads no peer credentials on
// every root class debug path is refused there
func peerCred(*net.UnixConn) (Caller, bool) { return Caller{}, false }
