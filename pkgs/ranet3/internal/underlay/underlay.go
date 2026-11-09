// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

// Package underlay holds the one way each platform keeps a socket out of the
// mesh. The transport, the resolver and the exit take a [Prepare] from their
// caller, so a platform whose way only an app can supply hands the same one to
// each. The transport calls it on linux, android, darwin and ios, the resolver
// on linux and darwin alone, and the exit on darwin alone, the one build whose
// daemon runs the userspace exit.
package underlay

import (
	"net/netip"
	"syscall"
)

// Prepare readies raw, a socket of network toward to, to leave by the
// underlay and never by the mesh, before it binds or connects. to is the zero
// AddrPort for a socket that only receives, which Prepare still sees. Its
// error refuses the socket.
type Prepare func(network string, to netip.AddrPort, raw syscall.RawConn) error

// Unchanged leaves every socket as it is. It is the preparer of the builds
// that have no way of their own: the android and ios daemons, whose platform's
// way is an app's to supply, and the BSDs, whose bind takes no preparer.
func Unchanged(string, netip.AddrPort, syscall.RawConn) error { return nil }
