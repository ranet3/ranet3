// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package registry

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"syscall"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/schema"
)

// PrefersGo is whether endpoint names are looked up through Go's own resolver
// whatever the build, and never through the C library
const PrefersGo = true

// resolverFor looks endpoint names up through Go's own resolver. A query to a
// nameserver outside every prefix of the overlay carries the underlay's mark
// where the process may set it, as markUnderlay says, as the underlay's
// datagrams do. One to a nameserver inside the overlay carries none, whatever
// zone resolv.conf writes after its address. routing.md's "Where a lookup ends
// on Linux" gives where each query ends. A link-local nameserver lies outside
// an overlay of the mesh's own prefixes, so its query is marked where the
// process may set the mark.
func resolverFor(overlay []schema.Prefix) *net.Resolver {
	return &net.Resolver{PreferGo: PrefersGo, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		nameserver, err := netip.ParseAddrPort(address)
		if err != nil {
			return nil, fmt.Errorf("registry: nameserver %q: %w", address, err)
		}
		var dialer net.Dialer
		if marksQueryTo(nameserver.Addr(), overlay) {
			dialer.Control = markUnderlay
		}
		return dialer.DialContext(ctx, network, address)
	}}
}

// marksQueryTo reports a nameserver lying outside every prefix of the overlay.
// Its zone is dropped first: a prefix contains no zoned address, and Linux
// routes by the zone only for a link-local destination, so a zoned nameserver
// inside the overlay goes unmarked as the same address with no zone does.
func marksQueryTo(nameserver netip.Addr, overlay []schema.Prefix) bool {
	nameserver = nameserver.Unmap().WithZone("")
	return !slices.ContainsFunc(overlay, func(entry schema.Prefix) bool { return entry.Contains(nameserver) })
}

// markUnderlay sets the underlay's mark on a socket before it connects. A
// process that may not set it, holding neither CAP_NET_ADMIN nor CAP_NET_RAW,
// writes no policy rule that reads it either, and its queries go unmarked.
func markUnderlay(_, _ string, raw syscall.RawConn) error {
	var setErr error
	if err := raw.Control(func(fd uintptr) {
		setErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(schema.UnderlayMark))
	}); err != nil {
		return err
	}
	if errors.Is(setErr, unix.EPERM) {
		return nil
	}
	return setErr
}
