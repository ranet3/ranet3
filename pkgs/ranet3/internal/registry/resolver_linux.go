// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package registry

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"syscall"

	"ranet3.com/pkgs/ranet3/internal/underlay"
	"ranet3.com/pkgs/ranet3/schema"
)

// PrefersGo is whether endpoint names are looked up through Go's own resolver
// whatever the build, and never through the C library
const PrefersGo = true

// resolverFor looks endpoint names up through Go's own resolver. prepare
// readies each socket of a query to a nameserver outside every prefix of the
// overlay, as the underlay's sockets are readied, and one to a nameserver inside
// the overlay goes as it is, whatever zone resolv.conf writes after its address.
// routing.md's "Where a lookup ends on Linux" gives where each query ends. A
// link-local nameserver lies outside every overlay the loader takes, so its
// query is readied.
func resolverFor(overlay []schema.Prefix, prepare underlay.Prepare) *net.Resolver {
	return &net.Resolver{PreferGo: PrefersGo, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		nameserver, err := netip.ParseAddrPort(address)
		if err != nil {
			return nil, fmt.Errorf("registry: nameserver %q: %w", address, err)
		}
		var dialer net.Dialer
		if marksQueryTo(nameserver.Addr(), overlay) {
			dialer.Control = func(network, _ string, raw syscall.RawConn) error { return prepare(network, nameserver, raw) }
		}
		return dialer.DialContext(ctx, network, address)
	}}
}

// marksQueryTo reports a nameserver lying outside every prefix of the overlay.
// Its zone is dropped first: a prefix contains no zoned address, and Linux
// routes by the zone only for a link-local destination, so a zoned nameserver
// inside the overlay goes unprepared as the same address with no zone does.
func marksQueryTo(nameserver netip.Addr, overlay []schema.Prefix) bool {
	nameserver = nameserver.Unmap().WithZone("")
	return !slices.ContainsFunc(overlay, func(entry schema.Prefix) bool { return entry.Contains(nameserver) })
}
