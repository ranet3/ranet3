// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package userspace

import (
	"net/netip"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// for any sequence of dials' sockets bound and released, for three leaf
// endpoints on two ports, each dial drawing either loopback address as the
// one it leaves from, its class's or its route's, each socket is bound on its
// mapping's outside endpoint, on the address it was drawn, every socket of one
// inside endpoint on one address on one endpoint (RFC 5382 REQ-1), no two
// sockets of two inside endpoints on one endpoint, though they may share a
// port on two addresses (REQ-7), and the table holds a mapping for each inside
// endpoint and address a socket is bound for and for nothing else
func TestMappingsKeepOneEndpointForEachInsideEndpointAndShareNone(t *testing.T) {
	addresses := loopbacks(t)
	port := freeTCPPort(t, addresses[0])
	leaves := []netip.AddrPort{netip.AddrPortFrom(leaf4, port), netip.AddrPortFrom(other4, port), netip.AddrPortFrom(leaf4, freeTCPPort(t, addresses[0]))}
	pbt.Check(t, func(ht *hegel.T) {
		var mappings tcpMappings
		var sockets []boundSocket
		defer func() {
			for _, s := range sockets {
				_ = unix.Close(s.fd)
			}
		}()
		for range hegel.Draw(ht, hegel.Integers(1, 16)) {
			if len(sockets) > 0 && hegel.Draw(ht, hegel.Booleans()) {
				i := hegel.Draw(ht, hegel.Integers(0, len(sockets)-1))
				_ = unix.Close(sockets[i].fd)
				mappings.release(sockets[i].mapping)
				sockets = slices.Delete(sockets, i, i+1)
			} else {
				inside := tcpInside{leaves[hegel.Draw(ht, hegel.Integers(0, len(leaves)-1))], addresses[hegel.Draw(ht, hegel.Integers(0, len(addresses)-1))]}
				fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
				if err != nil {
					ht.Fatal(err)
				}
				m, err := mappings.bind(fd, inside)
				if err != nil {
					_ = unix.Close(fd)
					ht.Fatalf("bind a socket for %s on %s: %v", inside.leaf, inside.address, err)
				}
				sockets = append(sockets, boundSocket{fd, inside, m})
			}
			holdsMappings(ht, &mappings, sockets)
		}
	})
}

// loopbacks is the IPv4 loopback addresses a socket here binds, 127.0.0.1 and,
// where the host holds it, as Linux does, 127.0.0.2
func loopbacks(t *testing.T) []netip.Addr {
	t.Helper()
	addresses := []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	second := netip.MustParseAddr("127.0.0.2")
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if unix.Bind(fd, sockaddrOf(netip.AddrPortFrom(second, 0))) == nil {
		addresses = append(addresses, second)
	}
	return addresses
}

// boundSocket is a socket the table bound for inside, and its mapping
type boundSocket struct {
	fd      int
	inside  tcpInside
	mapping *tcpMapping
}

// holdsMappings fails ht unless sockets hold the property's invariants
func holdsMappings(ht *hegel.T, mappings *tcpMappings, sockets []boundSocket) {
	bound := make([]netip.AddrPort, len(sockets))
	for i, s := range sockets {
		at, err := unix.Getsockname(s.fd)
		if err != nil {
			ht.Fatal(err)
		}
		if bound[i] = sockaddrPort(at); bound[i] != s.mapping.outside || bound[i].Addr() != s.inside.address {
			ht.Fatalf("a socket for %s on %s is bound on %s, its mapping's %s", s.inside.leaf, s.inside.address, bound[i], s.mapping.outside)
		}
	}
	held := map[tcpInside]bool{}
	for i, a := range sockets {
		held[a.inside] = true
		for j, b := range sockets[i+1:] {
			switch {
			case a.inside == b.inside && bound[i] != bound[i+1+j]:
				ht.Fatalf("two sockets for %s on %s are bound on %s and %s", a.inside.leaf, a.inside.address, bound[i], bound[i+1+j])
			case a.inside != b.inside && bound[i] == bound[i+1+j]:
				ht.Fatalf("sockets for %s on %s and for %s on %s are both bound on %s", a.inside.leaf, a.inside.address, b.inside.leaf, b.inside.address, bound[i])
			}
		}
	}
	mappings.mu.Lock()
	defer mappings.mu.Unlock()
	if len(mappings.byInside) != len(held) || len(mappings.byOutside) != len(held) {
		ht.Fatalf("the table holds %d mappings by inside endpoint and %d by outside endpoint, want the %d inside endpoints and addresses a socket is bound for", len(mappings.byInside), len(mappings.byOutside), len(held))
	}
}
