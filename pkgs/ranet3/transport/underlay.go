// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package transport

import (
	"log/slog"
	"net/netip"

	"ranet3.com/pkgs/ranet3/internal/underlay"
)

// Runtime carries what the caller resolves at startup rather than writes in a
// file.
type Runtime struct {
	// Prepare readies every socket the hub opens to stay out of the mesh, and
	// NewHub refuses a nil one
	Prepare underlay.Prepare
	// Selection names the interface of every underlay datagram on darwin, and nil names none
	Selection Selection
	// Events records each fallback a send to a peer took, each socket
	// connected to one peer that opens or closes, and on darwin each interface
	// the selection names for an endpoint. Nil records nothing.
	Events func(kind string, attrs ...slog.Attr)
}

// Selection answers which interface the host's own routes send a datagram by,
// the routes of ranet3's own interface left out, as a lookup carrying linux's
// underlay mark ends past them. internal/kernel implements it on darwin.
type Selection interface {
	// Interface is the index of the interface a datagram to addr names, zero where no route holds it,
	// and the generation the answer comes from
	Interface(addr netip.Addr) (index int, generation uint64)
	// Generation moves on whenever an answer may have changed, and whenever an address of the host may have moved between interfaces
	Generation() uint64
}
