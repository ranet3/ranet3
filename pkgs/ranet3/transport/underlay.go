// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package transport

import (
	"errors"
	"log/slog"
	"net/netip"
)

// Underlay is darwin's link.underlay. Bind decides how the reconciler there
// installs an exit's default, and is refused by name on a platform that has
// no meaning for it, rather than accepted and ignored.
type Underlay struct {
	// Bind installs an exit's default unscoped as its zero-free cover rather than scoped to the tun, darwin only
	Bind bool `yaml:"bind,omitempty" json:"bind,omitempty" toml:"bind,omitempty"`
}

// Runtime carries what the caller resolves at startup rather than writes in a
// file. It is separate from Underlay so the setting stays a value that a
// config file, a control plane and a test can each produce whole.
type Runtime struct {
	// Selection names the interface of every underlay datagram on darwin, and nil names none
	Selection Selection
	// Events records each fallback a send to a peer took, each socket
	// connected to one peer that opens or closes, and on darwin each interface
	// the selection names for an endpoint. Nil records nothing.
	Events func(kind string, attrs ...slog.Attr)
}

// UnderlayPath is the interface darwin's datagrams to one endpoint name, or the one holding their pin
type UnderlayPath struct {
	// Address is the endpoint's, its zone kept, which the selection answers the interface for
	Address netip.Addr
	// Pin is the interface holding the endpoint's pin, empty where the selection names it
	Pin string
}

// underlayPather is a bind that names the interface of each datagram, darwin's
type underlayPather interface {
	underlayPath(Endpoint) (UnderlayPath, bool)
}

// SendsBy is the interface the hub's datagrams to endpoint name, or the one holding their pin, false on a hub that names no interface
func (h *Hub) SendsBy(endpoint Endpoint) (UnderlayPath, bool) {
	if bind, ok := h.bind.(underlayPather); ok {
		return bind.underlayPath(endpoint)
	}
	return UnderlayPath{}, false
}

// Selection answers which interface the host's own routes send a datagram by,
// the routes of ranet3's own interface left out, as a lookup carrying linux's
// underlay mark ends past them. internal/kernel implements it on darwin.
type Selection interface {
	// Interface is the index of the interface a datagram to addr names, zero where no route holds it,
	// and the generation the answer comes from
	Interface(addr netip.Addr) (index int, generation uint64)
	// Generation moves on whenever an answer may have changed
	Generation() uint64
}

// refuse reports why this platform cannot apply u, or nil. A setting that
// means nothing here is refused by name rather than accepted and ignored.
func (u Underlay) refuse() error {
	if u.Bind && !takesBind {
		return errors.New("link.underlay.bind decides how macOS installs an exit's default and is set on no other platform")
	}
	return nil
}
