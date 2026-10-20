// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

package netstack

import (
	"fmt"
	"net/netip"
	"sort"

	"ranet3.com/pkgs/ranet3/sadr"
)

// RouteTable adds peer diagnostics to the shared SADR implementation. The
// forwarding trie is the sole source of truth for lookup, removal and dumps.
type RouteTable struct {
	table   sadr.Table[*Peer]
	changed chan struct{}
}

func NewRouteTable() *RouteTable { return &RouteTable{changed: make(chan struct{}, 1)} }

// Unreachable is installed for a prefix that is known and has no usable route.
// A lookup that lands on it is answered rather than falling through to a
// covering entry, as RFC 8966 section 3.5.4 requires while a retracted prefix
// is still held: "packets destined to an address within P MUST NOT be
// forwarded by following a route for a shorter prefix". It is a sentinel
// rather than a usable Peer: its budgets have no room, so a send through it is
// refused and counted in its Dropped. Resolve answers it as RouteHeld, and
// Snapshot hands it out as a value a caller has to recognize, as the doc there
// says.
var Unreachable = &Peer{ID: "unreachable"}

// Local is installed for a prefix this node originates.
var Local = &Peer{ID: "this node"}

// Assigned is installed for an address cap.table assigns this node and nothing
// originates, which the kernel mirror leaves out, since the host already
// delivers an address it carries.
var Assigned = &Peer{ID: "this node"}

// Verdict is the table's answer for a packet.
type Verdict uint8

const (
	RouteNone Verdict = iota
	RoutePeer
	RouteLocal
	RouteHeld
)

// Changed carries one coalesced notification per batch of forwarding table
// changes, so a mirror outside this process reconciles from Snapshot rather
// than from an event stream it could fall behind on. A writer never blocks on
// it, so a reader that misses a wake still sees the change on the next one.
func (rt *RouteTable) Changed() <-chan struct{} { return rt.changed }

// Snapshot is one consistent view of the forwarding table. The underlying
// trie publishes immutable roots, so this is safe to call from any goroutine.
//
// The unreachable holds are included, carrying the Unreachable sentinel as
// their value. They exist to stop a packet for a retracted prefix following a
// shorter one instead, and a mirror of this table has to hold them for the
// same reason rather than letting its own longest-prefix match fall through.
// This node's own entries are included too, carrying Local or Assigned. No
// sentinel is a Peer that can be sent through, so a caller walking these has
// to recognize each before treating one as a destination.
func (rt *RouteTable) Snapshot() []sadr.Route[*Peer] {
	var out []sadr.Route[*Peer]
	for route := range rt.table.All() {
		out = append(out, route)
	}
	return out
}

func (rt *RouteTable) notify() {
	if rt.changed == nil {
		return
	}
	select {
	case rt.changed <- struct{}{}:
	default:
	}
}

func (rt *RouteTable) Set(src, dst netip.Prefix, peer *Peer) {
	rt.table.Set(src, dst, peer)
	rt.notify()
}

func (rt *RouteTable) Remove(src, dst netip.Prefix) {
	rt.table.Remove(src, dst)
	rt.notify()
}

func (rt *RouteTable) RemovePeer(peer *Peer) {
	rt.table.RemoveValue(peer)
	rt.notify()
}

// Resolve answers a packet from src to dst with the entry RFC 9079 section 4
// prefers among those that match it, by "destination-first ordering, where
// routing table entry R1 is preferred to routing table entry R2 when either
// R1's destination prefix is more specific than R2's or the destination
// prefixes are equal and R1's source prefix is more specific than R2's". An
// entry holding Unreachable answers RouteHeld, so no covering entry is
// consulted for a packet inside it. The peer is nil for every verdict but
// RoutePeer.
func (rt *RouteTable) Resolve(src, dst netip.Addr) (*Peer, Verdict) {
	peer, ok := rt.table.Lookup(src, dst)
	switch {
	case !ok:
		return nil, RouteNone
	case peer == Unreachable:
		return nil, RouteHeld
	case peer == Local || peer == Assigned:
		return nil, RouteLocal
	}
	return peer, RoutePeer
}

func (rt *RouteTable) Debug() []string {
	var out []string
	for route := range rt.table.All() {
		if route.Source.IsValid() {
			out = append(out, fmt.Sprintf("%s from %s via %s", route.Destination, route.Source, route.Value.ID))
		} else {
			out = append(out, fmt.Sprintf("%s via %s", route.Destination, route.Value.ID))
		}
	}
	sort.Strings(out)
	return out
}
