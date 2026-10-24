// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

package netstack

import (
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"sync"
	"sync/atomic"

	"ranet3.com/pkgs/ranet3/sadr"
	"ranet3.com/pkgs/ranet3/schema"
)

// RouteTable adds peer diagnostics to the shared SADR implementation. The
// forwarding trie is the sole source of truth for lookup, removal and dumps.
type RouteTable struct {
	table   sadr.Table[routeEntry]
	changed chan struct{}
	// mu orders the writers, so each entry takes its flags from the overlay and the egress prefixes in force as it enters
	// and a change of either flags every entry again with no write lost between
	mu sync.Mutex
	// overlay is cap.border's overlay as written, nil without cap.border
	overlay []schema.Prefix
	// egress is the prefixes cap.egress advertises, masked
	egress []netip.Prefix
	// generation moves under mu once a write that can change a lookup's verdict or Counted flag is in the table
	// so an answer looked up after reading it holds until it moves, SetEgress changing neither
	generation atomic.Uint64
}

// routeEntry is one entry's value, with the flags Resolve answers beside its verdict
type routeEntry struct {
	peer *Peer
	// counted is an entry whose destination counts as a default with the overlay, schema.CapturesTheMachine
	counted bool
	// egress is this node's own entry for a prefix cap.egress advertises, with no source prefix
	egress bool
}

// flaggedLocked is peer's entry for src and dst, flagged under the overlay and the egress prefixes rt holds, with rt.mu held
func (rt *RouteTable) flaggedLocked(src, dst netip.Prefix, peer *Peer) routeEntry {
	return routeEntry{
		peer:    peer,
		counted: schema.CapturesTheMachine(dst, rt.overlay),
		egress:  peer == Local && !src.IsValid() && slices.Contains(rt.egress, dst.Masked()),
	}
}

// SetOverlay flags every entry again under cap.border's overlay as written, nil without cap.border
func (rt *RouteTable) SetOverlay(overlay []schema.Prefix) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.overlay = slices.Clone(overlay)
	rt.reflagLocked()
	rt.generation.Add(1)
}

// SetEgress flags every entry again under the prefixes cap.egress advertises
func (rt *RouteTable) SetEgress(advertised []netip.Prefix) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.egress = make([]netip.Prefix, len(advertised))
	for i, prefix := range advertised {
		rt.egress[i] = prefix.Masked()
	}
	rt.reflagLocked()
}

// reflagLocked writes again each entry whose flags the overlay or the egress prefixes now set otherwise, with rt.mu held
func (rt *RouteTable) reflagLocked() {
	for route := range rt.table.All() {
		if next := rt.flaggedLocked(route.Source, route.Destination, route.Value.peer); next != route.Value {
			rt.table.Set(route.Source, route.Destination, next)
		}
	}
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
// same reason rather than letting its own longest-prefix match fall through,
// but for a hold that counts as a default (schema.CapturesTheMachine): the
// kernel's mirror leaves that one to this table's lookup, the departure the
// protocol deviations page lists for RFC 8966 section 3.5.4.
// This node's own entries are included too, carrying Local or Assigned. No
// sentinel is a Peer that can be sent through, so a caller walking these has
// to recognize each before treating one as a destination.
func (rt *RouteTable) Snapshot() []sadr.Route[*Peer] {
	var out []sadr.Route[*Peer]
	for route := range rt.table.All() {
		out = append(out, sadr.Route[*Peer]{Source: route.Source, Destination: route.Destination, Value: route.Value.peer})
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
	rt.mu.Lock()
	rt.table.Set(src, dst, rt.flaggedLocked(src, dst, peer))
	rt.generation.Add(1)
	rt.mu.Unlock()
	rt.notify()
}

func (rt *RouteTable) Remove(src, dst netip.Prefix) {
	rt.mu.Lock()
	rt.table.Remove(src, dst)
	rt.generation.Add(1)
	rt.mu.Unlock()
	rt.notify()
}

func (rt *RouteTable) RemovePeer(peer *Peer) {
	rt.mu.Lock()
	rt.table.RemoveFunc(func(entry routeEntry) bool { return entry.peer == peer })
	rt.generation.Add(1)
	rt.mu.Unlock()
	rt.notify()
}

// Match is the entry Resolve matched, beside its verdict
type Match struct {
	// Bits is the length of the entry's destination prefix in the bits of the destination's own family, zero when no entry matched
	Bits int
	// Counted is an entry whose destination counts as a default with cap.border's overlay, schema.CapturesTheMachine
	// every entry covering such an entry's destination counts too, so a lookup passing over it finds none
	Counted bool
	// Egress is this node's own entry for a prefix cap.egress advertises
	Egress bool
}

// Resolve answers a packet from src to dst with the entry RFC 9079 section 4
// prefers among those that match it, by "destination-first ordering, where
// routing table entry R1 is preferred to routing table entry R2 when either
// R1's destination prefix is more specific than R2's or the destination
// prefixes are equal and R1's source prefix is more specific than R2's". An
// entry holding Unreachable answers RouteHeld, so no covering entry is
// consulted for a packet inside it. The peer is nil for every verdict but
// RoutePeer.
func (rt *RouteTable) Resolve(src, dst netip.Addr) (*Peer, Verdict, Match) {
	entry, bits, ok := rt.table.LookupBits(src, dst)
	match := Match{Bits: bits, Counted: entry.counted, Egress: entry.egress}
	switch {
	case !ok:
		return nil, RouteNone, match
	case entry.peer == Unreachable:
		return nil, RouteHeld, match
	case entry.peer == Local || entry.peer == Assigned:
		return nil, RouteLocal, match
	}
	return entry.peer, RoutePeer, match
}

func (rt *RouteTable) Debug() []string {
	var out []string
	for route := range rt.table.All() {
		if route.Source.IsValid() {
			out = append(out, fmt.Sprintf("%s from %s via %s", route.Destination, route.Source, route.Value.peer.ID))
		} else {
			out = append(out, fmt.Sprintf("%s via %s", route.Destination, route.Value.peer.ID))
		}
	}
	sort.Strings(out)
	return out
}
