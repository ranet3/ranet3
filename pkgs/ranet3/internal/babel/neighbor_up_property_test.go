// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package babel

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"testing"
	"time"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// ownsHost reports a host prefix one of own holds under any source, for which a node drops every route a neighbor offers whatever its source
func ownsHost(own []routeKey, dest netip.Prefix) bool {
	return dest.IsSingleIP() && slices.ContainsFunc(own, func(key routeKey) bool { return key.dest == dest })
}

func TestNodeHoldsExactlyWhatItsNeighborAnnouncesAfterItsFirstHello(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		keysA := hegel.Draw(ht, hegel.Lists(learnedKeys()).MinSize(1).MaxSize(12))
		keysB := hegel.Draw(ht, hegel.Lists(learnedKeys()).MinSize(1).MaxSize(12))
		packetSize := hegel.Draw(ht, pbt.Spanning(63, 1400))
		returns := hegel.Draw(ht, hegel.Booleans())

		w := newHeldWire(ht, packetSize)
		defer w.close()
		for _, key := range keysA {
			w.a.OriginateFrom(key.dest, key.source)
		}
		for _, key := range keysB {
			w.b.OriginateFrom(key.dest, key.source)
		}
		// an end holds its own keys as Local and every other key through its neighbor,
		// so a key that both announce stays its own at each, and one for a host prefix an end holds under another source goes nowhere there
		held := func(own, announced []routeKey, neighbor *netstack.Peer) map[routeKey]*netstack.Peer {
			want := make(map[routeKey]*netstack.Peer, len(own)+len(announced))
			for _, key := range announced {
				if !ownsHost(own, key.dest) {
					want[key] = neighbor
				}
			}
			for _, key := range own {
				want[key] = netstack.Local
			}
			return want
		}
		wantA, wantB := held(keysA, keysB, w.peerBForA.Peer), held(keysB, keysA, w.peerAForB.Peer)
		forwarded := func(s *Speaker) map[routeKey]*netstack.Peer {
			got := make(map[routeKey]*netstack.Peer)
			for _, route := range s.mesh.Routes.Snapshot() {
				got[routeKey{source: route.Source, dest: route.Destination}] = route.Value
			}
			return got
		}
		holds := func(when string) {
			if !maps.Equal(forwarded(w.a), wantA) {
				ht.Fatalf("%s a forwards %v, want its own routes and every one announced through b", when, w.a.mesh.Routes.Debug())
			}
			if !maps.Equal(forwarded(w.b), wantB) {
				ht.Fatalf("%s b forwards %v, want its own routes and every one announced through a", when, w.b.mesh.Routes.Debug())
			}
		}

		// b's session-start dump reaches a before a has the session, and a drops it
		w.joinB()
		w.b.flushUpdates()
		w.deliver()
		w.joinA()
		w.helloFromB()
		w.deliver()
		holds("after b's first hello")

		if returns {
			// both ends declare the other down before b's next hello
			later := time.Now().Add(deadTimeout(w.b.hello) + time.Second)
			for _, s := range []*Speaker{w.a, w.b} {
				s.mu.Lock()
				s.sweepExpiredLocked(later)
				s.mu.Unlock()
			}
			through := func(s *Speaker, neighbor *netstack.Peer) bool {
				return slices.Contains(slices.Collect(maps.Values(forwarded(s))), neighbor)
			}
			if through(w.a, w.peerBForA.Peer) || through(w.b, w.peerAForB.Peer) {
				ht.Fatal("an end still forwards through its neighbor after it declared it down, so this proves nothing")
			}
			w.helloFromB()
			w.deliver()
			holds("after b returned")
		}
	})
}

// When the session to a neighbor goes, closed or replaced, a node holds each
// key it learned from that neighbor alone and named in a finite update to
// another neighbor, until the last such update has expired there: 3.5 update
// intervals and one Hello interval from when it was sent. A retraction sent
// after it moves nothing, since it may have been lost. Every other key the
// neighbor offered goes at once, and the node's own keys stay its own.
func TestNodeHoldsWhatItRelayedOnceItsNeighborGoes(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		keysA := hegel.Draw(ht, hegel.Lists(learnedKeys()).MaxSize(4))
		keysB := hegel.Draw(ht, hegel.Lists(learnedKeys()).MinSize(1).MaxSize(12))
		// whether a dumps its table to c before b retracts some of its keys,
		// and after, each dump at a moment of its own in the past
		relayed, relayedAfter := hegel.Draw(ht, hegel.Booleans()), hegel.Draw(ht, hegel.Booleans())
		replaced := hegel.Draw(ht, hegel.Booleans())
		own := make(map[routeKey]bool, len(keysA))
		for _, key := range keysA {
			own[key] = true
		}
		retracted := make(map[routeKey]bool, len(keysB))
		var kept []OriginatedRoute
		for _, key := range keysB {
			if _, seen := retracted[key]; seen {
				continue
			}
			retracted[key] = hegel.Draw(ht, hegel.Booleans())
			if !retracted[key] {
				kept = append(kept, OriginatedRoute{Destination: key.dest, Source: key.source})
			}
		}

		w := newHeldWire(ht, 0)
		defer w.close()
		c := newHeldPeer(ht, "c", nil)
		defer c.Close()
		for _, key := range keysA {
			w.a.OriginateFrom(key.dest, key.source)
		}
		for _, key := range keysB {
			w.b.OriginateFrom(key.dest, key.source)
		}
		w.joinB()
		w.joinA()
		w.helloFromB()
		w.deliver()
		w.a.AddPeer(c.Peer, identity.Identity{})
		for key := range retracted {
			if value, ok := entryAt(w.a.mesh, key); !own[key] && !ownsHost(keysA, key.dest) && (!ok || value != w.peerBForA.Peer) {
				ht.Fatalf("a holds %s for %s before b goes, so this proves nothing", peerName(value), describeRoute(key))
			}
		}

		first, later := time.Now().Add(-20*time.Second), time.Now().Add(-10*time.Second)
		if relayed {
			dumpAt(w.a, first)
		}
		w.b.SetOriginated(kept)
		w.b.flushUpdates()
		w.deliver()
		if relayedAfter {
			dumpAt(w.a, later)
		}
		w.a.mu.Lock()
		gone := w.a.neighbors["b"]
		hold := deadTimeout(w.a.update) + w.a.hello
		w.a.mu.Unlock()
		if replaced {
			replacement := newHeldPeer(ht, "b", nil)
			defer replacement.Close()
			w.a.AddPeer(replacement.Peer, identity.Identity{})
		} else {
			w.a.removePeer(gone)
		}

		// the last finite update c was sent for a key is the later dump's for
		// one b kept, and the earlier dump's otherwise, since the later dump
		// retracts what b retracted
		ends := make(map[routeKey]time.Time)
		for key := range retracted {
			switch {
			case own[key], ownsHost(keysA, key.dest):
			case relayedAfter && !retracted[key]:
				ends[key] = later.Add(hold)
			case relayed:
				ends[key] = first.Add(hold)
			}
		}
		forwards := func(when string, at time.Time) {
			want := make(map[routeKey]*netstack.Peer)
			for key := range own {
				want[key] = netstack.Local
			}
			for key, end := range ends {
				if at.Before(end) {
					want[key] = netstack.Unreachable
				}
			}
			got := make(map[routeKey]*netstack.Peer)
			for _, route := range w.a.mesh.Routes.Snapshot() {
				got[routeKey{source: route.Source, dest: route.Destination}] = route.Value
			}
			if !maps.Equal(got, want) {
				ht.Fatalf("%s a forwards %v, want its own keys and those whose last update to c has not expired held", when, w.a.mesh.Routes.Debug())
			}
			if prefixes := w.a.Stats().Prefixes; prefixes != len(want) {
				ht.Fatalf("%s a counts %d prefixes, want the %d it forwards", when, prefixes, len(want))
			}
		}
		forwards("once b went", time.Now())
		for _, at := range []time.Time{first.Add(hold - time.Nanosecond), first.Add(hold), later.Add(hold - time.Nanosecond), later.Add(hold)} {
			w.a.mu.Lock()
			w.a.sweepExpiredLocked(at)
			w.a.mu.Unlock()
			forwards(fmt.Sprintf("%v past the earlier dump", at.Sub(first)), at)
		}
	})
}
