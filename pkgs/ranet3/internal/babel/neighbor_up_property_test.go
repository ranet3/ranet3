// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package babel

import (
	"maps"
	"slices"
	"testing"
	"time"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/pbt"
)

func TestNodeHoldsExactlyWhatItsNeighborAnnouncesAfterItsFirstHello(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		keysA := hegel.Draw(ht, hegel.Lists(learnedKeys()).MinSize(1).MaxSize(12))
		keysB := hegel.Draw(ht, hegel.Lists(learnedKeys()).MinSize(1).MaxSize(12))
		packetSize := hegel.Draw(ht, pbt.Spanning(63, 1400))
		returns := hegel.Draw(ht, hegel.Booleans())

		w := newHeldWire(ht, packetSize)
		for _, key := range keysA {
			w.a.OriginateFrom(key.dest, key.source)
		}
		for _, key := range keysB {
			w.b.OriginateFrom(key.dest, key.source)
		}
		// an end holds its own keys unreachable and every other key through its neighbor,
		// so a key that both announce stays its own at each
		held := func(own, announced []routeKey, neighbor *netstack.Peer) map[routeKey]*netstack.Peer {
			want := make(map[routeKey]*netstack.Peer, len(own)+len(announced))
			for _, key := range announced {
				want[key] = neighbor
			}
			for _, key := range own {
				want[key] = netstack.Unreachable
			}
			return want
		}
		wantA, wantB := held(keysA, keysB, w.peerBForA), held(keysB, keysA, w.peerAForB)
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
			if through(w.a, w.peerBForA) || through(w.b, w.peerAForB) {
				ht.Fatal("an end still forwards through its neighbor after it declared it down, so this proves nothing")
			}
			w.helloFromB()
			w.deliver()
			holds("after b returned")
		}
	})
}
