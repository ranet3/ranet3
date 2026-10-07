// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package babel

import (
	"maps"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/pbt"
)

func TestNodeHoldsExactlyWhatItsNeighborAnnouncesAfterItsFirstHello(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		drawn := hegel.Draw(ht, hegel.Lists(learnedKeys()).MinSize(1).MaxSize(12))
		packetSize := hegel.Draw(ht, pbt.Spanning(63, 1400))

		w := newHeldWire(ht, packetSize)
		want := make(map[routeKey]*netstack.Peer, len(drawn))
		for _, key := range drawn {
			want[key] = w.peerBForA
			w.b.OriginateFrom(key.dest, key.source)
		}

		// b's session-start dump reaches a before a has the session, and a drops it
		w.joinB()
		w.b.flushUpdates()
		w.deliver()
		w.joinA()
		w.helloFromB()
		w.deliver()

		forwarded := make(map[routeKey]*netstack.Peer, len(want))
		for _, route := range w.a.mesh.Routes.Snapshot() {
			forwarded[routeKey{source: route.Source, dest: route.Destination}] = route.Value
		}
		if !maps.Equal(forwarded, want) {
			ht.Fatalf("a forwards %v, want every route announced through b", w.a.mesh.Routes.Debug())
		}
	})
}
