// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package transport

import (
	"net"
	"net/netip"
	"slices"
	"testing"
)

// every socket the hub opens passes its runtime's Prepare before it binds or connects:
// the listener of each family with no destination, then for a pair to a peer the socket that reads the route's source and the pair's own,
// and the socket a path MTU read connects, each toward the peer
func TestEverySocketOfTheHubPassesItsPrepare(t *testing.T) {
	for _, family := range []struct{ network, loopback string }{{"udp4", "127.0.0.1"}, {"udp6", "::1"}} {
		t.Run(family.network, func(t *testing.T) {
			recording := &recordingPrepare{}
			hub, err := NewHub(0, Runtime{Prepare: recording.prepare})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = hub.Close() })
			if seen := recording.take(); !slices.Equal(seen, []readied{{"udp4", netip.AddrPort{}}, {"udp6", netip.AddrPort{}}}) {
				t.Errorf("the hub's listener readied %v, want each family's with no destination", seen)
			}
			peer := listenPeer(t, family.network, family.loopback)
			at := peer.LocalAddr().(*net.UDPAddr)
			to := netip.AddrPortFrom(at.AddrPort().Addr().Unmap(), at.AddrPort().Port())
			mux, err := hub.NewMux(at.IP, at.Port)
			if err != nil {
				t.Fatal(err)
			}
			if openNow(mux).socket.Load() == nil {
				t.Fatalf("the pair to %s opened no socket", to)
			}
			if seen := recording.take(); !slices.Equal(seen, []readied{{family.network, to}, {family.network, to}}) {
				t.Errorf("the pair to %s readied %v, want its route's source read and its own socket, each toward the peer", to, seen)
			}
			if _, err := mux.PathMTU(); err != nil {
				t.Fatal(err)
			}
			if seen := recording.take(); !slices.Equal(seen, []readied{{family.network, to}}) {
				t.Errorf("the path MTU read to %s readied %v, want one socket toward the peer", to, seen)
			}
		})
	}
}
