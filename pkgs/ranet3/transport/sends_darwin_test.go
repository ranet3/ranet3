// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package transport

import (
	"net"
	"net/netip"
	"testing"
)

// darwin's mux answers where its datagrams go and leaves the pin to its selection, whose pair key a read must not record
func TestSendsNamesWhatAMuxsDatagramsCarry(t *testing.T) {
	lo, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range []struct{ network, loopback string }{{"udp4", "127.0.0.1"}, {"udp6", "::1"}} {
		t.Run(family.network, func(t *testing.T) {
			hub, peer, dialed := pairHub(t, family.network, family.loopback)
			at := peer.LocalAddr().(*net.UDPAddr).AddrPort()
			at = netip.AddrPortFrom(at.Addr().Unmap(), at.Port())
			pinned, err := hub.NewMuxTo(pinnedEndpoint(at, netip.MustParseAddr(family.loopback), lo.Index))
			if err != nil {
				t.Fatal(err)
			}
			for _, mux := range []*Mux{dialed, pinned} {
				if got, want := mux.Sends(), (Send{Destination: at.Addr()}); got != want {
					t.Errorf("the mux sends %+v, want %+v", got, want)
				}
			}
		})
	}
}
