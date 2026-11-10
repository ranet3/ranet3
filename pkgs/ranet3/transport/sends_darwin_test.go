// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package transport

import (
	"net"
	"net/netip"
	"testing"
)

// a mux of a hub with no selection names no interface for its dialed sends, and for a pinned one the pin, its arrival interface and the pin's interface
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
			source := netip.MustParseAddr(family.loopback)
			pinned, err := hub.NewMuxTo(pinnedEndpoint(at, source, lo.Index))
			if err != nil {
				t.Fatal(err)
			}
			for _, sent := range []struct {
				mux  *Mux
				want Send
			}{
				{dialed, Send{Destination: at.Addr()}},
				{pinned, Send{Destination: at.Addr(), Source: source, Interface: lo.Index, PinInterface: lo.Index}},
			} {
				if got := sent.mux.Sends(); got != sent.want {
					t.Errorf("the mux sends %+v, want %+v", got, sent.want)
				}
			}
		})
	}
}
