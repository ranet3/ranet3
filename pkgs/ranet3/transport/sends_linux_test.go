// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package transport

import (
	"net"
	"net/netip"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

// a mux's datagrams carry its pin while the kernel takes it and nothing once the pin fell back or for a session this node dialed,
// and the address the socket connected to its peer is bound to while it sends on one, beside the pin's interface for a pinned pair,
// and an unpinned send to a zoned peer the zone's interface
func TestSendsNamesWhatAMuxsDatagramsCarry(t *testing.T) {
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range []struct{ network, loopback string }{{"udp4", "127.0.0.1"}, {"udp6", "::1"}} {
		loopback := netip.MustParseAddr(family.loopback)
		accepted := func(t *testing.T) (*Mux, *udpEndpoint, netip.Addr) {
			t.Helper()
			hub, peer, _ := pairHub(t, family.network, family.loopback)
			at := peer.LocalAddr().(*net.UDPAddr).AddrPort()
			pin := pinnedEndpoint(net.UDPAddrFromAddrPort(at), loopback.AsSlice(), lo.Index, family.network == "udp6")
			mux, err := hub.NewMuxTo(pin)
			if err != nil {
				t.Fatal(err)
			}
			return mux, pin, at.Addr().Unmap()
		}
		opened := func(t *testing.T, m *Mux) {
			t.Helper()
			if p := openNow(m); p.socket.Load() == nil {
				t.Fatalf("the pair to %s opened no socket", p.key.remote)
			}
		}
		expect := func(t *testing.T, m *Mux, want Send) {
			t.Helper()
			if got := m.Sends(); got != want {
				t.Errorf("the mux sends %+v, want %+v", got, want)
			}
		}
		t.Run(family.network+"/dialed", func(t *testing.T) {
			_, peer, mux := pairHub(t, family.network, family.loopback)
			expect(t, mux, Send{Destination: peer.LocalAddr().(*net.UDPAddr).AddrPort().Addr().Unmap()})
		})
		t.Run(family.network+"/pinned", func(t *testing.T) {
			mux, _, destination := accepted(t)
			expect(t, mux, Send{Destination: destination, Source: loopback, Interface: lo.Index})
		})
		t.Run(family.network+"/fallen back", func(t *testing.T) {
			mux, pin, destination := accepted(t)
			pin.unpin(unix.ENETUNREACH)
			expect(t, mux, Send{Destination: destination})
		})
		t.Run(family.network+"/pinned pair", func(t *testing.T) {
			mux, pin, destination := accepted(t)
			opened(t, mux)
			expect(t, mux, Send{Destination: destination, Source: loopback, Interface: lo.Index, Pair: true})
			pin.unpin(unix.ENETUNREACH)
			expect(t, mux, Send{Destination: destination})
		})
		t.Run(family.network+"/unpinned pair", func(t *testing.T) {
			_, peer, mux := pairHub(t, family.network, family.loopback)
			opened(t, mux)
			expect(t, mux, Send{Destination: peer.LocalAddr().(*net.UDPAddr).AddrPort().Addr().Unmap(), Source: loopback, Pair: true})
		})
	}
	t.Run("udp6/zoned", func(t *testing.T) {
		hub, _, _ := pairHub(t, "udp6", "::1")
		peer := netip.MustParseAddr("fe80::9")
		mux, err := hub.NewMuxTo(&udpEndpoint{addr: &net.UDPAddr{IP: peer.AsSlice(), Port: 4500, Zone: strconv.Itoa(lo.Index)}})
		if err != nil {
			t.Fatal(err)
		}
		if got, want := mux.Sends(), (Send{Destination: peer, Interface: lo.Index}); got != want {
			t.Errorf("the mux sends %+v, want %+v", got, want)
		}
	})
}
