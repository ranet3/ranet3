// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux

package transport

import (
	"math"
	"net"
	"net/netip"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// pairPeerAddresses draws an address of the family a socket of ipv6 receives from, a link-local one zoned where zoned
func pairPeerAddresses(ipv6, zoned bool) hegel.Generator[netip.Addr] {
	if !ipv6 {
		return hegel.IPAddresses().IPv4()
	}
	return hegel.Composite(func(tc hegel.TestCase) netip.Addr {
		address := hegel.Draw(tc, hegel.Filter(hegel.IPAddresses().IPv6(), func(a netip.Addr) bool { return !a.Is4In6() }))
		if !hegel.Draw(tc, hegel.Booleans()) {
			return address
		}
		raw := address.As16()
		copy(raw[:8], []byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0})
		linkLocal := netip.AddrFrom16(raw)
		if zoned {
			linkLocal = linkLocal.WithZone(hegel.Draw(tc, hegel.SampledFrom([]string{"near", "2"})))
		}
		return linkLocal
	})
}

// a pair leaves from the address and the interface the shared socket's sends to its endpoint name in their pin
// and leaves both to the route where those sends carry no pin, for an endpoint dialed or one that fell back from its pin
// an IPv4 source that arrived mapped into IPv6 names the IPv4 address, and a link-local source names its interface by index alone
func TestPairLeavesWhereTheSharedSocketsSendsDo(t *testing.T) {
	bind := &udpBind{}
	pbt.Check(t, func(ht *hegel.T) {
		ipv6 := hegel.Draw(ht, hegel.Booleans())
		remote := netip.AddrPortFrom(hegel.Draw(ht, pairPeerAddresses(ipv6, true)), hegel.Draw(ht, hegel.Integers[uint16](1, math.MaxUint16)))
		addr := net.UDPAddrFromAddrPort(remote)
		ep := &udpEndpoint{addr: addr}
		if kind := hegel.Draw(ht, hegel.SampledFrom([]string{"dialed", "pinned", "unpinned"})); kind != "dialed" {
			source := hegel.Draw(ht, pairPeerAddresses(ipv6, false))
			raw := source.AsSlice()
			if source.Is4() && hegel.Draw(ht, hegel.Booleans()) {
				mapped := source.As16()
				raw = mapped[:]
			}
			ep = pinnedEndpoint(addr, raw, hegel.Draw(ht, pbt.Spanning(0, math.MaxUint16)), ipv6)
			ep.unpinned.Store(kind == "unpinned")
		}
		want := pairKey{remote: remote}
		if control := ep.pin(); control != nil {
			want.local, want.index, _, _ = parseSendControl(control)
		}
		if got := bind.pairOf(ep); got != want {
			ht.Fatalf("the pair of %s from %v at interface %d is %+v, want %+v", remote, ep.source, ep.index, got, want)
		}
	})
}
