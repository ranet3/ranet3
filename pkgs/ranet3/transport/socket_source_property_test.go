// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin

package transport

import (
	"math"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// holdMargin is the least hold a case leaves where it keeps the hold, far past the time a case takes
const holdMargin = time.Second

// receivedAddresses draws an address of the family a socket of ipv6 receives on, a link-local IPv6 one outright half the time
func receivedAddresses(ipv6 bool) hegel.Generator[netip.Addr] {
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
		return netip.AddrFrom16(raw)
	})
}

// an answer names the address its request reached, and an IPv6 one the interface holding it, the one it arrived on for a link-local address
// its sends are keyed on the interface holding that address, or the one it arrived on for an IPv6 link-local address
// an IPv6 answer that fragments carries IPV6_DONTFRAG of 0 beside the pin
// two endpoints are one destination only where the peer and the source and interface sends carry are
// one whose sends fell back to the kernel's choice is the endpoint without its source, unless the pin fell back after EHOSTUNREACH, where it stays the pinned one until unroutedHold ends
// a pair leaves from the pin as the shared socket's sends do, and leaves the source to the route where they carry none
func TestDarwinRepliesNameTheAddressTheRequestReached(t *testing.T) {
	bind := &darwinBind{}
	pbt.Check(t, func(ht *hegel.T) {
		ipv6 := hegel.Draw(ht, hegel.Booleans())
		peer := netip.AddrPortFrom(hegel.Draw(ht, receivedAddresses(ipv6)), hegel.Draw(ht, hegel.Integers[uint16](1, math.MaxUint16)))
		reached := hegel.Draw(ht, receivedAddresses(ipv6))
		other := hegel.Draw(ht, hegel.Filter(receivedAddresses(ipv6), func(a netip.Addr) bool { return a != reached }))
		// the interface a request arrived on is never zero: ip6_input in bsd/netinet6/ip6_input.c requires a receive interface, which ip6_savecontrol names in IPV6_PKTINFO
		index := hegel.Draw(ht, pbt.Spanning(1, math.MaxUint16))
		otherIndex := hegel.Draw(ht, hegel.Filter(pbt.Spanning(1, math.MaxUint16), func(i int) bool { return i != index }))
		// holder is the interface holding reached, zero for none
		holder := hegel.Draw(ht, pbt.Spanning(0, math.MaxUint16))
		holding := &darwinBind{selection: newTestSelection(1), readHeld: func() (map[netip.Addr]int, error) { return map[netip.Addr]int{reached: holder}, nil }}
		fragments := ipv6 && hegel.Draw(ht, hegel.Booleans())
		socket := &darwinSocket{ipv6: ipv6}
		arrived := func(at netip.Addr, on int) *darwinEndpoint {
			ep, err := socket.replyEndpoint(peer, receivedControl(ipv6, at, on))
			if err != nil {
				ht.Fatalf("a request from %s that reached %s on interface %d: %v", peer, at, on, err)
			}
			ep.fragments.Store(fragments)
			return ep
		}
		ep, same, moved, elsewhere := arrived(reached, index), arrived(reached, index), arrived(other, index), arrived(reached, otherIndex)
		linkLocal := ipv6 && reached.IsLinkLocalUnicast()
		wantIndex, pairIndex, wantKey := 0, 0, unheldPin
		if linkLocal {
			wantIndex, pairIndex = index, index
		} else if ipv6 {
			wantIndex = holder
		}
		switch {
		case linkLocal:
			wantKey = int64(index)
		case holder != 0:
			wantKey = int64(holder)
		}
		pin := holding.pinned(ep)
		if key := pin.key(); key != wantKey {
			ht.Fatalf("the sends answering %s that reached %s on interface %d, held by %d, are keyed %d, want %d", peer, reached, index, holder, key, wantKey)
		}
		source, gotIndex, gotFragments, err := sentPin(ep.carried(pin.control, pin.fragmentingControl))
		if err != nil || source != reached || gotIndex != wantIndex || gotFragments != fragments {
			ht.Fatalf("the answer to %s that reached %s on interface %d, held by %d, names %s at interface %d, fragmenting %v, %v, want %s at interface %d, fragmenting %v",
				peer, reached, index, holder, source, gotIndex, gotFragments, err, reached, wantIndex, fragments)
		}
		if !ep.sameDestination(same) || !same.sameDestination(ep) {
			ht.Fatalf("two requests from %s that reached %s are not one destination", peer, reached)
		}
		if ep.sameDestination(moved) || moved.sameDestination(ep) {
			ht.Fatalf("requests from %s that reached %s and %s are one destination", peer, reached, other)
		}
		if ep.sameDestination(elsewhere) == linkLocal || elsewhere.sameDestination(ep) == linkLocal {
			ht.Fatalf("requests from %s that reached %s on interfaces %d and %d read as one destination %v, want %v", peer, reached, index, otherIndex, ep.sameDestination(elsewhere), !linkLocal)
		}
		if got := bind.pairOf(ep); got != (pairKey{local: reached, index: pairIndex, remote: peer}) {
			ht.Fatalf("the pair of %s pinned to %s at interface %d is %+v", peer, reached, pairIndex, got)
		}
		bare := ep.withoutSource().(*darwinEndpoint)
		if bare.pin() != nil || bare.AddrPort() != ep.AddrPort() {
			ht.Fatalf("%s without its source still names one, or moved to %s", ep, bare.AddrPort())
		}
		refused := hegel.Draw(ht, hegel.SampledFrom([]unix.Errno{unix.ENETUNREACH, unix.EHOSTUNREACH, unix.EINVAL, unix.ENODEV, unix.EADDRNOTAVAIL}))
		before := time.Now()
		if !ep.unpin(refused) || ep.unpin(refused) {
			ht.Fatalf("%s fell back on %s other than once", ep, unix.ErrnoName(refused))
		}
		after := time.Now()
		if until := ep.unroutedUntil.Load(); (until != nil) != (refused == unix.EHOSTUNREACH) ||
			until != nil && (until.Before(before.Add(unroutedHold)) || until.After(after.Add(unroutedHold))) {
			ht.Fatalf("%s fell back on %s and holds the pin until %v, want unroutedHold after the fallback for EHOSTUNREACH alone", ep, unix.ErrnoName(refused), until)
		}
		source, _, gotFragments, err = sentPin(ep.unpinnedControl())
		if ep.pin() != nil || err != nil || source.IsValid() || gotFragments != fragments {
			ht.Fatalf("%s fell back and still names %s, fragmenting %v, %v", ep, source, gotFragments, err)
		}
		// the hold ends before the case reads it, or holdMargin or more after
		held := hegel.Draw(ht, hegel.Booleans())
		left := hegel.Draw(ht, pbt.Spanning(-unroutedHold, 0))
		if held {
			left = hegel.Draw(ht, pbt.Spanning(holdMargin, unroutedHold))
		}
		if ep.unroutedUntil.Load() != nil {
			ep.unroutedUntil.Store(new(time.Now().Add(left)))
		}
		unrouted := refused == unix.EHOSTUNREACH && held
		if ep.sameDestination(bare) == unrouted || ep.sameDestination(same) != unrouted || same.sameDestination(ep) != unrouted {
			ht.Fatalf("%s fell back on %s with %s of the hold left and reads as the endpoint without its source %v and as the pinned one %v, want %v and %v",
				ep, unix.ErrnoName(refused), left, ep.sameDestination(bare), ep.sameDestination(same), !unrouted, unrouted)
		}
		if got := bind.pairOf(ep); got != (pairKey{remote: peer}) {
			ht.Fatalf("the pair of %s that fell back is %+v", peer, got)
		}
	})
}
