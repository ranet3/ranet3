// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package transport

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// unreachableRoute is a route of type unreachable to an address in table
// fib_props in net/ipv4/fib_semantics.c and ip6_rt_type_to_error in net/ipv6/route.c answer a lookup that meets one with EHOSTUNREACH
func unreachableRoute(to netip.Addr, table uint32) []byte {
	header := []byte{addressFamily(to), byte(to.BitLen()), 0, 0, byte(table), unix.RTPROT_BOOT, unix.RT_SCOPE_UNIVERSE, unix.RTN_UNREACHABLE, 0, 0, 0, 0}
	return append(header, attribute(unix.RTA_DST, to.AsSlice())...)
}

func (n routeNetlink) unreachable(to netip.Addr, table uint32) error {
	return n.request(unix.RTM_NEWROUTE, unix.NLM_F_CREATE|unix.NLM_F_EXCL, unreachableRoute(to, table))
}

// unroutedPin is the near end's address of family i that the host does not pick for to, routed by a rule into sourceTable, where to is unreachable
// chosen is the address the host picks
func unroutedPin(t *testing.T, netlink routeNetlink, i int, to netip.AddrPort) (pin, chosen netip.Addr) {
	t.Helper()
	conn, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(to))
	if err != nil {
		t.Fatal(err)
	}
	chosen = conn.LocalAddr().(*net.UDPAddr).AddrPort().Addr().Unmap()
	_ = conn.Close()
	pin = nearAddresses[i].Addr()
	if pin == chosen {
		pin = steeredSources[i].Addr()
	}
	if err := netlink.steer(addressFamily(pin), sourceTable, pin.BitLen(), attribute(unix.FRA_SRC, pin.AsSlice())); err != nil {
		t.Fatalf("route %s by a rule into table %d: %v", pin, sourceTable, err)
	}
	if err := netlink.unreachable(to.Addr(), sourceTable); err != nil {
		t.Fatalf("make %s unreachable in table %d: %v", to.Addr(), sourceTable, err)
	}
	return pin, chosen
}

// a pinned answer whose source a rule routes into a table that holds only an unreachable route to the peer goes from the kernel's choice of source
// a fresh request that reaches the same pin within unroutedHold is the same destination, so it moves nothing and the session's next send does not try the pin again
// the hub records the fallback once a family, naming the EHOSTUNREACH linux refuses the pinned send with
// the pin is the near end's address the host does not pick for the far end, so the answer the far end reads tells the two apart
func TestKernelHostUnreachableFromThePinFallsBack(t *testing.T) {
	far, _, netlink := vethPair(t, 1, slices.Concat(nearAddresses, steeredSources))
	events := &eventLog{}
	hub, err := NewHub(":0", Underlay{}, Runtime{Events: events.record})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	var want []string
	for i, address := range farAddresses {
		listener := far.listeners[i]
		to := netip.AddrPortFrom(address.Addr(), uint16(listener.LocalAddr().(*net.UDPAddr).Port))
		pin, chosen := unroutedPin(t, netlink, i, to)
		arrived := func() *udpEndpoint { return pinnedEndpoint(net.UDPAddrFromAddrPort(to), pin.AsSlice(), 0, !pin.Is4()) }
		ep := arrived()
		mux, err := hub.NewMuxTo(ep)
		if err != nil {
			t.Fatal(err)
		}
		answer := fmt.Appendf(nil, "answer to %s", to)
		if err := mux.SendESP(answer); err != nil {
			t.Fatalf("an answer to %s pinned to %s, which a rule makes unreachable from there, was not sent from another address: %v", to, pin, err)
		}
		if !ep.unpinned.Load() {
			t.Errorf("the endpoint to %s still names %s", to, pin)
		}
		if from := readFrom(t, listener, answer); from.Addr() != chosen {
			t.Errorf("the far end read the answer from %s, want the kernel's choice %s", from, chosen)
		}
		for request := range 3 {
			if mux.AdoptEndpoint(arrived()) {
				t.Errorf("fresh request %d from %s to %s, which holds no route back, moved the session", request, to, pin)
			}
			again := fmt.Appendf(nil, "answer %d to %s", request, to)
			if err := mux.SendESP(again); err != nil {
				t.Fatal(err)
			}
			if from := readFrom(t, listener, again); from.Addr() != chosen {
				t.Errorf("the far end read answer %d from %s, want the kernel's choice %s", request, from, chosen)
			}
		}
		want = append(want, fmt.Sprintf("transport.endpoint.unpinned endpoint=%s errno=EHOSTUNREACH", ep))
	}
	if got := events.recorded(); !slices.Equal(got, want) {
		t.Errorf("the hub recorded %q, want %q", got, want)
	}
}

// a session pinned to an address the host lost sends from the kernel's choice
// once the host holds the address again, a fresh request that reaches it moves the session back onto it
// the hub records the fallback once a family
func TestKernelSessionReturnsToAnAddressTheHostHoldsAgain(t *testing.T) {
	far, link, netlink := vethPair(t, 1, pairAddresses)
	events := &eventLog{}
	hub, err := NewHub(":0", Underlay{}, Runtime{Events: events.record})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	for i, address := range farAddresses {
		peer := far.listeners[i]
		kept, lost := pairAddresses[2*i].Addr(), pairAddresses[2*i+1]
		remote := netip.AddrPortFrom(address.Addr(), uint16(peer.LocalAddr().(*net.UDPAddr).Port))
		arrived := func() *udpEndpoint { return arrivedFrom(remote.String(), lost.Addr().String(), link.Index) }
		mux, err := hub.NewMuxTo(arrived())
		if err != nil {
			t.Fatal(err)
		}
		if err := netlink.unconfigure(link.Index, lost); err != nil {
			t.Fatalf("remove %s: %v", lost, err)
		}
		gone := []byte("while the address is gone")
		if err := mux.SendESP(gone); err != nil {
			t.Fatalf("a send after %s went failed: %v", lost, err)
		}
		if from, want := readFrom(t, peer, gone), netip.AddrPortFrom(kept, hub.port); from != want {
			t.Errorf("a send after %s went arrived from %s, want %s", lost, from, want)
		}
		if err := netlink.configure(link.Index, []netip.Prefix{lost}); err != nil {
			t.Fatalf("add %s back: %v", lost, err)
		}
		if !mux.AdoptEndpoint(arrived()) {
			t.Errorf("a fresh request to %s, which the host holds again, left the session on the kernel's choice", lost)
		}
		back := []byte("once the address is back")
		if err := mux.SendESP(back); err != nil {
			t.Fatal(err)
		}
		if from, want := readFrom(t, peer, back), netip.AddrPortFrom(lost.Addr(), hub.port); from != want {
			t.Errorf("a send after %s came back arrived from %s, want %s", lost, from, want)
		}
	}
	unpinned := 0
	for _, line := range events.recorded() {
		if strings.HasPrefix(line, "transport.endpoint.unpinned ") {
			unpinned++
		}
	}
	if unpinned != len(farAddresses) {
		t.Errorf("the hub recorded %q, want one transport.endpoint.unpinned a family", events.recorded())
	}
}

// a session whose pin fell back after EHOSTUNREACH stays on the kernel's choice while unroutedHold lasts, through a fresh request to the pin once it routes again
// after the hold, a fresh request to the pin moves the session back onto it, and its sends leave from the pin
// the hub records the fallback once a family
// the test deletes the unreachable route, so the rule's table holds nothing and the pin routes by the main table
func TestKernelSessionReturnsToAPinThatRoutesAgain(t *testing.T) {
	far, _, netlink := vethPair(t, 1, slices.Concat(nearAddresses, steeredSources))
	events := &eventLog{}
	hub, err := NewHub(":0", Underlay{}, Runtime{Events: events.record})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	var want []string
	for i, address := range farAddresses {
		listener := far.listeners[i]
		to := netip.AddrPortFrom(address.Addr(), uint16(listener.LocalAddr().(*net.UDPAddr).Port))
		pin, chosen := unroutedPin(t, netlink, i, to)
		arrived := func() *udpEndpoint { return pinnedEndpoint(net.UDPAddrFromAddrPort(to), pin.AsSlice(), 0, !pin.Is4()) }
		ep := arrived()
		mux, err := hub.NewMuxTo(ep)
		if err != nil {
			t.Fatal(err)
		}
		sentFrom := func(step string) netip.Addr {
			t.Helper()
			datagram := fmt.Appendf(nil, "%s to %s", step, to)
			if err := mux.SendESP(datagram); err != nil {
				t.Fatalf("a send %s to %s: %v", step, to, err)
			}
			return readFrom(t, listener, datagram).Addr()
		}
		if from := sentFrom("with no route from the pin"); from != chosen || ep.unroutedUntil.Load() == nil {
			t.Fatalf("premise: a send to %s pinned to %s, which has no route there, arrived from %s, fallen back for want of a route %v", to, pin, from, ep.unroutedUntil.Load() != nil)
		}
		if err := netlink.request(unix.RTM_DELROUTE, 0, unreachableRoute(address.Addr(), sourceTable)); err != nil {
			t.Fatalf("delete the unreachable route to %s: %v", address.Addr(), err)
		}
		if mux.AdoptEndpoint(arrived()) {
			t.Errorf("a fresh request to %s within the hold moved the session", pin)
		}
		if from := sentFrom("within the hold"); from != chosen {
			t.Errorf("a send within the hold arrived from %s, want the kernel's choice %s", from, chosen)
		}
		ep.unroutedUntil.Store(new(time.Now()))
		if !mux.AdoptEndpoint(arrived()) {
			t.Errorf("a fresh request to %s after the hold left the session on the kernel's choice", pin)
		}
		if from := sentFrom("after the hold"); from != pin {
			t.Errorf("a send after the hold arrived from %s, want the pin %s, which routes again", from, pin)
		}
		want = append(want, fmt.Sprintf("transport.endpoint.unpinned endpoint=%s errno=EHOSTUNREACH", ep))
	}
	if got := events.recorded(); !slices.Equal(got, want) {
		t.Errorf("the hub recorded %q, want %q", got, want)
	}
}
