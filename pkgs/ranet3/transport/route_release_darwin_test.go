// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin

package transport

import (
	"errors"
	"math"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/ipv6"
)

// answersPerGeneration is how many fresh pinned endpoints a test answers from one address under one generation
const answersPerGeneration = 8

// goneIndex is an interface index past every interface a host holds
const goneIndex = math.MaxUint16

// staleReadWait is how long a test lets a second sender reach the read of the host's addresses another sender is inside
const staleReadWait = 200 * time.Millisecond

// countReleases counts the releases of the cached routes of bind's shared sockets, each of which still goes to darwin
func countReleases(bind *darwinBind) *atomic.Int64 {
	count := &atomic.Int64{}
	release := bind.dropRoute
	bind.dropRoute = func(socket *darwinSocket) error {
		count.Add(1)
		return release(socket)
	}
	return count
}

// loopbackShared is a hub's shared socket of one family, a peer on that family's loopback address, and the count of the socket's releases
type loopbackShared struct {
	bind     *darwinBind
	socket   *darwinSocket
	peer     *net.UDPConn
	to       netip.AddrPort
	released *atomic.Int64
}

// overLoopback is a hub whose sends name the interface selection answers, or none where selection is nil, and its shared socket to a peer on loopback
func overLoopback(t *testing.T, network, loopback string, selection Selection) loopbackShared {
	t.Helper()
	hub, err := NewHub(0, Runtime{Prepare: testPrepare(), Selection: selection})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	bind := hub.bind.(*darwinBind)
	peer := listenPeer(t, network, loopback)
	to := peer.LocalAddr().(*net.UDPAddr).AddrPort()
	to = netip.AddrPortFrom(to.Addr().Unmap(), to.Port())
	return loopbackShared{bind: bind, socket: bind.socketFor(to.Addr()), peer: peer, to: to, released: countReleases(bind)}
}

// send sends payload to ep and asserts that it reached the peer, from want where it is valid
func (l loopbackShared) send(t *testing.T, ep *darwinEndpoint, payload string, want netip.Addr) {
	t.Helper()
	if err := l.bind.Send([][]byte{[]byte(payload)}, ep); err != nil {
		t.Fatalf("send %q to %s: %v", payload, ep.addr, err)
	}
	if from := readFrom(t, l.peer, []byte(payload)); want.IsValid() && from.Addr() != want {
		t.Errorf("%q reached the peer from %s, want %s", payload, from.Addr(), want)
	}
}

// the shared socket releases its cached route at each send whose key differs from the last one stored, once,
// and after a write only where another key was stored since
func TestDarwinSharedSocketReleasesItsRouteOncePerChangeOfInterface(t *testing.T) {
	for _, family := range loopbackFamilies {
		t.Run(family.network, func(t *testing.T) {
			l := overLoopback(t, family.network, family.loopback, nil)
			for i, step := range []struct {
				after    bool
				key      int64
				releases int64
			}{
				{false, 1, 1},
				{false, 1, 0},
				{true, 1, 0},
				{false, 2, 1},
				{true, 1, 1},
				{false, 2, 0},
				{false, 1, 1},
				{false, unheldPin, 1},
				{true, unheldPin, 0},
				{false, unheldPin, 0},
				{false, noInterface, 1},
				{false, noInterface, 0},
			} {
				before := l.released.Load()
				check, run := l.bind.beforeWrite, "before"
				if step.after {
					check, run = l.bind.afterWrite, "after"
				}
				if err := check(l.socket, step.key); err != nil {
					t.Fatalf("step %d, the check %s a write keyed %d: %v", i, run, step.key, err)
				}
				if got := l.released.Load() - before; got != step.releases {
					t.Errorf("step %d, the check %s a write keyed %d released the route %d times, want %d", i, run, step.key, got, step.releases)
				}
			}
		})
	}
}

// a send keyed B that runs whole while a send keyed A to the same address is inside its release, after the release took effect,
// leaves the record naming B and the socket caching no route of A's, so once both ended a send of either key leaves by its own interface
// a send stores its key before it releases, which this order needs: one that stored after would leave the record naming A over B's route
func TestDarwinSharedSocketRecordHoldsThroughASendInsideARelease(t *testing.T) {
	route := &cachedRoute{}
	const to = 0
	a, b := int64(1), int64(2)
	var inside func()
	bind := &darwinBind{dropRoute: func(*darwinSocket) error {
		route.held = false
		if run := inside; run != nil {
			inside = nil
			run()
		}
		return nil
	}}
	socket := &darwinSocket{}
	send := func(key int64) (int64, error) {
		if err := bind.beforeWrite(socket, key); err != nil {
			return 0, err
		}
		by, _ := route.write(to, key)
		return by, bind.afterWrite(socket, key)
	}
	var insideErr error
	inside = func() { _, insideErr = send(b) }
	if _, err := send(a); err != nil || insideErr != nil {
		t.Fatalf("the send keyed %d answered %v, and the one keyed %d inside its release %v", a, err, b, insideErr)
	}
	for _, key := range []int64{a, b, a} {
		if by, err := send(key); err != nil || by != key {
			t.Errorf("once both sends ended, a send keyed %d left by %d, %v", key, by, err)
		}
	}
}

// on one interface nothing is released past the first send: sends naming the selection's interface and sends from a pin it holds
func TestDarwinSendsOnOneInterfaceReleaseNothing(t *testing.T) {
	loopback, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range loopbackFamilies {
		t.Run(family.network, func(t *testing.T) {
			l := overLoopback(t, family.network, family.loopback, newTestSelection(loopback.Index))
			selected := &darwinEndpoint{addr: l.to}
			source := netip.MustParseAddr(family.loopback)
			pinned := pinnedEndpoint(l.to, source, 0)
			l.send(t, selected, "the first send", netip.Addr{})
			l.released.Store(0)
			for _, ep := range []*darwinEndpoint{selected, selected, pinned, selected, pinned, pinned} {
				l.send(t, ep, "a send naming lo0", netip.Addr{})
			}
			if released := l.released.Load(); released != 0 {
				t.Errorf("sends naming lo0 and from %s, which lo0 holds, released the route %d times past the first send, want none", source, released)
			}
			if pinned.unpinned.Load() {
				t.Errorf("the sends from %s left the pin", source)
			}
		})
	}
}

// a send from a pin another interface than the selection's holds releases the route before its write, and the next send naming the selection's releases it again
// the pin's reading stands for an address the host holds on another interface, while its datagram still leaves by lo0
func TestDarwinPinOnAnotherInterfaceReleasesAroundItsSend(t *testing.T) {
	loopback, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range loopbackFamilies {
		t.Run(family.network, func(t *testing.T) {
			selection := newTestSelection(loopback.Index)
			l := overLoopback(t, family.network, family.loopback, selection)
			selected := &darwinEndpoint{addr: l.to}
			source := netip.MustParseAddr(family.loopback)
			pinned := pinnedEndpoint(l.to, source, 0)
			other := loopback.Index + 1
			pinned.holder.Store(&pinHolder{generation: selection.Generation(), index: other, control: pinned.control, fragmentingControl: pinned.fragmentingControl})
			l.send(t, selected, "the first send", netip.Addr{})
			for _, step := range []struct {
				name string
				ep   *darwinEndpoint
			}{
				{"a send from a pin interface " + strconv.Itoa(other) + " holds", pinned},
				{"a send naming lo0", selected},
			} {
				l.released.Store(0)
				l.send(t, step.ep, step.name, netip.Addr{})
				if released := l.released.Load(); released != 1 {
					t.Errorf("%s after a send keyed otherwise released the route %d times, want once", step.name, released)
				}
			}
		})
	}
}

// a send from an IPv6 pin past lo0's MTU is refused for its size while its endpoint keeps DF,
// and leaves in fragments that reach the peer whole from the pin while its endpoint fragments
func TestDarwinPinnedSendFragmentsWhileItsEndpointDoes(t *testing.T) {
	loopback, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Fatal(err)
	}
	l := overLoopback(t, "udp6", "::1", newTestSelection(loopback.Index))
	source := netip.MustParseAddr("::1")
	pinned := pinnedEndpoint(l.to, source, 0)
	datagram := make([]byte, loopback.MTU+pastLoopback)
	err = l.bind.Send([][]byte{datagram}, pinned)
	if report, ok := err.(*PathMTUError); !ok || report.MTU != loopback.MTU {
		t.Fatalf("a send of %d bytes from %s past lo0's MTU answered %v, want the report of its %d", len(datagram), source, err, loopback.MTU)
	}
	pinned.fragments.Store(true)
	if err := l.bind.Send([][]byte{datagram}, pinned); err != nil {
		t.Fatalf("a send of %d bytes from %s past lo0's MTU while its endpoint fragments: %v", len(datagram), source, err)
	}
	if from := readFrom(t, l.peer, datagram); from.Addr() != source {
		t.Errorf("the datagram reached the peer from %s, want %s", from.Addr(), source)
	}
	if pinned.unpinned.Load() {
		t.Errorf("the sends from %s left the pin", source)
	}
}

// a send from an IPv6 pin whose holder names an interface gone since it was read, which darwin refuses with ENXIO,
// falls back to the kernel's source by the selection's interface and leaves the pin
func TestDarwinPinOnAGoneInterfaceFallsBack(t *testing.T) {
	loopback, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Fatal(err)
	}
	selection := newTestSelection(loopback.Index)
	l := overLoopback(t, "udp6", "::1", selection)
	source := netip.MustParseAddr("::1")
	pinned := pinnedEndpoint(l.to, source, 0)
	control := (&ipv6.ControlMessage{Src: source.AsSlice(), IfIndex: goneIndex}).Marshal()
	pinned.holder.Store(&pinHolder{generation: selection.Generation(), index: goneIndex, control: control, fragmentingControl: control})
	l.send(t, pinned, "from a pin on an interface gone", source)
	if !pinned.unpinned.Load() {
		t.Errorf("the send from %s naming interface %d, which the host does not have, kept the pin", source, goneIndex)
	}
}

// a send from a pin no interface holds releases the route before its write, whatever interface the send before it named or none,
// so the kernel refuses the pin and the send falls back to the kernel's source, which releases it again
func TestDarwinPinNoInterfaceHoldsReleasesBeforeItsSend(t *testing.T) {
	loopback, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range loopbackFamilies {
		gone := family.gone
		for _, hub := range []struct {
			name      string
			selection Selection
		}{
			{"no selection", nil},
			{"a selection naming lo0", newTestSelection(loopback.Index)},
		} {
			t.Run(family.network+", "+hub.name, func(t *testing.T) {
				l := overLoopback(t, family.network, family.loopback, hub.selection)
				l.send(t, &darwinEndpoint{addr: l.to}, "the first send", netip.Addr{})
				l.released.Store(0)
				pinned := pinnedEndpoint(l.to, gone, 0)
				l.send(t, pinned, "from a pin no interface holds", netip.MustParseAddr(family.loopback))
				if !pinned.unpinned.Load() {
					t.Errorf("the send to %s kept the pin %s, which no interface holds", l.to, gone)
				}
				if released := l.released.Load(); released != 2 {
					t.Errorf("the send from %s and its fallback released the route %d times, want twice", gone, released)
				}
			})
		}
	}
}

// the host's addresses are read once per selection generation whatever the count of fresh endpoints answered from one of them,
// and an endpoint's pin is read again at a new generation, so a pin whose address moved to another interface is keyed on that one from then on
// the record, the path MTU and the debug view take the pin's interface from that reading
func TestDarwinHostAddressesAreReadOncePerGeneration(t *testing.T) {
	loopback, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range loopbackFamilies {
		t.Run(family.network, func(t *testing.T) {
			selection := newTestSelection(loopback.Index)
			l := overLoopback(t, family.network, family.loopback, selection)
			source := netip.MustParseAddr(family.loopback)
			holder, reads := loopback.Index, 0
			l.bind.readHeld = func() (map[netip.Addr]int, error) {
				reads++
				return map[netip.Addr]int{source: holder}, nil
			}
			pinned := pinnedEndpoint(l.to, source, 0)
			l.send(t, pinned, "an answer", source)
			for range answersPerGeneration {
				l.send(t, pinnedEndpoint(l.to, source, 0), "an answer from a fresh endpoint", source)
			}
			if reads != 1 {
				t.Errorf("%d answers from %s under one generation read the host's addresses %d times, want once", answersPerGeneration+1, source, reads)
			}
			// the address moves to another interface, which the selection's next generation follows
			moved := loopback.Index + 1
			holder = moved
			if index := l.bind.pinInterface(pinned); index != loopback.Index {
				t.Errorf("the pin %s is held by interface %d under the generation it was read in, want that reading's lo0 %d", source, index, loopback.Index)
			}
			selection.move(loopback.Index)
			if index := l.bind.pinInterface(pinned); index != moved {
				t.Errorf("the pin %s is held by interface %d after a new generation, want %d", source, index, moved)
			}
			if reads != 2 {
				t.Errorf("a new generation read the host's addresses %d times in all, want twice", reads)
			}
			if key := l.bind.pinned(pinned).key(); key != int64(moved) {
				t.Errorf("a send from the pin %s is keyed %d, want %d", source, key, moved)
			}
			if index, err := l.bind.sendInterface(pinned); err != nil || index != moved {
				t.Errorf("the path MTU of the pin %s is read on interface %d, %v, want %d", source, index, err, moved)
			}
			if _, index := l.bind.sendKey(pinned); index != moved {
				t.Errorf("the sends from the pin %s name interface %d, want %d", source, index, moved)
			}
		})
	}
}

// askedSelection is a testSelection that keeps the addresses it answers for
type askedSelection struct {
	*testSelection
	addrs []netip.Addr
}

func (s *askedSelection) Interface(addr netip.Addr) (int, uint64) {
	s.addrs = append(s.addrs, addr)
	return s.testSelection.Interface(addr)
}

// a link-local destination whose zone names its interface by name is asked of the selection by that interface's index,
// read at the endpoint's first answer and kept for each later generation's, so no later answer looks the name up
func TestDarwinSelectionIsAskedForAZoneByIndex(t *testing.T) {
	loopback, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Fatal(err)
	}
	selection := &askedSelection{testSelection: newTestSelection(loopback.Index)}
	bind := &darwinBind{selection: selection}
	ep := &darwinEndpoint{addr: netip.AddrPortFrom(netip.MustParseAddr("fe80::1").WithZone(loopback.Name), underlayPort)}
	bind.selectedFor(ep)
	// the endpoint's zone then names no interface, which a lookup at the next generation would read
	ep.addr = netip.AddrPortFrom(ep.addr.Addr().WithZone("gone0"), ep.addr.Port())
	selection.move(loopback.Index)
	bind.selectedFor(ep)
	want := strconv.Itoa(loopback.Index)
	for i, addr := range selection.addrs {
		if addr.Zone() != want {
			t.Errorf("answer %d of the selection was for the zone %q, want lo0's index %s", i, addr.Zone(), want)
		}
	}
	if len(selection.addrs) != 2 {
		t.Errorf("two generations asked the selection %d times, want twice", len(selection.addrs))
	}
}

// heldPeer and heldSource are the peer and the pin of the tests that answer the host's addresses in place of darwin
var heldPeer, heldSource = netip.MustParseAddrPort("[2001:db8::1]:4500"), netip.MustParseAddr("2001:db8::7")

// a read of the host's addresses that fails keys that send apart and is not kept, so the next send from the pin under the same generation reads them again
func TestDarwinFailedReadOfTheHostAddressesIsReadAgain(t *testing.T) {
	const holder = 7
	reads := 0
	bind := &darwinBind{selection: newTestSelection(holder), readHeld: func() (map[netip.Addr]int, error) {
		reads++
		if reads == 1 {
			return nil, errors.New("the dump failed")
		}
		return map[netip.Addr]int{heldSource: holder}, nil
	}}
	ep := pinnedEndpoint(heldPeer, heldSource, 0)
	if key := bind.pinned(ep).key(); key != unheldPin {
		t.Errorf("a send from %s after a failed read is keyed %d, want %d", heldSource, key, unheldPin)
	}
	if key := bind.pinned(ep).key(); key != holder || reads != 2 {
		t.Errorf("the next send from %s is keyed %d after %d reads, want %d after 2", heldSource, key, reads, holder)
	}
}

// senders that find the host's addresses stale take one read of them, a second waiting for the read the first is inside,
// and their answers from one address share the one holder that read built
func TestDarwinSendersThatFindTheHostAddressesStaleTakeOneRead(t *testing.T) {
	var reads atomic.Int64
	inside, release := make(chan struct{}), make(chan struct{})
	bind := &darwinBind{selection: newTestSelection(7), readHeld: func() (map[netip.Addr]int, error) {
		if reads.Add(1) == 1 {
			close(inside)
			<-release
		}
		return map[netip.Addr]int{heldSource: 7}, nil
	}}
	first, second := make(chan *pinHolder), make(chan *pinHolder)
	go func() { first <- bind.pinned(pinnedEndpoint(heldPeer, heldSource, 0)) }()
	<-inside
	go func() { second <- bind.pinned(pinnedEndpoint(heldPeer, heldSource, 0)) }()
	time.Sleep(staleReadWait)
	close(release)
	a, b := <-first, <-second
	if got := reads.Load(); got != 1 {
		t.Errorf("two senders that found the host's addresses stale read them %d times, want once", got)
	}
	if a != b {
		t.Errorf("two answers from %s go by holders of their own, %+v and %+v, want one", heldSource, a, b)
	}
}

// a hub with no selection reads the host's addresses at each fresh endpoint's first send, so a pin whose address moved is keyed on its new interface
func TestDarwinHubWithNoSelectionReadsTheHostAddressesAtEachAsk(t *testing.T) {
	holder, reads := 7, 0
	bind := &darwinBind{readHeld: func() (map[netip.Addr]int, error) {
		reads++
		return map[netip.Addr]int{heldSource: holder}, nil
	}}
	for _, moved := range []int{7, 8} {
		holder = moved
		if key := bind.pinned(pinnedEndpoint(heldPeer, heldSource, 0)).key(); key != int64(moved) {
			t.Errorf("a fresh endpoint from %s, which interface %d holds, is keyed %d", heldSource, moved, key)
		}
	}
	if reads != 2 {
		t.Errorf("two fresh endpoints on a hub with no selection read the host's addresses %d times, want twice", reads)
	}
}
