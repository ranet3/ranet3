// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"
)

// quietWindow is how long a test waits to be sure the watch signals nothing
// the settle window and a read are over well inside it
const quietWindow = 4 * watchSettle

// burstGap is how far into a settle window a test makes its second change
// a watch without the window has read the first change well before it
const burstGap = watchSettle / 4

func addrs(list ...string) []netip.Addr {
	out := make([]netip.Addr, 0, len(list))
	for _, s := range list {
		out = append(out, netip.MustParseAddr(s))
	}
	return addressSet(out)
}

// each family's default and addresses are compared on their own, and only what moved is reported
func TestNetworkChangeReportsWhatMovedPerFamily(t *testing.T) {
	wifi := DefaultRoute{Interface: "en0", Gateway: netip.MustParseAddr("192.168.1.1")}
	before := NetworkState{
		IPv4: NetworkFamily{Default: wifi, Addresses: addrs("192.168.1.20")},
		IPv6: NetworkFamily{Addresses: addrs("2001:db8::20")},
	}
	if moved := (NetworkChange{Before: before, After: before}).Families(); moved != nil {
		t.Errorf("one state against itself moved %+v", moved)
	}
	after := before
	after.IPv4 = NetworkFamily{
		Default:   DefaultRoute{Interface: "en7", Gateway: netip.MustParseAddr("10.0.0.1")},
		Addresses: addrs("10.0.0.20", "192.168.1.20"),
	}
	moved := NetworkChange{Before: before, After: after}.Families()
	if len(moved) != 1 || moved[0].Family != FamilyIPv4 {
		t.Fatalf("a move of IPv4 alone reported %+v", moved)
	}
	if !moved[0].DefaultMoved() || moved[0].DefaultBefore != wifi || moved[0].DefaultAfter.Interface != "en7" {
		t.Errorf("the default moved as %+v", moved[0])
	}
	if !slices.Equal(moved[0].Added, addrs("10.0.0.20")) || moved[0].Removed != nil {
		t.Errorf("the addresses moved as added %v removed %v", moved[0].Added, moved[0].Removed)
	}
}

// scriptedHost is a host whose state a test sets, read the way a platform's reader is
type scriptedHost struct {
	mu    sync.Mutex
	state NetworkState
}

func (h *scriptedHost) set(state NetworkState) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.state = state
}

func (h *scriptedHost) read() (NetworkState, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.state, nil
}

func withAddress(address string) NetworkState {
	return NetworkState{IPv4: NetworkFamily{Addresses: addrs(address)}}
}

// a notification that leaves the state as it was signals nothing, and one that moves it signals once
// a change the reader has not taken yet is merged with the next, and one the next undoes goes
// changes inside one settle window signal once, from before the first to after the last
func TestNetworkWatchSignalsOnlyAMovedState(t *testing.T) {
	first, second, third, fourth := withAddress("192.0.2.1"), withAddress("192.0.2.2"), withAddress("192.0.2.3"), withAddress("192.0.2.4")
	host := &scriptedHost{state: first}
	notify := make(chan struct{}, 1)
	w, err := newNetworkWatch(notify, host.read, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	poke := func() {
		select {
		case notify <- struct{}{}:
		default:
		}
	}
	quiet := func(step string) {
		t.Helper()
		select {
		case change := <-w.Changes():
			t.Fatalf("%s signaled %+v", step, change)
		case <-time.After(quietWindow):
		}
	}
	signaled := func(step string, before, after NetworkState) {
		t.Helper()
		select {
		case change := <-w.Changes():
			if !slices.Equal(change.Before.IPv4.Addresses, before.IPv4.Addresses) || !slices.Equal(change.After.IPv4.Addresses, after.IPv4.Addresses) {
				t.Fatalf("%s signaled %v to %v, want %v to %v", step, change.Before.IPv4.Addresses, change.After.IPv4.Addresses,
					before.IPv4.Addresses, after.IPv4.Addresses)
			}
		case <-time.After(quietWindow):
			t.Fatalf("%s signaled nothing", step)
		}
	}
	// lastIs waits until the watch has signaled after, whether or not anything took it
	lastIs := func(after NetworkState) {
		t.Helper()
		waitFor(t, func() bool {
			_, last := w.State()
			return slices.Equal(last.After.IPv4.Addresses, after.IPv4.Addresses)
		})
	}

	poke()
	quiet("a notification leaving the state alone")
	host.set(second)
	poke()
	signaled("a new address", first, second)
	if current, last := w.State(); !slices.Equal(current.IPv4.Addresses, second.IPv4.Addresses) || last.At.IsZero() {
		t.Errorf("the watch reports %v and a last change at %v", current.IPv4.Addresses, last.At)
	}
	poke()
	quiet("a repeated notification")

	host.set(third)
	poke()
	lastIs(third)
	host.set(fourth)
	poke()
	lastIs(fourth)
	signaled("two changes nothing took between", second, fourth)

	host.set(first)
	poke()
	lastIs(first)
	host.set(fourth)
	poke()
	lastIs(fourth)
	quiet("a change undone before anything took it")

	host.set(second)
	poke()
	time.Sleep(burstGap)
	host.set(third)
	poke()
	// the last change records each read before deliver merges it into one still waiting
	lastIs(third)
	if _, last := w.State(); !slices.Equal(last.Before.IPv4.Addresses, fourth.IPv4.Addresses) {
		t.Fatalf("the burst was read in two, the last change starts at %v", last.Before.IPv4.Addresses)
	}
	signaled("a burst inside one settle window", fourth, third)
	quiet("the rest of the burst")
}

// a watch closes once however often it is asked, and releases what the platform opened
func TestNetworkWatchClosesOnce(t *testing.T) {
	released := 0
	w, err := newNetworkWatch(make(chan struct{}), (&scriptedHost{}).read, func() error { released++; return nil })
	if err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	_ = w.Close()
	if released != 1 {
		t.Errorf("two closes released %d times", released)
	}
}
