// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"errors"
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
// each queued failure fails one read, and a standing failure fails every read while it is set
type scriptedHost struct {
	mu       sync.Mutex
	state    NetworkState
	failures []error
	standing error
	reads    int
}

func (h *scriptedHost) set(state NetworkState) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.state = state
}

func (h *scriptedHost) fail(err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.failures = append(h.failures, err)
}

func (h *scriptedHost) failEvery(err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.standing = err
}

func (h *scriptedHost) readCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.reads
}

func (h *scriptedHost) read() (NetworkState, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.reads++
	if h.standing != nil {
		return NetworkState{}, h.standing
	}
	if len(h.failures) > 0 {
		err := h.failures[0]
		h.failures = h.failures[1:]
		return NetworkState{}, err
	}
	return h.state, nil
}

// errScriptedRead is a read of the host that failed, as a dump the kernel could not allocate fails
var errScriptedRead = errors.New("kernel: dump addresses: no buffer space available")

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

// a link that comes up with no address, a network's length that moves under the same address, and a far end that moves under the same local
// address each signal though the default and the addresses stay
// the reconciler derives rules from the links, so a change holding links alone reaches the reader
func TestNetworkWatchSignalsALinkAlone(t *testing.T) {
	uplink := NetworkFamily{Addresses: addrs("198.51.100.10"), Links: []Link{{Name: "eth0", Prefixes: []netip.Prefix{netip.MustParsePrefix("198.51.100.10/24")}}}}
	first := NetworkState{IPv4: uplink}
	bridged := first
	bridged.IPv4.Links = append(slices.Clone(uplink.Links), Link{Name: "veth1"})
	narrowed := first
	narrowed.IPv4.Links = []Link{{Name: "eth0", Prefixes: []netip.Prefix{netip.MustParsePrefix("198.51.100.10/25")}}}
	pointToPoint := first
	pointToPoint.IPv4.Links = []Link{{Name: "eth0", Prefixes: []netip.Prefix{netip.MustParsePrefix("198.51.100.10/32")}, Peers: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/28")}}}
	farEndMoved := first
	farEndMoved.IPv4.Links = []Link{{Name: "eth0", Prefixes: []netip.Prefix{netip.MustParsePrefix("198.51.100.10/32")}, Peers: []netip.Prefix{netip.MustParsePrefix("203.0.113.16/28")}}}
	host := &scriptedHost{state: first}
	notify := make(chan struct{}, 1)
	w, err := newNetworkWatch(notify, host.read, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	for _, step := range []struct {
		name  string
		state NetworkState
	}{{"a link with no address", bridged}, {"the link gone", first}, {"a network's length", narrowed}, {"a point-to-point far end", pointToPoint}, {"the far end alone", farEndMoved}} {
		host.set(step.state)
		notify <- struct{}{}
		select {
		case change := <-w.Changes():
			moved := change.Families()
			if len(moved) != 1 || moved[0].PathMoved() || !moved[0].LinksMoved() || !sameLinks(moved[0].LinksAfter, step.state.IPv4.Links) {
				t.Errorf("%s signaled %+v", step.name, moved)
			}
		case <-time.After(quietWindow):
			t.Fatalf("%s signaled nothing", step.name)
		}
	}
}

// a read that fails is read again on the backoff, and the change it missed is signaled once a read succeeds
// nothing else wakes the watch here, as nothing does after a move that has settled
func TestNetworkWatchReadsAgainAfterAFailedRead(t *testing.T) {
	first, second := withAddress("192.0.2.1"), withAddress("192.0.2.2")
	host := &scriptedHost{state: first}
	notify := make(chan struct{}, 1)
	w, err := newNetworkWatch(notify, host.read, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	host.fail(errScriptedRead)
	host.set(second)
	notify <- struct{}{}
	select {
	case change := <-w.Changes():
		if !slices.Equal(change.Before.IPv4.Addresses, first.IPv4.Addresses) || !slices.Equal(change.After.IPv4.Addresses, second.IPv4.Addresses) {
			t.Errorf("the change read again went from %v to %v", change.Before.IPv4.Addresses, change.After.IPv4.Addresses)
		}
	case <-time.After(minRetryInterval + quietWindow):
		t.Fatalf("a change whose first read failed was not signaled within a retry, after %d reads", host.readCount())
	}
	if current, _ := w.State(); !slices.Equal(current.IPv4.Addresses, second.IPv4.Addresses) {
		t.Errorf("the watch reads %v after the retry", current.IPv4.Addresses)
	}
}

// backoffWindow is how long a test counts the reads of a host whose every read fails
const backoffWindow = 9 * minRetryInterval / 2

// maxReadsIn bounds from above the reads a window holds of a source read immediate times with no wait and then on a backoff
// doubling from minRetryInterval, as the immediate reads plus one for each doubling no longer than the window on its own
func maxReadsIn(window time.Duration, immediate int) int {
	reads := immediate
	for wait := minRetryInterval; wait <= window; wait *= 2 {
		reads++
	}
	return reads
}

// a host whose every read fails is read on a backoff doubling from minRetryInterval, notifications or not
func TestNetworkWatchBacksOffWhileReadsFail(t *testing.T) {
	host := &scriptedHost{state: withAddress("192.0.2.1")}
	notify := make(chan struct{}, 1)
	w, err := newNetworkWatch(notify, host.read, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	host.failEvery(errScriptedRead)
	notify <- struct{}{}
	waitFor(t, func() bool { return host.readCount() >= 2 })
	failed := host.readCount()
	for end := time.Now().Add(backoffWindow); time.Now().Before(end); time.Sleep(burstGap) {
		select {
		case notify <- struct{}{}:
		default:
		}
	}
	if reads, limit := host.readCount()-failed+1, maxReadsIn(backoffWindow, 1); reads > limit {
		t.Errorf("a host failing every read was read %d times in %v, want at most %d", reads, backoffWindow, limit)
	}
}

// a streak of failed reads that ended leaves no backoff behind, so a later streak reads again after minRetryInterval and not after
// the longer backoff the first streak doubled to
func TestNetworkWatchStartsItsBackoffOverAfterARead(t *testing.T) {
	first, second, third := withAddress("192.0.2.1"), withAddress("192.0.2.2"), withAddress("192.0.2.3")
	host := &scriptedHost{state: first}
	notify := make(chan struct{}, 1)
	w, err := newNetworkWatch(notify, host.read, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	host.fail(errScriptedRead)
	host.fail(errScriptedRead)
	host.set(second)
	notify <- struct{}{}
	select {
	case <-w.Changes():
	case <-time.After(3*minRetryInterval + quietWindow):
		t.Fatalf("a change whose first two reads failed was not signaled within two retries, after %d reads", host.readCount())
	}
	host.fail(errScriptedRead)
	host.set(third)
	notify <- struct{}{}
	select {
	case change := <-w.Changes():
		if !slices.Equal(change.After.IPv4.Addresses, third.IPv4.Addresses) {
			t.Errorf("the later streak's read again signaled the addresses %v", change.After.IPv4.Addresses)
		}
	case <-time.After(minRetryInterval + quietWindow):
		t.Fatal("a later streak's first read again waited out the backoff of the streak before it")
	}
}

// closeBudget is how soon Close returns while the watch or a monitor waits out a backoff, well under its first delay
const closeBudget = minRetryInterval / 4

// Close ends the wait for a retry at once, and the watch's goroutine ends with it
func TestNetworkWatchClosesWhileRetrying(t *testing.T) {
	host := &scriptedHost{state: withAddress("192.0.2.1")}
	notify := make(chan struct{}, 1)
	released := 0
	w, err := newNetworkWatch(notify, host.read, func() error { released++; return nil })
	if err != nil {
		t.Fatal(err)
	}
	host.failEvery(errScriptedRead)
	notify <- struct{}{}
	// each failure leaves the watch waiting out a backoff of at least minRetryInterval, which Close must end at once
	waitFor(t, func() bool { return host.readCount() >= 3 })
	closed := make(chan error, 1)
	go func() { closed <- w.Close() }()
	select {
	case <-closed:
	case <-time.After(closeBudget):
		t.Fatalf("Close waited out the backoff, more than %v", closeBudget)
	}
	select {
	case <-w.done:
	default:
		t.Error("the watch's goroutine still runs after Close returned")
	}
	if released != 1 {
		t.Errorf("Close released %d times", released)
	}
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
