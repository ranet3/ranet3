// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"time"
)

// DefaultRoute is the host's own default route of one family, the zero value where it has none
// Gateway is invalid where the route leaves through a link
type DefaultRoute struct {
	Interface string
	Gateway   netip.Addr
}

// NetworkFamily holds the default and the addresses the paths of one family off this host leave by
// Addresses holds the global unicast addresses of the up interfaces outside the mesh, sorted and each once
// Links holds each of those interfaces by name, sorted and each once, with its global unicast addresses of the family, and is empty on darwin
type NetworkFamily struct {
	Default   DefaultRoute
	Addresses []netip.Addr
	Links     []Link
}

// Link is one up interface outside the mesh, with the addresses of one family it carries
// each prefix is an address under the length of the network it is on, sorted and each once
// Peers is the far end of each point-to-point address, a network main routes by the link that holds none of its addresses, sorted and each once
type Link struct {
	Name     string
	Prefixes []netip.Prefix
	Peers    []netip.Prefix
}

// sameLinks compares two link lists, each sorted as the reader gives one
func sameLinks(a, b []Link) bool {
	return slices.EqualFunc(a, b, func(x, y Link) bool {
		return x.Name == y.Name && slices.Equal(x.Prefixes, y.Prefixes) && slices.Equal(x.Peers, y.Peers)
	})
}

// NetworkState is the host's network outside the mesh
type NetworkState struct {
	IPv4, IPv6 NetworkFamily
}

// NetworkChange is one change the watch signaled, from the state it last signaled to the one it read
type NetworkChange struct {
	At            time.Time
	Before, After NetworkState
}

// FamilyChange lists the moves in one family
type FamilyChange struct {
	Family                      Family
	DefaultBefore, DefaultAfter DefaultRoute
	Added, Removed              []netip.Addr
	LinksBefore, LinksAfter     []Link
}

// DefaultMoved reports whether the family's default route is another one now
func (c FamilyChange) DefaultMoved() bool { return c.DefaultBefore != c.DefaultAfter }

// PathMoved reports whether the default or the addresses moved, which can break or heal a session's path
// a link that comes or goes, or a network's length, moves none of them
func (c FamilyChange) PathMoved() bool {
	return c.DefaultMoved() || len(c.Added) > 0 || len(c.Removed) > 0
}

// LinksMoved reports whether a link came, went, or moved a prefix or a far end
func (c FamilyChange) LinksMoved() bool { return !sameLinks(c.LinksBefore, c.LinksAfter) }

// Families is one entry for each family where anything moved
func (c NetworkChange) Families() []FamilyChange {
	var out []FamilyChange
	if change, moved := diffFamily(FamilyIPv4, c.Before.IPv4, c.After.IPv4); moved {
		out = append(out, change)
	}
	if change, moved := diffFamily(FamilyIPv6, c.Before.IPv6, c.After.IPv6); moved {
		out = append(out, change)
	}
	return out
}

// diffFamily walks the two sorted address lists once
func diffFamily(family Family, before, after NetworkFamily) (FamilyChange, bool) {
	change := FamilyChange{Family: family, DefaultBefore: before.Default, DefaultAfter: after.Default, LinksBefore: before.Links, LinksAfter: after.Links}
	old, now := before.Addresses, after.Addresses
	for len(old) > 0 || len(now) > 0 {
		switch {
		case len(now) == 0 || len(old) > 0 && old[0].Less(now[0]):
			change.Removed, old = append(change.Removed, old[0]), old[1:]
		case len(old) == 0 || now[0].Less(old[0]):
			change.Added, now = append(change.Added, now[0]), now[1:]
		default:
			old, now = old[1:], now[1:]
		}
	}
	return change, change.PathMoved() || change.LinksMoved()
}

// addressSet sorts addresses and keeps each once, the form diffFamily walks
func addressSet(addresses []netip.Addr) []netip.Addr {
	slices.SortFunc(addresses, netip.Addr.Compare)
	return slices.Compact(addresses)
}

// NetworkWatch says when the host's defaults, its addresses or its links outside the mesh changed
// a notification starts a settle window, and the state read after it is signaled only where it differs from the last one signaled
type NetworkWatch struct {
	notify <-chan struct{}
	// read takes the state through what the platform opened, and only the watch's own goroutine calls it after the first read
	read    func() (NetworkState, error)
	release func() error
	changes chan NetworkChange
	stop    chan struct{}
	done    chan struct{}
	closing sync.Once

	mu      sync.Mutex
	current NetworkState
	last    NetworkChange
}

// newNetworkWatch reads the state once and follows notify from there
// it takes over release, which it calls when the first read fails or when the watch closes
func newNetworkWatch(notify <-chan struct{}, read func() (NetworkState, error), release func() error) (*NetworkWatch, error) {
	current, err := read()
	if err != nil {
		_ = release()
		return nil, err
	}
	w := &NetworkWatch{
		notify: notify, read: read, release: release,
		changes: make(chan NetworkChange, 1),
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
		current: current,
	}
	go w.run()
	return w, nil
}

// Changes carries each change the watch signals
// a change the reader has not taken yet is merged with the next, so it always starts from the last state the reader saw
func (w *NetworkWatch) Changes() <-chan NetworkChange { return w.changes }

// State is the network as the watch last read it and the last change it signaled, zero before the first
func (w *NetworkWatch) State() (NetworkState, NetworkChange) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.current, w.last
}

// Close stops the watch and releases what the platform opened, and a second call does nothing
func (w *NetworkWatch) Close() error {
	var err error
	w.closing.Do(func() {
		close(w.stop)
		<-w.done
		err = w.release()
	})
	return err
}

func (w *NetworkWatch) run() {
	defer close(w.done)
	signaled := w.current
	for {
		select {
		case <-w.stop:
			return
		case <-w.notify:
		}
		if !settle(w.notify, w.stop, watchSettle) {
			return
		}
		state, err := w.read()
		if err != nil {
			slog.Warn("kernel could not read the host's network after a change", "err", err)
			continue
		}
		w.mu.Lock()
		w.current = state
		w.mu.Unlock()
		change := NetworkChange{At: time.Now(), Before: signaled, After: state}
		if len(change.Families()) == 0 {
			continue
		}
		signaled = state
		w.mu.Lock()
		w.last = change
		w.mu.Unlock()
		w.deliver(change)
	}
}

// settle waits out delay from the first notification of a change, taking the notifications that arrive meanwhile,
// and reports false once stop closes
func settle(notify, stop <-chan struct{}, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	for {
		select {
		case <-stop:
			return false
		case <-notify:
		case <-timer.C:
			return true
		}
	}
}

// deliver never blocks, since run is the only sender and takes back a change still waiting first
// a change that undoes the waiting one leaves nothing to deliver
func (w *NetworkWatch) deliver(change NetworkChange) {
	select {
	case waiting := <-w.changes:
		change.Before = waiting.Before
	default:
	}
	if len(change.Families()) > 0 {
		w.changes <- change
	}
}
