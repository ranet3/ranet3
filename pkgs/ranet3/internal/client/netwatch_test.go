// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/ike"
	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/transport"
)

// networkChangeBudget bounds how long one change takes to reach the sessions, the dialers and the bus
// and how long a busy peer takes to get a socket connected to it
const networkChangeBudget = 5 * time.Second

// busyDatagrams of busyDatagram bytes carry a peer past the 1 MiB at which the transport connects a socket to it
const (
	busyDatagrams = 1000
	busyDatagram  = 1200
)

// recordingHub is a hub on loopback whose events go to bus
func recordingHub(t *testing.T, bus *events.Bus) *transport.Hub {
	t.Helper()
	hub, err := transport.NewHub("127.0.0.1:0", transport.Underlay{}, transport.Runtime{Events: func(kind string, attrs ...slog.Attr) {
		bus.Emit(kind, "", attrs...)
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	return hub
}

// busyPeer is a mux of hub to a peer of its own on loopback, sent enough that the hub connects a socket to the peer
// it waits until bus records that socket
func busyPeer(t *testing.T, hub *transport.Hub, bus *events.Bus) *transport.Mux {
	t.Helper()
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	at := peer.LocalAddr().(*net.UDPAddr)
	mux, err := hub.NewMux(at.IP, at.Port)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mux.Close() })
	busy := make([][]byte, busyDatagrams)
	for i := range busy {
		busy[i] = make([]byte, busyDatagram)
	}
	if err := mux.SendESPBatch(busy); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(networkChangeBudget); len(recorded(bus, "transport.pair.connected")) == 0; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("%d bytes to %s connected no socket to it", busyDatagrams*busyDatagram, at)
		}
	}
	return mux
}

// fakeNetwork is a watch whose changes a test sends and whose reading it sets
type fakeNetwork struct {
	changes chan kernel.NetworkChange
	current kernel.NetworkState
	last    kernel.NetworkChange
}

func (f *fakeNetwork) Changes() <-chan kernel.NetworkChange { return f.changes }

func (f *fakeNetwork) State() (kernel.NetworkState, kernel.NetworkChange) {
	return f.current, f.last
}

func (f *fakeNetwork) Close() error { return nil }

// a change of the host's network asks every session to prove its path and sets every dialer going at once
// the change is recorded with what moved and how many it reached
func TestNetworkChangeProbesEverySessionAndWakesEveryDialer(t *testing.T) {
	c := writable(t)
	c.events = events.New()
	c.hub = recordingHub(t, c.events)
	var probedMu sync.Mutex
	var probed []*ike.Session
	c.sessions.probe = func(sess *ike.Session) {
		probedMu.Lock()
		defer probedMu.Unlock()
		probed = append(probed, sess)
	}
	c.sessions.active = func(*ike.Session) bool { return true }
	sessions := []*ike.Session{{}, {}}
	c.sessions.adoptPreferred("example/gateway:1@0", sessions[0], true, nil)
	c.sessions.adoptPreferred("example/inbound:1@0", sessions[1], true, nil)
	dialers := []*dialer{{cancel: func() {}, wake: make(chan struct{}, 1)}, {cancel: func() {}, wake: make(chan struct{}, 1)}}
	c.dialers["example/gateway:1@0"] = dialers[0]
	c.dialers["example/elsewhere:1@0"] = dialers[1]

	network := &fakeNetwork{changes: make(chan kernel.NetworkChange, 1)}
	c.network = network
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.followNetwork(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	wifi := kernel.DefaultRoute{Interface: "en0", Gateway: netip.MustParseAddr("192.168.1.1")}
	network.changes <- kernel.NetworkChange{
		At:     time.Now(),
		Before: kernel.NetworkState{IPv4: kernel.NetworkFamily{Default: wifi, Addresses: []netip.Addr{netip.MustParseAddr("192.168.1.20")}}},
		After:  kernel.NetworkState{IPv4: kernel.NetworkFamily{Default: kernel.DefaultRoute{Interface: "en7"}, Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.20")}}},
	}
	deadline := time.Now().Add(networkChangeBudget)
	for len(recorded(c.events, "network.changed")) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the change was never recorded")
		}
		time.Sleep(time.Millisecond)
	}

	probedMu.Lock()
	got := slices.Clone(probed)
	probedMu.Unlock()
	if len(got) != 2 || !slices.Contains(got, sessions[0]) || !slices.Contains(got, sessions[1]) {
		t.Errorf("the change probed %d sessions, want both", len(got))
	}
	for i, dialer := range dialers {
		select {
		case <-dialer.wake:
		default:
			t.Errorf("dialer %d was not woken, so it waits out its reconnect delay", i)
		}
	}
	event := recorded(c.events, "network.changed")[0]
	for key, want := range map[string]string{
		"ipv4_default":     "en7",
		"ipv4_default_was": "en0 via 192.168.1.1",
		"ipv4_added":       "10.0.0.20",
		"ipv4_removed":     "192.168.1.20",
		"probed":           "2",
		"woken":            "2",
	} {
		if event.Attrs[key] != want {
			t.Errorf("the event carries %s=%q, want %q (all %v)", key, event.Attrs[key], want, event.Attrs)
		}
	}
	if _, ok := event.Attrs["ipv6_default"]; ok {
		t.Errorf("a change to IPv4 alone recorded IPv6 as well: %v", event.Attrs)
	}
}

// a change holding links alone, a container's bridge coming up, wakes the route reconciler and probes no session, wakes no dialer and closes no socket
// a point-to-point far end moving alone is named among the links that changed
// a change of the path that follows it wakes the reconciler again and probes every session
func TestLinkAloneWakesTheReconcilerAndProbesNoSession(t *testing.T) {
	c := writable(t)
	c.events = events.New()
	c.hub = recordingHub(t, c.events)
	busyPeer(t, c.hub, c.events)
	var probedMu sync.Mutex
	probed := 0
	c.sessions.probe = func(*ike.Session) {
		probedMu.Lock()
		defer probedMu.Unlock()
		probed++
	}
	c.sessions.active = func(*ike.Session) bool { return true }
	c.sessions.adoptPreferred("example/gateway:1@0", &ike.Session{}, true, nil)
	dialer := &dialer{cancel: func() {}, wake: make(chan struct{}, 1)}
	c.dialers["example/gateway:1@0"] = dialer
	wakes := make(chan struct{}, 2)
	c.SetReconcilerNetwork(func() { wakes <- struct{}{} })

	network := &fakeNetwork{changes: make(chan kernel.NetworkChange, 1)}
	c.network = network
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.followNetwork(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	uplink := kernel.NetworkFamily{
		Default:   kernel.DefaultRoute{Interface: "eth0"},
		Addresses: []netip.Addr{netip.MustParseAddr("198.51.100.10")},
		Links:     []kernel.Link{{Name: "eth0", Prefixes: []netip.Prefix{netip.MustParsePrefix("198.51.100.10/24")}}, {Name: "veth9"}},
	}
	// a bridge comes, a container's link goes and the uplink's network narrows, its address kept
	bridged := uplink
	bridged.Links = []kernel.Link{{Name: "docker0"}, {Name: "eth0", Prefixes: []netip.Prefix{netip.MustParsePrefix("198.51.100.10/25")}}}
	recordedChanges := func(want int) []control.Event {
		t.Helper()
		for deadline := time.Now().Add(networkChangeBudget); len(recorded(c.events, "network.changed")) < want; time.Sleep(time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("%d changes were recorded, want %d", len(recorded(c.events, "network.changed")), want)
			}
		}
		return recorded(c.events, "network.changed")
	}
	woke := func(step string) {
		t.Helper()
		select {
		case <-wakes:
		case <-time.After(networkChangeBudget):
			t.Fatalf("%s did not wake the reconciler", step)
		}
	}

	network.changes <- kernel.NetworkChange{At: time.Now(), Before: kernel.NetworkState{IPv4: uplink}, After: kernel.NetworkState{IPv4: bridged}}
	woke("a link alone")
	event := recordedChanges(1)[0]
	probedMu.Lock()
	alone := probed
	probedMu.Unlock()
	if alone != 0 || event.Attrs["probed"] != "0" || event.Attrs["woken"] != "0" {
		t.Errorf("a link alone probed %d sessions and was recorded as %v", alone, event.Attrs)
	}
	for key, want := range map[string]string{"ipv4_links_added": "docker0", "ipv4_links_removed": "veth9", "ipv4_links_changed": "eth0"} {
		if event.Attrs[key] != want {
			t.Errorf("a change of links alone carries %s=%q, want %q (all %v)", key, event.Attrs[key], want, event.Attrs)
		}
	}
	select {
	case <-dialer.wake:
		t.Error("a link alone woke a dialer")
	default:
	}
	if open := c.hub.PairSockets(); open != 1 {
		t.Errorf("a link alone left %d sockets connected to one peer, want the one it had", open)
	}

	// a point-to-point link's far end moves, its local address kept
	pointToPoint := func(far string) kernel.NetworkState {
		family := bridged
		family.Links = append(slices.Clone(bridged.Links), kernel.Link{Name: "ppp0", Prefixes: []netip.Prefix{netip.MustParsePrefix("203.0.113.1/32")}, Peers: []netip.Prefix{netip.MustParsePrefix(far)}})
		return kernel.NetworkState{IPv4: family}
	}
	network.changes <- kernel.NetworkChange{At: time.Now(), Before: pointToPoint("203.0.113.16/28"), After: pointToPoint("203.0.113.32/28")}
	woke("a far end alone")
	if event := recordedChanges(2)[1]; event.Attrs["probed"] != "0" || event.Attrs["ipv4_links_changed"] != "ppp0" {
		t.Errorf("a far end alone was recorded as %v, want no session probed and ipv4_links_changed=ppp0", event.Attrs)
	}

	moved := bridged
	moved.Default = kernel.DefaultRoute{Interface: "docker0"}
	network.changes <- kernel.NetworkChange{At: time.Now(), Before: kernel.NetworkState{IPv4: bridged}, After: kernel.NetworkState{IPv4: moved}}
	woke("a default moving")
	if event := recordedChanges(3)[2]; event.Attrs["probed"] != "1" || event.Attrs["woken"] != "1" {
		t.Errorf("a default moving was recorded as %v, want one session probed and one dialer woken", event.Attrs)
	}
}

// the reconciler's runtime reads the network at each call, so a pass after a link comes derives its rules from the links as they are then
func TestKernelRuntimeReadsTheNetworkAtEachCall(t *testing.T) {
	c := writable(t)
	c.Mesh = netstack.NewRoutesOnly()
	eth0 := kernel.Link{Name: "eth0", Prefixes: []netip.Prefix{netip.MustParsePrefix("198.51.100.10/24")}}
	network := &fakeNetwork{current: kernel.NetworkState{IPv4: kernel.NetworkFamily{Links: []kernel.Link{eth0}}}}
	c.network = network
	read := c.KernelRuntime().Network
	if got := read().IPv4.Links; !slices.EqualFunc(got, []kernel.Link{eth0}, sameLink) {
		t.Fatalf("the first call read the links %v, want eth0 alone", got)
	}
	bridged := []kernel.Link{{Name: "docker0", Prefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/24")}}, eth0}
	network.current = kernel.NetworkState{IPv4: kernel.NetworkFamily{Links: bridged}}
	if got := read().IPv4.Links; !slices.EqualFunc(got, bridged, sameLink) {
		t.Errorf("the call after a bridge came read the links %v, want %v", got, bridged)
	}
}

// sameLink is whether two links hold one name, its prefixes and its far ends
func sameLink(a, b kernel.Link) bool {
	return a.Name == b.Name && slices.Equal(a.Prefixes, b.Prefixes) && slices.Equal(a.Peers, b.Peers)
}

// a change of the host's network closes every socket connected to one peer, which may keep a source the host lost
// or one the route no longer picks
func TestNetworkChangeClosesEverySocketConnectedToOnePeer(t *testing.T) {
	c := writable(t)
	c.events = events.New()
	c.hub = recordingHub(t, c.events)
	busyPeer(t, c.hub, c.events)
	network := &fakeNetwork{changes: make(chan kernel.NetworkChange, 1)}
	c.network = network
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.followNetwork(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	network.changes <- kernel.NetworkChange{
		At:     time.Now(),
		Before: kernel.NetworkState{IPv4: kernel.NetworkFamily{Default: kernel.DefaultRoute{Interface: "en0"}}},
		After:  kernel.NetworkState{IPv4: kernel.NetworkFamily{Default: kernel.DefaultRoute{Interface: "en7"}}},
	}
	for deadline := time.Now().Add(networkChangeBudget); len(recorded(c.events, "network.changed")) == 0; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the change was never recorded")
		}
	}
	if open := c.hub.PairSockets(); open != 0 {
		t.Fatalf("the hub holds %d sockets connected to one peer after the network changed, want none", open)
	}
	closed := recorded(c.events, "transport.pair.closed")
	if len(closed) != 1 || closed[0].Attrs["reason"] != "network" {
		t.Fatalf("the hub recorded %v closing, want the one socket closed for the network", closed)
	}
}
