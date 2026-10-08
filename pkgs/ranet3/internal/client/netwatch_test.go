// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"context"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/ike"
	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/kernel"
)

// networkChangeBudget bounds how long one change takes to reach the sessions, the dialers and the bus
const networkChangeBudget = 5 * time.Second

// fakeNetwork is a watch whose changes a test sends
type fakeNetwork struct {
	changes chan kernel.NetworkChange
}

func (f *fakeNetwork) Changes() <-chan kernel.NetworkChange { return f.changes }

func (f *fakeNetwork) State() (kernel.NetworkState, kernel.NetworkChange) {
	return kernel.NetworkState{}, kernel.NetworkChange{}
}

func (f *fakeNetwork) Close() error { return nil }

// a change of the host's network asks every session to prove its path and sets every dialer going at once
// the change is recorded with what moved and how many it reached
func TestNetworkChangeProbesEverySessionAndWakesEveryDialer(t *testing.T) {
	c := writable(t)
	c.events = events.New()
	var probedMu sync.Mutex
	var probed []*ike.Session
	c.sessions.probe = func(sess *ike.Session) {
		probedMu.Lock()
		defer probedMu.Unlock()
		probed = append(probed, sess)
	}
	c.sessions.active = func(*ike.Session) bool { return true }
	sessions := []*ike.Session{{}, {}}
	c.sessions.adoptPreferred("example/gateway/1@0", sessions[0], true, nil)
	c.sessions.adoptPreferred("example/inbound/1@0", sessions[1], true, nil)
	dialers := []*dialer{{cancel: func() {}, wake: make(chan struct{}, 1)}, {cancel: func() {}, wake: make(chan struct{}, 1)}}
	c.dialers["example/gateway/1@0"] = dialers[0]
	c.dialers["example/elsewhere/1@0"] = dialers[1]

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
