// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"context"
	"net/netip"
	"slices"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/ike"
	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/kernel"
)

// a renamed method would drop the view without a word, since the server finds it by assertion
var _ interface {
	control.NetmonSource
	control.ProbeSource
} = (*Client)(nil)

// the view carries the watch's reading per family and the last change by what moved in it
// a node without a watch says so, and a watch that signaled nothing yet has no last change
func TestNetmonViewReportsTheWatchAndItsLastChange(t *testing.T) {
	if info := (&Client{}).DebugNetmon(); info.Watching || info.LastChange != nil {
		t.Errorf("a node without a watch reports %+v", info)
	}
	wifi := kernel.DefaultRoute{Interface: "en0", Gateway: netip.MustParseAddr("192.168.1.1")}
	dock := kernel.DefaultRoute{Interface: "en7"}
	before := kernel.NetworkState{IPv4: kernel.NetworkFamily{Default: wifi}, IPv6: kernel.NetworkFamily{Addresses: []netip.Addr{netip.MustParseAddr("2001:db8::20")}}}
	after := kernel.NetworkState{IPv4: kernel.NetworkFamily{Default: dock}, IPv6: before.IPv6}
	network := &fakeNetwork{current: after}
	c := &Client{network: network}
	if info := c.DebugNetmon(); !info.Watching || info.LastChange != nil || len(info.Families) != 2 || info.Families[0].Default.Interface != "en7" {
		t.Errorf("a watch that signaled nothing reports %+v", info)
	}

	network.last = kernel.NetworkChange{At: time.Now().Add(-time.Minute), Before: before, After: after}
	info := c.DebugNetmon()
	if info.LastChange == nil || len(info.LastChange.Families) != 1 {
		t.Fatalf("a change of IPv4 alone reports %+v", info.LastChange)
	}
	moved := info.LastChange.Families[0]
	if moved.Family != "ipv4" || moved.DefaultWas == nil || moved.DefaultWas.Interface != "en0" || moved.Default == nil || moved.Default.Interface != "en7" {
		t.Errorf("the default moved as %+v", moved)
	}
	if time.Duration(info.LastChange.Ago) < time.Minute {
		t.Errorf("a change a minute old reads as %s ago", time.Duration(info.LastChange.Ago))
	}
}

// a probe reaches the sessions it names and no other, and is recorded as a verb under each
// a peer and every session at once, or neither, is refused
func TestProbeAsksTheSessionsItNames(t *testing.T) {
	c := writable(t)
	c.events = events.New()
	var probed []*ike.Session
	c.sessions.probe = func(sess *ike.Session) { probed = append(probed, sess) }
	gateway, inbound := &ike.Session{}, &ike.Session{}
	c.sessions.adoptPreferred("example/gateway/1@0", gateway, true, nil)
	c.sessions.adoptPreferred("example/inbound/1@0", inbound, true, nil)

	for _, refused := range []struct {
		peer string
		all  bool
	}{{"gateway", true}, {"", false}} {
		if _, err := c.DebugProbe(context.Background(), refused.peer, refused.all); err == nil {
			t.Errorf("a probe of peer %q with every session %v was accepted", refused.peer, refused.all)
		}
	}
	if _, err := c.DebugProbe(context.Background(), "nobody", false); err == nil {
		t.Error("a probe of a peer this node holds no session with was accepted")
	}
	result, err := c.DebugProbe(context.Background(), "gateway", false)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(probed, []*ike.Session{gateway}) || !slices.Equal(result.Acted, []string{"example/gateway/1@0"}) {
		t.Errorf("a probe of gateway reached %d sessions and reports %v", len(probed), result.Acted)
	}
	verbs := recorded(c.events, "control.verb")
	if last := verbs[len(verbs)-1]; last.Peer != "example/gateway/1@0" || last.Attrs["verb"] != "probe" {
		t.Errorf("the probe was recorded as %+v", last)
	}

	probed = nil
	if result, err := c.DebugProbe(context.Background(), "", true); err != nil || len(probed) != 2 || len(result.Acted) != 2 {
		t.Errorf("a probe of every session reached %d and reports %v (err %v)", len(probed), result.Acted, err)
	}
}
