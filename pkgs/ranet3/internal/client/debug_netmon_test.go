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

	// a bridge and a point-to-point link coming up move the links alone, which the view names with their prefixes and far ends
	bridge := kernel.Link{Name: "docker0", Prefixes: []netip.Prefix{netip.MustParsePrefix("198.51.100.129/25")}}
	ppp := kernel.Link{Name: "ppp0", Prefixes: []netip.Prefix{netip.MustParsePrefix("203.0.113.33/32")}, Peers: []netip.Prefix{netip.MustParsePrefix("203.0.113.64/28")}}
	before = after
	after.IPv4.Links = []kernel.Link{bridge, ppp}
	network.current, network.last = after, kernel.NetworkChange{At: time.Now(), Before: before, After: after}
	info = c.DebugNetmon()
	if got := info.Families[0].Links; len(got) != 2 || got[0].Name != "docker0" || !slices.Equal(got[0].Prefixes, bridge.Prefixes) ||
		got[1].Name != "ppp0" || !slices.Equal(got[1].Prefixes, ppp.Prefixes) || !slices.Equal(got[1].Peers, ppp.Peers) {
		t.Errorf("the IPv4 links read %+v, want docker0 with %v and ppp0 with %v far end %v", got, bridge.Prefixes, ppp.Prefixes, ppp.Peers)
	}
	if info.LastChange == nil || len(info.LastChange.Families) != 1 || len(info.LastChange.Families[0].Links) != 2 || info.LastChange.Families[0].Default != nil {
		t.Errorf("a bridge coming up reports %+v, want the IPv4 links alone", info.LastChange)
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
	c.sessions.adoptPreferred("example/gateway:1@0", gateway, true, nil)
	c.sessions.adoptPreferred("example/inbound:1@0", inbound, true, nil)

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
	if !slices.Equal(probed, []*ike.Session{gateway}) || !slices.Equal(result.Acted, []string{"example/gateway:1@0"}) {
		t.Errorf("a probe of gateway reached %d sessions and reports %v", len(probed), result.Acted)
	}
	verbs := recorded(c.events, "control.verb")
	if last := verbs[len(verbs)-1]; last.Peer != "example/gateway:1@0" || last.Attrs["verb"] != "probe" {
		t.Errorf("the probe was recorded as %+v", last)
	}

	probed = nil
	if result, err := c.DebugProbe(context.Background(), "", true); err != nil || len(probed) != 2 || len(result.Acted) != 2 {
		t.Errorf("a probe of every session reached %d and reports %v (err %v)", len(probed), result.Acted, err)
	}
}
