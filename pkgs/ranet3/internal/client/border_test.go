// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"maps"
	"net/netip"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/internal/babel"
	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/egress"
	kernelexit "ranet3.com/pkgs/ranet3/internal/egress/kernel"
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/logtest"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/pf"
	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
)

// borderRecord is the antispoof filter as the node drives one, recording each
// configuration a reload hands it
type borderRecord struct {
	mu      sync.Mutex
	border  egress.Border
	handed  int
	refusal error
	debug   egress.BorderDebug
	// missing is a chain another writer took, which the filter reads not ready
	missing bool
	// pf is the filter as darwin's runs, over pf, nil for Linux's
	pf *egress.BorderPF
}

func (b *borderRecord) SetConfig(cfg egress.Border) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.handed++
	if b.refusal != nil {
		return b.refusal
	}
	b.border = cfg
	return nil
}

func (b *borderRecord) Capability() egress.Border {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.border
}

func (b *borderRecord) calls() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.handed
}

func (*borderRecord) Inside() []string { return []string{"ranet3", "lo"} }

func (b *borderRecord) Where() string {
	if b.pf != nil {
		return "pf anchor " + b.pf.Anchor
	}
	return "nftables table inet ranet3 chain antispoof"
}

func (b *borderRecord) Stats() egress.BorderStats {
	if b.missing {
		return egress.BorderStats{At: time.Unix(1_790_000_000, 0), Unready: "another writer changed its table", PF: b.pf}
	}
	if b.pf != nil {
		// the anchor's rules write chain antispoof's drops, the first four kinds, and none of the entry chain's
		return egress.BorderStats{At: time.Unix(1_790_000_000, 0), Ready: true, Installed: 6,
			Dropped: egress.BorderDrops{3, 1, 4, 5, 0, 0}, Kinds: egress.BorderDropKinds[:4], PF: b.pf}
	}
	return egress.BorderStats{At: time.Unix(1_790_000_000, 0), Ready: true, Installed: 7,
		Dropped: egress.BorderDrops{3, 1, 4, 5, 6, 8}, Kinds: egress.BorderDropKinds[:],
		CarveOuts: []egress.CarveOut{{Link: "eth0", Prefix: netip.MustParsePrefix("198.18.0.0/24")}}}
}

func (b *borderRecord) Debug() egress.BorderDebug { return b.debug }

// passProbe is the antispoof filter as a reload drives it, deriving at each
// SetConfig the sets a pass derives from the configuration handed, as the
// pass the filter's SetConfig wakes may run before the reload stores the file
type passProbe struct {
	*borderRecord
	sets func(*egress.Border) egress.BorderSets
	mu   sync.Mutex
	seen []egress.BorderSets
}

func (p *passProbe) SetConfig(cfg egress.Border) error {
	if err := p.borderRecord.SetConfig(cfg); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.seen = append(p.seen, p.sets(&cfg))
	return nil
}

// passes is the sets each pass a SetConfig woke derived, in order
func (p *passProbe) passes() []egress.BorderSets {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.seen)
}

// probeBorder hands c a passProbe deriving the sets as c's filter does
func probeBorder(c *Client) *passProbe {
	probe := &passProbe{borderRecord: &borderRecord{}, sets: c.BorderRuntime().Sets}
	c.SetBorder(probe)
	return probe
}

// overlayOf is an overlay of the prefixes given
func overlayOf(prefixes ...string) []schema.Prefix {
	var overlay []schema.Prefix
	for _, prefix := range prefixes {
		overlay = append(overlay, schema.MustPrefix(prefix))
	}
	return overlay
}

// an exit's egress follows the translator alone: with the border's chain
// missing, its SID stays originated, both families ready and the status
// carries the translator's word, while the border's status says the chain is
// not ready
func TestEgressFollowsTheTranslatorWhileTheBordersChainIsMissing(t *testing.T) {
	const sid = "3fff:b:0:106::3"
	c, _, _, bus := reloadOf(t, func(cfg *config.Config) { egressNode(cfg, egressSegment(sid, "3fff:a::/32")) })
	segmentsOf(t, c)
	speakerRecording(t, c, bus)
	c.SetBorder(&borderRecord{missing: true})
	c.SetExit(&fakeExit{status: egress.Status{Ready4: true, Ready6: true}})
	for _, serves := range []bool{true, false, true} {
		c.SetEgressReady(true, true, serves)
		if got := sidOriginated(c, sid); got != serves {
			t.Errorf("with the translator serving %v and the antispoof filter's chain missing the SID's /128 is originated %v", serves, got)
		}
	}
	if status := c.exitStatus(); len(status.Ready) != 2 || status.Unready != "" {
		t.Errorf("with the antispoof filter's chain missing the egress status reads ready %v, unready %q, want the translator's word alone", status.Ready, status.Unready)
	}
	if status := c.borderStatus(); status == nil || status.Ready || status.Unready == "" {
		t.Errorf("the antispoof filter's status reads %+v, want not ready and why", status)
	}
}

// A republish that read the SID standing before the translator withdrew it
// ends before the republish of the withdrawal, so the SID's /128 ends
// withdrawn
func TestRepublishRacingAFallLeavesTheSIDWithdrawn(t *testing.T) {
	const sid = "3fff:b:0:106::3"
	c, _, _, bus := reloadOf(t, func(cfg *config.Config) { egressNode(cfg, egressSegment(sid, "3fff:a::/32")) })
	segmentsOf(t, c)
	speakerRecording(t, c, bus)
	h := holdRepublish(c)
	c.SetEgressReady(true, true, true)
	if !sidOriginated(c, sid) {
		t.Fatal("the SID is not originated with the translator ready")
	}

	h.armed.Store(true)
	held := make(chan struct{})
	go func() { defer close(held); c.SetEgressReady(true, true, true) }()
	h.wait(t)
	fell := make(chan struct{})
	go func() { defer close(fell); c.SetEgressReady(true, true, false) }()
	waitFor(t, heldWait, "the fall stored", func() bool { return !c.egressServes.Load() })
	// a fall whose republish nothing orders runs to its end here
	select {
	case <-fell:
	case <-time.After(unorderedWait):
	}
	close(h.release)
	joined(t, "the held republish", held)
	joined(t, "the fall", fell)
	if sidOriginated(c, sid) {
		t.Error("after the translator withdrew the SID's /128 is originated: the republish that read it standing landed last")
	}
}

// a reload changing the overlay hands the running filter it, and one
// reordering the overlay or moving a SID hands it nothing
func TestReloadMovesTheBorderInPlace(t *testing.T) {
	const sid, moved = "3fff:b:0:106::3", "3fff:b:0:106::4"
	c, path, _, bus := reloadOf(t, func(cfg *config.Config) { egressNode(cfg, egressSegment(sid, "3fff:a::/32")) })
	segmentsOf(t, c)
	border := &borderRecord{}
	c.SetBorder(border)

	reordered := *c.config()
	reordered.Overlay = overlayOf("203.0.113.0/24", "3fff::/20")
	writeConfig(t, path, &reordered)
	if err := c.ReloadFrom(path); err != nil {
		t.Fatalf("a reordered overlay was refused: %v", err)
	}
	if border.calls() != 0 || strings.Contains(lastReload(t, bus)["applied"], "overlay") {
		t.Errorf("a reordered overlay handed the filter %d lists and applied %q", border.calls(), lastReload(t, bus)["applied"])
	}

	grown := *c.config()
	grown.Overlay = overlayOf("203.0.113.0/24", "3fff::/20", "2001:db8::/32")
	writeConfig(t, path, &grown)
	if err := c.ReloadFrom(path); err != nil {
		t.Fatalf("a grown overlay was refused: %v", err)
	}
	if got := border.Capability().Normalized(); len(got.Overlay) != 3 || border.calls() != 1 {
		t.Errorf("after a grown overlay the filter holds %v after %d lists", got.Overlay, border.calls())
	}
	if applied := lastReload(t, bus)["applied"]; !strings.Contains(applied, "overlay") || strings.Contains(applied, "cap.antispoof") {
		t.Errorf("a grown overlay applied %q, want overlay among it and not cap.antispoof", applied)
	}

	// exemptions moved alone hand the filter the overlay with them, in any order
	exempting := *c.config()
	exempting.Cap.Antispoof = &egress.Antispoof{Exempt: overlayOf("203.0.113.128/25"), Interface: map[string]egress.AntispoofInterface{"wl*": {Exempt: overlayOf("3fff:a::/48", "203.0.113.0/26")}}}
	writeConfig(t, path, &exempting)
	if err := c.ReloadFrom(path); err != nil {
		t.Fatalf("exemptions were refused: %v", err)
	}
	want := []egress.Exemption{
		{Prefix: netip.MustParsePrefix("203.0.113.128/25")},
		{Interface: "wl*", Prefix: netip.MustParsePrefix("203.0.113.0/26")},
		{Interface: "wl*", Prefix: netip.MustParsePrefix("3fff:a::/48")},
	}
	if got := border.Capability().Exemptions(); !slices.Equal(got, want) || border.calls() != 2 {
		t.Errorf("after the exemptions the filter exempts %v after %d configurations, want %v after 2", got, border.calls(), want)
	}
	if applied := lastReload(t, bus)["applied"]; !strings.Contains(applied, "cap.antispoof") || strings.Contains(applied, "overlay") {
		t.Errorf("exemptions applied %q, want cap.antispoof among it and not overlay", applied)
	}
	reexempting := *c.config()
	reexempting.Cap.Antispoof = &egress.Antispoof{Exempt: overlayOf("203.0.113.128/25"), Interface: map[string]egress.AntispoofInterface{"wl*": {Exempt: overlayOf("203.0.113.0/26", "3fff:a::/48")}}}
	writeConfig(t, path, &reexempting)
	if err := c.ReloadFrom(path); err != nil {
		t.Fatalf("reordered exemptions were refused: %v", err)
	}
	if border.calls() != 2 || strings.Contains(lastReload(t, bus)["applied"], "cap.antispoof") {
		t.Errorf("reordered exemptions handed the filter %d configurations in all and applied %q", border.calls(), lastReload(t, bus)["applied"])
	}

	next := *c.config()
	next.Cap.Segment = &srv6.Segments{Local: []srv6.Segment{egressSegment(moved, "3fff:a::/32")}}
	writeConfig(t, path, &next)
	if err := c.ReloadFrom(path); err != nil {
		t.Fatalf("an egress segment moved to another SID was refused: %v", err)
	}
	if border.calls() != 2 {
		t.Errorf("a SID moved handed the filter %d configurations in all, want the grown overlay's and the exemptions' alone", border.calls())
	}
}

// a reload growing the overlay onto a lease the host holds hands the filter
// the overlay it carves from, so the pass its SetConfig wakes, which may run
// before the reload stores the file, carves the lease
func TestReloadOntoACarvedLeaseHandsTheFilterTheOverlayItCarvesFrom(t *testing.T) {
	c, path, _, _ := reloadOf(t, func(cfg *config.Config) { egressNode(cfg, egressSegment("3fff:b:0:106::3", "3fff:a::/32")) })
	segmentsOf(t, c)
	lease := netip.MustParsePrefix("198.18.0.10/24")
	c.network = &fakeNetwork{changes: make(chan kernel.NetworkChange), current: kernel.NetworkState{IPv4: kernel.NetworkFamily{Links: []kernel.Link{{Name: "eth0", Prefixes: []netip.Prefix{lease}}}}}}
	probe := probeBorder(c)
	if carved := probe.sets(c.config().Border()).CarveOuts; len(carved) != 0 {
		t.Fatalf("before the reload the antispoof filter carves %v, want nothing", carved)
	}
	grown := *c.config()
	grown.Overlay = overlayOf("203.0.113.0/24", "3fff::/20", "198.18.0.0/15")
	writeConfig(t, path, &grown)
	if err := c.ReloadFrom(path); err != nil {
		t.Fatalf("an overlay grown onto the lease was refused: %v", err)
	}
	want := []egress.CarveOut{{Link: "eth0", Prefix: lease.Masked()}}
	passes := probe.passes()
	if len(passes) == 0 {
		t.Fatal("the reload grew the overlay onto the lease and handed the filter nothing")
	}
	for i, pass := range passes {
		if !slices.Equal(pass.CarveOuts, want) {
			t.Errorf("the pass SetConfig %d woke carves %v, want %v", i, pass.CarveOuts, want)
		}
	}
}

// a reload adding an exemption over another node's prefix hands the filter
// the exemption and the rest it carves from at once, so the pass that writes
// the exemption's accept, which may run before the reload stores the file,
// carves the other node's prefix out of it
func TestReloadOfAnExemptionHandsTheFilterWhatItCarvesFrom(t *testing.T) {
	c, path, _, _ := reloadOf(t, func(cfg *config.Config) { egressNode(cfg, egressSegment("3fff:b:0:106::3", "3fff:a::/32")) })
	segmentsOf(t, c)
	another := netip.MustParsePrefix("203.0.113.70/32")
	c.Mesh.Routes.Set(netip.Prefix{}, another, &netstack.Peer{ID: "example/peer"})
	c.network = &fakeNetwork{changes: make(chan kernel.NetworkChange)}
	probe := probeBorder(c)
	if carved := probe.sets(c.config().Border()).Carved; len(carved) != 0 {
		t.Fatalf("before the reload the antispoof filter carves %v, want nothing", carved)
	}
	exempted := *c.config()
	exempted.Cap.Antispoof = &egress.Antispoof{Interface: map[string]egress.AntispoofInterface{"eth1": {Exempt: overlayOf("203.0.113.64/26")}}}
	writeConfig(t, path, &exempted)
	if err := c.ReloadFrom(path); err != nil {
		t.Fatalf("an exemption was refused: %v", err)
	}
	want := kernel.Ranges([]netip.Prefix{another})
	passes := probe.passes()
	if len(passes) == 0 {
		t.Fatal("the reload added an exemption and handed the filter nothing")
	}
	for i, pass := range passes {
		if !slices.Equal(pass.Carved, want) {
			t.Errorf("the pass SetConfig %d woke carves %v, want %v", i, pass.Carved, want)
		}
	}
}

// a gateway announcing its site's range and exempting it under the site's
// interface carves, of the routes the speaker learns from a peer, the peer's
// more specific prefix inside the range and nothing of the peer's prefix
// covering it, and names the router-id of the route selected for the prefix it
// carves
func TestBorderSetsCarveAnotherNodesPrefixAndKeepTheGatewaysRange(t *testing.T) {
	c, _, _, _ := reloadOf(t, func(cfg *config.Config) {
		cfg.Overlay = overlayOf("203.0.113.0/24")
		cfg.Cap.Route = &babel.Routes{Announce: announce("203.0.113.0/25")}
		cfg.Cap.Antispoof = &egress.Antispoof{Interface: map[string]egress.AntispoofInterface{"eth1": {Exempt: overlayOf("203.0.113.0/25")}}}
	})
	c.network = &fakeNetwork{changes: make(chan kernel.NetworkChange)}
	// the fixture's speaker writes a table of its own, and this one the node's
	speaker, err := babel.New(babel.Config{}, babel.Routes{}, babel.Runtime{}, c.Mesh)
	if err != nil {
		t.Fatal(err)
	}
	c.speaker = speaker
	peer := sinkPeer(t, "example/gateway:1@0")
	defer c.speaker.AddPeer(peer, identity.MustParse("example/gateway:1")).Close()
	update := func(prefix string) babel.RawTLV {
		p := netip.MustParsePrefix(prefix)
		return babel.EncodeUpdate(babel.Update{AE: babel.AEIPv4ViaIPv6, Plen: p.Bits(), Prefix: p.Addr().AsSlice(), Seqno: 1, Metric: 20, Interval: 1000})
	}
	c.speaker.Receive(peer, babelPacket(
		babel.EncodeHello(babel.Hello{Seqno: 1, Interval: 1000}),
		babel.EncodeIHU(babel.IHU{RxCost: 96, Interval: 1000}),
		babel.EncodeRouterID([8]byte{1, 2, 3, 4, 5, 6, 7, 8}),
		update("203.0.113.0/24"),
		update("203.0.113.96/28"),
	))
	sets := c.BorderRuntime().Sets(c.config().Border())
	if want := kernel.Ranges([]netip.Prefix{netip.MustParsePrefix("203.0.113.96/28")}); !slices.Equal(sets.Carved, want) {
		t.Errorf("the filter carves %v, want %v alone", sets.Carved, want)
	}
	want := []egress.ExemptConflict{{
		Exemption: egress.Exemption{Interface: "eth1", Prefix: netip.MustParsePrefix("203.0.113.0/25")},
		Prefix:    netip.MustParsePrefix("203.0.113.96/28"), Carved: netip.MustParsePrefix("203.0.113.96/28"),
		Via: peer.ID, RouterID: "0102030405060708",
	}}
	if !slices.Equal(sets.Conflicts, want) {
		t.Errorf("the filter reports the conflicts %+v, want %+v", sets.Conflicts, want)
	}
}

// a gateway announcing 203.0.113.0/25 and exempting it under eth1, whose own
// network holds the range, carves of the carve-out eth1 is only its node
// address and another node's prefix inside the range
func TestBorderSetsLiftTheGatewaysExemptRangeOutOfItsSiteCarveOut(t *testing.T) {
	c, _, _, _ := reloadOf(t, func(cfg *config.Config) {
		cfg.Overlay = overlayOf("203.0.113.0/24")
		cfg.Cap.Route = &babel.Routes{Announce: announce("203.0.113.0/25", "203.0.113.1/32")}
		cfg.Cap.Antispoof = &egress.Antispoof{Interface: map[string]egress.AntispoofInterface{"eth1": {Exempt: overlayOf("203.0.113.0/25")}}}
	})
	site := netip.MustParsePrefix("203.0.113.126/25")
	c.network = &fakeNetwork{changes: make(chan kernel.NetworkChange), current: kernel.NetworkState{IPv4: kernel.NetworkFamily{Links: []kernel.Link{{Name: "eth1", Prefixes: []netip.Prefix{site}}}}}}
	for prefix, value := range map[string]*netstack.Peer{"203.0.113.0/25": netstack.Local, "203.0.113.1/32": netstack.Local, "203.0.113.96/28": {ID: "example/peer"}} {
		c.Mesh.Routes.Set(netip.Prefix{}, netip.MustParsePrefix(prefix), value)
	}
	sets := c.BorderRuntime().Sets(c.config().Border())
	if want := []egress.CarveOut{{Link: "eth1", Prefix: site.Masked()}}; !slices.Equal(sets.CarveOuts, want) {
		t.Fatalf("the filter's carve-outs are %v, want %v", sets.CarveOuts, want)
	}
	if want := kernel.Ranges([]netip.Prefix{netip.MustParsePrefix("203.0.113.1/32"), netip.MustParsePrefix("203.0.113.96/28")}); !slices.Equal(sets.Carved, want) {
		t.Errorf("the filter carves %v, want %v", sets.Carved, want)
	}
}

// the antispoof filter's sets name each link the host's watch reports, in
// either family, once where both report it and whatever its addresses, so a
// backend matching a name exactly can expand a wildcard exemption over them,
// and none where overlay is not written
func TestBorderSetsNameEveryLinkTheWatchReports(t *testing.T) {
	c, _, _, _ := reloadOf(t, func(cfg *config.Config) { cfg.Overlay = overlayOf("203.0.113.0/24") })
	c.network = &fakeNetwork{changes: make(chan kernel.NetworkChange), current: kernel.NetworkState{
		IPv4: kernel.NetworkFamily{Links: []kernel.Link{{Name: "en1", Prefixes: []netip.Prefix{netip.MustParsePrefix("198.51.100.10/24")}}, {Name: "bridge100"}}},
		IPv6: kernel.NetworkFamily{Links: []kernel.Link{{Name: "en1"}, {Name: "en0", Prefixes: []netip.Prefix{netip.MustParsePrefix("2001:db8:b::10/64")}}}},
	}}
	if got, want := c.BorderRuntime().Sets(c.config().Border()).Links, []string{"bridge100", "en0", "en1"}; !slices.Equal(got, want) {
		t.Errorf("the filter's sets name the links %v, want %v", got, want)
	}
	if got := c.BorderRuntime().Sets(nil).Links; len(got) != 0 {
		t.Errorf("with no overlay the filter's sets name the links %v, want none", got)
	}
}

// a reload that moves only what cap.route announces hands the filter this
// node's own prefixes, so the pass its SetConfig wakes, which may run before
// the reload stores the file, carves a node address it announces inside an
// exemption
func TestReloadOfAnAnnouncementHandsTheFilterWhatItCarvesFrom(t *testing.T) {
	c, path, _, _ := reloadOf(t, func(cfg *config.Config) {
		cfg.Overlay = overlayOf("203.0.113.0/24")
		cfg.Cap.Antispoof = &egress.Antispoof{Interface: map[string]egress.AntispoofInterface{"eth1": {Exempt: overlayOf("203.0.113.64/26")}}}
	})
	c.network = &fakeNetwork{changes: make(chan kernel.NetworkChange)}
	probe := probeBorder(c)
	if carved := probe.sets(c.config().Border()).Carved; len(carved) != 0 {
		t.Fatalf("before the reload the antispoof filter carves %v, want nothing", carved)
	}
	announced := *c.config()
	announced.Cap.Route = &babel.Routes{Announce: announce("203.0.113.65/32")}
	writeConfig(t, path, &announced)
	if err := c.ReloadFrom(path); err != nil {
		t.Fatalf("an announcement was refused: %v", err)
	}
	want := kernel.Ranges([]netip.Prefix{netip.MustParsePrefix("203.0.113.65/32")})
	passes := probe.passes()
	if len(passes) == 0 {
		t.Fatal("the reload moved what cap.route announces and handed the filter nothing")
	}
	for i, pass := range passes {
		if !slices.Equal(pass.Carved, want) {
			t.Errorf("the pass SetConfig %d woke carves %v, want %v", i, pass.Carved, want)
		}
	}
}

// a gateway announcing 203.0.113.64/26 and exempting it under eth1 carves
// nothing of another node's 203.0.113.0/24 covering it. A reload that stops
// announcing the range, and moves nothing else the filter holds, hands the
// filter this node's own ranges, so the pass its SetConfig wakes carves the
// exemption as the other node's.
func TestReloadDroppingAnOwnRangeHandsTheFilterWhatItCarvesFrom(t *testing.T) {
	c, path, _, _ := reloadOf(t, func(cfg *config.Config) {
		cfg.Overlay = overlayOf("203.0.113.0/24")
		cfg.Cap.Route = &babel.Routes{Announce: announce("203.0.113.64/26")}
		cfg.Cap.Antispoof = &egress.Antispoof{Interface: map[string]egress.AntispoofInterface{"eth1": {Exempt: overlayOf("203.0.113.64/26")}}}
	})
	c.network = &fakeNetwork{changes: make(chan kernel.NetworkChange)}
	c.Mesh.Routes.Set(netip.Prefix{}, netip.MustParsePrefix("203.0.113.0/24"), &netstack.Peer{ID: "example/peer"})
	probe := probeBorder(c)
	if carved := probe.sets(c.config().Border()).Carved; len(carved) != 0 {
		t.Fatalf("while this node announces 203.0.113.64/26 the antispoof filter carves %v, want nothing", carved)
	}
	dropped := *c.config()
	dropped.Cap.Route = nil
	writeConfig(t, path, &dropped)
	if err := c.ReloadFrom(path); err != nil {
		t.Fatalf("a reload that stops announcing 203.0.113.64/26 was refused: %v", err)
	}
	want := kernel.Ranges([]netip.Prefix{netip.MustParsePrefix("203.0.113.64/26")})
	passes := probe.passes()
	if len(passes) == 0 {
		t.Fatal("the reload stopped announcing 203.0.113.64/26 and handed the filter nothing, so it keeps the range as this node's own")
	}
	for i, pass := range passes {
		if !slices.Equal(pass.Carved, want) {
			t.Errorf("the pass SetConfig %d woke carves %v, want %v", i, pass.Carved, want)
		}
	}
}

// every local SID admits only an outer source in the overlay, so a reload
// narrowing the overlay alone rebuilds the table the mesh acts on, and a SID
// delivering to the mesh refuses a source the old overlay held
func TestReloadMovingTheOverlayRebuildsTheLocalTable(t *testing.T) {
	const sid, mesh = "3fff:b:0:106::3", "3fff:b:0:106::1"
	c, path, _, _ := reloadOf(t, func(cfg *config.Config) {
		egressNode(cfg, egressSegment(sid, "3fff:a::/32"), srv6.Segment{SID: schema.MustAddr(mesh), Behavior: srv6.BehaviorEndDT46})
	})
	segmentsOf(t, c)
	c.SetBorder(&borderRecord{})
	handled := func() srv6.Result {
		inner := make([]byte, 40)
		inner[0], inner[6] = 0x60, 59
		raw, err := srv6.Encapsulate(inner, netip.MustParseAddr("3fff:b::1"), []netip.Addr{netip.MustParseAddr(mesh)})
		if err != nil {
			t.Fatal(err)
		}
		return c.Mesh.Segments().Handle(raw)
	}
	if got := handled(); got.Action != srv6.ActionDeliver {
		t.Fatalf("from inside 3fff::/20 the SID returned %v (%v), want a delivery", got.Action, got.Err)
	}
	narrowed := *c.config()
	narrowed.Overlay = overlayOf("203.0.113.0/24", "3fff:a::/32")
	writeConfig(t, path, &narrowed)
	if err := c.ReloadFrom(path); err != nil {
		t.Fatalf("a narrowed overlay was refused: %v", err)
	}
	if got := handled(); got.Action != srv6.ActionDrop || !errors.Is(got.Err, srv6.ErrSourceRefused) {
		t.Errorf("from outside the narrowed overlay the SID returned %v (%v), want a refusal of the source", got.Action, got.Err)
	}
}

// the filter and its run goroutine are built once in main, so a reload
// adding overlay is refused and applies nothing
func TestReloadRefusesAddingTheOverlay(t *testing.T) {
	c, path, _, _ := reloadOf(t, func(*config.Config) {})
	next := *c.config()
	next.Overlay = overlayOf("3fff::/20")
	writeConfig(t, path, &next)
	err := c.ReloadFrom(path)
	if err == nil || !strings.Contains(err.Error(), "config: overlay added, restart to apply") {
		t.Errorf("a reload adding overlay was answered %v", err)
	}
	if c.config().Border() != nil {
		t.Error("the refused reload stored overlay")
	}
}

// and a reload removing it is refused, leaving the filter its overlay
func TestReloadRefusesRemovingTheOverlay(t *testing.T) {
	c, path, _, _ := reloadOf(t, func(cfg *config.Config) { cfg.Overlay = overlayOf("3fff::/20") })
	border := &borderRecord{}
	c.SetBorder(border)
	next := *c.config()
	next.Overlay = nil
	writeConfig(t, path, &next)
	err := c.ReloadFrom(path)
	if err == nil || !strings.Contains(err.Error(), "config: overlay removed, restart to apply") {
		t.Errorf("a reload removing overlay was answered %v", err)
	}
	if c.config().Border() == nil || border.calls() != 0 {
		t.Errorf("the refused reload dropped overlay or handed the filter %d configurations", border.calls())
	}
}

// a reload whose exemption names an interface the filter's backend cannot
// write is refused ahead of the reconciler's table, the last refusal, so the
// refused file changes nothing
func TestReloadRefusesAnInterfaceNameTheFilterCannotWriteAheadOfTheTable(t *testing.T) {
	c, path, reconciler, bus := reloadOf(t, func(cfg *config.Config) {
		cfg.Cap.Table = &kernel.Table{}
		cfg.Overlay = overlayOf("3fff::/20")
	})
	refusal := errors.New(`egress: an exemption names the interface "br-lan", which the antispoof filter's pf anchor cannot write`)
	var handed *egress.Border
	c.borderRefusal = func(border *egress.Border) error {
		handed = border
		if border == nil {
			return nil
		}
		if _, named := border.Antispoof.Interface["br-lan"]; !named {
			return nil
		}
		return refusal
	}
	old := c.config()
	next := *old
	next.Cap.Table = &kernel.Table{Reconcile: schema.Duration(time.Minute)}
	next.Cap.Antispoof = &egress.Antispoof{Interface: map[string]egress.AntispoofInterface{"br-lan": {Exempt: overlayOf("3fff:a::/36")}}}
	writeConfig(t, path, &next)
	if err := c.ReloadFrom(path); !errors.Is(err, refusal) {
		t.Fatalf("the reload answered %v, want the filter's refusal of br-lan, handed %+v", err, handed)
	}
	if len(reconciler.tables) != 0 {
		t.Errorf("the reconciler was handed %d tables of a refused file", len(reconciler.tables))
	}
	changedNothing(t, c, old, bus)
}

// the start refuses an exemption's interface name the filter here cannot
// write, which only pf does: on darwin br-lan is refused naming it, and on
// every other platform it starts, as kernelexit.RefuseBorder answers for this
// platform. A prefix this node announces is the tun read's to check on darwin,
// so fe80:1:2::/48 announced starts everywhere.
func TestStartRefusesAnInterfaceNameTheFilterCannotWrite(t *testing.T) {
	for name, test := range map[string]struct {
		set   func(cfg *config.Config)
		named string
	}{
		"an exemption's interface": {func(cfg *config.Config) {
			cfg.Overlay = overlayOf("3fff::/20")
			cfg.Cap.Antispoof = &egress.Antispoof{Interface: map[string]egress.AntispoofInterface{"br-lan": {Exempt: overlayOf("3fff:a::/36")}}}
		}, `"br-lan"`},
		"announced": {func(cfg *config.Config) {
			cfg.Overlay = overlayOf("3fff::/20")
			cfg.Cap.Route = &babel.Routes{Announce: announce("fe80:1:2::/48")}
		}, ""},
	} {
		cfg, privateKey, reg := runtimeFixture(t)
		test.set(cfg)
		err := validateRuntimeConfig(cfg, privateKey, trust(t, reg))
		refused := test.named != "" && runtime.GOOS == "darwin"
		if want := kernelexit.RefuseBorder(cfg.Border()); (want != nil) != refused {
			t.Fatalf("%s: this platform's refusal answers %v", name, want)
		}
		if (err != nil) != refused || refused && !strings.Contains(err.Error(), test.named) {
			t.Errorf("%s: the start answered %v, want it refused %v naming %s", name, err, refused, test.named)
		}
	}
}

// down takes the node off the mesh and leaves the antispoof filter running and
// ready, since the kernel still forwards and the host's services still trust
// mesh sources
func TestDownKeepsTheBorder(t *testing.T) {
	c, _, translator := downable(t, t.TempDir())
	c.SetBorder(&borderRecord{})
	if _, err := c.Down(context.Background()); err != nil {
		t.Fatal(err)
	}
	if on, _ := translator.calls(); len(on) == 0 || on[len(on)-1] {
		t.Fatalf("down left the translator at %v", on)
	}
	if status := c.Status().Border; status == nil || !status.Ready {
		t.Errorf("down left the antispoof filter with status %+v", status)
	}
	if _, err := c.Up(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// where the filter runs on every node no node is told, and where it runs for
// the overlay a node that writes it is not told. Elsewhere a node whose host
// forwards is told at every reload that no filter runs, naming the families and
// the platform, with the overlay's absence named where that is why. One on a
// host forwarding nothing is not told.
func TestUnborderedNodeIsWarnedWhereItsHostForwards(t *testing.T) {
	var lines bytes.Buffer
	logtest.SetDefault(t, slog.New(slog.NewTextHandler(&lines, nil)))
	overlay := &egress.Border{Overlay: []schema.Prefix{schema.MustPrefix("192.0.2.0/24")}}
	for _, border := range []*egress.Border{nil, overlay} {
		for _, host := range []struct {
			v4, v6   *bool
			families string
		}{
			{new(true), new(true), "IPv4 and IPv6"},
			{new(true), new(false), "IPv4"},
			{new(false), new(true), "IPv6"},
			{new(false), new(false), ""},
		} {
			forwards := func() (*bool, *bool) { return host.v4, host.v6 }
			lines.Reset()
			warnUnbordered(border, forwards)
			warning := "this node forwards " + host.families + " and " + runtime.GOOS + " runs no antispoof filter"
			switch {
			case host.families == "" || kernelexit.Filters(border):
				warning = ""
			case border == nil:
				warning = "this node forwards " + host.families + " and writes no overlay, and " + runtime.GOOS + " runs no antispoof filter"
			}
			switch got := lines.String(); {
			case warning == "" && got != "":
				t.Errorf("a node with overlay %v on a host forwarding %v %v, or where the filter runs for it, warned:\n%s", border != nil, *host.v4, *host.v6, got)
			case warning != "" && (!strings.Contains(got, warning) || !strings.Contains(got, "this host's own services")):
				t.Errorf("a node with overlay %v on a host forwarding %v %v warned %q, want it to say %q", border != nil, *host.v4, *host.v6, got, warning)
			}
		}
	}

	// a reload reads the host this test runs on, so the warning it wants is
	// the one that host's forwarding gives, and the peers a reload starts log
	// beside the test reading
	var reloaded syncBuffer
	logtest.SetDefault(t, slog.New(slog.NewTextHandler(&reloaded, nil)))
	c, path, _, _ := reloadOf(t, func(*config.Config) {})
	writeConfig(t, path, c.config())
	if err := c.ReloadFrom(path); err != nil {
		t.Fatal(err)
	}
	want := 0
	if len(forwardedFamilies(forwardingEnabled())) != 0 && !kernelexit.Filters(c.config().Border()) {
		want = 1
	}
	if n := reloaded.count("runs no antispoof filter"); n != want {
		t.Errorf("a reload warned %d times, want %d: %q", n, want, reloaded.lines("antispoof"))
	}
}

// a family whose forwarding setting the node could not read is no family it forwards for the warning, and one the exit counts as forwarding
// the exit's lookups then judge it, rather than a refusal that says the kernel does not forward it
func TestForwardingThatCannotBeReadIsNotWarnedOf(t *testing.T) {
	for _, host := range []struct {
		v4, v6       *bool
		warned       []string
		exit4, exit6 bool
	}{
		{nil, nil, nil, true, true},
		{nil, new(true), []string{"IPv6"}, true, true},
		{new(true), nil, []string{"IPv4"}, true, true},
		{new(false), nil, nil, false, true},
		{nil, new(false), nil, true, false},
	} {
		if got := forwardedFamilies(host.v4, host.v6); !slices.Equal(got, host.warned) {
			t.Errorf("a host read as forwarding %s and %s is warned of forwarding %v, want %v", onOffUnread(host.v4), onOffUnread(host.v6), got, host.warned)
		}
		if exit4, exit6 := forwardsUnlessOff(host.v4, host.v6); exit4 != host.exit4 || exit6 != host.exit6 {
			t.Errorf("a host read as forwarding %s and %s is forwarding %v and %v to the exit, want %v and %v", onOffUnread(host.v4), onOffUnread(host.v6), exit4, exit6, host.exit4, host.exit6)
		}
	}
}

func onOffUnread(on *bool) string {
	if on == nil {
		return "unread"
	}
	return strconv.FormatBool(*on)
}

// the antispoof filter accepts the mesh tun and the loopback link, and an exit's egress leaves through
// the mesh tun, so it adds nothing
func TestBorderInsideIsEveryDeviceTheMeshArrivesOn(t *testing.T) {
	for name, node := range map[string]struct {
		exit bool
		want []string
	}{
		"a leaf":  {false, []string{"ranet3", kernel.Loopback}},
		"an exit": {true, []string{"ranet3", kernel.Loopback}},
	} {
		t.Run(name, func(t *testing.T) {
			c, _, _, _ := reloadOf(t, func(cfg *config.Config) {
				if node.exit {
					egressNode(cfg, egressSegment("3fff:b:0:106::3", "3fff:a::/32"))
				}
			})
			c.Mesh = &netstack.Mesh{Name: "ranet3"}
			if got := c.BorderInside(); !slices.Equal(got, node.want) {
				t.Errorf("the antispoof filter accepts %v, want %v", got, node.want)
			}
		})
	}
}

// the status carries the filter as it reports itself, nothing on a node
// writing no overlay, and on one writing it where no filter runs, that it is
// not enforced there
func TestStatusReportsTheBorderOnlyWhereItRuns(t *testing.T) {
	c := writable(t)
	if status := c.Status().Border; status != nil {
		t.Errorf("a node with no overlay reported %+v", status)
	}
	written := *c.config()
	written.Overlay = overlayOf("3fff::/20", "198.18.0.0/15")
	c.cfg.Store(&written)
	unenforced := c.Status().Border
	runs := kernelexit.Filters(written.Border())
	if runs && unenforced != nil {
		t.Errorf("a node with overlay and no filter, where the filter runs for it, reported %+v", unenforced)
	}
	if !runs && (unenforced == nil || unenforced.UnenforcedOn != runtime.GOOS || len(unenforced.Overlay) != 2 || unenforced.Ready) {
		t.Errorf("a node with overlay on %s, which runs no filter, reported %+v, want it not enforced there", runtime.GOOS, unenforced)
	}
	c.SetBorder(&borderRecord{border: egress.Border{Overlay: overlayOf("3fff::/20", "198.18.0.0/15")}})
	status := c.Status().Border
	want := control.BorderDrops{
		"overlay_source_ipv4": 3, "overlay_source_ipv6": 1, "carved_source_ipv4": 4, "carved_source_ipv6": 5,
		"mesh_entry_ipv4": 6, "mesh_entry_ipv6": 8,
	}
	carved := []control.BorderCarveOut{{Link: "eth0", Prefix: netip.MustParsePrefix("198.18.0.0/24")}}
	if status == nil || !status.Ready || status.Installed != 7 || !maps.Equal(status.Dropped, want) || len(status.Overlay) != 2 || len(status.Inside) != 2 || !slices.Equal(status.Carved, carved) || status.UnenforcedOn != "" || status.PF != nil {
		t.Errorf("the antispoof filter reported %+v", status)
	}

	// darwin's filter, over pf, its status carrying its pf block and the drops
	// its rules write, none of the entry chain's
	held := &egress.BorderPF{Anchor: "com.apple/ranet3", Token: 1 << 63, PID: 4242, Listed: true, Called: true,
		Enablers: []pf.Enabler{{PID: 4242, Name: "ranet3", Token: 1 << 63}}}
	c.SetBorder(&borderRecord{border: egress.Border{Overlay: overlayOf("3fff::/20", "198.18.0.0/15")}, pf: held})
	status = c.Status().Border
	want = control.BorderDrops{
		"overlay_source_ipv4": 3, "overlay_source_ipv6": 1, "carved_source_ipv4": 4, "carved_source_ipv6": 5,
	}
	block := control.BorderPF{Anchor: "com.apple/ranet3", Token: 1 << 63, PID: 4242, Listed: true, Called: true}
	if status == nil || status.Where != "pf anchor com.apple/ranet3" || status.UnenforcedOn != "" || status.PF == nil || *status.PF != block ||
		!status.Ready || status.Installed != 6 || !maps.Equal(status.Dropped, want) || len(status.Carved) != 0 {
		t.Errorf("the antispoof filter over pf reported %+v, want its pf block %+v and the drops %v", status, block, want)
	}
}

// the scrape carries the antispoof filter's readiness and a series for each
// kind of drop its stats say the last pass's rules write, and nothing of the
// filter on a node running none
func TestMetricsExposeTheBorderOnlyWhereItRuns(t *testing.T) {
	c := writable(t)
	var off strings.Builder
	c.Metrics(&off)
	if strings.Contains(off.String(), "ranet3_antispoof") || strings.Contains(off.String(), "ranet3_border") {
		t.Errorf("a node with no filter wrote:\n%s", off.String())
	}
	c.SetBorder(&borderRecord{})
	var out strings.Builder
	c.Metrics(&out)
	for _, want := range []string{
		"ranet3_antispoof_ready 1",
		`ranet3_antispoof_dropped_packets_total{reason="overlay_source",family="ipv4"} 3`,
		`ranet3_antispoof_dropped_packets_total{reason="overlay_source",family="ipv6"} 1`,
		`ranet3_antispoof_dropped_packets_total{reason="carved_source",family="ipv4"} 4`,
		`ranet3_antispoof_dropped_packets_total{reason="carved_source",family="ipv6"} 5`,
		`ranet3_antispoof_dropped_packets_total{reason="mesh_entry",family="ipv4"} 6`,
		`ranet3_antispoof_dropped_packets_total{reason="mesh_entry",family="ipv6"} 8`,
	} {
		if !strings.Contains(out.String(), want+"\n") {
			t.Errorf("the scrape does not carry %q:\n%s", want, out.String())
		}
	}

	// darwin's filter writes the series of chain antispoof's drops as Linux's
	// does, and none of the entry chain's, which its rules do not write
	written := *c.config()
	written.Overlay = overlayOf("3fff::/20")
	c.cfg.Store(&written)
	c.SetBorder(&borderRecord{pf: &egress.BorderPF{Anchor: "com.apple/ranet3", Listed: true, Called: true}})
	var pf strings.Builder
	c.Metrics(&pf)
	for _, want := range []string{
		"ranet3_antispoof_ready 1",
		`ranet3_antispoof_dropped_packets_total{reason="overlay_source",family="ipv4"} 3`,
		`ranet3_antispoof_dropped_packets_total{reason="overlay_source",family="ipv6"} 1`,
		`ranet3_antispoof_dropped_packets_total{reason="carved_source",family="ipv4"} 4`,
		`ranet3_antispoof_dropped_packets_total{reason="carved_source",family="ipv6"} 5`,
	} {
		if !strings.Contains(pf.String(), want+"\n") {
			t.Errorf("the scrape over pf does not carry %q:\n%s", want, pf.String())
		}
	}
	if strings.Contains(pf.String(), `reason="mesh_entry"`) {
		t.Errorf("the scrape over pf carries the entry chain's series, which its rules do not write:\n%s", pf.String())
	}
}

// debug rules reads every policy rule the dump finds, an l3mdev rule as one,
// marks the reconciler's by the protocol cap.table names and the ones the
// reconciler derived, a goto and a suppress length among them, lists what it
// derived that the host does not hold, and carries the reconciler's lookups by
// kind and the antispoof filter's chains, or where overlay is written and no
// filter runs, that it is not enforced there
func TestDebugRulesSortsEveryRuleByOwnerAndNamesTheMissing(t *testing.T) {
	const ownProto = kernel.DefaultProtocol + 1
	c, _, _, _ := reloadOf(t, func(cfg *config.Config) {
		cfg.Cap.Table = &kernel.Table{Proto: ownProto}
	})
	derived := []kernel.DumpedRule{
		{Family: kernel.FamilyIPv4, Priority: 5100, FWMark: 0x72, FWMask: ^uint32(0), Action: "goto", Goto: 5190, Protocol: ownProto},
		{Family: kernel.FamilyIPv4, Priority: 5110, To: netip.MustParsePrefix("203.0.113.0/24"), Action: "lookup", Table: uint32(kernel.DefaultTable), Protocol: ownProto},
		{Family: kernel.FamilyIPv4, Priority: 5190, Action: "nop", Protocol: ownProto},
		{Family: kernel.FamilyIPv6, Priority: 5410, Action: "lookup", Table: 254, Suppress: kernel.SuppressUpTo(0), Protocol: ownProto},
	}
	held := []kernel.DumpedRule{
		{Family: kernel.FamilyIPv4, Priority: 0, Action: "lookup", Table: 255, Protocol: 2},
		derived[0], derived[1], derived[2],
		// the reconciler's protocol on a rule it did not derive
		{Family: kernel.FamilyIPv4, Priority: 5120, IIF: "eth1", Action: "lookup", Table: 254, Protocol: ownProto},
		// the default protocol, which a reconciler naming another does not own
		{Family: kernel.FamilyIPv4, Priority: 5150, From: netip.MustParsePrefix("203.0.113.0/25"), Action: "lookup", Table: 254, Protocol: kernel.DefaultProtocol},
		{Family: kernel.FamilyIPv4, Priority: 1000, L3mdev: true, Action: "lookup", Protocol: 2},
		{Family: kernel.FamilyIPv6, Priority: 5410, Action: "lookup", Table: 254, Protocol: 4},
	}
	c.ruleDump = func() ([]kernel.DumpedRule, error) { return held, nil }
	c.SetReconciler(Reconciler{Rules: func() []kernel.DumpedRule { return derived }, Lookups: func() []kernel.Lookup {
		return []kernel.Lookup{
			{Family: kernel.FamilyIPv4, Prefix: netip.MustParsePrefix("192.0.2.0/24"), Address: netip.MustParseAddr("192.0.2.2"), Answer: "table 51820 dev wg0", Taken: true},
			{Family: kernel.FamilyIPv6, Address: netip.MustParseAddr("2001:db8:400::7"), Answer: "table main dev eth0"},
		}
	}})
	info := c.DebugRules()
	lookups := []control.RuleLookup{
		{Lookup: "overlay", Family: "ipv4", Prefix: netip.MustParsePrefix("192.0.2.0/24"), Address: netip.MustParseAddr("192.0.2.2"), Answer: "table 51820 dev wg0", Taken: true},
		{Lookup: "underlay", Family: "ipv6", Address: netip.MustParseAddr("2001:db8:400::7"), Answer: "table main dev eth0"},
	}
	if !slices.Equal(info.Lookups, lookups) {
		t.Errorf("debug rules carries the lookups %+v, want %+v", info.Lookups, lookups)
	}
	type flags struct{ owned, wanted bool }
	want := []flags{{false, false}, {true, true}, {true, true}, {true, true}, {true, false}, {false, false}, {false, false}, {false, false}}
	if len(info.Policy) != len(want) {
		t.Fatalf("debug rules read %d rules, want %d: %+v", len(info.Policy), len(want), info.Policy)
	}
	for i, rule := range info.Policy {
		if got := (flags{rule.Owned, rule.Wanted}); got != want[i] {
			t.Errorf("rule %d %+v reads owned %v, wanted %v, want %+v", i, rule, rule.Owned, rule.Wanted, want[i])
		}
	}
	if !info.Policy[6].L3mdev {
		t.Errorf("debug rules reads the l3mdev rule as %+v", info.Policy[6])
	}
	if info.Policy[1].Goto != 5190 || info.Policy[1].Suppress != nil {
		t.Errorf("debug rules reads the mark's goto as %+v", info.Policy[1])
	}
	zero := 0
	missing := control.PolicyRule{Family: "ipv6", Priority: 5410, Action: "lookup", Table: 254, Suppress: &zero, Protocol: ownProto, Owned: true, Wanted: true}
	if len(info.Missing) != 1 || !reflect.DeepEqual(info.Missing[0], missing) {
		t.Errorf("debug rules names missing %+v, want %+v alone", info.Missing, missing)
	}
	if info.PolicyErr != "" || info.Border != nil {
		t.Errorf("debug rules reads policy error %q and antispoof filter %+v on a node with no overlay", info.PolicyErr, info.Border)
	}
	written := *c.config()
	written.Overlay = overlayOf("3fff::/20")
	c.cfg.Store(&written)
	unenforced := c.DebugRules().Border
	runs := kernelexit.Filters(written.Border())
	if runs && unenforced != nil {
		t.Errorf("debug rules reads antispoof filter %+v on a node with overlay and no filter where the filter runs for it", unenforced)
	}
	if !runs && (unenforced == nil || unenforced.UnenforcedOn != runtime.GOOS || len(unenforced.Chains) != 0) {
		t.Errorf("debug rules reads antispoof filter %+v on %s, which runs none, want it not enforced there", unenforced, runtime.GOOS)
	}

	passed := time.Now().Add(-3 * time.Second)
	c.SetBorder(&borderRecord{debug: egress.BorderDebug{
		Where: "nftables table inet ranet3 chains antispoof and mesh_entry", PassAt: passed, Ready: true,
		Chains: []egress.BorderChainReading{{Name: "antispoof", Hook: "prerouting", Priority: new(-300),
			Rules: []egress.BorderReading{{Spec: "drop ipv6 source 3fff::/20", Verdict: "drop", Reason: "overlay_source", Family: "ipv6", Held: true, Packets: 2, Bytes: 160}}}},
		Sets: []egress.BorderSetReading{{Kind: "set", Name: "owned4", Elements: []egress.Range{{First: netip.MustParseAddr("192.0.2.7"), Last: netip.MustParseAddr("192.0.2.7")}}}},
	}})
	for name, dump := range map[string]struct {
		err  error
		want string
	}{
		"a platform with none": {kernel.ErrUnsupported, "this platform has no policy rules"},
		"a dump that failed":   {errors.New("kernel: dump rules: permission denied"), "kernel: dump rules: permission denied"},
	} {
		c.ruleDump = func() ([]kernel.DumpedRule, error) { return nil, dump.err }
		info := c.DebugRules()
		if info.PolicyErr != dump.want || len(info.Policy) != 0 || len(info.Missing) != 0 {
			t.Errorf("%s: debug rules reads policy error %q, %d rules and missing %+v", name, info.PolicyErr, len(info.Policy), info.Missing)
		}
		table := info.Border
		if table == nil || !table.ReadAt.Equal(passed) || table.ReadAt.Location() != time.UTC || time.Duration(table.ReadAgo) < 3*time.Second ||
			len(table.Chains) != 1 || len(table.Chains[0].Rules) != 1 || table.Chains[0].Rules[0].Packets != 2 || table.Chains[0].Priority == nil || *table.Chains[0].Priority != -300 || !table.Ready ||
			len(table.Sets) != 1 || table.Sets[0].Kind != "set" || table.Sets[0].Name != "owned4" || !slices.Equal(table.Sets[0].Elements, []string{"192.0.2.7"}) ||
			table.UnenforcedOn != "" || table.PF != nil || len(table.Enablers) != 0 {
			t.Errorf("%s: debug rules carries the table %+v", name, table)
		}
	}

	// darwin's filter carries its pf block and every reference pf lists
	c.SetBorder(&borderRecord{pf: &egress.BorderPF{Anchor: "com.apple/ranet3"}, debug: egress.BorderDebug{
		Where: "pf anchor com.apple/ranet3", PassAt: passed, Ready: true,
		Chains: []egress.BorderChainReading{{Name: "antispoof", Hook: "in",
			Rules: []egress.BorderReading{{Spec: "drop ipv6 source 3fff::/20", Verdict: "drop", Reason: "overlay_source", Family: "ipv6", Held: true, Packets: 2, Bytes: 160}}}},
		Sets: []egress.BorderSetReading{{Kind: "table", Name: "ranet3_carved"}},
		PF: &egress.BorderPF{Anchor: "com.apple/ranet3", Token: 1 << 63, PID: 4242, Listed: true, Called: true,
			Enablers: []pf.Enabler{{PID: 4242, Name: "ranet3", Token: 1 << 63}, {PID: 77, Name: "othervpn", Token: 9}}},
	}})
	table := c.DebugRules().Border
	block := control.BorderPF{Anchor: "com.apple/ranet3", Token: 1 << 63, PID: 4242, Listed: true, Called: true}
	enablers := []control.BorderEnabler{{PID: 4242, Name: "ranet3"}, {PID: 77, Name: "othervpn"}}
	if table == nil || table.UnenforcedOn != "" || table.PF == nil || *table.PF != block || !slices.Equal(table.Enablers, enablers) ||
		len(table.Chains) != 1 || table.Chains[0].Hook != "in" || table.Chains[0].Priority != nil ||
		len(table.Sets) != 1 || table.Sets[0].Kind != "table" {
		t.Errorf("debug rules carries the table over pf %+v, want its pf block %+v, the enablers %+v and its table", table, block, enablers)
	}
}
