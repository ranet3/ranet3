// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package babel

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/netstack"
)

// exchangeBudget bounds how long two running speakers take to read each other's IHUs
const exchangeBudget = 5 * time.Second

// the most specific key wins and the amounts never add up
func TestExtraCostTakesTheMostSpecificKey(t *testing.T) {
	extra := ExtraCost{
		Foreign: 1024,
		Org:     map[string]uint16{"gravity": 2048, "cheap": 5},
		Node:    map[string]uint16{"gravity/near": 300, "ysun/lagern": 7},
	}
	for _, test := range []struct {
		peer string
		want uint16
	}{
		{"gravity/near:0", 300},
		{"gravity/far:0", 2048},
		{"cheap/any:0", 5},
		{"other/any:0", 1024},
		{"ysun/cradle:0", 0},
		{"ysun/lagern:1", 7},
	} {
		if got := extra.For("ysun", identity.MustParse(test.peer)); got != test.want {
			t.Errorf("%s pays %d, want %d", test.peer, got, test.want)
		}
	}
	extra.Org["ysun"] = 11
	if got := extra.For("ysun", identity.MustParse("ysun/cradle:0")); got != 11 {
		t.Errorf("an org key naming this node's own organization charges its peer %d, want 11", got)
	}
	if got := extra.For("ysun", identity.Identity{}); got != 0 {
		t.Errorf("a neighbor with no identity pays %d, want nothing", got)
	}
}

// foreign is measured against the organization the speaker is given, so its own organization's neighbor pays nothing
func TestSpeakerChargesForeignAgainstItsOwnOrganization(t *testing.T) {
	speaker, err := New(Config{Cost: CostOptions{Extra: ExtraCost{Foreign: 1024}}}, Routes{}, Runtime{Organization: "ysun"}, netstack.NewRoutesOnly())
	if err != nil {
		t.Fatal(err)
	}
	speaker.AddPeer(newTestPeer(t, "own", nil).Peer, identity.MustParse("ysun/cradle:0"))
	speaker.AddPeer(newTestPeer(t, "other", nil).Peer, identity.MustParse("gravity/far:0"))
	for _, neighbor := range speaker.Stats().Neighbors {
		want := map[string]uint16{"own": 0, "other": 1024}[neighbor.Peer]
		if neighbor.Extra != want {
			t.Errorf("%s pays %d, want %d", neighbor.Peer, neighbor.Extra, want)
		}
	}
}

// an amount of infinity, and a node key that is not organization/name, are refused by the key that holds them
func TestExtraCostRefusals(t *testing.T) {
	for _, test := range []struct {
		extra ExtraCost
		names string
	}{
		{ExtraCost{Foreign: MetricInfinity}, "foreign"},
		{ExtraCost{Org: map[string]uint16{"gravity": MetricInfinity}}, `org "gravity"`},
		{ExtraCost{Org: map[string]uint16{"": 1}}, "empty organization"},
		{ExtraCost{Node: map[string]uint16{"ysun/lagern": MetricInfinity}}, `node "ysun/lagern"`},
		{ExtraCost{Node: map[string]uint16{"ysun/lagern:0": 1}}, "names an endpoint"},
		{ExtraCost{Node: map[string]uint16{"lagern": 1}}, `node "lagern"`},
	} {
		err := (Config{Cost: CostOptions{Extra: test.extra}}).Validate()
		if err == nil || !strings.Contains(err.Error(), test.names) {
			t.Errorf("%+v was refused with %v, want an error naming %s", test.extra, err, test.names)
		}
	}
	top := ExtraCost{Foreign: MetricInfinity - 1, Org: map[string]uint16{"gravity": MetricInfinity - 1}, Node: map[string]uint16{"ysun/lagern": MetricInfinity - 1}}
	if err := (Config{Cost: CostOptions{Extra: top}}).Validate(); err != nil {
		t.Errorf("the largest amounts were refused: %v", err)
	}
}

// extraNeighbor is a reachable neighbor of a fresh speaker whose cost.extra charges it amount
func extraNeighbor(t *testing.T, amount uint16) (*Speaker, *neighborState) {
	t.Helper()
	zero := uint16(0)
	cfg := Config{Quality: LinkQualityNone, Cost: CostOptions{RTT: RTTOptions{Weight: &zero}, Extra: ExtraCost{Foreign: amount}}}
	speaker, err := New(cfg, Routes{}, Runtime{Organization: "ysun"}, netstack.NewRoutesOnly())
	if err != nil {
		t.Fatal(err)
	}
	speaker.AddPeer(newTestPeer(t, "peer", nil).Peer, identity.MustParse("gravity/far:0"))
	n := speaker.neighbors["peer"]
	makeNeighborReachable(n)
	return speaker, n
}

// ihuRxCost is the rxcost of the IHU the speaker would send n now
func ihuRxCost(t *testing.T, speaker *Speaker, n *neighborState) uint16 {
	t.Helper()
	action := speaker.helloAction(n, time.Now())
	for _, tlv := range action.tlvs {
		if tlv.Type == TLVIHU {
			ihu, _, err := DecodeIHU(tlv.Body)
			if err != nil {
				t.Fatal(err)
			}
			return ihu.RxCost
		}
	}
	t.Fatal("the hello carries no IHU")
	return 0
}

// the amount goes on the link cost and on the IHU's rxcost, a finite sum stops one short of infinity and an infinite figure stays as it was
func TestExtraCostSaturatesBelowInfinityInBothPlaces(t *testing.T) {
	speaker, n := extraNeighbor(t, 1024)
	if got := n.linkCost(time.Now(), speaker.cost); got != 32+1024 {
		t.Errorf("the link costs %d, want the reported 32 and the 1024 extra", got)
	}
	if got := ihuRxCost(t, speaker, n); got != 96+1024 {
		t.Errorf("the IHU carries %d, want the rx cost 96 and the 1024 extra", got)
	}

	speaker, n = extraNeighbor(t, MetricInfinity-1)
	if got := n.linkCost(time.Now(), speaker.cost); got != MetricInfinity-1 {
		t.Errorf("the link costs %d with the largest extra, want %d", got, MetricInfinity-1)
	}
	if got := ihuRxCost(t, speaker, n); got != MetricInfinity-1 {
		t.Errorf("the IHU carries %d with the largest extra, want %d", got, MetricInfinity-1)
	}

	n.reportedCost = MetricInfinity
	if got := n.linkCost(time.Now(), speaker.cost); got != MetricInfinity {
		t.Errorf("an infinite txcost with an extra costs %d, want infinity", got)
	}
	speaker.cost.Quality = LinkQualityETX
	n.multicastHistory = helloHistory{started: true, samples: historyDepth}
	if got := ihuRxCost(t, speaker, n); got != MetricInfinity {
		t.Errorf("an IHU for a link that received no Hello carries %d with an extra, want infinity", got)
	}
}

// a pair of running speakers whose sessions authenticated a and b, a charging b's organization amount
func wireExtraPair(t *testing.T, amount uint16) (speakerA, speakerB *Speaker) {
	t.Helper()
	zero := uint16(0)
	cost := CostOptions{RTT: RTTOptions{Weight: &zero}}
	fast := Config{Hello: dur(20 * time.Millisecond), Update: dur(40 * time.Millisecond), Quality: LinkQualityNone, Cost: cost}
	charging := fast
	charging.Cost.Extra = ExtraCost{Org: map[string]uint16{"bravo": amount}}
	speakerA, err := New(charging, Routes{}, Runtime{Organization: "alpha"}, netstack.NewRoutesOnly())
	if err != nil {
		t.Fatal(err)
	}
	speakerB, err = New(fast, Routes{}, Runtime{Organization: "bravo"}, netstack.NewRoutesOnly())
	if err != nil {
		t.Fatal(err)
	}
	var peerAForB, peerBForA *testPeer
	peerBForA = newTestPeer(t, "b", func(raw []byte) { speakerB.Receive(peerAForB.Peer, raw) })
	peerAForB = newTestPeer(t, "a", func(raw []byte) { speakerA.Receive(peerBForA.Peer, raw) })
	speakerA.AddPeer(peerBForA.Peer, identity.MustParse("bravo/b:0"))
	speakerB.AddPeer(peerAForB.Peer, identity.MustParse("alpha/a:0"))
	go speakerA.Run(t.Context())
	go speakerB.Run(t.Context())
	return speakerA, speakerB
}

// the IHU half reaches the far speaker, which needs no setting: b reads a's rxcost with the amount in it and costs its link to a by it
func TestPeerSpeakerReadsTheExtraInTheIHU(t *testing.T) {
	speakerA, speakerB := wireExtraPair(t, 1000)
	want := uint16(96 + 1000)
	var b NeighborStat
	for deadline := time.Now().Add(exchangeBudget); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if b = speakerB.Stats().Neighbors[0]; b.HaveReportedCost && b.ReportedCost == want && b.Cost == want {
			break
		}
	}
	if b.ReportedCost != want || b.Cost != want || b.Extra != 0 {
		t.Errorf("b reads a as %+v, want a reported cost and a cost of %d and no extra of its own", b, want)
	}
	a := speakerA.Stats().Neighbors[0]
	if a.Cost != want || a.Extra != 1000 {
		t.Errorf("a reads b as %+v, want b's 96 with the 1000 extra, and the extra shown apart", a)
	}
}

// a reload that changes an amount charges each neighbor again, selection moves off the dearer one and the neighbors are told
func TestReloadedExtraCostMovesTheRoute(t *testing.T) {
	zero := uint16(0)
	cost := CostOptions{RTT: RTTOptions{Weight: &zero}}
	mesh := &netstack.Mesh{Routes: netstack.NewRouteTable()}
	bus := events.New()
	speaker, err := New(Config{Cost: cost}, Routes{}, Runtime{Organization: "alpha", Events: bus}, mesh)
	if err != nil {
		t.Fatal(err)
	}
	var toB [][]byte
	b := newTestPeer(t, "b", func(raw []byte) { toB = append(toB, append([]byte(nil), raw...)) })
	c := newTestPeer(t, "c", nil)
	speaker.AddPeer(b.Peer, identity.MustParse("bravo/b:0"))
	speaker.AddPeer(c.Peer, identity.MustParse("charlie/c:0"))

	dest := netip.MustParsePrefix("fd00:c::/64")
	key := routeKey{dest: dest}
	now := time.Now()
	speaker.mu.Lock()
	makeNeighborReachable(speaker.neighbors["b"])
	makeNeighborReachable(speaker.neighbors["c"])
	speaker.routes.update(speaker.neighbors["b"], key, advertisement{routerID: [8]byte{1}, seqno: 1, metric: 10}, time.Minute, now)
	speaker.routes.update(speaker.neighbors["c"], key, advertisement{routerID: [8]byte{2}, seqno: 1, metric: 100}, time.Minute, now)
	speaker.mu.Unlock()
	if peer, verdict, _ := mesh.Routes.Resolve(dest.Addr(), dest.Addr()); verdict != netstack.RoutePeer || peer != b.Peer {
		t.Fatalf("the prefix is not through b before the reload, so this proves nothing: %v", mesh.Routes.Debug())
	}
	b.settle(t)
	toB = nil

	speaker.SetConfig(Config{Cost: CostOptions{RTT: cost.RTT, Extra: ExtraCost{Org: map[string]uint16{"bravo": 500}}}})
	if peer, verdict, _ := mesh.Routes.Resolve(dest.Addr(), dest.Addr()); verdict != netstack.RoutePeer || peer != c.Peer {
		t.Errorf("the prefix is forwarded as %v once b pays 500, want through c", mesh.Routes.Debug())
	}
	for _, neighbor := range speaker.Stats().Neighbors {
		want := uint16(0)
		if neighbor.Peer == "b" {
			want = 500
		}
		if neighbor.Extra != want || neighbor.Cost != 32+want {
			t.Errorf("%s reads as extra %d and cost %d, want %d and %d", neighbor.Peer, neighbor.Extra, neighbor.Cost, want, 32+want)
		}
	}
	b.settle(t)
	if len(toB) == 0 {
		t.Error("the reload sent b nothing, want the Hello with its IHU and the table")
	}
	var charged []string
	for _, event := range bus.Recorded(everything, 0) {
		if event.Kind == "babel.neighbor.extra" {
			charged = append(charged, event.Peer+" "+event.Attrs["from"]+" "+event.Attrs["extra"])
		}
	}
	if len(charged) != 1 || charged[0] != "b 0 500" {
		t.Errorf("the reload recorded %q, want b charged from 0 to 500 alone", charged)
	}

	speaker.SetConfig(Config{Cost: CostOptions{RTT: cost.RTT, Extra: ExtraCost{Foreign: 50, Org: map[string]uint16{"bravo": 500}}}})
	for _, neighbor := range speaker.Stats().Neighbors {
		want := map[string]uint16{"b": 500, "c": 50}[neighbor.Peer]
		if neighbor.Extra != want {
			t.Errorf("%s reads as extra %d after a reload changing only foreign, want %d", neighbor.Peer, neighbor.Extra, want)
		}
	}
}
