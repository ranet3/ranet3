// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package babel

import (
	"context"
	"log/slog"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/netstack"
)

// entryAt is the value the forwarding table holds at exactly key
func entryAt(mesh *netstack.Mesh, key routeKey) (*netstack.Peer, bool) {
	for _, route := range mesh.Routes.Snapshot() {
		if route.Source == key.source && route.Destination == key.dest {
			return route.Value, true
		}
	}
	return nil, false
}

// peerName names a forwarding entry's value in a failure, nothing for none
func peerName(peer *netstack.Peer) string {
	if peer == nil {
		return "nothing"
	}
	return peer.ID
}

// offer hands node an Update from peer for key, under origin's router id at
// seqno and metric
func (f *meshFabric) offer(node, peer, origin string, key routeKey, seqno, metric uint16) {
	f.t.Helper()
	f.inject(node, peer,
		EncodeRouterID(routerID(origin)),
		EncodeUpdate(Update{AE: AEIPv6, Plen: key.dest.Bits(), Prefix: key.dest.Addr().AsSlice(),
			Interval: 6000, Seqno: seqno, Metric: metric, SourcePrefix: key.source}))
}

// Every key this node originates is its own in the forwarding table, a plain
// prefix and a default from its transit prefix alike, and the default is its
// own only for a packet from that prefix.
func TestOriginationInstallsLocal(t *testing.T) {
	mesh := &netstack.Mesh{Routes: netstack.NewRouteTable()}
	speaker, err := New(Config{}, Routes{}, Runtime{}, mesh)
	if err != nil {
		t.Fatal(err)
	}
	plain := routeKey{dest: netip.MustParsePrefix("2001:db8:1::/48")}
	exit := routeKey{source: netip.MustParsePrefix("2001:db8:a::/48"), dest: netip.MustParsePrefix("::/0")}
	speaker.Originate(plain.dest)
	speaker.OriginateFrom(exit.dest, exit.source)
	for _, key := range []routeKey{plain, exit} {
		if value, ok := entryAt(mesh, key); !ok || value != netstack.Local {
			t.Errorf("%s holds %s, want this node's own entry", describeRoute(key), peerName(value))
		}
	}
	internet := netip.MustParseAddr("2001:4860:4860::8888")
	for _, test := range []struct {
		from, to netip.Addr
		want     netstack.Verdict
		wanted   string
	}{
		{netip.MustParseAddr("2001:db8:5::1"), netip.MustParseAddr("2001:db8:1::1"), netstack.RouteLocal, "this node's own"},
		{netip.MustParseAddr("2001:db8:a::1"), internet, netstack.RouteLocal, "this node's own"},
		{netip.MustParseAddr("2001:db8:b::1"), internet, netstack.RouteNone, "no route"},
	} {
		if _, verdict, _ := mesh.Routes.Resolve(test.from, test.to); verdict != test.want {
			t.Errorf("a packet from %s to %s resolves as verdict %d, want %s", test.from, test.to, verdict, test.wanted)
		}
	}
}

// A route a neighbor offers for a key this node holds as its own never takes
// its place, whether the key is announced, announced from a source, or an
// address cap.table assigns, and the offer never enters the route table where
// a later selection could install it.
func TestLearnedRouteNeverReplacesThisNodesOwnEntry(t *testing.T) {
	fabric := newMeshFabric(t, Config{}, "a-b")
	plain := routeKey{dest: netip.MustParsePrefix("2001:db8:1::/48")}
	exit := routeKey{source: netip.MustParsePrefix("2001:db8:a::/48"), dest: netip.MustParsePrefix("::/0")}
	address := netip.MustParseAddr("2001:db8:5::1")
	assigned := routeKey{dest: netip.PrefixFrom(address, address.BitLen())}
	a, b := fabric.speakers["a"], fabric.speakers["b"]
	a.Originate(plain.dest)
	a.OriginateFrom(exit.dest, exit.source)
	a.SetAssigned([]netip.Addr{address})
	b.Originate(plain.dest)
	b.OriginateFrom(exit.dest, exit.source)
	b.Originate(assigned.dest)
	fabric.flush("b")
	for _, test := range []struct {
		key  routeKey
		want *netstack.Peer
	}{
		{plain, netstack.Local},
		{exit, netstack.Local},
		{assigned, netstack.Assigned},
	} {
		fabric.offer("a", "b", "b", test.key, 7, 1)
		if value, ok := entryAt(fabric.meshes["a"], test.key); !ok || value != test.want {
			t.Errorf("%s holds %s after b offered it, want this node's own entry", describeRoute(test.key), peerName(value))
		}
		if _, learned := a.routes.entries[test.key]; learned {
			t.Errorf("b's offer of %s entered the route table", describeRoute(test.key))
		}
	}
}

// An address cap.table assigns is this node's own and is never announced. A
// neighbor told of it before, as a route this node relayed, is sent a
// retraction by the next dump, and no dump after that mentions it. A route
// request for it is answered as RFC 8966 section 3.8.1.1 answers one for a
// prefix with no selected route: "if such a route does not exist, it MUST send
// a retraction for that prefix". A seqno request for it naming another node's
// router id is neither answered with an update nor forwarded, since this node
// holds no route of Babel's to it. RFC 8966 section 3.8.1.2 has a node answer
// one when "a selected route for the given prefix exists and has finite
// metric", and forward it when "the node is advertising the prefix to its
// neighbours".
func TestAssignedAddressIsThisNodesAndNeverAnnounced(t *testing.T) {
	fabric := newMeshFabric(t, Config{}, "c-a", "a-b")
	address := netip.MustParseAddr("2001:db8:5::1")
	key := routeKey{dest: netip.PrefixFrom(address, address.BitLen())}
	fabric.speakers["c"].Originate(key.dest)
	fabric.flush("c", "a")
	if got := fabric.nextHop("b", key); got != "a" {
		t.Fatalf("b reaches %s via %q before a is assigned it, want a", key.dest, got)
	}

	fabric.reset()
	fabric.speakers["a"].SetAssigned([]netip.Addr{address})
	if value, ok := entryAt(fabric.meshes["a"], key); !ok || value != netstack.Assigned {
		t.Fatalf("%s holds %s once assigned, want this node's entry for an assigned address", key.dest, peerName(value))
	}
	fabric.flush("a")
	if updates := updatesFor(t, fabric.tlvs("a", "b"), key.dest); len(updates) != 1 || updates[0].Metric != MetricInfinity {
		t.Errorf("a sent b %v for an address it had relayed to b and is now assigned, want one retraction", updates)
	}
	if updates := updatesFor(t, fabric.tlvs("a", "c"), key.dest); len(updates) != 0 {
		t.Errorf("a sent c %v for an address it is assigned, want nothing", updates)
	}
	if got := fabric.nextHop("b", key); got != "" {
		t.Errorf("b still reaches %s via %q after a retracted it", key.dest, got)
	}

	fabric.reset()
	fabric.flush("a")
	for _, peer := range []string{"b", "c"} {
		if updates := updatesFor(t, fabric.tlvs("a", peer), key.dest); len(updates) != 0 {
			t.Errorf("a's next dump carried %v to %s, want nothing about an address it never announces", updates, peer)
		}
	}

	fabric.reset()
	fabric.inject("a", "b", EncodeRouteRequest(RouteRequest{AE: AEIPv6, Prefix: key.dest}))
	if updates := updatesFor(t, fabric.tlvs("a", "b"), key.dest); len(updates) != 1 || updates[0].Metric != MetricInfinity {
		t.Errorf("a answered a route request for %s with %v, want one retraction", key.dest, updates)
	}

	fabric.reset()
	fabric.inject("a", "b", EncodeSeqnoRequest(SeqnoRequest{AE: AEIPv6, Prefix: key.dest, Seqno: 9, HopCount: 64, RouterID: routerID("c")}))
	for _, peer := range []string{"b", "c"} {
		if updates := updatesFor(t, fabric.tlvs("a", peer), key.dest); len(updates) != 0 {
			t.Errorf("a answered a seqno request for %s by sending %s %v", key.dest, peer, updates)
		}
	}
	if requests := seqnoRequestsFor(t, fabric.tlvs("a", "c"), key.dest); len(requests) != 0 {
		t.Errorf("a forwarded a seqno request for %s, an address it is assigned, to c: %v", key.dest, requests)
	}
}

// An address cap.table stops assigning is given back, so the route a neighbor
// offers for it is learned again rather than left behind this node's own entry
// for the life of the process.
func TestUnassignedAddressCanBeLearnedAgain(t *testing.T) {
	fabric := newMeshFabric(t, Config{}, "a-b")
	address := netip.MustParseAddr("2001:db8:5::1")
	key := routeKey{dest: netip.PrefixFrom(address, address.BitLen())}
	fabric.speakers["b"].Originate(key.dest)
	fabric.speakers["a"].SetAssigned([]netip.Addr{address})
	fabric.flush("b")
	if got := fabric.nextHop("a", key); got != "" {
		t.Fatalf("a learned %s from %q while it is assigned", key.dest, got)
	}

	fabric.speakers["a"].SetAssigned(nil)
	if value, ok := entryAt(fabric.meshes["a"], key); ok {
		t.Fatalf("%s still holds %s once it is no longer assigned", key.dest, peerName(value))
	}
	fabric.flush("b")
	if got := fabric.forwards("a", address); got != "b" {
		t.Errorf("a reaches %s via %q once it is no longer assigned, want b", address, got)
	}
}

// A host prefix this node announces and also carries as an assigned address
// stays its own while either holds it, as a prefix it originates while it is
// announced. Dropping the announcement retracts it from the neighbor it was
// announced to and keeps it this node's own as an assigned address, and only
// dropping both gives it back, held as a prefix this node announced is.
func TestAddressBothOriginatedAndAssignedStaysThisNodesUntilNeither(t *testing.T) {
	fabric := newMeshFabric(t, Config{}, "a-b")
	address := netip.MustParseAddr("2001:db8:5::1")
	key := routeKey{dest: netip.PrefixFrom(address, address.BitLen())}
	a := fabric.speakers["a"]
	a.Originate(key.dest)
	a.SetAssigned([]netip.Addr{address})
	if value, ok := entryAt(fabric.meshes["a"], key); !ok || value != netstack.Local {
		t.Fatalf("%s holds %s while announced and assigned, want the entry of a prefix this node originates", key.dest, peerName(value))
	}
	fabric.flush("a")
	if got := fabric.nextHop("b", key); got != "a" {
		t.Fatalf("b reaches %s via %q, want a", key.dest, got)
	}

	fabric.reset()
	a.SetOriginated(nil)
	if value, ok := entryAt(fabric.meshes["a"], key); !ok || value != netstack.Assigned {
		t.Fatalf("%s holds %s once no longer announced, want this node's entry for an assigned address", key.dest, peerName(value))
	}
	fabric.flush("a")
	if updates := updatesFor(t, fabric.tlvs("a", "b"), key.dest); len(updates) != 1 || updates[0].Metric != MetricInfinity {
		t.Errorf("a sent b %v for an address it stopped announcing, want one retraction", updates)
	}

	a.Originate(key.dest)
	a.SetAssigned(nil)
	if value, ok := entryAt(fabric.meshes["a"], key); !ok || value != netstack.Local {
		t.Fatalf("%s holds %s once no longer assigned, want this node's own entry while it is announced", key.dest, peerName(value))
	}
	a.SetOriginated(nil)
	if value, ok := entryAt(fabric.meshes["a"], key); !ok || value != netstack.Unreachable {
		t.Errorf("%s holds %s once neither announced nor assigned, want it held", key.dest, peerName(value))
	}
}

// A changed set of assigned addresses asks for a dump at the next pass, which
// is where a neighbor told of one of them hears the retraction. The same set
// again, in any order, asks for nothing.
func TestAssignedAddressesAskForDumpOnlyWhenChanged(t *testing.T) {
	speaker, err := New(Config{}, Routes{}, Runtime{}, &netstack.Mesh{Routes: netstack.NewRouteTable()})
	if err != nil {
		t.Fatal(err)
	}
	pending := func() bool {
		speaker.mu.Lock()
		defer speaker.mu.Unlock()
		asked := speaker.updatePending
		speaker.updatePending = false
		return asked
	}
	pending()
	first, second := netip.MustParseAddr("2001:db8:5::1"), netip.MustParseAddr("192.0.2.7")
	speaker.SetAssigned([]netip.Addr{first, second})
	if !pending() {
		t.Error("assigning two addresses asked for no dump")
	}
	speaker.SetAssigned([]netip.Addr{second, first})
	if pending() {
		t.Error("the same two addresses again asked for a dump")
	}
	speaker.SetAssigned(nil)
	if !pending() {
		t.Error("dropping both addresses asked for no dump")
	}
}

// A prefix learned inside one this node originates is forwarded by the longer
// match, and once retracted it is held: RFC 8966 section 3.5.4 says "packets
// destined to an address within P MUST NOT be forwarded by following a route
// for a shorter prefix", and this node's own covering entry is a shorter
// prefix too. Once the hold is flushed the covering entry answers again.
func TestRetractedPrefixInsideThisNodesOwnIsHeld(t *testing.T) {
	fabric := newMeshFabric(t, Config{}, "a-b")
	covering := netip.MustParsePrefix("fd00::/16")
	specific := routeKey{dest: netip.MustParsePrefix("fd00:b::/64")}
	inside := netip.MustParseAddr("fd00:b::1")
	fabric.speakers["a"].Originate(covering)
	fabric.speakers["b"].Originate(specific.dest)
	fabric.flush("b")
	if peer, verdict, _ := fabric.meshes["a"].Routes.Resolve(inside, inside); verdict != netstack.RoutePeer || peer.ID != "b" {
		t.Fatalf("a resolves %s as %v through %s, want b by the longer match", inside, verdict, peerName(peer))
	}

	fabric.offer("a", "b", "b", specific, 1, MetricInfinity)
	if peer, verdict, _ := fabric.meshes["a"].Routes.Resolve(inside, inside); verdict != netstack.RouteHeld {
		t.Fatalf("a resolves %s as %v through %s once it is retracted, want it held", inside, verdict, peerName(peer))
	}

	a := fabric.speakers["a"]
	a.mu.Lock()
	a.routes.sweepExpired(time.Now().Add(time.Hour))
	_, held := a.routes.entries[specific]
	a.mu.Unlock()
	if held {
		t.Fatal("the retracted route was not flushed, so this proves nothing")
	}
	if _, verdict, _ := fabric.meshes["a"].Routes.Resolve(inside, inside); verdict != netstack.RouteLocal {
		t.Errorf("a resolves %s as %v once the hold is flushed, want this node's own covering prefix", inside, verdict)
	}
}

// quietInterval is the hello and update interval of a speaker whose run loop
// sends nothing of its own accord while a test waits
const quietInterval = time.Minute

// assignedWakeWait is how long a test waits for the pass a changed set of
// assigned addresses wakes, far inside quietInterval
const assignedWakeWait = 5 * time.Second

// A changed set of assigned addresses wakes the running speaker, so a neighbor
// told of one of them before, as a route this node relayed, hears the
// retraction at once rather than at the next periodic update.
func TestAssignedAddressesWakeTheRunningSpeaker(t *testing.T) {
	fabric := newMeshFabric(t, Config{Hello: dur(quietInterval), Update: dur(quietInterval)}, "c-a", "a-b")
	address := netip.MustParseAddr("2001:db8:5::1")
	key := routeKey{dest: netip.PrefixFrom(address, address.BitLen())}
	fabric.speakers["c"].Originate(key.dest)
	fabric.flush("c", "a")
	if got := fabric.nextHop("b", key); got != "a" {
		t.Fatalf("b reaches %s via %q before a is assigned it, want a", key.dest, got)
	}
	a := fabric.speakers["a"]
	select {
	case <-a.changed:
	default:
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); _ = a.Run(ctx) }()
	defer func() { cancel(); <-done }()
	for deadline := time.Now().Add(assignedWakeWait); a.Passes() == 0; {
		if time.Now().After(deadline) {
			t.Fatal("the speaker never ran its first pass, so this proves nothing")
		}
		time.Sleep(time.Millisecond)
	}
	fabric.reset()

	a.SetAssigned([]netip.Addr{address})
	var updates []Update
	for deadline := time.Now().Add(assignedWakeWait); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if updates = updatesFor(t, fabric.tlvs("a", "b"), key.dest); len(updates) != 0 {
			break
		}
	}
	if len(updates) != 1 || updates[0].Metric != MetricInfinity {
		t.Errorf("a sent b %v within %v of being assigned an address it had relayed, want one retraction", updates, assignedWakeWait)
	}
}

// A change to the keys this node originates, or to the addresses cap.table
// assigns it, is recorded once, with the keys it added and removed and those
// it holds, and the same set again records nothing. Only a key new to the set
// is added. A key is held while a finite update this node sent for it has not
// yet expired, so an address both announced and assigned is held once its
// assignment goes too, though a retraction followed when its announcement went.
func TestChangesToThisNodesOwnKeysAreRecorded(t *testing.T) {
	bus := events.New()
	speaker, _, _ := captureSpeaker(t, Config{}, Runtime{Events: bus})
	address, second := netip.MustParseAddr("2001:db8:5::1"), netip.MustParseAddr("2001:db8:5::2")
	host := netip.PrefixFrom(address, address.BitLen())
	plain, exit := netip.MustParsePrefix("2001:db8:1::/48"), netip.MustParsePrefix("::/0")
	transit := netip.MustParsePrefix("2001:db8:a::/48")
	speaker.SetOriginated([]OriginatedRoute{{Destination: plain}, {Destination: exit, Source: transit}, {Destination: host}})
	speaker.flushUpdates()
	speaker.SetAssigned([]netip.Addr{address})
	speaker.SetAssigned([]netip.Addr{address, second})
	speaker.SetOriginated([]OriginatedRoute{{Destination: plain}, {Destination: host}})
	speaker.SetOriginated([]OriginatedRoute{{Destination: plain}, {Destination: host}})
	speaker.SetOriginated([]OriginatedRoute{{Destination: plain}})
	speaker.flushUpdates()
	speaker.SetAssigned(nil)
	speaker.Originate(netip.MustParsePrefix("2001:db8:2::/48"))
	speaker.Originate(netip.MustParsePrefix("2001:db8:2::/48"))
	var got []map[string]string
	for _, event := range bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "babel.own.changed" }, 0) {
		got = append(got, event.Attrs)
	}
	want := []map[string]string{
		{"set": "originated", "added": "::/0 from 2001:db8:a::/48, 2001:db8:1::/48, 2001:db8:5::1/128"},
		{"set": "assigned", "added": "2001:db8:5::1/128"},
		{"set": "assigned", "added": "2001:db8:5::2/128"},
		{"set": "originated", "removed": "::/0 from 2001:db8:a::/48", "held": "::/0 from 2001:db8:a::/48"},
		{"set": "originated", "removed": "2001:db8:5::1/128"},
		{"set": "assigned", "removed": "2001:db8:5::1/128, 2001:db8:5::2/128", "held": "2001:db8:5::1/128"},
		{"set": "originated", "added": "2001:db8:2::/48"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("the changes were recorded as %v, want %v", got, want)
	}
}
