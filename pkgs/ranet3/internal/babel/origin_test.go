// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package babel

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/internal/events"
)

// seqnoEvents is every babel.seqno and babel.state event bus holds, each as its kind, its peer and the attributes named in order
func seqnoEvents(bus *events.Bus, attrs ...string) []string {
	var out []string
	for _, event := range bus.Recorded(func(kind, _ string, _ []slog.Attr) bool {
		return strings.HasPrefix(kind, "babel.seqno.") || strings.HasPrefix(kind, "babel.state.")
	}, 0) {
		var line strings.Builder
		line.WriteString(event.Kind + " " + event.Peer)
		for _, name := range attrs {
			if value, ok := event.Attrs[name]; ok {
				line.WriteString(" " + name + "=" + value)
			}
		}
		out = append(out, line.String())
	}
	return out
}

// askSeqno is a seqno request for prefix under id
func askSeqno(id [8]byte, prefix netip.Prefix, seqno uint16) RawTLV {
	return EncodeSeqnoRequest(SeqnoRequest{AE: AEIPv6, Prefix: prefix, Seqno: seqno, HopCount: 64, RouterID: id})
}

// a start records its raise with the router id
// a seqno request naming this node records whether a raise answers it
// a raise for a request records the neighbor whose request owed it first, once the next update is built
// a run after the first records its own raise
// every request asking past the seqno of a prefix this node originates before that update is answered by the one raise
// a request naming another router id records nothing and leaves the seqno where it was
func TestSeqnoRequestsAndRaisesAreRecorded(t *testing.T) {
	bus := events.New()
	id, foreign := [8]byte{0x72, 1, 2, 3, 4, 5, 6, 7}, [8]byte{0x72, 9, 9, 9, 9, 9, 9, 9}
	speaker, neighbor, _ := captureSpeaker(t, Config{}, Runtime{RouterID: id, Events: bus})
	mine, other := netip.MustParsePrefix("fd00:5::/64"), netip.MustParsePrefix("fd00:6::/64")
	speaker.Originate(mine)
	speaker.SetOrigin(Origin{RouterID: id, Limit: 10}, func(Origin) error { return nil }, "")
	speaker.handlePacket(neighbor, EncodePacket([]RawTLV{askSeqno(id, mine, 12), askSeqno(id, mine, 13)}))
	speaker.sendTriggered(time.Now())
	speaker.handlePacket(neighbor, EncodePacket([]RawTLV{
		askSeqno(id, mine, 12), askSeqno(id, mine, 11), askSeqno(foreign, mine, 40), askSeqno(id, other, 40),
	}))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for range 2 {
		_ = speaker.Run(ctx)
	}

	got := seqnoEvents(bus, "route", "asked", "seqno", "raised", "cause", "from", "to", "limit", "router_id", "drawn")
	want := []string{
		"babel.seqno.raised  cause=start from=10 to=11 limit=267 router_id=7201020304050607",
		"babel.seqno.requested peer route=fd00:5::/64 asked=12 seqno=11 raised=true",
		"babel.seqno.requested peer route=fd00:5::/64 asked=13 seqno=11 raised=true",
		"babel.seqno.raised peer cause=request from=11 to=12 limit=267",
		"babel.seqno.requested peer route=fd00:5::/64 asked=12 seqno=12 raised=false",
		"babel.seqno.requested peer route=fd00:5::/64 asked=11 seqno=12 raised=false",
		"babel.seqno.requested peer route=fd00:6::/64 asked=40 seqno=12 raised=false",
		"babel.seqno.raised  cause=start from=12 to=13 limit=267",
	}
	if !slices.Equal(got, want) {
		t.Errorf("the speaker recorded\n%q\nwant\n%q", got, want)
	}

	// a router id drawn for want of one to keep says why
	drawn := events.New()
	fresh, _, _ := captureSpeaker(t, Config{}, Runtime{RouterID: id, Events: drawn})
	fresh.SetOrigin(Origin{}, func(Origin) error { return nil }, "no state file")
	if got := seqnoEvents(drawn, "cause", "from", "to", "router_id", "drawn"); !slices.Equal(got, []string{
		"babel.seqno.raised  cause=start from=0 to=1 router_id=7201020304050607 drawn=no state file",
	}) {
		t.Errorf("a start under a drawn router id recorded %q", got)
	}
}

// the first pass of a run sends every prefix this node originates at the seqno its start raised, and so does the first pass of a run after it
// a dump at the seqno before the raise could repeat one the process before sent with another metric, which a neighbor holding it finds unfeasible
func TestFirstPassOfARunSendsTheSeqnoItsStartRaised(t *testing.T) {
	id := [8]byte{0x72, 1, 2, 3, 4, 5, 6, 9}
	speaker, _, packets := captureSpeaker(t, Config{}, Runtime{RouterID: id})
	mine := []netip.Prefix{netip.MustParsePrefix("fd00:5:2::/64"), netip.MustParsePrefix("fd00:5:3::/64")}
	for _, prefix := range mine {
		speaker.Originate(prefix)
	}
	speaker.SetOrigin(Origin{RouterID: id, Limit: 10}, func(Origin) error { return nil }, "")
	for run := range 2 {
		packets.reset()
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { defer close(done); _ = speaker.Run(ctx) }()
		deadline := time.Now().Add(10 * time.Second)
		var first map[netip.Prefix]uint16
		for {
			first = map[netip.Prefix]uint16{}
			for _, prefix := range mine {
				if updates := updatesIn(t, packets.sent(), prefix); len(updates) != 0 {
					first[prefix] = updates[0].Seqno
				}
			}
			if len(first) == len(mine) || time.Now().After(deadline) {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		cancel()
		<-done
		_, seqno := speaker.Origin()
		for _, prefix := range mine {
			if got, ok := first[prefix]; !ok || got != seqno {
				t.Errorf("run %d first sent %s at seqno %d (sent %v), want the raised %d", run+1, prefix, got, ok, seqno)
			}
		}
	}
}

// a raise for a request owes every neighbor a triggered update of the prefix asked for, RFC 8966 section 3.7.2
// b asks a for one of its two prefixes
// b and c hear that one at the raised seqno from the next triggered pass, and the other only from the next periodic dump
func TestRaiseForARequestTriggersOnlyThePrefixAskedFor(t *testing.T) {
	fabric := newMeshFabric(t, Config{}, "a-b", "a-c")
	origin := fabric.speakers["a"]
	asked, other := netip.MustParsePrefix("fd00:a::/64"), netip.MustParsePrefix("fd00:a:1::/64")
	origin.Originate(asked)
	origin.Originate(other)
	fabric.flush("a")
	_, seqno := origin.Origin()
	fabric.reset()
	fabric.inject("a", "b", askSeqno(routerID("a"), asked, seqno+1))
	fabric.trigger("a")
	for _, peer := range []string{"b", "c"} {
		if got := updatesFor(t, fabric.tlvs("a", peer), asked); len(got) != 1 || got[0].Seqno != seqno+1 {
			t.Errorf("a sent %s %+v for %s after the raise, want one Update at seqno %d", peer, got, asked, seqno+1)
		}
		if got := updatesFor(t, fabric.tlvs("a", peer), other); len(got) != 0 {
			t.Errorf("a sent %s %+v for %s, which nobody asked for, before the periodic dump", peer, got, other)
		}
	}
	fabric.flush("a")
	if got := updatesFor(t, fabric.tlvs("a", "c"), other); len(got) != 1 || got[0].Seqno != seqno+1 {
		t.Errorf("the periodic dump sent c %+v for %s, want one Update at the raised seqno %d", got, other, seqno+1)
	}
}

// two neighbors ask past the seqno before the next update is built, and the one raise names the first as its peer
func TestRaiseNamesTheFirstNeighborWhoseRequestOwedIt(t *testing.T) {
	bus := events.New()
	id := [8]byte{0x72, 1, 2, 3, 4, 5, 6, 8}
	speaker, first, _ := captureSpeaker(t, Config{}, Runtime{RouterID: id, Events: bus})
	other := newHeldPeer(t, "other", nil)
	speaker.AddPeer(other.Peer, identity.Identity{})
	second := speaker.neighbors[other.ID]
	mine := netip.MustParsePrefix("fd00:5:1::/64")
	speaker.Originate(mine)
	_, seqno := speaker.Origin()
	speaker.handlePacket(first, EncodePacket([]RawTLV{askSeqno(id, mine, seqno+1)}))
	speaker.handlePacket(second, EncodePacket([]RawTLV{askSeqno(id, mine, seqno+1)}))
	speaker.sendTriggered(time.Now())
	var raised []string
	for _, event := range seqnoEvents(bus, "cause") {
		if strings.HasPrefix(event, "babel.seqno.raised ") {
			raised = append(raised, event)
		}
	}
	if want := []string{"babel.seqno.raised " + first.peer.ID + " cause=request"}; !slices.Equal(raised, want) {
		t.Errorf("the raise was recorded as %q, want %q", raised, want)
	}
}

// a save that fails is logged and recorded, and the seqno rises all the same
// the next raise past the limit last saved tries the save again
func TestFailedSaveRaisesAnywayAndIsTriedAgain(t *testing.T) {
	bus := events.New()
	id := [8]byte{0x72, 1, 2, 3, 4, 5, 6, 7}
	speaker, neighbor, _ := captureSpeaker(t, Config{}, Runtime{RouterID: id, Events: bus})
	prefix := netip.MustParsePrefix("fd00:5::/64")
	speaker.Originate(prefix)
	var tried []Origin
	full := true
	speaker.SetOrigin(Origin{RouterID: id, Limit: 10}, func(origin Origin) error {
		tried = append(tried, origin)
		if full {
			return errors.New("no space left on device")
		}
		return nil
	}, "")
	if origin, seqno := speaker.Origin(); origin.Limit != 10 || seqno != 11 {
		t.Errorf("a start whose save failed holds the limit %d and the seqno %d, want 10 and 11", origin.Limit, seqno)
	}
	full = false
	speaker.handlePacket(neighbor, EncodePacket([]RawTLV{askSeqno(id, prefix, 12)}))
	speaker.sendTriggered(time.Now())
	if origin, seqno := speaker.Origin(); origin.Limit != 268 || seqno != 12 {
		t.Errorf("the raise after a failed save holds the limit %d and the seqno %d, want 268 and 12", origin.Limit, seqno)
	}
	if want := []Origin{{RouterID: id, Limit: 267}, {RouterID: id, Limit: 268}}; !slices.Equal(tried, want) {
		t.Errorf("the speaker tried to save %v, want %v", tried, want)
	}
	got := seqnoEvents(bus, "cause", "from", "to", "limit", "seqno", "err")
	want := []string{
		"babel.state.unsaved  limit=267 seqno=11 err=no space left on device",
		"babel.seqno.raised  cause=start from=10 to=11 limit=10",
		"babel.seqno.requested peer seqno=11",
		"babel.seqno.raised peer cause=request from=11 to=12 limit=268",
	}
	if !slices.Equal(got, want) {
		t.Errorf("the speaker recorded\n%q\nwant\n%q", got, want)
	}
}

// a restarted origin's routes are feasible at once at a node holding a feasibility distance from before the restart, which asks for no seqno
// the origin last advertised the limit it saved, and comes back over a costlier link, so only a seqno past that limit is feasible there
func TestRestartedOriginIsFeasibleFarAwayWithoutASeqnoRequest(t *testing.T) {
	fabric := newMeshFabric(t, Config{}, "d-a", "a-b", "b-c")
	dest := netip.MustParsePrefix("fd00:c::/64")
	key := routeKey{dest: dest}
	var saved Origin
	save := func(origin Origin) error {
		saved = origin
		return nil
	}
	origin := fabric.speakers["c"]
	origin.SetOrigin(Origin{}, save, "no state file")
	origin.Originate(dest)
	fabric.flush("c", "b", "a", "d")
	limit := saved.Limit
	for range seqnoLimitAhead {
		if origin.originSeqno != limit {
			fabric.inject("c", "b", askSeqno(routerID("c"), dest, origin.originSeqno+1))
			fabric.flush("c")
		}
	}
	fabric.flush("c", "b", "a", "d")
	if got := fabric.selected("a", key); fabric.nextHop("a", key) != "b" || got.seqno != limit {
		t.Fatalf("a selected %+v before the restart, want the route through b at the saved limit %d", got, limit)
	}

	fabric.down("b-c")
	fabric.flush("b", "a")
	delete(fabric.speakers, "c")
	restarted := fabric.node(Config{}, "c")
	restarted.SetOrigin(saved, save, "")
	restarted.Originate(dest)
	fabric.connect(Config{}, "b", "c")
	fabric.cost("b", "c", 1000)
	fabric.reset()
	fabric.flush("c", "b", "a", "d")
	if got := fabric.selected("a", key); fabric.nextHop("a", key) != "b" || got.seqno != limit+1 {
		t.Errorf("a selected %+v after the restart, want the route through b at seqno %d", got, limit+1)
	}
	for _, link := range [][2]string{{"a", "b"}, {"b", "c"}, {"d", "a"}} {
		if asked := seqnoRequestsFor(t, fabric.tlvs(link[0], link[1]), dest); len(asked) != 0 {
			t.Errorf("%s asked %s for seqnos %+v after the restart", link[0], link[1], asked)
		}
	}
}
