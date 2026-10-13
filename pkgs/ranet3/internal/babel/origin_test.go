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
// a seqno request naming this node records whether it raised
// a raise for a request records the request's neighbor
// a run after the first records its own raise
// only the first request in a packet asking past the seqno of a prefix this node originates raises it
// a request naming another router id records nothing and leaves the seqno where it was
func TestSeqnoRequestsAndRaisesAreRecorded(t *testing.T) {
	bus := events.New()
	id, foreign := [8]byte{0x72, 1, 2, 3, 4, 5, 6, 7}, [8]byte{0x72, 9, 9, 9, 9, 9, 9, 9}
	speaker, neighbor, _ := captureSpeaker(t, Config{}, Runtime{RouterID: id, Events: bus})
	mine, other := netip.MustParsePrefix("fd00:5::/64"), netip.MustParsePrefix("fd00:6::/64")
	speaker.Originate(mine)
	speaker.SetOrigin(Origin{RouterID: id, Limit: 10}, func(Origin) error { return nil }, "")
	speaker.handlePacket(neighbor, EncodePacket([]RawTLV{askSeqno(id, mine, 12), askSeqno(id, mine, 13)}))
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
		"babel.seqno.raised peer cause=request from=11 to=12 limit=267",
		"babel.seqno.requested peer route=fd00:5::/64 asked=13 seqno=12 raised=false",
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

// a raise owes every neighbor a triggered update of every prefix this node originates
// b asks a for one of its two prefixes
// c hears the other at the raised seqno from the next triggered pass, before any periodic dump
func TestRaisedSeqnoReachesEveryNeighborBeforeTheNextDump(t *testing.T) {
	fabric := newMeshFabric(t, Config{}, "a-b", "a-c")
	origin := fabric.speakers["a"]
	asked, other := netip.MustParsePrefix("fd00:a::/64"), netip.MustParsePrefix("fd00:a:1::/64")
	origin.Originate(asked)
	origin.Originate(other)
	fabric.flush("a")
	_, seqno := origin.Origin()
	fabric.reset()
	fabric.inject("a", "b", askSeqno(routerID("a"), asked, seqno+1))
	origin.mu.Lock()
	send := origin.emitLocked(origin.triggeredActions(time.Now()))
	origin.mu.Unlock()
	send()
	if got := updatesFor(t, fabric.tlvs("a", "c"), other); len(got) != 1 || got[0].Seqno != seqno+1 {
		t.Errorf("a sent c %+v for %s after the raise, want one Update at seqno %d", got, other, seqno+1)
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
