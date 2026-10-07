// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package babel

import (
	"log/slog"
	"net/netip"
	"slices"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/netstack"
)

func everything(string, string, []slog.Attr) bool { return true }

// a neighbor coming up and the request sent to it, every change of a selected next hop and the neighbor going down are recorded
// the selection is recorded every time, where its log line is said once a second at most
func TestSpeakerRecordsNeighborsAndSelections(t *testing.T) {
	bus := events.New()
	speaker, neighbor, _ := captureSpeaker(t, Config{}, Runtime{Events: bus})
	speaker.handlePacket(neighbor, EncodePacket([]RawTLV{EncodeHello(Hello{Seqno: 1, Interval: 100})}))
	makeNeighborReachable(neighbor)
	key := routeKey{dest: netip.MustParsePrefix("fd00:1::/64")}
	now := time.Now()
	speaker.mu.Lock()
	for i := range 6 {
		metric := uint16(64)
		if i%2 == 1 {
			metric = MetricInfinity
		}
		speaker.routes.update(neighbor, key, advertisement{routerID: [8]byte{1}, seqno: 1, metric: metric}, time.Minute, now)
	}
	speaker.sweepExpiredLocked(now.Add(time.Hour))
	speaker.mu.Unlock()

	var got []string
	for _, event := range bus.Recorded(everything, 0) {
		got = append(got, event.Kind+" "+event.Peer+" "+event.Attrs["route"])
	}
	selected, retracted := "babel.route.selected peer fd00:1::/64", "babel.route.retracted  fd00:1::/64"
	want := []string{"babel.neighbor.up peer ", "babel.request.sent peer ",
		selected, retracted, selected, retracted, selected, retracted,
		"babel.neighbor.down peer "}
	if !slices.Equal(got, want) {
		t.Errorf("the speaker recorded\n%q\nwant\n%q", got, want)
	}
}

// a live neighbor whose session another replaces, or whose session ends, is recorded going down
func TestSpeakerRecordsANeighborLeavingWithItsSession(t *testing.T) {
	bus := events.New()
	speaker, neighbor, _ := captureSpeaker(t, Config{}, Runtime{Events: bus})
	hello := EncodePacket([]RawTLV{EncodeHello(Hello{Seqno: 1, Interval: 100})})
	speaker.handlePacket(neighbor, hello)
	handle := speaker.AddPeer(netstack.NewPeer(neighbor.peer.ID, plainEncrypt,
		func([]byte) error { return nil }))
	replacement := speaker.neighbors[neighbor.peer.ID]
	replacement.addr = neighbor.addr
	speaker.handlePacket(replacement, hello)
	handle.Close()

	var got []string
	for _, event := range bus.Recorded(everything, 0) {
		got = append(got, event.Kind+" "+event.Peer)
	}
	up, asked, down := "babel.neighbor.up "+neighbor.peer.ID, "babel.request.sent "+neighbor.peer.ID, "babel.neighbor.down "+neighbor.peer.ID
	if want := []string{up, asked, down, up, asked, down}; !slices.Equal(got, want) {
		t.Errorf("a neighbor replaced and then closed recorded %q, want %q", got, want)
	}
}

// a neighbor is recorded going down once when it is lost, whichever way its session then leaves
// one the sweep already took down, or one that never came up, records no down when its session ends or is replaced
func TestSpeakerRecordsOneDownPerNeighborLost(t *testing.T) {
	hello := EncodePacket([]RawTLV{EncodeHello(Hello{Seqno: 1, Interval: 100})})
	newPeer := func() *netstack.Peer {
		return netstack.NewPeer("other", plainEncrypt, func([]byte) error { return nil })
	}
	for _, test := range []struct {
		name  string
		swept bool
		leave func(*Speaker, *PeerHandle)
	}{
		{"closed after the sweep", true, func(_ *Speaker, handle *PeerHandle) { handle.Close() }},
		{"closed never heard", false, func(_ *Speaker, handle *PeerHandle) { handle.Close() }},
		{"replaced after the sweep", true, func(speaker *Speaker, _ *PeerHandle) { speaker.AddPeer(newPeer()) }},
		{"replaced never heard", false, func(speaker *Speaker, _ *PeerHandle) { speaker.AddPeer(newPeer()) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			bus := events.New()
			speaker, _, _ := captureSpeaker(t, Config{}, Runtime{Events: bus})
			handle := speaker.AddPeer(newPeer())
			if test.swept {
				neighbor := speaker.neighbors["other"]
				neighbor.addr = netip.MustParseAddr("fe80::3")
				speaker.handlePacket(neighbor, hello)
				speaker.mu.Lock()
				speaker.sweepExpiredLocked(time.Now().Add(time.Hour))
				speaker.mu.Unlock()
			}
			test.leave(speaker, handle)
			downs := bus.Recorded(func(kind, peer string, _ []slog.Attr) bool { return kind == "babel.neighbor.down" && peer == "other" }, 0)
			want := 0
			if test.swept {
				want = 1
			}
			if len(downs) != want {
				t.Errorf("the neighbor was recorded down %d times, want %d", len(downs), want)
			}
		})
	}
}
