// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package babel

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/netstack"
)

// reloadedConfig moves the hello and update intervals of newHeldWire's config and the rx cost
func reloadedConfig() Config {
	rx := uint16(200)
	return Config{Hello: dur(3 * time.Second), Update: dur(5 * time.Minute), Cost: CostOptions{Rx: &rx}}
}

// upWire is a heldWire whose two ends hold each other up, with b holding the prefix a announces
func upWire(t *testing.T, dest netip.Prefix) *heldWire {
	t.Helper()
	w := newHeldWire(t, 0)
	w.a.Originate(dest)
	w.joinA()
	w.joinB()
	w.helloFromA()
	w.helloFromB()
	w.deliver()
	w.a.flushUpdates()
	w.deliver()
	if peer, ok := w.b.mesh.Routes.Lookup(dest.Addr(), dest.Addr()); !ok || peer != w.peerAForB {
		t.Fatalf("b did not learn a's prefix, so this proves nothing: %v", w.b.mesh.Routes.Debug())
	}
	return w
}

// sentHellos is the interval of every Hello in packets, in the order they left
func sentHellos(t tester, packets [][]byte) []uint16 {
	t.Helper()
	var out []uint16
	for _, raw := range packets {
		to, _ := netip.AddrFromSlice(raw[24:40])
		_, payload, err := parsePacket(raw, to)
		if err != nil {
			t.Fatal(err)
		}
		tlvs, err := DecodePacket(payload)
		if err != nil {
			t.Fatal(err)
		}
		for _, tlv := range tlvs {
			if tlv.Type != TLVHello {
				continue
			}
			hello, err := DecodeHello(tlv.Body)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, hello.Interval)
		}
	}
	return out
}

// the neighbor holds the new hello interval, rx cost and update interval as soon as the change is delivered, with no pass in between
// the hello sequence number and the history of the neighbor's hellos go on from where they were
func TestReloadedCapBabelReachesTheNeighborAtOnce(t *testing.T) {
	dest := netip.MustParsePrefix("fd00:a::/64")
	w := upWire(t, dest)
	w.a.mu.Lock()
	seqno, history := w.a.neighbors["b"].helloSeqno, w.a.neighbors["b"].multicastHistory
	w.a.mu.Unlock()

	next := reloadedConfig()
	w.a.SetConfig(next)
	if len(w.toB) == 0 {
		t.Fatal("the change sent the neighbor nothing")
	}
	w.deliver()

	w.b.mu.Lock()
	n := w.b.neighbors["a"]
	if n.helloInterval != next.HelloInterval() {
		t.Errorf("b holds a's hello interval as %s, want %s", n.helloInterval, next.HelloInterval())
	}
	if n.reportedCost != next.CostEffective().RxCost {
		t.Errorf("b holds a's rx cost as %d, want %d", n.reportedCost, next.CostEffective().RxCost)
	}
	if route := w.b.routes.route(n, routeKey{dest: dest}); route == nil || route.hold != deadTimeout(next.UpdateInterval()) {
		t.Errorf("b holds a's prefix as %+v, want it held for 3.5 times the new update interval", route)
	}
	w.b.mu.Unlock()

	w.a.mu.Lock()
	defer w.a.mu.Unlock()
	if got := w.a.neighbors["b"].helloSeqno; got != seqno+1 {
		t.Errorf("the hello at the change carried seqno %d, want %d", got, seqno+1)
	}
	if got := w.a.neighbors["b"].multicastHistory; got != history {
		t.Errorf("the change left b's hello history at %+v, want %+v", got, history)
	}
}

// RFC 8966 section 3.4.1 lets the interval grow only immediately before a Hello announcing it
func TestLongerHelloIntervalIsAnnouncedBeforeItIsInForce(t *testing.T) {
	speaker, _, packets := captureSpeaker(t, Config{Hello: dur(time.Second)})
	longer := Config{Hello: dur(4 * time.Second)}
	before := time.Now()
	speaker.SetConfig(longer)
	after := time.Now()

	want := uint16(longer.HelloInterval() / (10 * time.Millisecond))
	if got := sentHellos(t, *packets); len(got) != 1 || got[0] != want {
		t.Fatalf("the change sent hellos announcing %v, want one announcing %d", got, want)
	}
	speaker.mu.Lock()
	next := speaker.nextHello
	speaker.mu.Unlock()
	if next.Before(before.Add(longer.HelloInterval())) || next.After(after.Add(longer.HelloInterval())) {
		t.Errorf("the next hello is due %s after the change, want the new interval from the hello that announced it", next.Sub(before))
	}
}

// changedIntervalsWindow is how long a running speaker is watched after a change to intervals far shorter than it
const changedIntervalsWindow = time.Second

// a running speaker sends hellos and updates on the new, shorter intervals from the change on
// rather than sleeping out the deadlines it set on the old ones
func TestRunningSpeakerTakesShorterIntervalsAtOnce(t *testing.T) {
	speaker, err := New(Config{Hello: dur(time.Minute), Update: dur(10 * time.Minute)}, Routes{}, Runtime{}, netstack.NewRoutesOnly())
	if err != nil {
		t.Fatal(err)
	}
	speaker.Originate(netip.MustParsePrefix("fd00:e::/64"))
	var mu sync.Mutex
	var packets [][]byte
	peer := netstack.NewPeer("peer", plainEncrypt, func(raw []byte) error {
		mu.Lock()
		defer mu.Unlock()
		packets = append(packets, append([]byte(nil), raw...))
		return nil
	})
	defer peer.Close()
	speaker.AddPeer(peer)
	sent := func() [][]byte {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(packets)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); _ = speaker.Run(ctx) }()
	defer func() { cancel(); <-done }()
	deadline := time.Now().Add(changedIntervalsWindow)
	for len(sent()) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	before := len(sent())
	if before == 0 {
		t.Fatal("the speaker never sent its first pass, so this proves nothing")
	}

	fast := Config{Hello: dur(50 * time.Millisecond), Update: dur(100 * time.Millisecond)}
	speaker.SetConfig(fast)
	time.Sleep(changedIntervalsWindow)
	after := sent()[before:]
	updates := 0
	for _, raw := range after {
		to, _ := netip.AddrFromSlice(raw[24:40])
		_, payload, err := parsePacket(raw, to)
		if err != nil {
			t.Fatal(err)
		}
		tlvs, err := DecodePacket(payload)
		if err != nil {
			t.Fatal(err)
		}
		if slices.ContainsFunc(tlvs, func(tlv RawTLV) bool { return tlv.Type == TLVUpdate }) {
			updates++
		}
	}
	// the change itself sends one hello and one update
	// the run loop sends the rest
	if hellos := len(sentHellos(t, after)); hellos < 3 {
		t.Errorf("%d hellos left in the %s after the change to a %s hello, want the run loop to keep sending them", hellos, changedIntervalsWindow, fast.HelloInterval())
	}
	if updates < 3 {
		t.Errorf("%d packets with updates left in the %s after the change to a %s update, want the run loop to keep sending them", updates, changedIntervalsWindow, fast.UpdateInterval())
	}
}

// a cost change reruns selection on every prefix at once, and the neighbors are told the route it chose
func TestReloadedCostReselectsEveryPrefix(t *testing.T) {
	zero, heavy := uint16(0), uint16(1000)
	mesh := &netstack.Mesh{Routes: netstack.NewRouteTable()}
	speaker, err := New(Config{Cost: CostOptions{RTT: RTTOptions{Weight: &zero}}}, Routes{}, Runtime{}, mesh)
	if err != nil {
		t.Fatal(err)
	}
	toB := new([][]byte)
	b := netstack.NewPeer("b", plainEncrypt, func(raw []byte) error { *toB = append(*toB, append([]byte(nil), raw...)); return nil })
	c := netstack.NewPeer("c", plainEncrypt, func([]byte) error { return nil })
	speaker.AddPeer(b)
	speaker.AddPeer(c)

	dest := netip.MustParsePrefix("fd00:c::/64")
	key := routeKey{dest: dest}
	now := time.Now()
	speaker.mu.Lock()
	far, near := speaker.neighbors["b"], speaker.neighbors["c"]
	makeNeighborReachable(far)
	makeNeighborReachable(near)
	far.measuredRTT, far.haveRTT, far.rttExpiry = 500*time.Millisecond, true, now.Add(time.Minute)
	near.reportedCost = 100
	speaker.routes.update(far, key, advertisement{routerID: [8]byte{1}, seqno: 1, metric: 10}, time.Minute, now)
	speaker.routes.update(near, key, advertisement{routerID: [8]byte{2}, seqno: 1, metric: 10}, time.Minute, now)
	speaker.mu.Unlock()
	if peer, ok := mesh.Routes.Lookup(dest.Addr(), dest.Addr()); !ok || peer != b {
		t.Fatalf("the prefix is not through b while round trips cost nothing, so this proves nothing: %v", mesh.Routes.Debug())
	}
	*toB = nil

	speaker.SetConfig(Config{Cost: CostOptions{RTT: RTTOptions{Weight: &heavy}}})
	if peer, ok := mesh.Routes.Lookup(dest.Addr(), dest.Addr()); !ok || peer != c {
		t.Errorf("the prefix is forwarded as %v once b's round trip costs %d, want through c", mesh.Routes.Debug(), heavy)
	}
	want := DefaultCostParams()
	want.RTT.Weight = heavy
	for _, neighbor := range speaker.Stats().Neighbors {
		if neighbor.Peer == "b" && neighbor.Cost != saturatingAdd(32, want.RTTPenalty(500*time.Millisecond, true)) {
			t.Errorf("b's link costs %d, want its rx cost and the new round trip penalty", neighbor.Cost)
		}
	}
	var metrics []uint16
	var decoder PrefixDecoder
	for _, raw := range *toB {
		_, payload, err := parsePacket(raw, multicastGroup)
		if err != nil {
			t.Fatal(err)
		}
		tlvs, err := DecodePacket(payload)
		if err != nil {
			t.Fatal(err)
		}
		for _, tlv := range tlvs {
			if tlv.Type == TLVUpdate {
				update, err := decoder.Decode(tlv.Body)
				if err != nil {
					t.Fatal(err)
				}
				metrics = append(metrics, update.Metric)
			}
		}
	}
	if len(metrics) != 1 || metrics[0] != 110 {
		t.Errorf("b was sent updates with metrics %v, want one carrying c's 110", metrics)
	}
}

// an omitted field and the same value spelled out are one speaker, and taking it is no change
func TestEqualCapBabelSendsNothing(t *testing.T) {
	bus := events.New()
	speaker, _, packets := captureSpeaker(t, Config{}, Runtime{Events: bus})
	speaker.mu.Lock()
	scheduled := speaker.nextHello
	speaker.mu.Unlock()
	params := DefaultCostParams()
	spelled := Config{Hello: dur(4 * time.Second), Update: dur(16 * time.Second), Cost: CostOptions{Rx: &params.RxCost,
		RTT: RTTOptions{Weight: &params.RTT.Weight, Min: &params.RTT.Min, Max: &params.RTT.Max}}}
	if spelled.Effective() != (Config{}).Effective() {
		t.Fatal("the spelled out config is another speaker, so this proves nothing")
	}
	speaker.SetConfig(spelled)
	if len(*packets) != 0 {
		t.Errorf("an equal config sent %d packets", len(*packets))
	}
	speaker.mu.Lock()
	defer speaker.mu.Unlock()
	if speaker.nextHello != scheduled {
		t.Error("an equal config moved the next hello")
	}
	if got := len(bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "babel.config.applied" }, 0)); got != 0 {
		t.Errorf("an equal config was recorded %d times", got)
	}
}

func TestReloadedCapBabelIsRecordedWithItsIntervalsAndCost(t *testing.T) {
	bus := events.New()
	speaker, _, _ := captureSpeaker(t, Config{}, Runtime{Events: bus})
	speaker.SetConfig(reloadedConfig())
	got := bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "babel.config.applied" }, 0)
	if len(got) != 1 {
		t.Fatalf("the change was recorded %d times, want once", len(got))
	}
	for key, want := range map[string]string{"hello": "3s", "update": "5m0s", "rx": "200", "quality": "etx",
		"rtt_weight": "1024", "rtt_min": "10ms", "rtt_max": "1.024s"} {
		if got[0].Attrs[key] != want {
			t.Errorf("the event carries %s=%q, want %q", key, got[0].Attrs[key], want)
		}
	}
}

// reconfigurations is how many changes race the lost packets below
const reconfigurations = 64

// a peer's sender reports a lost packet on its own goroutine and reads the hello interval there under lostMu alone
// under -race this holds that a change writes the interval under lostMu as well
func TestLostPacketReportsReadTheHelloIntervalAChangeWrites(t *testing.T) {
	speaker, err := New(Config{}, Routes{}, Runtime{}, netstack.NewRoutesOnly())
	if err != nil {
		t.Fatal(err)
	}
	speaker.Originate(netip.MustParsePrefix("fd00:d::/64"))
	lossy := netstack.NewPeer("lossy", plainEncrypt, func([]byte) error { return errors.New("babel: a transport that loses every packet") })
	defer lossy.Close()
	speaker.AddPeer(lossy)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range reconfigurations {
			speaker.flushUpdates()
		}
	}()
	for i := range reconfigurations {
		speaker.SetConfig(Config{Hello: dur(time.Duration(1+i%2) * time.Second)})
	}
	<-done
	speaker.lostMu.Lock()
	defer speaker.lostMu.Unlock()
	if speaker.lostWoke.IsZero() {
		t.Fatal("no lost packet was reported, so this proves nothing")
	}
}
