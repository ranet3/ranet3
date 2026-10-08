// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package babel

import (
	"net/netip"
	"testing"
	"time"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/schema"
)

// the shortest hello interval drawn below, in centiseconds
// ten seconds keeps every neighbor's next hello from falling due while a case runs, which would move its history for a reason other than the change
const drawnHelloFloor = 1000

// drawnConfig is a valid cap.babel with each field written or left out
func drawnConfig(ht *hegel.T) Config {
	var cfg Config
	if hegel.Draw(ht, hegel.Booleans()) {
		cfg.Hello = dur(time.Duration(hegel.Draw(ht, pbt.Spanning[int64](drawnHelloFloor, 65535))) * 10 * time.Millisecond)
	}
	if hegel.Draw(ht, hegel.Booleans()) {
		cfg.Update = dur(time.Duration(hegel.Draw(ht, pbt.Spanning[int64](drawnHelloFloor, 65535))) * 10 * time.Millisecond)
	}
	if hegel.Draw(ht, hegel.Booleans()) {
		cfg.Quality = LinkQualityNone
	}
	if hegel.Draw(ht, hegel.Booleans()) {
		rx := hegel.Draw(ht, pbt.Spanning[uint16](1, MetricInfinity-1))
		weight := hegel.Draw(ht, pbt.Spanning[uint16](0, MetricInfinity-1-rx))
		low := hegel.Draw(ht, pbt.Spanning[int64](0, 2000))
		high := hegel.Draw(ht, pbt.Spanning(low, 4000))
		minimum, maximum := schema.Duration(time.Duration(low)*time.Millisecond), schema.Duration(time.Duration(high)*time.Millisecond)
		cfg.Cost = CostOptions{Rx: &rx, RTT: RTTOptions{Weight: &weight, Min: &minimum, Max: &maximum}}
	}
	if err := cfg.Validate(); err != nil {
		ht.Fatalf("drew %+v, which Validate refuses: %v", cfg, err)
	}
	return cfg
}

// one Hello as it left a speaker, and whether it left from the change itself
type leftHello struct {
	interval uint16
	atChange bool
}

// after every change at either end of a pair exchanging hellos and dumps, the changed end runs the intervals and the cost a speaker built from that config runs
// each neighbor keeps its hello history and is costed from it as that speaker would cost it
// an equal config sends nothing, and no hello announces an interval longer than the one before it unless it left from the change
func TestReconfiguredSpeakerRunsAsASpeakerBuiltFromItsConfig(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		w := newHeldWire(ht, 0)
		w.a.Originate(netip.MustParsePrefix("fd00:a::/64"))
		w.b.Originate(netip.MustParsePrefix("fd00:b::/64"))
		// set before either end has a neighbor, so it sends nothing and starts the pair above the floor as well
		initial := Config{Hello: dur(100 * time.Second), Update: dur(10 * time.Minute)}
		running := map[*Speaker]Config{w.a: initial, w.b: initial}
		w.a.SetConfig(initial)
		w.b.SetConfig(initial)
		w.joinA()
		w.joinB()

		left := map[*Speaker][]leftHello{}
		atChange := map[*byte]bool{}
		take := func(from *Speaker, raw []byte) {
			for _, interval := range sentHellos(ht, [][]byte{raw}) {
				left[from] = append(left[from], leftHello{interval, atChange[&raw[0]]})
			}
		}
		deliver := func(dropFromA bool) {
			for delivered := 0; len(w.toA) > 0 || len(w.toB) > 0; delivered++ {
				if delivered >= deliveryBudget {
					ht.Fatal("the speakers were still answering each other past the delivery budget")
				}
				if len(w.toB) > 0 {
					raw := w.toB[0]
					w.toB = w.toB[1:]
					take(w.a, raw)
					if !dropFromA {
						w.b.Receive(w.peerAForB, raw)
					}
				}
				if len(w.toA) > 0 {
					raw := w.toA[0]
					w.toA = w.toA[1:]
					take(w.b, raw)
					w.a.Receive(w.peerBForA, raw)
				}
			}
		}
		scheduled := func(s *Speaker) {
			now := time.Now()
			s.mu.Lock()
			actions := make([]sendAction, 0, len(s.neighbors))
			for _, n := range s.neighbors {
				actions = append(actions, s.helloAction(n, now))
			}
			send := s.emitLocked(actions)
			s.mu.Unlock()
			send()
		}
		exchange := func() {
			scheduled(w.a)
			scheduled(w.b)
			deliver(hegel.Draw(ht, hegel.Booleans()))
			if hegel.Draw(ht, hegel.Booleans()) {
				w.a.flushUpdates()
				w.b.flushUpdates()
				deliver(false)
			}
		}
		exchange()
		exchange()

		steps := hegel.Draw(ht, pbt.Spanning(1, 8))
		for range steps {
			s, queue, other := w.a, &w.toB, "b"
			if hegel.Draw(ht, hegel.Booleans()) {
				s, queue, other = w.b, &w.toA, "a"
			}
			cfg := running[s]
			if !hegel.Draw(ht, hegel.Booleans()) {
				cfg = drawnConfig(ht)
			}
			equal := cfg.Effective() == running[s].Effective()

			s.mu.Lock()
			neighbor := s.neighbors[other]
			history, seqno := neighbor.multicastHistory, neighbor.helloSeqno
			s.mu.Unlock()
			before := len(*queue)
			s.SetConfig(cfg)
			sent := (*queue)[before:]
			switch {
			case equal && len(sent) != 0:
				ht.Fatalf("an equal config sent %d packets", len(sent))
			case !equal && len(sentHellos(ht, sent)) != 1:
				ht.Fatalf("a change sent %d hellos, want one", len(sentHellos(ht, sent)))
			}
			for _, raw := range sent {
				atChange[&raw[0]] = true
			}
			running[s] = cfg

			fresh, err := New(cfg, Routes{}, Runtime{}, &netstack.Mesh{Routes: netstack.NewRouteTable()})
			if err != nil {
				ht.Fatal(err)
			}
			wantSeqno := seqno
			if !equal {
				wantSeqno++
			}
			s.mu.Lock()
			switch {
			case s.hello != fresh.hello || s.update != fresh.update || s.cost != fresh.cost:
				ht.Fatalf("the speaker runs %s, %s and %+v, want %s, %s and %+v", s.hello, s.update, s.cost, fresh.hello, fresh.update, fresh.cost)
			case s.routes.cost != fresh.routes.cost || s.routes.tau != fresh.routes.tau || s.routes.trigger != fresh.routes.trigger:
				ht.Fatalf("selection runs on %+v, %s and %d, want %+v, %s and %d",
					s.routes.cost, s.routes.tau, s.routes.trigger, fresh.routes.cost, fresh.routes.tau, fresh.routes.trigger)
			case neighbor.multicastHistory != history:
				ht.Fatalf("the change left %s's hello history at %+v, want %+v", other, neighbor.multicastHistory, history)
			case neighbor.helloSeqno != wantSeqno:
				ht.Fatalf("the change left the hello seqno at %d, want %d", neighbor.helloSeqno, wantSeqno)
			}
			kept := *neighbor
			kept.multicastHistory = history
			want := kept.linkCost(time.Now(), fresh.cost)
			s.mu.Unlock()
			for _, stat := range s.Stats().Neighbors {
				if stat.Cost != want {
					ht.Fatalf("%s's link costs %d, want %d from its kept history", other, stat.Cost, want)
				}
			}

			for range hegel.Draw(ht, pbt.Spanning(0, 3)) {
				exchange()
			}
		}

		for _, hellos := range left {
			for k := 1; k < len(hellos); k++ {
				if !hellos[k].atChange && hellos[k].interval > hellos[k-1].interval {
					ht.Fatalf("hello %d of %d announced %d after %d, and did not leave from a change", k, len(hellos), hellos[k].interval, hellos[k-1].interval)
				}
			}
		}
	})
}
