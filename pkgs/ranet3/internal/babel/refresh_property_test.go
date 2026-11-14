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
)

// each finite update permits one request, due only while its route is selected
// the history knows update times and requests, not how selection or its timers work
func TestRefreshRequestsFollowTheLatestFiniteUpdate(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		for _, learnedFirst := range []bool{false, true} {
			key := routeKey{dest: netip.MustParsePrefix("2001:db8:7:1::/64")}
			neighbors := [2]*neighborState{
				{peer: &netstack.Peer{ID: "near"}},
				{peer: &netstack.Peer{ID: "far"}},
			}
			type history struct {
				updated time.Time
				asked   bool
			}
			last := make(map[*neighborState]*history)
			for _, n := range neighbors {
				makeNeighborReachable(n)
				last[n] = &history{}
			}
			rt := newRouteTable(func(routeKey, routeSelection) {})
			now := time.Now()
			owned := false
			hold := 7 * refreshInterval / 2
			check := func() {
				var selected *neighborState
				if entry := rt.entries[key]; entry != nil {
					selected = entry.selected.neighbor
				}
				for _, request := range rt.takeRefresh() {
					if request.key != key || request.neighbor != selected {
						ht.Fatalf("request %+v did not go to the selected neighbor %p", request, selected)
					}
					h := last[request.neighbor]
					if h == nil || h.updated.IsZero() || h.asked || now.Before(h.updated.Add(refreshDue)) || !now.Before(h.updated.Add(hold)) {
						ht.Fatalf("request at %v outside the unasked update's window: %+v, learned first %v", now, h, learnedFirst)
					}
					h.asked = true
				}
				if selected != nil {
					h := last[selected]
					if !now.Before(h.updated.Add(refreshDue)) && now.Before(h.updated.Add(hold)) && !h.asked {
						ht.Fatalf("selected %s was not asked at age %v, learned first %v", selected.peer.ID, now.Sub(h.updated), learnedFirst)
					}
				}
			}
			advance := func(target time.Time) {
				for now.Before(target) {
					next := target
					// visit the windows even when updates are lost across a long clock step
					for _, h := range last {
						if h.updated.IsZero() {
							continue
						}
						for _, boundary := range []time.Time{h.updated.Add(refreshDue), h.updated.Add(hold)} {
							if now.Before(boundary) && boundary.Before(next) {
								next = boundary
							}
						}
					}
					now = next
					rt.sweepExpired(now)
					check()
				}
			}
			update := func(index int, metric uint16) {
				n := neighbors[index]
				adv := advertisement{routerID: [8]byte{1}, seqno: 1, metric: metric}
				if metric != MetricInfinity {
					last[n].updated, last[n].asked = now, false
				}
				if owned {
					rt.offer(n, key, adv, hold, now)
				} else {
					rt.update(n, key, adv, hold, now)
				}
				check()
			}
			own := func(want bool) {
				if owned == want {
					return
				}
				owned = want
				if owned {
					rt.setAside(key, now)
				} else {
					rt.restore(key, now)
				}
				check()
			}

			// release both a new offer and a route whose earlier refresh is now past
			if learnedFirst {
				update(0, 60)
			}
			own(true)
			advance(now.Add(refreshDue))
			update(0, 60)
			advance(now.Add(time.Nanosecond))
			own(false)
			advance(last[neighbors[0]].updated.Add(refreshDue))

			for range 40 {
				op := hegel.Draw(ht, pbt.Spanning[int64](0, 11))
				index := int(op % 2)
				switch op {
				case 0, 1:
					update(index, uint16(60+index))
				case 2, 3:
					update(index, MetricInfinity)
				case 4, 5, 6, 7:
					n := neighbors[index]
					n.alive = op >= 6
					rt.recomputeNeighbor(n, now)
					check()
				case 8, 9:
					own(op == 8)
				case 10, 11:
					boundary := []time.Duration{refreshDue, hold}[op-10]
					delta := hegel.Draw(ht, pbt.Spanning[int64](-1, 1))
					advance(now.Add(boundary + time.Duration(delta)))
				}
			}
			advance(now.Add(hold))
		}
	})
}
