// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package babel

import (
	"fmt"
	"maps"
	"net/netip"
	"testing"
	"time"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// offerModel is one route or offer as the model holds it, the update that made it
type offerModel struct {
	routerID  [8]byte
	seqno     uint16
	metric    uint16
	expiresAt time.Time
}

// offerHello is the Hello and IHU interval every packet of the property carries, so a neighbor is up until 3.5 of it pass without one,
// longer than the interval of many an update, so an offer can expire while its neighbor is still up
const offerHello = 4 * time.Second

// offerRxCost is the rxcost every neighbor reports, which with quality none is the link's whole cost
const offerRxCost = 96

// The offers a node keeps for its own keys follow a model of them under any
// order of adopting and releasing a key, a neighbor's update, retraction and
// wildcard retraction, the clock passing, a sweep, and a neighbor going down. An update for an owned key is its neighbor's offer and enters no route,
// and one for any other key is a route. A retraction or a wildcard retraction
// takes the offer or the route out, a sweep takes out each offer past its
// expiry and each of a neighbor whose Hellos lapsed, and a neighbor going down
// takes its offers and leaves its routes. Adopting a key makes each route of
// it that is finite and not expired its neighbor's offer, and releasing one
// makes each offer not expired its route, selecting at once the one of least
// cost among those whose link is up, or leaving no entry where there is none.
// An owned key's forwarding entry is this node's own throughout.
func TestOffersFollowTheirModel(t *testing.T) {
	keys := []routeKey{
		{dest: netip.MustParsePrefix("2001:db8:1::/48")},
		{dest: netip.MustParsePrefix("2001:db8:2::/48")},
		{source: netip.MustParsePrefix("2001:db8:a::/48"), dest: netip.MustParsePrefix("::/0")},
	}
	names := []string{"n0", "n1", "n2"}
	origins := [][8]byte{routerID("x"), routerID("y")}
	pbt.Check(t, func(ht *hegel.T) {
		mesh := &netstack.Mesh{Routes: netstack.NewRouteTable()}
		s, err := New(Config{Quality: LinkQualityNone}, Routes{}, Runtime{RouterID: routerID("self")}, mesh)
		if err != nil {
			ht.Fatal(err)
		}
		neighbors := make([]*neighborState, len(names))
		for i, name := range names {
			peer := newHeldPeer(ht, name, nil)
			defer s.AddPeer(peer.Peer, identity.Identity{}).Close()
			neighbors[i] = s.neighbors[name]
		}
		start := time.Now()
		now := start
		owned := make(map[routeKey]bool)
		offers := make(map[routeKey]map[int]offerModel)
		routes := make(map[routeKey]map[int]offerModel)
		heard := make([]time.Time, len(names))
		down := make([]bool, len(names))
		var hellos uint16
		// send hands the speaker one packet from neighbor i at now, a Hello and an IHU ahead of tlvs
		send := func(i int, tlvs ...RawTLV) {
			hellos++
			packet := append([]RawTLV{
				EncodeHello(Hello{Seqno: hellos, Interval: uint16(offerHello / (10 * time.Millisecond))}),
				EncodeIHU(IHU{RxCost: offerRxCost, Interval: uint16(offerHello / (10 * time.Millisecond))}),
			}, tlvs...)
			s.handlePacketLocked(neighbors[i], EncodePacket(packet), now)
			heard[i], down[i] = now, false
		}
		dropOf := func(table map[routeKey]map[int]offerModel, gone func(int, offerModel) bool) {
			for _, held := range table {
				maps.DeleteFunc(held, gone)
			}
		}
		linkUp := func(i int) bool {
			return !heard[i].IsZero() && !down[i] && now.Before(heard[i].Add(deadTimeout(offerHello)))
		}
		own := func(key routeKey, adopt bool) {
			previous := s.originate
			wanted := maps.Clone(previous)
			if adopt {
				wanted[key] = struct{}{}
			} else {
				delete(wanted, key)
			}
			s.originate = wanted
			s.replaceOwnLocked("originated", previous, wanted, now)
		}
		// live is a table's entries not past their expiry, each key with none left out
		live := func(table map[routeKey]map[int]offerModel) map[routeKey]map[int]offerModel {
			out := make(map[routeKey]map[int]offerModel)
			for key, held := range table {
				for i, entry := range held {
					if now.Before(entry.expiresAt) {
						if out[key] == nil {
							out[key] = make(map[int]offerModel)
						}
						out[key][i] = entry
					}
				}
			}
			return out
		}
		read := func(table map[*neighborState]*routeInfo, finite bool) map[int]offerModel {
			out := make(map[int]offerModel)
			for i, n := range neighbors {
				if route := table[n]; route != nil && (!finite || route.rxMetric != MetricInfinity) {
					out[i] = offerModel{routerID: route.routerID, seqno: route.seqno, metric: route.rxMetric, expiresAt: route.expiresAt}
				}
			}
			return out
		}
		equal := func(a, b map[int]offerModel) bool {
			return maps.EqualFunc(a, b, func(x, y offerModel) bool {
				return x.routerID == y.routerID && x.seqno == y.seqno && x.metric == y.metric && x.expiresAt.Equal(y.expiresAt)
			})
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		for step := range hegel.Draw(ht, pbt.Spanning(1, 80)) {
			key := keys[hegel.Draw(ht, hegel.Integers(0, len(keys)-1))]
			i := hegel.Draw(ht, hegel.Integers(0, len(names)-1))
			var did string
			switch hegel.Draw(ht, hegel.Integers(0, 7)) {
			case 0:
				origin := origins[hegel.Draw(ht, hegel.Integers(0, len(origins)-1))]
				seqno := hegel.Draw(ht, pbt.Spanning[uint16](0, 0xffff))
				metric := hegel.Draw(ht, pbt.Spanning[uint16](0, 1000))
				interval := time.Duration(hegel.Draw(ht, pbt.Spanning(20, 2000))) * 10 * time.Millisecond
				send(i, EncodeRouterID(origin), EncodeUpdate(Update{AE: updateAE(key.dest), Plen: key.dest.Bits(), Prefix: key.dest.Addr().AsSlice(),
					Interval: uint16(interval / (10 * time.Millisecond)), Seqno: seqno, Metric: metric, SourcePrefix: key.source}))
				table := routes
				if owned[key] {
					table = offers
				}
				if table[key] == nil {
					table[key] = make(map[int]offerModel)
				}
				table[key][i] = offerModel{routerID: origin, seqno: seqno, metric: metric, expiresAt: now.Add(deadTimeout(interval))}
				did = fmt.Sprintf("%s offered %s under %x at seqno %d, metric %d and interval %v", names[i], describeRoute(key), origin, seqno, metric, interval)
			case 1:
				send(i, EncodeRouterID(origins[0]), EncodeUpdate(Update{AE: updateAE(key.dest), Plen: key.dest.Bits(), Prefix: key.dest.Addr().AsSlice(),
					Interval: 100, Metric: MetricInfinity, SourcePrefix: key.source}))
				delete(offers[key], i)
				delete(routes[key], i)
				did = fmt.Sprintf("%s retracted %s", names[i], describeRoute(key))
			case 2:
				send(i, wildcardRetraction())
				gone := func(j int, _ offerModel) bool { return j == i }
				dropOf(offers, gone)
				dropOf(routes, gone)
				did = names[i] + " retracted everything"
			case 3:
				now = now.Add(time.Duration(hegel.Draw(ht, pbt.Spanning(0, 60))) * time.Second / 2)
				did = fmt.Sprintf("the clock passed to %v", now.Sub(start))
			case 7:
				for j := range names {
					if !heard[j].IsZero() && !down[j] && !now.Before(heard[j].Add(deadTimeout(offerHello))) {
						down[j] = true
						dropOf(offers, func(k int, _ offerModel) bool { return k == j })
					}
				}
				dropOf(offers, func(_ int, offer offerModel) bool { return !now.Before(offer.expiresAt) })
				s.sweepExpiredLocked(now)
				did = "a sweep ran"
			case 4:
				if neighbors[i].alive {
					s.neighborDownLocked(neighbors[i])
					down[i] = true
					dropOf(offers, func(j int, _ offerModel) bool { return j == i })
				}
				did = names[i] + " went down"
			case 5:
				if !owned[key] {
					owned[key] = true
					offers[key] = live(map[routeKey]map[int]offerModel{key: routes[key]})[key]
					delete(routes, key)
					own(key, true)
				}
				did = "the node took " + describeRoute(key)
			case 6:
				if owned[key] {
					owned[key] = false
					routes[key] = live(map[routeKey]map[int]offerModel{key: offers[key]})[key]
					delete(offers, key)
					own(key, false)
					var restored map[*neighborState]*routeInfo
					if entry := s.routes.entries[key]; entry != nil {
						restored = entry.routes
					}
					if !equal(read(restored, false), routes[key]) {
						ht.Fatalf("step %d: %s takes %v as its routes once released, want %v, its offers not expired", step, describeRoute(key), read(restored, false), routes[key])
					}
					best := -1
					for j, route := range routes[key] {
						if linkUp(j) && (best < 0 || route.metric < routes[key][best].metric || route.metric == routes[key][best].metric && j < best) {
							best = j
						}
					}
					value, ok := entryAt(mesh, key)
					switch {
					case best >= 0 && (!ok || value != neighbors[best].peer):
						ht.Fatalf("step %d: %s holds %s once released, want %s, the offer of least cost", step, describeRoute(key), peerName(value), names[best])
					case best < 0 && ok:
						ht.Fatalf("step %d: %s holds %s once released with no offer over a link that is up, want no entry", step, describeRoute(key), peerName(value))
					}
				}
				did = "the node gave back " + describeRoute(key)
			}
			wantRoutes := live(routes)
			for _, key := range keys {
				if owned[key] {
					if !equal(read(s.routes.offers[key], false), offers[key]) {
						ht.Fatalf("step %d, after %s: the node keeps %v for %s, want %v", step, did, read(s.routes.offers[key], false), describeRoute(key), offers[key])
					}
					if s.routes.entries[key] != nil {
						ht.Fatalf("step %d, after %s: %s, which the node owns, is in its route table", step, did, describeRoute(key))
					}
					if value, ok := entryAt(mesh, key); !ok || value != netstack.Local {
						ht.Fatalf("step %d, after %s: %s, which the node owns, holds %s", step, did, describeRoute(key), peerName(value))
					}
					continue
				}
				if held := s.routes.offers[key]; held != nil {
					ht.Fatalf("step %d, after %s: the node keeps %d offers for %s, which it does not own", step, did, len(held), describeRoute(key))
				}
				var got map[int]offerModel
				if entry := s.routes.entries[key]; entry != nil {
					got = live(map[routeKey]map[int]offerModel{key: read(entry.routes, true)})[key]
				}
				if len(got) != 0 || len(wantRoutes[key]) != 0 {
					if !equal(got, wantRoutes[key]) {
						ht.Fatalf("step %d, after %s: the node routes %s by %v, want %v", step, did, describeRoute(key), got, wantRoutes[key])
					}
				}
			}
		}
	})
}
