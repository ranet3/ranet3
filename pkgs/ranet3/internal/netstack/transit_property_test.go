// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package netstack

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/packet"
	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
)

// orderedPeer is a peer recording what it transmits, whose sealing of a batch takes a while that depends on the batch
// so batches the workers seal at once finish in an order of their own
type orderedPeer struct {
	peer *Peer
	mu   sync.Mutex
	sent [][]byte
}

func newOrderedPeer(id string) *orderedPeer {
	o := &orderedPeer{}
	o.peer = NewPeer(id, func(int) (BatchSealer, error) {
		return func(raw [][]byte, headers []byte, out [][]byte) ([][]byte, error) {
			if len(raw) > 0 {
				time.Sleep(time.Duration(raw[0][len(raw[0])-1]%4) * 50 * time.Microsecond)
			}
			return cloning(raw, headers, out)
		}, nil
	}, func(sealed [][]byte) error {
		o.mu.Lock()
		defer o.mu.Unlock()
		o.sent = append(o.sent, sealed...)
		return nil
	}, nil)
	return o
}

// orderDestination is the address the routes send to the i-th outbound peer
func orderDestination(i int) netip.Addr {
	return netip.AddrFrom16([16]byte{0x3f, 0xff, 15: byte(0x10 + i)})
}

// orderedPacket is a packet a session delivers to the i-th outbound peer's destination, carrying its session and its place in the session
func orderedPacket(session, seq, peer, size int) []byte {
	raw := udpPacket(transitSender[6], orderDestination(peer), size, false)
	raw[48] = byte(session)
	binary.BigEndian.PutUint32(raw[49:], uint32(seq))
	raw[len(raw)-1] = byte(seq)
	return raw
}

// sessions delivering forwarded packets at once keep each session's order toward every outbound peer
// whatever order the workers finish sealing in, since a session reserves its peers' tickets in the order it delivered
// a packet the peer's budget refused is counted dropped, and every other one is transmitted
func TestForwardingKeepsEachSessionsOrderPerPeer(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		sessions := hegel.Draw(ht, pbt.Spanning(1, 4))
		outs := hegel.Draw(ht, pbt.Spanning(1, 3))
		m, _ := startTransitMesh(nil)
		defer m.Close()
		peers := make([]*orderedPeer, outs)
		for i := range peers {
			peers[i] = newOrderedPeer(fmt.Sprint("out", i))
			defer peers[i].peer.Close()
			m.Routes.Set(netip.Prefix{}, hostPrefix(orderDestination(i)), peers[i].peer)
		}
		plans := make([][][][]byte, sessions)
		sent := 0
		for s := range plans {
			seq := 0
			for range hegel.Draw(ht, pbt.Spanning(1, 4)) {
				var batch [][]byte
				for range hegel.Draw(ht, pbt.Spanning(1, 2*m.dev.BatchSize()+1)) {
					batch = append(batch, orderedPacket(s, seq, hegel.Draw(ht, pbt.Spanning(0, outs-1)), hegel.Draw(ht, pbt.Spanning(60, 200))))
					seq++
				}
				plans[s] = append(plans[s], batch)
				sent += len(batch)
			}
		}
		var delivering sync.WaitGroup
		for _, batches := range plans {
			delivering.Go(func() {
				for _, batch := range batches {
					m.DeliverInboundBatch(framed(batch...), DefaultMTU, nil)
				}
			})
		}
		delivering.Wait()
		transmitted, dropped := 0, uint64(0)
		for _, o := range peers {
			waitForBudget(ht, o.peer)
			o.mu.Lock()
			last := make(map[byte]int64)
			for _, raw := range o.sent {
				session, seq := raw[48], int64(binary.BigEndian.Uint32(raw[49:]))
				if previous, seen := last[session]; seen && seq <= previous {
					ht.Fatalf("%s transmitted session %d's packet %d after its packet %d", o.peer.ID, session, seq, previous)
				}
				last[session] = seq
			}
			transmitted += len(o.sent)
			o.mu.Unlock()
			dropped += o.peer.Dropped()
		}
		if transmitted+int(dropped) != sent {
			ht.Fatalf("of %d packets the peers transmitted %d and dropped %d", sent, transmitted, dropped)
		}
	})
}

// the prefixes the exits of the exactness property advertise, overlapping, and the destinations outside the overlay its probes go to
var (
	exactnessPrefixes = []netip.Prefix{
		segPrefix("::/0"), segPrefix("2000::/3"), segPrefix("2001:db8::/32"), segPrefix("2001:db8::/33"), segPrefix("2001:db8:8000::/33"), segPrefix("2001:db8::/48"),
		segPrefix("0.0.0.0/0"), segPrefix("128.0.0.0/1"), segPrefix("203.0.113.0/24"), segPrefix("203.0.113.0/25"), segPrefix("203.0.113.128/25"), segPrefix("203.0.113.0/26"),
	}
	exactnessDestinations = map[int][]netip.Addr{
		4: {segAddr("203.0.113.5"), segAddr("203.0.113.100"), segAddr("203.0.113.200")},
		6: {segAddr("2001:db8::5"), segAddr("2001:db8:1::5"), segAddr("2001:db8:8000::5")},
	}
)

// exactnessHost is node i's own address of family, inside the overlay
func exactnessHost(i, family int) netip.Addr {
	if family == 4 {
		return netip.AddrFrom4([4]byte{192, 0, 2, byte(100 + i)})
	}
	return netip.AddrFrom16([16]byte{0x3f, 0xff, 14: 1, 15: byte(i)})
}

// exactnessSID is the egress SID node i holds where it holds one
func exactnessSID(i int) netip.Addr {
	return netip.AddrFrom16([16]byte{0x3f, 0xff, 0, 5, 15: byte(i + 1)})
}

// exactnessEntry is one entry of a node's table in the property's model, where next is the neighbor it forwards to
// and from the source prefix it is announced from, none for most
type exactnessEntry struct {
	prefix  netip.Prefix
	from    netip.Prefix
	verdict Verdict
	next    int
}

// lookup is the model's longest match of destination among entries, none where no entry holds it
func lookup(entries []exactnessEntry, destination netip.Addr) exactnessEntry {
	best := exactnessEntry{verdict: RouteNone, prefix: netip.Prefix{}}
	found := false
	for _, entry := range entries {
		if entry.prefix.Contains(destination) && (!found || entry.prefix.Bits() > best.prefix.Bits()) {
			best, found = entry, true
		}
	}
	return best
}

// towards is each node's neighbor one hop nearer to the nearest of targets, the lowest such, and -1 for a target or a node none reaches
func towards(links [][]int, targets []int) []int {
	distance := make([]int, len(links))
	for i := range distance {
		distance[i] = -1
	}
	queue := slices.Clone(targets)
	for _, target := range targets {
		distance[target] = 0
	}
	for len(queue) > 0 {
		at := queue[0]
		queue = queue[1:]
		for _, next := range links[at] {
			if distance[next] < 0 {
				distance[next] = distance[at] + 1
				queue = append(queue, next)
			}
		}
	}
	next := make([]int, len(links))
	for i := range next {
		next[i] = -1
		for _, neighbor := range links[i] {
			if distance[i] > 0 && distance[neighbor] == distance[i]-1 && (next[i] < 0 || neighbor < next[i]) {
				next[i] = neighbor
			}
		}
	}
	return next
}

// exactnessProbe is one packet the property sends from node from, as a read off its tun
// mode 3 steers it to holder's egress SID, and want is the node whose tun it must reach alone, -1 for none
type exactnessProbe struct {
	from, holder, want int
	raw                []byte
}

// a mesh of meshes joined by in-memory sessions over a drawn topology, its exits advertising drawn overlapping prefixes and its nodes holding drawn ones
// a packet a node reads off its tun for a destination outside the overlay reaches the tun of exactly the node whose own entry the path's longest matches lead to, and of no other
// a packet steered to an egress SID reaches the tun of exactly the node holding the SID as an egressed write, whatever the other nodes' tables say of its inner destination
// and of none where the holder's own table routes that destination, as egressRefused says
// and no node writes to its tun a packet it does not resolve as its own but as an egressed write at its egress SID
// a write is told egressed from the probe it carries, a probe steered to the writing node's SID, and the holder's Egressed counts each one
func TestModeTwoAndThreeReachExactlyTheExitSelectedOrNamed(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		n := hegel.Draw(ht, pbt.Spanning(2, 6))
		links := make([][]int, n)
		connect := func(i, j int) {
			if i != j && !slices.Contains(links[i], j) {
				links[i], links[j] = append(links[i], j), append(links[j], i)
			}
		}
		for i := 1; i < n; i++ {
			connect(i, hegel.Draw(ht, hegel.Integers(0, i-1)))
		}
		for range hegel.Draw(ht, pbt.Spanning(0, 2)) {
			connect(hegel.Draw(ht, hegel.Integers(0, n-1)), hegel.Draw(ht, hegel.Integers(0, n-1)))
		}
		every := make([]int, n)
		for i := range every {
			every[i] = i
		}
		originators := make(map[netip.Prefix][]int)
		for _, exit := range pbt.Subset(ht, every, 1, 3) {
			for _, prefix := range pbt.Subset(ht, exactnessPrefixes, 1, 4) {
				originators[prefix] = append(originators[prefix], exit)
			}
		}
		holders := pbt.Subset(ht, every, 1, 2)

		// the model's tables, which the meshes are given
		tables := make([][]exactnessEntry, n)
		route := func(prefix netip.Prefix, targets []int, held func(int) bool) {
			next := towards(links, targets)
			for i := range tables {
				switch {
				case slices.Contains(targets, i):
					tables[i] = append(tables[i], exactnessEntry{prefix: prefix, verdict: RouteLocal})
				case held(i):
					tables[i] = append(tables[i], exactnessEntry{prefix: prefix, verdict: RouteHeld})
				case next[i] >= 0:
					tables[i] = append(tables[i], exactnessEntry{prefix: prefix, verdict: RoutePeer, next: next[i]})
				}
			}
		}
		never := func(int) bool { return false }
		for i := range n {
			for _, family := range []int{4, 6} {
				route(hostPrefix(exactnessHost(i, family)), []int{i}, never)
			}
		}
		for _, holder := range holders {
			route(hostPrefix(exactnessSID(holder)), []int{holder}, never)
		}
		for _, prefix := range exactnessPrefixes {
			if targets := originators[prefix]; len(targets) > 0 {
				held := make([]bool, n)
				for i := range held {
					held[i] = hegel.Draw(ht, hegel.WeightedBooleans(1.0/8))
				}
				route(prefix, targets, func(i int) bool { return held[i] })
			}
		}

		allow := transitOverlay
		var handoffs atomic.Int64
		meshes := make([]*Mesh, n)
		tuns := make([]*scriptedDevice, n)
		peers := make([]map[int]*Peer, n)
		var all []*Peer
		for i := range n {
			tuns[i] = &scriptedDevice{recordingDevice: recordingDevice{writes: make(chan recordedWrite, 4096)}, reads: make(chan scriptedRead), closed: make(chan struct{})}
			m := &Mesh{Name: fmt.Sprint("node", i), Routes: NewRouteTable(), closed: make(chan struct{})}
			m.setDevice(tuns[i])
			// an exit's egress reaches its tun, as the kernel exit's does
			m.SetExit(tunExit{m.WriteHost})
			m.startSegmentReports()
			m.startOutboundPipeline()
			defer m.Close()
			m.SetTransit(true)
			m.SetOverlay(transitOverlay)
			m.SetAnswerSources(AnswerSources{Router4: exactnessHost(i, 4), Router6: exactnessHost(i, 6)})
			if slices.Contains(holders, i) {
				table, err := srv6.NewLocalTable([]srv6.Segment{{SID: schema.AddrFrom(exactnessSID(i)), Behavior: srv6.BehaviorEndDT46, Deliver: srv6.DeliverEgress, Allow: allow}}, everySource)
				if err != nil {
					ht.Fatal(err)
				}
				m.SetSegments(table)
				m.SetEgressReady(true, true)
			}
			meshes[i], peers[i] = m, make(map[int]*Peer)
		}
		for i := range n {
			for _, j := range links[i] {
				peers[i][j] = NewPeer(fmt.Sprintf("node%d>node%d", i, j), func(int) (BatchSealer, error) { return cloning, nil }, func(sealed [][]byte) error {
					meshes[j].DeliverInboundBatch(framed(sealed...), DefaultMTU, peers[j][i])
					handoffs.Add(1)
					return nil
				}, nil)
				defer peers[i][j].Close()
				all = append(all, peers[i][j])
			}
		}
		for i, entries := range tables {
			for _, entry := range entries {
				value := map[Verdict]*Peer{RouteLocal: Local, RouteHeld: Unreachable}[entry.verdict]
				if entry.verdict == RoutePeer {
					value = peers[i][entry.next]
				}
				meshes[i].Routes.Set(netip.Prefix{}, entry.prefix, value)
			}
		}
		// each exit advertises what it originates through cap.egress, so a verdict through a prefix counting as a default is handed to egress
		advertised := make([][]netip.Prefix, n)
		for prefix, exits := range originators {
			for _, exit := range exits {
				advertised[exit] = append(advertised[exit], prefix)
			}
		}
		for i, prefixes := range advertised {
			meshes[i].SetEgressPrefixes(prefixes)
			meshes[i].SetAdvertisedReady(true, true)
		}

		// the path a packet the model's tables send, from the read off from's tun, ends at the node that holds its destination as its own
		// a read off the tun for this node's own destination, held or with no route is dropped there
		walk := func(from int, destination netip.Addr) int {
			at := from
			for hop := 0; hop <= n; hop++ {
				entry := lookup(tables[at], destination)
				switch {
				case entry.verdict == RouteLocal && hop > 0:
					return at
				case entry.verdict != RoutePeer:
					return -1
				}
				at = entry.next
			}
			return -1
		}
		var probes []exactnessProbe
		for id := range hegel.Draw(ht, pbt.Spanning(1, 6)) {
			family := 4
			if hegel.Draw(ht, hegel.Booleans()) {
				family = 6
			}
			from := hegel.Draw(ht, hegel.Integers(0, n-1))
			destination := hegel.Draw(ht, hegel.SampledFrom(exactnessDestinations[family]))
			inner := udpPacket(exactnessHost(from, family), destination, 100, false)
			marker := map[int]int{4: 28, 6: 48}[family]
			inner[marker], inner[marker+1] = 0xc2, byte(id)
			probe := exactnessProbe{from: from, holder: -1, want: walk(from, destination), raw: inner}
			if hegel.Draw(ht, hegel.Booleans()) {
				probe.holder = hegel.Draw(ht, hegel.SampledFrom(holders))
				probe.want = -1
				if walk(from, exactnessSID(probe.holder)) == probe.holder && !egressRefused(tables[probe.holder], transitOverlay, exactnessHost(from, family), destination) {
					probe.want = probe.holder
				}
				outer, err := srv6.Encapsulate(inner, exactnessHost(from, 6), []netip.Addr{exactnessSID(probe.holder)})
				if err != nil {
					ht.Fatal(err)
				}
				probe.raw = outer
			}
			probes = append(probes, probe)
		}
		for _, probe := range probes {
			// a read off the tun, classified and dispatched on this goroutine, so it holds a budget until it lands
			m := meshes[probe.from]
			b := <-m.outboundFree
			fill(b, probe.raw)
			m.classify(b)
			if len(b.peerOrder) == 0 {
				b.reset()
				m.outboundFree <- b
			} else {
				m.dispatchOutbound(b)
			}
		}
		// a packet on its way holds a budget of the session it is in from its reservation until the next node has taken it, which ends a handoff
		// so a pass that sees every budget empty and no handoff end sees none on its way
		waitUntil(ht, "every probe and every answer to land", func() bool {
			before := handoffs.Load()
			for _, peer := range all {
				if peer.dataBudget.used.Load() != 0 || peer.controlBudget.used.Load() != 0 {
					return false
				}
			}
			return handoffs.Load() == before
		})

		reached := make(map[[2]int][]string)
		for i := range n {
			var egressed uint64
			for _, write := range tunWrites(&tuns[i].recordingDevice) {
				for _, raw := range write {
					id, ok := probeOf(raw)
					if ok && probes[id].holder == i {
						egressed++
						reached[[2]int{id, i}] = append(reached[[2]int{id, i}], "egress")
						continue
					}
					src, dst, _ := packet.Addrs(raw)
					if _, verdict, _ := meshes[i].Routes.Resolve(src, dst); verdict != RouteLocal && !linkScoped(dst) {
						ht.Fatalf("node %d wrote to its tun a packet from %s to %s it resolves as verdict %d", i, src, dst, verdict)
					}
					if ok {
						reached[[2]int{id, i}] = append(reached[[2]int{id, i}], "tun")
					}
				}
			}
			if got := meshes[i].SegmentCounters().Egressed; got != egressed {
				ht.Fatalf("node %d counted %d egressed and wrote %d probes steered to its SID to its tun", i, got, egressed)
			}
		}
		for id, probe := range probes {
			sink := "tun"
			if probe.holder >= 0 {
				sink = "egress"
			}
			for i := range n {
				want := []string(nil)
				if i == probe.want {
					want = []string{sink}
				}
				if got := reached[[2]int{id, i}]; !slices.Equal(got, want) {
					ht.Fatalf("probe %d from node %d to %s through the SID of node %d reached node %d as %v, want %v, its path's end being node %d", id, probe.from, packetDestination(probe), probe.holder, i, got, want, probe.want)
				}
			}
		}
	})
}

// probeOf is the id a probe of the exactness property carries, for a UDP packet that is one
func probeOf(raw []byte) (int, bool) {
	marker := map[byte]int{4: 28, 6: 48}[raw[0]>>4]
	next := map[byte]int{4: 9, 6: 6}[raw[0]>>4]
	if marker == 0 || len(raw) <= marker+1 || raw[next] != 17 || raw[marker] != 0xc2 {
		return 0, false
	}
	return int(raw[marker+1]), true
}

// packetDestination is the inner destination a probe of the exactness property goes to
func packetDestination(probe exactnessProbe) netip.Addr {
	raw := probe.raw
	if probe.holder >= 0 {
		raw = raw[len(raw)-100:]
	}
	_, destination, _ := packet.Addrs(raw)
	return destination
}
