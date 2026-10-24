// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/schema"
)

const (
	// raceReaders is how many reads run at once in the race test, each on a goroutine of its own as each queue's reader is
	raceReaders = 4
	// raceWrites is how many times each writer of the race test writes
	raceWrites = 200
)

// rereadTo classifies packets as the next read of b and reports the peer each went to, nil for none
// b keeps what its reads looked up for their sources, as a queue's reader keeps it from read to read
func rereadTo(m *Mesh, b *outboundBatch, packets ...[]byte) []*Peer {
	b.reset()
	fill(b, packets...)
	m.classify(b)
	return slices.Clone(b.peers[:len(packets)])
}

// readAcross reads raw off m's tun twice through one batch with change made between, and reports where each read went, nil for dropped, and what the two counted
func readAcross(m *Mesh, raw []byte, change func()) (*Peer, *Peer, TransitCounters) {
	b := newOutboundBatch(1)
	first := rereadTo(m, b, raw)[0]
	change()
	second := rereadTo(m, b, raw)[0]
	return first, second, m.TransitCounters()
}

// a change between two reads off the tun decides the second, though what the first looked up for its source outlives it
// each writer of what a source's answer reads that can move its verdict, the table's entries, the flags SetOverlay gives them and the overlay itself
// a source turning forged, a forged source turning owned, and an owned one turning unowned behind a destination counting as a default
func TestTUNReadAfterAChangeAnswersByTheChangedTable(t *testing.T) {
	for _, family := range []int{4, 6} {
		defaultRoute := map[int]netip.Prefix{4: segPrefix("0.0.0.0/0"), 6: segPrefix("::/0")}[family]
		// short is an entry of this node's that covers lan, not beyond, and counts as a default unless the overlay takes it in
		short := map[int]netip.Prefix{4: segPrefix("192.0.0.0/5"), 6: segPrefix("2000::/4")}[family]
		beyond := map[int]netip.Addr{4: segAddr("203.0.113.5"), 6: segAddr("3fff::5")}[family]
		lan, far, nowhere := edgeLAN[family], transitFar[family], transitNowhere[family]
		for _, c := range []struct {
			name string
			// arrange builds the mesh, the packet read, the change between the two reads and where each read goes, nil for dropped
			arrange func(t *testing.T) (*Mesh, []byte, func(), *Peer, *Peer)
			want    TransitCounters
		}{
			{"a source turning another node's", func(t *testing.T) (*Mesh, []byte, func(), *Peer, *Peer) {
				m, peer := edgeMesh(t)
				other := (&recordingPeer{}).peer(t, "another node")
				return m, udpPacket(nowhere, far, 100, false), func() { m.Routes.Set(netip.Prefix{}, hostPrefix(nowhere), other) }, peer, nil
			}, TransitCounters{Forged: 1}},
			{"another node's source turning this node's own", func(t *testing.T) (*Mesh, []byte, func(), *Peer, *Peer) {
				m, peer := edgeMesh(t)
				sender := transitSender[family]
				return m, udpPacket(sender, far, 100, false), func() { m.Routes.Set(netip.Prefix{}, hostPrefix(sender), Local) }, nil, peer
			}, TransitCounters{Forged: 1}},
			{"this node's own source left uncovered, toward a default", func(t *testing.T) (*Mesh, []byte, func(), *Peer, *Peer) {
				m, _ := edgeMesh(t)
				exit := (&recordingPeer{}).peer(t, "exit")
				m.Routes.Set(netip.Prefix{}, defaultRoute, exit)
				m.Routes.Set(netip.Prefix{}, hostPrefix(lan), Local)
				return m, udpPacket(lan, beyond, 100, false), func() { m.Routes.Remove(netip.Prefix{}, hostPrefix(lan)) }, exit, nil
			}, TransitCounters{UnownedSource: 1}},
			{"a source of a node whose routes are gone", func(t *testing.T) (*Mesh, []byte, func(), *Peer, *Peer) {
				m, peer := edgeMesh(t)
				other := (&recordingPeer{}).peer(t, "another node")
				m.Routes.Set(netip.Prefix{}, edgeSubnet[family], other)
				return m, udpPacket(edgeSubnetHost[family], far, 100, false), func() { m.Routes.RemovePeer(other) }, nil, peer
			}, TransitCounters{Forged: 1}},
			{"a source the overlay takes in", func(t *testing.T) (*Mesh, []byte, func(), *Peer, *Peer) {
				m, peer := edgeMesh(t)
				overlay := append(slices.Clone(transitOverlay), schema.PrefixFrom(hostPrefix(nowhere)))
				return m, udpPacket(nowhere, far, 100, false), func() { m.SetOverlay(overlay) }, peer, nil
			}, TransitCounters{Forged: 1}},
			{"this node's own source under an entry the overlay leaves to count as a default, toward a default", func(t *testing.T) (*Mesh, []byte, func(), *Peer, *Peer) {
				m, _ := edgeMesh(t)
				exit := (&recordingPeer{}).peer(t, "exit")
				m.SetOverlay(append(slices.Clone(transitOverlay), schema.PrefixFrom(short)))
				m.Routes.Set(netip.Prefix{}, defaultRoute, exit)
				m.Routes.Set(netip.Prefix{}, short, Local)
				return m, udpPacket(lan, beyond, 100, false), func() { m.SetOverlay(transitOverlay) }, exit, nil
			}, TransitCounters{UnownedSource: 1}},
		} {
			t.Run(fmt.Sprintf("IPv%d %s", family, c.name), func(t *testing.T) {
				m, raw, change, wantFirst, wantSecond := c.arrange(t)
				first, second, counted := readAcross(m, raw, change)
				if first != wantFirst || second != wantSecond {
					t.Errorf("the read went to %v before the change and to %v after it, want %v and %v", first, second, wantFirst, wantSecond)
				}
				if counted != c.want {
					t.Errorf("the two reads counted %+v, want %+v", counted, c.want)
				}
			})
		}
	}
}

// the overlay a change brings is in place before the table's generation moves, the change's write to the table waiting while the table's writers are held
// so a read the change falls within keeps no answer looked up from the old overlay under the new generation
func TestTUNOverlayIsInPlaceBeforeTheGenerationMoves(t *testing.T) {
	m, _ := edgeMesh(t)
	nowhere := transitNowhere[4]
	overlay := append(slices.Clone(transitOverlay), schema.PrefixFrom(hostPrefix(nowhere)))
	before := m.Routes.generation.Load()
	changed := make(chan struct{})
	m.Routes.mu.Lock()
	go func() {
		defer close(changed)
		m.SetOverlay(overlay)
	}()
	for deadline := time.Now().Add(deliveryTimeout); !m.inOverlay(nowhere) && time.Now().Before(deadline); {
		time.Sleep(deliveryPoll)
	}
	inPlace, held := m.inOverlay(nowhere), m.Routes.generation.Load() == before
	m.Routes.mu.Unlock()
	<-changed
	if !inPlace || !held {
		t.Errorf("with the table's writers held, the overlay was in place %v and the generation where it was %v, want both", inPlace, held)
	}
	if m.Routes.generation.Load() == before {
		t.Error("the overlay's change left the table's generation where it was")
	}
}

// answers outlive the read that looked them up until the table's generation moves
// so a write to the table that moves none, which no writer of the table makes, leaves the answer kept before it in force
func TestTUNReadsKeepTheirAnswersUntilTheGenerationMoves(t *testing.T) {
	for _, family := range []int{4, 6} {
		m, peer := edgeMesh(t)
		nowhere := transitNowhere[family]
		raw := udpPacket(nowhere, transitFar[family], 100, false)
		b := newOutboundBatch(1)
		first := rereadTo(m, b, raw)[0]
		m.Routes.table.Set(netip.Prefix{}, hostPrefix(nowhere), routeEntry{peer: (&recordingPeer{}).peer(t, "another node")})
		if second := rereadTo(m, b, raw)[0]; first != peer || second != peer {
			t.Errorf("IPv%d from %s, routed to another node by a write that moved no generation, went to %v and then to %v, want %v both times", family, nowhere, first, second, peer)
		}
	}
}

// a queue's reader keeps its answers from one of its reads to the next, though each read takes a batch of its own from the pool
// nothing hands the first read's batch back, so the second read takes the pool's other one
// and a write to the table that moves no generation leaves the answer the first read looked up in force for the second
func TestTUNReaderKeepsItsAnswersFromOneReadToTheNext(t *testing.T) {
	for _, family := range []int{4, 6} {
		m, peer := edgeMesh(t)
		dev := &scriptedDevice{reads: make(chan scriptedRead, 2), closed: make(chan struct{})}
		m.setDevice(dev)
		// a pool of two batches and no worker to give one back, the test taking each batch the reader hands on
		m.outboundFree, m.outboundJobs = make(chan *outboundBatch, 2), make(chan *outboundBatch, 2)
		for range cap(m.outboundFree) {
			m.outboundFree <- newOutboundBatch(dev.BatchSize())
		}
		m.outboundReaderWG.Add(1)
		go m.outboundReader(m.queues[0])
		t.Cleanup(m.Close)
		// handedOn is the batch the reader hands on for the read it was given, nil for a read it dropped
		handedOn := func() *outboundBatch {
			var b *outboundBatch
			waitUntil(t, "the read to be handed on or dropped", func() bool {
				select {
				case b = <-m.outboundJobs:
					return true
				default:
					return m.TransitCounters() != (TransitCounters{})
				}
			})
			return b
		}
		nowhere := transitNowhere[family]
		raw := udpPacket(nowhere, transitFar[family], 100, false)
		dev.reads <- scriptedRead{packets: [][]byte{raw}}
		first := handedOn()
		// the messages name the peer by its ID, which its sender, running beside the test, never writes
		if first == nil || first.peers[0] != peer {
			t.Fatalf("IPv%d from %s, the reader's first read was not sent to %s", family, nowhere, peer.ID)
		}
		m.Routes.table.Set(netip.Prefix{}, hostPrefix(nowhere), routeEntry{peer: (&recordingPeer{}).peer(t, "another node")})
		dev.reads <- scriptedRead{packets: [][]byte{raw}}
		switch second := handedOn(); {
		case second == nil:
			t.Errorf("IPv%d from %s, routed to another node by a write that moved no generation, was dropped at the reader's second read, want it sent to %s as the first read's answer says", family, nowhere, peer.ID)
		case second == first:
			t.Errorf("IPv%d from %s, the reader's second read came in the batch of its first, which nothing handed back", family, nowhere)
		case second.peers[0] != peer:
			t.Errorf("IPv%d from %s, the reader's second read was not sent to %s, as the first read's answer says", family, nowhere, peer.ID)
		}
	}
}

// the readers of a tun's queues keep answers of their own, though they all take their batches from one pool
// each reader here reads a lane of its own, so the test knows which reader each read goes to, and the two read in turn
// the first reads a new pair in each batch it takes from the pool, then a pair it sends on
// a write to the table that moves no generation then routes that pair's source to another node
// the second reads a new pair, which leaves it holding a batch the first read in, then that pair, which it has to look up itself
// answers the first kept would send the pair on, whether the mesh or a batch carried them, where the second's own drop it as forged
// last the two read new pairs at once, as the readers of two queues do
func TestTUNReadersOfTwoLanesKeepAnswersOfTheirOwn(t *testing.T) {
	m, _ := edgeMesh(t)
	far := &recordingPeer{}
	m.Routes.Set(netip.Prefix{}, hostPrefix(transitFar[6]), far.peer(t, "far"))
	// the lanes close together, since closing the tun closes its first lane alone
	closed := make(chan struct{})
	lanes := []*scriptedDevice{{reads: make(chan scriptedRead, 1), closed: closed}, {reads: make(chan scriptedRead, 1), closed: closed}}
	m.setDevice(lanesOf(lanes[0], lanes[1]))
	m.startOutboundPipeline()
	t.Cleanup(m.Close)
	var forged uint64
	// readNew reads on lane a packet of a pair no read brought before, from a source inside the overlay no route covers, so forged
	readNew := func(lane *scriptedDevice) {
		forged++
		source := netip.AddrFrom16([16]byte{0x3f, 0xff, 7: 1, 14: byte(forged >> 8), 15: byte(forged)})
		lane.reads <- scriptedRead{packets: [][]byte{udpPacket(source, transitFar[6], 100, false)}}
	}
	counted := func() {
		waitUntil(t, fmt.Sprintf("%d reads to be counted forged", forged), func() bool { return m.TransitCounters().Forged == forged })
	}
	// as many reads as the pool holds batches take the first lane's reader through each batch the pool lends it
	for range cap(m.outboundFree) {
		readNew(lanes[0])
		counted()
	}
	nowhere := transitNowhere[6]
	raw := udpPacket(nowhere, transitFar[6], 100, false)
	lanes[0].reads <- scriptedRead{packets: [][]byte{raw}}
	waitUntil(t, "the first lane's read from nowhere to reach far", func() bool { return len(far.packets(t)) == 1 })
	m.Routes.table.Set(netip.Prefix{}, hostPrefix(nowhere), routeEntry{peer: (&recordingPeer{}).peer(t, "another node")})
	readNew(lanes[1])
	counted()
	lanes[1].reads <- scriptedRead{packets: [][]byte{raw}}
	waitUntil(t, "the second lane's read from nowhere to be counted or sent", func() bool {
		return m.TransitCounters().Forged == forged+1 || len(far.packets(t)) == 2
	})
	if len(far.packets(t)) != 1 {
		t.Fatalf("the second lane's read from %s, routed to another node by a write that moved no generation, reached far by the answer the first lane's reader kept, want it looked up and dropped as forged", nowhere)
	}
	forged++
	for i := range 2 * keptPairs {
		readNew(lanes[i%2])
	}
	counted()
	if got := m.TransitCounters(); got != (TransitCounters{Forged: forged}) {
		t.Errorf("the reads counted %+v, want %d forged", got, forged)
	}
}

// the answers kept from read to read hold at most keptPairs pairs, however many the reads bring while the table holds still
func TestTUNReadsKeepAnswersForAtMostKeptPairs(t *testing.T) {
	m, _ := edgeMesh(t)
	b := newOutboundBatch(1)
	for i := range 2*keptPairs + 1 {
		source := netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 14: byte(i >> 8), 15: byte(i)})
		rereadTo(m, b, udpPacket(source, transitFar[6], 100, false))
		if kept := len(b.answers.pairs); kept > keptPairs {
			t.Fatalf("after reads of %d pairs %d answers were kept, want at most %d", i+1, kept, keptPairs)
		}
	}
}

// reads off the tun, each on a goroutine of its own as each queue's reader is, race every writer of what their sources' answers read
// each reader reads once before the writes start, and once the writers are done its next read goes where a read looking every answer up afresh goes
func TestTUNReadsRaceTheWritersOfTheirAnswers(t *testing.T) {
	m, _ := edgeMesh(t)
	other := (&recordingPeer{}).peer(t, "another node")
	exit := (&recordingPeer{}).peer(t, "exit")
	defaultRoute := map[int]netip.Prefix{4: segPrefix("0.0.0.0/0"), 6: segPrefix("::/0")}
	// internet is an address only the default reaches
	internet := map[int]netip.Addr{4: segAddr("203.0.113.99"), 6: segAddr("2001:db8::99")}
	var packets [][]byte
	var taken []schema.Prefix
	for _, family := range []int{4, 6} {
		for _, source := range []netip.Addr{transitNowhere[family], transitSender[family], edgeLAN[family], edgeSubnetHost[family]} {
			packets = append(packets, udpPacket(source, transitFar[family], 100, false), udpPacket(source, internet[family], 100, false))
		}
		taken = append(taken, schema.PrefixFrom(hostPrefix(transitNowhere[family])), schema.PrefixFrom(edgeSubnet[family]))
	}
	for _, family := range []int{4, 6} {
		m.Routes.Set(netip.Prefix{}, defaultRoute[family], exit)
	}
	writes := []func(i int){
		func(i int) {
			for _, family := range []int{4, 6} {
				if i%2 == 0 {
					m.Routes.Set(netip.Prefix{}, hostPrefix(transitNowhere[family]), other)
				} else {
					m.Routes.Remove(netip.Prefix{}, hostPrefix(transitNowhere[family]))
				}
			}
		},
		func(i int) {
			for _, family := range []int{4, 6} {
				m.Routes.Set(netip.Prefix{}, edgeSubnet[family], other)
			}
			if i%2 == 0 {
				m.Routes.RemovePeer(other)
			}
		},
		func(i int) {
			for _, family := range []int{4, 6} {
				if i%2 == 0 {
					m.Routes.Set(netip.Prefix{}, hostPrefix(edgeLAN[family]), Local)
				} else {
					m.Routes.Remove(netip.Prefix{}, hostPrefix(edgeLAN[family]))
				}
			}
		},
		func(i int) {
			if i%2 == 0 {
				m.SetOverlay(append(slices.Clone(transitOverlay), taken...))
			} else {
				m.SetOverlay(transitOverlay)
			}
		},
		func(i int) {
			var advertised []netip.Prefix
			if i%2 == 0 {
				advertised = []netip.Prefix{defaultRoute[4], defaultRoute[6]}
			}
			m.SetEgressPrefixes(advertised)
		},
	}
	done := make(chan struct{})
	var first, readers, writers sync.WaitGroup
	first.Add(raceReaders)
	for range raceReaders {
		readers.Go(func() {
			b := newOutboundBatch(len(packets))
			rereadTo(m, b, packets...)
			first.Done()
			for {
				select {
				case <-done:
					// every write came before this read began
					if got, want := rereadTo(m, b, packets...), classifiedTo(m, packets...); !slices.Equal(got, want) {
						t.Errorf("a read after the writes went to %v, a read looking its answers up afresh to %v", got, want)
					}
					return
				default:
					rereadTo(m, b, packets...)
				}
			}
		})
	}
	first.Wait()
	for _, write := range writes {
		writers.Go(func() {
			for i := range raceWrites {
				write(i)
			}
		})
	}
	writers.Wait()
	close(done)
	readers.Wait()
}
