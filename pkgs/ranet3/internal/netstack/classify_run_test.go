// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package netstack

import (
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/schema"
)

// hookDevice is a recordingDevice that runs next[i], where it is not nil, once its i-th write is recorded
// a write to the host comes from the packet classify is deciding
// next lands a change between that packet and the read's next
type hookDevice struct {
	*recordingDevice
	wrote int
	next  []func()
}

func (d *hookDevice) Write(bufs [][]byte, offset int) (int, error) {
	n, err := d.recordingDevice.Write(bufs, offset)
	if d.wrote < len(d.next) && d.next[d.wrote] != nil {
		d.next[d.wrote]()
	}
	d.wrote++
	return n, err
}

// drain is the packets written to the host since the last drain
func (d *hookDevice) drain() [][]byte {
	var packets [][]byte
	for {
		select {
		case w := <-d.recordingDevice.writes:
			packets = append(packets, w.packets...)
		default:
			return packets
		}
	}
}

// hookedLeaf is conservingLeaf with its tun a hookDevice and its clock unstarted
// each answer limit lets its burst out and never refills
// and two meshes given the same reads answer the same of them
// it returns the peer transitFar routes to
func hookedLeaf(tb testing.TB) (*Mesh, *hookDevice, *Peer) {
	tb.Helper()
	m := conservingLeaf(tb)
	m.segmentsStarted = time.Time{}
	dev := &hookDevice{recordingDevice: &recordingDevice{writes: make(chan recordedWrite, 1024)}}
	m.setDevice(dev)
	peer, _, _ := m.Routes.Resolve(netip.Addr{}, transitFar[4])
	return m, dev, peer
}

// besideWriterReads is how many reads TestClassifyBesideTableWriter classifies while the table is written
const besideWriterReads = 200

// classify beside a goroutine writing the table sends each packet to one of the peers some state the writer leaves routes transitFar to, or to none
// the writer moves, holds, withdraws and restores the route of transitFar in each family and changes the overlay, and under -race the race detector watches both
func TestClassifyBesideTableWriter(t *testing.T) {
	m, dev, peer := hookedLeaf(t)
	moved := (&recordingPeer{}).peer(t, "moved")
	exit, _, _ := m.Routes.Resolve(netip.Addr{}, edgeInternet[4])
	named := map[*Peer]bool{nil: true, peer: true, moved: true, exit: true}
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		for i := 0; ; i++ {
			select {
			case <-done:
				return
			default:
			}
			far := hostPrefix(transitFar[both[i%2]])
			switch i / 2 % 5 {
			case 0:
				m.Routes.Set(netip.Prefix{}, far, moved)
			case 1:
				m.Routes.Set(netip.Prefix{}, far, Unreachable)
			case 2:
				m.Routes.Remove(netip.Prefix{}, far)
			case 3:
				m.SetOverlay([]schema.Prefix{transitOverlay[i%2]})
			case 4:
				m.Routes.Set(netip.Prefix{}, far, peer)
				m.SetOverlay(transitOverlay)
			}
		}
	})
	defer func() {
		close(done)
		wg.Wait()
	}()
	var packets [][]byte
	for i := range pairReadPackets {
		packets = append(packets, udpPacket(transitOwn[both[i*2/pairReadPackets]], transitFar[both[i*2/pairReadPackets]], 100, false))
	}
	b := newOutboundBatch(len(packets))
	for read := range besideWriterReads {
		fill(b, packets...)
		m.classify(b)
		for i, went := range b.peers[:len(packets)] {
			if !named[went] {
				t.Fatalf("read %d: packet %d went to %v, which no state of the table named", read, i, went)
			}
		}
		dev.drain()
		b.reset()
	}
}

// peerIDs is the peer each of a read's n packets went to, "" for none
func peerIDs(b *outboundBatch, n int) []string {
	ids := make([]string, n)
	for i, peer := range b.peers[:n] {
		if peer != nil {
			ids[i] = peer.ID
		}
	}
	return ids
}

// a run of one pair in one read meets a change of its route made between its first packet and its second from its second packet on, as a lookup of each packet's own does
// the run's first packet is too big for the peer and answered into the tun, and that write changes the table before the next packet is classified
// from a host on a LAN the mesh routes nothing to, a withdrawal leaves the exit's default, which counts as one
func TestClassifyRunMeetsRouteChangeAtNextPacket(t *testing.T) {
	type runCase struct {
		name string
		// lan sends from edgeLAN rather than this node's own address
		lan    bool
		change func(m *Mesh, peer, moved *Peer, far netip.Addr)
		// later is the peer the run's later packets and the next read's go to, "" for none
		later string
		// first and second are the transit counts after the first read and after the second
		first, second TransitCounters
		// answered is each later packet answered into the tun
		answered bool
		// dropped is the packets the peer counts dropped when the read's share asks it for places
		dropped uint64
	}
	// the first packet's answer is counted answered in every case
	tooBigAnswered := TransitCounters{TooBig: 1, Answered: 1}
	cases := []runCase{
		{
			name:   "withdrawn",
			change: func(m *Mesh, _, _ *Peer, far netip.Addr) { m.Routes.Remove(netip.Prefix{}, hostPrefix(far)) },
			later:  "exit", first: tooBigAnswered, second: tooBigAnswered,
		},
		{
			name:   "moved",
			change: func(m *Mesh, _, moved *Peer, far netip.Addr) { m.Routes.Set(netip.Prefix{}, hostPrefix(far), moved) },
			later:  "moved", first: tooBigAnswered, second: tooBigAnswered,
		},
		{
			name:   "held",
			change: func(m *Mesh, _, _ *Peer, far netip.Addr) { m.Routes.Set(netip.Prefix{}, hostPrefix(far), Unreachable) },
			later:  "", first: TransitCounters{TooBig: 1, Held: 3, Answered: 4}, second: TransitCounters{TooBig: 1, Held: 4, Answered: 5}, answered: true,
		},
		{
			name:   "session closed",
			change: func(_ *Mesh, peer, _ *Peer, _ netip.Addr) { peer.Close() },
			later:  "peer", first: tooBigAnswered, second: tooBigAnswered, dropped: 4,
		},
		{
			name:   "withdrawn under a LAN host's packets",
			lan:    true,
			change: func(m *Mesh, _, _ *Peer, far netip.Addr) { m.Routes.Remove(netip.Prefix{}, hostPrefix(far)) },
			later:  "", first: TransitCounters{TooBig: 1, UnownedSource: 3, Answered: 1}, second: TransitCounters{TooBig: 1, UnownedSource: 4, Answered: 1},
		},
	}
	for _, c := range cases {
		for _, family := range both {
			m, dev, peer := hookedLeaf(t)
			moved := (&recordingPeer{}).peer(t, "moved")
			moved.SetMTU(tracedMTU)
			source, far := transitOwn[family], transitFar[family]
			if c.lan {
				source = edgeLAN[family]
			}
			changed := false
			dev.next = []func(){func() { c.change(m, peer, moved, far); changed = true }}
			small := udpPacket(source, far, 100, false)
			packets := [][]byte{udpPacket(source, far, tracedMTU+100, family == 4), small, small, small, udpPacket(source, edgeSubnetHost[family], 100, false)}
			b := newOutboundBatch(len(packets))
			fill(b, packets...)
			m.classify(b)
			if !changed {
				t.Fatalf("%s, IPv%d: the run's first packet wrote nothing to the host", c.name, family)
			}
			want := []string{"", c.later, c.later, c.later, "peer"}
			if got := peerIDs(b, len(packets)); !slices.Equal(got, want) {
				t.Errorf("%s, IPv%d: the read's packets went to %q, want %q", c.name, family, got, want)
			}
			if got := m.TransitCounters(); got != c.first {
				t.Errorf("%s, IPv%d: the read counted %+v, want %+v", c.name, family, got, c.first)
			}
			wantWrites := 1
			if c.answered {
				wantWrites += 3
			}
			if got := len(dev.drain()); got != wantWrites {
				t.Errorf("%s, IPv%d: the read wrote %d packets to the host, want %d", c.name, family, got, wantWrites)
			}
			if c.dropped != 0 {
				share := b.shares[peer]
				if batch := peer.reserveBatchNow(share.count, share.bytes); batch != nil {
					t.Errorf("%s, IPv%d: the closed peer gave the read's share places", c.name, family)
				}
				if got := peer.Dropped(); got != c.dropped {
					t.Errorf("%s, IPv%d: the closed peer counted %d dropped, want %d", c.name, family, got, c.dropped)
				}
			}
			b.reset()
			fill(b, small)
			m.classify(b)
			if got := peerIDs(b, 1); got[0] != c.later {
				t.Errorf("%s, IPv%d: the next read's packet went to %q, want %q", c.name, family, got[0], c.later)
			}
			if got := m.TransitCounters(); got != c.second {
				t.Errorf("%s, IPv%d: the next read left the counts at %+v, want %+v", c.name, family, got, c.second)
			}
		}
	}
}

// a read of one run of pairReadPackets packets of one pair answers every packet from the first packet's lookup, and in a read alternating two pairs no packet but the first takes that lookup's answer
// the read's first packet is too big for the peer, and its answer into the tun makes Unreachable the peer both pairs route to, the table and its root unchanged
// a packet looked up after that resolves as held and goes to no peer, and one that takes the first packet's lookup still goes to the peer
// Unreachable is again the peer it was once the read is classified
func TestClassifyLooksUpOnceARun(t *testing.T) {
	held := Unreachable
	defer func() { Unreachable = held }()
	for _, family := range both {
		for _, alternating := range []bool{false, true} {
			m, dev, peer := hookedLeaf(t)
			m.Routes.Set(netip.Prefix{}, hostPrefix(pairFar[family]), peer)
			packets := [][]byte{udpPacket(transitOwn[family], transitFar[family], tracedMTU+100, family == 4)}
			for i := 1; i < pairReadPackets; i++ {
				dst := transitFar[family]
				if alternating && i%2 == 1 {
					dst = pairFar[family]
				}
				packets = append(packets, udpPacket(transitOwn[family], dst, 100, false))
			}
			dev.next = []func(){func() { Unreachable = peer }}
			b := newOutboundBatch(len(packets))
			fill(b, packets...)
			m.classify(b)
			Unreachable = held
			lookups := 1
			for _, went := range b.peers[1:len(packets)] {
				if went == nil {
					lookups++
				}
			}
			want := 1
			if alternating {
				want = len(packets)
			}
			if lookups != want {
				t.Errorf("IPv%d, alternating %v: a read of %d packets made %d lookups, want %d", family, alternating, len(packets), lookups, want)
			}
		}
	}
}
