// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"bytes"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ranet3.com/pkgs/wireguard/tun"
)

// countedHold is a hold as a session's delivery is, one reference its caller's from the start
// zero closes when the last reference goes, and a release past it panics as the delivery's does
type countedHold struct {
	refs    atomic.Int32
	retains atomic.Int32
	zero    chan struct{}
}

func newCountedHold() *countedHold {
	h := &countedHold{zero: make(chan struct{})}
	h.refs.Store(1)
	return h
}

func (h *countedHold) Retain() {
	h.retains.Add(1)
	h.refs.Add(1)
}

func (h *countedHold) Release() {
	switch refs := h.refs.Add(-1); {
	case refs == 0:
		close(h.zero)
	case refs < 0:
		panic("a hold was released more times than it was held")
	}
}

// released waits until the last reference to h is gone
func (h *countedHold) released(tb testing.TB, what string) {
	tb.Helper()
	select {
	case <-h.zero:
	case <-time.After(deliveryTimeout):
		tb.Fatalf("%s still counts %d references", what, h.refs.Load())
	}
}

// gatedDevice is a lane whose every write waits at its gate, saying when one has started, and records what it wrote once it is let through
type gatedDevice struct {
	recordingDevice
	entered chan struct{}
	gate    chan struct{}
	// open lets every write through from now on
	open func()
}

func (d *gatedDevice) Write(bufs [][]byte, offset int) (int, error) {
	d.entered <- struct{}{}
	<-d.gate
	return d.recordingDevice.Write(bufs, offset)
}

// pass lets one write through
func (d *gatedDevice) pass() { d.gate <- struct{}{} }

// inside waits until a write has started and waits at the gate
func (d *gatedDevice) inside(tb testing.TB) {
	tb.Helper()
	select {
	case <-d.entered:
	case <-time.After(deliveryTimeout):
		tb.Fatal("no lane took the frames it was handed")
	}
}

// wrote is the packets of the next write the lane finished
func (d *gatedDevice) wrote(tb testing.TB) [][]byte {
	tb.Helper()
	select {
	case write := <-d.writes:
		return write.packets
	case <-time.After(deliveryTimeout):
		tb.Fatal("the lane finished no write")
		return nil
	}
}

// gatedLanes gives m a multiqueue tun of count gated lanes and starts its writers
// every gate opens before the mesh closes, so a test that fails with a write waiting still ends
func gatedLanes(tb testing.TB, m *Mesh, count int) []*gatedDevice {
	tb.Helper()
	gated := make([]*gatedDevice, count)
	devices := make([]tun.Device, count)
	for i := range gated {
		gate := make(chan struct{})
		gated[i] = &gatedDevice{
			recordingDevice: recordingDevice{writes: make(chan recordedWrite, 8)},
			entered:         make(chan struct{}, 8),
			gate:            gate,
			open:            sync.OnceFunc(func() { close(gate) }),
		}
		devices[i] = gated[i]
	}
	m.setDevice(lanesOf(devices...))
	m.startInboundWriters()
	tb.Cleanup(func() {
		for _, d := range gated {
			d.open()
		}
		m.Close()
	})
	return gated
}

// laneFlows is a TCP packet for each of count lanes, packet i of a flow whose hash names lane i
func laneFlows(count int) [][]byte {
	flows := make([][]byte, count)
	for port, found := uint16(40000), 0; found < count; port++ {
		packet := ipv6TCPPacket(port, 5201, byte(port))
		if lane := innerFlowHash(packet) % uint64(count); flows[lane] == nil {
			flows[lane] = packet
			found++
		}
	}
	return flows
}

// a lane handed frames under a hold keeps a reference until its write to the tun has returned, whatever the caller does with its own
// so the receive storage the frames lie in outlives every write that reads it, and goes back once the last lane is done
func TestLanesHoldTheFramesUntilTheirWritesReturn(t *testing.T) {
	m := ownEverything(&Mesh{closed: make(chan struct{})})
	lanes := gatedLanes(t, m, 2)
	flows := laneFlows(2)
	hold := newCountedHold()
	m.WriteHost(framed(flows...), hold)
	// the caller's own, as the emitter gives it back once emit returns
	hold.Release()
	for _, lane := range lanes {
		lane.inside(t)
	}
	if got := hold.refs.Load(); got != 2 {
		t.Fatalf("the hold counts %d references while both lanes write, want one for each", got)
	}
	lanes[0].pass()
	if got := lanes[0].wrote(t); len(got) != 1 || !bytes.Equal(got[0], flows[0]) {
		t.Fatalf("lane 0 wrote %x, want its flow's packet", got)
	}
	waitUntil(t, "lane 0 to give back its reference once its write returned", func() bool { return hold.refs.Load() == 1 })
	lanes[1].pass()
	lanes[1].wrote(t)
	hold.released(t, "the hold both lanes wrote under")
}

// a lane that merges the frames of two deliveries into one write keeps both until that write returns, and gives each back once
func TestLaneMergingTwoDeliveriesHoldsBoth(t *testing.T) {
	m := ownEverything(&Mesh{closed: make(chan struct{})})
	lanes := gatedLanes(t, m, 2)
	flow := laneFlows(2)[0]
	first := newCountedHold()
	m.WriteHost(framed(flow), first)
	first.Release()
	lanes[0].inside(t)
	// both queue behind the write the lane is held in, so it takes them together once it is through
	second, third := newCountedHold(), newCountedHold()
	m.WriteHost(framed(flow), second)
	second.Release()
	m.WriteHost(framed(flow), third)
	third.Release()
	lanes[0].pass()
	lanes[0].wrote(t)
	first.released(t, "the first delivery's hold")
	lanes[0].inside(t)
	if a, b := second.refs.Load(), third.refs.Load(); a != 1 || b != 1 {
		t.Fatalf("the merged deliveries' holds count %d and %d references while the lane writes them, want 1 each", a, b)
	}
	lanes[0].pass()
	if got := lanes[0].wrote(t); len(got) != 2 {
		t.Fatalf("the lane wrote %d packets, want the two deliveries' in one write", len(got))
	}
	second.released(t, "the second delivery's hold")
	third.released(t, "the third delivery's hold")
}

// a lane whose merged deliveries pass what one write carries writes them in two, and keeps every one of their holds until the last write has returned
func TestLaneHoldsMergedDeliveriesUntilItsLastWrite(t *testing.T) {
	m := ownEverything(&Mesh{closed: make(chan struct{})})
	lanes := gatedLanes(t, m, 2)
	flow := laneFlows(2)[0]
	first := newCountedHold()
	m.WriteHost(framed(flow), first)
	first.Release()
	lanes[0].inside(t)
	// both queue behind the write the lane is held in, and together they pass inboundWriteBatchSize by 2
	half := slices.Repeat([][]byte{flow}, inboundWriteBatchSize/2+1)
	second, third := newCountedHold(), newCountedHold()
	m.WriteHost(framed(half...), second)
	second.Release()
	m.WriteHost(framed(half...), third)
	third.Release()
	lanes[0].pass()
	lanes[0].wrote(t)
	first.released(t, "the first delivery's hold")
	lanes[0].inside(t)
	lanes[0].pass()
	if got := lanes[0].wrote(t); len(got) != inboundWriteBatchSize {
		t.Fatalf("the lane's first write of the merged deliveries carried %d packets, want %d", len(got), inboundWriteBatchSize)
	}
	lanes[0].inside(t)
	if a, b := second.refs.Load(), third.refs.Load(); a != 1 || b != 1 {
		t.Fatalf("the merged deliveries' holds count %d and %d references while the lane writes the rest of their frames, want 1 each", a, b)
	}
	lanes[0].pass()
	if got := lanes[0].wrote(t); len(got) != 2 {
		t.Fatalf("the lane's last write carried %d packets, want the 2 the first left", len(got))
	}
	second.released(t, "the second delivery's hold")
	third.released(t, "the third delivery's hold")
}

// a forward batch keeps the delivery's hold while a worker seals its packets, which still lie in the frames, and gives it back at reset
func TestForwardBatchHoldsTheFramesUntilReset(t *testing.T) {
	n := newTransitNode(t, DefaultMTU)
	sealing, through := make(chan struct{}, 1), make(chan struct{})
	open := sync.OnceFunc(func() { close(through) })
	t.Cleanup(open)
	blocked := NewPeer("blocked", func(int) (BatchSealer, error) {
		return func(raw [][]byte, headers []byte, out [][]byte) ([][]byte, error) {
			sealing <- struct{}{}
			<-through
			return cloning(raw, headers, out)
		}, nil
	}, func([][]byte) error { return nil }, nil)
	t.Cleanup(blocked.Close)
	blocked.SetMTU(DefaultMTU)
	n.m.Routes.Set(netip.Prefix{}, hostPrefix(transitFar[6]), blocked)

	hold := newCountedHold()
	n.m.DeliverInboundBatch(framed(udpPacket(transitSender[6], transitFar[6], 100, false)), DefaultMTU, n.fromPeer, hold)
	hold.Release()
	select {
	case <-sealing:
	case <-time.After(deliveryTimeout):
		t.Fatal("no worker sealed the forwarded packet")
	}
	if got := hold.refs.Load(); got != 1 {
		t.Fatalf("the hold counts %d references while its forwarded packet is sealed, want the forward batch's", got)
	}
	open()
	hold.released(t, "the forward batch's hold")
}

// what egresses through an exit writing to the tun, as the kernel exit does, carries the delivery's hold to the lane that writes it
// both for an egress segment's inner packet and for the decision's verdict through a prefix cap.egress advertises
func TestEgressCarriesTheHoldToTheLane(t *testing.T) {
	inner := flowPacket(tooBigSource[6], transitNowhere[6], 40000, 0)
	for name, frame := range map[string][]byte{
		"an egress segment": steered(t, inner, headend, egressExit),
		"the decision":      inner,
	} {
		t.Run(name, func(t *testing.T) {
			m := &Mesh{Name: "test0", Routes: NewRouteTable(), closed: make(chan struct{})}
			lanes := gatedLanes(t, m, 2)
			m.SetExit(tunExit{m.WriteHost})
			m.SetTransit(true)
			m.SetOverlay(transitOverlay)
			m.SetSegments(egressTable(t))
			defaults := []netip.Prefix{segPrefix("0.0.0.0/0"), segPrefix("::/0")}
			for _, prefix := range defaults {
				m.Routes.Set(netip.Prefix{}, prefix, Local)
			}
			m.SetEgressPrefixes(defaults)
			m.SetEgressReady(true, true)
			m.SetAdvertisedReady(true, true)
			routeLeaf(t, m, tooBigSource[4], tooBigSource[6])
			lane := lanes[innerFlowHash(inner)%2]

			hold := newCountedHold()
			m.DeliverInboundBatch(framed(frame), DefaultMTU, nil, hold)
			hold.Release()
			lane.inside(t)
			if got := hold.refs.Load(); got != 1 {
				t.Fatalf("the hold counts %d references while the lane writes what egressed, want the lane's", got)
			}
			lane.pass()
			if got := lane.wrote(t); len(got) != 1 || !bytes.Equal(got[0], inner) {
				t.Fatalf("the lane wrote %x, want the egressed packet", got)
			}
			hold.released(t, "the egressed frames' hold")
		})
	}
}

// Close may leave frames in a lane nobody reads any more, and gives back no hold for them a second time
// a frame left is never written and keeps its reference for the collector, one a writer took before it saw the close is written and given back once
// and a write after Close returns, keeping its reference only where it lands in a lane
func TestCloseWithFramesInALaneReleasesNoneTwice(t *testing.T) {
	m := ownEverything(&Mesh{closed: make(chan struct{})})
	lanes := gatedLanes(t, m, 2)
	flow := laneFlows(2)[0]
	first := newCountedHold()
	m.WriteHost(framed(flow), first)
	first.Release()
	lanes[0].inside(t)
	queued := newCountedHold()
	m.WriteHost(framed(flow), queued)
	queued.Release()

	closed := make(chan struct{})
	go func() { m.Close(); close(closed) }()
	<-m.closed
	lanes[0].open()
	select {
	case <-closed:
	case <-time.After(deliveryTimeout):
		t.Fatal("Close did not return once the write it waited for had finished")
	}
	lanes[0].wrote(t)
	first.released(t, "the hold of the write Close waited for")
	written := len(lanes[0].writes) == 1
	if got := queued.refs.Load(); written != (got == 0) || got < 0 || got > 1 {
		t.Errorf("the hold of the frame queued at the close counts %d references, and its frame was written %v", got, written)
	}

	late := newCountedHold()
	returned := make(chan struct{})
	go func() { m.WriteHost(framed(flow), late); close(returned) }()
	select {
	case <-returned:
	case <-time.After(deliveryTimeout):
		t.Fatal("a write after Close never returned")
	}
	late.Release()
	if got := late.refs.Load(); got < 0 || got > 1 {
		t.Errorf("the hold of a write after Close counts %d references", got)
	}
}

// a tun of one queue writes inside the caller's call, so the caller's own reference covers the write and the mesh takes none
func TestSingleQueueRetainsNothing(t *testing.T) {
	dev := &recordingDevice{writes: make(chan recordedWrite, 4)}
	m := ownEverything(&Mesh{closed: make(chan struct{})})
	m.setDevice(dev)
	m.startInboundWriters()
	t.Cleanup(m.Close)
	hold := newCountedHold()
	m.WriteHost(framed(laneFlows(1)[0]), hold)
	m.DeliverInboundBatch(framed(ipv6TCPPacket(40000, 5201, 1)), DefaultMTU, nil, hold)
	if got := hold.retains.Load(); got != 0 {
		t.Errorf("a single-queue mesh retained the hold %d times", got)
	}
	if got := len(dev.writes); got != 2 {
		t.Errorf("the tun took %d writes inside the calls, want 2", got)
	}
	hold.Release()
}
