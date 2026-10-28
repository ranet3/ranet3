// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"math"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/logtest"
	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
	"ranet3.com/pkgs/wireguard/tun"
)

// the segments the tests below hold, an End.DT46 to the mesh, an egress segment and a waypoint
// the allow list holds headend, the inner sources tcpPacket writes and a leaf network of the overlay, and none of the stranger addresses
var (
	meshExit       = segAddr("3fff:b:0:106::1")
	egressExit     = segAddr("3fff:b:0:106::3")
	egressWaypoint = segAddr("3fff:b:0:106::2")
	egressNext     = segAddr("3fff:b:0:206::1")
	egressAllow    = []netip.Prefix{segPrefix("3fff:b::/48"), segPrefix("3fff:a::/32"), segPrefix("10.0.0.0/8"), segPrefix("192.0.2.64/26")}
	headend        = segAddr("3fff:b:0:200::1")
	stranger       = map[int]netip.Addr{4: segAddr("192.0.2.1"), 6: segAddr("2001:db8:bad::1")}
	// egressOwned are egressMesh's own destinations, which the tests deliver to and never egress to
	egressOwned = []netip.Addr{segAddr("2001:db8::a"), segAddr("2001:db8::b"), segAddr("3fff:a::2"), segAddr("3fff:a::3"), segAddr("192.0.2.70")}
)

func egressTable(tb testing.TB) *srv6.LocalTable {
	tb.Helper()
	allow := make([]schema.Prefix, len(egressAllow))
	for i, prefix := range egressAllow {
		allow[i] = schema.PrefixFrom(prefix)
	}
	table, err := srv6.NewLocalTable([]srv6.Segment{
		{SID: schema.AddrFrom(meshExit), Behavior: srv6.BehaviorEndDT46},
		{SID: schema.AddrFrom(egressExit), Behavior: srv6.BehaviorEndDT46, Deliver: srv6.DeliverEgress, Allow: allow},
		{SID: schema.AddrFrom(egressWaypoint), Behavior: srv6.BehaviorEnd},
	}, everySource)
	if err != nil {
		tb.Fatal(err)
	}
	return table
}

func steered(tb testing.TB, inner []byte, source netip.Addr, path ...netip.Addr) []byte {
	tb.Helper()
	outer, err := srv6.Encapsulate(inner, source, path)
	if err != nil {
		tb.Fatal(err)
	}
	return outer
}

// egressMesh is a mesh of one tun lane recording its writes, holding egressTable, with both families ready to egress
// egressOwned are its own, so a packet no segment takes goes to the tun where it is for one of them
// the inner sources tcpPacket writes are a leaf's, a source the mesh routes a reply to, which an egress segment asks of what it egresses
// and nothing else is routed, so no egress segment's result is for the mesh
// its drop reports are not spaced, so every one reaches the log
func egressMesh(tb testing.TB) (*Mesh, *recordingDevice) {
	tb.Helper()
	dev := &boundedDevice{recordingDevice: recordingDevice{writes: make(chan recordedWrite, 16)}, tb: tb}
	m := ownEgressOwned(&Mesh{Name: "test0", Routes: NewRouteTable(), closed: make(chan struct{})})
	m.setDevice(dev)
	m.SetExit(tunExit{m.WriteHost})
	m.SetSegments(egressTable(tb))
	m.SetEgressReady(true, true)
	routeLeaf(tb, m, tooBigSource[4], tooBigSource[6])
	tb.Cleanup(m.Close)
	return m, &dev.recordingDevice
}

// boundedDevice is a tun of one lane recording its writes, which fails the test at a write past its writes' capacity rather than block it
type boundedDevice struct {
	recordingDevice
	tb testing.TB
}

func (d *boundedDevice) Write(bufs [][]byte, offset int) (int, error) {
	if len(d.writes) == cap(d.writes) {
		d.tb.Errorf("the tun was written more than the %d times it records", cap(d.writes))
		return 0, errors.New("the recording is full")
	}
	return d.recordingDevice.Write(bufs, offset)
}

// tunExit hands what it takes to write, the mesh's tun writer as the kernel exit's Runtime holds it
type tunExit struct{ write func(frames [][]byte) }

func (e tunExit) Egress(frames [][]byte) { e.write(frames) }

// recordingExit keeps each batch it takes, every packet copied out of its frame
type recordingExit struct {
	mu      sync.Mutex
	batches [][][]byte
}

func (e *recordingExit) Egress(frames [][]byte) {
	batch := make([][]byte, len(frames))
	for i, frame := range frames {
		batch[i] = slices.Clone(frame[TUNHeadroom:])
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.batches = append(e.batches, batch)
}

// taken is the batches the exit took since the last call
func (e *recordingExit) taken() [][][]byte {
	e.mu.Lock()
	defer e.mu.Unlock()
	batches := e.batches
	e.batches = nil
	return batches
}

// ownEgressOwned makes each of egressOwned m's own as a host route
func ownEgressOwned(m *Mesh) *Mesh {
	for _, own := range egressOwned {
		m.Routes.Set(netip.Prefix{}, netip.PrefixFrom(own, own.BitLen()), Local)
	}
	return m
}

// routeLeaf routes each of sources to a leaf of m's, a source the mesh routes
func routeLeaf(tb testing.TB, m *Mesh, sources ...netip.Addr) {
	tb.Helper()
	leaf := (&recordingPeer{}).peer(tb, "leaf")
	for _, source := range sources {
		m.Routes.Set(netip.Prefix{}, netip.PrefixFrom(source, source.BitLen()), leaf)
	}
}

func tunWrites(dev *recordingDevice) [][][]byte {
	var writes [][][]byte
	for {
		select {
		case write := <-dev.writes:
			writes = append(writes, write.packets)
		default:
			return writes
		}
	}
}

func logLines(t *testing.T) func() []string {
	t.Helper()
	h := &lineHandler{}
	logtest.SetDefault(t, slog.New(h))
	return func() []string {
		h.mu.Lock()
		defer h.mu.Unlock()
		return slices.Clone(h.lines)
	}
}

type lineHandler struct {
	mu    sync.Mutex
	lines []string
}

func (h *lineHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *lineHandler) Handle(_ context.Context, r slog.Record) error {
	line := r.Message
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "err" {
			line += ": " + a.Value.String()
		}
		return true
	})
	h.mu.Lock()
	defer h.mu.Unlock()
	h.lines = append(h.lines, line)
	return nil
}
func (h *lineHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *lineHandler) WithGroup(string) slog.Handler      { return h }

// egressLanes is how many lanes the tun of the hand-off test below has
const egressLanes = 4

// flowPacket is packet seq of a UDP flow from source to destination, told from the other flows of a test by port
func flowPacket(source, destination netip.Addr, port uint16, seq byte) []byte {
	raw := udpPacket(source, destination, 64, false)
	header := 40
	if source.Is4() {
		header = 20
	}
	binary.BigEndian.PutUint16(raw[header:], port)
	raw[len(raw)-1] = seq
	return raw
}

// both egress hand-offs reach the tun's lanes through an exit writing as the kernel exit does, an egress segment's inner packet and the decision's verdict through a prefix cap.egress advertises, in both families
// each flow reaches the one lane its hash names, in the order it came, its packets counted egressed or delivered
// and a family whose word is not ready is dropped and counted not ready, the egress segments' word for the first and advertisedReady for the second
func TestEgressThroughTheTunWriterKeepsEachFlowOnItsLaneInOrder(t *testing.T) {
	const flows, packets = 6, 3
	lanes := make([]*recordingDevice, egressLanes)
	devices := make([]tun.Device, egressLanes)
	for i := range lanes {
		lanes[i] = &recordingDevice{writes: make(chan recordedWrite, 64)}
		devices[i] = lanes[i]
	}
	m := &Mesh{Name: "test0", Routes: NewRouteTable(), closed: make(chan struct{})}
	m.setDevice(lanesOf(devices...))
	m.SetExit(tunExit{m.WriteHost})
	m.startInboundWriters()
	t.Cleanup(m.Close)
	m.SetTransit(true)
	m.SetOverlay(transitOverlay)
	m.SetSegments(egressTable(t))
	defaults := []netip.Prefix{segPrefix("0.0.0.0/0"), segPrefix("::/0")}
	for _, prefix := range defaults {
		m.Routes.Set(netip.Prefix{}, prefix, Local)
	}
	m.SetEgressPrefixes(defaults)
	routeLeaf(t, m, tooBigSource[4], tooBigSource[6])

	// flow i is of family 4 or 6 as i is even or odd, and of mode 3 for i of 0, 1, 4 and 5, mode 2 for 2 and 3, interleaved packet by packet
	kind := func(flow int) (family int, mode3 bool) { return []int{4, 6}[flow%2], flow/2%2 == 0 }
	batch := func() (frames [][]byte, want map[uint16][][]byte) {
		want = make(map[uint16][][]byte)
		for seq := range packets {
			for flow := range flows {
				family, mode3 := kind(flow)
				port := uint16(40000 + flow)
				inner := flowPacket(tooBigSource[family], transitNowhere[family], port, byte(seq))
				want[port] = append(want[port], inner)
				if mode3 {
					frames = append(frames, steered(t, inner, headend, egressExit))
				} else {
					frames = append(frames, inner)
				}
			}
		}
		return frames, want
	}
	// collect reads what the lanes took until they hold total packets, by the flow each belongs to
	collect := func(total int) map[uint16][][]byte {
		got := make(map[uint16][][]byte)
		deadline := time.After(deliveryTimeout)
		for n := 0; n < total; {
			select {
			case write := <-lanes[0].writes:
				n += note(t, got, 0, write.packets)
			case write := <-lanes[1].writes:
				n += note(t, got, 1, write.packets)
			case write := <-lanes[2].writes:
				n += note(t, got, 2, write.packets)
			case write := <-lanes[3].writes:
				n += note(t, got, 3, write.packets)
			case <-deadline:
				t.Fatalf("the tun's lanes took %d packets of %d", n, total)
			}
		}
		return got
	}
	// run delivers one batch with ready deciding each flow, and checks what reached the tun and what was counted
	var egressed, segmentsNotReady, delivered, transitNotReady uint64
	run := func(ready func(family int, mode3 bool) bool) {
		t.Helper()
		frames, want := batch()
		m.DeliverInboundBatch(framed(frames...), DefaultMTU, nil)
		total := 0
		for flow := range flows {
			family, mode3 := kind(flow)
			switch {
			case ready(family, mode3) && mode3:
				egressed += packets
			case ready(family, mode3):
				delivered += packets
			case mode3:
				segmentsNotReady += packets
			default:
				transitNotReady += packets
			}
			if ready(family, mode3) {
				total += packets
			}
		}
		got := collect(total)
		for flow := range flows {
			family, mode3 := kind(flow)
			port := uint16(40000 + flow)
			wanted := want[port]
			if !ready(family, mode3) {
				wanted = nil
			}
			if !slices.EqualFunc(got[port], wanted, bytes.Equal) {
				t.Errorf("the IPv%d flow from port %d through mode 3 %t reached the tun as %d packets, want its %d in order", family, port, mode3, len(got[port]), len(wanted))
			}
		}
		if counters := m.SegmentCounters(); counters.Egressed != egressed || counters.NotReady != segmentsNotReady || counters.Dropped != 0 {
			t.Errorf("the egress segment counted %+v, want %d egressed and %d not ready", counters, egressed, segmentsNotReady)
		}
		if counters := m.TransitCounters(); counters.Delivered != delivered || counters.NotReady != transitNotReady {
			t.Errorf("the decision counted %+v, want %d delivered and %d not ready", counters, delivered, transitNotReady)
		}
	}

	m.SetEgressReady(true, true)
	m.SetAdvertisedReady(true, true)
	run(func(int, bool) bool { return true })
	// IPv4 of the egress segments and IPv6 of the advertised prefixes not ready
	m.SetEgressReady(false, true)
	m.SetAdvertisedReady(true, false)
	run(func(family int, mode3 bool) bool { return mode3 == (family == 6) })
}

// handOffMesh is a mesh of one tun lane recording its writes, with the segments and advertised defaults the tests below use, handing both egress verdicts to exit
func handOffMesh(t *testing.T, exit Exit) (*Mesh, *recordingDevice) {
	dev := &recordingDevice{writes: make(chan recordedWrite, 16)}
	m := &Mesh{Name: "test0", Routes: NewRouteTable(), closed: make(chan struct{})}
	m.setDevice(dev)
	m.SetExit(exit)
	t.Cleanup(m.Close)
	m.SetTransit(true)
	m.SetOverlay(transitOverlay)
	m.SetSegments(egressTable(t))
	defaults := []netip.Prefix{segPrefix("0.0.0.0/0"), segPrefix("::/0")}
	for _, prefix := range defaults {
		m.Routes.Set(netip.Prefix{}, prefix, Local)
	}
	m.SetEgressPrefixes(defaults)
	routeLeaf(t, m, tooBigSource[4], tooBigSource[6])
	return m, dev
}

// handOffBatch is the packets of an egress segment and of the decision's verdicts, and the frames carrying both interleaved
// mode 3's packets are of the families 4, 6, 4 and mode 2's of 6, 4, 6
func handOffBatch(t *testing.T) (mode3, mode2, frames [][]byte) {
	for i, family := range []int{4, 6, 4} {
		other := map[int]int{4: 6, 6: 4}[family]
		segment := flowPacket(tooBigSource[family], transitNowhere[family], uint16(40000+i), 3)
		decided := flowPacket(tooBigSource[other], transitNowhere[other], uint16(41000+i), 2)
		mode3, mode2 = append(mode3, segment), append(mode2, decided)
		frames = append(frames, steered(t, segment, headend, egressExit), decided)
	}
	return mode3, mode2, frames
}

// both egress hand-offs hand their batches to the exit and never to the tun, in both families
// an egress segment's inner packets in a batch of their own, then the decision's verdicts through a prefix cap.egress advertises in another, each in the order they came
// each counted egressed or delivered, and a family whose word is not ready dropped and counted not ready by its own mode's word, the egress segments' for mode 3 and advertisedReady for mode 2
func TestBothEgressHandOffsReachTheExit(t *testing.T) {
	exit := &recordingExit{}
	m, dev := handOffMesh(t, exit)
	mode3, mode2, frames := handOffBatch(t)
	ready := func(packets [][]byte, v4, v6 bool) [][]byte {
		var out [][]byte
		for _, raw := range packets {
			if raw[0]>>4 == 4 && v4 || raw[0]>>4 == 6 && v6 {
				out = append(out, raw)
			}
		}
		return out
	}
	for _, c := range []struct {
		name                               string
		egress4, egress6, advert4, advert6 bool
	}{
		{"with every family ready", true, true, true, true},
		{"with IPv4 of the egress segments and IPv6 of the advertised prefixes not ready", false, true, true, false},
		{"with no family ready", false, false, false, false},
	} {
		m.SetEgressReady(c.egress4, c.egress6)
		m.SetAdvertisedReady(c.advert4, c.advert6)
		segments, decisions := m.SegmentCounters(), m.TransitCounters()
		m.DeliverInboundBatch(framed(frames...), DefaultMTU, nil)
		want3, want2 := ready(mode3, c.egress4, c.egress6), ready(mode2, c.advert4, c.advert6)
		var want [][][]byte
		for _, batch := range [][][]byte{want3, want2} {
			if len(batch) != 0 {
				want = append(want, batch)
			}
		}
		if got := exit.taken(); !slices.EqualFunc(got, want, func(a, b [][]byte) bool { return slices.EqualFunc(a, b, bytes.Equal) }) {
			t.Errorf("%s the exit took %d batches %q, want mode 3's %d packets and then mode 2's %d, each in order", c.name, len(got), got, len(want3), len(want2))
		}
		if writes := tunWrites(dev); len(writes) != 0 {
			t.Errorf("%s the tun took %q, want nothing", c.name, writes)
		}
		after := m.SegmentCounters()
		if egressed, notReady := after.Egressed-segments.Egressed, after.NotReady-segments.NotReady; egressed != uint64(len(want3)) || notReady != uint64(len(mode3)-len(want3)) {
			t.Errorf("%s the egress segment counted %d egressed and %d not ready, want %d and %d", c.name, egressed, notReady, len(want3), len(mode3)-len(want3))
		}
		decided := m.TransitCounters()
		if delivered, notReady := decided.Delivered-decisions.Delivered, decided.NotReady-decisions.NotReady; delivered != uint64(len(want2)) || notReady != uint64(len(mode2)-len(want2)) {
			t.Errorf("%s the decision counted %d delivered and %d not ready, want %d and %d", c.name, delivered, notReady, len(want2), len(mode2)-len(want2))
		}
	}
}

// countReadingExit is a recordingExit that reads m's counters when each batch reaches it, before it keeps the batch
type countReadingExit struct {
	recordingExit
	m     *Mesh
	reads []handOffCounts
}

type handOffCounts struct{ egressed, delivered uint64 }

func (e *countReadingExit) Egress(frames [][]byte) {
	read := handOffCounts{e.m.SegmentCounters().Egressed, e.m.TransitCounters().Delivered}
	e.mu.Lock()
	e.reads = append(e.reads, read)
	e.mu.Unlock()
	e.recordingExit.Egress(frames)
}

// both egress hand-offs count a batch before the exit takes it, so a reader that has a frame at the exit finds it counted
// the exit reads the egress segments' Egressed and the decision's Delivered as each batch reaches it, in the batch of an egress segment's inner packets and then in the batch of the decision's verdicts, each of both families
func TestEgressHandOffsCountEachBatchBeforeTheExitTakesIt(t *testing.T) {
	exit := &countReadingExit{}
	m, _ := handOffMesh(t, exit)
	exit.m = m
	_, _, frames := handOffBatch(t)
	m.SetEgressReady(true, true)
	m.SetAdvertisedReady(true, true)
	before := handOffCounts{m.SegmentCounters().Egressed, m.TransitCounters().Delivered}
	m.DeliverInboundBatch(framed(frames...), DefaultMTU, nil)
	batches := exit.taken()
	if len(batches) != 2 || len(exit.reads) != 2 {
		t.Fatalf("the exit took %d batches and read the counters %d times, want mode 3's and then mode 2's", len(batches), len(exit.reads))
	}
	if got, want := exit.reads[0].egressed-before.egressed, uint64(len(batches[0])); got != want {
		t.Errorf("the exit found %d packets counted egressed as the batch of %d egress segment packets reached it", got, want)
	}
	if got, want := exit.reads[1].delivered-before.delivered, uint64(len(batches[1])); got != want {
		t.Errorf("the exit found %d packets counted delivered as the batch of %d verdicts reached it", got, want)
	}
}

// note files packets, a write to lane, under their flows' ports in got, and fails the test where a flow reaches a lane other than its hash names
func note(t *testing.T, got map[uint16][][]byte, lane int, packets [][]byte) int {
	t.Helper()
	for _, raw := range packets {
		header := 40
		if raw[0]>>4 == 4 {
			header = 20
		}
		port := binary.BigEndian.Uint16(raw[header:])
		if want := int(innerFlowHash(raw) % egressLanes); lane != want {
			t.Errorf("a packet of the flow from port %d reached lane %d, want lane %d its hash names", port, lane, want)
		}
		got[port] = append(got[port], raw)
	}
	return len(packets)
}

// on a tun of one lane an egress segment's results reach it in one write of their own, in batch order, ahead of the frames passed and delivered around them
func TestEgressResultsReachTheTunInOneWrite(t *testing.T) {
	m, meshTUN := egressMesh(t)
	first := plainV6(segAddr("2001:db8::1"), segAddr("2001:db8::a"), "first")
	delivered := plainV6(segAddr("3fff:a::1"), segAddr("3fff:a::2"), "delivered")
	egressed6 := plainV6(segAddr("3fff:a::1"), segAddr("2001:db8:4860::8888"), "egressed over IPv6")
	middle := plainV6(segAddr("2001:db8::1"), segAddr("2001:db8::b"), "middle")
	egressed4 := udpPacket(tooBigSource[4], tooBigDestination[4], 64, false)
	last := plainV6(segAddr("3fff:a::1"), segAddr("3fff:a::3"), "last delivered")
	m.DeliverInboundBatch(framed(
		first,
		steered(t, delivered, headend, meshExit),
		steered(t, egressed6, headend, egressExit),
		middle,
		steered(t, egressed4, headend, egressExit),
		steered(t, last, headend, meshExit),
	), DefaultMTU, nil)

	writes := tunWrites(meshTUN)
	if len(writes) != 2 || !slices.EqualFunc(writes[0], [][]byte{egressed6, egressed4}, bytes.Equal) || !slices.EqualFunc(writes[1], [][]byte{first, delivered, middle, last}, bytes.Equal) {
		t.Errorf("the tun took %q, want the two inner packets in one write, then the passed and delivered packets in their order", writes)
	}
	if counters := m.SegmentCounters(); counters.Egressed != 2 || counters.Delivered != 2 || counters.Dropped != 0 || counters.NotReady != 0 {
		t.Errorf("the batch counted %+v, want 2 egressed and 2 delivered", counters)
	}
}

const allocTries = 5

// AllocsPerRun counts every goroutine's allocations, which only ever add to f's own
func leastAllocs(f func()) float64 {
	least := math.Inf(1)
	for range allocTries {
		least = min(least, testing.AllocsPerRun(100, f))
	}
	return least
}

// discardDevice is a tun of one lane taking every write and keeping nothing
type discardDevice struct{ recordingDevice }

func (*discardDevice) Write(bufs [][]byte, _ int) (int, error) { return len(bufs), nil }

// a batch of egress results allocates at most once more than a batch of as many packets delivered to the mesh tun, its egress list sized once
func TestEgressBatchAllocatesOnceMoreThanADelivery(t *testing.T) {
	m := ownEgressOwned(&Mesh{Name: "test0", Routes: NewRouteTable(), closed: make(chan struct{})})
	m.setDevice(&discardDevice{})
	m.SetExit(tunExit{m.WriteHost})
	m.SetSegments(egressTable(t))
	m.SetEgressReady(true, true)
	routeLeaf(t, m, tooBigSource[6])
	t.Cleanup(m.Close)
	batch := func(exit, destination netip.Addr) [][]byte {
		frames := make([][]byte, inboundWriteBatchSize)
		for i := range frames {
			frames[i] = steered(t, plainV6(segAddr("3fff:a::1"), destination, "payload"), headend, exit)
		}
		return framed(frames...)
	}
	delivered, egressed := batch(meshExit, egressOwned[2]), batch(egressExit, segAddr("2001:db8:4860::8888"))
	m.applySegments(egressed, DefaultMTU)
	if got := m.SegmentCounters().Egressed; got != inboundWriteBatchSize {
		t.Fatalf("%d of the batch's %d packets took the egress segment, so this proves nothing", got, inboundWriteBatchSize)
	}
	deliver := leastAllocs(func() { m.applySegments(delivered, DefaultMTU) })
	if egress := leastAllocs(func() { m.applySegments(egressed, DefaultMTU) }); egress > deliver+1 {
		t.Errorf("a batch of %d egress results allocated %.0f times, want at most one more than the %.0f of delivering it", inboundWriteBatchSize, egress, deliver)
	}
}

// an egress result of a family the translator has not reported ready is dropped and counted not ready, since the host would carry it out untranslated
// it reaches neither the tun nor the sender, while the ready family's result is written
func TestEgressOfAFamilyNotReadyIsNotReady(t *testing.T) {
	m, meshTUN := egressMesh(t)
	m.SetEgressReady(false, false)
	back := &recordingPeer{}
	m.Routes.Set(netip.Prefix{}, netip.PrefixFrom(headend, 128), back.peer(t, "headend"))
	egressed6 := plainV6(segAddr("3fff:a::1"), segAddr("2001:db8:4860::8888"), "egressed over IPv6")
	egressed4 := udpPacket(tooBigSource[4], tooBigDestination[4], 64, false)
	batch := func() {
		m.DeliverInboundBatch(framed(steered(t, egressed6, headend, egressExit), steered(t, egressed4, headend, egressExit)), DefaultMTU, nil)
	}

	batch()
	if counters := m.SegmentCounters(); counters.NotReady != 2 || counters.Egressed != 0 || counters.Dropped != 0 {
		t.Errorf("a mesh with neither family ready counted %+v, want 2 not ready", counters)
	}
	if writes := tunWrites(meshTUN); len(writes) != 0 {
		t.Errorf("an egress result not ready reached the tun as %q", writes)
	}
	m.SetEgressReady(false, true)
	batch()
	if writes := tunWrites(meshTUN); len(writes) != 1 || !slices.EqualFunc(writes[0], [][]byte{egressed6}, bytes.Equal) {
		t.Errorf("with IPv6 alone ready the tun took %q, want the IPv6 packet alone", writes)
	}
	if counters := m.SegmentCounters(); counters.NotReady != 3 || counters.Egressed != 1 || counters.Dropped != 0 {
		t.Errorf("with IPv6 alone ready the mesh counted %+v, want 3 not ready and 1 egressed", counters)
	}
	if sent := back.packets(t); len(sent) != 0 {
		t.Errorf("an egress result not ready was answered with %q", sent)
	}
}

// a packet whose outer or inner source is outside the egress segment's allow list is counted refused and dropped
// and stays out of the tun and the answers to its sender, whose route is there and whose ICMP budget is full
func TestEgressRefusedSourceIsCountedAndNeverAnswered(t *testing.T) {
	m, meshTUN := egressMesh(t)
	back := &recordingPeer{}
	peer := back.peer(t, "sender")
	for _, source := range []netip.Addr{headend, stranger[4], stranger[6], segAddr("3fff:bad::1")} {
		m.Routes.Set(netip.Prefix{}, netip.PrefixFrom(source, source.BitLen()), peer)
	}

	m.DeliverInboundBatch(framed(
		steered(t, plainV6(segAddr("3fff:a::1"), segAddr("2001:db8:4860::8888"), "outer outside"), segAddr("3fff:bad::1"), egressExit),
		steered(t, plainV6(stranger[6], segAddr("2001:db8:4860::8888"), "inner outside"), headend, egressExit),
		steered(t, udpPacket(stranger[4], tooBigDestination[4], 64, false), headend, egressExit),
	), DefaultMTU, nil)
	if writes := tunWrites(meshTUN); len(writes) != 0 {
		t.Errorf("a refused source reached the tun as %q", writes)
	}
	if sent := back.packets(t); len(sent) != 0 {
		t.Errorf("a refused source was answered with %q", sent)
	}
	if counters := m.SegmentCounters(); counters.Refused != 3 || counters.Dropped != 3 || counters.Answered != 0 || counters.Egressed != 0 {
		t.Errorf("three refused sources counted %+v, want 3 refused among 3 dropped", counters)
	}
}

// past the allow list an egress segment egresses an inner packet only where the mesh routes a reply to it
// from a peer's source, from one inside a hold, from this node's own network, or from a leaf network announced from a source prefix covering the packet's destination
// one the mesh routes no reply to is counted refused and dropped
// from an allowed source only entries counting as a default reach, with no overlay covering this node's short prefixes, or from that leaf network to a destination outside its source prefix
// as is one to the link-local 169.254.169.254, in its IPv4-mapped form for IPv6, which the host would forward out of its uplink
// one to any other IPv4-mapped address, and one from a link-local source the mesh routes that an allow list admitting 169.254.0.0/16 lets through
// and stays out of the tun and the answers to its sender
func TestEgressSegmentRefusesAnInnerPacketTheMeshRoutesNoReplyTo(t *testing.T) {
	m, meshTUN := egressMesh(t)
	ownEverything(m)
	m.SetOverlay(nil)
	allow := []schema.Prefix{schema.MustPrefix("169.254.0.0/16")}
	for _, prefix := range egressAllow {
		allow = append(allow, schema.PrefixFrom(prefix))
	}
	table, err := srv6.NewLocalTable([]srv6.Segment{{SID: schema.AddrFrom(egressExit), Behavior: srv6.BehaviorEndDT46, Deliver: srv6.DeliverEgress, Allow: allow}}, everySource)
	if err != nil {
		t.Fatal(err)
	}
	m.SetSegments(table)
	linkLocalSource := segAddr("169.254.1.1")
	routeLeaf(t, m, linkLocalSource)
	back := &recordingPeer{}
	m.Routes.Set(netip.Prefix{}, netip.PrefixFrom(headend, 128), back.peer(t, "headend"))
	held := map[int]netip.Addr{4: segAddr("192.0.2.71"), 6: segAddr("3fff:a::7")}
	own := map[int]netip.Prefix{4: segPrefix("192.0.2.112/28"), 6: segPrefix("3fff:a:0:70::/64")}
	unrouted := map[int]netip.Addr{4: segAddr("192.0.2.99"), 6: segAddr("3fff:a::99")}
	leaves := map[int]netip.Prefix{4: segPrefix("192.0.2.80/28"), 6: segPrefix("3fff:a:0:40::/64")}
	from := map[int]netip.Prefix{4: segPrefix("203.0.113.0/25"), 6: segPrefix("2001:db8::/48")}
	inside := map[int]netip.Addr{4: segAddr("203.0.113.5"), 6: segAddr("2001:db8::5")}
	outside := map[int]netip.Addr{4: segAddr("203.0.113.200"), 6: segAddr("2001:db8:1::5")}
	linkLocal := map[int]netip.Addr{4: segAddr("169.254.169.254"), 6: segAddr("::ffff:169.254.169.254")}
	leafPeer := (&recordingPeer{}).peer(t, "leaves")
	for _, family := range []int{4, 6} {
		m.Routes.Set(netip.Prefix{}, netip.PrefixFrom(held[family], held[family].BitLen()), Unreachable)
		m.Routes.Set(netip.Prefix{}, own[family], Local)
		m.Routes.Set(from[family], leaves[family], leafPeer)
	}
	var frames, want [][]byte
	var refused uint64
	for _, family := range []int{4, 6} {
		leaf := leaves[family].Addr().Next().Next()
		type egressCase struct {
			source, destination netip.Addr
			egresses            bool
		}
		cases := []egressCase{
			{tooBigSource[family], inside[family], true},
			{held[family], inside[family], true},
			{own[family].Addr().Next(), inside[family], true},
			{unrouted[family], inside[family], false},
			{leaf, inside[family], true},
			{leaf, outside[family], false},
			{tooBigSource[family], linkLocal[family], false},
		}
		if family == 6 {
			cases = append(cases, egressCase{tooBigSource[6], segAddr("::ffff:192.0.2.3"), false})
		} else {
			cases = append(cases, egressCase{linkLocalSource, inside[4], false})
		}
		for _, c := range cases {
			inner := udpPacket(c.source, c.destination, 64, false)
			frames = append(frames, steered(t, inner, headend, egressExit))
			if c.egresses {
				want = append(want, inner)
			} else {
				refused++
			}
		}
	}
	m.DeliverInboundBatch(framed(frames...), DefaultMTU, nil)
	if writes := tunWrites(meshTUN); len(writes) != 1 || !slices.EqualFunc(writes[0], want, bytes.Equal) {
		t.Errorf("the tun took %q, want the packets the mesh routes a reply to of each family", writes)
	}
	if counters := m.SegmentCounters(); counters.Refused != refused || counters.Dropped != refused || counters.Egressed != uint64(len(want)) || counters.Answered != 0 {
		t.Errorf("%d packets the mesh routes no reply to counted %+v, want each refused and dropped and %d egressed", refused, counters, len(want))
	}
	if sent := back.packets(t); len(sent) != 0 {
		t.Errorf("a packet the mesh routes no reply to was answered with %q", sent)
	}
}

// a batch of egress results refused for an inner source the mesh routes no reply to, or for an inner destination the mesh routes, allocates at most once more than the same batch delivered to the mesh tun
// since the address is boxed only for the one refusal an interval reports
func TestEgressRefusalAllocatesOnceMoreThanADelivery(t *testing.T) {
	lines := logLines(t)
	m, _ := egressMesh(t)
	ownEverything(m)
	m.SetOverlay(nil)
	m.startSegmentReports()
	batch := func(source, destination, exit netip.Addr) [][]byte {
		frames := make([][]byte, inboundWriteBatchSize)
		for i := range frames {
			frames[i] = steered(t, plainV6(source, destination, "payload"), headend, exit)
		}
		return framed(frames...)
	}
	delivered := batch(tooBigSource[6], segAddr("2001:db8::5"), meshExit)
	deliver := leastAllocs(func() { m.applySegments(delivered, DefaultMTU) })
	for _, refusal := range []struct {
		name   string
		frames [][]byte
	}{
		{"for their source", batch(segAddr("3fff:a::99"), segAddr("2001:db8::5"), egressExit)},
		{"for their destination", batch(tooBigSource[6], egressOwned[0], egressExit)},
	} {
		count := func() uint64 {
			before := m.SegmentCounters().Refused
			m.applySegments(refusal.frames, DefaultMTU)
			return m.SegmentCounters().Refused - before
		}
		if got := count(); got != inboundWriteBatchSize {
			t.Fatalf("%d of the batch's %d packets were refused %s, so this proves nothing", got, inboundWriteBatchSize, refusal.name)
		}
		if refuse := leastAllocs(func() { m.applySegments(refusal.frames, DefaultMTU) }); refuse > deliver+1 {
			t.Errorf("a batch of %d egress results refused %s allocated %.0f times, want at most one more than the %.0f of delivering it", inboundWriteBatchSize, refusal.name, refuse, deliver)
		}
		if got := count(); got != inboundWriteBatchSize {
			t.Errorf("after the runs %d of the batch's %d packets were refused %s, so the runs measured another path", got, inboundWriteBatchSize, refusal.name)
		}
	}
	if got := lines(); len(got) != 1 {
		t.Errorf("the refusals were reported as %q, want one line", got)
	}
}

// past the reply check an egress segment refuses an inner packet whose destination the mesh routes itself, in either family
// to another node, into a hold, to a prefix of this node's own or to an address cap.table assigns it, or by a route announced from a source prefix holding the packet's source
// and one inside cap.border's overlay that only another exit's halves cover, which this node's decision routes to that exit, whose own decision answers it as no route where its cap.border sets the overlay and egresses it where it has no cap.border
// counted refused and dropped, with no answer and nothing at any peer
// a destination only another exit's halves cover egresses, and so does one the source-prefixed route covers from a source outside its prefix
// a packet for a destination the mesh routes that the martian test or the reply check refuses first is counted once
// and one whose family is not ready is counted refused, not not ready, since the refusal comes ahead of the readiness read
func TestEgressSegmentRefusesAnInnerDestinationTheMeshRoutes(t *testing.T) {
	m, meshTUN := egressMesh(t)
	m.SetOverlay(transitOverlay)
	back, other, exit := &recordingPeer{}, &recordingPeer{}, &recordingPeer{}
	m.Routes.Set(netip.Prefix{}, netip.PrefixFrom(headend, 128), back.peer(t, "headend"))
	toOther, toExit := other.peer(t, "other"), exit.peer(t, "exit")
	// the third source of each family lies in the allow list and only the halves reach it
	sources := map[int][3]netip.Addr{4: {segAddr("192.0.2.65"), segAddr("192.0.2.67"), segAddr("192.0.2.99")}, 6: {segAddr("3fff:a::5"), segAddr("3fff:a::6"), segAddr("3fff:a::99")}}
	routeLeaf(t, m, sources[4][0], sources[4][1], sources[6][0], sources[6][1])
	for _, entry := range []struct {
		from, to string
		peer     *Peer
	}{
		{"", "0.0.0.0/1", toExit}, {"", "128.0.0.0/1", toExit}, {"", "::/1", toExit}, {"", "8000::/1", toExit},
		{"", "203.0.113.0/26", toOther}, {"", "2001:db8:1::/48", toOther},
		{"", "169.254.0.0/16", toOther}, {"", "fe80::/10", toOther},
		{"", "203.0.113.64/26", Unreachable}, {"", "2001:db8:2::/48", Unreachable},
		{"", "203.0.113.128/26", Local}, {"", "2001:db8:3::/48", Local},
		{"", "203.0.113.200/32", Assigned}, {"", "2001:db8:4::4/128", Assigned},
		{"192.0.2.65/32", "203.0.113.224/27", toOther}, {"3fff:a::5/128", "2001:db8:5::/48", toOther},
	} {
		var from netip.Prefix
		if entry.from != "" {
			from = segPrefix(entry.from)
		}
		m.Routes.Set(from, segPrefix(entry.to), entry.peer)
	}
	var frames, want [][]byte
	var refused uint64
	for _, c := range []struct {
		family, source int
		destination    string
		egresses       bool
	}{
		{4, 0, "203.0.113.5", false}, {4, 0, "203.0.113.70", false}, {4, 0, "203.0.113.130", false}, {4, 0, "203.0.113.200", false},
		{4, 0, "198.51.100.9", true}, {4, 0, "203.0.113.230", false}, {4, 1, "203.0.113.230", true},
		{6, 0, "2001:db8:1::5", false}, {6, 0, "2001:db8:2::5", false}, {6, 0, "2001:db8:3::5", false}, {6, 0, "2001:db8:4::4", false},
		{6, 0, "2001:db8:9::9", true}, {6, 0, "2001:db8:5::5", false}, {6, 1, "2001:db8:5::5", true},
		{4, 0, "169.254.169.254", false}, {6, 0, "fe80::5", false}, {4, 2, "203.0.113.5", false}, {6, 2, "2001:db8:1::5", false},
		{4, 0, "192.0.2.200", false}, {6, 0, "3fff:0:99::1", false},
	} {
		inner := udpPacket(sources[c.family][c.source], segAddr(c.destination), 64, false)
		frames = append(frames, steered(t, inner, headend, egressExit))
		if c.egresses {
			want = append(want, inner)
		} else {
			refused++
		}
	}
	m.DeliverInboundBatch(framed(frames...), DefaultMTU, nil)
	if writes := tunWrites(meshTUN); len(writes) != 1 || !slices.EqualFunc(writes[0], want, bytes.Equal) {
		t.Errorf("the tun took %q, want the packets for destinations the mesh does not route of each family", writes)
	}
	if counters := m.SegmentCounters(); counters.Refused != refused || counters.Dropped != refused || counters.Egressed != uint64(len(want)) || counters.Answered != 0 {
		t.Errorf("%d packets for the mesh counted %+v, want each refused and dropped and %d egressed", refused, counters, len(want))
	}
	for _, peer := range []*recordingPeer{back, other, exit} {
		if sent := peer.packets(t); len(sent) != 0 {
			t.Errorf("a peer was sent %q, want nothing sent for a packet an egress segment took", sent)
		}
	}

	for _, family := range []int{4, 6} {
		m.SetEgressReady(family == 6, family == 4)
		mesh := udpPacket(sources[family][0], segAddr(map[int]string{4: "203.0.113.5", 6: "2001:db8:1::5"}[family]), 64, false)
		elsewhere := udpPacket(sources[family][0], segAddr(map[int]string{4: "198.51.100.9", 6: "2001:db8:9::9"}[family]), 64, false)
		before := m.SegmentCounters()
		m.DeliverInboundBatch(framed(steered(t, mesh, headend, egressExit), steered(t, elsewhere, headend, egressExit)), DefaultMTU, nil)
		if got := m.SegmentCounters(); got.Refused != before.Refused+1 || got.Dropped != before.Dropped+1 || got.NotReady != before.NotReady+1 || got.Egressed != before.Egressed {
			t.Errorf("with IPv%d not ready a packet for the mesh and one past it moved the counters from %+v to %+v, want one refused and dropped and one not ready", family, before, got)
		}
	}
	if writes := tunWrites(meshTUN); len(writes) != 0 {
		t.Errorf("with a family not ready the tun took %q", writes)
	}
}

// an egress segment answers each packet of a batch as the first of its source and destination pair, each pair looked up once
// a pair the mesh routes no reply to, one for a destination the mesh routes, one that egresses, and a destination a route from one source's prefix covers sent from that source and from another
// each sent twice, so an answer kept for the wrong pair or holding the wrong check egresses or refuses a packet the first of its pair did not
func TestEgressSegmentAnswersEachPacketAsTheFirstOfItsPair(t *testing.T) {
	m, meshTUN := egressMesh(t)
	// the unrouted source lies in the allow list and no route reaches it
	routed, other, unrouted := segAddr("3fff:a::5"), segAddr("3fff:a::6"), segAddr("3fff:a::99")
	routeLeaf(t, m, routed, other)
	peer := (&recordingPeer{}).peer(t, "other")
	m.Routes.Set(netip.Prefix{}, segPrefix("2001:db8:1::/48"), peer)
	m.Routes.Set(hostPrefix(routed), segPrefix("2001:db8:5::/48"), peer)
	pairs := []struct {
		source, destination netip.Addr
		egresses            bool
	}{
		{unrouted, segAddr("2001:db8:9::9"), false},
		{routed, segAddr("2001:db8:1::5"), false},
		{routed, segAddr("2001:db8:9::9"), true},
		{routed, segAddr("2001:db8:5::5"), false},
		{other, segAddr("2001:db8:5::5"), true},
	}
	var frames, want [][]byte
	var refused uint64
	for range 2 {
		for _, pair := range pairs {
			inner := plainV6(pair.source, pair.destination, string(rune('a'+len(frames))))
			frames = append(frames, steered(t, inner, headend, egressExit))
			if pair.egresses {
				want = append(want, inner)
			} else {
				refused++
			}
		}
	}
	m.DeliverInboundBatch(framed(frames...), DefaultMTU, nil)
	if writes := tunWrites(meshTUN); len(writes) != 1 || !slices.EqualFunc(writes[0], want, bytes.Equal) {
		t.Errorf("the tun took %q, want both packets of each pair that egresses, in order", writes)
	}
	if counters := m.SegmentCounters(); counters.Refused != refused || counters.Dropped != refused || counters.Egressed != uint64(len(want)) {
		t.Errorf("%d packets of pairs refused and %d egressing counted %+v", refused, len(want), counters)
	}
}

// a SYN or SYN-ACK an egress segment lets through reaches the tun with its MSS lowered to what the session it came through carries
// the replies come back through the mesh, and the session's own clamp saw only the outer header
func TestEgressClampsTheMSSOfASYN(t *testing.T) {
	const session, offered = 1300, 8800
	for _, family := range []int{4, 6} {
		header := 20
		if family == 6 {
			header = 40
		}
		for _, flags := range []byte{synFlag, synFlag | 0x10} {
			m, meshTUN := egressMesh(t)
			inner := tcpPacket(family, 0, false, flags, binary.BigEndian.AppendUint16([]byte{optionMSS, mssLen}, offered), 0, 0)
			m.DeliverInboundBatch(framed(steered(t, inner, headend, egressExit)), session, nil)
			want := bytes.Clone(inner)
			binary.BigEndian.PutUint16(want[header+tcpHeaderLen+2:], uint16(session-header-tcpHeaderLen))
			binary.BigEndian.PutUint16(want[header+tcpChecksum:], tcpSum(want, header))
			if writes := tunWrites(meshTUN); len(writes) != 1 || len(writes[0]) != 1 || !bytes.Equal(writes[0][0], want) {
				t.Errorf("an IPv%d packet flagged %#02x offering %d through a %d byte session reached the tun as %x, want %x", family, flags, offered, session, writes, want)
			}
		}
	}
}

// a result naming an action applySegments does not know leaves the batch, counted dropped and reported
// rather than reaching the mesh tun as the packet it came in as
func TestUnknownActionIsDroppedAndReported(t *testing.T) {
	lines := logLines(t)
	m := &Mesh{Name: "test0", Routes: NewRouteTable()}
	before := plainV6(segAddr("2001:db8::1"), segAddr("2001:db8::a"), "before")
	unknown := plainV6(segAddr("2001:db8::1"), egressExit, "unknown")
	after := plainV6(segAddr("2001:db8::1"), segAddr("2001:db8::b"), "after")
	left, _ := m.actOnSegments(framed(before, unknown, after), DefaultMTU, func(packet []byte) srv6.Result {
		if bytes.Equal(packet, unknown) {
			return srv6.Result{Action: srv6.ActionDrop + 1}
		}
		return srv6.Result{Action: srv6.ActionPass}
	})
	if got := unframed(left); !slices.EqualFunc(got, [][]byte{before, after}, bytes.Equal) {
		t.Errorf("the batch came back as %q, want the two packets around the unknown one", got)
	}
	if counters := m.SegmentCounters(); counters.Dropped != 1 {
		t.Errorf("an unknown action counted %+v, want 1 dropped", counters)
	}
	if got := lines(); len(got) != 1 {
		t.Errorf("an unknown action was reported as %q, want one line", got)
	}
}
