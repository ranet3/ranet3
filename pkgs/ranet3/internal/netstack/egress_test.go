// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/logtest"
	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
	"ranet3.com/pkgs/wireguard/tun"
)

// the segments the tests below hold, an End.DT46 to the mesh, an egress segment and a waypoint
// the allow list holds headend and the inner sources tcpPacket writes, and none of the stranger addresses
var (
	meshExit       = segAddr("3fff:1:69c:8c6::1")
	egressExit     = segAddr("3fff:1:69c:8c6::3")
	egressWaypoint = segAddr("3fff:1:69c:8c6::2")
	egressNext     = segAddr("3fff:1:69c:98d6::1")
	egressAllow    = []netip.Prefix{segPrefix("3fff:1:69c::/48"), segPrefix("3fff:a::/32"), segPrefix("10.0.0.0/8")}
	headend        = segAddr("3fff:1:69c:98d0::1")
	stranger       = map[int]netip.Addr{4: segAddr("192.0.2.1"), 6: segAddr("2001:db8:bad::1")}
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
	})
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
// its drop reports are not spaced, so every one reaches the log
func egressMesh(tb testing.TB) (*Mesh, *recordingDevice) {
	tb.Helper()
	dev := &recordingDevice{writes: make(chan recordedWrite, 16)}
	m := &Mesh{Name: "test0", Routes: NewRouteTable(), closed: make(chan struct{})}
	m.setDevice(dev)
	m.SetSegments(egressTable(tb))
	m.SetEgressReady(true, true)
	tb.Cleanup(m.Close)
	return m, dev
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

// fakeEgress answers a write after its Close with errClosedTUN, an error naming no closure the writer could test for
var errClosedTUN = errors.New("write to a tun that is gone")

// fakeEgress is an egress device recording what it accepts, and the size of every write it is handed
// a Read answers with the next of reads, laid out as a device lays out a read, until Close, after which it waits lingers and reports closure
// readErr, when set, fails every Read before Close with that error, and failed counts those reads
// writeErr refuses the next write with that error, and entered, when set, holds every write until Close
// Close waits holds after it closes done, which wakes a held write and a read, so a closer that marks its close only after the device's shows it
type fakeEgress struct {
	recordingDevice
	reads    chan scriptedRead
	readErr  error
	failed   atomic.Int64
	lingers  time.Duration
	holds    time.Duration
	writeErr error
	entered  chan struct{}
	done     chan struct{}
	closes   atomic.Int64
	mu       sync.Mutex
	closed   bool
	writes   [][][]byte
	sizes    []int
}

func newFakeEgress() *fakeEgress {
	return &fakeEgress{reads: make(chan scriptedRead, 4), done: make(chan struct{})}
}

func (d *fakeEgress) Read(slab []byte, packets []tun.ReadPacket) (int, error) {
	if d.readErr != nil {
		select {
		case <-d.done:
			return 0, os.ErrClosed
		default:
			d.failed.Add(1)
			return 0, d.readErr
		}
	}
	select {
	case read := <-d.reads:
		return layOut(slab, packets, read.packets), read.err
	case <-d.done:
		time.Sleep(d.lingers)
		return 0, os.ErrClosed
	}
}

func (d *fakeEgress) Write(bufs [][]byte, offset int) (int, error) {
	if d.entered != nil {
		d.entered <- struct{}{}
		<-d.done
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.sizes = append(d.sizes, len(bufs))
	if d.closed {
		return 0, errClosedTUN
	}
	if err := d.writeErr; err != nil {
		d.writeErr = nil
		return 0, err
	}
	packets := make([][]byte, len(bufs))
	for i, buf := range bufs {
		packets[i] = bytes.Clone(buf[offset:])
	}
	d.writes = append(d.writes, packets)
	return len(bufs), nil
}

func (d *fakeEgress) Close() error {
	d.closes.Add(1)
	d.mu.Lock()
	if !d.closed {
		d.closed = true
		close(d.done)
	}
	d.mu.Unlock()
	time.Sleep(d.holds)
	return nil
}

func (d *fakeEgress) accepted() [][][]byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.writes)
}

func (d *fakeEgress) handed() []int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.sizes)
}

func drains() int {
	buf := make([]byte, 1<<22)
	return strings.Count(string(buf[:runtime.Stack(buf, true)]), "netstack.(*Mesh).drain(")
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

// an egress result leaves the batch for the egress device, and the frames passed and delivered around it reach the mesh tun in their order
// the egress results of a batch of up to inboundWriteBatchSize reach the device in one write, in batch order
func TestEgressResultsLeaveTheBatchInOneWrite(t *testing.T) {
	m, meshTUN := egressMesh(t)
	dev := newFakeEgress()
	m.SetEgress(dev)

	first := plainV6(segAddr("2001:db8::1"), segAddr("2001:db8::a"), "first")
	delivered := plainV6(segAddr("3fff:a::1"), segAddr("3fff:a::2"), "delivered")
	egressed6 := plainV6(segAddr("3fff:a::1"), segAddr("2001:4860:4860::8888"), "egressed over IPv6")
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
	), DefaultMTU)

	if writes := tunWrites(meshTUN); len(writes) != 1 || !slices.EqualFunc(writes[0], [][]byte{first, delivered, middle, last}, bytes.Equal) {
		t.Errorf("the mesh tun took %q, want the passed and delivered packets in their order in one write", writes)
	}
	if writes := dev.accepted(); len(writes) != 1 || !slices.EqualFunc(writes[0], [][]byte{egressed6, egressed4}, bytes.Equal) {
		t.Errorf("the egress device took %d writes, %q, want the two inner packets in one write in batch order", len(writes), writes)
	}
	if counters := m.SegmentCounters(); counters.Egressed != 2 || counters.Delivered != 2 || counters.Dropped != 0 || counters.NotReady != 0 {
		t.Errorf("the batch counted %+v, want 2 egressed and 2 delivered", counters)
	}
}

// a batch of more egress results than one tun write carries reaches the egress device in writes of at most inboundWriteBatchSize, in batch order
// each write is counted on its own, and one the device refuses leaves the writes after it to be made
func TestEgressWritesAtMostABatchAtATime(t *testing.T) {
	const results = 2*inboundWriteBatchSize + 1
	lines := logLines(t)
	m, _ := egressMesh(t)
	dev := newFakeEgress()
	dev.writeErr = errors.New("no buffer space available")
	m.SetEgress(dev)
	inners := make([][]byte, results)
	frames := make([][]byte, results)
	for i := range inners {
		inners[i] = plainV6(segAddr("3fff:a::1"), segAddr("2001:4860:4860::8888"), fmt.Sprint(i))
		frames[i] = steered(t, inners[i], headend, egressExit)
	}
	m.DeliverInboundBatch(framed(frames...), DefaultMTU)

	if got, want := dev.handed(), []int{inboundWriteBatchSize, inboundWriteBatchSize, 1}; !slices.Equal(got, want) {
		t.Errorf("the egress device was handed writes of %v packets, want %v", got, want)
	}
	if got := slices.Concat(dev.accepted()...); !slices.EqualFunc(got, inners[inboundWriteBatchSize:], bytes.Equal) {
		t.Errorf("the egress device took %d packets, want the %d after the refused write in batch order", len(got), results-inboundWriteBatchSize)
	}
	if counters := m.SegmentCounters(); counters.Dropped != inboundWriteBatchSize || counters.Egressed != results-inboundWriteBatchSize || counters.NotReady != 0 {
		t.Errorf("%d egress results with the first write refused counted %+v, want %d dropped and the rest egressed", results, counters, inboundWriteBatchSize)
	}
	if got := lines(); len(got) != 1 {
		t.Errorf("one refused write was reported as %q, want one line", got)
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

// a batch of egress results allocates at most once more than the same batch delivered to the mesh tun, its egress list sized once
func TestEgressBatchAllocatesOnceMoreThanADelivery(t *testing.T) {
	m, _ := egressMesh(t)
	batch := func(exit netip.Addr) [][]byte {
		frames := make([][]byte, inboundWriteBatchSize)
		for i := range frames {
			frames[i] = steered(t, plainV6(segAddr("3fff:a::1"), segAddr("2001:4860:4860::8888"), "payload"), headend, exit)
		}
		return framed(frames...)
	}
	delivered, egressed := batch(meshExit), batch(egressExit)
	m.applySegments(egressed, DefaultMTU)
	if got := m.SegmentCounters().NotReady; got != inboundWriteBatchSize {
		t.Fatalf("%d of the batch's %d packets took the egress segment, so this proves nothing", got, inboundWriteBatchSize)
	}
	deliver := leastAllocs(func() { m.applySegments(delivered, DefaultMTU) })
	if egress := leastAllocs(func() { m.applySegments(egressed, DefaultMTU) }); egress > deliver+1 {
		t.Errorf("a batch of %d egress results allocated %.0f times, want at most one more than the %.0f of delivering it", inboundWriteBatchSize, egress, deliver)
	}
}

// an egress result with no egress device installed is dropped and counted not ready, which is this node's state and no peer's
// it reaches neither the mesh tun nor the sender, and is never answered
func TestEgressWithoutADeviceIsNotReady(t *testing.T) {
	m, meshTUN := egressMesh(t)
	back := &recordingPeer{}
	m.Routes.Set(netip.Prefix{}, netip.PrefixFrom(headend, 128), back.peer(t, "headend"))

	m.DeliverInboundBatch(framed(steered(t, plainV6(segAddr("3fff:a::1"), segAddr("2001:4860:4860::8888"), "payload"), headend, egressExit)), DefaultMTU)
	if writes := tunWrites(meshTUN); len(writes) != 0 {
		t.Errorf("an egress result with no device reached the mesh tun as %q", writes)
	}
	if sent := back.packets(t); len(sent) != 0 {
		t.Errorf("an egress result with no device was answered with %q", sent)
	}
	if counters := m.SegmentCounters(); counters.NotReady != 1 || counters.Dropped != 0 || counters.Egressed != 0 || counters.Answered != 0 {
		t.Errorf("an egress result with no device counted %+v, want 1 not ready", counters)
	}
}

// with a device installed, an egress result of a family the translator has not reported ready is dropped and counted not ready
// since the device would carry it out of the uplink untranslated
// it reaches neither the device, the mesh tun nor the sender, while the ready family's result is written
func TestEgressOfAFamilyNotReadyIsNotReady(t *testing.T) {
	m, meshTUN := egressMesh(t)
	m.SetEgressReady(false, false)
	dev := newFakeEgress()
	m.SetEgress(dev)
	back := &recordingPeer{}
	m.Routes.Set(netip.Prefix{}, netip.PrefixFrom(headend, 128), back.peer(t, "headend"))
	egressed6 := plainV6(segAddr("3fff:a::1"), segAddr("2001:4860:4860::8888"), "egressed over IPv6")
	egressed4 := udpPacket(tooBigSource[4], tooBigDestination[4], 64, false)
	batch := func() {
		m.DeliverInboundBatch(framed(steered(t, egressed6, headend, egressExit), steered(t, egressed4, headend, egressExit)), DefaultMTU)
	}

	batch()
	if counters := m.SegmentCounters(); counters.NotReady != 2 || counters.Egressed != 0 || counters.Dropped != 0 {
		t.Errorf("a mesh with neither family ready counted %+v, want 2 not ready", counters)
	}
	m.SetEgressReady(false, true)
	batch()
	if writes := dev.accepted(); len(writes) != 1 || !slices.EqualFunc(writes[0], [][]byte{egressed6}, bytes.Equal) {
		t.Errorf("with IPv6 alone ready the egress device took %q, want the IPv6 packet alone", writes)
	}
	if counters := m.SegmentCounters(); counters.NotReady != 3 || counters.Egressed != 1 || counters.Dropped != 0 {
		t.Errorf("with IPv6 alone ready the mesh counted %+v, want 3 not ready and 1 egressed", counters)
	}
	if writes := tunWrites(meshTUN); len(writes) != 0 {
		t.Errorf("an egress result not ready reached the mesh tun as %q", writes)
	}
	if sent := back.packets(t); len(sent) != 0 {
		t.Errorf("an egress result not ready was answered with %q", sent)
	}
}

// a packet whose outer or inner source is outside the egress segment's allow list is counted refused and dropped
// and stays out of the egress device, the mesh tun and the answers to its sender, whose route is there and whose ICMP budget is full
func TestEgressRefusedSourceIsCountedAndNeverAnswered(t *testing.T) {
	m, meshTUN := egressMesh(t)
	dev := newFakeEgress()
	m.SetEgress(dev)
	back := &recordingPeer{}
	peer := back.peer(t, "sender")
	for _, source := range []netip.Addr{headend, stranger[4], stranger[6], segAddr("3fff:bad::1")} {
		m.Routes.Set(netip.Prefix{}, netip.PrefixFrom(source, source.BitLen()), peer)
	}

	m.DeliverInboundBatch(framed(
		steered(t, plainV6(segAddr("3fff:a::1"), segAddr("2001:4860:4860::8888"), "outer outside"), segAddr("3fff:bad::1"), egressExit),
		steered(t, plainV6(stranger[6], segAddr("2001:4860:4860::8888"), "inner outside"), headend, egressExit),
		steered(t, udpPacket(stranger[4], tooBigDestination[4], 64, false), headend, egressExit),
	), DefaultMTU)
	if writes := tunWrites(meshTUN); len(writes) != 0 {
		t.Errorf("a refused source reached the mesh tun as %q", writes)
	}
	if writes := dev.accepted(); len(writes) != 0 {
		t.Errorf("a refused source reached the egress device as %q", writes)
	}
	if sent := back.packets(t); len(sent) != 0 {
		t.Errorf("a refused source was answered with %q", sent)
	}
	if counters := m.SegmentCounters(); counters.Refused != 3 || counters.Dropped != 3 || counters.Answered != 0 || counters.Egressed != 0 {
		t.Errorf("three refused sources counted %+v, want 3 refused among 3 dropped", counters)
	}
}

// a SYN or SYN-ACK an egress segment lets through reaches the egress device with its MSS lowered to what the session it came through carries
// the replies come back through the mesh, and the session's own clamp saw only the outer header
func TestEgressClampsTheMSSOfASYN(t *testing.T) {
	const session, offered = 1300, 8800
	for _, family := range []int{4, 6} {
		header := 20
		if family == 6 {
			header = 40
		}
		for _, flags := range []byte{synFlag, synFlag | 0x10} {
			m, _ := egressMesh(t)
			dev := newFakeEgress()
			m.SetEgress(dev)
			inner := tcpPacket(family, 0, false, flags, binary.BigEndian.AppendUint16([]byte{optionMSS, mssLen}, offered), 0, 0)
			m.DeliverInboundBatch(framed(steered(t, inner, headend, egressExit)), session)
			want := bytes.Clone(inner)
			binary.BigEndian.PutUint16(want[header+tcpHeaderLen+2:], uint16(session-header-tcpHeaderLen))
			binary.BigEndian.PutUint16(want[header+tcpChecksum:], tcpSum(want, header))
			if writes := dev.accepted(); len(writes) != 1 || len(writes[0]) != 1 || !bytes.Equal(writes[0][0], want) {
				t.Errorf("an IPv%d packet flagged %#02x offering %d through a %d byte session reached the egress device as %x, want %x", family, flags, offered, session, writes, want)
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
	left := m.actOnSegments(framed(before, unknown, after), DefaultMTU, func(packet []byte) srv6.Result {
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

// a write the egress device refuses is counted dropped and reported
// and one to a device closed under it, by a swap or Close, is counted not ready and not reported, the node's own state
func TestEgressWriteErrors(t *testing.T) {
	inner := plainV6(segAddr("3fff:a::1"), segAddr("2001:4860:4860::8888"), "payload")
	batch := func() [][]byte {
		return framed(steered(t, inner, headend, egressExit), steered(t, inner, headend, egressExit))
	}
	t.Run("refused", func(t *testing.T) {
		lines := logLines(t)
		m, _ := egressMesh(t)
		dev := newFakeEgress()
		dev.writeErr = errors.New("no buffer space available")
		m.SetEgress(dev)
		m.DeliverInboundBatch(batch(), DefaultMTU)
		if counters := m.SegmentCounters(); counters.Dropped != 2 || counters.NotReady != 0 || counters.Egressed != 0 {
			t.Errorf("a refused write of two packets counted %+v, want 2 dropped", counters)
		}
		if got := lines(); len(got) != 1 || !strings.Contains(got[0], "no buffer space available") {
			t.Errorf("a refused write was reported as %q, want one line naming the error", got)
		}
	})
	t.Run("closed under the write", func(t *testing.T) {
		lines := logLines(t)
		m, _ := egressMesh(t)
		dev := newFakeEgress()
		dev.entered = make(chan struct{}, 1)
		dev.holds = closeHold
		m.SetEgress(dev)
		delivered := make(chan struct{})
		go func() { m.DeliverInboundBatch(batch(), DefaultMTU); close(delivered) }()
		select {
		case <-dev.entered:
		case <-time.After(deliveryTimeout):
			t.Fatal("the delivery never reached the egress device, so this proves nothing")
		}
		m.SetEgress(nil)
		select {
		case <-delivered:
		case <-time.After(deliveryTimeout):
			t.Fatal("the delivery never returned after its device closed")
		}
		if counters := m.SegmentCounters(); counters.NotReady != 2 || counters.Dropped != 0 || counters.Egressed != 0 {
			t.Errorf("a write of two packets to a device closed under it counted %+v, want 2 not ready", counters)
		}
		if got := lines(); len(got) != 0 {
			t.Errorf("a write to a device closed under it was reported as %q", got)
		}
	})
}

// the drain counts and throws away what each read of the egress device yields, a read cut short by its slab too
// a read error other than closure is reported and the drain reads on
// a swap and Close each close the device they replace exactly once and return only once its drain has ended, which the device's slow reads make visible
// and a mesh that has closed closes a device it is handed and starts no drain
func TestEgressDrainCountsWhatItReadsAndEndsWithItsDevice(t *testing.T) {
	lines := logLines(t)
	m, _ := egressMesh(t)
	first := newFakeEgress()
	first.lingers = closeHold
	m.SetEgress(first)
	drained := func(want uint64) {
		t.Helper()
		waitUntil(t, "the drain to count what it read", func() bool { return m.SegmentCounters().Drained == want })
	}

	one := plainV6(segAddr("3fff:a::1"), segAddr("2001:db8::1"), "routed into the wrong device")
	first.reads <- scriptedRead{packets: [][]byte{one, one, one}}
	drained(3)
	first.reads <- scriptedRead{packets: [][]byte{one, one}, err: tun.ErrTooManySegments}
	drained(5)
	first.reads <- scriptedRead{err: errors.New("read failed")}
	first.reads <- scriptedRead{packets: [][]byte{one}}
	drained(6)
	if got := lines(); len(got) != 1 || !strings.Contains(got[0], "read failed") {
		t.Errorf("the drain reported %q, want one line for the failed read", got)
	}

	second := newFakeEgress()
	second.lingers = closeHold
	m.SetEgress(second)
	if closes := first.closes.Load(); closes != 1 {
		t.Errorf("the swap closed the device it replaced %d times, want once", closes)
	}
	if running := drains(); running != 1 {
		t.Errorf("%d drains run after the swap returned, want the new device's one", running)
	}
	second.reads <- scriptedRead{packets: [][]byte{one}}
	drained(7)

	m.Close()
	if closes := second.closes.Load(); closes != 1 {
		t.Errorf("Close closed the egress device %d times, want once", closes)
	}
	if running := drains(); running != 0 {
		t.Errorf("%d drains outlived Close", running)
	}
	late := newFakeEgress()
	m.SetEgress(late)
	if closes := late.closes.Load(); closes != 1 {
		t.Errorf("a device handed to a closed mesh was closed %d times, want once", closes)
	}
	if running := drains(); running != 0 {
		t.Errorf("a device handed to a closed mesh started %d drains", running)
	}
	if closes := first.closes.Load(); closes != 1 {
		t.Errorf("the first device was closed %d times in all, want once", closes)
	}
}

// the drain leaves out of Drained an IPv6 packet to a multicast address of
// scope 0 to 2, and counts one to every wider scope, an IPv4 packet whatever
// its bytes where an IPv6 destination would sit, and a packet too short to hold
// an IPv6 header
func TestEgressDrainLeavesTheKernelsLinkScopedMulticastUncounted(t *testing.T) {
	m, _ := egressMesh(t)
	dev := newFakeEgress()
	m.SetEgress(dev)
	var packets [][]byte
	var want uint64
	for scope := range 16 {
		destination := netip.AddrFrom16([16]byte{0: 0xff, 1: byte(scope), 15: 1})
		packets = append(packets, plainV6(segAddr("3fff:a::1"), destination, "multicast"))
		if scope > 2 {
			want++
		}
	}
	ipv4 := plainV6(segAddr("3fff:a::1"), segAddr("ff02::16"), "ipv4")
	ipv4[0] = 0x45
	packets = append(packets, ipv4, []byte{0x60})
	want += 2
	dev.reads <- scriptedRead{packets: packets}
	waitUntil(t, "the drain to count what it read", func() bool { return m.SegmentCounters().Drained >= want })
	// a read of one packet that counts shows the drain has finished the read before it
	dev.reads <- scriptedRead{packets: [][]byte{plainV6(segAddr("3fff:a::1"), segAddr("2001:db8::1"), "unicast")}}
	waitUntil(t, "the drain to count the unicast packet", func() bool { return m.SegmentCounters().Drained >= want+1 })
	if drained := m.SegmentCounters().Drained; drained != want+1 {
		t.Errorf("drained reads %d, want %d", drained, want+1)
	}
}

// Close marks the mesh closed before it waits for the egress slot, so a SetEgress the slot orders after Close's own installs nothing
func TestCloseMarksTheMeshClosedBeforeTheEgressSlot(t *testing.T) {
	m, _ := egressMesh(t)
	m.egressMu.Lock()
	returned := make(chan struct{})
	go func() { m.Close(); close(returned) }()
	select {
	case <-m.closed:
		m.egressMu.Unlock()
	case <-time.After(deliveryTimeout):
		m.egressMu.Unlock()
		t.Fatalf("Close did not mark the mesh closed in %s while the egress slot was held", deliveryTimeout)
	}
	select {
	case <-returned:
	case <-time.After(deliveryTimeout):
		t.Fatal("Close never returned")
	}
	late := newFakeEgress()
	m.SetEgress(late)
	if closes := late.closes.Load(); closes != 1 {
		t.Errorf("a device handed to a closed mesh was closed %d times, want once", closes)
	}
	if running := drains(); running != 0 {
		t.Errorf("a device handed to a closed mesh started %d drains", running)
	}
}

// failedReadWatch is how long the test below lets a drain meet a device that fails every read
const failedReadWatch = 3 * egressDrainRetry

// a device that fails every read is read again once each egressDrainRetry rather than spun on
func TestEgressDrainWaitsBetweenFailedReads(t *testing.T) {
	logLines(t)
	m, _ := egressMesh(t)
	dev := newFakeEgress()
	dev.readErr = errors.New("read failed")
	m.SetEgress(dev)
	time.Sleep(failedReadWatch)
	m.Close()
	if reads, most := dev.failed.Load(), int64(failedReadWatch/egressDrainRetry)+2; reads < 2 || reads > most {
		t.Errorf("the drain read a failing device %d times in %s, want from 2 to %d", reads, failedReadWatch, most)
	}
}

// retryWaitClose is the longest Close may take while the drain waits out egressDrainRetry
const retryWaitClose = egressDrainRetry / 2

// Close ends the drain's wait after a failed read at once rather than when the wait runs out
func TestCloseEndsTheDrainsWaitAfterAFailedRead(t *testing.T) {
	logLines(t)
	m, _ := egressMesh(t)
	dev := newFakeEgress()
	dev.readErr = errors.New("read failed")
	m.SetEgress(dev)
	waitUntil(t, "the drain to fail a read", func() bool { return dev.failed.Load() >= 1 })
	start := time.Now()
	m.Close()
	if took := time.Since(start); took > retryWaitClose {
		t.Errorf("Close took %s while the drain waited after a failed read, want at most %s", took, retryWaitClose)
	}
}

// sessions deliver egress results while the device is swapped again and again and the mesh closes
// every delivery returns, each device is closed exactly once, nothing outlives Close
// and every egress result is counted once, egressed as a device accepted it or not ready
func TestSetEgressRacingDeliveries(t *testing.T) {
	const sessions, deliveries, swaps = 4, 300, 20
	m, meshTUN := egressMesh(t)
	inner := plainV6(segAddr("3fff:a::1"), segAddr("2001:4860:4860::8888"), "payload")
	outer := steered(t, inner, headend, egressExit)
	devices := make([]*fakeEgress, swaps)
	devices[0] = newFakeEgress()
	m.SetEgress(devices[0])
	// each session delivers until the mesh has closed and then deliveries more, so deliveries run through every swap, Close and after it
	var closed atomic.Bool
	var batches atomic.Int64
	deliver := func() {
		m.DeliverInboundBatch(framed(outer, outer), DefaultMTU)
		batches.Add(1)
	}
	var delivering sync.WaitGroup
	for range sessions {
		delivering.Go(func() {
			for !closed.Load() {
				deliver()
			}
			for range deliveries {
				deliver()
			}
		})
	}
	waitUntil(t, "a delivery to reach the first device", func() bool { return m.SegmentCounters().Egressed > 0 })
	for i := 1; i < swaps; i++ {
		devices[i] = newFakeEgress()
		m.SetEgress(devices[i])
	}
	m.Close()
	closed.Store(true)
	returned := make(chan struct{})
	go func() { delivering.Wait(); close(returned) }()
	select {
	case <-returned:
	case <-time.After(deliveryTimeout):
		t.Fatal("a delivery never returned")
	}

	accepted := 0
	for i, dev := range devices {
		if closes := dev.closes.Load(); closes != 1 {
			t.Errorf("device %d was closed %d times, want once", i, closes)
		}
		for _, write := range dev.accepted() {
			accepted += len(write)
		}
	}
	counters, results := m.SegmentCounters(), 2*uint64(batches.Load())
	if counters.Egressed != uint64(accepted) || counters.Egressed+counters.NotReady != results || counters.Dropped != 0 {
		t.Errorf("%d egress results counted %+v with %d accepted, want each once as egressed or not ready", results, counters, accepted)
	}
	if writes := tunWrites(meshTUN); len(writes) != 0 {
		t.Errorf("egress results reached the mesh tun as %d writes", len(writes))
	}
	if running := drains(); running != 0 {
		t.Errorf("%d drains outlived Close", running)
	}
}
