// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"ranet3.com/pkgs/ranet3/internal/events"
)

// icmpRaceSources and icmpRaceDraws are the sources and the draws of each that TestICMPLimitTakesConcurrentAnswers runs
const (
	icmpRaceSources = 64
	icmpRaceDraws   = 200
)

// capSpentWait is how long decidedUnderLock waits for draws on a spent cap while it holds the limit's lock
const capSpentWait = 5 * time.Second

// freshSource is the i-th of a run of addresses no other test draws from, IPv6 for an even i and IPv4 for an odd one
func freshSource(i int) netip.Addr {
	if i%2 == 1 {
		return netip.AddrFrom4([4]byte{10, 200, byte(i >> 9), byte(i >> 1)})
	}
	return netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0xff, 12: byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)})
}

// decided is how many of a run of answers the limit let out and how many each of its limits withheld
type decided struct{ allowed, bySource, byNode int }

// draws counts the limit's decisions on count answers to packets from source at now, the zero Addr drawing as packet too big
func draws(l *icmpLimit, now time.Duration, source netip.Addr, count int) decided {
	var got decided
	for range count {
		switch l.take(int64(now), source) {
		case icmpAllowed:
			got.allowed++
		case icmpBySource:
			got.bySource++
		case icmpByNode:
			got.byNode++
		}
	}
	return got
}

// capHolding leaves the node's cap of m holding left answers, which it earns no more of for an hour of the mesh's clock
// a draw before the cap's last draw is judged as of that one
func capHolding(m *Mesh, left int) {
	m.icmpLimit.node = icmpBucket{spent: (icmpNodeBurst - int64(left)) * int64(icmpNodeCost), last: int64(time.Since(m.segmentsStarted) + time.Hour)}
}

// untouched fails unless the limit of m was never drawn from and counted nothing withheld
func untouched(tb testing.TB, m *Mesh) {
	tb.Helper()
	if source, node := m.ICMPWithheld(); source != 0 || node != 0 {
		tb.Errorf("the limits withheld %d answers by source and %d by the node's cap, want none", source, node)
	}
	if m.icmpLimit.node != (icmpBucket{}) || len(m.icmpLimit.sources) != 0 {
		tb.Errorf("the cap spent %d nanoseconds of its burst and the table holds %d sources, want the limit untouched", m.icmpLimit.node.spent, len(m.icmpLimit.sources))
	}
}

// a fresh source draws 6 of 20 answers asked at once and then one an interval, 1 second for IPv4 and 100 milliseconds for IPv6, as the kernel answered on 7.2.10
// none comes a nanosecond before the interval is up, and its bucket alone withholds the rest
func TestFreshSourceDrawsTheKernelsBurstThenOneAnInterval(t *testing.T) {
	for _, c := range []struct {
		source   netip.Addr
		interval time.Duration
	}{
		{segAddr("10.0.1.4"), time.Second},
		{segAddr("2001:db8:1::4"), 100 * time.Millisecond},
	} {
		var l icmpLimit
		start := time.Hour
		if got := draws(&l, start, c.source, 20); got != (decided{allowed: 6, bySource: 14}) {
			t.Errorf("%s: of 20 answers asked at once %+v, want 6 let out and 14 withheld by its bucket", c.source, got)
		}
		for k := time.Duration(1); k <= 3; k++ {
			at := start + k*c.interval
			if got := draws(&l, at-1, c.source, 1); got != (decided{bySource: 1}) {
				t.Errorf("%s: of an answer a nanosecond before interval %d was up %+v, want it withheld by its bucket", c.source, k, got)
			}
			if got := draws(&l, at, c.source, 5); got != (decided{allowed: 1, bySource: 4}) {
				t.Errorf("%s: of 5 answers once interval %d was up %+v, want 1 let out and 4 withheld by its bucket", c.source, k, got)
			}
		}
	}
}

// a draw whose clock reading trails the last one's, as a caller that read the clock before waiting for the lock has, is judged as of the last
func TestICMPLimitJudgesATrailingDrawAsOfTheLast(t *testing.T) {
	var l icmpLimit
	source := segAddr("10.0.1.4")
	if got := draws(&l, time.Hour, source, 5); got.allowed != 5 {
		t.Fatalf("a fresh source drew %d of 5 answers, want every one", got.allowed)
	}
	if got := draws(&l, time.Hour-time.Microsecond, source, 2); got.allowed != 1 {
		t.Errorf("a source holding one answer drew %d of 2 asked a microsecond before its last draw, want 1", got.allowed)
	}
}

// one source's flood spends its own bucket, and a second source of either family draws its whole burst after it
// packet too big and fragmentation needed, which draw from no source's bucket, go out after it, as the kernel answered them while another source flooded
func TestOneSourcesFloodLeavesTheOthersAndPathMTU(t *testing.T) {
	var l icmpLimit
	flooder := segAddr("2001:db8:1::2")
	if got := draws(&l, 0, flooder, 400); got.allowed != 6 {
		t.Fatalf("a fresh source drew %d of 400 answers, want 6", got.allowed)
	}
	for _, other := range []netip.Addr{segAddr("2001:db8:1::3"), segAddr("10.0.1.3")} {
		if got := draws(&l, 0, other, 6); got.allowed != 6 {
			t.Errorf("%s drew %d of 6 answers after another source's flood, want every one", other, got.allowed)
		}
	}
	if got := draws(&l, 0, netip.Addr{}, 200); got.allowed != 200 {
		t.Errorf("%d of 200 too-big answers went out after a source's flood, want every one", got.allowed)
	}
}

// the cap holds every answer of either family and kind to 10000 at once and 10000 a second after, the kernel's icmp_msgs_burst and icmp_msgs_per_sec
// an answer it withholds costs its source's bucket nothing, since the kernel reads the cap before the source
func TestNodeCapBoundsEveryAnswer(t *testing.T) {
	var l icmpLimit
	kept := segAddr("10.9.0.1")
	if got := draws(&l, 0, kept, 5); got.allowed != 5 {
		t.Fatalf("a fresh source drew %d of 5 answers, want every one", got.allowed)
	}
	if got := draws(&l, 0, netip.Addr{}, 9995); got.allowed != 9995 {
		t.Fatalf("the cap let %d of the 9995 too-big answers left of its burst out, want every one", got.allowed)
	}
	// kept asks first, so its answer is the one the cap withholds under the lock, before a draw can find the cap spent without it
	for _, source := range []netip.Addr{kept, freshSource(0), {}} {
		if got := l.take(0, source); got != icmpByNode {
			t.Errorf("answer 10001, to %s, was decided %d, want withheld by the cap", source, got)
		}
	}
	// the cap earns one answer every 100 microseconds, and the source spends its last
	if got := l.take(int64(100*time.Microsecond), kept); got != icmpAllowed {
		t.Errorf("a source whose answer the cap withheld lost its last answer with it, decided %d", got)
	}
	if got := l.take(int64(200*time.Microsecond), kept); got != icmpBySource {
		t.Errorf("a source's seventh answer within a second was decided %d, want withheld by its bucket", got)
	}
	if got := draws(&l, time.Millisecond, netip.Addr{}, 20); got != (decided{allowed: 9, byNode: 11}) {
		t.Errorf("of 20 answers 900 microseconds after the cap was last spent %+v, want 9 let out and 11 withheld by the cap", got)
	}
	total := 0
	for i := range 10001 {
		source := freshSource(i)
		if i%3 == 0 {
			source = netip.Addr{}
		}
		total += draws(&l, time.Hour, source, 1).allowed
	}
	if total != 10000 {
		t.Errorf("a refilled cap let %d of 10001 answers out at once, want 10000", total)
	}
}

// heldDraw is one draw decidedUnderLock makes, at a reading of the limit's clock for a source
type heldDraw struct {
	at     time.Duration
	source netip.Addr
}

// decidedUnderLock makes the draws in turn on another goroutine while this one holds the limit's lock, and returns what each was decided
// a draw the early-out does not withhold waits for the lock, so draws still waiting after capSpentWait fail the test
func decidedUnderLock(t *testing.T, l *icmpLimit, held ...heldDraw) []icmpVerdict {
	t.Helper()
	returned := make(chan []icmpVerdict, 1)
	l.mu.Lock()
	go func() {
		got := make([]icmpVerdict, 0, len(held))
		for _, d := range held {
			got = append(got, l.take(int64(d.at), d.source))
		}
		returned <- got
	}()
	var got []icmpVerdict
	waited := false
	select {
	case got = <-returned:
	case <-time.After(capSpentWait):
		waited = true
	}
	l.mu.Unlock()
	if waited {
		got = <-returned
		t.Errorf("draws on a spent cap were still waiting for the limit's lock after %s", capSpentWait)
	}
	return got
}

// once the cap has withheld an answer, a draw of either kind before it earns its next token comes back withheld by it while another goroutine holds the limit's lock
// and a draw at the instant it earns that token lets one answer out
func TestSpentCapWithholdsWithoutTheLock(t *testing.T) {
	var l icmpLimit
	at, cost := time.Hour, icmpNodeCost
	if got := draws(&l, at, netip.Addr{}, icmpNodeBurst+1); got != (decided{allowed: icmpNodeBurst, byNode: 1}) {
		t.Fatalf("of the cap's burst and one more answer %+v, want the burst let out and 1 withheld by the cap", got)
	}
	if got := decidedUnderLock(t, &l, heldDraw{at, netip.Addr{}}, heldDraw{at + cost - 1, freshSource(1)}); !slices.Equal(got, []icmpVerdict{icmpByNode, icmpByNode}) {
		t.Errorf("a too-big answer and a source's answer on a spent cap were decided %v, want both withheld by the cap", got)
	}
	if got := l.take(int64(at+cost), freshSource(1)); got != icmpAllowed {
		t.Errorf("the source's answer at the instant the cap earned a token was decided %d, want let out", got)
	}
}

// a withheld draw whose clock reading trails the cap's last draw publishes the instant the cap next holds a token, not one taken from its own reading
// so a draw at the cap's last instant, before that token, is withheld without the lock as one after a leading draw is
func TestTrailingDrawPublishesTheCapsNextToken(t *testing.T) {
	var l icmpLimit
	at, cost := time.Hour, icmpNodeCost
	if got := draws(&l, at, netip.Addr{}, icmpNodeBurst); got != (decided{allowed: icmpNodeBurst}) {
		t.Fatalf("of the cap's burst %+v, want every answer let out", got)
	}
	// the last token went at at, and a draw that read the clock 10 tokens' time earlier reaches the lock only now
	if got := l.take(int64(at-10*cost), netip.Addr{}); got != icmpByNode {
		t.Fatalf("the trailing draw on a spent cap was decided %d, want withheld by the cap", got)
	}
	if got := decidedUnderLock(t, &l, heldDraw{at, netip.Addr{}}); !slices.Equal(got, []icmpVerdict{icmpByNode}) {
		t.Errorf("a draw at the instant the cap spent its last token was decided %v, want withheld by the cap", got)
	}
}

// every withheld draw reads spentUntil and segmentsStarted and adds to withheldBySource or withheldByNode
// 56 bytes no other field takes lie on each side of spentUntil and of each count, a 64-byte line less the 8 bytes a word is aligned to
// so none of them shares a line with another field wherever the allocator puts the Mesh
func TestWithheldCountsSitOnLinesOfTheirOwn(t *testing.T) {
	var c segmentCounters
	limit := unsafe.Offsetof(c.icmpLimit)
	spent := limit + unsafe.Offsetof(c.icmpLimit.spentUntil)
	for _, gap := range []struct {
		before, after string
		end, start    uintptr
	}{
		{"the limit's list", "spentUntil", limit + unsafe.Offsetof(c.icmpLimit.order) + unsafe.Sizeof(c.icmpLimit.order), spent},
		{"spentUntil", "withheldBySource", spent + unsafe.Sizeof(c.icmpLimit.spentUntil), unsafe.Offsetof(c.withheldBySource)},
		{"withheldBySource", "withheldByNode", unsafe.Offsetof(c.withheldBySource) + unsafe.Sizeof(c.withheldBySource), unsafe.Offsetof(c.withheldByNode)},
		{"withheldByNode", "segmentsStarted", unsafe.Offsetof(c.withheldByNode) + unsafe.Sizeof(c.withheldByNode), unsafe.Offsetof(c.segmentsStarted)},
	} {
		if gap.start < gap.end+56 {
			t.Errorf("%d bytes lie between %s and %s, want 56 or more", gap.start-gap.end, gap.before, gap.after)
		}
	}
}

// draws from many goroutines at one instant let the cap's burst out and no more, whether a draw takes the lock or meets the spent cap without it
func TestCapLetsItsBurstOutToConcurrentDraws(t *testing.T) {
	const goroutines, each = 16, 1000
	var l icmpLimit
	var allowed, byNode atomic.Int64
	var wg sync.WaitGroup
	for range goroutines {
		wg.Go(func() {
			for range each {
				switch l.take(int64(time.Hour), netip.Addr{}) {
				case icmpAllowed:
					allowed.Add(1)
				case icmpByNode:
					byNode.Add(1)
				}
			}
		})
	}
	wg.Wait()
	if allowed.Load() != icmpNodeBurst || byNode.Load() != goroutines*each-icmpNodeBurst {
		t.Errorf("of %d draws at once %d were let out and %d withheld by the cap, want %d and %d", goroutines*each, allowed.Load(), byNode.Load(), icmpNodeBurst, goroutines*each-icmpNodeBurst)
	}
}

// the table holds at most 4096 sources and gives the place of the one that drew least recently, which returns full like a new one
// a source that drew since keeps its place and what it spent
func TestICMPLimitTableEvictsTheLeastRecentSource(t *testing.T) {
	var l icmpLimit
	for i := range 4096 {
		draws(&l, 0, freshSource(i), 1)
	}
	draws(&l, 0, freshSource(0), 1)
	draws(&l, 0, freshSource(4096), 1)
	if got := len(l.sources); got != 4096 || l.order.Len() != 4096 {
		t.Fatalf("the table holds %d sources in a list of %d, want 4096", got, l.order.Len())
	}
	if _, ok := l.sources[freshSource(1)]; ok {
		t.Fatal("the table kept the source that drew least recently")
	}
	for _, c := range []struct {
		source int
		left   int
	}{
		{2, 5},
		{0, 4},
		{4096, 5},
		{1, 6},
	} {
		if got := draws(&l, 0, freshSource(c.source), 7); got.allowed != c.left {
			t.Errorf("source %d drew %d answers, want %d", c.source, got.allowed, c.left)
		}
	}
	for i := 4097; i < 4097+5000; i++ {
		draws(&l, time.Nanosecond, freshSource(i), 1)
	}
	if got := len(l.sources); got != 4096 || l.order.Len() != 4096 {
		t.Errorf("the table holds %d sources in a list of %d after 5000 more, want 4096", got, l.order.Len())
	}
}

// icmpEvents lists the netstack.icmp.withheld events recorded on bus, each as its interface, limit and count withheld
func icmpEvents(bus *events.Bus) [][3]string {
	var out [][3]string
	for _, event := range bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "netstack.icmp.withheld" }, 0) {
		out = append(out, [3]string{event.Attrs["interface"], event.Attrs["limit"], event.Attrs["withheld"]})
	}
	return out
}

// each limit that starts withholding records netstack.icmp.withheld on the mesh's interface at once, its limit named as the metric's label names it
// while it goes on withholding it records one every 30 seconds, with the answers it withheld since the one before
// the cap withholding alone, every source's bucket full, records the cap's event and counts nothing against a source
func TestWithheldAnswersRecordAnEventForEachLimit(t *testing.T) {
	bus := events.New()
	m := &Mesh{Name: "test0", Routes: NewRouteTable(), events: bus.Emit}
	m.startSegmentReports()
	flooder := segAddr("10.0.1.2")
	before := time.Since(m.segmentsStarted)
	for range 1000 {
		m.takeICMPToken(flooder)
	}
	after := time.Since(m.segmentsStarted)
	if got, want := icmpEvents(bus), [][3]string{{"test0", "source", "1"}}; !slices.Equal(got, want) {
		t.Fatalf("a source past its burst recorded %v, want %v for the first answer its bucket withheld", got, want)
	}
	if next := time.Duration(m.withheldBySource.next.Load()); next < before+30*time.Second || next > after+30*time.Second {
		t.Errorf("the source's next event is due %s after the draws began, want 30 seconds after its first", next-before)
	}
	m.withheldBySource.next.Add(-int64(reportInterval))
	m.takeICMPToken(flooder)
	capHolding(m, 0)
	for i := range 3 {
		m.takeICMPToken(freshSource(i))
	}
	want := [][3]string{{"test0", "source", "1"}, {"test0", "source", "994"}, {"test0", "node", "1"}}
	if got := icmpEvents(bus); !slices.Equal(got, want) {
		t.Errorf("once an interval passed and the cap was spent the events were %v, want %v", got, want)
	}
	if source, node := m.ICMPWithheld(); source != 995 || node != 3 {
		t.Errorf("the limits withheld %d answers by source and %d by the cap, want 995 and 3", source, node)
	}
}

// answers from many goroutines at once to many sources keep each limit, and every one is let out or counted withheld once
func TestICMPLimitTakesConcurrentAnswers(t *testing.T) {
	m := &Mesh{Routes: NewRouteTable()}
	m.startSegmentReports()
	allowed := make([]int, icmpRaceSources)
	var wg sync.WaitGroup
	for i := range icmpRaceSources {
		wg.Go(func() {
			for draw := range icmpRaceDraws {
				source := freshSource(i)
				if draw%4 == 0 {
					source = netip.Addr{}
				}
				if m.takeICMPToken(source) {
					allowed[i]++
				}
			}
		})
	}
	wg.Wait()
	elapsed := time.Since(m.segmentsStarted)
	total := 0
	for i, got := range allowed {
		total += got
		interval := 100 * time.Millisecond
		if i%2 == 1 {
			interval = time.Second
		}
		// every fourth draw is a too-big answer, which only the cap holds back
		least := icmpRaceDraws/4 + 6
		most := least + int(elapsed/interval)
		if got < least || got > most {
			t.Errorf("source %d drew %d of %d answers, want from %d to %d", i, got, icmpRaceDraws, least, most)
		}
	}
	source, node := m.ICMPWithheld()
	if uint64(total)+source+node != icmpRaceSources*icmpRaceDraws || node != 0 {
		t.Errorf("%d answers went out, %d were withheld by source and %d by the cap, of %d", total, source, node, icmpRaceSources*icmpRaceDraws)
	}
}
