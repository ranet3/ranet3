// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"encoding/binary"
	"log/slog"
	"math"
	"math/bits"
	"math/rand/v2"
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

// capSpentWait is how long decidedUnderLock waits for draws on a spent cap while it holds every shard's lock
const capSpentWait = 5 * time.Second

// warmDrawRuns is how many times TestWarmDrawAllocatesNothing makes its draws
const warmDrawRuns = 100

// spreadSeeds is how many seeds TestSequentialSourcesSpreadOverTheShardsUnderEachSeed draws from its generator
const spreadSeeds = 4096

// freshSource is the i-th of a run of addresses no other test draws from, IPv6 for an even i and IPv4 for an odd one
func freshSource(i int) netip.Addr {
	if i%2 == 1 {
		return netip.AddrFrom4([4]byte{10, 200, byte(i >> 9), byte(i >> 1)})
	}
	return netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0xff, 12: byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)})
}

// icmpShardOf is the shard the table's rule puts source in, of 64
// the high half of its 16-byte form XORed with the seed's first word goes through splitmix64's finish, the low half and the second word are XORed in,
// and the top bits of that word's finish pick the shard
func icmpShardOf(source netip.Addr) int {
	finish := func(z uint64) uint64 {
		z = (z ^ z>>30) * 0xbf58476d1ce4e5b9
		z = (z ^ z>>27) * 0x94d049bb133111eb
		return z ^ z>>31
	}
	address := source.As16()
	return int(finish(finish(binary.BigEndian.Uint64(address[:8])^icmpSeed[0])^binary.BigEndian.Uint64(address[8:])^icmpSeed[1]) >> 58)
}

// sequentialSources is count addresses from first on, each the one before it plus one
func sequentialSources(first netip.Addr, count int) []netip.Addr {
	sources := make([]netip.Addr, 0, count)
	for source := first; len(sources) < count; source = source.Next() {
		sources = append(sources, source)
	}
	return sources
}

// sourcesOfShard is the first count fresh sources from the from-th on that lie in shard
func sourcesOfShard(shard, from, count int) []netip.Addr {
	var out []netip.Addr
	for i := from; len(out) < count; i++ {
		if source := freshSource(i); icmpShardOf(source) == shard {
			out = append(out, source)
		}
	}
	return out
}

// held is how many sources the limit's shards hold, failing unless each shard's order lists as many as its map
func held(tb testing.TB, l *icmpLimit) int {
	tb.Helper()
	total := 0
	for i := range l.shards {
		if got, listed := len(l.shards[i].sources), l.shards[i].order.Len(); got != listed {
			tb.Fatalf("shard %d holds %d sources in a list of %d", i, got, listed)
		}
		total += len(l.shards[i].sources)
	}
	return total
}

// decided is how many of a run of answers the limit let out and how many each of its limits withheld
type decided struct{ allowed, bySource, byNode int }

func (d *decided) count(verdict icmpVerdict) {
	switch verdict {
	case icmpAllowed:
		d.allowed++
	case icmpBySource:
		d.bySource++
	case icmpByNode:
		d.byNode++
	}
}

// draws counts the limit's decisions on count answers to packets from source at now, the zero Addr drawing as packet too big
func draws(l *icmpLimit, now time.Duration, source netip.Addr, count int) decided {
	var got decided
	for range count {
		got.count(l.take(int64(now), source))
	}
	return got
}

// spendCap counts the limit's decisions on count answers at now, one to each fresh IPv6 source from the from-th on, so the node's cap alone can withhold them
func spendCap(l *icmpLimit, now time.Duration, from, count int) decided {
	var got decided
	for i := range count {
		got.count(l.take(int64(now), freshSource(2*(from+i))))
	}
	return got
}

// spendCapBeside is spendCap with the fresh sources lying in the shard of kept left out, so its draws evict no source of that shard
func spendCapBeside(l *icmpLimit, now time.Duration, kept netip.Addr, from, count int) decided {
	var got decided
	for i := from; count > 0; i++ {
		if source := freshSource(2 * i); icmpShardOf(source) != icmpShardOf(kept) {
			got.count(l.take(int64(now), source))
			count--
		}
	}
	return got
}

// capHolding leaves the node's cap of m holding left answers, which it earns no more of for an hour of the mesh's clock
// a draw before the cap's last draw is judged as of that one
func capHolding(m *Mesh, left int) {
	last := int64(time.Since(m.segmentsStarted) + time.Hour)
	m.icmpLimit.node.last.Store(last)
	m.icmpLimit.node.full.Store(last + (icmpNodeBurst-int64(left))*int64(icmpNodeCost))
}

// untouched fails unless the limit of m was never drawn from and counted nothing withheld
func untouched(tb testing.TB, m *Mesh) {
	tb.Helper()
	if source, node := m.ICMPWithheld(); source != 0 || node != 0 {
		tb.Errorf("the limits withheld %d answers by source and %d by the node's cap, want none", source, node)
	}
	if full, sources := m.icmpLimit.node.full.Load(), held(tb, &m.icmpLimit); full != 0 || m.icmpLimit.node.last.Load() != 0 || sources != 0 {
		tb.Errorf("the cap is full again at %d and the table holds %d sources, want the limit untouched", full, sources)
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
// packet too big and fragmentation needed, which draw on no limit, go out after it, as the kernel answered them while another source flooded
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

// the cap holds every answer of either family to a source to 10000 at once and 10000 a second after, the kernel's icmp_msgs_burst and icmp_msgs_per_sec
// an answer it withholds costs its source's bucket nothing, since the kernel reads the cap before the source
func TestNodeCapBoundsEveryAnswer(t *testing.T) {
	var l icmpLimit
	kept := segAddr("10.9.0.1")
	if got := draws(&l, 0, kept, 5); got.allowed != 5 {
		t.Fatalf("a fresh source drew %d of 5 answers, want every one", got.allowed)
	}
	if got := spendCapBeside(&l, 0, kept, 0, 9995); got.allowed != 9995 {
		t.Fatalf("the cap let %d of the 9995 answers left of its burst out, want every one", got.allowed)
	}
	for _, source := range []netip.Addr{kept, freshSource(1)} {
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
	if got := spendCapBeside(&l, time.Millisecond, kept, 20000, 20); got != (decided{allowed: 9, byNode: 11}) {
		t.Errorf("of 20 answers 900 microseconds after the cap was last spent %+v, want 9 let out and 11 withheld by the cap", got)
	}
	total := 0
	for i := range 10001 {
		total += draws(&l, time.Hour, freshSource(i), 1).allowed
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

// decidedUnderLock makes the draws in turn on another goroutine while this one holds every shard's lock, and returns what each was decided
// a draw the cap does not withhold first waits for its shard's lock, so draws still waiting after capSpentWait fail the test
func decidedUnderLock(t *testing.T, l *icmpLimit, held ...heldDraw) []icmpVerdict {
	t.Helper()
	returned := make(chan []icmpVerdict, 1)
	for i := range l.shards {
		l.shards[i].mu.Lock()
	}
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
	for i := range l.shards {
		l.shards[i].mu.Unlock()
	}
	if waited {
		got = <-returned
		t.Errorf("draws on a spent cap were still waiting for a shard's lock after %s", capSpentWait)
	}
	return got
}

// once the cap is spent, a source's draw before it earns its next token comes back withheld by it while another goroutine holds every shard's lock
// a too-big draw there comes back let out, since no limit holds it back, and a draw at the instant the cap earns that token lets one answer out
func TestSpentCapWithholdsWithoutTheLock(t *testing.T) {
	var l icmpLimit
	at, cost := time.Hour, icmpNodeCost
	if got := spendCap(&l, at, 0, icmpNodeBurst+1); got != (decided{allowed: icmpNodeBurst, byNode: 1}) {
		t.Fatalf("of the cap's burst and one more answer %+v, want the burst let out and 1 withheld by the cap", got)
	}
	if got := decidedUnderLock(t, &l, heldDraw{at + cost - 1, freshSource(1)}, heldDraw{at, netip.Addr{}}); !slices.Equal(got, []icmpVerdict{icmpByNode, icmpAllowed}) {
		t.Errorf("a source's answer and a too-big answer on a spent cap were decided %v, want the first withheld by the cap and the second let out", got)
	}
	if got := l.take(int64(at+cost), freshSource(1)); got != icmpAllowed {
		t.Errorf("the source's answer at the instant the cap earned a token was decided %d, want let out", got)
	}
}

// a draw on a spent cap whose clock reading trails the cap's last answer is judged as of that answer, not its own reading
// so a draw at the cap's last instant, before its next token, is withheld without the lock as one after a leading draw is
func TestTrailingDrawOnASpentCapIsJudgedAsOfItsLastAnswer(t *testing.T) {
	var l icmpLimit
	at, cost := time.Hour, icmpNodeCost
	if got := spendCap(&l, at, 0, icmpNodeBurst); got != (decided{allowed: icmpNodeBurst}) {
		t.Fatalf("of the cap's burst %+v, want every answer let out", got)
	}
	// the last token went at at, and a draw that read the clock 10 tokens' time earlier reaches the cap only now
	if got := l.take(int64(at-10*cost), freshSource(1)); got != icmpByNode {
		t.Fatalf("the trailing draw on a spent cap was decided %d, want withheld by the cap", got)
	}
	if got := decidedUnderLock(t, &l, heldDraw{at, freshSource(3)}); !slices.Equal(got, []icmpVerdict{icmpByNode}) {
		t.Errorf("a draw at the instant the cap spent its last token was decided %v, want withheld by the cap", got)
	}
}

// every draw reads the cap and writes its shard, its lock, its table and its counts
// 120 bytes no other field takes lie on each side of the cap and after each shard's fields, a 128-byte line less the 8 bytes a word is aligned to
// so the cap shares no line of 64 or 128 bytes with a shard or another field, and no shard one with another, wherever the allocator puts the Mesh
func TestCapAndShardsSitOnLinesOfTheirOwn(t *testing.T) {
	var c segmentCounters
	var s icmpShard
	limit := unsafe.Offsetof(c.icmpLimit)
	node := limit + unsafe.Offsetof(c.icmpLimit.node)
	shards := limit + unsafe.Offsetof(c.icmpLimit.shards)
	used := unsafe.Offsetof(s.withheld) + unsafe.Sizeof(s.withheld)
	last := shards + (icmpShards-1)*unsafe.Sizeof(s)
	for _, gap := range []struct {
		before, after string
		end, start    uintptr
	}{
		{"segmentsNotReady", "the cap", unsafe.Offsetof(c.segmentsNotReady) + unsafe.Sizeof(c.segmentsNotReady), node},
		{"the cap", "the first shard", node + unsafe.Sizeof(c.icmpLimit.node), shards},
		{"a shard's counts", "the next shard", shards + used, shards + unsafe.Sizeof(s)},
		{"the last shard's counts", "withheldBySource", last + used, unsafe.Offsetof(c.withheldBySource)},
	} {
		if gap.start < gap.end+120 {
			t.Errorf("%d bytes lie between %s and %s, want 120 or more", gap.start-gap.end, gap.before, gap.after)
		}
	}
}

// draws from many goroutines at one instant let the cap's burst out and no more, whether a draw spends the cap or meets it spent
func TestCapLetsItsBurstOutToConcurrentDraws(t *testing.T) {
	const goroutines, each = 16, 1000
	var l icmpLimit
	var allowed, byNode atomic.Int64
	var wg sync.WaitGroup
	for g := range goroutines {
		wg.Go(func() {
			for i := range each {
				switch l.take(int64(time.Hour), freshSource(2*(g*each+i))) {
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

// at a reading near the end of the clock, as a mesh with no segmentsStarted reads, the cap lets its burst out at one instant and no more
// so neither its check nor its spend carries a sum past the end
func TestCapHoldsItsBurstAtTheClocksEnd(t *testing.T) {
	var l icmpLimit
	end := time.Duration(math.MaxInt64)
	if got := spendCap(&l, end, 0, icmpNodeBurst+1); got.allowed != icmpNodeBurst || got.byNode != 1 {
		t.Errorf("of %d draws at the clock's end %d were let out and %d withheld by the cap, want %d and 1", icmpNodeBurst+1, got.allowed, got.byNode, icmpNodeBurst)
	}
}

// emitters drawing at one instant, each for sources of its own and for too-big answers, let out the cap's burst of the sources' answers and not one more, and every too-big answer
// every draw is let out or withheld once, and ICMPWithheld sums what each limit withheld over every shard
// a source's bucket has spent its answers let out and nothing more, and one whose every draw the cap withheld is not in the table
// since a draw the cap withholds spends nothing of its source and leaves the table as it found it
func TestConcurrentDrawsKeepTheCapExactAndTheBucketsTheirOwn(t *testing.T) {
	const emitters, sourcesEach, drawsEach, tooBigEach = 16, 128, 10, 500
	type tally struct{ allowed, bySource, byNode int }
	m := &Mesh{Routes: NewRouteTable()}
	at := int64(time.Hour)
	tallies := make([][sourcesEach]tally, emitters)
	tooBig := make([]tally, emitters)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for e := range emitters {
		wg.Go(func() {
			<-start
			count := func(t *tally, verdict icmpVerdict) {
				switch verdict {
				case icmpAllowed:
					t.allowed++
				case icmpBySource:
					t.bySource++
				case icmpByNode:
					t.byNode++
				}
			}
			for step := range drawsEach * sourcesEach {
				k := step % sourcesEach
				count(&tallies[e][k], m.icmpLimit.take(at, freshSource(e*sourcesEach+k)))
				if step < tooBigEach {
					count(&tooBig[e], m.icmpLimit.take(at, netip.Addr{}))
				}
			}
		})
	}
	close(start)
	wg.Wait()
	var allowed, bySource, byNode int
	for e := range emitters {
		if tooBig[e] != (tally{allowed: tooBigEach}) {
			t.Errorf("emitter %d's too-big answers were decided %+v, want all %d let out", e, tooBig[e], tooBigEach)
		}
		for k, got := range tallies[e] {
			source := freshSource(e*sourcesEach + k)
			allowed, bySource, byNode = allowed+got.allowed, bySource+got.bySource, byNode+got.byNode
			if got.allowed+got.bySource+got.byNode != drawsEach || got.allowed > icmpSourceBurst || got.bySource > 0 && got.allowed != icmpSourceBurst {
				t.Errorf("%s drew %+v of %d answers, want at most %d let out and its bucket withholding only once they were", source, got, drawsEach, icmpSourceBurst)
			}
			interval := int64(icmpSourceInterval6)
			if source.Is4() {
				interval = int64(icmpSourceInterval4)
			}
			element := m.icmpLimit.shard(source).sources[source]
			switch {
			case got.allowed+got.bySource == 0 && element != nil:
				t.Errorf("%s is in the table, though the cap withheld its every draw", source)
			case got.allowed+got.bySource != 0 && element == nil:
				t.Errorf("%s is not in the table after %d draws its bucket decided", source, got.allowed+got.bySource)
			case element != nil:
				if spent := element.Value.(*icmpSource).bucket.spent; spent != int64(got.allowed)*interval {
					t.Errorf("%s's bucket spent %d nanoseconds for %d answers let out, want %d", source, spent, got.allowed, int64(got.allowed)*interval)
				}
			}
		}
	}
	if allowed != icmpNodeBurst {
		t.Errorf("%d answers to sources went out at one instant, want the cap's %d", allowed, icmpNodeBurst)
	}
	if source, node := m.ICMPWithheld(); source != uint64(bySource) || node != uint64(byNode) {
		t.Errorf("ICMPWithheld reads %d by source and %d by the cap, want the %d and %d the draws were decided", source, node, bySource, byNode)
	}
}

// a draw on a warm table, for a source it holds or for a too-big answer, let out or withheld, allocates nothing
func TestWarmDrawAllocatesNothing(t *testing.T) {
	var l icmpLimit
	v4, v6 := freshSource(1), freshSource(2)
	draws(&l, 0, v4, 1)
	draws(&l, 0, v6, 1)
	now := time.Duration(0)
	if allocs := testing.AllocsPerRun(warmDrawRuns, func() {
		now += time.Microsecond
		draws(&l, now, v4, 3)
		draws(&l, now, v6, 3)
		draws(&l, now, netip.Addr{}, 1)
	}); allocs != 0 {
		t.Errorf("a run of draws on a warm table allocated %.1f times, want none", allocs)
	}
}

// each shard holds at most its share of the sources, 96, and gives the place of its own source that drew least recently, which returns full like a new one
// a source that drew since keeps its place and what it spent, and a source of another shard keeps its place however long ago it drew
func TestICMPLimitShardEvictsItsLeastRecentSource(t *testing.T) {
	const share = 96
	var l icmpLimit
	first := freshSource(0)
	in := sourcesOfShard((icmpShardOf(first)+1)%64, 1, share+1)
	shard := l.shard(in[0])
	draws(&l, 0, first, 1)
	for _, source := range in[:share] {
		draws(&l, 0, source, 1)
	}
	draws(&l, 0, in[0], 1)
	draws(&l, 0, in[share], 1)
	if got := len(shard.sources); got != share || shard.order.Len() != share {
		t.Fatalf("the shard holds %d sources in a list of %d, want %d", got, shard.order.Len(), share)
	}
	if _, ok := shard.sources[in[1]]; ok {
		t.Fatal("the shard kept its source that drew least recently")
	}
	if _, ok := l.shard(first).sources[first]; !ok {
		t.Fatal("a source of another shard gave its place to one of a full shard")
	}
	for _, c := range []struct {
		source netip.Addr
		left   int
	}{
		{in[2], 5},
		{in[0], 4},
		{in[share], 5},
		{in[1], 6},
		{first, 5},
	} {
		if got := draws(&l, 0, c.source, 7); got.allowed != c.left {
			t.Errorf("%s drew %d answers, want %d", c.source, got.allowed, c.left)
		}
	}
	for i := share + 1; i < share+1+5000; i++ {
		draws(&l, time.Nanosecond, freshSource(i), 1)
	}
	for i := range l.shards {
		if got := len(l.shards[i].sources); got > share {
			t.Errorf("shard %d holds %d sources after 5000 more, want %d at most", i, got, share)
		}
	}
	if got := held(t, &l); got > icmpSources {
		t.Errorf("the table holds %d sources, want %d at most", got, icmpSources)
	}
}

// 1024 sequential IPv4 sources, 1024 sequential IPv6 sources of one /64, the 2048 TestConcurrentDrawsKeepTheCapExactAndTheBucketsTheirOwn draws for,
// and 1024 IPv6 sources whose two halves step together, each put no more in any shard than 8 square roots of the mean past the mean,
// below a shard's 96, under every seed of the run
// a pick at random puts more than that in one shard less often than once in 10^10 shards
// the seeds are 4096 a generator of a fixed seed draws, and those whose first word, alone or XORed with the /64's high half, is p/q of 2^64 for a q up to 16
// those words are the steps at which a mix linear in the low half crowds each sequential run onto q shards or fewer
// and a mix that joined the halves before its first finish would put the last run in one shard under every seed
func TestSequentialSourcesSpreadOverTheShardsUnderEachSeed(t *testing.T) {
	v4, v6 := netip.MustParseAddr("198.18.0.0"), netip.MustParseAddr("2001:db8:1::")
	concurrent := make([]netip.Addr, 2048)
	for i := range concurrent {
		concurrent[i] = freshSource(i)
	}
	together := make([]netip.Addr, 1024)
	for j := range together {
		var address [16]byte
		binary.BigEndian.PutUint64(address[:8], 0x20010db800020000|uint64(j))
		binary.BigEndian.PutUint64(address[8:], uint64(j))
		together[j] = netip.AddrFrom16(address)
	}
	runs := []struct {
		name    string
		sources []netip.Addr
	}{
		{"1024 sequential IPv4 sources", sequentialSources(v4, 1024)},
		{"1024 sequential IPv6 sources of one /64", sequentialSources(v6, 1024)},
		{"2048 sources of the concurrent draws", concurrent},
		{"1024 IPv6 sources whose halves step together", together},
	}
	draw := rand.New(rand.NewPCG(65, 1024))
	seeds := make([][2]uint64, 0, spreadSeeds+2*120)
	for range spreadSeeds {
		seeds = append(seeds, [2]uint64{draw.Uint64(), draw.Uint64()})
	}
	high := v6.As16()
	for q := uint64(2); q <= 16; q++ {
		for p := uint64(1); p < q; p++ {
			step, _ := bits.Div64(p, 0, q)
			seeds = append(seeds, [2]uint64{step, draw.Uint64()}, [2]uint64{step ^ binary.BigEndian.Uint64(high[:8]), draw.Uint64()})
		}
	}
	for _, run := range runs {
		mean := float64(len(run.sources)) / icmpShards
		bound := min(icmpSources/icmpShards, int(mean+8*math.Sqrt(mean)))
		worst, over := 0, 0
		for _, seed := range seeds {
			var counts [icmpShards]int
			for _, source := range run.sources {
				counts[icmpShardIndex(seed, source)]++
			}
			most := slices.Max(counts[:])
			worst = max(worst, most)
			if most > bound {
				over++
				if over <= 5 {
					t.Errorf("under seed %016x %016x the %s put %d in one shard, want at most %d", seed[0], seed[1], run.name, most, bound)
				}
			}
		}
		if over > 5 {
			t.Errorf("the %s crowded a shard under %d more seeds", run.name, over-5)
		}
		t.Logf("the %s put at most %d in one shard under %d seeds, against a mean of %.0f and a bound of %d", run.name, worst, len(seeds), mean, bound)
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
		// every fourth draw is a too-big answer, which no limit holds back
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
