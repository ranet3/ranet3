// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package netstack

import (
	"net/netip"
	"testing"
	"time"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// icmpModel is the limit as the kernel describes it, inet_peer_xrlim_allow's credit per source and icmp_global_allow's over the node
// a credit is earned in nanoseconds up to a burst and an answer spends one interval of it, a new source starting full
// the sources lie in 64 shards as icmpShardOf puts them, each holding the limit's share, and a full shard forgets its own least recent source
// found by walking that shard's draws in order and skipping each a source has made a later one since
type icmpModel struct {
	node    modelCredit
	sources map[netip.Addr]*modelSource
	shards  [64]modelShard
}

type modelCredit struct{ credit, last int64 }

type modelSource struct {
	credit modelCredit
	// latest is the index in its shard's draws of the source's latest draw
	latest int
}

type modelShard struct {
	draws  []netip.Addr
	oldest int
	held   int
}

// earn adds the time since last, up to most, now never before last
func (c *modelCredit) earn(now, most int64) {
	c.credit, c.last = min(most, c.credit+now-c.last), now
}

func newICMPModel() *icmpModel {
	return &icmpModel{node: modelCredit{credit: int64(time.Second)}, sources: map[netip.Addr]*modelSource{}}
}

// take is the model's verdict on an answer to a packet from source, the zero Addr for packet too big and fragmentation needed
func (m *icmpModel) take(now int64, source netip.Addr) icmpVerdict {
	// 10000 a second with a burst of 10000 is a second of credit at 100 microseconds an answer
	const nodeCost = int64(100 * time.Microsecond)
	m.node.earn(now, int64(time.Second))
	if m.node.credit < nodeCost {
		return icmpByNode
	}
	if source.IsValid() {
		interval := int64(100 * time.Millisecond)
		if source.Is4() {
			interval = int64(time.Second)
		}
		shard := &m.shards[icmpShardOf(source)]
		entry := m.sources[source]
		if entry == nil {
			if shard.held == icmpSources/icmpShards {
				m.evict(shard)
			}
			entry = &modelSource{credit: modelCredit{credit: 6 * interval, last: now}}
			m.sources[source] = entry
			shard.held++
		}
		entry.latest = len(shard.draws)
		shard.draws = append(shard.draws, source)
		entry.credit.earn(now, 6*interval)
		if entry.credit.credit < interval {
			return icmpBySource
		}
		entry.credit.credit -= interval
	}
	m.node.credit -= nodeCost
	return icmpAllowed
}

// evict forgets the source of shard whose latest draw is the oldest
func (m *icmpModel) evict(shard *modelShard) {
	for ; ; shard.oldest++ {
		source := shard.draws[shard.oldest]
		if entry := m.sources[source]; entry != nil && entry.latest == shard.oldest {
			delete(m.sources, source)
			shard.held--
			shard.oldest++
			return
		}
	}
}

// icmpStep is one instant of a drawn run: count answers to packets from one source of icmpPool, after one answer each from spray sources never seen before
// a homed spray draws only the fresh sources lying in the shard of the step's source, and no too-big answer
type icmpStep struct {
	at     int64
	source int
	tooBig bool
	count  int
	spray  int
	homed  bool
}

// icmpPool is the sources a run's steps draw from, IPv4 and IPv6 in turn
var icmpPool = []netip.Addr{
	segAddr("10.0.1.2"), segAddr("2001:db8:1::2"), segAddr("10.0.1.3"), segAddr("2001:db8:1::3"),
	segAddr("192.0.2.1"), segAddr("2001:db8:2::1"), segAddr("198.51.100.7"), segAddr("3fff::7"),
}

// runICMPSteps hands each step's answers to take and reports each verdict in order
// a too-big answer is handed the zero Addr, as its callers draw it
func runICMPSteps(steps []icmpStep, take func(now int64, source netip.Addr) bool) []bool {
	var verdicts []bool
	fresh := 0
	for _, step := range steps {
		home := icmpShardOf(icmpPool[step.source])
		for range step.spray {
			source := freshSource(fresh)
			switch {
			case step.homed:
				for icmpShardOf(source) != home {
					fresh++
					source = freshSource(fresh)
				}
			case fresh%3 == 0:
				source = netip.Addr{}
			}
			verdicts = append(verdicts, take(step.at, source))
			fresh++
		}
		for range step.count {
			source := icmpPool[step.source]
			if step.tooBig {
				source = netip.Addr{}
			}
			verdicts = append(verdicts, take(step.at, source))
		}
	}
	return verdicts
}

// drawn runs of answers of drawn kinds from drawn sources, at drawn instants on a fake clock, get the model's verdicts, each naming the limit that withheld it
// and each shard holds as many sources as the model's, every source of it that has drawn from a bucket up to the limit's share, in the order of their latest draws
// and three statements hold that need no model
// over any span of instants the answers let out number at most the cap's burst and what the span earns it
// with no spray step, which keeps the cap from withholding and every source in the table, one source's answers get the same verdicts with every other source's answers taken out of the run
// and the answers other than packet too big and fragmentation needed the same verdicts with those taken out, while every too-big answer goes out
// a source that draws between two sprays, which keeps its place only by the draw moving it to the front, is tried before anything is drawn
// and so are a source drawing last before its shard fills, and a cap spent at one instant, which the drawn runs reach only now and then
func TestICMPLimitMatchesTheKernelsModel(t *testing.T) {
	// the first spray puts 24 sources in icmpPool[0]'s shard of 96 and the second 73 more, so 2 places go, the first spray's least recent
	// which but for icmpPool[0]'s draw between the sprays would be its own
	checkICMPSteps(t, []icmpStep{
		{source: 0, count: 3},
		{spray: 24, homed: true},
		{source: 0, count: 1},
		{spray: 73, homed: true},
		{source: 0, count: 3},
	}, true)
	// a spray leaving 95 sources in icmpPool[0]'s shard, so it is the newest of 96 when 3 more new sources take the least recent places, and it keeps what it spent
	checkICMPSteps(t, []icmpStep{
		{spray: 95, homed: true},
		{source: 0, count: 1},
		{spray: 3, homed: true},
		{source: 0, count: 6},
	}, true)
	// a spray spending the cap at one instant, then a source's answer the cap withholds before that source's bucket is read
	// an answer a nanosecond before the cap earns its next token and one at that instant, and the source's whole burst once the cap holds it
	checkICMPSteps(t, []icmpStep{
		{spray: 10000, source: 2, count: 1},
		{at: int64(100*time.Microsecond) - 1, source: 3, count: 1},
		{at: int64(100 * time.Microsecond), source: 3, count: 1},
		{at: int64(800 * time.Microsecond), source: 2, count: 6},
	}, true)
	pbt.Check(t, func(ht *hegel.T) {
		steps := make([]icmpStep, hegel.Draw(ht, pbt.Spanning(1, 24)))
		sprayed := false
		var now int64
		for i := range steps {
			// whole intervals and a nanosecond either side meet each bucket's edges
			now += max(0, int64(hegel.Draw(ht, pbt.Spanning(0, 20)))*int64(100*time.Millisecond)+int64(hegel.Draw(ht, pbt.Spanning(-1, 1))))
			if hegel.Draw(ht, pbt.Spanning(0, 3)) == 0 {
				now += int64(hegel.Draw(ht, pbt.Spanning(0, int(2*time.Second))))
			}
			steps[i] = icmpStep{
				at:     now,
				source: hegel.Draw(ht, pbt.Spanning(0, len(icmpPool)-1)),
				tooBig: hegel.Draw(ht, pbt.Spanning(0, 3)) == 0,
				count:  hegel.Draw(ht, pbt.Spanning(0, 20)),
			}
			if hegel.Draw(ht, pbt.Spanning(0, 15)) == 0 {
				steps[i].spray = hegel.Draw(ht, pbt.Spanning(1, 10500))
				sprayed = true
			}
		}
		checkICMPSteps(ht, steps, sprayed)
	})
}

// checkICMPSteps runs steps on a fresh limit beside the model and holds them to the statements above
// sprayed leaves out the two that need a cap withholding nothing and every source kept in the table
func checkICMPSteps(tb testing.TB, steps []icmpStep, sprayed bool) {
	tb.Helper()
	// offsets[i] is where the verdicts of step i start
	offsets := make([]int, len(steps)+1)
	for i, step := range steps {
		offsets[i+1] = offsets[i] + step.spray + step.count
	}

	var l icmpLimit
	model := newICMPModel()
	answer := 0
	verdicts := runICMPSteps(steps, func(now int64, source netip.Addr) bool {
		got, want := l.take(now, source), model.take(now, source)
		if got != want {
			tb.Fatalf("answer %d to %s at %d was decided %d, the model says %d", answer, source, now, got, want)
		}
		// the model holds every source of a shard that drew from a bucket up to the limit's share, so a shard of another size or a table evicting across shards fails against it
		// and the drawn source's shard lists the sources the model holds there, from the latest draw to the least recent
		// so a draw the cap withheld that kept its source or moved a held one forward fails at once
		if source.IsValid() {
			shard, home := l.shard(source), icmpShardOf(source)
			if got, want := len(shard.sources), model.shards[home].held; got != want || shard.order.Len() != want {
				tb.Fatalf("after answer %d the shard of %s holds %d sources in a list of %d, want the model's %d", answer, source, got, shard.order.Len(), want)
			}
			latest := len(model.shards[home].draws)
			for element := shard.order.Front(); element != nil; element = element.Next() {
				held := element.Value.(*icmpSource).addr
				entry := model.sources[held]
				if entry == nil || icmpShardOf(held) != home || entry.latest >= latest {
					tb.Fatalf("after answer %d the shard of %s lists %s out of the model's order", answer, source, held)
				}
				latest = entry.latest
			}
		}
		answer++
		return got == icmpAllowed
	})
	if got, want := held(tb, &l), len(model.sources); got != want {
		tb.Fatalf("the table holds %d sources after the run, want the model's %d", got, want)
	}

	for i := range steps {
		let := int64(0)
		for j := i; j < len(steps); j++ {
			for _, out := range verdicts[offsets[j]:offsets[j+1]] {
				if out {
					let++
				}
			}
			if most := 10000 + (steps[j].at-steps[i].at)/int64(100*time.Microsecond); let > most {
				tb.Fatalf("%d answers went out from %d to %d nanoseconds, past the cap's %d", let, steps[i].at, steps[j].at, most)
			}
		}
	}

	if sprayed {
		return
	}
	// rerun replays the steps keep holds on a fresh limit and compares each verdict with the one it got in the whole run
	rerun := func(keep func(icmpStep) bool, what string) {
		var kept []icmpStep
		var want []bool
		for i, step := range steps {
			if keep(step) {
				kept = append(kept, step)
				want = append(want, verdicts[offsets[i]:offsets[i+1]]...)
			}
		}
		var fresh icmpLimit
		replay := func(now int64, source netip.Addr) bool { return fresh.take(now, source) == icmpAllowed }
		for k, got := range runICMPSteps(kept, replay) {
			if got != want[k] {
				tb.Fatalf("answer %d was let out %t %s and %t in the whole run", k, got, what, want[k])
			}
		}
	}
	for source, addr := range icmpPool {
		rerun(func(step icmpStep) bool { return step.source == source }, "of "+addr.String()+"'s answers alone")
	}
	rerun(func(step icmpStep) bool { return !step.tooBig }, "with the too-big answers taken out")
	for i, step := range steps {
		for _, out := range verdicts[offsets[i]:offsets[i+1]] {
			if step.tooBig && !out {
				tb.Fatalf("a too-big answer of step %d to %s was withheld while the cap withheld nothing", i, icmpPool[step.source])
			}
		}
	}
}
