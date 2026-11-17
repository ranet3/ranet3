// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package userspace

import (
	"math"
	"net/netip"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/codel"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/pbt"
)

const (
	// delaySteps bounds the steps of a drawn sequence over the link
	delaySteps = 40
	// largestPacket is the most bytes an IP packet's 16 bit length gives
	largestPacket = math.MaxUint16
)

// delayEnds are the source and destination of the packets a sequence queues:
// toward a session of each family that may carry an MTU, toward one of each
// that carries none, and with no network header
var delayEnds = [][2]netip.Addr{{server4, leaf4}, {server6, leaf6}, {server4, other4}, {server6, other6}, {}}

// delayStepKind names the action of one step of a sequence over the link
type delayStepKind int

const (
	// stepWrite queues a packet of size bytes between ends
	stepWrite delayStepKind = iota
	// stepFill queues a packet between ends sized to leave size bytes past the
	// largest session MTU behind the queue's head, the edge past which no
	// session's MTU changes the delay's answer. One packet reaches that edge
	// only so far: its size stays within largestPacket and at least a header
	// and its tag, so behind a short queue it may leave less and behind a long
	// one more, and into an empty queue it goes as the head with none behind.
	stepFill
	// stepWait moves the clock on by wait
	stepWait
	// stepTake takes the next packet the delay keeps and releases it, or finds
	// the queue empty
	stepTake
)

// delayStep is one step of a sequence over the link
type delayStep struct {
	kind delayStepKind
	ends [2]netip.Addr
	size int
	wait time.Duration
}

// checkDelaySideBySide fails tb where, over steps toward sessions whose MTUs
// are mtus and none for an address it leaves out, the link's delay answers
// otherwise than looking every session up at or over the target would, or the
// link looks a session up where no session's MTU can change the answer, or
// skips one where one can. It reports the packets dropped and those taken over
// the target without a lookup.
func checkDelaySideBySide(tb testing.TB, mtus map[netip.Addr]int, steps []delayStep) (drops, unasked int) {
	tb.Helper()
	largest := largestSessionMTU()
	l := newLink(1 << 30)
	defer l.Close()
	now := fakeClock(l)
	asked, seen := 0, 0
	l.mtu = func(_, destination netip.Addr) int {
		asked++
		return mtus[destination]
	}
	every := &link{mtu: func(_, destination netip.Addr) int { return mtus[destination] }}
	var model codel.Controller
	var modelDelayed uint64
	// queued is the sizes of the packets queued and not yet taken, oldest
	// first
	var queued []int
	observe := func(pkt *stack.PacketBuffer, sojourn time.Duration, dropped bool) {
		left := int(l.held.Load()) - pkt.Size()
		mtu := 0
		if sojourn >= codel.Target {
			mtu = every.sessionMTU(pkt)
		}
		want := model.Drop(*now, sojourn, left, mtu)
		if want {
			modelDelayed++
		}
		lookups := asked - seen
		seen = asked
		queued = queued[1:]
		family := len(pkt.NetworkHeader().Slice()) != 0
		may := family && sojourn >= codel.Target && left < largest
		if dropped {
			drops++
		}
		if family && sojourn >= codel.Target && !may {
			unasked++
		}
		switch {
		case dropped != want:
			tb.Fatalf("at %s a packet %s old with %d behind it and a session MTU of %d dropped %t, want %t", *now, sojourn, left, mtu, dropped, want)
		case l.delay != model:
			tb.Fatalf("at %s a packet %s old with %d behind it left the delay at %+v, want %+v", *now, sojourn, left, l.delay, model)
		case may && lookups != 1 || !may && lookups != 0:
			tb.Fatalf("at %s a packet %s old with %d behind it looked its session up %d times, want it looked up %t", *now, sojourn, left, lookups, may)
		}
	}
	l.observe.Store(&observe)
	for i, s := range steps {
		switch s.kind {
		case stepWrite, stepFill:
			size := s.size
			if s.kind == stepFill {
				behind := 0
				for _, q := range queued {
					behind += q
				}
				if len(queued) != 0 {
					behind -= queued[0]
				}
				size = min(largest+s.size-behind, largestPacket)
			}
			queued = append(queued, queuePacket(tb, l, s.ends[0], s.ends[1], size, uint32(i)))
		case stepWait:
			*now += s.wait
		case stepTake:
			if pkt := l.poll(); pkt != nil {
				l.release(pkt)
				break
			}
			model.Empty()
			if l.delay != model {
				tb.Fatalf("step %d found the queue empty and left the delay at %+v, want %+v", i, l.delay, model)
			}
		}
		if delayed := l.delayed.Load(); delayed != modelDelayed {
			tb.Fatalf("step %d counted %d dropped for the delay, want %d", i, delayed, modelDelayed)
		}
	}
	return drops, unasked
}

// The link's controlled delay answers every packet as looking every session up
// at or over the target would, and looks a session up only where its MTU may
// change the answer. The sweep must drop some packets and skip some lookups,
// else one side of the comparison goes untried.
func TestLinkDelayAnswersAsLookingEverySessionUp(t *testing.T) {
	largest := largestSessionMTU()
	mtus := map[netip.Addr]int{leaf4: largest, leaf6: netstack.DefaultMTU}
	drops, unasked := 0, 0
	for _, ends := range delayEnds {
		for _, d := range []int{-1, 0, 1} {
			for _, first := range []time.Duration{codel.Target - 1, codel.Target} {
				dropped, skipped := checkDelaySideBySide(t, mtus, []delayStep{
					{kind: stepWrite, ends: ends, size: smallPacket},
					{kind: stepWrite, ends: ends, size: smallPacket},
					{kind: stepFill, ends: ends, size: d},
					{kind: stepWait, wait: first},
					{kind: stepTake},
					{kind: stepFill, ends: ends, size: d},
					{kind: stepWait, wait: codel.Interval},
					{kind: stepTake},
					{kind: stepTake},
					{kind: stepTake},
					{kind: stepWait, wait: codel.Interval},
					{kind: stepTake},
					{kind: stepWrite, ends: ends, size: smallPacket},
					{kind: stepFill, ends: ends, size: d},
					{kind: stepWait, wait: codel.Interval},
					{kind: stepTake},
					{kind: stepTake},
					{kind: stepTake},
				})
				drops, unasked = drops+dropped, unasked+skipped
			}
		}
	}
	if drops == 0 || unasked == 0 {
		t.Fatalf("the sequences dropped %d packets and took %d over the target without a lookup, want some of each", drops, unasked)
	}
	waits := []time.Duration{0, time.Millisecond, codel.Target - 1, codel.Target, codel.Interval - 1, codel.Interval, 2 * codel.Interval}
	pbt.Check(t, func(ht *hegel.T) {
		mtus := map[netip.Addr]int{
			leaf4: hegel.Draw(ht, pbt.Spanning(0, largest)),
			leaf6: hegel.Draw(ht, pbt.Spanning(0, largest)),
		}
		var steps []delayStep
		for range hegel.Draw(ht, hegel.Integers(1, delaySteps)) {
			s := delayStep{kind: hegel.Draw(ht, hegel.SampledFrom([]delayStepKind{stepWrite, stepFill, stepWait, stepTake}))}
			switch s.kind {
			case stepWrite:
				s.ends = hegel.Draw(ht, hegel.SampledFrom(delayEnds))
				most := smallBuffer
				if hegel.Draw(ht, hegel.Booleans()) {
					most = largestPacket
				}
				s.size = hegel.Draw(ht, pbt.Spanning(0, most))
			case stepFill:
				s.ends = hegel.Draw(ht, hegel.SampledFrom(delayEnds))
				s.size = hegel.Draw(ht, pbt.Spanning(-2, 2))
			case stepWait:
				s.wait = hegel.Draw(ht, hegel.SampledFrom(waits))
			}
			steps = append(steps, s)
		}
		checkDelaySideBySide(ht, mtus, steps)
	})
}
