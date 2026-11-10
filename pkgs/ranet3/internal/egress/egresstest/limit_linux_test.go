// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package egresstest

import (
	"context"
	"encoding/binary"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/wireguard/tun"
)

// declared is the declaration of the fakes whose count misses flows
var declared = Missed{Reason: "the fake carries flows past the share uncounted", LimitsRow: "the fake's own"}

// an arm whose count misses flows meets the limit's row where its exit carries
// carriedBound flows past the share and refuses the next, which the row holds
// to every check, the carried flows' packets left out of the refusals counted
func TestSourceLimitTakesFlowsCarriedPastTheShareFromAnArmThatDeclaresIt(t *testing.T) {
	t.Parallel()
	var built *limitedExit
	fakeRows(t, Arm{New: limitedFake(0, carriedBound, &built), Holds: fakeTables, MissesFlows: &declared}, func(t *testing.T, r *rows) {
		t.Run("the limit on a source's flows", r.judged(r.sourceLimit))
		if got := built.carried(r.family.Spare); got != carriedBound {
			t.Errorf("the fake carried %d flows past the share, want the %d it carries", got, carriedBound)
		}
	})
}

// the limit's row fails an arm whose count misses flows where its exit carries
// one flow more than carriedBound past the share, having sent no flow past
// those
func TestSourceLimitFailsAnArmCarryingMoreThanItsBound(t *testing.T) {
	t.Parallel()
	var built *limitedExit
	fakeRows(t, Arm{New: limitedFake(0, carriedBound+1, &built), Holds: fakeTables, MissesFlows: &declared}, func(t *testing.T, r *rows) {
		if err := pastTheShare(t, r); err == nil || !strings.Contains(err.Error(), "flows past its share") {
			t.Errorf("the next flow's step failed by %v, want a failure naming the flows the server read past the share", err)
		}
		if got := built.carried(r.family.Spare); got != carriedBound+1 {
			t.Errorf("the row sent %d flows the fake carried past the share, want the %d it tries", got, carriedBound+1)
		}
	})
}

// the limit's row fails an arm whose count misses flows where its exit drops
// the next flow past the share unanswered, which the server never reads
func TestSourceLimitFailsAnArmDroppingAFlowPastTheShare(t *testing.T) {
	t.Parallel()
	var built *limitedExit
	fakeRows(t, Arm{New: limitedFake(1, 0, &built), Holds: fakeTables, MissesFlows: &declared}, func(t *testing.T, r *rows) {
		if err := pastTheShare(t, r); err == nil || !strings.Contains(err.Error(), "the server read none") {
			t.Errorf("the next flow's step failed by %v, want a failure naming the flow the server read none of", err)
		}
	})
}

// the limit's row holds an arm that declares no missed count to the share
// exactly, failing at the first flow its exit carries past it
func TestSourceLimitFailsAFlowCarriedPastTheShareOfAnArmThatCountsExactly(t *testing.T) {
	t.Parallel()
	var built *limitedExit
	fakeRows(t, Arm{New: limitedFake(0, 1, &built), Holds: fakeTables}, func(t *testing.T, r *rows) {
		if err := pastTheShare(t, r); err == nil || !strings.Contains(err.Error(), "no refusal") {
			t.Errorf("the next flow's step failed by %v, want a failure naming the missing refusal", err)
		}
		if got := built.carried(r.family.Spare); got != 1 {
			t.Errorf("the row sent %d flows the fake carried past the share, want the 1 it carries and no other", got)
		}
	})
}

// pastTheShare fills the spare address's share and returns what the next
// flow's step failed by
func pastTheShare(t *testing.T, r *rows) error {
	before := r.exit.Status()
	to, refusedTo := netip.AddrPortFrom(r.family.Server, limitPort), netip.AddrPortFrom(r.family.Server, limitRefusedPort)
	server, refusedServer := r.listenUDP(t, to), r.listenUDP(t, refusedTo)
	r.fill(t, server, to, before.FlowsPerSource)
	_, err := r.nextRefused(refusedServer, refusedTo, []byte("past the limit over "+r.family.Name), before)
	t.Logf("the next flow's step failed by %v", err)
	return err
}

// limitedExit is fakeExit holding each source to the share its capability
// names, a flow being one protocol's pair of endpoints: of each source's new
// flows past its share it drops the first drop unanswered and uncounted,
// carries the next carry, as a count that missed them would, then refuses
// each packet of a new flow with an answer from the exit
type limitedExit struct {
	*fakeExit
	drop, carry int
	lane        *netstack.Lane

	mu sync.Mutex
	// flows holds the judgment of each flow the fake admitted or dropped
	flows map[flowKey]judgment
	// held is each source's flows within its share, and dropped and past
	// those it dropped and carried beyond
	held, dropped, past map[netip.Addr]int
	refused4, refused6  uint64
}

type flowKey struct {
	protocol byte
	from, to netip.AddrPort
}

// judgment is limitedExit's handling of a packet: it admits, drops or refuses it
type judgment int

const (
	admit judgment = iota
	drop
	refuse
)

// limitedFake builds a limitedExit dropping drop and carrying carry flows
// past each share, and keeps it in built
func limitedFake(drop, carry int, built **limitedExit) func(testing.TB, Host, egress.Egress, egress.Hooks) egress.Exit {
	return func(t testing.TB, host Host, cfg egress.Egress, hooks egress.Hooks) egress.Exit {
		*built = &limitedExit{
			fakeExit: fake{}.build(t, host, cfg, hooks).(*fakeExit), drop: drop, carry: carry, lane: host.Lanes.OpenLane(),
			flows: map[flowKey]judgment{}, held: map[netip.Addr]int{}, dropped: map[netip.Addr]int{}, past: map[netip.Addr]int{},
		}
		return *built
	}
}

// Run gives the lane back once the fake withdrew, which the mesh's close waits for
func (l *limitedExit) Run(ctx context.Context) error {
	defer l.lane.Close()
	return l.fakeExit.Run(ctx)
}

func (l *limitedExit) Egress(frames [][]byte, hold netstack.Hold) {
	var admitted [][]byte
	for _, frame := range frames {
		packet := frame[netstack.TUNHeadroom:]
		switch l.judge(packet) {
		case admit:
			admitted = append(admitted, frame)
		case refuse:
			l.refuse(packet)
		}
	}
	if len(admitted) > 0 {
		l.fakeExit.Egress(admitted, hold)
	}
}

// refuse lays the exit's answer to a flow past its source's share into the
// mesh toward that source, from the exit's mesh address of its family, since
// the mesh of a network the exit does not own builds no answer of its own
func (l *limitedExit) refuse(packet []byte) {
	p, _ := parse(packet)
	from := l.host.Mesh[slices.IndexFunc(l.host.Mesh, func(a netip.Addr) bool { return a.Is4() == p.src.Is4() })]
	answer := icmpError(from, p.src, pastTheLimit, packet)
	l.lane.Fill(func(slab []byte, reads []tun.ReadPacket) int {
		copy(slab[tun.ReadPacketSpacing:], answer)
		reads[0] = tun.ReadPacket{Offset: tun.ReadPacketSpacing, Size: len(answer)}
		return 1
	})
}

// judge counts a TCP or UDP packet's new flow against its source's share, and
// admits every other packet
func (l *limitedExit) judge(packet []byte) judgment {
	p, ok := parse(packet)
	if !ok || p.protocol != syscall.IPPROTO_TCP && p.protocol != syscall.IPPROTO_UDP || len(p.payload) < 4 {
		return admit
	}
	flow := flowKey{p.protocol, netip.AddrPortFrom(p.src, binary.BigEndian.Uint16(p.payload)), netip.AddrPortFrom(p.dst, binary.BigEndian.Uint16(p.payload[2:]))}
	l.mu.Lock()
	defer l.mu.Unlock()
	if known, ok := l.flows[flow]; ok {
		return known
	}
	judged := admit
	switch {
	case l.held[p.src] < l.cfg.SourceLimit():
		l.held[p.src]++
	case l.dropped[p.src] < l.drop:
		l.dropped[p.src]++
		judged = drop
	case l.past[p.src] < l.carry:
		l.past[p.src]++
	case p.src.Is4():
		l.refused4++
		return refuse
	default:
		l.refused6++
		return refuse
	}
	l.flows[flow] = judged
	return judged
}

// carried is how many flows of source the fake carried past its share
func (l *limitedExit) carried(source netip.Addr) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.past[source]
}

func (l *limitedExit) Status() egress.Status {
	s := l.fakeExit.Status()
	l.mu.Lock()
	defer l.mu.Unlock()
	s.FlowsPerSource, s.Refused4, s.Refused6 = l.cfg.SourceLimit(), l.refused4, l.refused6
	return s
}
