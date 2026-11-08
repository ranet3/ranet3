// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package userspace

import (
	"cmp"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"

	"ranet3.com/pkgs/ranet3/internal/egress"
)

// The reasons the status counts a packet dropped by the queues: a lane full
// past Limits.Lanes, the link's queue full past Limits.Link, and a packet the
// pump could lay into no batch
const (
	reasonLaneFull = "lane full"
	reasonLinkFull = "link full"
	reasonUnlaid   = "unlaid"
)

// flowsStatus is the exit's detail as Status reports it: the flows open by
// family, the dials and the endpoints in TIME_WAIT, the limits and the bytes
// the TCP buffers hold, the refusals and drops by why, and the sources
// holding the most flows
func (x *Exit) flowsStatus() *egress.Flows {
	l := x.rt.Limits
	from := egress.BudgetHost
	if l.From == FromGoLimit {
		from = egress.BudgetGoLimit
	}
	f := &egress.Flows{
		Limits: egress.FlowLimits{
			Budget: l.Budget, From: from, Flows: l.Flows, Connections: l.Connections, Dials: l.Dials,
			TimeWait: l.TimeWait, Window: l.Window, Lanes: l.Lanes, Link: l.Link,
		},
		Reused: x.counts.reused.Load(), Closed: x.counts.closed.Load(),
		Sources: x.flows.most(statusSources),
	}
	x.tcp.mu.Lock()
	f.Dialing = x.tcp.dials
	for flow := range x.tcp.flows {
		f.TCP[family(flow.ipv6)]++
		f.Buffered += queued(flow.ep)
	}
	x.tcp.mu.Unlock()
	f.TimeWait = x.tcp.closed.waiting()
	x.udp.mu.RLock()
	for leaf, m := range x.udp.mappings {
		m.mu.RLock()
		f.UDP[family(leaf.Addr().Is6())] += len(m.destinations)
		if m.hairpinned {
			f.UDP[family(leaf.Addr().Is6())]++
		}
		m.mu.RUnlock()
	}
	x.udp.mu.RUnlock()
	x.echo.mu.Lock()
	for key := range x.echo.mappings {
		f.Echo[family(key.leaf.Is6())]++
	}
	x.echo.mu.Unlock()
	x.counts.mu.Lock()
	f.Refused, f.Dropped = maps.Clone(x.counts.refused), maps.Clone(x.counts.dropped)
	x.counts.mu.Unlock()
	for reason, n := range map[string]uint64{reasonLaneFull: x.counts.laneDropped.Load(), reasonLinkFull: x.link.dropped.Load(), reasonUnlaid: x.counts.unlaid.Load()} {
		if n != 0 {
			if f.Dropped == nil {
				f.Dropped = map[string]uint64{}
			}
			f.Dropped[reason] = n
		}
	}
	return f
}

// family is the index of a family's count, IPv4's 0 and IPv6's 1
func family(ipv6 bool) int {
	if ipv6 {
		return 1
	}
	return 0
}

// queued is the bytes ep's buffers hold now, received and not yet read, and
// written and not yet acknowledged
func queued(ep tcpip.Endpoint) uint64 {
	var total uint64
	for _, option := range []tcpip.SockOptInt{tcpip.ReceiveQueueSizeOption, tcpip.SendQueueSizeOption} {
		if n, err := ep.GetSockOptInt(option); err == nil && n > 0 {
			total += uint64(n)
		}
	}
	return total
}

// waiting is the endpoints held that wait in TIME_WAIT now
func (c *closedEndpoints) waiting() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, ep := range c.queue {
		if ep.EndpointState() == tcp.StateTimeWait {
			n++
		}
	}
	return n
}

// most is the n sources holding the most flows, most first, then by address
func (f *flows) most(n int) []egress.SourceFlows {
	f.mu.Lock()
	sources := make([]egress.SourceFlows, 0, len(f.bySource))
	for source, open := range f.bySource {
		sources = append(sources, egress.SourceFlows{Source: source, Flows: open})
	}
	f.mu.Unlock()
	slices.SortFunc(sources, func(a, b egress.SourceFlows) int {
		return cmp.Or(cmp.Compare(b.Flows, a.Flows), a.Source.Compare(b.Source))
	})
	return sources[:min(n, len(sources))]
}

// refused counts a new flow refused for reason, raw its first packet, among
// them each refused past its source's share in its family, and records
// egress.refused naming the source and the reason, an interval apart, with
// the refusals since the last record
func (x *Exit) refused(raw []byte, reason string) {
	x.counts.refuse(reason)
	source := sourceOf(raw)
	if reason == reasonShare {
		x.counts.share[family(source.Is6())].Add(1)
	}
	if since, ok := x.refusals.add(x.reportClock()); ok {
		x.rt.Events.Emit("egress.refused", "", slog.String("source", source.String()), slog.String("reason", reason), slog.Uint64("refused", since))
	}
}

// sourceOf is the source address of raw, an IPv4 or IPv6 packet
func sourceOf(raw []byte) netip.Addr {
	switch {
	case len(raw) >= 20 && raw[0]>>4 == 4:
		return netip.AddrFrom4([4]byte(raw[12:16]))
	case len(raw) >= 40 && raw[0]>>4 == 6:
		return netip.AddrFrom16([16]byte(raw[8:24]))
	}
	return netip.Addr{}
}

// spaced counts one kind of occasion and lets one report of it out an
// interval apart, with the occasions since the last, as the mesh spaces its
// reports
type spaced struct {
	total, reported atomic.Uint64
	// next is the earliest the next report may go, in nanoseconds on the
	// caller's clock, zero letting the first go at once
	next atomic.Int64
}

// add counts one at now and reports whether the caller reports, with the
// occasions since the last report
func (s *spaced) add(now int64) (uint64, bool) {
	total := s.total.Add(1)
	next := s.next.Load()
	if now < next || !s.next.CompareAndSwap(next, now+int64(refusedInterval)) {
		return 0, false
	}
	return total - s.reported.Swap(total), true
}
