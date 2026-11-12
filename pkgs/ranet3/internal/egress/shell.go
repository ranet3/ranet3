// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package egress

import (
	"context"
	"log/slog"
	"net/netip"
	"slices"
	"sync/atomic"
)

// Shell is the readiness and announcement every exit keeps around its own
// passes. Enabled and the announcement are read from any goroutine, and the
// readiness belongs to the exit's run goroutine.
type Shell struct {
	// hooks are the exit's own, read at each report
	hooks *Hooks
	// Enabled is whether the exit carries at all. SetEnabled stores it and
	// wakes the run goroutine, and a store alone leaves the change to the
	// next pass.
	Enabled atomic.Bool
	wake    chan struct{}
	// announced holds the prefixes Announce answers, stored before Republish
	// is called, so a pass that changes nothing does not republish and a
	// caller reading it directly gets the same answer the speaker has
	announced atomic.Pointer[[]netip.Prefix]

	ready4, ready6, serves bool
	unready, skipped       string
	// reported is whether SetReady has run, before which no pass judged the
	// starting state it compares against
	reported bool
}

// Readiness is one pass's judgment of both families
type Readiness struct {
	Ready4, Ready6 bool
	// Why4 and Why6 say why a family is not ready
	Why4, Why6 string
	// Carries4 and Carries6 are whether the host carries a family out at
	// all, by its forwarding under the kernel exit, and under the userspace
	// exit by a route outside the mesh or where the lookup of that route
	// failed, since an unknown route is not a known absence
	Carries4, Carries6 bool
	// Skipped names the lookups left out and why
	Skipped string
}

// NewShell is an enabled shell that reports through hooks
func NewShell(hooks *Hooks) *Shell {
	s := &Shell{hooks: hooks, wake: make(chan struct{}, 1)}
	s.Enabled.Store(true)
	return s
}

// SetEnabled records the request and wakes the run goroutine, which does the
// work, so a caller returns before the exit has caught up and reads Status to
// see that it has
func (s *Shell) SetEnabled(on bool) {
	s.Enabled.Store(on)
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// Wake carries one coalesced wake-up per batch of SetEnabled calls
func (s *Shell) Wake() <-chan struct{} { return s.wake }

// Announce is the prefixes this node may advertise right now: the configured
// list narrowed to the families that are ready, and nothing at all before the
// first pass has run. A caller announces from this rather than from the
// configuration, which is how an exit that cannot carry refuses to advertise
// rather than advertising and dropping.
func (s *Shell) Announce() []netip.Prefix {
	if prefixes := s.announced.Load(); prefixes != nil {
		return slices.Clone(*prefixes)
	}
	return nil
}

// Publish hands the announcement to Republish, and only when it changed, and
// reports whether it did. A republish rebuilds the speaker's originated set,
// which an unchanged pass has no reason to do.
func (s *Shell) Publish(prefixes []netip.Prefix) bool { return s.publish(prefixes, slog.LevelWarn) }

// publish is Publish logging a change at level
func (s *Shell) publish(prefixes []netip.Prefix, level slog.Level) bool {
	previous := s.announced.Load()
	if previous != nil && slices.Equal(*previous, prefixes) {
		return false
	}
	stored := slices.Clone(prefixes)
	s.announced.Store(&stored)
	if previous != nil {
		// said on every transition, because a prefix silently leaving the
		// advertisement is a customer's exit node going away and the counters
		// alone would not name it
		slog.Log(context.Background(), level, "egress advertisement changed", "prefixes", len(prefixes),
			"was", len(*previous), "detail", "a family is advertised only while it is ready, as ranet3 status says")
	}
	s.hooks.Republish()
	return true
}

// SetReady records r. Ready is told when either family or whether the SIDs
// are served moves, and egress.ready is recorded at the first call and when
// any of them or the skip moves. The first call logs each family it judged, a
// family with no reason being one the exit does not carry.
func (s *Shell) SetReady(r Readiness) { s.setReady(r, slog.LevelWarn) }

// Retract records both families not ready for why and publishes the empty
// announcement, its lines at info, since a stop the daemon was asked for is no
// fault. A shell no pass has judged has announced nothing, so there it records
// the reason alone, logs and publishes nothing, and the first judged pass stays
// the first.
func (s *Shell) Retract(why string) {
	if !s.reported {
		s.unready = why
		return
	}
	s.setReady(Readiness{Why4: why, Why6: why}, slog.LevelInfo)
	s.publish(nil, slog.LevelInfo)
}

// setReady is SetReady logging a family not ready at level
func (s *Shell) setReady(r Readiness, level slog.Level) {
	first := !s.reported
	s.reported = true
	s.unready = unreadyText(r.Ready4, r.Ready6, r.Why4, r.Why6)
	// a leaf reads the SID's /128 as the exit's liveness, so a family the host carries out and the exit cannot withdraws it
	serves := (r.Ready4 || r.Ready6) && (r.Ready4 || !r.Carries4) && (r.Ready6 || !r.Carries6)
	moved := r.Ready4 != s.ready4 || r.Ready6 != s.ready6 || serves != s.serves
	if !first && !moved && r.Skipped == s.skipped {
		return
	}
	for _, family := range []struct {
		family     uint8
		was, ready bool
		why        string
	}{{FamilyIPv4, s.ready4, r.Ready4, r.Why4}, {FamilyIPv6, s.ready6, r.Ready6, r.Why6}} {
		switch {
		case family.was == family.ready && (!first || family.why == ""):
		case family.ready:
			slog.Info("egress ready", "family", FamilyName(family.family))
		default:
			slog.Log(context.Background(), level, "egress not ready", "family", FamilyName(family.family), "detail", family.why)
		}
	}
	s.ready4, s.ready6, s.serves, s.skipped = r.Ready4, r.Ready6, serves, r.Skipped
	if moved {
		s.hooks.Ready(r.Ready4, r.Ready6, serves)
	}
	s.hooks.Events.Emit("egress.ready", "", slog.Bool("ipv4", r.Ready4), slog.Bool("ipv6", r.Ready6), slog.Bool("sid", serves),
		slog.String("reason", s.unready), slog.String("skipped", r.Skipped))
}

// SetUnready records both families not ready for why, with nothing skipped. It
// is a judgment and takes the first pass as SetReady does, so an exit that is
// stopped does not call it.
func (s *Shell) SetUnready(why string) { s.SetReady(Readiness{Why4: why, Why6: why}) }

// Unready is why the families not ready are not, as SetReady last recorded
func (s *Shell) Unready() string { return s.unready }

// unreadyText is why the families not ready are not, a family the exit does
// not carry giving no reason, and each reason named by its family where both
// families are not ready
func unreadyText(v4, v6 bool, why4, why6 string) string {
	switch {
	case v4 && v6:
		return ""
	case v6:
		return why4
	case v4:
		return why6
	case why4 == why6:
		return why4
	case why6 == "":
		return "ipv4 " + why4
	case why4 == "":
		return "ipv6 " + why6
	}
	return "ipv4 " + why4 + ", ipv6 " + why6
}

// ReadPrefixes is the prefixes a family's readiness lookups read, those it
// advertises, or its default where it advertises none, which only a family
// translated beside an egress segment does
func (e Egress) ReadPrefixes(family uint8) []netip.Prefix {
	var prefixes []netip.Prefix
	for _, entry := range e.Advertise {
		if AddressFamily(entry.Addr()) == family {
			prefixes = append(prefixes, entry.Prefix)
		}
	}
	if len(prefixes) == 0 {
		unspecified := netip.IPv6Unspecified()
		if family == FamilyIPv4 {
			unspecified = netip.IPv4Unspecified()
		}
		prefixes = []netip.Prefix{netip.PrefixFrom(unspecified, 0)}
	}
	return prefixes
}
