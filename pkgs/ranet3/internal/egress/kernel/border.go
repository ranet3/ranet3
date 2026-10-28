// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ranet3.com/pkgs/ranet3/internal/egress"
)

// BorderClass names the packets one rule of the border chain matches
type BorderClass uint8

const (
	BorderInside BorderClass = iota
	BorderSource
)

// BorderRule is one rule of the chain and its own diff key, as Rule is the
// translator's: the backend writes String into the rule's comment and reads
// it back
type BorderRule struct {
	Class BorderClass
	// Device is the device an inside rule accepts
	Device string
	// Source is the overlay prefix a source rule drops
	Source netip.Prefix
}

func (r BorderRule) String() string {
	if r.Class == BorderInside {
		return "accept via " + r.Device
	}
	return "drop " + r.Family() + " source " + r.Source.String()
}

// Verdict names the verdict a matching packet meets, accept or drop
func (r BorderRule) Verdict() string {
	if r.Class == BorderInside {
		return "accept"
	}
	return "drop"
}

// Reason names a drop as the metric labels it, and is inside for an accept
func (r BorderRule) Reason() string {
	if r.Class == BorderInside {
		return "inside"
	}
	return "overlay_source"
}

// Family is the address family a rule matches, empty for an inside rule,
// which takes both
func (r BorderRule) Family() string {
	switch {
	case r.Class == BorderInside:
		return ""
	case r.Source.Addr().Is4():
		return "ipv4"
	}
	return "ipv6"
}

// addDrops counts packets in d under the family rule drops
func addDrops(d *egress.BorderDrops, rule BorderRule, packets uint64) {
	switch {
	case rule.Class == BorderInside:
	case rule.Source.Addr().Is4():
		d.Source4 += packets
	default:
		d.Source6 += packets
	}
}

// dropsSince is the drops of each family in d after was, a counter below its
// earlier reading being a chain rewritten in between
func dropsSince(d, was egress.BorderDrops) egress.BorderDrops {
	after := func(now, before uint64) uint64 {
		if now < before {
			return now
		}
		return now - before
	}
	return egress.BorderDrops{Source4: after(d.Source4, was.Source4), Source6: after(d.Source6, was.Source6)}
}

func dropAttrs(d egress.BorderDrops) []any {
	return []any{"overlay_source_ipv4", d.Source4, "overlay_source_ipv6", d.Source6}
}

// borderBackend is the kernel surface the filter drives
type borderBackend interface {
	// Rules reads the filter's own table and chain back whole
	Rules() (chainReadback, error)
	// Apply creates the table and the chain and rewrites the chain to rules in
	// one transaction, deleting the table first where remake holds
	Apply(rules []BorderRule, remake bool) error
	// Withdraw removes the filter's table, and a table already gone is success
	Withdraw() error
	// Changed carries one coalesced wake-up per batch of another writer's
	// changes to the filter's table
	Changed() <-chan struct{}
	// Missed carries one coalesced wake-up per batch of notifications the
	// backend lost or could not read, any of which may have been a change
	Missed() <-chan struct{}
	// Read is Rules through a socket of its own, for a reader off the run
	// goroutine
	Read() (chainReadback, error)
	Close() error
}

// BorderFilter owns the border chain on one node: its table, its readback and
// its readiness
type BorderFilter struct {
	rt    egress.BorderRuntime
	be    borderBackend
	sweep time.Duration
	// config is replaced whole by SetConfig and read by the run goroutine
	config atomic.Pointer[egress.Border]
	// stats is the last pass, published whole as Translator.stats is
	stats atomic.Pointer[egress.BorderStats]
	// wake carries a SetConfig to the run goroutine
	wake chan struct{}
	// finish withdraws the table and closes the backend once, at the end of
	// Run or of a start that failed
	finish func() error

	// trigger, ready, unready and dropped belong to the run goroutine, and to
	// NewBorderFilter before it starts: what woke the pass, the readiness last
	// reported, why it is not ready, and the counters last reported
	trigger string
	ready   bool
	unready string
	dropped egress.BorderDrops
}

// NewBorderFilter validates the capability, opens the backend and runs the
// first pass, and refuses the start when that pass cannot install the chain
// and read it back: a node that asked for the filter does not run without it.
// Run keeps it from then on.
func NewBorderFilter(cfg egress.Border, rt egress.BorderRuntime) (*BorderFilter, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if len(rt.Inside) == 0 {
		return nil, errors.New("egress: the border filter needs the devices inside the mesh, the mesh tun at least")
	}
	be, err := newBorderBackend()
	if err != nil {
		return nil, err
	}
	return startBorderFilter(cfg, rt, be)
}

// startBorderFilter runs the first pass over a backend that is open, and
// withdraws and closes it when the pass does not leave the chain read back
func startBorderFilter(cfg egress.Border, rt egress.BorderRuntime, be borderBackend) (*BorderFilter, error) {
	f := newBorderFilter(cfg, rt, be)
	if err := f.reconcile(); err != nil {
		return nil, errors.Join(fmt.Errorf("egress: the border filter could not be installed in %s: %w", f.Where(), err), f.finish())
	}
	if !f.ready {
		return nil, errors.Join(fmt.Errorf("egress: the border filter in %s is not ready, since %s", f.Where(), f.unready), f.finish())
	}
	return f, nil
}

// newBorderFilter is a filter over a backend that is already open, before its first pass
func newBorderFilter(cfg egress.Border, rt egress.BorderRuntime, be borderBackend) *BorderFilter {
	f := &BorderFilter{rt: rt, be: be, sweep: egress.DefaultSweep, wake: make(chan struct{}, 1), trigger: "start"}
	f.config.Store(&cfg)
	f.finish = sync.OnceValue(func() error {
		f.setReady(false, "the border filter is stopping")
		err := f.be.Withdraw()
		if err != nil {
			err = fmt.Errorf("withdraw %s: %w", f.Where(), err)
		} else {
			slog.Info("border filter withdrawn", "where", f.Where())
		}
		return errors.Join(err, f.be.Close())
	})
	return f
}

// SetConfig hands the filter the overlay a reload carries, refusing what
// NewBorderFilter refuses before anything changes, and wakes the run goroutine
// to rewrite the chain
func (f *BorderFilter) SetConfig(cfg egress.Border) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	f.config.Store(&cfg)
	select {
	case f.wake <- struct{}{}:
	default:
	}
	return nil
}

// Capability is the block as the last SetConfig gave it
func (f *BorderFilter) Capability() egress.Border { return *f.config.Load() }

func (f *BorderFilter) Inside() []string { return slices.Clone(f.rt.Inside) }

// Where names the table and the chain the filter owns
func (f *BorderFilter) Where() string {
	return fmt.Sprintf("nftables table inet %s chain %s", TableName, BorderChain)
}

func (f *BorderFilter) Stats() egress.BorderStats {
	if s := f.stats.Load(); s != nil {
		return *s
	}
	return egress.BorderStats{}
}

// Run keeps the chain until ctx is canceled, then reports it not ready,
// withdraws the table and closes the backend. NewBorderFilter ran the first
// pass, so a pass here follows a sweep, a retry, a SetConfig, another writer's
// change or lost notifications. Run returns the withdrawal error, never a
// pass's.
func (f *BorderFilter) Run(ctx context.Context) error {
	ticker := time.NewTicker(f.sweep)
	defer ticker.Stop()
	retry := newRetryTimer(f.sweep)
	defer retry.Stop()
	for {
		select {
		case <-ctx.Done():
			return f.finish()
		case <-ticker.C:
			f.trigger = "sweep"
		case <-retry.C:
			f.trigger = "retry"
		case <-f.wake:
			f.trigger = "reload"
		case <-f.be.Changed():
			// the chain may be gone or bypassed already, so it reads not ready until the pass puts it back
			f.trigger = "changed"
			f.setReady(false, "another writer changed its table")
		case <-f.be.Missed():
			// another table's large transaction overflows the socket as readily as a flush of this one, so only the pass's readback decides
			f.trigger = "missed"
		}
		if err := f.reconcile(); err != nil {
			slog.Warn("border filter pass failed, retrying", "err", err, "retry_in", retry.failed())
		} else {
			retry.passed()
		}
	}
}

// desired is the chain the configuration asks for, in the order a packet
// meets it: the inside accepts, then the overlay source drops
func (f *BorderFilter) desired() []BorderRule {
	overlay := f.config.Load().Normalized().Overlay
	out := make([]BorderRule, 0, len(f.rt.Inside)+len(overlay))
	for _, device := range f.rt.Inside {
		out = append(out, BorderRule{Class: BorderInside, Device: device})
	}
	for _, prefix := range overlay {
		out = append(out, BorderRule{Class: BorderSource, Source: prefix.Prefix})
	}
	return out
}

func sameBorderRules(held []Installed, desired []BorderRule) bool {
	return slices.EqualFunc(held, desired, func(held Installed, rule BorderRule) bool { return held.Spec == rule.String() })
}

// reconcile rewrites the table and the chain where either differs from what
// the configuration asks, a rule another writer added among them, reads both
// back, and reports ready only when the readback equals what was written
func (f *BorderFilter) reconcile() error {
	started := time.Now()
	desired := f.desired()
	applied := false
	read, err := f.be.Rules()
	if err != nil {
		err = fmt.Errorf("list rules: %w", err)
	} else if read.fault != "" || !sameBorderRules(read.rules, desired) {
		if applyErr := f.be.Apply(desired, read.remake); applyErr != nil {
			err = fmt.Errorf("install rules: %w", applyErr)
		} else {
			applied = true
			slog.Info("border filter installed", "rules", len(desired), "replaced", len(read.rules), "where", f.Where())
			if read, err = f.be.Rules(); err != nil {
				err = fmt.Errorf("list rules: %w", err)
			}
		}
	}
	held := read.rules
	switch {
	case err != nil:
		f.setReady(false, "a pass failed: "+err.Error())
	case read.fault != "":
		f.setReady(false, read.fault)
	case !sameBorderRules(held, desired):
		f.setReady(false, "its chain reads back other than it was written")
	default:
		f.setReady(true, "")
	}
	stats := egress.BorderStats{At: time.Now(), Ready: f.ready, Unready: f.unready, Installed: len(held), Dropped: f.dropped}
	if err != nil {
		stats.Err = err.Error()
	} else {
		stats.Dropped = f.countDrops(held, desired)
	}
	f.stats.Store(&stats)
	if applied || err != nil {
		attrs := []slog.Attr{slog.String("trigger", f.trigger), slog.Duration("took", time.Since(started)), slog.Int("installed", stats.Installed)}
		if err != nil {
			attrs = append(attrs, slog.String("err", stats.Err))
		}
		f.rt.Events.Emit("border.pass", "", attrs...)
	}
	return err
}

// countDrops reads the counters of the drops the chain holds and, at most
// once per pass, reports the packets each family dropped since the last pass
// when one moved
func (f *BorderFilter) countDrops(held []Installed, desired []BorderRule) egress.BorderDrops {
	rules := make(map[string]BorderRule, len(desired))
	for _, rule := range desired {
		rules[rule.String()] = rule
	}
	var now egress.BorderDrops
	for _, reading := range held {
		if rule, ok := rules[reading.Spec]; ok {
			addDrops(&now, rule, reading.Packets)
		}
	}
	moved := dropsSince(now, f.dropped)
	f.dropped = now
	if moved != (egress.BorderDrops{}) {
		slog.Info("border filter dropped packets", dropAttrs(moved)...)
		f.rt.Events.Emit("border.dropped", "", slog.Uint64("overlay_source_ipv4", moved.Source4), slog.Uint64("overlay_source_ipv6", moved.Source6))
	}
	return now
}

// setReady logs and records the chain's readiness when it moved, with detail
// saying why it is not ready
func (f *BorderFilter) setReady(ok bool, detail string) {
	f.unready = ""
	if !ok {
		f.unready = detail
	}
	if ok == f.ready {
		return
	}
	f.ready = ok
	if ok {
		slog.Info("border filter ready", "where", f.Where())
	} else {
		slog.Warn("border filter not ready", "where", f.Where(), "detail", detail)
	}
	f.rt.Events.Emit("border.ready", "", slog.Bool("ready", ok))
}

// Debug reads the chain now through a socket of its own, so an operator
// injecting a packet reads counters of now rather than of the last sweep, and
// lays it beside the chain the configuration asks for
func (f *BorderFilter) Debug() egress.BorderDebug {
	stats := f.Stats()
	out := egress.BorderDebug{Where: f.Where(), Hook: "prerouting", Priority: rawPriority, PassAt: stats.At, Ready: stats.Ready, Unready: stats.Unready}
	read, err := f.be.Read()
	if err != nil {
		out.Err = err.Error()
	}
	held := read.rules
	readings := make(map[string]Installed, len(held))
	for _, reading := range held {
		readings[reading.Spec] = reading
	}
	for _, rule := range f.desired() {
		reading, ok := readings[rule.String()]
		delete(readings, rule.String())
		out.Rules = append(out.Rules, egress.BorderReading{Spec: rule.String(), Verdict: rule.Verdict(), Reason: rule.Reason(), Family: rule.Family(),
			Held: ok, Packets: reading.Packets, Bytes: reading.Bytes})
	}
	for _, reading := range held {
		if _, extra := readings[reading.Spec]; !extra {
			continue
		}
		spec := reading.Spec
		verdict, _, _ := strings.Cut(spec, " ")
		if spec == "" {
			spec = "a rule with no comment"
		}
		out.Rules = append(out.Rules, egress.BorderReading{Spec: spec, Verdict: verdict, Held: true, Packets: reading.Packets, Bytes: reading.Bytes})
	}
	return out
}
