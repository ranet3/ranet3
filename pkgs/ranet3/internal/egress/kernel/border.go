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

// BorderClass names the packets one rule of the table matches
type BorderClass uint8

const (
	// BorderInside to BorderSource are the border chain's, in the order a
	// packet meets them
	BorderInside BorderClass = iota
	BorderCarved
	BorderCarveOut
	BorderSource
	// EntryOutside to EntryDrop are the entry chain's, in that order
	EntryOutside
	EntryReply
	EntryLinkLocal
	EntryOwned
	EntryNone
	EntryDrop
)

// BorderRule is one rule of the table and its own diff key, as Rule is the
// translator's: the backend writes String into the rule's comment and reads
// it back
type BorderRule struct {
	Class BorderClass
	// Device is the device an inside rule accepts, the link a carve-out's rule
	// accepts from, and the tun the entry chain guards
	Device string
	// Source is the overlay prefix a source rule drops and the carve-out a
	// carve-out's rule accepts
	Source netip.Prefix
	// Destination is the prefix a link-local rule returns
	Destination netip.Prefix
	// IPv6 is the family of every rule that matches one, set where the rule is
	// built
	IPv6 bool
}

func (r BorderRule) String() string {
	switch r.Class {
	case BorderInside:
		return "accept via " + r.Device
	case BorderCarved:
		return "drop " + r.Family() + " source @" + r.Set()
	case BorderCarveOut:
		return "accept via " + r.Device + " source " + r.Source.String()
	case BorderSource:
		return "drop " + r.Family() + " source " + r.Source.String()
	case EntryOutside:
		return "return via other than " + r.Device
	case EntryReply:
		return "return a reply"
	case EntryLinkLocal:
		return "return ipv6 to " + r.Destination.String()
	case EntryOwned:
		return "return " + r.Family() + " source @" + r.Set()
	case EntryNone:
		return "return " + r.Family() + " to @" + r.Set()
	}
	return "drop " + r.Family() + " entering the mesh"
}

// Chain is the chain the rule sits in
func (r BorderRule) Chain() string {
	if r.Class <= BorderSource {
		return BorderChain
	}
	return EntryChain
}

// Set names the set a rule reads, empty for one that reads none
func (r BorderRule) Set() string {
	var name string
	switch r.Class {
	case BorderCarved:
		name = carvedSet
	case EntryOwned:
		name = ownedSet
	case EntryNone:
		name = noneSet
	default:
		return ""
	}
	if r.IPv6 {
		return name + "6"
	}
	return name + "4"
}

// Verdict names the verdict a matching packet meets, accept, return or drop
func (r BorderRule) Verdict() string {
	switch r.Class {
	case BorderInside, BorderCarveOut:
		return "accept"
	case BorderCarved, BorderSource, EntryDrop:
		return "drop"
	}
	return "return"
}

// Reason names a drop as the metric labels it, and what a rule passes for any
// other
func (r BorderRule) Reason() string {
	switch r.Class {
	case BorderInside:
		return "inside"
	case BorderCarved:
		return "carved_source"
	case BorderCarveOut:
		return "carve_out"
	case BorderSource:
		return "overlay_source"
	case EntryOutside:
		return "outside"
	case EntryReply:
		return "reply"
	case EntryLinkLocal:
		return "link_local"
	case EntryOwned:
		return "owned"
	case EntryNone:
		return "none"
	}
	return "mesh_entry"
}

// Family is the address family a rule matches, empty for one that takes both
func (r BorderRule) Family() string {
	switch {
	case r.Class == BorderInside || r.Class == EntryOutside || r.Class == EntryReply:
		return ""
	case r.IPv6:
		return "ipv6"
	}
	return "ipv4"
}

// addDrops counts packets in d under the drop and family of rule
func addDrops(d *egress.BorderDrops, rule BorderRule, packets uint64) {
	v6 := rule.Family() == "ipv6"
	var into *uint64
	switch {
	case rule.Class == BorderSource && v6:
		into = &d.Source6
	case rule.Class == BorderSource:
		into = &d.Source4
	case rule.Class == BorderCarved && v6:
		into = &d.Carved6
	case rule.Class == BorderCarved:
		into = &d.Carved4
	case rule.Class == EntryDrop && v6:
		into = &d.Entry6
	case rule.Class == EntryDrop:
		into = &d.Entry4
	default:
		return
	}
	*into += packets
}

// dropsSince is the drops in d after was, a counter below its earlier reading
// being a table rewritten in between
func dropsSince(d, was egress.BorderDrops) egress.BorderDrops {
	after := func(now, before uint64) uint64 {
		if now < before {
			return now
		}
		return now - before
	}
	return egress.BorderDrops{
		Source4: after(d.Source4, was.Source4), Source6: after(d.Source6, was.Source6),
		Carved4: after(d.Carved4, was.Carved4), Carved6: after(d.Carved6, was.Carved6),
		Entry4: after(d.Entry4, was.Entry4), Entry6: after(d.Entry6, was.Entry6),
	}
}

func dropAttrs(d egress.BorderDrops) []slog.Attr {
	return []slog.Attr{
		slog.Uint64("overlay_source_ipv4", d.Source4), slog.Uint64("overlay_source_ipv6", d.Source6),
		slog.Uint64("carved_source_ipv4", d.Carved4), slog.Uint64("carved_source_ipv6", d.Carved6),
		slog.Uint64("mesh_entry_ipv4", d.Entry4), slog.Uint64("mesh_entry_ipv6", d.Entry6),
	}
}

// borderSets is each named set's ranges, of its one family and as
// egress.Union leaves them, by the set's name
type borderSets map[string][]egress.Range

// changed is the sets of s that differ from was, nil where none does
func (s borderSets) changed(was borderSets) borderSets {
	var out borderSets
	for name, ranges := range s {
		if !slices.Equal(ranges, was[name]) {
			if out == nil {
				out = borderSets{}
			}
			out[name] = ranges
		}
	}
	return out
}

// borderBackend is the kernel surface the filter drives
type borderBackend interface {
	// Rules reads the filter's own table back whole: both chains' rules against
	// rules, each by its comment and by what it does, and each set's elements
	// against sets
	Rules(rules []BorderRule, sets borderSets) (chainReadback, error)
	// Apply writes the table whole in one transaction: the table, the sets
	// filled with sets, and the chains rewritten to rules, deleting the table
	// first where remake holds
	Apply(rules []BorderRule, sets borderSets, remake bool) error
	// Fill moves each set sets names from the ranges was gives it, which the
	// table holds, to those sets gives it, in one transaction that sends the
	// ranges that differ alone and leaves the chains as they are
	Fill(was, sets borderSets) error
	// Withdraw removes the filter's table, and a table already gone is success
	Withdraw() error
	// Changed carries one coalesced wake-up per batch of another writer's
	// changes to the filter's table
	Changed() <-chan struct{}
	// Missed carries one coalesced wake-up per batch of notifications the
	// backend lost or could not read, any of which may have been a change
	Missed() <-chan struct{}
	// Read is Rules with no sets through a socket of its own, for a reader off
	// the run goroutine
	Read() (chainReadback, error)
	Close() error
}

// BorderFilter owns the table inet ranet3 on one node: its border chain where
// cap.border is written, its entry chain, their sets, the readback and the
// readiness
type BorderFilter struct {
	rt    egress.BorderRuntime
	be    borderBackend
	sweep time.Duration
	// config is replaced whole by SetConfig and read by the run goroutine, nil
	// where cap.border is not written
	config atomic.Pointer[egress.Border]
	// stats is the last pass, published whole as Translator.stats is
	stats atomic.Pointer[egress.BorderStats]
	// wake carries a SetConfig to the run goroutine
	wake chan struct{}
	// finish withdraws the table and closes the backend once, at the end of
	// Run or of a start that failed
	finish func() error

	// the rest belong to the run goroutine, and to NewBorderFilter before it
	// starts. held is nil where no write's sets are known, and last is the
	// rules of the last pass that read the table back as written.
	trigger   string
	ready     bool
	unready   string
	dropped   egress.BorderDrops
	held      borderSets
	carveOuts []egress.CarveOut
	last      []BorderRule
}

// NewBorderFilter validates the capability, nil where cap.border is not
// written, opens the backend and runs the first pass, and refuses the start
// when that pass cannot install the table and read it back: a node does not
// run without it. Run keeps it from then on. A platform with no nf_tables
// returns no filter where cap.border is not written, and refuses it where it
// is.
func NewBorderFilter(cfg *egress.Border, rt egress.BorderRuntime) (*BorderFilter, error) {
	if cfg != nil {
		if err := cfg.Validate(); err != nil {
			return nil, err
		}
		if len(rt.Inside) == 0 {
			return nil, errors.New("egress: the border filter needs the devices inside the mesh, the mesh tun at least")
		}
	}
	if !EntryRuns && cfg == nil {
		return nil, nil
	}
	if rt.Tun == "" {
		return nil, errors.New("egress: the entry chain needs the mesh's tun")
	}
	be, err := newBorderBackend()
	if err != nil {
		return nil, err
	}
	return startBorderFilter(cfg, rt, be)
}

// startBorderFilter runs the first pass over a backend that is open, and
// withdraws and closes it when the pass does not leave the table read back
func startBorderFilter(cfg *egress.Border, rt egress.BorderRuntime, be borderBackend) (*BorderFilter, error) {
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
func newBorderFilter(cfg *egress.Border, rt egress.BorderRuntime, be borderBackend) *BorderFilter {
	f := &BorderFilter{rt: rt, be: be, sweep: egress.DefaultSweep, wake: make(chan struct{}, 1), trigger: "start"}
	f.config.Store(cfg)
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

// Capability is the block as the last SetConfig gave it, the zero block where
// cap.border is not written
func (f *BorderFilter) Capability() egress.Border {
	if cfg := f.config.Load(); cfg != nil {
		return *cfg
	}
	return egress.Border{}
}

func (f *BorderFilter) Inside() []string { return slices.Clone(f.rt.Inside) }

// Where names the table and the chains the filter owns
func (f *BorderFilter) Where() string {
	if f.config.Load() == nil {
		return fmt.Sprintf("nftables table inet %s chain %s", TableName, EntryChain)
	}
	return fmt.Sprintf("nftables table inet %s chains %s and %s", TableName, BorderChain, EntryChain)
}

func (f *BorderFilter) Stats() egress.BorderStats {
	if s := f.stats.Load(); s != nil {
		return *s
	}
	return egress.BorderStats{}
}

// Run keeps the table until ctx is canceled, then reports it not ready,
// withdraws the table and closes the backend. NewBorderFilter ran the first
// pass. Run returns the withdrawal error, never a pass's.
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
		case <-f.rt.Routes:
			f.trigger = "routes"
		case <-f.rt.Network:
			f.trigger = "network"
		case <-f.be.Changed():
			// the table may be gone or bypassed already, so it reads not ready until the pass puts it back
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

// desired is the table the configuration and the sets ask for: the rules in
// the order a packet meets them, the border chain's ahead of the entry
// chain's, the sets, and the carve-outs the border chain accepts
func (f *BorderFilter) desired() ([]BorderRule, borderSets, []egress.CarveOut) {
	var derived egress.BorderSets
	if f.rt.Sets != nil {
		derived = f.rt.Sets()
	}
	var rules []BorderRule
	var carveOuts []egress.CarveOut
	if cfg := f.config.Load(); cfg != nil {
		for _, device := range f.rt.Inside {
			rules = append(rules, BorderRule{Class: BorderInside, Device: device})
		}
		carveOuts = derived.CarveOuts
		// a family with no carve-out holds an empty carved set, so its drop is left out
		for _, v6 := range []bool{false, true} {
			if slices.ContainsFunc(carveOuts, func(c egress.CarveOut) bool { return c.Prefix.Addr().Is6() == v6 }) {
				rules = append(rules, BorderRule{Class: BorderCarved, IPv6: v6})
			}
		}
		for _, carveOut := range carveOuts {
			rules = append(rules, BorderRule{Class: BorderCarveOut, Device: carveOut.Link, Source: carveOut.Prefix, IPv6: carveOut.Prefix.Addr().Is6()})
		}
		for _, prefix := range cfg.Normalized().Overlay {
			rules = append(rules, BorderRule{Class: BorderSource, Source: prefix.Prefix, IPv6: prefix.Addr().Is6()})
		}
	}
	rules = append(rules,
		BorderRule{Class: EntryOutside, Device: f.rt.Tun},
		BorderRule{Class: EntryReply},
		BorderRule{Class: EntryLinkLocal, Destination: netip.MustParsePrefix("fe80::/10"), IPv6: true},
		BorderRule{Class: EntryLinkLocal, Destination: netip.MustParsePrefix("ff00::/8"), IPv6: true},
	)
	for _, class := range []BorderClass{EntryOwned, EntryNone, EntryDrop} {
		rules = append(rules, BorderRule{Class: class}, BorderRule{Class: class, IPv6: true})
	}
	sets := borderSets{}
	for _, one := range []struct {
		name   string
		ranges []egress.Range
	}{{carvedSet, derived.Carved}, {ownedSet, derived.Owned}, {noneSet, derived.None}} {
		// the union orders every IPv4 range ahead of every IPv6 one
		ranges := egress.Union(one.ranges)
		v6 := slices.IndexFunc(ranges, func(r egress.Range) bool { return r.First.Is6() })
		if v6 < 0 {
			v6 = len(ranges)
		}
		sets[one.name+"4"], sets[one.name+"6"] = ranges[:v6:v6], ranges[v6:]
	}
	return rules, sets, carveOuts
}

// reconcile makes the table what the pass asks for, each rule by its comment
// and by what it does, sending the sets' changed ranges alone where only they
// moved, and reports ready only when the readback equals it. A pass woken
// by the mesh's table or the host's links that asks for what the last good
// pass read back reads nothing.
func (f *BorderFilter) reconcile() error {
	started := time.Now()
	rules, sets, carveOuts := f.desired()
	f.reportCarveOuts(carveOuts)
	if (f.trigger == "routes" || f.trigger == "network") && f.ready && slices.Equal(rules, f.last) && sets.changed(f.held) == nil {
		return nil
	}
	want := f.held
	if want == nil {
		want = sets
	}
	wrote := ""
	read, err := f.be.Rules(rules, want)
	changed := sets.changed(want)
	switch {
	case err != nil:
		err = fmt.Errorf("list rules: %w", err)
	case read.fault != "":
		// a table with no border chain is made again whole, so one an earlier start left goes
		if applyErr := f.be.Apply(rules, sets, read.remake || f.config.Load() == nil); applyErr != nil {
			f.held = nil
			err = fmt.Errorf("install rules: %w", applyErr)
		} else {
			wrote, f.held = "table", sets
			slog.Info("border filter installed", "rules", len(rules), "replaced", len(read.rules), "where", f.Where())
		}
	case changed != nil:
		// the readback found the table holding want, so the fill sends what differs from it
		if fillErr := f.be.Fill(want, changed); fillErr != nil {
			f.held = nil
			err = fmt.Errorf("fill sets: %w", fillErr)
		} else {
			wrote, f.held = "sets", sets
		}
	}
	if err == nil && wrote != "" {
		if read, err = f.be.Rules(rules, sets); err != nil {
			err = fmt.Errorf("list rules: %w", err)
		}
	}
	held := read.rules
	switch {
	case err != nil:
		f.setReady(false, "a pass failed: "+err.Error())
	case read.fault != "":
		f.setReady(false, read.fault)
	default:
		f.setReady(true, "")
	}
	f.last = nil
	if f.ready {
		f.last = rules
	}
	stats := egress.BorderStats{At: time.Now(), Ready: f.ready, Unready: f.unready, Installed: len(held), Dropped: f.dropped, CarveOuts: carveOuts}
	if err != nil {
		stats.Err = err.Error()
	} else {
		stats.Dropped = f.countDrops(held, rules)
	}
	f.stats.Store(&stats)
	if wrote != "" || err != nil {
		attrs := []slog.Attr{slog.String("trigger", f.trigger), slog.Duration("took", time.Since(started)), slog.Int("installed", stats.Installed)}
		if wrote != "" {
			attrs = append(attrs, slog.String("wrote", wrote))
		}
		if err != nil {
			attrs = append(attrs, slog.String("err", stats.Err))
		}
		f.rt.Events.Emit("border.pass", "", attrs...)
	}
	return err
}

// reportCarveOuts reports each carve-out that came since the last pass at
// warning and each that went at info, each with an event
func (f *BorderFilter) reportCarveOuts(now []egress.CarveOut) {
	for _, carveOut := range now {
		if !slices.Contains(f.carveOuts, carveOut) {
			slog.Warn("border carves the overlay for a link that holds part of it", "link", carveOut.Link, "prefix", carveOut.Prefix)
			f.rt.Events.Emit("border.carve", "", slog.String("link", carveOut.Link), slog.String("prefix", carveOut.Prefix.String()), slog.Bool("carved", true))
		}
	}
	for _, carveOut := range f.carveOuts {
		if !slices.Contains(now, carveOut) {
			slog.Info("border no longer carves the overlay for a link", "link", carveOut.Link, "prefix", carveOut.Prefix)
			f.rt.Events.Emit("border.carve", "", slog.String("link", carveOut.Link), slog.String("prefix", carveOut.Prefix.String()), slog.Bool("carved", false))
		}
	}
	f.carveOuts = now
}

// countDrops reads the counters of the drops the table holds and, at most
// once per pass, reports the packets each drop took since the last pass when
// one moved
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
		slog.LogAttrs(context.Background(), slog.LevelInfo, "border filter dropped packets", dropAttrs(moved)...)
		f.rt.Events.Emit("border.dropped", "", dropAttrs(moved)...)
	}
	return now
}

// setReady logs and records the table's readiness when it moved, with detail
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

// Debug reads the table now through a socket of its own, so an operator
// injecting a packet reads counters of now rather than of the last sweep, and
// lays it beside the table the configuration asks for
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
	rules, _, _ := f.desired()
	for _, rule := range rules {
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
