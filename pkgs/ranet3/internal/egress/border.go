// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package egress

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

	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/schema"
)

// Border is the cap.border capability: this node drops what arrives on a link
// outside the mesh carrying a mesh source, a routing header or one of this
// node's own SIDs. Writing the block turns it on.
type Border struct {
	// Overlay names the prefixes the mesh numbers its nodes from. A packet
	// arriving from outside the mesh with a source in one of them is forged,
	// and every exit's allow list lies inside them.
	Overlay []schema.Prefix `yaml:"overlay,omitempty" json:"overlay,omitempty" toml:"overlay,omitempty"`
}

// Normalized is the capability as the filter runs it: the prefixes in one
// order, an omitted list and an empty one the same. The order is not
// meaningful, since a packet matches at most one source of a valid list.
func (b Border) Normalized() Border {
	if len(b.Overlay) == 0 {
		b.Overlay = nil
	} else {
		b.Overlay = slices.SortedFunc(slices.Values(b.Overlay), schema.ComparePrefix)
	}
	return b
}

// Validate refuses an overlay list that would pass a forged mesh source or
// drop what no mesh numbers from, worded as Egress.Validate words advertise
func (b Border) Validate() error {
	if len(b.Overlay) == 0 {
		return errors.New("egress: cap.border overlay is empty, so the filter would pass every forged mesh source: name the prefixes the mesh numbers its nodes from")
	}
	return schema.CheckPrefixes("egress: cap.border overlay", b.Overlay, func(prefix netip.Prefix) string {
		switch {
		case prefix.Bits() == 0:
			return "covers every address of its family, so the filter would drop everything arriving from outside the mesh"
		case schema.BelowSourceFloor(prefix):
			return fmt.Sprintf("is shorter than /%d for IPv4 or /%d for IPv6, the unit IANA delegates to a regional registry, so it holds addresses the mesh does not number from", schema.MinSourceBits4, schema.MinSourceBits6)
		}
		return ""
	})
}

// BorderRuntime holds what the command resolves at startup for the filter
type BorderRuntime struct {
	// Inside names the devices whose traffic the filter takes whatever it
	// carries: the mesh tun, the egress device, lo and the VRF master the tun
	// is enslaved to, which a packet arriving on the tun meets prerouting as a
	// second time
	Inside []string
	// SIDs are this node's own local segments, each dropped as a destination
	// arriving from outside. SetConfig replaces them on a reload.
	SIDs []netip.Addr
	// Ready receives whether the chain reads back as the configuration asks,
	// whenever that moves, starting from false. Nil where nothing reads it,
	// which only a test does.
	Ready func(bool)
	// Events records the passes that rewrote the chain or failed, readiness
	// moving and the drops each pass read, nil records nothing
	Events *events.Bus
}

// BorderClass names the packets one rule of the border chain matches
type BorderClass uint8

const (
	BorderInside BorderClass = iota
	BorderSource
	BorderRoutingHeader
	BorderDestination
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
	// Destination is the SID a destination rule drops
	Destination netip.Addr
}

func (r BorderRule) String() string {
	switch r.Class {
	case BorderInside:
		return "accept via " + r.Device
	case BorderSource:
		return "drop " + r.Family() + " source " + r.Source.String()
	case BorderRoutingHeader:
		return "drop ipv6 routing header"
	}
	return "drop ipv6 destination " + r.Destination.String()
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
	switch r.Class {
	case BorderInside:
		return "inside"
	case BorderSource:
		return "overlay_source"
	case BorderRoutingHeader:
		return "routing_header"
	}
	return "sid_destination"
}

// Family is the address family a rule matches, empty for an inside rule,
// which takes both
func (r BorderRule) Family() string {
	switch {
	case r.Class == BorderInside:
		return ""
	case r.Class == BorderSource && r.Source.Addr().Is4():
		return "ipv4"
	}
	return "ipv6"
}

// BorderDrops counts the packets each class dropped, as the chain's counters
// read on a pass. A rewrite of the chain starts them from zero.
type BorderDrops struct {
	Source4, Source6, RoutingHeader, Destination uint64
}

func (d *BorderDrops) add(rule BorderRule, packets uint64) {
	switch {
	case rule.Class == BorderSource && rule.Source.Addr().Is4():
		d.Source4 += packets
	case rule.Class == BorderSource:
		d.Source6 += packets
	case rule.Class == BorderRoutingHeader:
		d.RoutingHeader += packets
	case rule.Class == BorderDestination:
		d.Destination += packets
	}
}

// since is the drops of each class after was, a counter below its earlier
// reading being a chain rewritten in between
func (d BorderDrops) since(was BorderDrops) BorderDrops {
	after := func(now, before uint64) uint64 {
		if now < before {
			return now
		}
		return now - before
	}
	return BorderDrops{
		Source4:       after(d.Source4, was.Source4),
		Source6:       after(d.Source6, was.Source6),
		RoutingHeader: after(d.RoutingHeader, was.RoutingHeader),
		Destination:   after(d.Destination, was.Destination),
	}
}

func (d BorderDrops) attrs() []any {
	return []any{"overlay_source_ipv4", d.Source4, "overlay_source_ipv6", d.Source6, "routing_header", d.RoutingHeader, "sid_destination", d.Destination}
}

// BorderStats is one finished pass as an operator reads it
type BorderStats struct {
	At    time.Time
	Ready bool
	// Unready says why the chain is not ready, empty while it is
	Unready   string
	Installed int
	// Dropped is the counters as the last pass read them, kept from the pass
	// before over a listing that failed
	Dropped BorderDrops
	Err     string
}

// BorderReading is one rule of the chain as a debug read finds it
type BorderReading struct {
	Spec, Verdict, Reason, Family string
	// Held is whether the chain holds it, which a rule the configuration asks
	// for and the last pass has not written yet does not
	Held           bool
	Packets, Bytes uint64
}

// BorderDebug is the chain as a debug read finds it: the rules the
// configuration asks for in order, each with the counters read now through a
// socket of its own, then any the chain holds that it does not ask for
type BorderDebug struct {
	Where    string
	Hook     string
	Priority int
	// PassAt is the last pass, whose readback Ready and Unready report
	PassAt  time.Time
	Ready   bool
	Unready string
	Rules   []BorderReading
	Err     string
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

type borderConfig struct {
	border Border
	sids   []netip.Addr
}

// BorderFilter owns the border chain on one node: its table, its readback and
// the readiness the egress device's families wait for
type BorderFilter struct {
	rt    BorderRuntime
	be    borderBackend
	sweep time.Duration
	// config is replaced whole by SetConfig and read by the run goroutine
	config atomic.Pointer[borderConfig]
	// stats is the last pass, published whole as Translator.stats is
	stats atomic.Pointer[BorderStats]
	// wake carries a SetConfig to the run goroutine
	wake chan struct{}
	// finish withdraws the table and closes the backend once, at the end of
	// Run or of a start that failed
	finish func() error

	// trigger, ready, unready and dropped belong to the run goroutine, and to
	// NewBorderFilter before it starts: what woke the pass, the readiness last
	// handed to Ready, why it is not ready, and the counters last reported
	trigger string
	ready   bool
	unready string
	dropped BorderDrops
}

// NewBorderFilter validates the capability, opens the backend and runs the
// first pass, and refuses the start when that pass cannot install the chain
// and read it back: a node that asked for the filter does not run without it.
// Run keeps it from then on.
func NewBorderFilter(cfg Border, rt BorderRuntime) (*BorderFilter, error) {
	if err := checkBorder(cfg, rt.SIDs); err != nil {
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
func startBorderFilter(cfg Border, rt BorderRuntime, be borderBackend) (*BorderFilter, error) {
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
func newBorderFilter(cfg Border, rt BorderRuntime, be borderBackend) *BorderFilter {
	f := &BorderFilter{rt: rt, be: be, sweep: DefaultSweep, wake: make(chan struct{}, 1), trigger: "start"}
	f.config.Store(&borderConfig{border: cfg, sids: slices.Clone(rt.SIDs)})
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

// checkBorder refuses an overlay list Validate refuses and a SID the chain
// cannot compare as an IPv6 destination
func checkBorder(cfg Border, sids []netip.Addr) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	for _, sid := range sids {
		if !sid.Is6() || sid.Is4In6() || sid.Zone() != "" {
			return fmt.Errorf("egress: the border filter drops SIDs as IPv6 destinations, and %s is not one", sid)
		}
	}
	return nil
}

// SetConfig hands the filter the overlay and the SIDs a reload carries,
// refusing what NewBorderFilter refuses before anything changes, and wakes the
// run goroutine to rewrite the chain
func (f *BorderFilter) SetConfig(cfg Border, sids []netip.Addr) error {
	if err := checkBorder(cfg, sids); err != nil {
		return err
	}
	f.config.Store(&borderConfig{border: cfg, sids: slices.Clone(sids)})
	select {
	case f.wake <- struct{}{}:
	default:
	}
	return nil
}

// Capability is the block as the last SetConfig gave it
func (f *BorderFilter) Capability() Border { return f.config.Load().border }

// SIDs are the SIDs as the last SetConfig gave them
func (f *BorderFilter) SIDs() []netip.Addr { return slices.Clone(f.config.Load().sids) }

func (f *BorderFilter) Inside() []string { return slices.Clone(f.rt.Inside) }

// Where names the table and the chain the filter owns
func (f *BorderFilter) Where() string {
	return fmt.Sprintf("nftables table inet %s chain %s", TableName, BorderChain)
}

func (f *BorderFilter) Stats() BorderStats {
	if s := f.stats.Load(); s != nil {
		return *s
	}
	return BorderStats{}
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
			// the chain may be gone or bypassed already, so the egress device stops before the pass that puts it back
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
// meets it: the inside accepts, then the drops in the order overlay source,
// routing header, SID destination, so a packet two drops match counts in the
// first and the counters partition the drops
func (f *BorderFilter) desired() []BorderRule {
	in := f.config.Load()
	overlay := in.border.Normalized().Overlay
	out := make([]BorderRule, 0, len(f.rt.Inside)+len(overlay)+1+len(in.sids))
	for _, device := range f.rt.Inside {
		out = append(out, BorderRule{Class: BorderInside, Device: device})
	}
	for _, prefix := range overlay {
		out = append(out, BorderRule{Class: BorderSource, Source: prefix.Prefix})
	}
	out = append(out, BorderRule{Class: BorderRoutingHeader})
	for _, sid := range slices.SortedFunc(slices.Values(in.sids), netip.Addr.Compare) {
		out = append(out, BorderRule{Class: BorderDestination, Destination: sid})
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
	stats := BorderStats{At: time.Now(), Ready: f.ready, Unready: f.unready, Installed: len(held), Dropped: f.dropped}
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
// once per pass, reports the packets each class dropped since the last pass
// when one moved
func (f *BorderFilter) countDrops(held []Installed, desired []BorderRule) BorderDrops {
	rules := make(map[string]BorderRule, len(desired))
	for _, rule := range desired {
		rules[rule.String()] = rule
	}
	var now BorderDrops
	for _, reading := range held {
		if rule, ok := rules[reading.Spec]; ok {
			now.add(rule, reading.Packets)
		}
	}
	moved := now.since(f.dropped)
	f.dropped = now
	if moved != (BorderDrops{}) {
		slog.Info("border filter dropped packets", moved.attrs()...)
		f.rt.Events.Emit("border.dropped", "",
			slog.Uint64("overlay_source_ipv4", moved.Source4), slog.Uint64("overlay_source_ipv6", moved.Source6),
			slog.Uint64("routing_header", moved.RoutingHeader), slog.Uint64("sid_destination", moved.Destination))
	}
	return now
}

// setReady hands Runtime.Ready the chain's readiness when it moved, logs it
// and records it, with detail saying why it is not ready
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
	if f.rt.Ready != nil {
		f.rt.Ready(ok)
	}
	f.rt.Events.Emit("border.ready", "", slog.Bool("ready", ok))
}

// Debug reads the chain now through a socket of its own, so an operator
// injecting a packet reads counters of now rather than of the last sweep, and
// lays it beside the chain the configuration asks for
func (f *BorderFilter) Debug() BorderDebug {
	stats := f.Stats()
	out := BorderDebug{Where: f.Where(), Hook: "prerouting", Priority: rawPriority, PassAt: stats.At, Ready: stats.Ready, Unready: stats.Unready}
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
		out.Rules = append(out.Rules, BorderReading{Spec: rule.String(), Verdict: rule.Verdict(), Reason: rule.Reason(), Family: rule.Family(),
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
		out.Rules = append(out.Rules, BorderReading{Spec: spec, Verdict: verdict, Held: true, Packets: reading.Packets, Bytes: reading.Bytes})
	}
	return out
}
