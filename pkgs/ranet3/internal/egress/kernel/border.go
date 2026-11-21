// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/events"
	meshkernel "ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/sadr"
	"ranet3.com/pkgs/ranet3/schema"
)

// BorderClass names the packets one rule of the filter matches
type BorderClass uint8

const (
	// BorderMapped to BorderSource are the antispoof chain's, in the order a
	// packet meets them
	BorderMapped BorderClass = iota
	BorderInside
	BorderCarved
	BorderCarveOut
	BorderExempt
	BorderSource
	// EntryOutside to EntryDrop are the entry chain's, in that order
	EntryOutside
	EntryReply
	EntryLinkLocal
	EntryOwned
	EntryNone
	EntryDrop
)

// entryLinkLocal is the IPv6 link-local and multicast destinations the entry
// chain lets into the tun from any source
var entryLinkLocal = []netip.Prefix{netip.MustParsePrefix("fe80::/10"), netip.MustParsePrefix("ff00::/8")}

// mappedSources is the IPv4-mapped IPv6 addresses of RFC 4291 section
// 2.5.5.2, which the antispoof chain's first rule drops as a source on every
// device where the backend writes that rule, as nftables does and pf does not.
// A dual-stack socket reads a native IPv6 packet from ::ffff:a.b.c.d under the
// peer of an IPv4 packet from a.b.c.d.
var mappedSources = netip.MustParsePrefix("::ffff:0:0/96")

// BorderRule is one rule of the filter. The backend writes String as the rule's
// comment, which names the line in a readback.
type BorderRule struct {
	Class BorderClass
	// Device is the device an inside rule accepts, the link a carve-out's rule
	// accepts from, the interface or the name ending in * an exemption's rule
	// accepts from, empty for every one, and the tun the entry chain guards
	Device string
	// Source is the overlay prefix a source rule drops, mappedSources for the
	// mapped rule, the carve-out a carve-out's rule accepts and the prefix an
	// exemption's rule accepts
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
	case BorderExempt:
		if r.Device == "" {
			return "accept exempt source " + r.Source.String()
		}
		return "accept exempt via " + r.Device + " source " + r.Source.String()
	case BorderMapped, BorderSource:
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
	case BorderInside, BorderCarveOut, BorderExempt:
		return "accept"
	case BorderMapped, BorderCarved, BorderSource, EntryDrop:
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
	case BorderExempt:
		return "exempt"
	case BorderMapped:
		return "mapped_source"
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

// addDrops counts packets in d under the drop and family of rule, nothing for
// a rule that drops nothing
func addDrops(d *egress.BorderDrops, rule BorderRule, packets uint64) {
	if i := slices.Index(egress.BorderDropKinds[:], egress.BorderDrop{Reason: rule.Reason(), Family: rule.Family()}); i >= 0 {
		d[i] += packets
	}
}

// dropsSince is the drops in d after was, a counter below its earlier reading
// being the filter's rules rewritten in between
func dropsSince(d, was egress.BorderDrops) egress.BorderDrops {
	for i := range d {
		if d[i] >= was[i] {
			d[i] -= was[i]
		}
	}
	return d
}

// dropKinds is each drop of egress.BorderDropKinds a rule of rules writes, in
// that order
func dropKinds(rules []BorderRule) []egress.BorderDrop {
	var out []egress.BorderDrop
	for _, kind := range egress.BorderDropKinds {
		if slices.ContainsFunc(rules, func(rule BorderRule) bool { return rule.Reason() == kind.Reason && rule.Family() == kind.Family }) {
			out = append(out, kind)
		}
	}
	return out
}

// dropAttrs is d's count of each drop of kinds
func dropAttrs(d egress.BorderDrops, kinds []egress.BorderDrop) []slog.Attr {
	attrs := make([]slog.Attr, 0, len(kinds))
	for i, kind := range egress.BorderDropKinds {
		if slices.Contains(kinds, kind) {
			attrs = append(attrs, slog.Uint64(kind.Name(), d[i]))
		}
	}
	return attrs
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

// none is the ranges of the none sets, the IPv4 ranges ahead of the IPv6 ones
func (s borderSets) none() []egress.Range {
	return append(slices.Clone(s[noneSet+"4"]), s[noneSet+"6"]...)
}

// byFamily is ranges, sorted as egress.Union leaves them, as its IPv4 and its
// IPv6 ranges
func byFamily(ranges []egress.Range) (v4, v6 []egress.Range) {
	i := slices.IndexFunc(ranges, func(r egress.Range) bool { return r.First.Is6() })
	if i < 0 {
		i = len(ranges)
	}
	return ranges[:i:i], ranges[i:]
}

// borderBackend is the kernel surface the filter drives
type borderBackend interface {
	// Rules reads the filter's own chains and sets back: both chains' rules
	// against rules, each by its comment and by what it does, and each set's
	// elements against sets
	Rules(rules []BorderRule, sets borderSets) (chainReadback, error)
	// Apply writes the filter's chains and sets whole in one transaction: the
	// sets filled with sets and the chains holding rules, deleting first each
	// of its own the host holds that cannot change in place, on nftables each
	// nftables.Readback.Stale names, and a chain no rule sits in, and on
	// nftables, where nf_tables refuses that transaction
	// with EEXIST, every set of its own the table holds, as
	// nftables.Hold.Rewrite says, and nothing of another writer's but what
	// nf_tables ties to a rule of another writer's in the filter's chains
	Apply(rules []BorderRule, sets borderSets) error
	// Fill moves each set sets names from the ranges was gives it, which the
	// host holds under rules, to those sets gives it, in one transaction that
	// leaves the chains as they are. nftables sends the ranges that differ
	// alone, and pf sends each table rules read whole. It may return a refused
	// only where the host answered the transaction with an error, which commits
	// nothing of it, and any other error may leave the transaction committed.
	Fill(rules []BorderRule, was, sets borderSets) error
	// Withdraw removes what the filter writes and reports whether it removed
	// any, what is already gone being success. nftables removes the filter's
	// chains and sets, and the table as nftables.Hold.Withdraw says.
	Withdraw() (removed bool, err error)
	// Changed carries another writer's changes to what the filter writes. On
	// nftables it carries one coalesced wake-up per transaction in which
	// another writer deleted the table, set a flag on it, or changed one of
	// the filter's chains, rules or sets, and may carry more than one for a
	// transaction read in the span after a loss that nftables.Monitor's doc
	// gives. On pf it never fires, and the sweep reads the anchor back.
	Changed() <-chan struct{}
	// Missed carries one coalesced wake-up per batch of notifications the
	// backend lost or could not read, any of which may have been a change
	Missed() <-chan struct{}
	// Read is Rules with no sets and no fault through a socket of its own, for
	// a reader off the run goroutine. rules names each line the backend cannot
	// name by its comment alone.
	Read(rules []BorderRule) (chainReadback, error)
	// generation is the namespace's nf_tables generation, which every committed
	// transaction moves, as nftables.Conn.Generation gives, and 0 where the
	// backend counts none or the read fails, so a pass reads before every fill
	generation() uint32
	// Close closes the backend of a filter that ends, a start refused before
	// it ran among them, and gives back what opening it took for the filter
	// beyond what it writes where no earlier run left it so
	Close() error
	// Leave closes the backend at the mesh's failure and keeps what it writes
	// and whatever else the backend holds for it, so the next start takes them
	// over
	Leave() error
	// where names what the backend writes for cfg, nil where overlay is not
	// written
	where(cfg *egress.Border) string
	// writes reports whether the backend writes rule as a rule of its own. A
	// rule it does not write it folds into the rules it does, or runs nowhere.
	writes(rule BorderRule) bool
	// holds reports whether the backend writes the set named set in either
	// family. desired leaves out a set it does not, so moving one writes
	// nothing.
	holds(set string) bool
	// sweep is the period of the pass that reads the filter back unwoken, zero
	// for egress.DefaultSweep
	sweep() time.Duration
	// wildcards reports whether the backend matches an interface by a name
	// ending in *. desired writes an exemption under such a name for one that
	// does not as one rule per link the name matches.
	wildcards() bool
	// chain is chain's heading in a debug read, its rules left empty
	chain(name string) egress.BorderChainReading
	// readings is sets as the backend names and holds them
	readings(sets borderSets) []egress.BorderSetReading
}

// refused is the error of a transaction the host answered with an error,
// which commits nothing of it, where another error of a write leaves the
// commit unknown. This file builds on every platform and nftables.Refused is
// Linux's alone, so the Linux backend's Fill wraps that error in this one
// through asRefused.
type refused struct{ error }

func (r refused) Unwrap() error { return r.error }

// BorderFilter owns the antispoof filter on one node, as its backend writes it:
// its antispoof chain where overlay is written, its entry chain, their sets,
// the readback and the readiness
type BorderFilter struct {
	rt    egress.BorderRuntime
	be    borderBackend
	sweep time.Duration
	// config is replaced whole by SetConfig and read by the run goroutine, nil
	// where overlay is not written
	config atomic.Pointer[egress.Border]
	// stats is the last pass, published whole as Translator.stats is
	stats atomic.Pointer[egress.BorderStats]
	// wake carries a SetConfig to the run goroutine
	wake chan struct{}
	// finish withdraws what the filter writes and closes the backend once, at
	// the end of Run or at Close where the first pass made it
	finish func() error
	// noneMu guards the fields below it up to kernel. A pass leaves out of its
	// sets the addresses reported and promised keep out, and a Snapshot holds
	// back what none meets and promises the rest, each in one hold of noneMu,
	// so either the Snapshot sees the pass's none or the pass sees the
	// Snapshot's promise.
	noneMu sync.Mutex
	// none is the ranges the entry chain's none sets may hold, in Union form:
	// every address until a pass reads them back as written, and nothing once
	// a withdrawal took them. A pass joins its own sets in before it writes,
	// since a write can land and still fail, and leaves only its own once it
	// read them back as written. A stop that leaves the chains leaves none,
	// since the sets stay with them.
	none []egress.Range
	// reported is the routes the reconciler's last report says the kernel may
	// hold
	reported []meshkernel.Route
	// promised is the route the reconciler may install for each entry the
	// source handed since that report, which the next report accounts for
	promised []meshkernel.Route
	// derived is the last pass's none sets as derived from the configuration
	derived []egress.Range
	// left is the part of derived the last pass asked the none sets to hold,
	// the addresses of reported and promised taken out
	left []egress.Range
	// src is the route source Routes built, nil before
	src *routeSource
	// kernel carries a move of what the reconciler's report leaves of the
	// last pass's none sets to the run goroutine
	kernel chan struct{}
	// ended is closed once the filter stops, by end
	ended chan struct{}
	end   func()

	// the rest belong to the run goroutine, and to NewBorderFilter before it
	// starts. written is the sets the host held at the last confirmed read or
	// write, kept over a fill the host refused, since a refusal commits nothing,
	// and nil where a failed write may have committed. last is the rules of the
	// last pass that read or wrote, made is whether the first pass's read found
	// nothing the filter writes, so whatever is there is this start's, and found
	// whether that read found any of it.
	made      bool
	found     bool
	trigger   string
	ready     bool
	unready   string
	dropped   egress.BorderDrops
	written   borderSets
	carveOuts []egress.CarveOut
	conflicts []egress.ExemptConflict
	last      []BorderRule
	// cleanGeneration is the backend's generation read before the last read,
	// where that read found the filter as written and ready, and 0 where it did
	// not or the backend counts none, since nf_tables counts from 1 and skips 0
	// at a wrap
	cleanGeneration uint32
	// retryOnFault is whether the last pass ended on a readback fault that no
	// wake may come to repair: with the source holding a route back, or after
	// a fill with no read before it. Run then retries the pass on its own
	// timer, since no change of the table or the configuration may come to
	// wake it.
	retryOnFault bool
	// heldRoutes reports each route the source holds back as a pass ends
	heldRoutes routeReport
	// keptRoutes reports each route whose addresses a pass kept out of the
	// sets
	keptRoutes routeReport
}

// NewBorderFilter validates the configuration, nil where overlay is not
// written, opens the backend and runs the first pass, and refuses the start
// when that pass cannot install the filter and read it back: a node does not
// run without it. Run keeps it from then on. A platform with no backend
// returns no filter, and so does one the filter runs on only where overlay is
// written, where it is not, once it gives back what an earlier run left.
func NewBorderFilter(cfg *egress.Border, rt egress.BorderRuntime) (*BorderFilter, error) {
	if cfg != nil {
		if err := cfg.Validate(); err != nil {
			return nil, err
		}
		if len(rt.Inside) == 0 {
			return nil, errors.New("egress: the antispoof filter needs the devices inside the mesh, the mesh tun at least")
		}
	}
	if rt.Tun == "" {
		return nil, errors.New("egress: the entry chain needs the mesh's tun")
	}
	be, err := newBorderBackend(cfg, rt)
	if err != nil || be == nil {
		return nil, err
	}
	return startBorderFilter(cfg, rt, be)
}

// startBorderFilter runs the first pass over a backend that is open, and
// closes it as Close does when the pass does not leave the filter read back
func startBorderFilter(cfg *egress.Border, rt egress.BorderRuntime, be borderBackend) (*BorderFilter, error) {
	f := newBorderFilter(cfg, rt, be)
	f.reportInside(nil, cfg)
	if err := f.reconcile(); err != nil {
		return nil, errors.Join(fmt.Errorf("egress: the antispoof filter could not be installed in %s: %w", f.Where(), err), f.Close())
	}
	if !f.ready {
		return nil, errors.Join(fmt.Errorf("egress: the antispoof filter in %s is not ready, since %s", f.Where(), f.unready), f.Close())
	}
	return f, nil
}

// Close ends a filter whose Run was never called and reports it not ready.
// Where the first read found nothing the filter writes it withdraws what the
// pass made, logging it withdrawn only where any was there to remove, and it
// leaves the rest for the next start: what the first read found, adopted or
// rewritten, and whatever is there where that read failed, which it names
// nothing of. Either way the backend's close gives back what opening it took
// beyond what it writes, where no earlier run left it so. The route source
// holds back what the none sets it leaves may hold, as after a withdrawal
// that fails.
func (f *BorderFilter) Close() error {
	if f.made {
		return f.finish()
	}
	f.stopping()
	if f.found {
		slog.Info("antispoof filter is leaving the chains it found", "where", f.Where())
	}
	return f.be.Close()
}

// newBorderFilter is a filter over a backend that is already open, before its first pass
func newBorderFilter(cfg *egress.Border, rt egress.BorderRuntime, be borderBackend) *BorderFilter {
	f := &BorderFilter{rt: rt, be: be, sweep: cmp.Or(be.sweep(), egress.DefaultSweep), wake: make(chan struct{}, 1), trigger: "start", ended: make(chan struct{}), kernel: make(chan struct{}, 1)}
	f.heldRoutes = routeReport{what: "held",
		warn:    "antispoof holds learned routes back from the kernel, handing the reconciler a hold at each, until a pass writes the none sets without them",
		release: "antispoof no longer holds learned routes back from the kernel"}
	f.keptRoutes = routeReport{what: "kept",
		warn:    "antispoof keeps out of the none sets the addresses of routes the kernel may hold that no learned entry asks for",
		release: "antispoof no longer keeps out of the none sets the addresses of these routes, each one neither the reconciler's report nor the source's promise names, or one with none of its addresses outside the overlay in the sets as derived, as when a learned entry asks for them again, a reload brings them inside the overlay or no none class covers them"}
	f.none = everyAddress
	f.config.Store(cfg)
	f.end = sync.OnceFunc(func() { close(f.ended) })
	f.finish = sync.OnceValue(func() error {
		f.stopping()
		removed, err := f.be.Withdraw()
		switch {
		case err != nil:
			err = fmt.Errorf("withdraw %s: %w", f.Where(), err)
		case removed:
			slog.Info("antispoof filter withdrawn", "where", f.Where())
		}
		if err == nil {
			f.setNone(nil)
		}
		return errors.Join(err, f.be.Close())
	})
	return f
}

// Routes is the mesh's table as the route reconciler reads it. Where the entry
// chain runs, it is the table with a hold in place of each learned entry
// whose destination meets the ranges the none sets may hold, as
// internal/kernel's Unentered holds them back, it wakes on a change of the
// table, of those ranges and of the overlay, and it is told what the
// reconciler's passes may have left in the kernel. Before a pass has read the
// sets back it holds back each learned entry outside the overlay, and after a
// stop that leaves the chains what their sets may still hold. A nil filter,
// which a platform with no backend builds, and a platform with no entry chain
// hand the table itself. The filter builds one source, at the first call, and
// a later call hands that one, the first call's table standing. Its watch of
// the table ends with the filter.
func (f *BorderFilter) Routes(table *netstack.RouteTable) meshkernel.RouteSource {
	if f == nil || !EntryRuns {
		return table
	}
	f.noneMu.Lock()
	defer f.noneMu.Unlock()
	if f.src == nil {
		r := &routeSource{filter: f, table: table, wake: make(chan struct{}, 1)}
		f.src = r
		changes := table.Changes()
		go func() {
			for {
				select {
				case <-f.ended:
					return
				case <-changes:
					r.notify()
				}
			}
		}()
	}
	return f.src
}

// source is the route source Routes built, nil before
func (f *BorderFilter) source() *routeSource {
	f.noneMu.Lock()
	defer f.noneMu.Unlock()
	return f.src
}

// routeSource is the route source Routes builds
type routeSource struct {
	filter *BorderFilter
	table  *netstack.RouteTable
	wake   chan struct{}
}

func (r *routeSource) notify() {
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

func (r *routeSource) Changes() <-chan struct{} { return r.wake }

// Snapshot is the entries split hands over, and promises the route the
// reconciler may install for each that takes a packet into the tun, in the
// hold of noneMu that read none
func (r *routeSource) Snapshot() []sadr.Route[*netstack.Peer] {
	f := r.filter
	snapshot, overlay := r.table.Snapshot(), f.overlay()
	f.noneMu.Lock()
	defer f.noneMu.Unlock()
	handed, _ := meshkernel.Unentered(snapshot, f.none, overlay)
	f.promised = append(f.promised, meshkernel.Promised(handed, overlay)...)
	return handed
}

func (r *routeSource) Resolve(src, dst netip.Addr) (*netstack.Peer, netstack.Verdict, netstack.Match) {
	return r.table.Resolve(src, dst)
}

// Installed records the reconciler's report and forgets the routes promised
// before it, which the report accounts for. It wakes the filter's run only
// where what the report and the promise leave of the last pass's derived sets
// moved, since a pass costs a derivation of the sets on top of this walk.
func (r *routeSource) Installed(routes []meshkernel.Route) {
	f := r.filter
	var overlays [][]schema.Prefix
	if cfg := f.config.Load(); cfg != nil {
		overlays = append(overlays, cfg.Overlay)
	}
	f.noneMu.Lock()
	f.reported, f.promised = routes, nil
	left, _ := f.leftOf(f.derived, overlays)
	moved := !slices.Equal(left, f.left)
	f.noneMu.Unlock()
	if moved {
		select {
		case f.kernel <- struct{}{}:
		default:
		}
	}
}

// split reads the table now and returns it as Unentered does: handed, with a
// hold in place of each entry the source holds back, and held, those entries
func (r *routeSource) split() (handed, held []sadr.Route[*netstack.Peer]) {
	f := r.filter
	snapshot, overlay := r.table.Snapshot(), f.overlay()
	f.noneMu.Lock()
	defer f.noneMu.Unlock()
	return meshkernel.Unentered(snapshot, f.none, overlay)
}

// overlay is the overlay of the configuration now, nil where overlay is not written
func (f *BorderFilter) overlay() []schema.Prefix {
	if cfg := f.config.Load(); cfg != nil {
		return cfg.Overlay
	}
	return nil
}

// everyAddress is each IPv4 and IPv6 address, the ranges the none sets may
// hold until a pass reads them back
var everyAddress = []egress.Range{
	{First: netip.IPv4Unspecified(), Last: netip.MustParseAddr("255.255.255.255")},
	{First: netip.IPv6Unspecified(), Last: netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")},
}

// setNone records the ranges the none sets may hold
func (f *BorderFilter) setNone(none []egress.Range) {
	f.noneMu.Lock()
	defer f.noneMu.Unlock()
	f.putNone(none)
}

// putNone records the ranges the none sets may hold, with noneMu held, waking
// the route source's reader where they moved
func (f *BorderFilter) putNone(none []egress.Range) {
	if slices.Equal(f.none, none) {
		return
	}
	f.none = none
	if f.src != nil {
		f.src.notify()
	}
}

// leaveOut takes out of the none sets of sets the addresses the reconciler's
// report and the source's promise keep out, and joins what it leaves into
// none in the same hold of noneMu. It returns sets so changed, what it left
// of the none sets in Union form, and the routes whose addresses it took
// out. overlays is each overlay the pass read, an address counting as inside
// only where every one holds it.
func (f *BorderFilter) leaveOut(sets borderSets, overlays ...[]schema.Prefix) (borderSets, []egress.Range, []meshkernel.Route) {
	derived := sets.none()
	f.noneMu.Lock()
	defer f.noneMu.Unlock()
	left, kept := f.leftOf(derived, overlays)
	f.derived, f.left = derived, left
	out := maps.Clone(sets)
	if _, ok := sets[noneSet+"4"]; ok {
		out[noneSet+"4"], out[noneSet+"6"] = byFamily(left)
	}
	f.putNone(egress.Union(slices.Concat(f.none, left)))
	return out, left, kept
}

// leftOf returns what is left of derived once the reconciler's report and
// the source's promise keep their addresses out under overlays, and the
// routes that keep any out, each once. noneMu is held.
func (f *BorderFilter) leftOf(derived []egress.Range, overlays [][]schema.Prefix) ([]egress.Range, []meshkernel.Route) {
	routes := slices.Concat(f.reported, f.promised)
	var taken []egress.Range
	var kept []meshkernel.Route
	seen := make(map[meshkernel.Route]bool)
	for _, overlay := range overlays {
		by, ranges := meshkernel.Kept(routes, derived, overlay)
		taken = append(taken, ranges...)
		for _, route := range by {
			if !seen[route] {
				seen[route] = true
				kept = append(kept, route)
			}
		}
	}
	return meshkernel.Without(derived, taken), kept
}

// report records the routes the route source holds back and the routes whose
// addresses the pass kept out of the sets as the pass ends, and reports
// whether the source holds any back
func (f *BorderFilter) report(kept []meshkernel.Route) bool {
	r := f.source()
	if r == nil {
		return false
	}
	_, held := r.split()
	heldNames := make([]string, 0, len(held))
	for _, entry := range held {
		route := entry.Destination.String()
		if entry.Source.IsValid() {
			route += " from " + entry.Source.String()
		}
		heldNames = append(heldNames, route)
	}
	keptNames := make([]string, 0, len(kept))
	for _, route := range kept {
		keptNames = append(keptNames, route.String())
	}
	now := time.Now()
	f.heldRoutes.pass(heldNames, f.rt.Events, now)
	f.keptRoutes.pass(keptNames, f.rt.Events, now)
	return len(held) > 0
}

// routeReport turns the routes of one kind that each pass ends with into
// events and lines
type routeReport struct {
	// what is the event's kind after "antispoof." and the name of its bool
	what string
	// warn is the warning line that names routes an event named true
	warn string
	// release is the info line that names routes an event named false
	release string
	// atEnd is each route the last pass ended with, true once an event named
	// it
	atEnd map[string]bool
	// came is each route an event named true since the last warning that the
	// last pass ended with
	came map[string]bool
	// went is each route an event named false since the last release line
	// that the last pass did not end with
	went map[string]bool
	// warnedAt and releasedAt are when the last warning and the last release
	// line were logged
	warnedAt, releasedAt time.Time
}

// pass records the routes a pass ended with. It emits an event naming a route
// true when the route was there at two pass ends in a row, once, and one
// naming it false at the first pass end without it after that. It logs the
// warning where came holds a route and routeReportInterval has passed since
// the last one, and the release line likewise for went, so no warning names a
// route named true and gone again before the next warning is due.
func (r *routeReport) pass(now []string, bus *events.Bus, at time.Time) {
	next := make(map[string]bool, len(now))
	if r.came == nil {
		r.came, r.went = map[string]bool{}, map[string]bool{}
	}
	for _, route := range now {
		named, there := r.atEnd[route]
		if there && !named {
			bus.Emit("antispoof."+r.what, "", slog.String("route", route), slog.Bool(r.what, true))
			r.came[route] = true
			named = true
		}
		next[route] = named
	}
	for _, route := range slices.Sorted(maps.Keys(r.atEnd)) {
		if _, stays := next[route]; !stays && r.atEnd[route] {
			bus.Emit("antispoof."+r.what, "", slog.String("route", route), slog.Bool(r.what, false))
			r.went[route] = true
		}
	}
	r.atEnd = next
	maps.DeleteFunc(r.came, func(route string, _ bool) bool { _, stays := next[route]; return !stays })
	maps.DeleteFunc(r.went, func(route string, _ bool) bool { _, back := next[route]; return back })
	if len(r.came) > 0 && at.Sub(r.warnedAt) >= routeReportInterval {
		slog.Warn(r.warn, "routes", reportedRoutes(r.came), "count", len(r.came))
		clear(r.came)
		r.warnedAt = at
	}
	if len(r.went) > 0 && at.Sub(r.releasedAt) >= routeReportInterval {
		slog.Info(r.release, "routes", reportedRoutes(r.went), "count", len(r.went))
		clear(r.went)
		r.releasedAt = at
	}
}

// reportedRoutes names the first routes of a line in order, the count naming the rest
func reportedRoutes(routes map[string]bool) string {
	names := slices.Sorted(maps.Keys(routes))
	if len(names) > reportedRouteNames {
		return strings.Join(names[:reportedRouteNames], ", ") + ", ..."
	}
	return strings.Join(names, ", ")
}

// SetConfig hands the filter the configuration a reload carries, the overlay,
// the exemptions and this node's own prefixes, refusing what NewBorderFilter
// refuses before anything changes, and wakes the run goroutine for a pass
func (f *BorderFilter) SetConfig(cfg egress.Border) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	f.reportInside(f.config.Load(), &cfg)
	f.config.Store(&cfg)
	select {
	case f.wake <- struct{}{}:
	default:
	}
	// the source weighs each entry against the overlay, so what it hands may have moved
	if r := f.source(); r != nil {
		r.notify()
	}
	return nil
}

// Capability is the configuration as the last SetConfig gave it, the zero
// configuration where overlay is not written
func (f *BorderFilter) Capability() egress.Border {
	if cfg := f.config.Load(); cfg != nil {
		return *cfg
	}
	return egress.Border{}
}

func (f *BorderFilter) Inside() []string { return slices.Clone(f.rt.Inside) }

// Where names what the filter owns, as its backend writes it
func (f *BorderFilter) Where() string {
	return f.be.where(f.config.Load())
}

func (f *BorderFilter) Stats() egress.BorderStats {
	if s := f.stats.Load(); s != nil {
		return *s
	}
	return egress.BorderStats{}
}

// Run keeps the filter until ctx is canceled, then reports it not ready,
// withdraws what it writes and closes the backend. Where ctx's cause is
// internal/kernel's ErrMeshFailed it leaves that for the next start to take
// over. NewBorderFilter ran the first pass. Run returns the withdrawal's or
// the close's error, never a pass's.
func (f *BorderFilter) Run(ctx context.Context) error {
	ticker := time.NewTicker(f.sweep)
	defer ticker.Stop()
	retry := meshkernel.NewRetryTimer()
	defer retry.Stop()
	for {
		select {
		case <-ctx.Done():
			if errors.Is(context.Cause(ctx), meshkernel.ErrMeshFailed) {
				// the sets stay with the chains, so the route source holds back what they may hold
				f.stopping()
				slog.Warn("antispoof filter is leaving its chains after the mesh failed", "where", f.Where())
				return f.be.Leave()
			}
			return f.finish()
		case <-ticker.C:
			f.trigger = "sweep"
		case <-retry.C:
			f.trigger = "retry"
		case <-f.wake:
			f.trigger = "reload"
		case <-f.rt.Routes:
			f.trigger = "routes"
		case <-f.kernel:
			f.trigger = "kernel"
		case <-f.rt.Network:
			f.trigger = "network"
		case <-f.be.Changed():
			// the filter's chains may be gone or bypassed already, so it reads not ready until the pass puts them back
			f.trigger = "changed"
			f.setReady(false, "another writer changed its table")
		case <-f.be.Missed():
			// another table's large transaction overflows the socket as readily as a flush of this one, so only the pass's readback decides
			f.trigger = "missed"
		}
		switch err := f.reconcile(); {
		case err != nil:
			slog.Warn("antispoof filter pass failed, retrying", "err", err, "retry_in", retry.Failed(f.sweep))
		case f.retryOnFault:
			// the route source holds routes back until a pass reads the sets back, and a
			// fault the read after a fill found came from no change a wake reports
			retry.Failed(f.sweep)
		default:
			retry.Passed()
		}
	}
}

// desired is the filter the configuration and the sets ask for: the rules the
// backend writes as rules of their own in the order a packet meets them, the
// antispoof chain's ahead of the entry chain's, the sets, and the carve-outs
// the antispoof chain accepts with the exemptions' conflicts, neither where
// overlay is not written. The mapped drop comes first, ahead of the inside
// devices' accepts, since a packet arriving on an inside device such as lo
// need not have passed the mesh's source checks. The carved drops come ahead
// of every accept by source, so neither a carve-out nor an exemption lets in
// a source the carved sets hold.
func (f *BorderFilter) desired() ([]BorderRule, borderSets, egress.BorderSets) {
	// the sets and the rules read one configuration, so no pass carves from two
	cfg := f.config.Load()
	var derived egress.BorderSets
	if f.rt.Sets != nil {
		derived = f.rt.Sets(cfg)
	}
	var rules []BorderRule
	var reported egress.BorderSets
	if cfg != nil {
		rules = append(rules, BorderRule{Class: BorderMapped, Source: mappedSources, IPv6: true})
		for _, device := range f.rt.Inside {
			rules = append(rules, BorderRule{Class: BorderInside, Device: device})
		}
		reported = egress.BorderSets{CarveOuts: derived.CarveOuts, Conflicts: derived.Conflicts}
		carveOuts := derived.CarveOuts
		// a family Carved gives no prefix of holds an empty carved set, so its drop is left out
		carved := cfg.Carved(carveOuts)
		for _, v6 := range []bool{false, true} {
			if slices.ContainsFunc(carved, func(prefix netip.Prefix) bool { return prefix.Addr().Is6() == v6 }) {
				rules = append(rules, BorderRule{Class: BorderCarved, IPv6: v6})
			}
		}
		for _, carveOut := range carveOuts {
			rules = append(rules, BorderRule{Class: BorderCarveOut, Device: carveOut.Link, Source: carveOut.Prefix, IPv6: carveOut.Prefix.Addr().Is6()})
		}
		for _, exemption := range cfg.Exemptions() {
			for _, device := range f.exempting(exemption, derived.Links) {
				rule := BorderRule{Class: BorderExempt, Device: device, Source: exemption.Prefix, IPv6: exemption.Prefix.Addr().Is6()}
				// a comment names one rule, and an exact name beside a wildcard matching it gives the same rule twice
				if !slices.Contains(rules, rule) {
					rules = append(rules, rule)
				}
			}
		}
		for _, prefix := range cfg.Normalized().Overlay {
			rules = append(rules, BorderRule{Class: BorderSource, Source: prefix.Prefix, IPv6: prefix.Addr().Is6()})
		}
	}
	rules = append(rules, BorderRule{Class: EntryOutside, Device: f.rt.Tun}, BorderRule{Class: EntryReply})
	for _, destination := range entryLinkLocal {
		rules = append(rules, BorderRule{Class: EntryLinkLocal, Destination: destination, IPv6: true})
	}
	for _, class := range []BorderClass{EntryOwned, EntryNone, EntryDrop} {
		rules = append(rules, BorderRule{Class: class}, BorderRule{Class: class, IPv6: true})
	}
	rules = slices.DeleteFunc(rules, func(rule BorderRule) bool { return !f.be.writes(rule) })
	sets := borderSets{}
	for _, one := range []struct {
		name   string
		ranges []egress.Range
	}{{carvedSet, derived.Carved}, {ownedSet, derived.Owned}, {noneSet, derived.None}} {
		if !f.be.holds(one.name) {
			continue
		}
		sets[one.name+"4"], sets[one.name+"6"] = byFamily(egress.Union(one.ranges))
	}
	return rules, sets, reported
}

// exempting is the devices an exemption's rules name: none for the shared
// list, its name where the backend matches it, and for a name ending in * on a
// backend that matches exact names alone, each of links it matches, in their
// order, but a device inside the mesh, which no exemption reaches. A link that
// comes or goes changes the rules on the pass its change wakes.
func (f *BorderFilter) exempting(exemption egress.Exemption, links []string) []string {
	if _, wildcard := egress.InterfacePattern(exemption.Interface); !wildcard || f.be.wildcards() {
		if f.insideDevice(exemption.Interface) {
			return nil
		}
		return []string{exemption.Interface}
	}
	var out []string
	for _, link := range links {
		if exemption.Names(link) && !f.insideDevice(link) {
			out = append(out, link)
		}
	}
	return out
}

// insideDevice reports whether name is a device inside the mesh, which the
// antispoof chain accepts ahead of its carved and overlay drops
func (f *BorderFilter) insideDevice(name string) bool { return slices.Contains(f.rt.Inside, name) }

// reportInside warns once of each exemption cfg brings in beside was that
// names a device inside the mesh, which exempting leaves out
func (f *BorderFilter) reportInside(was, cfg *egress.Border) {
	inside := func(cfg *egress.Border) []egress.Exemption {
		if cfg == nil {
			return nil
		}
		return slices.DeleteFunc(cfg.Exemptions(), func(exemption egress.Exemption) bool { return !f.insideDevice(exemption.Interface) })
	}
	before := inside(was)
	for _, exemption := range inside(cfg) {
		if !slices.Contains(before, exemption) {
			slog.Warn("antispoof leaves out an exemption naming a device inside the mesh, where no overlay or carved drop applies", "interface", exemption.Interface, "prefix", exemption.Prefix)
		}
	}
}

// reconcile makes the filter what the pass asks for, each rule by its comment
// and by what it does, sending the sets' changed ranges alone where only they
// moved, and reports ready only when the readback equals it. A pass woken
// by the mesh's table or the host's links that asks for what the last good
// pass read back reads nothing. One that fills reads only after the fill where
// no transaction has committed since the last read that found the filter as
// written.
func (f *BorderFilter) reconcile() error {
	started := time.Now()
	before := f.config.Load()
	rules, sets, reported := f.desired()
	// a reload between the two reads leaves out what either overlay keeps out
	var overlays [][]schema.Prefix
	if before != nil {
		overlays = append(overlays, before.Overlay)
	}
	if after := f.config.Load(); after != before && after != nil {
		overlays = append(overlays, after.Overlay)
	}
	sets, none, kept := f.leaveOut(sets, overlays...)
	carveOuts := reported.CarveOuts
	f.reportCarveOuts(carveOuts)
	f.reportConflicts(reported.Conflicts)
	if (f.trigger == "routes" || f.trigger == "network" || f.trigger == "kernel") && f.ready && slices.Equal(rules, f.last) && sets.changed(f.written) == nil {
		return nil
	}
	want := f.written
	if want == nil {
		want = sets
	}
	fill := sets.changed(want)
	wrote := ""
	generation := f.be.generation()
	// the read after the fill stays, so a base older than another writer's
	// transaction costs a pass and its retry, as nftables.Conn.Generation gives.
	// The sweep attempts a read whatever the generation shows, and a pass another
	// writer's change woke reads because the generation can miss that change.
	skipped := generation != 0 && generation == f.cleanGeneration && f.trigger != "sweep" && f.trigger != "changed" &&
		slices.Equal(rules, f.last) && fill != nil
	var read chainReadback
	var err error
	if !skipped {
		read, err = f.be.Rules(rules, want)
	}
	if f.trigger == "start" {
		// a failed read tells nothing of the filter, which is then left
		f.made, f.found = err == nil && !read.held, err == nil && read.held
	}
	if err == nil && read.fault == "" {
		f.written = want
	}
	switch {
	case err != nil:
		err = fmt.Errorf("list rules: %w", err)
	case read.fault != "":
		// a rewrite makes what the filter writes again whole, and touches nothing beside it
		// but what nf_tables ties to a rule of another writer's in the filter's chains
		if applyErr := f.be.Apply(rules, sets); applyErr != nil {
			// the next pass reads the host against the rules and sets it derives
			// again, not against what the host held, so a host that holds them,
			// whether this rewrite committed with its answer lost or the host held
			// them before, is adopted with no second rewrite
			f.written = nil
			err = fmt.Errorf("%s, and the write failed: %w", read.fault, applyErr)
		} else {
			wrote, f.written = "table", sets
			slog.Info("antispoof filter installed", "rules", len(rules), "replaced", len(read.rules), "where", f.Where())
		}
	case fill != nil:
		// the readback found the filter holding want, so the fill sends what differs from it
		if fillErr := f.be.Fill(rules, want, fill); fillErr != nil {
			if !errors.As(fillErr, new(refused)) {
				// the fill may have committed, so the next read compares the host with the sets
				f.written = nil
			}
			err = fmt.Errorf("fill sets: %w", fillErr)
		} else {
			wrote, f.written = "sets", sets
		}
	}
	if err == nil && wrote != "" {
		generation = f.be.generation()
		if read, err = f.be.Rules(rules, sets); err != nil {
			err = fmt.Errorf("list rules: %w", err)
		}
	}
	installed := read.rules
	f.cleanGeneration = 0
	switch {
	case err != nil:
		f.setReady(false, "a pass failed: "+err.Error())
	case read.fault != "":
		f.setReady(false, read.fault)
	case read.unready != "":
		f.setReady(false, read.unready)
	default:
		f.setReady(true, "")
		f.cleanGeneration = generation
	}
	if err == nil && read.fault == "" {
		f.setNone(none)
	}
	holding := f.report(kept)
	f.retryOnFault = read.fault != "" && (holding || skipped)
	f.last = rules
	count := len(installed)
	if skipped && wrote == "" {
		// a fill that failed with no read before it reports the count the last read
		// found, wrong where another writer has changed the chains since, until the
		// retry reads a second later
		count = f.stats.Load().Installed
	}
	stats := egress.BorderStats{At: time.Now(), Ready: f.ready, Unready: f.unready, Installed: count, Dropped: f.dropped, Kinds: dropKinds(rules), CarveOuts: carveOuts, Sets: f.be.readings(sets), PF: read.pf}
	if err != nil {
		stats.Err = err.Error()
	} else {
		stats.Dropped = f.countDrops(installed, rules)
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
		f.rt.Events.Emit("antispoof.pass", "", attrs...)
	}
	return err
}

// reportCarveOuts reports each carve-out that came since the last pass at
// warning and each that went at info, each with an event
func (f *BorderFilter) reportCarveOuts(now []egress.CarveOut) {
	for _, carveOut := range now {
		if !slices.Contains(f.carveOuts, carveOut) {
			slog.Warn("antispoof carves the overlay for a link that holds part of it", "link", carveOut.Link, "prefix", carveOut.Prefix)
			f.rt.Events.Emit("antispoof.carve", "", slog.String("link", carveOut.Link), slog.String("prefix", carveOut.Prefix.String()), slog.Bool("carved", true))
		}
	}
	for _, carveOut := range f.carveOuts {
		if !slices.Contains(now, carveOut) {
			slog.Info("antispoof no longer carves the overlay for a link", "link", carveOut.Link, "prefix", carveOut.Prefix)
			f.rt.Events.Emit("antispoof.carve", "", slog.String("link", carveOut.Link), slog.String("prefix", carveOut.Prefix.String()), slog.Bool("carved", false))
		}
	}
	f.carveOuts = now
}

// reportConflicts reports each exemption another node's prefix, or a range of
// this node's own that another router announces too, came to overlap since the
// last pass, once, at warning with an event, and each conflict that ended at
// info. A conflict is its exemption, the prefix and the part carved, as a
// carve-out is its link and its prefix, so the prefix's route or offer moving
// to another peer or router-id reports nothing.
func (f *BorderFilter) reportConflicts(now []egress.ExemptConflict) {
	drops := func(list []egress.ExemptConflict, conflict egress.ExemptConflict) bool {
		return slices.ContainsFunc(list, func(other egress.ExemptConflict) bool {
			return other.Exemption == conflict.Exemption && other.Prefix == conflict.Prefix && other.Carved == conflict.Carved
		})
	}
	for i, conflict := range now {
		// two routes to one prefix from different sources are one drop
		if drops(f.conflicts, conflict) || drops(now[:i], conflict) {
			continue
		}
		attrs := []slog.Attr{
			slog.String("exemption", conflict.Exemption.Prefix.String()), slog.String("interface", conflict.Exemption.Interface),
			slog.String("prefix", conflict.Prefix.String()),
		}
		message := "antispoof admits this node's range though another router announces it too"
		if !conflict.Own {
			attrs = append(attrs, slog.String("carved", conflict.Carved.String()), slog.String("routed_via", conflict.Via))
			message = "antispoof drops part of an exemption, since another node's prefix holds it"
		}
		attrs = append(attrs, slog.String("router_id", conflict.RouterID))
		slog.LogAttrs(context.Background(), slog.LevelWarn, message, attrs...)
		f.rt.Events.Emit("antispoof.conflict", "", append(attrs, slog.Bool("own", conflict.Own))...)
	}
	for i, conflict := range f.conflicts {
		if drops(now, conflict) || drops(f.conflicts[:i], conflict) {
			continue
		}
		message := "antispoof no longer drops part of an exemption for another node's prefix"
		if conflict.Own {
			message = "antispoof no longer sees another router announce this node's range"
		}
		slog.Info(message, "exemption", conflict.Exemption.Prefix, "interface", conflict.Exemption.Interface, "prefix", conflict.Prefix)
	}
	f.conflicts = now
}

// countDrops reads the counters of the drops the filter holds and, at most
// once per pass, records the packets each drop took since the last pass when
// one moved
func (f *BorderFilter) countDrops(installed []Installed, desired []BorderRule) egress.BorderDrops {
	rules := make(map[string]BorderRule, len(desired))
	for _, rule := range desired {
		rules[rule.String()] = rule
	}
	var now egress.BorderDrops
	for _, reading := range installed {
		if rule, ok := rules[reading.Spec]; ok {
			addDrops(&now, rule, reading.Packets)
		}
	}
	moved := dropsSince(now, f.dropped)
	f.dropped = now
	if moved != (egress.BorderDrops{}) {
		f.rt.Events.Emit("antispoof.dropped", "", dropAttrs(moved, dropKinds(desired))...)
	}
	return now
}

// setReady logs and records the filter's readiness when it moved, with detail
// saying why it is not ready
func (f *BorderFilter) setReady(ok bool, detail string) { f.setReadyAt(ok, detail, slog.LevelWarn) }

// stopping records the filter not ready at a stop, which is no fault, so it
// logs the transition at info, and ends the route source's watch
func (f *BorderFilter) stopping() {
	f.end()
	f.setReadyAt(false, "the antispoof filter is stopping", slog.LevelInfo)
}

// setReadyAt is setReady logging a transition to not ready at level
func (f *BorderFilter) setReadyAt(ok bool, detail string, level slog.Level) {
	f.unready = ""
	if !ok {
		f.unready = detail
	}
	if ok == f.ready {
		return
	}
	f.ready = ok
	if ok {
		slog.Info("antispoof filter ready", "where", f.Where())
	} else {
		slog.Log(context.Background(), level, "antispoof filter not ready", "where", f.Where(), "detail", detail)
	}
	f.rt.Events.Emit("antispoof.ready", "", slog.Bool("ready", ok))
}

// Debug reads current rule counters rather than reusing the last pass's
// readings.
func (f *BorderFilter) Debug() egress.BorderDebug {
	stats := f.Stats()
	out := egress.BorderDebug{Where: f.Where(), PassAt: stats.At, Ready: stats.Ready, Unready: stats.Unready, Sets: stats.Sets}
	rules, _, _ := f.desired()
	read, err := f.be.Read(rules)
	if err != nil {
		out.Err = err.Error()
	}
	if stats.PF != nil {
		state := *stats.PF
		if read.pf != nil {
			state.Enablers = read.pf.Enablers
		}
		out.PF = &state
	}
	listed := slices.Clone(read.rules)
	for _, rule := range rules {
		if len(out.Chains) == 0 || out.Chains[len(out.Chains)-1].Name != rule.Chain() {
			out.Chains = append(out.Chains, f.be.chain(rule.Chain()))
		}
		spec := rule.String()
		i := slices.IndexFunc(listed, func(reading Installed) bool {
			// pf reads one anchor and leaves its chain name empty
			return reading.Spec == spec && (reading.Chain == "" || reading.Chain == rule.Chain())
		})
		var reading Installed
		if i >= 0 {
			reading = listed[i]
			listed = slices.Delete(listed, i, i+1)
		}
		chain := &out.Chains[len(out.Chains)-1]
		chain.Rules = append(chain.Rules, egress.BorderReading{Spec: spec, Verdict: rule.Verdict(), Reason: rule.Reason(), Family: rule.Family(),
			Held: i >= 0, Packets: reading.Packets, Bytes: reading.Bytes})
	}
	var extra egress.BorderChainReading
	for _, reading := range listed {
		spec := reading.Spec
		verdict, _, _ := strings.Cut(spec, " ")
		if spec == "" {
			spec = "a rule with no comment"
		}
		extra.Rules = append(extra.Rules, egress.BorderReading{Spec: spec, Verdict: verdict, Held: true, Packets: reading.Packets, Bytes: reading.Bytes})
	}
	if len(extra.Rules) != 0 {
		out.Chains = append(out.Chains, extra)
	}
	return out
}

// readings is the sets by name, as nftables sets
func (s borderSets) readings() []egress.BorderSetReading {
	out := make([]egress.BorderSetReading, 0, len(s))
	for _, name := range slices.Sorted(maps.Keys(s)) {
		out = append(out, egress.BorderSetReading{Kind: "set", Name: name, Elements: slices.Clone(s[name])})
	}
	return out
}
