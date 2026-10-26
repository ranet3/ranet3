// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

// Package kernel translates the source address of a packet the mesh hands to
// this node and lets the host forward it by its ordinary routes. It is the one
// action behind an exit node and a subnet router: an exit advertises a default
// and a subnet router advertises the prefixes behind it, and both end at the
// same translation.
//
// # Ownership
//
// On linux the translation is an nftables table named after this tool, one per
// address family, holding one nat postrouting chain. That name is the ownership
// marker, the way Table.Proto is the reconciler's in internal/kernel. This
// package creates the table, writes only inside it and withdraws it whole at
// shutdown. It reads other writers' tables, chains and rules to find its own
// and to report conflicts, and writes, replaces or deletes nothing outside its
// own tables. A rule another writer puts in this package's chain is removed by
// the next pass. Other source translation already on the host is reported
// rather than fought over: several nat postrouting chains coexist at the same
// hook, the first to translate a connection wins it, and taking somebody else's
// rule away to win that race would break whatever put it there.
//
// A table a previous instance left behind carries the same name and is
// therefore adopted, then brought to the rules the configuration now asks for,
// exactly as a route carrying the reconciler's protocol is.
//
// Nothing here writes iptables. The two are separate registries on a modern
// host, an iptables-nft rule is visible here as an ordinary nftables table, and
// the conflicts everybody remembers between firewall managers are an iptables
// problem this package declines to join.
//
// # Refusing to advertise
//
// Babel carries no capability signal, so a node that advertises a prefix is
// promising to carry it and the only thing a peer learns is the advertisement.
// An exit whose rule will not install, or whose kernel will not forward, would
// therefore attract traffic and drop it with nothing to tell the sender. So the
// advertisement is published by this package rather than by the configuration:
// Announce answers the prefixes of each family that is ready, whose chain
// reads back as written, which the kernel forwards and whose route lookups
// take a translated packet's path, and nothing at all while no family is, and
// Republish says when that answer moves. Forwarding is the same fact
// internal/client warns about for transit, read from the same place, and acted
// on here because this end is the only one that knows.
//
// # The border filter
//
// An exit's allow list says which sources it carries out of the mesh, and
// it is authorization rather than a border: a host on any link of a forwarding
// node can send a packet with a mesh source into that node, which routes it
// into the mesh and on to the exit as if a mesh node had sent it. cap.border
// closes that. BorderFilter owns a second table of this tool's name, inet
// rather than ip and ip6, holding one filter chain at prerouting and priority
// raw, before conntrack, so a forged packet creates no connection entry. It
// accepts whatever arrives on a device inside the mesh, the tun and lo, then
// drops a source in the mesh's own prefixes, any routing header and this node's
// own SIDs as destinations, in that order, each drop counted. The routing header
// rule takes every type, since nf_tables finds only the first routing header of
// a packet, and one of type 0 or 2 would otherwise hide a type 4 header behind
// it. From Linux 7.1 the kernel's search for it gives up at the thirteenth
// extension header, so one behind twelve others passes, and a Linux host from
// 7.1 it is addressed to with seg6_enabled set still acts on a segment routing
// header there. That host's receive path drops a packet whose routing header
// sits further back. Before 7.1 neither search has a limit: the rule finds a
// routing header anywhere in the chain, and the host acts on one anywhere.
//
// It is a second owner beside Translator, with its own run goroutine, socket
// and change monitor, and neither writes, replaces or deletes the other's
// table. The filter keeps its table through `ranet3 down`, since it guards
// the host's links rather than the mesh, and withdraws it last at shutdown,
// after nothing routes into the tun. Its readiness is a condition of every
// family the egress segments carry, so an exit whose border is down stops
// egressing them until a pass puts it back.
package kernel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"ranet3.com/pkgs/ranet3/internal/egress"
)

// Runtime holds the values the command resolves at startup rather than the
// ones a file carries, kept beside the capability rather than inside it so
// that a generated or round-tripped one holds only the fields an operator can
// write.
type Runtime struct {
	// Interface is the mesh device, named as the kernel named it. A packet
	// arriving on it and leaving by another link is translated in each
	// advertised family, while one arriving on it and leaving by it again is
	// mesh transit and is left alone.
	Interface string
	// Steered is whether a local segment delivers to egress, writing its inner
	// packets to the mesh device. Both families are then translated, since
	// End.DT46 delivers either, whatever the advertised prefixes cover.
	Steered bool
	// MeshAddresses are the addresses this node carries on the mesh, which
	// "auto" resolves to for the return direction. They have to be unique per
	// node and routable within the mesh, which a mesh address already is. What
	// this node sends from one of them out of another link leaves under that
	// address's class.
	MeshAddresses []netip.Addr
	// Forwarding reports whether the host forwards, per family. It is supplied
	// rather than read here so that the node has one answer to the question
	// and not two: internal/client owns the reading.
	Forwarding func() (v4, v6 bool)
	// Lookup answers a pass's route lookups in one batch, and Sysctl reads a
	// setting under /proc/sys by its path there, the empty string where it
	// cannot. Both are supplied as Forwarding is, so this package makes no
	// system call of its own.
	Lookup func([]Lookup) ([]Answer, error)
	Sysctl func(path string) string
	// Members is the prefixes inside cap.border.overlay that this node's table
	// routes by the tun to other nodes, none of them overlapping one of this
	// node's own, read on each pass. A family's forward lookups read from a
	// member's address, and a family with no member skips them. Nil reads none.
	Members func() []netip.Prefix
	// Write is the mesh's tun writer, which Egress hands its frames to, so each
	// flow keeps its lane and its order and the host routes and translates what
	// the tun delivers
	Write func(frames [][]byte)
	// Hooks report what every exit reports. Republish is called once per pass
	// whose announcement differs from the last. A family is ready while this
	// node translates it, its chain reads back exactly as written, the host
	// forwards it, the host holds every address its classes translate to, and
	// the kernel's lookups route a translated packet and its reply the way the
	// translation needs (see judge). The SIDs are served while at least one
	// family is ready and every family the host forwards is.
	egress.Hooks
}

// Direction says which way through this node a packet is going, which decides
// both what the rule matches and what "auto" resolves to.
type Direction uint8

const (
	// Out is a packet the mesh handed this node, leaving by another link. The
	// reply has to come back to the link it left by, so the source is the one
	// this node's own routes would have used there.
	Out Direction = iota
	// In is a packet from behind this node, entering the mesh. The reply has
	// to come back through the mesh, so the source is this node's mesh
	// address.
	In
	// Local is a packet this node sends from one of its own mesh addresses,
	// leaving by another link, which takes its address's class's translation
	// as a leaf's packet from that address would. The drop of a packet no flow
	// is tracked for is the forward hook's, which meets forwarded packets alone.
	Local
)

func (d Direction) String() string {
	switch d {
	case In:
		return "in"
	case Local:
		return "local"
	}
	return "out"
}

// Rule is one translation this node installs, and simultaneously the diff key:
// the backend writes String into the rule's own comment and reads it back, so
// two rules with equal fields are the same rule whatever the kernel does to
// the expressions in between.
type Rule struct {
	Family    uint8
	Direction Direction
	// Interface is the mesh device the direction is relative to.
	Interface string
	// Source is the address to translate to. An invalid address means the
	// backend lets the host pick, which is nftables masquerade: the address of
	// the link the packet is leaving by, chosen per packet.
	Source netip.Addr
	// None binds the connection to the source it carries in place of a
	// translation, for a class of none, so no chain after this one at the hook
	// translates it. Source is then left invalid.
	None bool
	// From narrows a rule to the sources of one prefix: an In rule's advertised
	// prefix, an Out rule's class and a Local rule's own address. It is left
	// invalid for a prefix covering every address, which selects nothing
	// extra.
	From netip.Prefix
}

// String is the rule as an operator reads it in `nft list ruleset` and as the
// diff compares it. Every field that changes what the rule does is in it, so a
// changed source or prefix reads back as a different rule and is replaced.
func (r Rule) String() string {
	source := "masquerade"
	switch {
	case r.None:
		source = "untranslated"
	case r.Source.IsValid():
		source = "source " + r.Source.String()
	}
	parts := []string{r.Direction.String(), "via", r.Interface, egress.FamilyName(r.Family)}
	if r.From.IsValid() {
		parts = append(parts, "from", r.From.String())
	}
	return strings.Join(append(parts, source), " ")
}

// Installed is one rule as the backend read it back: the spelling it was
// written under, the family whose table it was read from and what it has
// carried since. The counters are outside the diff on purpose, because they
// change on every packet and a diff holding them would rewrite the ruleset on
// every pass.
type Installed struct {
	Spec string
	// Family places a rule another writer put in a chain, which reads back with
	// no spelling, in its family's readback. The border's one inet table leaves
	// it 0.
	Family  uint8
	Packets uint64
	Bytes   uint64
}

// chainReadback is nftables.Readback with each rule placed in its family. It
// lives here rather than there because this file builds on every platform.
type chainReadback struct {
	// rules is every rule of the chain in order, one carrying no comment as an
	// empty spec, which no rule this package writes has
	rules  []Installed
	fault  string
	remake bool
}

// backend is the kernel surface a translator drives. Everything above it is
// portable and syscall-free, so the diff and the refusal rules are testable
// against a fake.
type backend interface {
	// Rules reads back this tool's own chain and the table holding it in each
	// family it owns, keyed by family.
	Rules() (map[uint8]chainReadback, error)
	// Apply brings this tool's own chain to rules, deleting the table of each
	// family in remake first. It replaces the chain's contents in one
	// transaction rather than editing it, because nftables commits a batch
	// atomically and a chain rewritten rule by rule has a window in which a
	// packet leaves untranslated.
	Apply(rules []Rule, remake []uint8) error
	// Conflicts names the source translation already on the host that this
	// node's traffic could meet, for an operator rather than as a number.
	Conflicts() ([]string, error)
	// Withdraw removes this tool's own tables. A table that is already gone is
	// success.
	Withdraw() error
	// Changed carries one coalesced wake-up per batch of changes another
	// writer made to this tool's own tables, a deletion or an addition.
	Changed() <-chan struct{}
	// Missed carries one coalesced wake-up per batch of notifications the
	// backend lost or could not read, any of which may have been a change.
	Missed() <-chan struct{}
	Close() error
	// where names the space this backend owns, for a log line.
	where(egress.Egress) string
}

// passStats is one finished pass, which Status reports. Installed counts the
// rules the host holds for this translator once the pass has applied, and
// Announced the prefixes it is willing to advertise as a result.
type passStats struct {
	At        time.Time
	Desired   int
	Installed int
	// Flows counts the connections the rules have translated, and Bytes the
	// first packet of each. A nat chain is consulted once per connection and
	// never again, so neither is a packet count. Untranslated counts those the
	// rules of a class of none bound to their own source.
	Flows        uint64
	Bytes        uint64
	Untranslated uint64
	Announced    []netip.Prefix
	Conflicts    []string
	Err          string
	// Ready4 and Ready6 are each family's readiness, false for a family this
	// node does not translate. Unready says why a family it translates is not
	// ready, and Skipped what the lookups left out and why, each empty where
	// there is nothing to say
	Ready4, Ready6   bool
	Unready, Skipped string
}

// Translator owns the capability on one node: the rules, the tables they live
// in, and the advertisement that depends on both.
type Translator struct {
	cfg egress.Egress
	rt  Runtime
	be  backend

	// stats is the last pass as a reader takes it. The single run goroutine
	// publishes a whole value and a reader takes one, so this needs no lock
	// and a reader can never see half a pass.
	stats atomic.Pointer[passStats]
	// announced holds the prefixes Announce answers, stored before Republish
	// is called, so a pass that changes nothing does not republish and a
	// caller reading it directly gets the same answer the speaker has.
	announced atomic.Pointer[[]netip.Prefix]
	// warned holds the conflicts already reported, so a shared host costs one
	// log line per new conflict rather than one per pass.
	warned []string
	// trigger names what woke the run goroutine for the pass it runs, and belongs to that goroutine
	trigger string
	// enabled is whether this translator writes to the host at all, and wake
	// carries a change of it to the run goroutine. Both are touched from
	// outside that goroutine, and withdrawn is its own record of having acted
	// on a stop, as kernel.Reconciler keeps one.
	enabled   atomic.Bool
	wake      chan struct{}
	withdrawn bool
	// ready4, ready6 and serves hold what Ready was last given,
	// forwards4 and forwards6 the forwarding the last pass read, unready the
	// reason a family is not ready and skipped what its lookups left out, all
	// of them the run goroutine's
	ready4, ready6, serves bool
	forwards4, forwards6   bool
	unready, skipped       string
}

var _ egress.Exit = (*Translator)(nil)

// newTranslator is a translator over a backend that is already open, writing to the host until SetEnabled stops it
func newTranslator(cfg egress.Egress, rt Runtime, be backend) *Translator {
	t := &Translator{cfg: cfg, rt: rt, be: be, wake: make(chan struct{}, 1)}
	t.enabled.Store(true)
	return t
}

// SetEnabled stops or starts this translator while it runs, which a node
// taken off the mesh asks for. Stopping retracts the advertisement and then
// withdraws the tables, in the order Run's own exit takes, and starting puts
// them back on the next pass.
//
// The work runs on the run goroutine, which owns every field it touches. This
// records the request and wakes it, so a caller returns before the host has
// caught up and reads Status to see that it has.
func (t *Translator) SetEnabled(on bool) {
	t.enabled.Store(on)
	select {
	case t.wake <- struct{}{}:
	default:
	}
}

// Egress hands the frames to the mesh's tun writer, whose lanes keep each
// flow in order, and the host routes and translates what the tun delivers
func (t *Translator) Egress(frames [][]byte) { t.rt.Write(frames) }

// Status is the last pass, the capability's translation and the rules the
// host holds for this translator
func (t *Translator) Status() egress.Status {
	stats := t.lastPass()
	advertise := make([]netip.Prefix, 0, len(t.cfg.Advertise))
	for _, entry := range t.cfg.Advertise {
		advertise = append(advertise, entry.Prefix)
	}
	return egress.Status{
		Backend: "nftables", Where: t.where(),
		Ready4: stats.Ready4, Ready6: stats.Ready6, Unready: stats.Unready, Skipped: stats.Skipped,
		Advertise: advertise, Announced: stats.Announced,
		Translate: t.cfg.Translate, Return: t.cfg.Return,
		PassAt: stats.At, Err: stats.Err,
		Rules: &egress.Rules{Installed: stats.Installed, Flows: stats.Flows, Bytes: stats.Bytes, Untranslated: stats.Untranslated, Conflicts: stats.Conflicts},
	}
}

func (t *Translator) where() string { return t.be.where(t.cfg) }

// lastPass is the last pass, and the zero value before the first has run, which At tells apart
func (t *Translator) lastPass() passStats {
	if s := t.stats.Load(); s != nil {
		return *s
	}
	return passStats{}
}

// Announce is the prefixes this node may advertise right now: the configured
// list narrowed to the families that are ready, and nothing at all before the
// first pass has run. A caller announces from this rather than from the
// configuration, which is how an exit that cannot translate refuses to
// advertise rather than advertising and dropping.
func (t *Translator) Announce() []netip.Prefix {
	if prefixes := t.announced.Load(); prefixes != nil {
		return slices.Clone(*prefixes)
	}
	return nil
}

// Run reconciles until ctx is canceled, then withdraws the tables this
// translator owns and closes what the backend holds. It is called once.
//
// Run returns the withdrawal error, never a reconcile error: a failed pass is
// logged, costs the advertisement, and is retried.
func (t *Translator) Run(ctx context.Context) error {
	slog.Info("egress translator started", "interface", t.rt.Interface, "steered", t.rt.Steered, "where", t.where(),
		"advertise", len(t.cfg.Advertise))
	ticker := time.NewTicker(t.cfg.SweepInterval())
	defer ticker.Stop()
	retry := newRetryTimer(t.cfg.SweepInterval())
	defer retry.Stop()

	t.trigger = "start"
	for ctx.Err() == nil {
		if !t.enabled.Load() {
			// once per stop rather than once per wake, and a withdrawal that
			// failed is retried on the backoff a failed pass takes
			if !t.withdrawn {
				if err := t.stop(); err != nil {
					slog.Warn("egress could not withdraw its tables, retrying", "err", err, "retry_in", retry.failed())
				} else {
					t.withdrawn = true
					retry.passed()
				}
			}
		} else {
			// the record of a stop lasts until the next pass, whatever woke it
			if t.withdrawn {
				t.withdrawn = false
				slog.Info("egress translator started again", "where", t.where())
			}
			if err := t.reconcile(); err != nil {
				slog.Warn("egress pass failed, retrying", "err", err, "retry_in", retry.failed())
			} else {
				retry.passed()
			}
		}
		select {
		case <-ctx.Done():
		case <-ticker.C:
			t.trigger = "sweep"
		case <-retry.C:
			t.trigger = "retry"
		case <-t.wake:
			// SetEnabled wakes the loop whichever way it went
			t.trigger = "disable"
			if t.enabled.Load() {
				t.trigger = "enable"
			}
		case <-t.be.Changed():
			// the steered rule may be gone or bypassed already, so the mesh stops handing this exit its packets before the pass that puts it back
			t.trigger = "changed"
			const why = "another writer changed its table"
			t.setReady(false, false, why, why, "")
		case <-t.be.Missed():
			// another table's large transaction overflows the socket as readily as a flush of this one, so only the pass's readback decides
			t.trigger = "missed"
		}
	}
	// Readiness and the advertisement go before the rules do. A peer that
	// keeps selecting this node while its table is being taken down is a peer
	// whose traffic leaves untranslated, and babel's own retraction is the
	// only thing that can tell it otherwise.
	const why = "the translator is stopping"
	t.setReady(false, false, why, why, "")
	t.publish(nil)
	return errors.Join(t.withdraw(), t.be.Close())
}

func stopTimer(timer *time.Timer) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}

// retryTimer is a run loop's retry of a failed pass, on a backoff doubling
// from minRetryInterval up to the sweep, armed only while the backoff is set
type retryTimer struct {
	*time.Timer
	sweep, backoff time.Duration
}

func newRetryTimer(sweep time.Duration) *retryTimer {
	r := &retryTimer{Timer: time.NewTimer(sweep), sweep: sweep}
	stopTimer(r.Timer)
	return r
}

// failed arms the timer with the backoff doubled, which it returns
func (r *retryTimer) failed() time.Duration {
	r.backoff = min(max(2*r.backoff, minRetryInterval), r.sweep)
	stopTimer(r.Timer)
	r.Reset(r.backoff)
	return r.backoff
}

// passed disarms the timer and starts the backoff over
func (r *retryTimer) passed() {
	if r.backoff != 0 {
		r.backoff = 0
		stopTimer(r.Timer)
	}
}

// reconcile brings the host to the rules the configuration asks for and
// republishes what may be advertised as a result. The rules are compared
// before they are written, so a pass that changes nothing costs one readback
// and leaves the counters where they are.
func (t *Translator) reconcile() error {
	started := time.Now()
	desired := t.desired()
	applied := false
	read, err := t.be.Rules()
	held, faulted, remake := flatten(read)
	if err != nil {
		err = fmt.Errorf("list rules: %w", err)
	} else if faulted || !sameRules(held, desired) {
		if applyErr := t.be.Apply(desired, remake); applyErr != nil {
			err = fmt.Errorf("install rules: %w", applyErr)
		} else {
			applied = true
			slog.Info("egress rules installed", "rules", len(desired), "replaced", len(held), "where", t.where())
			// Read back rather than assumed. The counters below are the
			// host's, and a rule the kernel accepted under a spelling other
			// than the one asked for has to fail the readiness test rather
			// than pass it on this pass and fail on the next.
			if read, err = t.be.Rules(); err != nil {
				err = fmt.Errorf("list rules: %w", err)
			}
			held, _, _ = flatten(read)
		}
	}
	conflicts, conflictErr := t.be.Conflicts()
	err = errors.Join(err, conflictErr)
	t.reportConflicts(conflicts)

	// Readiness is per family and is read from the host on every pass rather
	// than captured at startup, because each part of it changes under a
	// running node: a table can be flushed by somebody else, a forwarding
	// sysctl can be turned on after this process started, and a route can send
	// a translated packet or its reply another way. A family's chain
	// counts only while it and its table read back exactly as written, since
	// another writer's rule among this tool's, a dormant table or a chain at
	// another hook, which an apply that failed leaves in place, changes what
	// the chain does to a packet.
	v4, v6 := t.rt.Forwarding()
	forwards := map[uint8]bool{egress.FamilyIPv4: v4, egress.FamilyIPv6: v6}
	unwritten := map[uint8]string{}
	for _, family := range []uint8{egress.FamilyIPv4, egress.FamilyIPv6} {
		switch {
		case read[family].fault != "":
			unwritten[family] = read[family].fault
		case !sameFamilyRules(held, desired, family):
			unwritten[family] = "its chain does not read back as written"
		}
	}
	judged := t.judge(unwritten, forwards)
	announced := make([]netip.Prefix, 0, len(t.cfg.Advertise))
	for _, entry := range t.cfg.Advertise {
		if judged[egress.AddressFamily(entry.Addr())].ready {
			announced = append(announced, entry.Prefix)
		}
	}
	t.forwards4, t.forwards6 = v4, v6
	j4, j6 := judged[egress.FamilyIPv4], judged[egress.FamilyIPv6]
	t.setReady(j4.ready, j6.ready, j4.why, j6.why, skippedText(j4, j6))
	moved := t.publish(announced)

	binding := map[string]bool{}
	for _, rule := range desired {
		binding[rule.String()] = rule.None
	}
	var flows, bytes, untranslated uint64
	for _, rule := range held {
		if binding[rule.Spec] {
			untranslated += rule.Packets
			continue
		}
		flows += rule.Packets
		bytes += rule.Bytes
	}
	stats := passStats{
		At: time.Now(), Desired: len(desired), Installed: len(held),
		Flows: flows, Bytes: bytes, Untranslated: untranslated,
		Announced: announced, Conflicts: conflicts,
		Ready4: t.ready4, Ready6: t.ready6, Unready: t.unready, Skipped: t.skipped,
	}
	if err != nil {
		stats.Err = err.Error()
	}
	t.stats.Store(&stats)
	if applied || moved || err != nil {
		attrs := []slog.Attr{slog.String("trigger", t.trigger), slog.Duration("took", time.Since(started)),
			slog.Int("installed", stats.Installed), slog.Int("announced", len(announced))}
		if err != nil {
			attrs = append(attrs, slog.String("err", stats.Err))
		}
		t.rt.Events.Emit("egress.pass", "", attrs...)
	}
	return err
}

// sameRules compares what the host holds against what the configuration asks
// for, by the spelling the backend reads back rather than by the expressions
// it encoded them into. Order counts: a chain is read top to bottom, and the
// counters are deliberately outside the comparison so that a pass does not
// rewrite the ruleset over a packet having arrived.
func sameRules(held []Installed, desired []Rule) bool {
	if len(held) != len(desired) {
		return false
	}
	for i, rule := range desired {
		if held[i].Spec != rule.String() {
			return false
		}
	}
	return true
}

// flatten is every family's rules in the order desired groups them, whether
// any family's table or chain reads back with a fault, and the families whose
// table Apply deletes and makes again
func flatten(read map[uint8]chainReadback) (held []Installed, faulted bool, remake []uint8) {
	for _, family := range []uint8{egress.FamilyIPv4, egress.FamilyIPv6} {
		held = append(held, read[family].rules...)
		faulted = faulted || read[family].fault != ""
		if read[family].remake {
			remake = append(remake, family)
		}
	}
	return held, faulted, remake
}

// sameFamilyRules is sameRules over family's table alone, so a rule another
// writer put in one family's chain leaves the other family's readback whole
func sameFamilyRules(held []Installed, desired []Rule, family uint8) bool {
	held = slices.DeleteFunc(slices.Clone(held), func(rule Installed) bool { return rule.Family != family })
	desired = slices.DeleteFunc(slices.Clone(desired), func(rule Rule) bool { return rule.Family != family })
	return sameRules(held, desired)
}

// desired is the rules this configuration asks for, grouped by family and
// then in the order a packet meets them within one chain. The grouping is not
// presentation: each family is a table of its own, so a backend reads them back
// one family at a time, and a list ordered any other way would never compare
// equal to its own readback and would be rewritten on every pass forever.
//
// Within a family the Out rules come first, a rule per class in the order
// Classes gives, the longest From first, since a chain reads top to bottom and
// the first translation ends it. Where no class covers every source, a rule of
// auto for the rest ends them. The In rules follow, then one Local rule per
// mesh source of the family under its class, which no packet arriving on the
// mesh device reaches past the Out rules.
func (t *Translator) desired() []Rule {
	var out []Rule
	for _, family := range t.cfg.Translated(t.rt.Steered) {
		covered := false
		for _, class := range t.cfg.Classes(family) {
			rule := t.rule(family, Out, class.To)
			// A prefix covering every address narrows nothing, and a rule
			// carrying it would encode a mask no packet fails, so it is left off
			// and the rule selects on the direction alone.
			if class.From.Bits() > 0 {
				rule.From = class.From.Prefix
			}
			covered = covered || class.From.Bits() == 0
			out = append(out, rule)
		}
		if !covered {
			out = append(out, t.rule(family, Out, egress.Translation{Auto: true}))
		}
		out = append(out, t.inbound(family)...)
		for _, address := range egress.MeshSources(family, t.rt.MeshAddresses) {
			rule := t.rule(family, Local, t.cfg.ClassOf(address).To)
			rule.From = netip.PrefixFrom(address, address.BitLen())
			out = append(out, rule)
		}
	}
	return out
}

// rule is the rule of family and direction translating as to says
func (t *Translator) rule(family uint8, direction Direction, to egress.Translation) Rule {
	return Rule{Family: family, Direction: direction, Interface: t.rt.Interface, Source: to.Addr, None: to.None}
}

// inbound is family's In rules, one per advertised prefix of the family, and
// none without return
func (t *Translator) inbound(family uint8) []Rule {
	// Resolved again rather than remembered, and its error dropped, because New
	// refused every advertised family that cannot answer it and a family
	// advertising nothing has no prefix to write a rule for.
	source, err := t.cfg.ReturnSource(family, t.rt.MeshAddresses)
	if err != nil || !source.IsValid() {
		return nil
	}
	var out []Rule
	for _, prefix := range t.cfg.Advertise {
		if egress.AddressFamily(prefix.Addr()) != family {
			continue
		}
		rule := Rule{Family: family, Direction: In, Interface: t.rt.Interface, Source: source}
		if prefix.Bits() > 0 {
			rule.From = prefix.Prefix
		}
		out = append(out, rule)
	}
	return out
}

// publish hands the announcement to the caller, and only when it changed. A
// republish rebuilds the speaker's originated set, which an unchanged pass
// every thirty seconds has no reason to do.
//
// it reports whether the announcement moved
func (t *Translator) publish(prefixes []netip.Prefix) bool {
	previous := t.announced.Load()
	if previous != nil && slices.Equal(*previous, prefixes) {
		return false
	}
	stored := slices.Clone(prefixes)
	t.announced.Store(&stored)
	if previous != nil {
		// Said out loud on every transition, because a prefix silently leaving
		// the advertisement is a customer's exit node going away and the
		// counters alone would not name it.
		slog.Warn("egress advertisement changed", "prefixes", len(prefixes),
			"was", len(*previous), "detail", "a family is advertised only while it is ready, as ranet3 status says")
	}
	if t.rt.Republish != nil {
		t.rt.Republish()
	}
	return true
}

// setReady records each family's readiness, why a family is not ready and
// what the lookups skipped. Ready is told when either family or whether the
// SIDs are served moves, and the egress.ready event is recorded when any of
// them or the skip does
func (t *Translator) setReady(v4, v6 bool, why4, why6, skipped string) {
	t.unready = unreadyText(v4, v6, why4, why6)
	// a leaf reads the SID's /128 as the exit's liveness, so a family the host forwards and cannot carry out withdraws it
	serves := (v4 || v6) && (v4 || !t.forwards4) && (v6 || !t.forwards6)
	moved := v4 != t.ready4 || v6 != t.ready6 || serves != t.serves
	if !moved && skipped == t.skipped {
		return
	}
	for _, family := range []struct {
		family     uint8
		was, ready bool
		why        string
	}{{egress.FamilyIPv4, t.ready4, v4, why4}, {egress.FamilyIPv6, t.ready6, v6, why6}} {
		switch {
		case family.was == family.ready:
		case family.ready:
			slog.Info("egress ready", "family", egress.FamilyName(family.family))
		default:
			slog.Warn("egress not ready", "family", egress.FamilyName(family.family), "detail", family.why)
		}
	}
	t.ready4, t.ready6, t.serves, t.skipped = v4, v6, serves, skipped
	if moved && t.rt.Ready != nil {
		t.rt.Ready(v4, v6, serves)
	}
	t.rt.Events.Emit("egress.ready", "", slog.Bool("ipv4", v4), slog.Bool("ipv6", v6), slog.Bool("sid", serves),
		slog.String("reason", t.unready), slog.String("skipped", skipped))
}

// unreadyText is why the families not ready are not, a family this node does
// not translate giving no reason, and each reason named by its family where
// both families are not ready
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

// reportConflicts names other source translation on this host once per new
// entry. It is a report rather than an action: several nat postrouting chains
// coexist, the first to translate a connection wins it, and taking another
// writer's rule away to win that race would break whatever installed it.
func (t *Translator) reportConflicts(conflicts []string) {
	for _, conflict := range conflicts {
		if slices.Contains(t.warned, conflict) {
			continue
		}
		slog.Warn("egress is sharing the source translation hook with another writer",
			"other", conflict,
			"detail", "the first chain to translate a connection keeps it, so a flow this node meant to translate may leave under that writer's address instead")
	}
	t.warned = slices.Clone(conflicts)
}

// stop retracts the advertisement and withdraws the tables, in the order Run's
// exit takes, and records the pass. The pass reads zero installed, so a
// diagnostic does not go on reporting the rules of the last pass that ran.
func (t *Translator) stop() error {
	started := time.Now()
	const why = "the translator is stopped"
	t.setReady(false, false, why, why, "")
	t.publish(nil)
	err := t.withdraw()
	stats := passStats{At: time.Now()}
	attrs := []slog.Attr{slog.String("trigger", t.trigger), slog.Duration("took", time.Since(started)),
		slog.Int("installed", 0), slog.Int("announced", 0)}
	if err != nil {
		stats.Err = err.Error()
		attrs = append(attrs, slog.String("err", stats.Err))
	}
	t.stats.Store(&stats)
	t.rt.Events.Emit("egress.pass", "", attrs...)
	return err
}

// withdraw removes the tables this translator owns. It is best effort by
// construction: the caller usually stops the mesh at the same moment, and a
// table that is already gone is not an error.
func (t *Translator) withdraw() error {
	if err := t.be.Withdraw(); err != nil {
		return fmt.Errorf("withdraw %s: %w", t.where(), err)
	}
	slog.Info("egress translator withdrawn", "where", t.where())
	return nil
}
