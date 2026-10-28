// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

// Package kernel mirrors the mesh forwarding table into the host's routing
// table, taking over from the BIRD kernel protocols a ranet deployment runs
// today. It is a one-way reconciler: internal/netstack keeps owning the
// forwarding decision and this package only teaches the kernel which packets
// to hand to the TUN, so every route it installs points at the device, but
// for the holds and throw routes on linux, which name no device of the
// mesh's, an IPv6 one dumping lo, and the peer in a snapshot entry never
// selects a kernel next hop.
//
// # Ownership
//
// On linux, every route this package installs lives in the table cap.table
// names and carries its rt_proto, and each points out of the mesh device but
// for the holds and throw routes, which name no device of the mesh's, an IPv6
// one dumping lo. Those together are the ownership marker. darwin has neither
// tables nor rt_proto, so ownership there is the interface and the shape of
// the route. See platform_darwin.go. The reconciler reads back only routes
// matching that marker, deletes only routes it read back that way, and stamps
// rtm_protocol on every RTM_DELROUTE so the kernel itself refuses to remove a
// route belonging to another protocol. The policy rules it writes are the ones
// it derives, each carrying the same rt_proto as FRA_PROTOCOL, and it reads
// back and deletes only those. It never touches another table, a route written
// by another protocol, a route out of another device, a policy rule of another
// protocol, a neighbor entry, or anything at all in the main table. Routes a
// previous instance of this process left behind carry the same marker and are
// therefore adopted, then withdrawn on the first pass if the mesh no longer
// wants them.
//
// Installation asks for the route exclusively, so a key another writer already
// holds in that table is left alone and reported once rather than taken
// over. A replace compares neither rtm_protocol nor the route type, so it
// would take the route another writer holds at that key. Give the reconciler a
// table no other daemon writes all the same, or the routes it declines to
// fight over are routes the mesh wanted.
//
// Addresses are narrower still. Only an address this reconciler added itself,
// in this process lifetime, is ever removed again, while an address that was
// already on the link belongs to whoever put it there.
//
// # Failure
//
// Every step reports its netlink errors rather than swallowing them, and a
// failed pass is retried with capped exponential backoff. The steps are
// independent, so one failing step never skips the others. Every apply is
// idempotent and every pass recomputes the difference against a fresh kernel
// dump, so a pass that fails halfway leaves the kernel in a state the next
// pass repairs.
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
	"sync/atomic"
	"time"

	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/sadr"
	"ranet3.com/pkgs/ranet3/schema"
)

const (
	// reservedTable and lastByteTable bracket the rtnetlink table numbers the
	// kernel keeps for itself: 253 default, 254 main, 255 local. Named here
	// rather than taken from unix.RT_TABLE_DEFAULT because this file builds on
	// darwin too.
	reservedTable = 253
	lastByteTable = 255
	// protocolStatic is RTPROT_STATIC, which systemd-networkd stamps on every
	// route and rule it installs. It is the highest protocol number this
	// reconciler must not claim, and it is named here for the same reason the
	// tables above are.
	protocolStatic = 4
	// defaultIPv6Metric is IP6_RT_PRIO_USER, what the kernel stamps on an
	// IPv6 route that arrives without RTA_PRIORITY. The reconciler sends it
	// explicitly instead, so a dump reports back exactly what it installed.
	defaultIPv6Metric = 1024
)

// ErrUnsupported is a platform's refusal of what it does not implement, New and
// WatchNetwork everywhere but linux and darwin, DumpRules and RouteGetBatch
// everywhere but linux, and the route lookups RouteGet does not make
var ErrUnsupported = errors.New("kernel: unsupported on this platform")

// errRouteSkipped distinguishes a route that was deliberately not installed
// from one that was, and from a transient failure. It covers a route the
// platform cannot represent and a key another writer already holds. The
// reconciler neither counts it as added nor retries with backoff: counting it
// would report the opposite of what the kernel holds, and backing off would
// stand down over something no retry can fix. The install is still attempted
// on the next pass, because the route stays in the diff until it is there.
var errRouteSkipped = errors.New("kernel: route was not installed")

// Table is the cap.table capability, parsed straight out of the file: the
// routing table this reconciler owns and everything it writes into it.
// Writing the block turns the reconciler on, so a deployment configuring its
// routes externally writes no cap.table and gets no reconciler. Every field is checked by Validate, which the loader calls, and
// again by New and by SetTable on a reload.
type Table struct {
	// ID is the routing table the reconciler owns. The fleet uses 200, the
	// table its policy rules and its End.DT46 look up. Zero uses DefaultTable.
	ID schema.TableID `yaml:"id,omitempty" json:"id,omitempty" toml:"id,omitempty"`
	// Proto is the rt_proto stamped on every installed route, and the marker
	// separating this reconciler's routes from everyone else's. Zero uses
	// DefaultProtocol.
	Proto uint8 `yaml:"proto,omitempty" json:"proto,omitempty" toml:"proto,omitempty"`
	// Metric is RTA_PRIORITY. Zero takes the kernel's own default, which is 0
	// for IPv4 and 1024 for IPv6. Do not set it to BIRD's 32 while BIRD is
	// still exporting to the same table: both daemons would then key on the
	// same prefix and priority, and since an install refuses a key another
	// writer holds rather than taking it over, whichever daemon got there
	// first keeps the prefix and the other loses it quietly.
	Metric uint32 `yaml:"metric,omitempty" json:"metric,omitempty" toml:"metric,omitempty"`
	// Addresses are assigned to the device when absent and removed again at
	// shutdown or when a reload stops assigning them. Only addresses the
	// reconciler added itself are ever removed.
	Addresses []schema.Prefix `yaml:"addresses,omitempty" json:"addresses,omitempty" toml:"addresses,omitempty"`
	// AssignAnnounced assigns every prefix cap.route announces as well, which
	// is the locally originated address an operator otherwise configures by
	// hand. A default is announced and never assigned, so it is skipped.
	AssignAnnounced bool `yaml:"assign_announced,omitempty" json:"assign_announced,omitempty" toml:"assign_announced,omitempty"`
	// Reconcile is the periodic sweep correcting drift nothing announced.
	// Zero uses DefaultReconcileInterval.
	Reconcile schema.Duration `yaml:"reconcile,omitempty" json:"reconcile,omitempty" toml:"reconcile,omitempty"`
	// CaptureGrace is how long a route that would carry this machine's own
	// traffic, an announced default above all, stays installed after the last
	// live session went away. Such a route is never installed before one has
	// been live and comes back on the next one, so this only sets how long a
	// node waits before falling back to its own uplink. Zero uses
	// DefaultCaptureGrace.
	CaptureGrace schema.Duration `yaml:"capture_grace,omitempty" json:"capture_grace,omitempty" toml:"capture_grace,omitempty"`
}

// Runtime holds what the reconciler reads from outside cap.table: the device
// the mesh actually got and the addresses this node's transport has to keep
// reaching, which only a running node knows, and what other capabilities
// write, the prefixes cap.route announces and cap.border's overlay among them.
type Runtime struct {
	// Interface is the TUN device every installed route points at, named as
	// the kernel named it (netstack.Mesh.Name, not the requested name).
	Interface string
	// Underlay names the addresses this node's own transport has to keep
	// reaching. The darwin backend asks once per pass and scopes a route that
	// covers one (see coversAny there). linux reads it never, and keeps the
	// underlay out with a socket mark instead. Nil decides scope on the
	// destination alone.
	Underlay func() []netip.Addr
	// Announced carries the prefixes cap.route announces, which
	// Table.AssignAnnounced puts on the device beside the addresses written
	// here, and one schema.CapturesTheMachine counts makes this node an exit.
	// SetTable replaces it on a reload.
	Announced []netip.Prefix
	// Overlay is cap.border's overlay, nil without the block, which
	// schema.CapturesTheMachine reads to tell a route that counts as a default
	// from a subnet. SetTable replaces it on a reload.
	Overlay []schema.Prefix
	// Advertised is the prefixes cap.egress advertises for the LANs behind
	// this node, masked, which the speaker originates beside cap.route's while
	// cap.egress stands behind them, and which are no prefixes of this node's
	// own. A reload never changes it, since it refuses every change of
	// cap.egress.
	Advertised []netip.Prefix
	// EgressSegment says cap.segment holds an egress segment, which makes this
	// node an exit. A reload never changes it, since it refuses adding the
	// first egress segment and removing the last.
	EgressSegment bool
	// BoundUnderlay is link.underlay.bind, which decides how the darwin
	// backend installs a route holding its family's zero address: unscoped,
	// as the zero-free cover's members it contains, rather than scoped out of
	// the reach of every socket that does not ask for the tun by name, which
	// is the difference between a node that can hold a mesh address and one
	// that can use a mesh exit. The underlay's datagrams name their interface
	// from the host's routes with the tun left out either way. Nothing reads
	// it on linux, where a socket mark and a policy rule keep the underlay off
	// the mesh and a default is installed unscoped either way. It is set from
	// link.underlay, so it is handed here rather than written in cap.table.
	BoundUnderlay bool
	// Sessions reports how many of this node's mesh sessions have recently
	// proved their peer is there. Until one has, and once none has for
	// Table.CaptureGrace, no route that would carry this machine's own
	// traffic is installed: see captureGate, which is the whole of why. Nil
	// installs every route the mesh announces as soon as it announces it,
	// which is right for a reconciler driven by something that has no
	// sessions. It is here rather than in the capability because no operator
	// writes it down.
	Sessions func() int
	// Endpoints reports the addresses the live sessions send their underlay
	// to now. Nil reports none
	Endpoints func() []netip.Addr
	// Host is the machine this reconciler reads and writes, nil for the one
	// this process is running on, as a daemon passes. A test hands
	// in a recorded routing table so the path from a configuration file to a
	// route on the wire can be run without a kernel (see Host). Only the darwin
	// backend reads it.
	Host Host
	// Events records every pass that changed the kernel, skipped a route it had not skipped before, followed a reload or failed
	// nil records nothing
	Events *events.Bus
}

// Assigned is every address the reconciler puts on the device: the ones
// written in the capability and, when it asks for them, the prefixes
// cap.route announces. It is exported because a segment this node answers for
// must not also be an address it carries, and that check spans two
// capabilities and so is made where the file is read.
//
// A default is announced, never assigned: an exit originates "::/0" from its
// transit prefix, and assigning it would try to put "::/0" on the device on
// every pass and fail on every one. The test is the address rather than the
// prefix length, because a prefix length says nothing about whether an address
// can be assigned. Validate refuses every other zero-length spelling.
func (t Table) Assigned(announced []netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	seen := make(map[netip.Prefix]bool)
	add := func(prefix netip.Prefix) {
		if !prefix.IsValid() || prefix.Addr().IsUnspecified() || seen[prefix] {
			return
		}
		seen[prefix] = true
		out = append(out, prefix)
	}
	for _, prefix := range t.Addresses {
		add(prefix.Prefix)
	}
	if t.AssignAnnounced {
		for _, prefix := range announced {
			add(prefix)
		}
	}
	return out
}

// Validate refuses a capability this reconciler could not honor, naming the
// field as the operator wrote it. It runs where the file is read, so a node
// that has no reconciler on this platform still refuses a table it could not
// have owned.
func (t Table) Validate() error {
	if t.Proto != 0 && t.Proto <= protocolStatic {
		// rtnetlink reserves 0 through 3 for unspec, redirect, kernel and
		// boot, and 4 is the static protocol systemd-networkd stamps on the
		// rules it installs. Claiming any of them makes this reconciler's
		// routes indistinguishable from somebody else's, and since a rule pass
		// deletes every rule carrying this protocol that it does not derive and
		// could have written, claiming 4 deletes every such static rule on the
		// host.
		return fmt.Errorf("kernel: cap.table proto %d is reserved for the kernel and for networkd, use 5 through 255", t.Proto)
	}
	if id := uint32(t.ID); id >= reservedTable && id <= lastByteTable {
		// rtnetlink reserves 253, 254 and 255 for default, main and local, and
		// nothing above 255 at all: the linux backend sends RT_TABLE_UNSPEC
		// plus a 32-bit RTA_TABLE for those, which is how a table id like
		// 51820 reaches the kernel. Nothing else here would refuse a route in
		// main, and an announced default is installed unscoped on linux, so
		// the reconciler would put the whole machine's default out of the tun
		// and take the ESP underlay with it. collectForeignWriters also leaves
		// the kernel's own entries in main out of its report, and that report
		// is the one warning that would have said so.
		return fmt.Errorf("kernel: cap.table id %d is reserved, use anything else from 1 to %d", id, ^uint32(0))
	}
	for i, prefix := range t.Addresses {
		// An entry left at zero, or an address under a length it cannot
		// carry, has no spelling, so a capability built with one renders to a
		// file nothing loads. Assigned skipped it without a word.
		if !prefix.IsValid() {
			return fmt.Errorf("kernel: cap.table addresses entry %d is not a prefix", i+1)
		}
		// Assigning the unspecified address is not something an interface can
		// do, and Assigned skips it, so taking the entry and dropping it
		// silently is the one outcome that tells the operator nothing.
		if prefix.Addr().IsUnspecified() {
			return fmt.Errorf("kernel: cap.table addresses %s is not an address an interface can carry", prefix)
		}
		// Its own message rather than the announcement's: an entry here is
		// assigned to an interface, never announced, so "write ::/0 if that is
		// what you mean" is advice the check above rejects.
		if prefix.Bits() == 0 {
			return fmt.Errorf("kernel: cap.table addresses %s has no prefix length, and an interface carries an address under one", prefix)
		}
	}
	if t.Reconcile < 0 {
		return fmt.Errorf("kernel: cap.table reconcile %s is not an interval", t.Reconcile)
	}
	if t.CaptureGrace < 0 {
		return fmt.Errorf("kernel: cap.table capture_grace %s is not an interval", t.CaptureGrace)
	}
	if t.CaptureGrace > 0 && t.CaptureGrace.Duration() < MinCaptureGrace {
		return fmt.Errorf("kernel: cap.table capture_grace %s is shorter than %s, which the reconciler cannot honor: the gate is sampled once a pass and a pass reads the routing table",
			t.CaptureGrace, MinCaptureGrace)
	}
	return nil
}

// RouteSource is the seam onto internal/netstack: one coalesced wake-up per
// batch of changes, and one consistent view per reconcile pass. Reconciling
// from snapshots rather than from an event stream lets a missed wake-up, a
// restart and outside interference all converge on the same state.
type RouteSource interface {
	Changed() <-chan struct{}
	Snapshot() []sadr.Route[*netstack.Peer]
}

// Route is one kernel route the reconciler manages, and simultaneously the
// diff key: the table, the protocol and the next hop are the same for every
// route it installs, so two routes with equal fields are the same route. The
// metric is in the key even though it comes from the configuration, because
// the kernel keys routes on it too: changing the configured metric has to withdraw
// the routes installed under the old one rather than leave them behind.
type Route struct {
	// Destination is canonical: masked and zoneless.
	Destination netip.Prefix
	// Source is RTA_SRC, invalid for an ordinary route. IPv6 only, because
	// the IPv4 FIB has no source-specific lookup.
	Source netip.Prefix
	// Metric is RTA_PRIORITY as the kernel holds it, never the zero that
	// means "your default" on the way in.
	Metric uint32
	// Scoped is set by the darwin backend on a route the kernel keys by
	// interface scope as well as by destination, so a withdrawal can name the
	// one it read back rather than re-deriving it. An unscoped route and a
	// scoped one to the same destination are different keys, and deleting by
	// destination alone removes whichever the flag happens to select.
	Scoped bool
	// Unreachable holds a prefix rather than carrying it, as
	// RFC 8966 section 3.5.4 requires of a retracted route until it is
	// flushed. Without it the entry leaves the table and a packet for that
	// prefix follows a shorter one instead, which on a node holding a default
	// is straight back out to the neighbor that just retracted it.
	Unreachable bool
	// Throw is RTN_THROW, which ends the lookup in this table with no answer,
	// so the rule walk goes on to the next rule. It is never set with
	// Unreachable.
	Throw bool
	// Cover marks a member of the zero-free cover a zero route goes in as (see
	// coverDefaults). It is never scoped, and a dump reads it back only for a
	// member this process installed.
	Cover bool
}

func (r Route) String() string {
	kind := ""
	if r.Unreachable {
		kind = " unreachable"
	}
	if r.Throw {
		kind = " throw"
	}
	if r.Cover {
		kind = " cover"
	}
	if r.Source.IsValid() {
		return fmt.Sprintf("%s from %s metric %d%s", r.Destination, r.Source, r.Metric, kind)
	}
	return fmt.Sprintf("%s metric %d%s", r.Destination, r.Metric, kind)
}

// auditor is implemented by a platform that can report other writers in the
// space this reconciler is about to take over. A platform that cannot answer
// does not implement it.
type auditor interface {
	// foreignWriters returns each protocol already writing into the space,
	// labeled for an operator rather than numbered, since the numbering is
	// the platform's own registry.
	foreignWriters() ([]string, error)
}

// ruler is implemented by a platform that has a policy routing engine. linux
// has FIB rules and 2^32 tables. darwin has one FIB and neither. A mobile
// tunnel provider is handed a list of routes to include and exclude and never
// sees a table at all. A platform without one does not implement this, and its
// reconciler writes no rule and leaves out the routes only a rule reads: the
// throw rows and the overlay holds.
//
// What the rules express is portable even where the mechanism is not: the
// underlay set apart, on linux by a mark the derived rules read, and the
// overlay and this node's own sources sent into the mesh, as routing.md's
// "Where a lookup ends on Linux" gives. darwin installs a source-specific route
// only where its source prefix holds an address of the tun, and that one, and
// without link.underlay.bind every route schema.CapturesTheMachine counts,
// scoped to the tun instead, which keeps them off every unbound socket. See
// the platform notes in pkgs/raweb3/pages/docs/platforms.md.
type ruler interface {
	// Rules returns only the rules carrying this reconciler's protocol.
	Rules() ([]Rule, error)
	AddRule(Rule) error
	// DelRule treats a rule that is already gone as success.
	DelRule(Rule) error
}

// looker is implemented by a platform that answers route lookups in the
// namespace it writes, as RouteGetBatch does, which is linux alone
type looker interface {
	lookups([]RouteRead) ([]BatchAnswer, error)
}

// platform is the kernel surface the reconciler drives. Everything above it is
// portable and syscall-free, so the diff is testable against a
// fake kernel.
type platform interface {
	// Routes returns only the routes carrying the reconciler's protocol, in
	// its table, out of its interface.
	Routes() ([]Route, error)
	// where names the space this platform gives a reconciler to own.
	where(Table) string

	AddRoute(Route) error
	// DelRoute treats a route that is already gone as success.
	DelRoute(Route) error
	// Addrs returns every address on the interface, whoever put it there.
	Addrs() ([]netip.Prefix, error)
	AddAddr(netip.Prefix) error
	DelAddr(netip.Prefix) error
	// Notify carries one coalesced wake-up per batch of kernel notifications
	// touching what the reconciler holds: on linux a route in its table or a
	// deleted rule of its protocol, on darwin a route of its interface.
	Notify() <-chan struct{}
	// retable takes the capability a reload installed, on the id and proto the platform was opened with
	retable(Table)
	Close() error
}

// Rule is one policy rule the reconciler derives, in one family. It is
// compared with ==, so every field is part of the key: the kernel matches a
// delete against the selectors it is given, and two rules differing in any of
// them are two entries, but for a goto's target, the invert flag and an exact
// mark's mask spelled as all ones, which the kernel does not tell apart.
//
// A rule this reconciler owns looks up a table, jumps to a later priority or
// does nothing, so no rule of its own refuses an address, only an unreachable,
// blackhole or prohibit route of a table it looks up.
type Rule struct {
	// action is the rule's FR_ACT, a lookup in Table at its zero value
	action ruleAction
	// target is FRA_GOTO, the priority a goto jumps to, and zero for any other action.
	target uint32
	// suppress is FRA_SUPPRESS_PREFIXLEN, which refuses a lookup's answer of
	// that length or shorter, but never an unreachable, blackhole or prohibit
	// one.
	suppress Suppress
	// invert is FIB_RULE_INVERT, oif FRA_OIFNAME and l3mdev FRA_L3MDEV, which
	// no derived rule holds. A rule of this reconciler's protocol another writer
	// gave one reads back unequal to every derived rule, so the pass deletes it,
	// naming the device and the l3mdev the kernel compares on a delete. The
	// kernel compares no invert flag there, so where an inverted copy sits behind
	// the derived rule the delete takes the derived rule, and the next pass
	// deletes the copy and adds the derived rule back.
	invert bool
	oif    string
	l3mdev bool
	// To is FRA_DST and From is FRA_SRC, each optional
	To, From schema.Prefix
	// FWMark and FWMask are FRA_FWMARK and FRA_FWMASK. A zero mark means the
	// rule does not select on one, and a zero mask with a nonzero mark is an
	// exact match, which is how the kernel reads an absent FRA_FWMASK.
	FWMark, FWMask uint32
	// IIF is FRA_IIFNAME, the device a packet arrived on, empty for any
	IIF string
	// Table is the table a lookup reads
	Table schema.TableID
	// Priority is FRA_PRIORITY, the rule's position in the list
	Priority uint32
	Family   Family
}

// ruleAction is a rule's FR_ACT, as far as this reconciler writes one.
type ruleAction uint8

const (
	// actionLookup is FR_ACT_TO_TBL, a lookup in the rule's table.
	actionLookup ruleAction = iota
	// actionGoto is FR_ACT_GOTO, a jump to the rule's target.
	actionGoto
	// actionNop is FR_ACT_NOP, a rule a goto lands on.
	actionNop
)

// String is the action as `ip rule` spells it
func (a ruleAction) String() string {
	switch a {
	case actionGoto:
		return "goto"
	case actionNop:
		return "nop"
	}
	return "lookup"
}

// Suppress is a rule's FRA_SUPPRESS_PREFIXLEN. The zero value suppresses
// nothing, which the kernel holds as -1 and tells apart from a length of 0.
type Suppress struct {
	set  bool
	bits uint32
}

// SuppressUpTo refuses a lookup's answer whose prefix is bits long or shorter,
// but never an unreachable, blackhole or prohibit one.
func SuppressUpTo(bits int) Suppress { return Suppress{set: true, bits: uint32(bits)} }

// Bits is the length, and whether the rule suppresses at all.
func (s Suppress) Bits() (int, bool) { return int(s.bits), s.set }

// Family is an address family, spelled as `ip -4` and `ip -6` name it rather
// than as AF_INET and AF_INET6, which are numbers on one platform and absent
// on the others.
type Family string

const (
	FamilyIPv4 Family = "ipv4"
	FamilyIPv6 Family = "ipv6"
)

// String is the rule as `ip rule` spells it, with its family, which is how
// every log line names one. The table is spelled by name where the kernel
// reserves one, and the family is there because a message about two rules
// that differ only in it identifies neither without it.
func (r Rule) String() string {
	parts := []string{fmt.Sprintf("priority %d", r.Priority)}
	if r.invert {
		parts = append(parts, "not")
	}
	if r.From.IsValid() {
		parts = append(parts, "from "+r.From.String())
	}
	if r.To.IsValid() {
		parts = append(parts, "to "+r.To.String())
	}
	if r.FWMark != 0 {
		mark := fmt.Sprintf("fwmark %#x", r.FWMark)
		if r.FWMask != 0 {
			mark += fmt.Sprintf("/%#x", r.FWMask)
		}
		parts = append(parts, mark)
	}
	if r.IIF != "" {
		parts = append(parts, "iif "+r.IIF)
	}
	if r.oif != "" {
		parts = append(parts, "oif "+r.oif)
	}
	if r.l3mdev {
		parts = append(parts, "l3mdev")
	}
	parts = append(parts, "family "+string(r.Family))
	switch r.action {
	case actionGoto:
		parts = append(parts, fmt.Sprintf("%s %d", r.action, r.target))
	case actionNop:
		parts = append(parts, r.action.String())
	default:
		parts = append(parts, r.action.String()+" "+r.Table.String())
	}
	if bits, ok := r.suppress.Bits(); ok {
		parts = append(parts, fmt.Sprintf("suppress_prefixlength %d", bits))
	}
	return strings.Join(parts, " ")
}

// dumped is the rule as a dump of the kernel holding it reads, carrying proto:
// a mark with no mask matches every bit, which the kernel stores and dumps as
// a mask of all ones, and a goto or a nop reads no table
func (r Rule) dumped(proto uint8) DumpedRule {
	held := DumpedRule{
		Family: r.Family, Priority: r.Priority, To: r.To.Prefix, From: r.From.Prefix, IIF: r.IIF, OIF: r.oif,
		FWMark: r.FWMark, FWMask: r.FWMask, L3mdev: r.l3mdev, Invert: r.invert,
		Action: r.action.String(), Goto: r.target, Suppress: r.suppress, Protocol: proto,
	}
	if r.FWMark != 0 && r.FWMask == 0 {
		held.FWMask = ^uint32(0)
	}
	if r.action == actionLookup {
		held.Table = uint32(r.Table)
	}
	return held
}

func familyOf(address netip.Addr) Family {
	if address.Is4() {
		return FamilyIPv4
	}
	return FamilyIPv6
}

type Reconciler struct {
	// table is the capability with its defaults filled in, rt what the caller
	// resolved, and addresses what New or SetTable made of the two: the address
	// set the device is to carry.
	table     Table
	rt        Runtime
	addresses []netip.Prefix
	// derived is the rules the last rule pass derived, as another goroutine
	// reads them, and nil while the reconciler holds none
	derived atomic.Pointer[[]Rule]

	src  RouteSource
	plat platform

	// owned holds the addresses this reconciler put on the link, the only
	// ones it will ever take off again. An address a previous instance added
	// and left behind is not in here, so it stays: losing an address that
	// turns out to be somebody else's is worse than leaking one.
	owned map[netip.Prefix]bool
	// warnedAddrs is the addresses reported as held by somebody else under the
	// current pass, rotated the way warned is so a report costs one log line
	// rather than one per pass.
	warnedAddrs map[netip.Prefix]bool
	// warned holds the routes already reported as unrepresentable. It is
	// rebuilt from each pass, so it stays bounded by the snapshot.
	warned map[Route]bool
	// capturing says whether this pass left a capture installed, the only
	// state whose grace needs a wake-up of its own.
	capturing bool
	// cover is the families the last pass left covered, so a change is
	// reported once.
	cover []Family
	// memberless holds the zero routes a cover installs as nothing that the
	// last pass reported, rebuilt each pass, so a route the mesh keeps
	// announcing costs one log line
	memberless map[Route]bool

	// rules is the optional half of the platform, nil where it has no policy
	// engine
	rules ruler
	// look is the platform's lookups, nil where it answers none. lookups is
	// what the last pass whose batch answered found, lookFailed whether the
	// last batch failed, and installed what the kernel held for this
	// reconciler once the last route pass had applied. All four belong to the
	// reconcile goroutine
	look       looker
	lookups    []Lookup
	lookFailed bool
	installed  map[Route]bool

	// gate holds back the routes that would carry this machine's own traffic
	// until the mesh has proved it can carry them. Only the reconcile
	// goroutine touches it, and capture is its answer for the pass now
	// running, sampled once so every route of a pass is judged the same way.
	gate    captureGate
	capture bool
	// now is the clock the gate reads, replaced by a test that drives the
	// grace without sleeping through it.
	now func() time.Time

	// enabled is whether this reconciler is writing to the kernel at all, and
	// wake carries a change of it to the loop. Both are touched from outside
	// the reconcile goroutine, while withdrawn is the loop's own record of having
	// acted on a stop, and belongs to that goroutine like every field above.
	enabled   atomic.Bool
	wake      chan struct{}
	withdrawn bool
	// next is the capability SetTable accepted last, which reload wakes the loop to take
	next   atomic.Pointer[accepted]
	reload chan struct{}
	// inForce is table as another goroutine reads it, stored whole when the loop takes a capability
	inForce atomic.Pointer[Table]
	// reloaded says the pass under way follows a capability the loop took, and belongs to that goroutine
	reloaded bool

	// stats is the last route pass as an operator reads it. The single
	// reconcile goroutine publishes a whole value and a reader takes one, so
	// this needs no lock and a reader can never see half a pass.
	stats atomic.Pointer[Stats]
	// routePass holds the counts applyRoutes took, between that step and the
	// record reconcile makes of the whole pass. Only the reconcile goroutine
	// touches it.
	routePass Stats
	// trigger names what woke the reconcile goroutine for the pass it runs, and belongs to that goroutine
	trigger string
	// refused is the routes the last route pass wanted and the platform refused, and belongs to the same goroutine
	// a refused route is tried and refused on every pass, so refusedAnew marks the pass that refused one first
	refused     map[Route]bool
	refusedAnew bool
	// changed says the pass under way wrote a rule or an address, which the route counts do not show
	// it belongs to the same goroutine, and the withdrawal never sets it
	changed bool
}

// Stats is one finished route pass. Installed counts the routes the kernel
// holds for this reconciler once the pass has applied, and Skipped the ones it wanted
// and did not get: one the platform cannot represent, one whose key
// another writer or a route of this reconciler's that has not left yet
// holds, a cover member left out with the rest of
// its family, or a zero route inside 0.0.0.0/8 or ::/8, of which a cover
// installs nothing. A prefix the mesh has and the kernel does not
// is explained by Skipped or by Err and by nothing else.
type Stats struct {
	At        time.Time
	Desired   int
	Installed int
	Skipped   int
	Added     int
	Removed   int
	// Cover is the families in which this pass left a zero route installed as
	// its zero-free cover.
	Cover []Family
	// Lookups holds the lookups the last pass whose batch answered asked of
	// the kernel to find another program's rule ahead of the mesh's
	Lookups []Lookup
	Err     string
}

// Stats reports the last route pass, and the zero value before the first one
// has run. A caller that wants to tell those apart reads At.
func (r *Reconciler) Stats() Stats {
	if s := r.stats.Load(); s != nil {
		return *s
	}
	return Stats{}
}

// New checks the capability, fills in its defaults, resolves it against the
// runtime the caller supplies and opens the netlink sockets, so a
// misconfigured or unsupported deployment fails at startup rather than on the
// first route. It installs nothing. Run does that.
func New(t Table, rt Runtime, src RouteSource) (*Reconciler, error) {
	if rt.Interface == "" {
		return nil, errors.New("kernel: interface is required")
	}
	if src == nil {
		return nil, errors.New("kernel: route source is required")
	}
	// Checked as written and normalized afterward, so a refusal names the
	// field an operator can find in their own file. The loader has already run
	// this, but a caller that built the capability by hand has not.
	if err := t.Validate(); err != nil {
		return nil, err
	}
	t = t.Normalized()
	if rt.BoundUnderlay && rt.Sessions == nil {
		// The two halves of one arrangement. link.underlay.bind lets this
		// backend install an announced default where every socket can see
		// it, and the gate is the only thing that keeps such a route out
		// of the kernel until the mesh has proved it can carry traffic. With
		// no session source the gate is open from the first pass, so the two
		// together would put this machine's traffic in a tun nothing has ever
		// answered on.
		return nil, errors.New("kernel: link.underlay.bind needs a session source, or an announced default would install before the mesh has carried anything")
	}
	addresses, err := resolveAddresses(t, rt.Announced)
	if err != nil {
		return nil, err
	}
	plat, err := newPlatform(t, rt)
	if err != nil {
		return nil, err
	}
	return newReconciler(t, rt, addresses, src, plat), nil
}

// resolveAddresses is the address set a reconciler of t carries on the device, given the prefixes cap.route announces
func resolveAddresses(t Table, announced []netip.Prefix) ([]netip.Prefix, error) {
	addresses := make([]netip.Prefix, 0, len(t.Addresses))
	for _, prefix := range t.Assigned(announced) {
		if _, ok := canonicalPrefix(prefix); !ok {
			return nil, fmt.Errorf("kernel: address %s is not a valid prefix", prefix)
		}
		// an assigned address keeps its host bits and only a route key is masked
		addresses = append(addresses, netip.PrefixFrom(prefix.Addr().WithZone(""), prefix.Bits()))
	}
	return addresses, nil
}

// Normalized is the capability as the reconciler runs it: every field the file
// left out filled in with the default it stands for, and the addresses, which
// are assigned to one device and read as a set, in one order. A reload
// compares two capabilities through it rather than as they were written, so
// neither a field written out as its own default nor a second order of the
// addresses is a change. Leaving either out refuses a reload over nothing
// where the field is the id or the proto, or where no reconciler runs to take
// the block, and a restart drops every SA on the node.
func (t Table) Normalized() Table {
	if t.ID == 0 {
		t.ID = DefaultTable
	}
	if t.Proto == 0 {
		t.Proto = DefaultProtocol
	}
	if t.Reconcile <= 0 {
		t.Reconcile = schema.Duration(DefaultReconcileInterval)
	}
	if t.CaptureGrace <= 0 {
		t.CaptureGrace = schema.Duration(DefaultCaptureGrace)
	}
	if len(t.Addresses) == 0 {
		t.Addresses = nil
	} else {
		t.Addresses = slices.SortedFunc(slices.Values(t.Addresses), schema.ComparePrefix)
	}
	return t
}

// Unreloadable names the setting next changes that a reconciler running t keeps for its life, or is empty
// the platform reads the id and proto it was opened on
func (t Table) Unreloadable(next Table) string {
	t, next = t.Normalized(), next.Normalized()
	switch {
	case t.ID != next.ID:
		return "id"
	case t.Proto != next.Proto:
		return "proto"
	}
	return ""
}

func newReconciler(t Table, rt Runtime, addresses []netip.Prefix, src RouteSource, plat platform) *Reconciler {
	r := &Reconciler{
		table: t, rt: rt, addresses: addresses,
		src: src, plat: plat,
		owned:       make(map[netip.Prefix]bool),
		warnedAddrs: make(map[netip.Prefix]bool),
		warned:      make(map[Route]bool),
		gate:        captureGate{grace: t.CaptureGrace.Duration()},
		now:         time.Now,
		wake:        make(chan struct{}, 1),
		reload:      make(chan struct{}, 1),
	}
	r.enabled.Store(true)
	r.inForce.Store(&t)
	r.rules, _ = plat.(ruler)
	r.look, _ = plat.(looker)
	return r
}

// Where names the space this reconciler owns, for an operator reading a log
// line: a routing table where the platform has them, and the interface itself
// where it does not.
func (r *Reconciler) Where() string { return r.plat.where(r.Table()) }

// Table is the capability this reconciler is running, defaults applied. New
// takes its argument by value and fills the gaps in its own copy, so the
// caller's is not the one in force and a diagnostic reporting that one names a
// table of zero on every deployment that left it out.
func (r *Reconciler) Table() Table { return *r.inForce.Load() }

// DerivedRules is the rules the last rule pass derived, each as a dump of the
// kernel holding it reads, and none before the first pass, after a withdrawal
// or on a platform with no policy rules
func (r *Reconciler) DerivedRules() []DumpedRule {
	derived := r.derived.Load()
	if derived == nil {
		return nil
	}
	out := make([]DumpedRule, 0, len(*derived))
	for _, rule := range *derived {
		out = append(out, rule.dumped(r.Table().Proto))
	}
	return out
}

// SetEnabled stops or starts this reconciler while it runs, which is the
// `birdc disable` a kernel protocol took while Babel lived in BIRD. Stopping
// withdraws every route, address and rule it installed, and starting puts them
// back on the next pass, which is idempotent like every other pass. A table
// left holding routes nobody maintains is the state a stop exists to avoid,
// so the withdrawal is part of it rather than a separate ask.
//
// The withdrawal runs on the reconcile goroutine rather than here, because
// every field it touches belongs to that goroutine alone. This records the
// request and wakes the loop, so a caller returns before the kernel has
// caught up and reads Stats to see that it has.
func (r *Reconciler) SetEnabled(on bool) {
	r.enabled.Store(on)
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

// Enabled reports whether this reconciler is writing to the kernel.
func (r *Reconciler) Enabled() bool { return r.enabled.Load() }

// accepted is a capability SetTable took, resolved as New resolves one
type accepted struct {
	table     Table
	overlay   []schema.Prefix
	announced []netip.Prefix
	addresses []netip.Prefix
}

// SetTable hands the loop the capability a reload read, with cap.border's overlay and the prefixes cap.route announces, for a pass at once
// it refuses what New refuses and a change of id or proto
// a refusal changes nothing
func (r *Reconciler) SetTable(t Table, overlay []schema.Prefix, announced []netip.Prefix) error {
	if err := t.Validate(); err != nil {
		return err
	}
	t = t.Normalized()
	if setting := r.Table().Unreloadable(t); setting != "" {
		return fmt.Errorf("kernel: cap.table %s changed, restart to apply", setting)
	}
	addresses, err := resolveAddresses(t, announced)
	if err != nil {
		return err
	}
	r.next.Store(&accepted{table: t, overlay: overlay, announced: announced, addresses: addresses})
	select {
	case r.reload <- struct{}{}:
	default:
	}
	return nil
}

// adopt installs the capability SetTable accepted last, and reports whether there was one
func (r *Reconciler) adopt() bool {
	next := r.next.Swap(nil)
	if next == nil {
		return false
	}
	r.table, r.addresses, r.rt.Overlay, r.rt.Announced = next.table, next.addresses, next.overlay, next.announced
	r.gate.grace = next.table.CaptureGrace.Duration()
	r.plat.retable(next.table)
	r.inForce.Store(&next.table)
	r.reloaded = true
	slog.Info("kernel reconciler took a reloaded cap.table", "where", r.Where())
	return true
}

// Run reconciles until ctx is canceled, then withdraws everything this
// reconciler installed and closes its netlink sockets. It is called once.
//
// Withdrawal is best effort by construction: the caller usually cancels the
// mesh at the same moment, and the kernel drops routes and addresses on its
// own when the TUN disappears, so a device that is already gone is not an
// error. Run returns the withdrawal error, never a reconcile error: a failed
// pass is logged and retried instead.
func (r *Reconciler) Run(ctx context.Context) error {
	changed := r.src.Changed()
	notify := r.plat.Notify()
	ticker := time.NewTicker(r.table.Reconcile.Duration())
	defer ticker.Stop()
	retry := time.NewTimer(r.table.Reconcile.Duration())
	stopTimer(retry)
	defer retry.Stop()
	// Nothing else wakes at the moment the capture grace expires: the mesh has
	// stopped changing, which is why the grace is running at all. Without this
	// the machine's own traffic stays in a dead tun until the periodic sweep,
	// which is three times the grace by default.
	grace := time.NewTimer(r.table.Reconcile.Duration())
	stopTimer(grace)
	defer grace.Stop()

	// The space this reconciler owns comes from the platform: darwin has one
	// FIB and no rt_proto, so naming a table and a protocol there prints two
	// settings it refuses to honor.
	slog.Info("kernel reconciler started", "interface", r.rt.Interface, "where", r.Where())

	r.audit()

	backoff := time.Duration(0)
	r.trigger = "start"
	for ctx.Err() == nil {
		switch {
		case !r.enabled.Load():
			// Stopped over the control socket. The withdrawal happens once per
			// stop rather than once per wake-up, and the pass recorded after
			// it reads zero installed, so a diagnostic does not go on
			// reporting the routes of the last pass that ran.
			// a withdrawal that failed is still owed
			// it is retried on the backoff a failed pass takes rather than reported done
			if !r.withdrawn {
				started := time.Now()
				err := r.withdraw()
				r.routePass = Stats{}
				r.recordPass(err, time.Since(started))
				stopTimer(retry)
				stopTimer(grace)
				if err != nil {
					backoff = min(max(2*backoff, minRetryInterval), r.table.Reconcile.Duration())
					slog.Warn("kernel could not withdraw everything it was asked to stop holding, retrying", "err", err, "retry_in", backoff)
					retry.Reset(backoff)
				} else {
					r.withdrawn, backoff = true, 0
					slog.Info("kernel reconciler stopped, its routes withdrawn", "where", r.Where())
				}
			}
		default:
			if r.withdrawn {
				r.withdrawn = false
				slog.Info("kernel reconciler started again", "where", r.Where())
			}
			if err := r.reconcile(); err != nil {
				backoff = min(max(2*backoff, minRetryInterval), r.table.Reconcile.Duration())
				slog.Warn("kernel reconcile failed, retrying", "err", err, "retry_in", backoff)
				stopTimer(retry)
				retry.Reset(backoff)
			} else if backoff != 0 {
				backoff = 0
				stopTimer(retry)
			}

			stopTimer(grace)
			if at, ok := r.captureDeadline(); ok {
				grace.Reset(max(at.Sub(r.now()), 0))
			}
		}

		select {
		case <-ctx.Done():
		case <-ticker.C:
			r.trigger = "sweep"
		case <-retry.C:
			r.trigger = "retry"
		case <-grace.C:
			r.trigger = "grace"
		case <-r.wake:
			// SetEnabled wakes the loop whichever way it went
			r.trigger = "disable"
			if r.enabled.Load() {
				r.trigger = "enable"
			}
		case <-r.reload:
			r.trigger = "reload"
			if r.adopt() {
				ticker.Reset(r.table.Reconcile.Duration())
			}
		case <-changed:
			r.trigger = "mesh"
			r.settle(ctx, changed, notify)
		case <-notify:
			r.trigger = "kernel"
			r.settle(ctx, changed, notify)
		}
	}

	// A reconciler stopped over the socket has already withdrawn, and this
	// second pass then lists an empty table and removes nothing. Running it
	// anyway rather than skipping it on the flag keeps one exit path: what the
	// kernel holds is read back rather than remembered, so anything installed
	// between the stop and here still leaves.
	return errors.Join(r.withdraw(), r.plat.Close())
}

// settle waits out a fixed window, discarding further wake-ups, so a burst of
// babel changes and the notifications of the reconciler's own writes collapse
// into one pass.
func (r *Reconciler) settle(ctx context.Context, changed, notify <-chan struct{}) {
	timer := time.NewTimer(settleDelay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-changed:
		case <-notify:
		case <-timer.C:
			return
		}
	}
}

func stopTimer(t *time.Timer) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
}

// reconcile brings the kernel to one snapshot. The steps are independent and
// every error is collected, so an address that cannot be assigned does not stop
// routes or rules from being installed.
//
// The pass is recorded here rather than inside applyRoutes, so that what a
// diagnostic reports is the error Run logged rather than part of it: a
// node whose rules fail on every pass would otherwise answer `ranet3 status`
// with a clean route count and no error at all.
func (r *Reconciler) reconcile() error {
	started := time.Now()
	// Sampled once for the whole pass, before any of the steps: a route
	// installed under one answer and withdrawn under another would leave the
	// kernel holding a key the diff never names again.
	r.sampleCapture()
	snapshot := r.src.Snapshot()
	err := errors.Join(r.applyAddresses(), r.applyRoutes(snapshot), r.applyRules(snapshot))
	// a pass missing a rule or a hold would find its own fault, which err reports
	if err == nil {
		r.lookUp()
	}
	r.recordPass(err, time.Since(started))
	return err
}

// sampleCapture asks how much of the mesh is carrying traffic and records what
// this pass may therefore install. A reconciler with no session source keeps
// the behavior it had before the gate existed, because nothing it could ask
// would answer.
func (r *Reconciler) sampleCapture() {
	if r.rt.Sessions == nil {
		r.capture = true
		return
	}
	open, changed := r.gate.sample(r.now(), r.rt.Sessions())
	r.capture = open
	if !changed {
		return
	}
	if open {
		slog.Info("kernel is carrying this machine's own traffic over the mesh again",
			"detail", "a session is live, so an announced default is installed")
		return
	}
	slog.Warn("kernel is withdrawing the routes that would carry this machine's own traffic",
		"grace", r.table.CaptureGrace,
		"detail", "no session has been live for that long, so this node falls back to its own uplink")
}

// captureDeadline is when a pass has to run for the grace to expire on time,
// and nothing at all while no capturing route is installed or wanted.
//
// The condition matters more than it looks. The gate is open whenever a
// session is live, which on an ordinary node is always, so arming the wake
// from that alone made the grace the reconcile rate: a full pass, both dumps
// and on darwin a table read and two route lookups, once per grace rather than
// once per reconcile interval. Measured at 239 passes in 300 ms with a one
// millisecond grace, against two.
func (r *Reconciler) captureDeadline() (time.Time, bool) {
	if !r.capturing {
		return time.Time{}, false
	}
	return r.gate.deadline()
}

// recordPass publishes the pass applyRoutes counted, with the whole pass's
// error rather than the route half's. A pass that failed before applyRoutes
// could count anything still records the attempt, so a stale PassAt cannot
// read as a reconciler that is keeping up.
func (r *Reconciler) recordPass(err error, took time.Duration) {
	stats := r.routePass
	stats.At, stats.Lookups = time.Now(), r.lookups
	if err != nil {
		stats.Err = err.Error()
	}
	r.stats.Store(&stats)
	anew, changed, reloaded := r.refusedAnew, r.changed, r.reloaded
	r.refusedAnew, r.changed, r.reloaded = false, false, false
	// only a pass that changed the kernel, refused a route anew, failed or followed a reload is recorded
	if stats.Added == 0 && stats.Removed == 0 && !changed && !anew && !reloaded && err == nil {
		return
	}
	attrs := []slog.Attr{slog.String("trigger", r.trigger), slog.Duration("took", took),
		slog.Int("added", stats.Added), slog.Int("removed", stats.Removed),
		slog.Int("skipped", stats.Skipped), slog.Int("installed", stats.Installed)}
	if err != nil {
		attrs = append(attrs, slog.String("err", stats.Err))
	}
	r.rt.Events.Emit("kernel.pass", "", attrs...)
}

// audit reports, once at startup, what in the space this reconciler is about
// to take over would defeat it without anything failing.
func (r *Reconciler) audit() {
	audit, ok := r.plat.(auditor)
	if !ok {
		return
	}
	// An install refuses a key another writer already holds, so sharing a table
	// with another daemon means the routes it refuses are routes the mesh
	// wanted.
	if writers, err := audit.foreignWriters(); err != nil {
		slog.Warn("kernel could not check the table for other writers", "err", err)
	} else if len(writers) > 0 {
		slog.Warn("kernel is sharing its table with another routing protocol",
			"table", uint32(r.table.ID), "protocols", strings.Join(writers, ", "),
			"detail", "an install refuses a key another writer already holds, so where both write a prefix the one that wrote it first keeps it",
			"fix", "give this reconciler a table of its own")
	}
}

// applyRules brings the policy rules to the derived set. It removes before it
// installs for the same reason applyRoutes does, and it reads the kernel back
// rather than trusting a record, so rules an earlier instance left behind are
// adopted, and withdrawn where no longer derived, rather than duplicated. It
// adds in the set's order, which puts each nop ahead of its goto.
func (r *Reconciler) applyRules(snapshot []sadr.Route[*netstack.Peer]) error {
	if r.rules == nil {
		return nil
	}
	ruleSet := derivedRules(r.table.ID, r.rt.Overlay, r.ownPrefixes(snapshot))
	r.derived.Store(&ruleSet)
	actual, err := r.rules.Rules()
	if err != nil {
		return fmt.Errorf("list rules: %w", err)
	}
	var errs []error
	added, removed := 0, 0
	wanted := make(map[Rule]bool, len(ruleSet))
	for _, rule := range ruleSet {
		wanted[rule] = true
	}
	for _, rule := range actual {
		if wanted[rule] {
			continue
		}
		if err := r.rules.DelRule(rule); err != nil {
			errs = append(errs, fmt.Errorf("delete rule %s: %w", rule, err))
		} else {
			removed++
		}
	}
	held := make(map[Rule]bool, len(actual))
	for _, rule := range actual {
		held[rule] = true
	}
	for _, rule := range ruleSet {
		if held[rule] {
			continue
		}
		if err := r.rules.AddRule(rule); err != nil {
			errs = append(errs, fmt.Errorf("add rule %s: %w", rule, err))
		} else {
			added++
		}
	}
	if added > 0 || removed > 0 {
		r.changed = true
		slog.Info("kernel rules reconciled", "added", added, "removed", removed)
	}
	return errors.Join(errs...)
}

// applyRoutes removes before it installs, so a changed non-key attribute does
// not collide with the old route under the exclusive-install policy.
func (r *Reconciler) applyRoutes(snapshot []sadr.Route[*netstack.Peer]) error {
	// Cleared first, so a pass that fails before it can count anything reports
	// nothing rather than the counts of the last pass that succeeded.
	r.routePass = Stats{}
	actual, err := r.plat.Routes()
	if err != nil {
		return fmt.Errorf("list routes: %w", err)
	}
	desired := r.desired(snapshot)
	// Whether this pass leaves the mesh carrying this machine's own traffic,
	// which desired answers alone: it already holds only the capturing routes
	// this pass may install.
	r.capturing = slices.ContainsFunc(desired, r.captures)
	covering, scopes := r.covers(), r.platformScopes()
	scoped := func(route Route) bool { return route.Scoped || scopes != nil && scopes(route) }
	// A member is withheld only for a route the kernel holds once the pass has
	// added, so a route refused last pass withholds nothing while it is tried
	// again, and one that fails in this pass hands its members back. The key
	// of a refused route that a member of ours holds is this process's own,
	// whoever refused the route first, so that member is withheld and leaves
	// before the route is tried.
	memberAt := func(destination netip.Prefix) bool {
		return slices.ContainsFunc(actual, func(member Route) bool { return member.Cover && member.Destination == destination })
	}
	unheld := map[Route]bool{}
	for route := range r.refused {
		if !memberAt(route.Destination) {
			unheld[route] = true
		}
	}
	unmet := func(route Route) bool { return scoped(route) || unheld[route] }
	bare := desired
	// After the capture grace check, which judges the zero route whole: a
	// member holds no zero address, and CapturesTheMachine counts one by its
	// length outside the overlay alone, which would pass the rest while that
	// check holds captures back.
	var dropped []Route
	if covering {
		desired = coverDefaults(bare, unmet)
		dropped = r.reportMemberless(bare)
	}
	wanted := map[Route]bool{}
	for _, route := range desired {
		if route.Cover {
			wanted[route] = true
		}
	}
	// a zero route the cover installs as nothing is desired and skipped, so
	// Desired stays Installed plus Skipped
	desiredCount := len(desired) + len(dropped)
	add, del := diffRoutes(desired, actual, scopes)
	// A route refused last pass is tried first, and a route before the members
	// it contains, its own key's included, so while a member or a route
	// withholding one stays refused the rest of its family is left out rather
	// than installed and withdrawn again every pass.
	slices.SortStableFunc(add, func(a, b Route) int {
		return cmp.Or(
			cmp.Compare(boolOrder(!r.refused[a]), boolOrder(!r.refused[b])),
			comparePrefixes(a.Destination, b.Destination),
			cmp.Compare(boolOrder(a.Cover), boolOrder(b.Cover)),
		)
	})
	broken := map[Family]bool{}
	var errs []error
	added, removed, skipped := 0, 0, len(dropped)
	held := make(map[Route]bool, len(actual))
	for _, route := range actual {
		held[route] = true
	}
	// An install refuses a key another writer already holds rather than
	// taking it over, so a route of ours that changed only in an attribute
	// the kernel does not key on, its type at an unchanged metric,
	// has to leave before its replacement arrives. Both lists are this
	// reconciler's own routes, so the gap is within one pass and touches
	// nothing else.
	for _, route := range del {
		if err := r.plat.DelRoute(route); err != nil {
			errs = append(errs, fmt.Errorf("delete route %s: %w", route, err))
		} else {
			removed++
			delete(held, route)
		}
	}
	heldRoutes := func() []Route { return slices.Collect(maps.Keys(held)) }
	var refused map[Route]bool
	for i := 0; i < len(add); i++ {
		route := add[i]
		if route.Cover && withheld(route.Destination, heldRoutes(), scoped) {
			desiredCount--
			continue
		}
		if route.Cover && broken[familyOf(route.Destination.Addr())] {
			skipped++
			continue
		}
		err := r.plat.AddRoute(route)
		if err == nil {
			added++
			held[route] = true
		} else if errors.Is(err, errRouteSkipped) {
			skipped++
			if refused == nil {
				refused = make(map[Route]bool)
			}
			refused[route] = true
			r.refusedAnew = r.refusedAnew || !r.refused[route]
		} else {
			errs = append(errs, fmt.Errorf("add route %s: %w", route, err))
		}
		if err != nil && route.Cover {
			broken[familyOf(route.Destination.Addr())] = true
		}
		if err != nil && !route.Cover && covering {
			// tried next, before the rest of the family, so a refusal at a
			// member's own key refuses the member too
			unheld[route] = true
			var handed []Route
			for _, member := range coverDefaults(bare, unmet) {
				if member.Cover && !wanted[member] && !held[member] {
					wanted[member] = true
					handed = append(handed, member)
				}
			}
			desiredCount += len(handed)
			add = slices.Insert(add, i+1, handed...)
		}
	}
	r.refused = refused
	// A cover goes in whole or not at all: part of one would split its
	// family's traffic between the mesh and whatever holds the rest.
	ordinary := heldRoutes()
	for _, route := range slices.SortedFunc(maps.Keys(held), compareRoutes) {
		if !route.Cover {
			continue
		}
		broke := broken[familyOf(route.Destination.Addr())]
		replaced := wanted[route] && withheld(route.Destination, ordinary, scoped)
		if !broke && !replaced {
			continue
		}
		if err := r.plat.DelRoute(route); err != nil {
			errs = append(errs, fmt.Errorf("delete route %s: %w", route, err))
			continue
		}
		removed++
		if replaced {
			desiredCount--
		} else {
			skipped++
		}
		delete(held, route)
	}
	// A route the platform refuses stays in the diff on purpose, because the
	// install is retried on every pass until it lands, so a node holding one
	// permanently unrepresentable route would otherwise log "added=0 removed=0"
	// once per pass for its whole life.
	if added > 0 || removed > 0 {
		slog.Info("kernel routes reconciled", "added", added, "removed", removed)
	}
	// Installed is counted rather than re-listed: the kernel held len(actual)
	// when the pass started and every add and delete above was confirmed, so
	// the sum is exact and costs no second dump.
	r.installed = held
	r.routePass = Stats{
		Desired:   desiredCount,
		Installed: len(actual) - removed + added,
		Skipped:   skipped,
		Added:     added,
		Removed:   removed,
		Cover:     coveredFamilies(slices.Collect(maps.Keys(held))),
	}
	r.reportCover(r.routePass.Cover)
	return errors.Join(errs...)
}

func (r *Reconciler) reportCover(now []Family) {
	for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
		was, is := slices.Contains(r.cover, family), slices.Contains(now, family)
		if was == is {
			continue
		}
		slog.Info("kernel changed the cover a zero route is installed as", "family", family, "installed", is)
		r.rt.Events.Emit("kernel.cover", "", slog.String("family", string(family)), slog.Bool("installed", is))
	}
	r.cover = now
}

// reportMemberless returns the zero routes of desired a cover installs as
// nothing, those inside 0.0.0.0/8, this network (RFC 1122 section 3.2.1.3),
// or ::/8, and warns once for each while the mesh keeps announcing it.
func (r *Reconciler) reportMemberless(desired []Route) []Route {
	var out []Route
	reported := make(map[Route]bool, len(r.memberless))
	for _, route := range desired {
		if !memberless(route) {
			continue
		}
		out = append(out, route)
		if !r.memberless[route] {
			slog.Warn("kernel is not installing a route its cover holds nothing of",
				"destination", route.Destination,
				"detail", "the cover leaves 0.0.0.0/8 and ::/8 to the host, and every address of the route lies there")
			r.refusedAnew = true
		}
		reported[route] = true
	}
	r.memberless = reported
	return out
}

// desired projects one forwarding table snapshot onto the routes the kernel
// can hold. The peer is dropped here: it says the route exists, not where it
// goes, because the mesh picks the peer after the kernel hands over the
// packet.
func (r *Reconciler) desired(snapshot []sadr.Route[*netstack.Peer]) []Route {
	out := make([]Route, 0, len(snapshot)+len(r.rt.Overlay))
	warned := make(map[Route]bool, len(r.warned))
	// the throw rows and the overlay holds stand with the policy rules that
	// read them, which linux alone has
	exit, policy := r.exit(), r.rules != nil
	for _, entry := range snapshot {
		// The host's kernel holds every address cap.table assigns as one of its
		// own already, so the mirror installs nothing for one this node does not
		// originate.
		if entry.Value == netstack.Assigned {
			continue
		}
		destination, ok := canonicalPrefix(entry.Destination)
		if !ok {
			continue
		}
		if reason := unroutable(destination); reason != "" {
			key := Route{Destination: destination}
			if !r.warned[key] {
				slog.Warn("kernel is not installing a prefix the mesh cannot carry",
					"destination", destination, "detail", reason)
			}
			warned[key] = true
			continue
		}
		// Local inside the overlay is installed exactly as the hold is, so the
		// kernel holds the same route for a key whichever of the two the mesh's
		// entry carries.
		unreachable := entry.Value == netstack.Unreachable || entry.Value == netstack.Local
		route := Route{
			Destination: destination,
			Metric:      routeMetric(r.table.Metric, destination, unreachable),
			Unreachable: unreachable,
		}
		// A hold or this node's own entry that counts as a default is declined,
		// since an unreachable route of that width would answer every lookup of
		// the host's own traffic that ends at it with an error. RFC 8966 section
		// 3.5.4 is kept for it by the mesh's own lookup, for each tun read no
		// steering policy takes past it.
		// An exit declines every route that counts, whatever the gate says:
		// with another exit's default in this table, on linux the exit's own
		// traffic from its own prefixes would take it into the tun at 5430 and
		// out of that exit (routing.md, where a lookup ends on Linux).
		if r.captures(route) && (unreachable || !r.capture || exit) {
			continue
		}
		// This node's own prefix outside the overlay that counts as no default
		// is a throw, which ends the lookup in this table so the rules after
		// the one that looked it up decide (routing.md, where a lookup ends on
		// Linux). Inside the overlay it stays the hold. Without the policy
		// rules nothing reads a throw, so the prefix gets no route at all.
		if entry.Value == netstack.Local && !schema.InsideOverlay(destination, r.rt.Overlay) {
			if !policy {
				continue
			}
			route.Unreachable, route.Throw = false, true
		}
		if entry.Source.IsValid() {
			source, ok := canonicalPrefix(entry.Source)
			if !ok || source.Addr().Is4() || destination.Addr().Is4() {
				// the IPv4 FIB has no source-specific lookup, and installing
				// such a route as an ordinary one would steal traffic from
				// every other source. Report it and leave it to the mesh's
				// own table, where forwarding still honors it.
				key := Route{Destination: destination, Source: entry.Source}
				if !r.warned[key] {
					slog.Warn("kernel cannot install source-specific IPv4 route",
						"destination", destination, "source", entry.Source)
				}
				warned[key] = true
				continue
			}
			route.Source = source
		}
		out = append(out, route)
	}
	r.warned = warned
	if policy {
		out = r.overlayHolds(out)
	}
	return out
}

// overlayHolds adds an unreachable hold to the pass's routes, once, for each
// prefix of the overlay that the mesh can carry and that holds no unspecified
// address. A lookup the walk ends at the hold is refused (routing.md, where a
// lookup ends on Linux), where without it an overlay destination no route of
// the mesh covers would follow an exit's default into the mesh, or leave by
// main, which on a host whose uplink shares the space carries it to a stranger
// holding the same address.
func (r *Reconciler) overlayHolds(out []Route) []Route {
	for _, entry := range r.rt.Overlay {
		destination, ok := canonicalPrefix(entry.Prefix)
		if !ok || unroutable(destination) != "" {
			continue
		}
		hold := Route{Destination: destination, Metric: holdMetric, Unreachable: true}
		if !r.captures(hold) && !slices.Contains(out, hold) {
			out = append(out, hold)
		}
	}
	return out
}

// exit reports whether this node is an exit: cap.egress advertises or
// cap.route announces a prefix schema.CapturesTheMachine counts, or cap.segment
// holds an egress segment
func (r *Reconciler) exit() bool {
	counts := func(prefix netip.Prefix) bool { return schema.CapturesTheMachine(prefix, r.rt.Overlay) }
	return r.rt.EgressSegment || slices.ContainsFunc(r.rt.Advertised, counts) || slices.ContainsFunc(r.rt.Announced, counts)
}

// limitedBroadcast is the one entry the darwin kernel installs that carries no
// flag separating it from a route of ours: scoped, RTF_STATIC, and leaving
// through the interface itself, the same shape that backend writes. It
// is not created for a tun configured the way this backend configures one
// (measured on a throwaway utun carrying a /24 and a /48, where every entry
// the kernel added named an address as its gateway and so was already
// excluded), but it is present on every broadcast-capable interface on that
// machine and on the utun another overlay configures differently.
var limitedBroadcast = netip.MustParsePrefix("255.255.255.255/32")

// unroutable names why a prefix has no business in a routing table that
// forwards out of a mesh tunnel, or is empty for one that does. These are
// prefixes whose meaning is the link they sit on: the kernel keys its own
// entries for them per interface, and a route the mesh installs at the same
// key shadows the machine's own plumbing. On darwin that is the single FIB
// every program shares, which this tool has to coexist with, and only a
// default or a source-specific route is interface-scoped there.
func unroutable(destination netip.Prefix) string {
	switch addr := destination.Addr(); {
	case addr.IsMulticast():
		return "multicast is delivered on a link, not routed through a tunnel"
	case addr.IsLinkLocalUnicast():
		return "a link-local prefix names the link it arrived on"
	case addr.IsLoopback():
		return "loopback belongs to the host"
	case destination == limitedBroadcast:
		return "the limited broadcast address is not a destination"
	}
	return ""
}

// holdMetric is where a retraction sits among the routes to the same prefix:
// last. A lookup is longest prefix first and only then by metric, so a hold
// still outranks the covering route it exists to keep a packet away from,
// while anything else holding that exact prefix wins.
const holdMetric = ^uint32(0)

// routeMetric is the value the kernel will actually hold, so a dump compares
// equal to what was installed. An unset configured metric means the kernel's
// own default, which differs by family. Both the reconciler and the darwin
// backend answer through here, because darwin's FIB keeps no metric and
// mirrors this onto every route it decodes: two answers to the same question
// make a diff that adds and deletes the same route on every pass.
func routeMetric(configured uint32, destination netip.Prefix, unreachable bool) uint32 {
	switch {
	case unreachable:
		return holdMetric
	case configured == 0 && !destination.Addr().Is4():
		return defaultIPv6Metric
	}
	return configured
}

// diffRoutes reports the routes the kernel is missing and the reconciler's
// own routes it still holds that the mesh no longer wants. Both results are
// sorted so a pass is reproducible and its log lines are stable.
//
// scopes says which routes this platform files under interface scope, which on
// darwin is how the kernel keys them and everywhere else is nothing. A desired
// route is compared under the scope it would be installed with, and a route
// read back under the scope the kernel actually holds, so the two agree for
// every route this reconciler installed. They disagree only for a scoped route
// it did not install, and that has to be replaced rather than accepted: an
// unbound lookup does not reach a scoped route, so leaving one in place of an
// unscoped route the mesh asked for is a black hole the diff would never
// notice again.
func diffRoutes(desired, actual []Route, scopes func(Route) bool) (add, del []Route) {
	if scopes == nil {
		scopes = func(Route) bool { return false }
	}
	wanted := func(r Route) Route { r.Scoped = scopes(r); return r }
	held := func(r Route) Route { return r }
	want := make(map[Route]bool, len(desired))
	for _, route := range desired {
		want[wanted(route)] = true
	}
	have := make(map[Route]bool, len(actual))
	for _, route := range actual {
		have[held(route)] = true
	}
	emitted := make(map[Route]bool, len(desired)+len(actual))
	for _, route := range desired {
		if k := wanted(route); !have[k] && !emitted[k] {
			emitted[k] = true
			add = append(add, route)
		}
	}
	clear(emitted)
	for _, route := range actual {
		if k := held(route); !want[k] && !emitted[k] {
			emitted[k] = true
			del = append(del, route)
		}
	}
	slices.SortFunc(add, compareRoutes)
	slices.SortFunc(del, compareRoutes)
	return add, del
}

func boolOrder(b bool) int {
	if b {
		return 1
	}
	return 0
}

func compareRoutes(a, b Route) int {
	return cmp.Or(
		comparePrefixes(a.Destination, b.Destination),
		compareSourceSpecificity(a.Source, b.Source),
		cmp.Compare(a.Metric, b.Metric),
		cmp.Compare(boolOrder(a.Unreachable), boolOrder(b.Unreachable)),
		cmp.Compare(boolOrder(a.Throw), boolOrder(b.Throw)),
		cmp.Compare(boolOrder(a.Scoped), boolOrder(b.Scoped)),
	)
}

func comparePrefixes(a, b netip.Prefix) int {
	return cmp.Or(a.Addr().Compare(b.Addr()), cmp.Compare(a.Bits(), b.Bits()))
}

// compareSourceSpecificity orders the more specific source prefix first, which
// is the tiebreaker RFC 9079 section 4 applies among equally specific
// destinations, with an absent source last because it stands for every source.
//
// Ordering carries policy here rather than only presentation. darwin holds one
// source per destination, so where two source-specific routes reach the same
// destination the one this list offers first is the one installed and the
// other is skipped. Ordering by address instead would hand that decision to
// whichever exit happened to be numbered lower. Nothing on linux depends on
// it, where both routes are installed and the FIB does the matching.
func compareSourceSpecificity(a, b netip.Prefix) int {
	return cmp.Or(cmp.Compare(b.Bits(), a.Bits()), a.Addr().Compare(b.Addr()))
}

// applyAddresses brings the link to the configured addresses. The only ones it
// removes are recorded in owned: an address on the link that is not configured
// and not recorded belongs to somebody else.
func (r *Reconciler) applyAddresses() error {
	if len(r.addresses) == 0 && len(r.owned) == 0 {
		return nil
	}
	actual, err := r.plat.Addrs()
	if err != nil {
		return fmt.Errorf("list addresses: %w", err)
	}
	keysByLength := func(netip.Addr) bool { return false }
	if p, ok := r.plat.(lengthKeyer); ok {
		keysByLength = p.keysByLength
	}
	var relengthed, stale []netip.Prefix
	for prefix := range r.owned {
		if slices.Contains(r.addresses, prefix) {
			continue
		}
		if !keysByLength(prefix.Addr()) && slices.ContainsFunc(r.addresses, func(wanted netip.Prefix) bool { return wanted.Addr() == prefix.Addr() }) {
			relengthed = append(relengthed, prefix)
		} else {
			stale = append(stale, prefix)
		}
	}
	slices.SortFunc(relengthed, comparePrefixes)
	slices.SortFunc(stale, comparePrefixes)
	// before the adds, so an address of ours given another length is replaced rather than left as another writer's
	removed, errs := r.release(relengthed, actual)
	for _, prefix := range removed {
		slog.Info("kernel address removed", "interface", r.rt.Interface, "address", prefix)
		r.changed = true
	}
	have := make(map[netip.Prefix]bool, len(actual))
	held := make(map[netip.Addr]netip.Prefix, len(actual))
	for _, prefix := range actual {
		// a stale prefix at a wanted address is ours at another length on a platform that keeps the two apart
		if slices.Contains(removed, prefix) || slices.Contains(stale, prefix) {
			continue
		}
		have[prefix] = true
		held[prefix.Addr()] = prefix
	}
	warned := make(map[netip.Prefix]bool, len(r.warnedAddrs))
	for _, prefix := range r.addresses {
		if have[prefix] {
			continue
		}
		// Both platforms assign an address by upsert: linux matches an
		// existing ifa by address alone and darwin's SIOCAIFADDR has no
		// "already present" at all, so assigning the same address under a
		// different prefix length rewrites somebody else's entry and reports
		// success. The reconciler would then record it as its own and take it
		// away at shutdown, against the rule that only an address it added
		// itself is ever removed. ranet3 attaches to a tun it did not
		// necessarily create, so this is reachable without anything unusual.
		if existing, taken := held[prefix.Addr()]; taken {
			if !r.warnedAddrs[prefix] {
				slog.Warn("kernel is leaving an address another writer holds",
					"interface", r.rt.Interface, "address", prefix, "held_as", existing)
			}
			warned[prefix] = true
			continue
		}
		if err := r.plat.AddAddr(prefix); err != nil {
			errs = append(errs, fmt.Errorf("add address %s: %w", prefix, err))
			continue
		}
		slog.Info("kernel address assigned", "interface", r.rt.Interface, "address", prefix)
		r.owned[prefix], r.changed = true, true
	}
	// the rest after the adds, so a renumbered tun is never left without an IPv4 address
	// linux flushes every IPv4 route out of a device that has none, another writer's among them
	gone, failed := r.release(stale, actual)
	errs = append(errs, failed...)
	for _, prefix := range gone {
		slog.Info("kernel address removed", "interface", r.rt.Interface, "address", prefix)
		r.changed = true
	}
	r.warnedAddrs = warned
	return errors.Join(errs...)
}

// withdraw removes exactly what this reconciler installed: every route and
// rule still carrying its marker and every address it added itself. Routes are
// read back rather than remembered, so routes an earlier crashed instance left
// behind go with them.
func (r *Reconciler) withdraw() error {
	r.report(nil)
	var errs []error
	routes, err := r.plat.Routes()
	if err != nil {
		errs = append(errs, fmt.Errorf("list routes: %w", err))
	}
	withdrawn := 0
	for _, route := range routes {
		if err := r.plat.DelRoute(route); err != nil {
			errs = append(errs, fmt.Errorf("delete route %s: %w", route, err))
		} else {
			withdrawn++
		}
	}
	// An address is removed only while the link still carries exactly what was
	// installed. darwin's SIOCDIFADDR matches on the address alone, so another
	// writer that rewrote ours under a different prefix length, which its
	// SIOCAIFADDR upsert lets it do, would otherwise have its entry taken away
	// by this shutdown. applyAddresses reads the link back rather than
	// trusting the record for the same reason, and refuses on the same
	// failure: a readback that did not happen is not one that said yes.
	held, err := r.plat.Addrs()
	addresses := slices.SortedFunc(maps.Keys(r.owned), comparePrefixes)
	if err != nil {
		errs = append(errs, fmt.Errorf("list addresses: %w", err))
		slog.Warn("kernel is leaving every address it installed, the link would not read back",
			"interface", r.rt.Interface, "addresses", len(addresses))
		addresses = nil
	}
	removed, failed := r.release(addresses, held)
	errs = append(errs, failed...)
	// Rules go the same way routes do, read back under this reconciler's own
	// protocol rather than remembered, so one an earlier instance left behind
	// leaves with them.
	rules := 0
	if r.rules != nil {
		r.derived.Store(nil)
		held, err := r.rules.Rules()
		if err != nil {
			errs = append(errs, fmt.Errorf("list rules: %w", err))
		}
		for _, rule := range held {
			if err := r.rules.DelRule(rule); err != nil {
				errs = append(errs, fmt.Errorf("delete rule %s: %w", rule, err))
			} else {
				rules++
			}
		}
	}
	// Every count is of something that left, so a line reporting nothing
	// removed is a shutdown that removed nothing.
	slog.Info("kernel reconciler withdrawn", "routes", withdrawn, "addresses", len(removed), "rules", rules)
	return errors.Join(errs...)
}

// release takes each address of ours in prefixes off the link while held shows it as it was added
// it forgets one held shows otherwise, which is no longer this reconciler's to take
func (r *Reconciler) release(prefixes, held []netip.Prefix) (removed []netip.Prefix, errs []error) {
	for _, prefix := range prefixes {
		if !slices.Contains(held, prefix) {
			slog.Warn("kernel is leaving an address it no longer holds as it installed it",
				"interface", r.rt.Interface, "address", prefix)
			delete(r.owned, prefix)
			continue
		}
		if err := r.plat.DelAddr(prefix); err != nil {
			errs = append(errs, fmt.Errorf("delete address %s: %w", prefix, err))
			continue
		}
		delete(r.owned, prefix)
		removed = append(removed, prefix)
	}
	return removed, errs
}

// lengthKeyer is implemented by a platform whose kernel keys an address of a family by its prefix length as well, which is linux IPv4 alone
// there a new length goes on beside the old one, which comes off after it
// a family keyed by address alone takes the old length off first
type lengthKeyer interface{ keysByLength(netip.Addr) bool }

// canonicalPrefix puts a prefix in the one form the kernel reports, so a diff
// key built from a snapshot compares equal to one built from a route dump. The
// 4-in-6 form is deliberately left alone rather than unmapped: sadr keeps such
// a prefix in its IPv6 table and the kernel would hold it as an IPv6 route, so
// unmapping here would make the two sides disagree about the family.
func canonicalPrefix(prefix netip.Prefix) (netip.Prefix, bool) {
	if !prefix.IsValid() {
		return netip.Prefix{}, false
	}
	canonical := netip.PrefixFrom(prefix.Addr().WithZone(""), prefix.Bits())
	if !canonical.IsValid() {
		return netip.Prefix{}, false
	}
	return canonical.Masked(), true
}

// scoper is implemented by a platform whose kernel keys a route by interface
// scope as well as by its destination, which is darwin alone.
type scoper interface{ scopes(Route) bool }

func (r *Reconciler) covers() bool {
	p, ok := r.plat.(coverer)
	return ok && p.covers()
}

func (r *Reconciler) platformScopes() func(Route) bool {
	if p, ok := r.plat.(scoper); ok {
		return p.scopes
	}
	return nil
}
