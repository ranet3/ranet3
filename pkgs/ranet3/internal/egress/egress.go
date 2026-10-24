// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

// Package egress translates the source address of a packet the mesh hands to
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
// Runtime.Announce is called with the prefixes of each family whose chain
// reads back as written and which the kernel forwards, and with nothing at all
// while no family is both. It is the same fact internal/client warns about
// for transit, read from the same place, and acted on here because this end
// is the only one that knows.
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
// accepts whatever arrives on a device inside the mesh, the tun, lo and the
// VRF master the tun is enslaved to, then drops a source
// in the mesh's own prefixes, any routing header and this node's own SIDs as
// destinations, in that order, each drop counted. The routing header rule
// takes every type, since nf_tables finds only the first routing header of a
// packet, and one of type 0 or 2 would otherwise hide a type 4 header behind
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
package egress

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

	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/schema"
)

// FamilyIPv4 and FamilyIPv6 are AF_INET and AF_INET6, spelled here rather than
// taken from x/sys so that this file still builds where the capability is
// refused rather than absent from the type. internal/kernel spells them the
// same way for the same reason.
const (
	FamilyIPv4 uint8 = 2
	FamilyIPv6 uint8 = 10
)

// ErrUnsupported is returned by New on every platform with no backend, which
// is everything but linux today. A pf anchor on darwin is the second backend
// and is not written yet.
var ErrUnsupported = errors.New("egress: source translation is unsupported on this platform")

// Egress is the cap.egress capability: this node carries other nodes' traffic
// out of the mesh, the one action behind an exit node and a subnet router.
// Writing the block turns it on. There is no enable field to forget.
type Egress struct {
	// Advertise names the prefixes this node offers to carry: 0.0.0.0/0 and
	// ::/0 for an exit node, the prefixes behind it for a subnet router. It
	// decides which families the rules keyed on the mesh device cover as well
	// as which are announced, because a family this node does not offer to
	// carry is one it has no reason to translate out of the mesh.
	Advertise []schema.Prefix `yaml:"advertise,omitempty" json:"advertise,omitempty" toml:"advertise,omitempty"`
	// Source4 and Source6 are the address a translated packet leaves under,
	// per family, whether it came through an advertised prefix or an egress
	// segment: a property of the node rather than of the path a packet took. See
	// Source: "auto" is the address this node's own routes would have used,
	// which is the only answer available to a deployment that owns no address
	// block.
	Source4 Source `yaml:"source4,omitempty" json:"source4,omitzero" toml:"source4,omitempty"`
	Source6 Source `yaml:"source6,omitempty" json:"source6,omitzero" toml:"source6,omitempty"`
	// Return translates the other direction too: a packet arriving from one of
	// the advertised prefixes and leaving through the mesh goes out under this
	// node's own mesh address. A subnet router needs it where the mesh has no
	// route back to the LAN, which is every deployment that advertises a
	// prefix the far end does not hold a route for. An exit node does not:
	// nothing sits behind it to start a flow.
	Return bool `yaml:"return,omitempty" json:"return,omitempty" toml:"return,omitempty"`
	// Sweep is the periodic pass. It reinstalls a table somebody removed and
	// re-reads the forwarding sysctls, which is the half of readiness that
	// changes under a running node. Zero uses DefaultSweep.
	Sweep schema.Duration `yaml:"sweep,omitempty" json:"sweep,omitempty" toml:"sweep,omitempty"`
}

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
	// node and routable within the mesh, which a mesh address already is.
	MeshAddresses []netip.Addr
	// Forwarding reports whether the host forwards, per family. It is supplied
	// rather than read here so that the node has one answer to the question
	// and not two: internal/client owns the reading.
	Forwarding func() (v4, v6 bool)
	// Announce publishes the prefixes this node may advertise right now. It is
	// called once per pass whose answer differs from the last, and with an
	// empty list while nothing may be advertised. Nil means the caller does
	// not announce, which only a test does.
	Announce func([]netip.Prefix)
	// Ready receives the egress segments' readiness per family, and whether
	// the egress SIDs are served, whenever one of the three moves, starting
	// from none. A family is ready while its chain reads back exactly as
	// written and the host forwards it, and is reported not ready before the
	// tables are withdrawn. The SIDs are served
	// while at least one family is ready and every family the host forwards
	// is. Nil where nothing reads it, which only a test does.
	Ready func(v4, v6, serves bool)
	// Events records every pass that rewrote the rules, moved the announcement or failed
	// nil records nothing
	Events *events.Bus
}

// Normalized is the capability as the translator runs it: the sweep the file
// left out filled in, an omitted list and an empty one the same, the
// advertised prefixes in one order, and a source naming no address written as
// the auto it means. Two configurations are compared through this rather than
// as they were written, so neither "source4 = auto", the spelling
// examples/config.toml documents, nor the order the prefixes were listed in is
// a change, and neither costs a restart.
//
// The order is not meaningful: the list decides which families the rules
// keyed on the mesh device cover and which prefixes are announced, and both
// are sets. A rule is installed per family rather than per entry, so nothing
// here is positional.
func (e Egress) Normalized() Egress {
	if len(e.Advertise) == 0 {
		e.Advertise = nil
	} else {
		e.Advertise = slices.SortedFunc(slices.Values(e.Advertise), schema.ComparePrefix)
	}
	if e.Sweep == 0 {
		e.Sweep = schema.Duration(DefaultSweep)
	}
	e.Source4, e.Source6 = e.Source4.normalized(), e.Source6.normalized()
	return e
}

// Validate refuses a capability that cannot mean anything, in the package that
// knows what its fields mean. It runs at load, so a mistake costs a refusal to
// start rather than an exit that advertises and drops. An empty advertise list
// is an exit serving only the traffic steered to its egress segment, which
// Serves judges, since whether a node has one is not in this block.
func (e Egress) Validate() error {
	if e.Return && len(e.Advertise) == 0 {
		return errors.New("egress: cap.egress return is set and advertise is empty, so there is no prefix to translate from")
	}
	// a prefix with bits below its length is refused rather than masked, which would advertise a whole prefix where one address was written
	// and one spelling IPv4 as IPv6 rather than unmapped, which an IPv6 rule would translate for a family no packet on the wire carries
	if err := schema.CheckPrefixes("egress: cap.egress advertise", e.Advertise, nil); err != nil {
		return err
	}
	for _, named := range []struct {
		field  string
		source Source
		is4    bool
	}{{"source4", e.Source4, true}, {"source6", e.Source6, false}} {
		if !named.source.Addr.IsValid() {
			continue
		}
		if named.source.Addr.Zone() != "" {
			// Checked first, as the decoder checks it before unmapping: it
			// refuses a zone, so a capability carrying one renders to a file
			// that does not load.
			return fmt.Errorf("egress: cap.egress %s %s carries a zone, which a translated address cannot", named.field, named.source.Addr)
		}
		if named.source.Auto {
			// A file writes one or the other, and this one is written as the
			// address and read back without the auto.
			return fmt.Errorf("egress: cap.egress %s is both auto and %s, and a source is one or the other", named.field, named.source.Addr)
		}
		if named.source.Addr.Is4In6() {
			// Refused rather than judged in the family it is written in, as an
			// advertised prefix in this spelling is. The decoder unmaps it, so
			// a capability carrying one renders to a file that reads back as
			// an IPv4 source, which source6 refuses after taking the value.
			return fmt.Errorf("egress: cap.egress %s %s is an IPv4 address written as IPv6, so write it as %s", named.field, named.source.Addr, named.source.Addr.Unmap())
		}
		if named.source.Addr.Is4() != named.is4 {
			return fmt.Errorf("egress: cap.egress %s %s is not of that family", named.field, named.source.Addr)
		}
		if !named.source.Addr.IsGlobalUnicast() && !named.source.Addr.IsPrivate() {
			// A translated packet has to be answerable, and a loopback,
			// multicast or unspecified source is one nothing replies to. The
			// check is here rather than in the backend because the backend
			// would install it and the failure would only show up as a flow
			// that never completes.
			return fmt.Errorf("egress: cap.egress %s %s is not an address a reply can be sent to", named.field, named.source.Addr)
		}
	}
	if e.Sweep < 0 {
		return fmt.Errorf("egress: cap.egress sweep %s is negative", e.Sweep)
	}
	return nil
}

// Serves refuses a capability that would translate nothing and offer nothing:
// one advertising no prefix on a node with no segment delivering to egress,
// which steered reports.
func (e Egress) Serves(steered bool) error {
	if len(e.Advertise) == 0 && !steered {
		return errors.New("egress: cap.egress advertise is empty and no segment here delivers to egress, so this node would translate nothing and offer nothing: name the prefixes it carries, or 0.0.0.0/0 and ::/0 for an exit node")
	}
	return nil
}

// translated is the address families a translator of this capability covers:
// those it advertises, and both beside an egress segment.
func (e Egress) translated(steered bool) []uint8 {
	if steered {
		return []uint8{FamilyIPv4, FamilyIPv6}
	}
	return e.families()
}

// families is the address families this configuration advertises, derived
// from its prefixes. A family nothing is advertised for is one the mesh device
// carries nothing out of here, so no rule keyed on it is created.
func (e Egress) families() []uint8 {
	var out []uint8
	for _, prefix := range e.Advertise {
		family := FamilyIPv6
		if prefix.Addr().Is4() {
			family = FamilyIPv4
		}
		if !slices.Contains(out, family) {
			out = append(out, family)
		}
	}
	slices.Sort(out)
	return out
}

func (e Egress) source(family uint8) Source {
	if family == FamilyIPv4 {
		return e.Source4
	}
	return e.Source6
}

// sweep is the interval with its default applied.
func (e Egress) sweep() time.Duration {
	if e.Sweep <= 0 {
		return DefaultSweep
	}
	return e.Sweep.Duration()
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
)

func (d Direction) String() string {
	if d == In {
		return "in"
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
	// From narrows an In rule to one advertised prefix. It is never set on an
	// Out rule, which selects on the direction alone, and it is left invalid
	// for a prefix covering every address, which selects nothing extra.
	From netip.Prefix
}

// String is the rule as an operator reads it in `nft list ruleset` and as the
// diff compares it. Every field that changes what the rule does is in it, so a
// changed source or prefix reads back as a different rule and is replaced.
func (r Rule) String() string {
	source := "masquerade"
	if r.Source.IsValid() {
		source = "source " + r.Source.String()
	}
	parts := []string{r.Direction.String(), "via", r.Interface, familyName(r.Family)}
	if r.From.IsValid() {
		parts = append(parts, "from", r.From.String())
	}
	return strings.Join(append(parts, source), " ")
}

func familyName(family uint8) string {
	if family == FamilyIPv4 {
		return "ipv4"
	}
	return "ipv6"
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
	where(Egress) string
}

// Stats is one finished pass as an operator reads it. Installed counts the
// rules the host holds for this translator once the pass has applied, and
// Announced the prefixes it is willing to advertise as a result.
type Stats struct {
	At        time.Time
	Desired   int
	Installed int
	// Flows counts the connections the rules have translated, and Bytes the
	// first packet of each. A nat chain is consulted once per connection and
	// never again, so neither is a packet count.
	Flows     uint64
	Bytes     uint64
	Announced []netip.Prefix
	Conflicts []string
	Err       string
	// Ready4 and Ready6 are false on a node with no egress segment, and
	// Unready is empty while both are ready
	Ready4, Ready6 bool
	Unready        string
}

// Translator owns the capability on one node: the rules, the tables they live
// in, and the advertisement that depends on both.
type Translator struct {
	cfg Egress
	rt  Runtime
	be  backend

	// stats is the last pass as a reader takes it. The single run goroutine
	// publishes a whole value and a reader takes one, so this needs no lock
	// and a reader can never see half a pass.
	stats atomic.Pointer[Stats]
	// announced holds the prefixes Runtime.Announce was last given, so a pass
	// that changes nothing does not republish and a caller reading it directly
	// gets the same answer the speaker has.
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
	// ready4, ready6 and serves hold what Runtime.Ready was last given,
	// forwards4 and forwards6 the forwarding the last pass read, and unready
	// the reason a family is not, all of them the run goroutine's
	ready4, ready6, serves bool
	forwards4, forwards6   bool
	unready                string
}

// New validates the capability against the platform and opens whatever the
// backend needs, so a deployment that cannot have it fails at startup rather
// than on the first packet. It installs nothing. Run does that.
func New(cfg Egress, rt Runtime) (*Translator, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if err := cfg.Serves(rt.Steered); err != nil {
		return nil, err
	}
	if rt.Interface == "" {
		return nil, errors.New("egress: the mesh interface is required")
	}
	if rt.Forwarding == nil {
		return nil, errors.New("egress: a forwarding reader is required")
	}
	// Resolved before the backend is opened, so a return direction with no
	// mesh address to translate to is refused with nothing to clean up.
	if _, err := cfg.ReturnSources(rt.MeshAddresses); err != nil {
		return nil, err
	}
	be, err := newBackend(cfg, rt)
	if err != nil {
		return nil, err
	}
	return newTranslator(cfg, rt, be), nil
}

// newTranslator is a translator over a backend that is already open, writing to the host until SetEnabled stops it
func newTranslator(cfg Egress, rt Runtime, be backend) *Translator {
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
// caught up and reads Stats to see that it has.
func (t *Translator) SetEnabled(on bool) {
	t.enabled.Store(on)
	select {
	case t.wake <- struct{}{}:
	default:
	}
}

// ReturnSources is the address the In direction translates to under each family the capability advertises, an auto source picked among mesh
// it refuses what New refuses, an auto source with no address or several to pick from
// without return set every one is the zero address
func (e Egress) ReturnSources(mesh []netip.Addr) ([]netip.Addr, error) {
	var out []netip.Addr
	for _, family := range e.families() {
		source, err := returnSource(e, Runtime{MeshAddresses: mesh}, family)
		if err != nil {
			return nil, err
		}
		out = append(out, source)
	}
	return out, nil
}

// returnSource is the address the In direction translates to for one family:
// the configured one, or this node's own mesh address of that family. A node
// with several is refused rather than picked from, because the choice decides
// which address every flow out of this node's LAN appears as and guessing it
// would change under an unrelated edit to the address list.
func returnSource(cfg Egress, rt Runtime, family uint8) (netip.Addr, error) {
	if !cfg.Return {
		return netip.Addr{}, nil
	}
	if source := cfg.source(family); source.Addr.IsValid() {
		return source.Addr, nil
	}
	var candidates []netip.Addr
	for _, address := range rt.MeshAddresses {
		if addressFamily(address) != family || !address.IsGlobalUnicast() && !address.IsPrivate() {
			continue
		}
		if !slices.Contains(candidates, address) {
			candidates = append(candidates, address)
		}
	}
	switch len(candidates) {
	case 1:
		return candidates[0], nil
	case 0:
		return netip.Addr{}, fmt.Errorf("egress: return is set and this node carries no %s mesh address to translate to, so name one in egress.source%s",
			familyName(family), familyDigit(family))
	default:
		return netip.Addr{}, fmt.Errorf("egress: return is set and this node carries %d %s mesh addresses (%s), so name the one to translate to in egress.source%s",
			len(candidates), familyName(family), joinAddrs(candidates), familyDigit(family))
	}
}

func familyDigit(family uint8) string {
	if family == FamilyIPv4 {
		return "4"
	}
	return "6"
}

func joinAddrs(addresses []netip.Addr) string {
	text := make([]string, 0, len(addresses))
	for _, address := range addresses {
		text = append(text, address.String())
	}
	return strings.Join(text, ", ")
}

func addressFamily(address netip.Addr) uint8 {
	if address.Is4() {
		return FamilyIPv4
	}
	return FamilyIPv6
}

// Capability is the block this translator is running, as the file spelled it.
func (t *Translator) Capability() Egress { return t.cfg }

// Where names the space this translator owns, for an operator reading a log
// line.
func (t *Translator) Where() string { return t.be.where(t.cfg) }

// Stats reports the last pass, and the zero value before the first one has
// run. A caller that wants to tell those apart reads At.
func (t *Translator) Stats() Stats {
	if s := t.stats.Load(); s != nil {
		return *s
	}
	return Stats{}
}

// Announce is the prefixes this node may advertise right now: the configured
// list narrowed to the families whose chain reads back as written and whose
// forwarding is on, and nothing at all before the first pass has run. A caller announces
// from this rather than from the configuration, which is how an exit that
// cannot translate refuses to advertise rather than advertising and dropping.
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
	slog.Info("egress translator started", "interface", t.rt.Interface, "steered", t.rt.Steered, "where", t.Where(),
		"advertise", len(t.cfg.Advertise))
	ticker := time.NewTicker(t.cfg.sweep())
	defer ticker.Stop()
	retry := newRetryTimer(t.cfg.sweep())
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
				slog.Info("egress translator started again", "where", t.Where())
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
			// the steered rule may be gone or bypassed already, so the mesh stops writing before the pass that puts it back
			t.trigger = "changed"
			const why = "another writer changed its table"
			t.setReady(false, false, why, why)
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
	t.setReady(false, false, why, why)
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
			slog.Info("egress rules installed", "rules", len(desired), "replaced", len(held), "where", t.Where())
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
	// than captured at startup, because both halves of it change under a
	// running node: a table can be flushed by somebody else and a forwarding
	// sysctl can be turned on after this process started. A family's chain
	// counts only while it and its table read back exactly as written, since
	// another writer's rule among this tool's, a dormant table or a chain at
	// another hook, which an apply that failed leaves in place, changes what
	// the chain does to a packet.
	v4, v6 := t.rt.Forwarding()
	forwards := map[uint8]bool{FamilyIPv4: v4, FamilyIPv6: v6}
	unwritten := map[uint8]string{}
	for _, family := range []uint8{FamilyIPv4, FamilyIPv6} {
		switch {
		case read[family].fault != "":
			unwritten[family] = read[family].fault
		case !sameFamilyRules(held, desired, family):
			unwritten[family] = "its chain does not read back as written"
		}
	}
	announced := make([]netip.Prefix, 0, len(t.cfg.Advertise))
	for _, entry := range t.cfg.Advertise {
		if family := addressFamily(entry.Addr()); unwritten[family] == "" && forwards[family] {
			announced = append(announced, entry.Prefix)
		}
	}
	if t.rt.Steered {
		t.setSteeredReady(unwritten, forwards)
	}
	moved := t.publish(announced)

	var flows, bytes uint64
	for _, rule := range held {
		flows += rule.Packets
		bytes += rule.Bytes
	}
	stats := Stats{
		At: time.Now(), Desired: len(desired), Installed: len(held),
		Flows: flows, Bytes: bytes,
		Announced: announced, Conflicts: conflicts,
		Ready4: t.ready4, Ready6: t.ready6, Unready: t.unready,
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
	for _, family := range []uint8{FamilyIPv4, FamilyIPv6} {
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
// Within a family the one Out rule comes first, because a chain reads top to
// bottom.
func (t *Translator) desired() []Rule {
	var out []Rule
	for _, family := range t.cfg.translated(t.rt.Steered) {
		out = append(out, Rule{Family: family, Direction: Out, Interface: t.rt.Interface, Source: t.cfg.source(family).Addr})
		if !t.cfg.Return {
			continue
		}
		// Resolved again rather than remembered, and its error dropped,
		// because New refused every advertised family that cannot answer it
		// and a family advertising nothing has no prefix to write a rule for.
		source, err := returnSource(t.cfg, t.rt, family)
		if err != nil || !source.IsValid() {
			continue
		}
		for _, prefix := range t.cfg.Advertise {
			if addressFamily(prefix.Addr()) != family {
				continue
			}
			inbound := Rule{Family: family, Direction: In, Interface: t.rt.Interface, Source: source}
			// A prefix covering every address narrows nothing, and a rule
			// carrying it would encode a mask no packet fails, so it is left
			// off and the rule selects on the direction alone.
			if prefix.Bits() > 0 {
				inbound.From = prefix.Prefix
			}
			out = append(out, inbound)
		}
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
			"was", len(*previous), "detail", "a family is advertised only while its chain reads back as written and the kernel forwards it")
	}
	if t.rt.Announce != nil {
		t.rt.Announce(slices.Clone(prefixes))
	}
	return true
}

// setSteeredReady judges each family beside an egress segment. Every family's
// chain then holds its rule keyed on the mesh device, so a chain reading back
// as written, with no entry in unwritten, covers that rule.
func (t *Translator) setSteeredReady(unwritten map[uint8]string, forwards map[uint8]bool) {
	judge := func(family uint8) (bool, string) {
		switch {
		case unwritten[family] != "":
			return false, unwritten[family]
		case !forwards[family]:
			return false, "the kernel does not forward " + familyName(family)
		}
		return true, ""
	}
	ready4, why4 := judge(FamilyIPv4)
	ready6, why6 := judge(FamilyIPv6)
	t.forwards4, t.forwards6 = forwards[FamilyIPv4], forwards[FamilyIPv6]
	t.setReady(ready4, ready6, why4, why6)
}

func (t *Translator) setReady(v4, v6 bool, why4, why6 string) {
	t.unready = unreadyText(v4, v6, why4, why6)
	// a leaf reads the SID's /128 as the exit's liveness, so a family the host forwards and cannot carry out withdraws it
	serves := (v4 || v6) && (v4 || !t.forwards4) && (v6 || !t.forwards6)
	if v4 == t.ready4 && v6 == t.ready6 && serves == t.serves {
		return
	}
	for _, moved := range []struct {
		family     uint8
		was, ready bool
		why        string
	}{{FamilyIPv4, t.ready4, v4, why4}, {FamilyIPv6, t.ready6, v6, why6}} {
		switch {
		case moved.was == moved.ready:
		case moved.ready:
			slog.Info("egress segments ready", "family", familyName(moved.family))
		default:
			slog.Warn("egress segments not ready", "family", familyName(moved.family), "detail", moved.why)
		}
	}
	t.ready4, t.ready6, t.serves = v4, v6, serves
	if t.rt.Ready != nil {
		t.rt.Ready(v4, v6, serves)
	}
	t.rt.Events.Emit("egress.ready", "", slog.Bool("ipv4", v4), slog.Bool("ipv6", v6), slog.Bool("sid", serves))
}

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
	t.setReady(false, false, why, why)
	t.publish(nil)
	err := t.withdraw()
	stats := Stats{At: time.Now()}
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
		return fmt.Errorf("withdraw %s: %w", t.Where(), err)
	}
	slog.Info("egress translator withdrawn", "where", t.Where())
	return nil
}
