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
// On linux the translation is chains in the nftables inet table named after
// this tool, nftables.Table, which the antispoof filter and internal/kernel's
// kill switch write their own chains in: a nat postrouting chain that
// translates, a filter forward chain, which sends IPv6's packets on to a
// regular chain of IPv6's and holds IPv4's lines itself, a regular chain for
// each class of none, which that class's pass goes to, and for each family the
// timeout objects the translation attaches and a set that holds each mesh
// source under a class that translates to its share of the flows
// (exit-nodes.md, "Each source's share of the flows"). Their names are the
// ownership marker, the way Table.Proto is the reconciler's in
// internal/kernel. This package writes only those, and withdraws them at
// shutdown, with the table where nothing of another writer's is left in it.
// It reads other writers' tables, chains and rules to find its own and to
// report conflicts, and writes, replaces or deletes nothing else. A rule
// another writer puts in this package's chains is removed by the next pass.
// Other source translation already on the host is reported rather than fought
// over: several nat postrouting chains coexist at the same hook, the first to
// translate a connection wins it, and taking somebody else's rule away to win
// that race would break whatever put it there.
//
// Chains a previous instance left behind carry the same names and are
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
// Announce answers the prefixes of each family that is ready, whose chains
// read back as written, which the kernel forwards and whose route lookups
// take a translated packet's path, and nothing at all while no family is, and
// Republish says when that answer moves. Forwarding is the same fact
// internal/client warns about for transit, read from the same place, and acted
// on here because this end is the only one that knows.
//
// # The antispoof filter
//
// An exit's allow list says which sources it carries out of the mesh, and
// it is authorization rather than a filter: a host on any link of a forwarding
// node can send that node a packet with a mesh source, which chain mesh_entry
// keeps out of the mesh on every Linux node and chain antispoof keeps off the
// host's own services. BorderFilter owns two chains of the same table on every
// Linux node: chain antispoof, written wherever overlay is, drops a source in
// the overlay or a carved one arriving from outside the mesh that no exemption
// passes, before conntrack, and chain mesh_entry, written with or without an
// overlay, lets into the tun from another device only a reply, a source this
// node owns, an IPv6 link-local or multicast destination, or a destination a
// none class takes. desired lists each chain's rules in order. On macOS, where
// overlay is written, chain antispoof is the one chain, kept in a pf anchor
// under com.apple, and the filter keeps pf enabled while it runs (antispoof.md,
// "The pf anchor on macOS").
//
// It is a second owner beside Translator, with its own run goroutine, socket
// and change monitor, and neither writes, replaces or deletes the other's
// chains or sets, nor wakes the other's monitor by writing them. A table
// message wakes every owner unless it is a NEWTABLE whose flags are 0, which
// makes the table or clears its flags, so a flush of the ruleset or another
// program setting the dormant flag wakes each owner once, and the owner whose
// pass then makes the table again or clears the flag wakes no other. The
// filter keeps its chains through `ranet3 down`, since it guards the host's
// links rather than the mesh, withdraws them last at a stop the operator asks
// for, after nothing routes into the tun, and leaves them at the stop for the
// mesh's failure (antispoof.md, "Where it runs"). Its readiness is a report,
// in status and the metrics, and holds back nothing the translator or a
// segment carries.
package kernel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"ranet3.com/pkgs/ranet3/internal/egress"
	meshkernel "ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/netstack"
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
	// Members is the prefixes inside overlay that this node's table
	// routes by the tun to other nodes, none of them overlapping one of this
	// node's own, read on each pass. A family's forward lookups read from a
	// member's address, and a family with no member skips them. Nil reads none.
	Members func() []netip.Prefix
	// Write is the mesh's tun writer, which Egress hands its frames to, so each
	// flow keeps its lane and its order and the host routes and translates what
	// the tun delivers, with the hold on their storage Egress was handed
	Write func(frames [][]byte, hold netstack.Hold)
	// Hooks report what every exit reports. Republish is called once per pass
	// whose announcement differs from the last. A family is ready while this
	// node translates it, its chains, set and timeout objects read back exactly
	// as written, the host forwards it, the host holds every address its
	// classes translate to, and the kernel's lookups route a translated packet
	// and its reply the way the translation needs (see judge). The SIDs are
	// served while at least one family is ready and every family the host
	// forwards is.
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

// Timeouts is the protocol whose new flows a rule attaches this exit's own
// timeouts to, on a rule that goes on to the next, and NoTimeouts on a rule
// that translates, binds or returns
type Timeouts uint8

const (
	NoTimeouts Timeouts = iota
	// UDPTimeouts takes UDP to any destination port but a resolver's, 53
	UDPTimeouts
	TCPTimeouts
	// ICMPTimeouts is IPv4's, and ICMPv6Timeouts IPv6's
	ICMPTimeouts
	ICMPv6Timeouts
)

func (t Timeouts) String() string {
	switch t {
	case UDPTimeouts:
		return "udp"
	case TCPTimeouts:
		return "tcp"
	case ICMPTimeouts:
		return "icmp"
	case ICMPv6Timeouts:
		return "icmpv6"
	}
	return ""
}

// Rule is one rule this node installs, a translation, the timeouts ahead of
// one or the limit on each source's flows. The backend writes String as the
// rule's comment, which names the line in a readback, and reads the line back
// by its comment and by what it does.
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
	// Sources narrows a rule of a class of none's chain, with From left
	// invalid, to the sources of the classes that translate directly inside
	// that class, matched as one set, so the chain holds one rule of each kind
	// whatever their count
	Sources PrefixSet
	// Timeouts makes the rule one that attaches this exit's timeouts to a new
	// flow of its protocol and translates nothing, with Source and None left
	// unset. Such rules come ahead of each rule that translates, an In rule's
	// among them, keyed as it is.
	Timeouts Timeouts
	// Limit makes the rule an Out rule of the limit's chain that refuses a new
	// flow from From while its source holds Limit
	Limit int
	// Passes makes the rule an Out rule that sends every packet from From on to
	// the chain of that class of none, whose end passes it on. It sits in the
	// limit's chain, or under Under in the chain of the nearest class of none
	// covering it, ahead of every limit of that chain, so no limit counts its
	// flows and a packet outside the class meets this one rule for it.
	Passes bool
	// Under places a rule of the limit's chain in the chain of the class of
	// none from that prefix, the nearest of none covering the rule's sources,
	// and is left invalid for the hook's own chain
	Under netip.Prefix
	// Untracked makes the rule an Out or In rule of the limit's chain, ahead of
	// the limit, that takes a packet from From no flow is tracked for and drops
	// it. nf_nat leaves such a packet as it is, so a rule that translates would
	// send it on under its own source.
	Untracked bool
	// Drops makes the rule an IPv4 Out or In rule of the limit's chain, ahead
	// of the rules taking what no flow is tracked for, that drops the ICMP
	// messages of that kind from any source and under every class, RFC 5508
	// section 7 saying a NAT SHOULD NOT support them
	Drops Message
	// Protocol makes the rule an Out or In rule of the limit's chain, ahead of
	// the limit, that takes a packet of this protocol from From in its flow's
	// original direction and refuses it. Its checksum covers the addresses,
	// and a kernel with no tracker for the protocol does not rewrite it, so a
	// translated one would arrive there with a checksum its receiver discards.
	// A reply is translated only where its flow's first packet was, which the
	// rule took.
	Protocol Protocol
}

// byProtocol is whether r is a rule of the limit's chain that takes a packet
// by its protocol first, an ICMP drop or a protocol's refusal
func (r Rule) byProtocol() bool { return r.Drops != NoMessage || r.Protocol.Number != 0 }

// PrefixSet is prefixes of one family as one value, their text joined in the
// order Classes gives them, so a Rule holding them stays comparable, and empty
// for none
type PrefixSet string

func prefixSet(prefixes []netip.Prefix) PrefixSet {
	parts := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		parts = append(parts, prefix.String())
	}
	return PrefixSet(strings.Join(parts, " "))
}

// Prefixes is the set's prefixes, as prefixSet was given them
func (s PrefixSet) Prefixes() []netip.Prefix {
	var out []netip.Prefix
	for part := range strings.FieldsSeq(string(s)) {
		out = append(out, netip.MustParsePrefix(part))
	}
	return out
}

func (s PrefixSet) Contains(address netip.Addr) bool {
	return slices.ContainsFunc(s.Prefixes(), func(prefix netip.Prefix) bool { return prefix.Contains(address) })
}

// Protocol is an IP protocol by its number and the name nft gives it, the zero
// value on a rule that takes none
type Protocol struct {
	Number uint8
	Name   string
}

var (
	dccp    = Protocol{33, "dccp"}
	udpLite = Protocol{136, "udplite"}
	// checksummed is the protocols whose checksums cover the addresses
	checksummed = []Protocol{dccp, udpLite}
)

// Message is the ICMP messages a rule drops, NoMessage on any rule that drops
// none
type Message uint8

const (
	NoMessage Message = iota
	// SourceQuench is type 4
	SourceQuench
	// Information is types 15 and 16, the request and the reply
	Information
)

func (m Message) String() string {
	switch m {
	case SourceQuench:
		return "icmp source quench"
	case Information:
		return "icmp information"
	}
	return ""
}

// ruleKind names a rule's action, which decides the chain it sits in and
// whether it keeps a counter
type ruleKind uint8

const (
	// translating translates a flow's source, or binds it to its own for a
	// class of none, in the translation's chain, counting the flows it meets
	translating ruleKind = iota
	// timing attaches timeouts ahead of a translation and keeps no counter,
	// so a flow is counted once, by the translation after it
	timing
	// limiting refuses a source's new flow past the limit, at the forward
	// hook, counting the packets it refuses
	limiting
	// dropping drops a packet no flow is tracked for, counting the packets
	dropping
	// passing sends every packet of a class of none on to its class's chain,
	// past the limit and the rules after it, keeping no counter
	passing
	// screening drops an ICMP message of a kind or refuses a packet by its
	// protocol, at the forward hook, counting the packets
	screening
)

func (r Rule) kind() ruleKind {
	switch {
	case r.Passes:
		return passing
	case r.Limit != 0:
		return limiting
	case r.byProtocol():
		return screening
	case r.Untracked:
		return dropping
	case r.Timeouts != NoTimeouts:
		return timing
	}
	return translating
}

// chain is the base chain whose hook meets a rule of the kind
func (k ruleKind) chain() string {
	if k == translating || k == timing {
		return ChainName
	}
	return LimitChain
}

// chain is the chain the rule sits in: the one Under names, else its family's
// for a kind of the forward hook's, else the translation's
func (r Rule) chain() string {
	switch {
	case r.Under.IsValid():
		return noneChain(r.Under)
	case r.kind().chain() == LimitChain:
		return familyChain(r.Family)
	}
	return ChainName
}

// familyChain names the chain family's lines at the forward hook sit in: for
// IPv4 the hook's own, past the first line, which sends IPv6's packets on, and
// for IPv6 the regular chain that line sends them to
func familyChain(family uint8) string {
	if family == egress.FamilyIPv4 {
		return LimitChain
	}
	return LimitChain + digit(family)
}

// digit ends the name of each of the translator's chains, sets and objects of
// family
func digit(family uint8) string {
	if family == egress.FamilyIPv4 {
		return "4"
	}
	return "6"
}

// noneChain names the chain of the class of none from prefix in letters,
// digits and underscores, which nft lists and reads back as they are written
func noneChain(prefix netip.Prefix) string {
	return NoneChain + strings.NewReplacer(".", "_", ":", "_", "/", "_").Replace(prefix.String())
}

// counted is whether a rule of the kind keeps a counter
func (k ruleKind) counted() bool { return k != timing && k != passing }

// counterUnit names the unit of a counter read from chain: flows in the
// translation's chain, which meets a flow's first packet alone, packets in
// those past the forward hook's, and none where the rule keeps no counter
func counterUnit(chain string, counted bool) string {
	switch {
	case !counted:
		return ""
	case chain == ChainName:
		return "flows"
	}
	return "packets"
}

// String is the rule as an operator reads it in `nft list ruleset`. Every
// field that changes what the rule does is in it, so two lines of a chain never
// share a comment, but Sources, which would not fit nft's comment: a rule
// taking them names the class of none whose chain it sits in, and its set's
// elements are read back apart.
func (r Rule) String() string {
	action := "masquerade"
	switch kind := r.kind(); {
	case kind == limiting:
		action = fmt.Sprintf("limit %d", r.Limit)
	case kind == passing:
		action = "passed"
	case r.Drops != NoMessage:
		action = r.Drops.String() + " dropped"
	case r.Protocol.Number != 0:
		action = r.Protocol.Name + " refused"
	case kind == dropping:
		action = "untracked dropped"
	case kind == timing:
		action = "timeouts " + r.Timeouts.String()
	case r.None:
		action = "untranslated"
	case r.Source.IsValid():
		action = "source " + r.Source.String()
	}
	parts := []string{r.Direction.String(), "via", r.Interface, egress.FamilyName(r.Family)}
	switch {
	case r.Sources != "":
		parts = append(parts, "translated inside", r.Under.String())
	case r.From.IsValid():
		parts = append(parts, "from", r.From.String())
	}
	return strings.Join(append(parts, action), " ")
}

// Installed is one rule as the backend read it back: the spelling it was
// written under, the family it is placed in and what it has carried since.
// The counters are outside the diff on purpose, because they change on every
// packet and a diff holding them would rewrite the ruleset on every pass.
type Installed struct {
	Spec string
	// Family is the family of the translator's rule written under Spec, which
	// places a rule another writer put in a chain, read back with no spelling,
	// by the chain it was read from. The antispoof filter leaves it 0.
	Family uint8
	// Chain is the chain it was read from, and Counted whether it keeps a
	// counter, which say what a rule another writer put there counts
	Chain   string
	Counted bool
	Packets uint64
	Bytes   uint64
}

// chainReadback is nftables.Readback with each rule placed in its family. It
// lives here rather than there because this file builds on every platform.
type chainReadback struct {
	// rules is every rule of the family's chains in order, the chains in the
	// order desired writes them, one carrying no comment as an empty spec,
	// which no rule this package writes has
	rules []Installed
	fault string
	// unready says why the filter is not ready where its own rules read back
	// as written, which a rewrite would not change
	unready string
	// remake is a chain, set or object the readback found that a rewrite
	// cannot mend in place, which the write deletes and makes again
	remake bool
	// pf is pf's state beside the anchor as the antispoof filter's pf backend
	// read it, nil on every other backend
	pf *egress.BorderPF
	// held is whether any of the antispoof filter's chains or sets is there,
	// which its readback alone sets
	held bool
}

// backend is the kernel surface a translator drives. Everything above it is
// portable and syscall-free, so the diff and the refusal rules are testable
// against a fake.
type backend interface {
	// Rules reads back the translator's own chains, sets and objects and the
	// table holding them, keyed by family, each chain's lines against desired
	// by their comments and their expressions.
	Rules(desired []Rule) (map[uint8]chainReadback, error)
	// Read is Rules with desired naming the chains alone, through a socket of
	// its own, for a reader off the run goroutine, which owns the backend's
	// socket
	Read(desired []Rule) (map[uint8]chainReadback, error)
	// Apply brings the translator's own chains to rules, deleting first where
	// remake each chain, set or object that cannot change in place. It
	// replaces the chains' contents in one transaction rather than editing
	// them, because nftables commits a batch atomically and a chain rewritten
	// rule by rule has a window in which a packet leaves untranslated.
	Apply(rules []Rule, remake bool) error
	// Conflicts names the source translation already on the host that this
	// node's traffic could meet, for an operator rather than as a number.
	Conflicts() ([]string, error)
	// Withdraw removes the translator's own chains, sets and objects, and the
	// table with them where it holds nothing else. What is already gone is
	// success.
	Withdraw() error
	// Changed carries one coalesced wake-up per transaction in which another
	// writer deleted the table, set a flag on it, or added, changed or deleted
	// one of the translator's own chains, rules or sets or a set's elements,
	// and may carry more than one for a transaction read in the span after a
	// loss that nftables.Monitor's doc gives.
	Changed() <-chan struct{}
	// Missed carries one coalesced wake-up per batch of notifications the
	// backend lost or could not read, any of which may have been a change.
	Missed() <-chan struct{}
	Close() error
	// where names the space this backend owns, for a log line.
	where() string
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
	// Refused4 and Refused6 count each family's packets the limit refused, each
	// retry of a refused flow among them, Dropped4 and Dropped6 those dropped
	// for want of a tracked flow, and ConntrackCount and ConntrackMax are the
	// host's table, nil where unread
	Refused4, Refused6           uint64
	Dropped4, Dropped6           uint64
	ConntrackCount, ConntrackMax *uint64
	Announced                    []netip.Prefix
	Conflicts                    []string
	Err                          string
	// Ready4 and Ready6 are each family's readiness, false for a family this
	// node does not translate. Unready says why a family it translates is not
	// ready, and Skipped what the lookups left out and why, each empty where
	// there is nothing to say
	Ready4, Ready6   bool
	Unready, Skipped string
	// judged is each translated family's judgment, which Debug reads
	judged map[uint8]judgment
}

// Translator owns the capability on one node: the rules, the chains they live
// in, and the advertisement that depends on both.
type Translator struct {
	cfg egress.Egress
	rt  Runtime
	be  backend

	// stats is the last pass as a reader takes it. The single run goroutine
	// publishes a whole value and a reader takes one, so this needs no lock
	// and a reader can never see half a pass.
	stats atomic.Pointer[passStats]
	*egress.Shell
	// warned holds the conflicts already reported, so a shared host costs one
	// log line per new conflict rather than one per pass.
	warned []string
	// trigger names what woke the run goroutine for the pass it runs, and belongs to that goroutine
	trigger string
	// withdrawn is the run goroutine's record of having acted on a stop, as
	// kernel.Reconciler keeps one
	withdrawn bool
}

var _ egress.Exit = (*Translator)(nil)

// newTranslator is a translator over a backend that is already open, writing to the host until SetEnabled stops it
func newTranslator(cfg egress.Egress, rt Runtime, be backend) *Translator {
	t := &Translator{cfg: cfg, rt: rt, be: be}
	t.Shell = egress.NewShell(&t.rt.Hooks)
	return t
}

// Egress hands the frames and their hold to the mesh's tun writer, whose lanes
// keep each flow in order and the hold until written, and the host routes and
// translates what the tun delivers
func (t *Translator) Egress(frames [][]byte, hold netstack.Hold) { t.rt.Write(frames, hold) }

// Status is the last pass, the capability's translation and the rules the
// host holds for this translator
func (t *Translator) Status() egress.Status { return t.statusOf(t.lastPass()) }

func (t *Translator) statusOf(stats passStats) egress.Status {
	advertise := make([]netip.Prefix, 0, len(t.cfg.Advertise))
	for _, entry := range t.cfg.Advertise {
		advertise = append(advertise, entry.Prefix)
	}
	return egress.Status{
		Backend: "nftables", Where: t.where(),
		Ready4: stats.Ready4, Ready6: stats.Ready6, Unready: stats.Unready, Skipped: stats.Skipped,
		Advertise: advertise, Announced: stats.Announced,
		Translate: t.cfg.Translate, Return: t.cfg.Return,
		FlowsPerSource: t.cfg.SourceLimit(), Refused4: stats.Refused4, Refused6: stats.Refused6,
		Dropped4: stats.Dropped4, Dropped6: stats.Dropped6,
		PassAt: stats.At, Err: stats.Err,
		Rules: &egress.Rules{
			Installed: stats.Installed, Flows: stats.Flows, Bytes: stats.Bytes, Untranslated: stats.Untranslated,
			ConntrackCount: stats.ConntrackCount, ConntrackMax: stats.ConntrackMax, Conflicts: stats.Conflicts,
		},
	}
}

// Debug reads the chains now through a socket of the backend's own, so an
// operator injecting a packet reads counters of now rather than of the last
// sweep, and lays each family's readiness beside them as the last pass judged
// it, from the lookups and answers that pass read
func (t *Translator) Debug() egress.ExitDebug {
	pass := t.lastPass()
	out := egress.ExitDebug{Status: t.statusOf(pass)}
	desired := t.desired()
	read, err := t.be.Read(desired)
	if err != nil {
		out.ReadErr = err.Error()
	}
	held, _, _ := flatten(read)
	readings := make(map[string]Installed, len(held))
	for _, reading := range held {
		readings[reading.Spec] = reading
	}
	for _, rule := range desired {
		reading, ok := readings[rule.String()]
		delete(readings, rule.String())
		out.Rules = append(out.Rules, egress.RuleReading{Spec: rule.String(), Wanted: true, Held: ok, Counter: counterUnit(rule.chain(), rule.kind().counted()), Packets: reading.Packets, Bytes: reading.Bytes})
	}
	for _, reading := range held {
		if _, extra := readings[reading.Spec]; extra {
			out.Rules = append(out.Rules, egress.RuleReading{Spec: reading.Spec, Held: true, Counter: counterUnit(reading.Chain, reading.Counted), Packets: reading.Packets, Bytes: reading.Bytes})
		}
	}
	var devices []string
	for _, family := range t.cfg.Translated(t.rt.Steered) {
		j, ok := pass.judged[family]
		if !ok {
			continue
		}
		out.Families = append(out.Families, egress.FamilyReading{
			Family: family, Ready: j.ready, Why: j.why, Unwritten: j.unwritten, Forwarding: j.forwarding, Lookups: j.lookups, Answers: j.answers,
		})
		for _, answer := range j.answers {
			for _, hop := range append(slices.Clone(answer.Route.Hops), answer.Reply.Hops...) {
				devices = append(devices, hop.Device)
			}
		}
	}
	slices.Sort(devices)
	for _, device := range append([]string{"all"}, slices.Compact(devices)...) {
		name := "net/ipv4/conf/" + device + "/rp_filter"
		out.RPFilter = append(out.RPFilter, egress.Setting{Name: name, Value: t.rt.Sysctl(name)})
	}
	return out
}

func (t *Translator) where() string { return t.be.where() }

// lastPass is the last pass, and the zero value before the first has run, which At tells apart
func (t *Translator) lastPass() passStats {
	if s := t.stats.Load(); s != nil {
		return *s
	}
	return passStats{}
}

// Run reconciles until ctx is canceled, then withdraws the chains this
// translator owns and closes what the backend holds. It is called once.
//
// Run returns the withdrawal error, never a reconcile error: a failed pass is
// logged, costs the advertisement, and is retried.
func (t *Translator) Run(ctx context.Context) error {
	slog.Info("egress translator started", "interface", t.rt.Interface, "steered", t.rt.Steered, "where", t.where(),
		"advertise", len(t.cfg.Advertise))
	sweep := t.cfg.SweepInterval()
	ticker := time.NewTicker(sweep)
	defer ticker.Stop()
	retry := meshkernel.NewRetryTimer()
	defer retry.Stop()

	t.trigger = "start"
	for ctx.Err() == nil {
		if !t.Enabled.Load() {
			// once per stop rather than once per wake, and a withdrawal that
			// failed is retried on the backoff a failed pass takes
			if !t.withdrawn {
				if err := t.stop(); err != nil {
					slog.Warn("egress could not withdraw its chains, retrying", "err", err, "retry_in", retry.Failed(sweep))
				} else {
					t.withdrawn = true
					retry.Passed()
				}
			}
		} else {
			// the record of a stop lasts until the next pass, whatever woke it
			if t.withdrawn {
				t.withdrawn = false
				slog.Info("egress translator started again", "where", t.where())
			}
			if err := t.reconcile(); err != nil {
				slog.Warn("egress pass failed, retrying", "err", err, "retry_in", retry.Failed(sweep))
			} else {
				retry.Passed()
			}
		}
		select {
		case <-ctx.Done():
		case <-ticker.C:
			t.trigger = "sweep"
		case <-retry.C:
			t.trigger = "retry"
		case <-t.Wake():
			// SetEnabled wakes the loop whichever way it went
			t.trigger = "disable"
			if t.Enabled.Load() {
				t.trigger = "enable"
			}
		case <-t.be.Changed():
			// the steered rule may be gone or bypassed already, so the mesh stops handing this exit its packets before the pass that puts it back
			t.trigger = "changed"
			t.SetUnready("another writer changed its table")
		case <-t.be.Missed():
			// another table's large transaction overflows the socket as readily as a flush of this one, so only the pass's readback decides
			t.trigger = "missed"
		}
	}
	// Readiness and the advertisement go before the rules do. A peer that
	// keeps selecting this node while its chains are being taken down is a peer
	// whose traffic leaves untranslated, and babel's own retraction is the
	// only thing that can tell it otherwise.
	t.SetUnready("the translator is stopping")
	t.Publish(nil)
	return errors.Join(t.withdraw(), t.be.Close())
}

func (t *Translator) Close() error { return t.be.Close() }

// reconcile brings the host to the rules the configuration asks for and
// republishes what may be advertised as a result. The rules are compared
// before they are written, so a pass that changes nothing costs one readback
// and leaves the counters where they are.
func (t *Translator) reconcile() error {
	started := time.Now()
	desired := t.desired()
	applied := false
	read, err := t.be.Rules(desired)
	unread := err != nil
	listed := !unread
	held, faulted, remake := flatten(read)
	if err != nil {
		err = fmt.Errorf("list rules: %w", err)
	} else if faulted {
		if applyErr := t.be.Apply(desired, remake); applyErr != nil {
			err = fmt.Errorf("install rules: %w", applyErr)
		} else {
			applied = true
			slog.Info("egress rules installed", "rules", len(desired), "replaced", len(held), "where", t.where())
			// Read back rather than assumed. The counters below are the
			// host's, and a rule the kernel holds other than it was written
			// has to fail the readiness test rather than pass it on this pass
			// and fail on the next.
			if read, err = t.be.Rules(desired); err != nil {
				err = fmt.Errorf("list rules: %w", err)
			}
			listed = err == nil
			held, _, _ = flatten(read)
		}
	}
	conflicts, conflictErr := t.be.Conflicts()
	err = errors.Join(err, conflictErr)
	if conflictErr == nil {
		t.reportConflicts(conflicts)
	}

	// Readiness is per family and is read from the host on every pass rather
	// than captured at startup, because each part of it changes under a
	// running node: a table can be flushed by somebody else, a forwarding
	// sysctl can be turned on after this process started, and a route can send
	// a translated packet or its reply another way. A family's chains
	// count only while they and their table read back exactly as written, since
	// another writer's rule among this tool's, a dormant table or a chain at
	// another hook, which an apply that failed leaves in place, changes what
	// a chain does to a packet.
	v4, v6 := t.rt.Forwarding()
	forwards := map[uint8]bool{egress.FamilyIPv4: v4, egress.FamilyIPv6: v6}
	unwritten := map[uint8]string{}
	for _, family := range []uint8{egress.FamilyIPv4, egress.FamilyIPv6} {
		switch {
		case !listed:
			unwritten[family] = "its chains could not be read back"
		case read[family].fault != "":
			unwritten[family] = read[family].fault
		}
	}
	judged := t.judge(unwritten, forwards)
	announced := make([]netip.Prefix, 0, len(t.cfg.Advertise))
	for _, entry := range t.cfg.Advertise {
		if judged[egress.AddressFamily(entry.Addr())].ready {
			announced = append(announced, entry.Prefix)
		}
	}
	j4, j6 := judged[egress.FamilyIPv4], judged[egress.FamilyIPv6]
	skipped := skippedText(j4, j6)
	t.SetReady(egress.Readiness{Ready4: j4.ready, Ready6: j6.ready, Why4: j4.why, Why6: j6.why, Carries4: v4, Carries6: v6, Skipped: skipped})
	moved := t.Publish(announced)

	kinds := map[string]Rule{}
	for _, rule := range desired {
		kinds[rule.String()] = rule
	}
	var flows, bytes, untranslated uint64
	refused, dropped := map[uint8]uint64{}, map[uint8]uint64{}
	for _, rule := range held {
		switch want := kinds[rule.Spec]; want.kind() {
		case screening, passing, timing:
			// nf_tables' counters alone hold a screen's, which no Status field
			// reads, and a pass and the timeouts keep none
		case limiting:
			refused[rule.Family] += rule.Packets
		case dropping:
			dropped[rule.Family] += rule.Packets
		case translating:
			if want.None {
				untranslated += rule.Packets
				continue
			}
			flows += rule.Packets
			bytes += rule.Bytes
		}
	}
	// the counters are the host's, and a pass that could not read them keeps the
	// last pass's rather than reading as a reset. One that rewrote the chains
	// starts from zero as their counters do, whether or not it read them back.
	if unread {
		last := t.lastPass()
		flows, bytes, untranslated = last.Flows, last.Bytes, last.Untranslated
		refused[egress.FamilyIPv4], refused[egress.FamilyIPv6] = last.Refused4, last.Refused6
		dropped[egress.FamilyIPv4], dropped[egress.FamilyIPv6] = last.Dropped4, last.Dropped6
	}
	stats := passStats{
		At: time.Now(), Desired: len(desired), Installed: len(held),
		Flows: flows, Bytes: bytes, Untranslated: untranslated,
		Refused4: refused[egress.FamilyIPv4], Refused6: refused[egress.FamilyIPv6],
		Dropped4: dropped[egress.FamilyIPv4], Dropped6: dropped[egress.FamilyIPv6],
		ConntrackCount: t.conntrack("count"), ConntrackMax: t.conntrack("max"),
		Announced: announced, Conflicts: conflicts,
		Ready4: j4.ready, Ready6: j6.ready, Unready: t.Unready(), Skipped: skipped,
		judged: judged,
	}
	if err != nil {
		stats.Err = err.Error()
	}
	last := t.lastPass()
	if applied {
		last = passStats{}
	}
	t.reportRefused(last, stats)
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

// conntrack reads conntrack's setting of that name, nil where it cannot, as
// before conntrack has loaded
func (t *Translator) conntrack(setting string) *uint64 {
	value, err := strconv.ParseUint(t.rt.Sysctl("net/netfilter/nf_conntrack_"+setting), 10, 64)
	if err != nil {
		return nil
	}
	return &value
}

// reportRefused records egress.refused for each family whose count of refused
// packets moved from last to now, with the packets refused since. A count below
// the last, which a reset of the rule's counter leaves, counts from zero.
func (t *Translator) reportRefused(last, now passStats) {
	for _, family := range []struct {
		family    uint8
		was, held uint64
	}{{egress.FamilyIPv4, last.Refused4, now.Refused4}, {egress.FamilyIPv6, last.Refused6, now.Refused6}} {
		since := family.held
		if family.held >= family.was {
			since -= family.was
		}
		if since != 0 {
			t.rt.Events.Emit("egress.refused", "", slog.String("family", egress.FamilyName(family.family)), slog.Uint64("refused", since))
		}
	}
}

// flatten is every family's rules in the order desired groups them, whether
// any family reads back with a fault, and whether any reads back with a chain,
// set or object Apply deletes and makes again
func flatten(read map[uint8]chainReadback) (held []Installed, faulted, remake bool) {
	for _, family := range []uint8{egress.FamilyIPv4, egress.FamilyIPv6} {
		held = append(held, read[family].rules...)
		faulted = faulted || read[family].fault != ""
		remake = remake || read[family].remake
	}
	return held, faulted, remake
}

// desired is the rules this configuration asks for, grouped by family and
// then in the order a packet meets them within one chain, which is the order a
// backend writes each chain's lines in and reads them back. Within a family
// the forward hook's rules come first, as a forwarded packet meets them before
// the translation's.
func (t *Translator) desired() []Rule {
	var out []Rule
	for _, family := range t.cfg.Translated(t.rt.Steered) {
		// ahead of the pass under none, which ends the chain
		if family == egress.FamilyIPv4 {
			for _, direction := range []Direction{Out, In} {
				for _, message := range []Message{SourceQuench, Information} {
					out = append(out, Rule{Family: family, Direction: direction, Interface: t.rt.Interface, Drops: message})
				}
			}
		}
		out = append(out, t.screens(family)...)
		covered := false
		for _, class := range t.cfg.Classes(family) {
			covered = covered || class.From.Bits() == 0
			out = append(out, t.classRules(family, Out, class.From.Prefix, class.To)...)
		}
		if !covered {
			out = append(out, t.classRules(family, Out, netip.Prefix{}, egress.Translation{Auto: true})...)
		}
		out = append(out, t.inbound(family)...)
		for _, address := range egress.MeshSources(family, t.rt.MeshAddresses) {
			out = append(out, t.classRules(family, Local, netip.PrefixFrom(address, address.BitLen()), t.cfg.ClassOf(address).To)...)
		}
	}
	return out
}

// classRules is the rules taking the new flows of family from from, keyed on
// direction, as to says. A translation is a NAT the three RFCs on timeouts
// cover, the return direction's included, so the exit's timeouts attach to its
// flows first, and a class of none binds its flows alone, so they keep the
// host's timeouts.
func (t *Translator) classRules(family uint8, direction Direction, from netip.Prefix, to egress.Translation) []Rule {
	// A prefix covering every address narrows nothing, and a rule carrying it
	// would encode a mask no packet fails, so it is left off and the rules
	// select on the direction alone.
	if from.Bits() == 0 {
		from = netip.Prefix{}
	}
	keyed := Rule{Family: family, Direction: direction, Interface: t.rt.Interface, From: from}
	translation := keyed
	translation.Source, translation.None = to.Addr, to.None
	if to.None {
		return []Rule{translation}
	}
	var out []Rule
	for _, timeouts := range familyTimeouts(family) {
		rule := keyed
		rule.Timeouts = timeouts
		out = append(out, rule)
	}
	return append(out, translation)
}

// screens is the limit chain's rules past the ICMP drops, then the rules of
// each class of none's chain, the chains in the order their passes come. A
// class of none has its pass, in the chain of the nearest class of none
// covering it or in the limit chain where none does. The chain of a class of
// none holds the passes of the classes of none it is nearest to, then where a
// class that translates has it as its nearest shorter class covering it, one
// rule of each kind of screen from the sources of every such class, matched as
// one set. One that translates inside another that translates meets the
// screens that one meets, every source's where no class of none covers it.
// The passes of each chain come in the order Classes gives, and the limit
// chain's are followed by the screens from every source, then those into the
// mesh from each prefix an In rule translates. So a packet under a class that
// translates meets one limit, one under a class of none meets none, one
// outside a class of none meets its pass alone, and one under a class of none
// that directly holds a class that translates meets one rule of each kind of
// screen there, whatever their count, and none under one that directly holds
// none.
func (t *Translator) screens(family uint8) []Rule {
	classes := t.cfg.Classes(family)
	var out []Rule
	passes := map[netip.Prefix][]Rule{}
	inside := map[netip.Prefix][]netip.Prefix{}
	for i, class := range classes {
		later := classes[i+1:]
		// the shorter class nearest it that covers it, whose rules its packets
		// meet next, and the nearest of none
		covering := slices.IndexFunc(later, func(c egress.Class) bool { return c.From.Overlaps(class.From.Prefix) })
		var under netip.Prefix
		if none := slices.IndexFunc(later, func(c egress.Class) bool { return c.To.None && c.From.Overlaps(class.From.Prefix) }); none >= 0 {
			under = later[none].From.Prefix
		}
		switch {
		case class.To.None && under.IsValid():
			passes[under] = append(passes[under], Rule{Family: family, Direction: Out, Interface: t.rt.Interface, From: class.From.Prefix, Passes: true, Under: under})
		case class.To.None:
			out = append(out, Rule{Family: family, Direction: Out, Interface: t.rt.Interface, From: class.From.Prefix, Passes: true})
		case covering >= 0 && later[covering].To.None:
			inside[under] = append(inside[under], class.From.Prefix)
		}
	}
	out = append(out, t.screen(family, Out, netip.Prefix{})...)
	for _, rule := range t.inbound(family) {
		if rule.Timeouts == NoTimeouts {
			out = append(out, t.screen(family, In, rule.From)...)
		}
	}
	for i := 0; i < len(out); i++ {
		if !out[i].Passes {
			continue
		}
		none := out[i].From
		out = append(out, passes[none]...)
		if len(inside[none]) == 0 {
			continue
		}
		for _, rule := range t.screen(family, Out, netip.Prefix{}) {
			rule.Sources, rule.Under = prefixSet(inside[none]), none
			out = append(out, rule)
		}
	}
	return out
}

// screen is the rules taking direction's packets from from that no flow is
// tracked for and those of each checksummed protocol, and out of the mesh the
// limit after them, which counts the flows of a source of a class that
// translates
func (t *Translator) screen(family uint8, direction Direction, from netip.Prefix) []Rule {
	keyed := Rule{Family: family, Direction: direction, Interface: t.rt.Interface, From: from}
	untracked := keyed
	untracked.Untracked = true
	out := []Rule{untracked}
	for _, protocol := range checksummed {
		rule := keyed
		rule.Protocol = protocol
		out = append(out, rule)
	}
	if direction == Out {
		limit := keyed
		limit.Limit = t.cfg.SourceLimit()
		out = append(out, limit)
	}
	return out
}

func familyTimeouts(family uint8) []Timeouts {
	if family == egress.FamilyIPv6 {
		return []Timeouts{UDPTimeouts, TCPTimeouts, ICMPv6Timeouts}
	}
	return []Timeouts{UDPTimeouts, TCPTimeouts, ICMPTimeouts}
}

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
		if egress.AddressFamily(prefix.Addr()) == family {
			out = append(out, t.classRules(family, In, prefix.Prefix, egress.Translation{Addr: source})...)
		}
	}
	return out
}

// reportConflicts names, once per new entry, other source translation on this
// host that can run ahead of this node's. It is a report rather than an
// action: several nat postrouting chains coexist, the first to translate a
// connection wins it, and taking another writer's rule away to win that race
// would break whatever installed it.
func (t *Translator) reportConflicts(conflicts []string) {
	for _, conflict := range conflicts {
		if slices.Contains(t.warned, conflict) {
			continue
		}
		slog.Warn("egress is sharing the source translation hook with another writer",
			"other", conflict,
			"detail", "a chain at this node's priority or below can run ahead of this node's, and the first chain to translate a connection keeps it, so a flow this node meant to translate may leave under that writer's address instead")
	}
	t.warned = slices.Clone(conflicts)
}

// stop retracts the advertisement and withdraws the chains, in the order Run's
// exit takes, and records the pass. The pass reads zero installed, so a
// diagnostic does not go on reporting the rules of the last pass that ran.
func (t *Translator) stop() error {
	started := time.Now()
	t.SetUnready("the translator is stopped")
	t.Publish(nil)
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

// withdraw removes the chains, sets and objects this translator owns, and the
// table with them where nothing else is in it. It is best effort by
// construction: the caller usually stops the mesh at the same moment, and what
// is already gone is not an error.
func (t *Translator) withdraw() error {
	if err := t.be.Withdraw(); err != nil {
		return fmt.Errorf("withdraw %s: %w", t.where(), err)
	}
	slog.Info("egress translator withdrawn", "where", t.where())
	return nil
}
