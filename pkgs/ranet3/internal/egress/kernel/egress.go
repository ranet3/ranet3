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
// regular chain of IPv6's and holds IPv4's lines itself, and for each family
// the timeout objects the translation attaches, a set that holds each mesh
// source under a class that translates to its share of the flows
// (exit-nodes.md, "Each source's share of the flows"), and a set of the sources
// whose class is none, which the forward chain passes. Their names are the
// ownership marker, the way Table.Proto is the reconciler's in
// internal/kernel. This package writes only those. A shutdown withdraws them,
// with the table as nftables.Hold.Withdraw says, where the mesh device has
// gone with the mesh, and leaves a stopped translator's rules in their place
// where it has not or that cannot be read (Translator.Run).
// It reads other writers' tables, chains and rules to find its own and to
// report conflicts, and writes, replaces or deletes nothing else. A rule
// another writer puts in this package's chains is removed by the next pass,
// with what nf_tables ties to a rule of another writer's in this package's
// chains.
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
// Announce answers the prefixes of each family that is ready (exit-nodes.md,
// "Readiness"), and nothing at all while no family is, and Republish says when
// that answer moves.
//
// # The antispoof filter
//
// An exit's allow list says which sources it carries out of the mesh, and
// it is authorization rather than a filter: a host on any link of a forwarding
// node can send that node a packet with a mesh source, which chain entry
// keeps out of the mesh on every Linux node and chain antispoof keeps off the
// host's own services. BorderFilter owns two chains of the same table on every
// Linux node: chain antispoof, written wherever overlay is, drops a source in
// the overlay or a carved one arriving from outside the mesh that no exemption
// passes, before conntrack, and chain entry, written with or without an
// overlay, lets into the tun from another device only the packets it lists
// (antispoof.md, "The entry chain"). desired lists each chain's rules in
// order. On macOS, where
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
	"cmp"
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
	// arriving on it and leaving by another link is translated in each family
	// egress.Egress.Translated gives, while one arriving on it and leaving by it
	// again is mesh transit and is left alone.
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
	// Done is closed once the mesh has closed, after which it writes nothing
	// more to the tun. The end of Run waits for it before the chains go, so a
	// packet a session took before the stop meets the chains it met before:
	// a running translator's, which translate it or bind it to its own source
	// under a class of none, or a stopped one's (Translator.stopped).
	Done <-chan struct{}
	// Present is whether a device of the calling thread's network namespace
	// holds the index the mesh device held when the exit was built, supplied
	// as Sysctl is. The end of Run reads it after Done and withdraws only
	// where none does: a mesh device that went with the mesh's close was
	// unregistered within it, and no frame it took reaches the forward hook
	// after, where one still there can hold such a frame past Done. Where one
	// does, the mesh device or another that took its index, or the reading
	// counts as unread, as DevicePresence's reader judges it, the shutdown
	// leaves a stopped translator's rules in place of the withdrawal. A device
	// another program removes or moves to another namespace while this reads
	// is gone from the reading while a frame it took can still reach the
	// forward hook (design/limits.md).
	Present func() (bool, error)
	// Hooks report what every exit reports. Republish is called once per pass
	// whose announcement differs from the last. A family is ready as Linux's
	// readiness gives (exit-nodes.md, "Readiness", and judge). The SIDs are
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
	// Sources is the prefixes a pass, and a stopped translator's Labelled rule
	// ahead of it, look a source up in, those whose class is none, which its
	// family's set of them holds
	Sources PrefixSet
	// Timeouts makes the rule one that attaches this exit's timeouts to a new
	// flow of its protocol and translates nothing, with Source and None left
	// unset. Such rules come ahead of each rule that translates, an In rule's
	// among them, keyed as it is.
	Timeouts Timeouts
	// Limit makes the rule an Out rule of the limit's chain that refuses a new
	// flow from From while its source holds Limit
	Limit int
	// Passes makes the rule an Out rule of the forward hook, ahead of every
	// screen, that accepts a packet from a source Sources holds, with From left
	// invalid, so no screen or limit meets a packet whose class is none
	Passes bool
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
	// Stopped names the rule's place among a stopped translator's rules
	Stopped Stop
}

// Stop names a rule's place among a stopped translator's rules (see stopped)
type Stop uint8

const (
	// Running is a running translator's rule, or one a stopped translator
	// keeps where it sat
	Running Stop = iota
	// Held stands in place of a limit and drops every packet out of the mesh
	// from From, whatever its flow's state
	Held
	// Labelled drops a packet of the family that leaves by a link other than
	// the mesh device and whose flow carries the exit's connection label,
	// whatever link it came in by, or with Sources set, one out of the mesh
	// from a source the family's pass looks up (Rule.setsLabel says which
	// rules set it)
	Labelled
)

// byProtocol is whether r is a rule of the limit's chain that takes a packet
// by its protocol first, an ICMP drop or a protocol's refusal
func (r Rule) byProtocol() bool { return r.Drops != NoMessage || r.Protocol.Number != 0 }

// PrefixSet is prefixes of one family as one value, their text joined in
// order, so a Rule holding them stays comparable, and empty for none
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
	// passing accepts every packet from a source whose class is none, past the
	// screens and the limit after it, keeping no counter
	passing
	// screening drops an ICMP message of a kind or refuses a packet by its
	// protocol, at the forward hook, counting the packets
	screening
	// holding is a Held rule's, at the forward hook, counting the packets
	holding
	// leaving is a Labelled rule's, at the forward hook, counting the packets
	leaving
)

func (r Rule) kind() ruleKind {
	switch {
	case r.Stopped == Held:
		return holding
	case r.Stopped == Labelled:
		return leaving
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

// chain is the chain the rule sits in: its family's for a kind of the forward
// hook's, else the translation's
func (r Rule) chain() string {
	if r.kind().chain() == LimitChain {
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
// share a comment, but Sources, which would not fit nft's comment: a pass, as
// the Labelled rule ahead of it, is its family's one, and its set's elements
// are read back apart.
func (r Rule) String() string {
	action := "masquerade"
	switch kind := r.kind(); {
	case kind == leaving && r.Sources != "":
		// out of the mesh from the untranslated sources, as the family's pass
		// takes a packet
		return "out via " + r.Interface + " " + egress.FamilyName(r.Family) + " untranslated leaving by another link dropped while stopped"
	case kind == leaving:
		return "translated via " + r.Interface + " " + egress.FamilyName(r.Family) + " leaving by another link dropped while stopped"
	case kind == holding:
		action = "dropped while stopped"
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
	case r.Passes:
		parts = append(parts, "untranslated")
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
	// flag is the fault of a flag other than dormant another writer gave the
	// table, which the translator's write is refused for and which fault
	// starts with in every family. Its text names every flag the table holds.
	flag string
	// dormant is the fault of the table's flags where they hold the dormant
	// one, the same text as flag where they hold another too. A dormant table
	// runs none of its chains.
	dormant string
	// misplaced is, where the readback read the chains' lines, the family's
	// first chain that reads back otherwise than written, by its type, hook,
	// priority, policy or lines, or else the first set or object a rule of the
	// family uses that reads back otherwise than written, a set by its elements
	// too, whatever else the readback names. It is empty where all of them
	// read back as written.
	misplaced string
	// refusedOn is the fault of a set or object of the family's that a write
	// is refused on, which names what holds it. It is empty where the family
	// has none.
	refusedOn string
	// unready says why the filter is not ready where its own rules read back
	// as written, which a rewrite would not change
	unready string
	// remake is a chain, set or object the readback found that a rewrite
	// cannot mend in place, which the write deletes and makes again
	remake bool
	// pf is pf's state beside the anchor as the antispoof filter's pf backend
	// read it, nil on every other backend
	pf *egress.BorderPF
	// held is whether any chain, set or object of the owner's that the family
	// reads is there, set by the antispoof filter's readback and by the
	// translator's
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
	// remake each chain, set or object that cannot change in place, and on
	// nftables, where nf_tables refuses that transaction with EEXIST, every
	// set of its own the table holds, its sets of flows and their counts
	// among them, as nftables.Hold.Rewrite says. It
	// replaces the chains' contents in one transaction rather than editing
	// them, because nftables commits a batch atomically and a chain rewritten
	// rule by rule has a window in which a packet leaves untranslated.
	Apply(rules []Rule, remake bool) error
	// Conflicts names the source translation already on the host that this
	// node's traffic could meet, for an operator rather than as a number.
	Conflicts() ([]string, error)
	// Withdraw removes the translator's own chains, sets and objects, and on
	// nftables the table as nftables.Hold.Withdraw says. What is already gone
	// is success.
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
	// unlabelled is why the backend writes no connection label on the flows
	// it translates, empty while it writes one
	unlabelled() string
	// written is the rules of rules the backend writes, which Apply writes
	// and Rules reads back
	written(rules []Rule) []Rule
	// refused is whether err, an Apply's, is the host's refusal of the write.
	// An error before the write was sent is none. An error read in place of
	// the host's answers is none either.
	refused(err error) bool
}

// passStats is the record of one finished pass or one stop, which Status
// reports. Installed counts the rules the host holds for this translator as
// the last read back of that pass or stop found them, and is 0 where a pass
// could not read them back or a stop could not after writing them. A stop
// that has neither written nor read them back, one under way or one whose
// read before its write failed, keeps the count of the record before it.
// Announced is the prefixes it is willing to advertise as a result, none in a
// stop's.
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

	// stats is the record of the last pass or stop as a reader takes it. The
	// single run goroutine publishes a whole value and a reader takes one, so
	// this needs no lock and a reader can never see half a record.
	stats atomic.Pointer[passStats]
	*egress.Shell
	// warned holds the conflicts already reported, so a shared host costs one
	// log line per new conflict rather than one per pass.
	warned []string
	// trigger names what woke the run goroutine for the pass it runs, and belongs to that goroutine
	trigger string
	// down is the run goroutine's record of the stop it recorded, which the
	// next pass clears
	down bool
	// placed is whether the last stop's readback found the stopped rules in
	// place, which belongs to the run goroutine
	placed bool
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

// Status is the record of the last pass or stop, the capability's translation
// and the rules the host holds for this translator
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
// sweep, against the rules of a stopped translator while SetEnabled holds it
// off, and lays each family's readiness beside them as the last pass judged
// it, from the lookups and answers that pass read, and none where a stop has
// stored the record since
func (t *Translator) Debug() egress.ExitDebug {
	pass := t.lastPass()
	out := egress.ExitDebug{Status: t.statusOf(pass), Unlabelled: t.be.unlabelled()}
	desired := t.desired()
	if !t.Enabled.Load() {
		desired = t.stopped()
	}
	desired = t.be.written(desired)
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

// lastPass is the record the last pass or stop stored, and the zero value
// before the first has run, which At tells apart
func (t *Translator) lastPass() passStats {
	if s := t.stats.Load(); s != nil {
		return *s
	}
	return passStats{}
}

// Run reconciles until ctx is canceled, then records the stop, waits for
// Runtime.Done and withdraws the chains this translator owns where the mesh
// device has gone, or else stops as a down does and leaves the stopped rules,
// and closes what the backend holds. It is called once.
//
// Run returns the error of the withdrawal or of that stop, never a reconcile
// error: a failed pass is logged, costs the advertisement, and is retried. It
// returns nil where the stopped rules read back as written, warning that it
// leaves them, and otherwise an error, which it does not try again, still
// warning where the stop saw the host take the write. The warning says the
// stopped rules hold the exit only where that stop read them in place, and
// otherwise that they did not read back in place.
func (t *Translator) Run(ctx context.Context) error {
	slog.Info("egress translator started", "interface", t.rt.Interface, "steered", t.rt.Steered, "where", t.where(),
		"advertise", len(t.cfg.Advertise))
	sweep := t.cfg.SweepInterval()
	ticker := time.NewTicker(sweep)
	defer ticker.Stop()
	retry := meshkernel.NewRetryTimer()
	defer retry.Stop()

	t.trigger = "start"
	// passing is whether this turn ran a pass rather than a stop, so another
	// writer's change is reported only for an exit a pass has judged
	var passing bool
	for ctx.Err() == nil {
		passing = t.Enabled.Load()
		if !passing {
			// read back on every wake, so a change another writer makes to the
			// stopped chains is written over as a pass writes over one to its own
			if _, err := t.stop(); err != nil {
				slog.Warn("egress could not stop its chains, retrying", "err", err, "retry_in", retry.Failed(sweep))
			} else {
				retry.Passed()
			}
		} else {
			// the record of a stop lasts until the next pass, whatever woke it
			if t.down {
				t.down = false
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
			// another writer may already have removed or bypassed the chains, so the mesh stops handing this exit its packets before the pass that puts them back
			t.trigger = "changed"
			// a stopped exit already reads not ready, and its next pass reads its chains back whatever was changed
			if passing {
				t.SetUnready("another writer changed its table")
			}
		case <-t.be.Missed():
			// another table's large transaction overflows the socket as readily as a flush of this one, so only the pass's readback decides
			t.trigger = "missed"
		}
	}
	// Readiness and the advertisement go first, so the mesh stops handing this
	// exit frames and peers stop selecting it while the shutdown waits for the
	// mesh to close, and the record stands for a stop's first turn.
	t.down = true
	t.recordStop("the translator is stopping")
	<-t.rt.Done
	why := t.lingers()
	if why == "" {
		return errors.Join(t.withdraw(), t.be.Close())
	}
	// a frame the device took before Done may still reach the forward hook,
	// where the stopped rules meet it as a down's do
	taken, err := t.stop()
	if err != nil && !taken {
		return errors.Join(fmt.Errorf("the shutdown saw no write of the stopped rules taken: %w", err), t.be.Close())
	}
	attrs, left := []any{"why", why, "where", t.where()}, "egress left its stopped rules at shutdown"
	if t.placed {
		attrs = append(attrs, "detail", "they hold the exit as ranet3 down does, as the exit page gives under down and up, until the next start with cap.egress takes them over or the table is deleted")
	} else {
		left += ", which did not read back in place"
	}
	if err != nil {
		attrs = append(attrs, "err", err)
	}
	slog.Warn(left, attrs...)
	return errors.Join(err, t.be.Close())
}

// lingers says why a frame the mesh device took before Done may still reach
// the forward hook after it, the device still there or whether it is unread,
// and is empty where the device is gone (Runtime.Present)
func (t *Translator) lingers() string {
	present, err := t.rt.Present()
	switch {
	case err != nil:
		return "whether the mesh device " + t.rt.Interface + " outlives the mesh could not be read: " + err.Error()
	case present:
		return "the mesh device " + t.rt.Interface + " outlives the mesh"
	}
	return ""
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

	// the counters are the host's, and a pass that could not read them keeps the
	// record's before it, a stop's among them, rather than reading as a reset.
	// One that rewrote the chains starts from zero as their counters do, whether
	// or not it read them back.
	counted := counts(desired, held)
	if unread {
		counted = t.lastPass()
	}
	stats := passStats{
		At: time.Now(), Desired: len(desired), Installed: len(held),
		Flows: counted.Flows, Bytes: counted.Bytes, Untranslated: counted.Untranslated,
		Refused4: counted.Refused4, Refused6: counted.Refused6,
		Dropped4: counted.Dropped4, Dropped6: counted.Dropped6,
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

// counts reads held's counters for Status, read back for rules: the flows the
// translation's rules translated and those a class of none's bound,
// and each family's packets its limits refused and its rules for what no flow
// is tracked for dropped
func counts(rules []Rule, held []Installed) passStats {
	kinds := map[string]Rule{}
	for _, rule := range rules {
		kinds[rule.String()] = rule
	}
	var stats passStats
	refused, dropped := map[uint8]uint64{}, map[uint8]uint64{}
	for _, rule := range held {
		want, ok := kinds[rule.Spec]
		if !ok {
			continue
		}
		switch want.kind() {
		case screening, passing, timing, holding, leaving:
			// nf_tables' counters alone hold a screen's and a stopped
			// translator's drops, which no Status field reads, and a pass and
			// the timeouts keep none
		case limiting:
			refused[rule.Family] += rule.Packets
		case dropping:
			dropped[rule.Family] += rule.Packets
		case translating:
			if want.None {
				stats.Untranslated += rule.Packets
				continue
			}
			stats.Flows += rule.Packets
			stats.Bytes += rule.Bytes
		}
	}
	stats.Refused4, stats.Refused6 = refused[egress.FamilyIPv4], refused[egress.FamilyIPv6]
	stats.Dropped4, stats.Dropped6 = dropped[egress.FamilyIPv4], dropped[egress.FamilyIPv6]
	return stats
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
		// the ICMP drops hold under every class, so they lead the pass
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

// screens is the forward hook's rules past the ICMP drops. The pass of the
// sources whose class is none leads them, so a packet out of the mesh from
// such a source meets no screen, and every other meets each screen once.
func (t *Translator) screens(family uint8) []Rule {
	var out []Rule
	// the addresses of the filter's sets of none before it leaves out the
	// prefixes the mesh's table learned, which no table given here holds
	untranslated := meshkernel.NoneDestinations(t.cfg.Classes(family), nil, nil)
	if sources := prefixSet(meshkernel.RangePrefixes(untranslated...)); sources != "" {
		out = append(out, Rule{Family: family, Direction: Out, Interface: t.rt.Interface, Sources: sources, Passes: true})
	}
	out = append(out, t.screen(family, Out, netip.Prefix{})...)
	for _, rule := range t.inbound(family) {
		if rule.Timeouts == NoTimeouts {
			out = append(out, t.screen(family, In, rule.From)...)
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

// stop records the stop on its first turn, then brings the host to the rules
// stopped gives as reconcile brings it to desired, in one transaction that
// leaves the translation's chain whole at every moment: a packet met before
// its commit meets a running translator's chains, and one met after it a
// stopped one's, which drop a packet out of the mesh under a class that
// translates before conntrack confirms its flow. Status reads the stop in
// effect, with the stopped rules the host holds counted, once they read back
// as written. Until then it reads the translator stopping and why, with the
// rules the host holds as it read them, none for a write whose rules it could
// not read back, and the last count for a read that failed before any write.
//
// A write's rules are read back whatever the host answered it with. A host
// that commits a large transaction can drop the acknowledgments past the
// socket's receive buffer, which reads as an error, so a write whose rules
// read back as written was taken, whatever the answer. A taken write whose
// rules read back otherwise is an error naming how, as a pass names it, and
// the stop is tried again as a refused one is. A write answered with the
// host's refusal whose rules read back is an error naming the refusal and then
// how they read back, a flag another writer gave the table and what clears it
// among them, and Status's reason names the refusal and how as well, as a
// pass's reason names a fault. A write answered with another error whose rules
// read back otherwise is an error naming that answer and then how they read
// back. Status's reason names no refusal there. Nothing read then says the
// host refused the write, which a host that refuses a large transaction can
// still have done, its refusal lost behind the acknowledgments the socket
// dropped. A write that failed before it was sent is one of those. Whatever
// the answer, the reason says the stopped rules are not in place, ahead of how
// they read back, unless the readback finds the table without the dormant
// flag and no family's chain, set or object misplaced. The running rules a
// refused write leaves are misplaced, and so is a chain another writer
// emptied or added a line to. How they read back is a flag of the table's
// that the write is refused for, then a set or object of either family's that
// it is refused on, IPv4's then IPv6's, and else the first family's fault,
// then each way the stopped rules are out of place that this has not named
// (stopFault).
//
// stop reports whether the host took a write of the stopped rules, which then
// hold whatever the readback found, and keeps in placed whether its last
// readback found them in place. It reports none, with both errors, where the
// host answered the write with an error and the rules could not be read back
// after, since whether it took the write is then unknown.
func (t *Translator) stop() (bool, error) {
	started := time.Now()
	if !t.down {
		t.down = true
		// before the write, which takes as long as the translation's chain is,
		// so the mesh stops handing the exit frames and peers stop selecting
		// it from the stop's start
		t.recordStop("the translator is stopping")
	}
	rules := t.stopped()
	read, err := t.be.Rules(rules)
	listed := err == nil
	installed, faulted, remake := flatten(read)
	tried, taken, refused := false, false, false
	switch {
	case err != nil:
		err = fmt.Errorf("list rules: %w", err)
	case faulted:
		tried = true
		answered := t.be.Apply(rules, remake)
		read, err = t.be.Rules(rules)
		listed = err == nil
		installed, faulted, _ = flatten(read)
		taken = answered == nil || listed && !faulted
		refused = !taken && t.be.refused(answered)
		switch {
		case !taken && listed:
			err = fmt.Errorf("install rules: %w, then the stopped rules read back other than written: %s", answered, stopFault(read))
		case !taken:
			err = fmt.Errorf("install rules: %w, then list rules: %w", answered, err)
		case err != nil:
			err = fmt.Errorf("list rules: %w", err)
		case faulted:
			err = fmt.Errorf("the stopped rules read back other than written: %s", stopFault(read))
		default:
			slog.Info("egress translator stopped", "rules", len(installed), "where", t.where())
		}
	}
	inPlace := listed && len(unplaced(read)) == 0
	t.placed = inPlace
	// the kept translation's chain counts while stopped as while running
	stats, why := counts(rules, installed), "the translator is stopped"
	stats.Installed = len(installed)
	if err != nil {
		stats, why = t.lastPass(), "the translator is stopping"
		if listed || tried {
			stats.Installed = len(installed)
		}
		// a write whose rules read back other than written, which is every
		// listed one here, names how, as a pass's reason names it. One whose
		// answer read as the host's refusal names the refusal first, as its
		// error names that answer first. One whose readback lacks a stopped
		// rule says the stopped rules are not in place, after the refusal where
		// the answer read as one.
		switch {
		case !listed:
			why += ": its chains could not be read back"
		case refused && !inPlace:
			why += ": the host refused the stopped rules, which are not in place: " + stopFault(read)
		case refused:
			why += ": the host refused the stopped rules: " + stopFault(read)
		case !inPlace:
			why += ": the stopped rules are not in place: " + stopFault(read)
		case faulted:
			why += ": " + stopFault(read)
		}
	}
	t.storeStop(why, stats, err)
	if taken || err != nil {
		attrs := []slog.Attr{slog.String("trigger", t.trigger), slog.Duration("took", time.Since(started)),
			slog.Int("installed", stats.Installed), slog.Int("announced", 0)}
		if err != nil {
			// err itself, since stats here holds the last record's error and
			// storeStop set this one's on its own copy
			attrs = append(attrs, slog.String("err", err.Error()))
		}
		t.rt.Events.Emit("egress.pass", "", attrs...)
	}
	return taken, err
}

// stopFault is how a stop names the way read differs from what it wrote. A
// flag of the table's that the write is refused for goes first. Then a
// family's refusedOn, IPv4's then IPv6's, which names a set or object the
// write is refused on and what holds it. It goes ahead of a stray chain or an
// object of an earlier version that every family's fault starts with, held or
// not. Where neither is, it is the first family's fault, IPv4's then IPv6's.
// Each way unplaced gives that is not equal to that cause or to a way already
// named follows it.
func stopFault(read map[uint8]chainReadback) string {
	v4, v6 := read[egress.FamilyIPv4], read[egress.FamilyIPv6]
	out := []string{cmp.Or(v4.flag, v6.flag, v4.refusedOn, v6.refusedOn, v4.fault, v6.fault)}
	for _, way := range unplaced(read) {
		if !slices.Contains(out, way) {
			out = append(out, way)
		}
	}
	return strings.Join(slices.DeleteFunc(out, func(fault string) bool { return fault == "" }), ", and ")
}

// unplaced is each way read keeps the stopped rules out of place: the table's
// dormant flag, then the first family's misplaced chain, set or object, IPv4's
// then IPv6's. It is empty where they are in place.
func unplaced(read map[uint8]chainReadback) []string {
	v4, v6 := read[egress.FamilyIPv4], read[egress.FamilyIPv6]
	return slices.DeleteFunc([]string{cmp.Or(v4.dormant, v6.dormant), cmp.Or(v4.misplaced, v6.misplaced)}, func(way string) bool { return way == "" })
}

// stopped is the rules of a stopped translator: desired's, changed so that no
// packet out of the mesh leaves under a class that translates and no
// forwarded packet of a labelled flow leaves by a link other than the mesh
// device. Each of desired's rules at the forward hook stays where it sits,
// the ICMP drops, each family's pass of its untranslated sources and the rules
// into the mesh among them, so a stopped translator lets into the mesh what a
// running one does, but:
//   - Each limit becomes a Held rule. A packet out of the mesh meets a limit
//     under every class that translates and under no class of none, so it
//     meets the hold exactly there.
//   - The rules out of the mesh that drop what no flow is tracked for or
//     refuse a protocol are left out, since each sits ahead of a limit and
//     takes only what the hold after it drops.
//   - A Labelled rule ends each family's chain at the forward hook, in both
//     families whatever the configuration translates, since an earlier run
//     may have labelled flows of a family this one does not translate.
//   - A Labelled rule that takes what the family's pass accepts, a packet out
//     of the mesh from an untranslated source, stands directly ahead of that
//     pass, since an earlier run may have labelled flows of a source this one
//     leaves untranslated.
//
// So a packet the host forwards meets no more rules than desired's give it,
// since a family desired translates has its chain at the forward hook hold
// the rules left out from every source ahead of its limit, but in three
// cases. A packet of a family the configuration does not translate meets one
// rule more, the Labelled rule. A packet out of the mesh from an untranslated
// source meets one rule more, the Labelled rule ahead of its family's pass,
// and so does one out of the mesh that no flow is tracked for in a family
// with a pass, which the running translator drops at the first screen past
// the pass and the hold drops in its place. A packet the host itself sends
// meets none of them, one to a leaf's mesh address among them (exit-nodes.md,
// "What the host itself sends to a leaf"). The
// translation's chain stays as a pass writes it, so every binding keeps its
// translation and every flow it translates keeps its label.
func (t *Translator) stopped() []Rule {
	var out []Rule
	desired := t.desired()
	for _, family := range []uint8{egress.FamilyIPv4, egress.FamilyIPv6} {
		for _, rule := range desired {
			if rule.Family != family {
				continue
			}
			switch kind := rule.kind(); {
			case kind == limiting:
				rule.Limit, rule.Stopped = 0, Held
			case rule.Direction == Out && (kind == dropping || kind == screening && rule.Protocol.Number != 0):
				continue
			case kind == passing:
				out = append(out, Rule{Family: family, Direction: Out, Interface: t.rt.Interface, Stopped: Labelled, Sources: rule.Sources})
			}
			out = append(out, rule)
		}
		out = append(out, Rule{Family: family, Direction: Out, Interface: t.rt.Interface, Stopped: Labelled})
	}
	return out
}

// recordStop stores the stop for why as storeStop does, beside the counts of
// the record before it, the last pass's or the last stop's
func (t *Translator) recordStop(why string) { t.storeStop(why, t.lastPass(), nil) }

// storeStop retracts the advertisement for why and stores stats with every
// family not ready for it, no lookup judged, nothing announced or skipped and
// err as its error, so Status says why from the moment a stop begins, beside
// the rules stats counts
func (t *Translator) storeStop(why string, stats passStats, err error) {
	t.Retract(why)
	stats.At, stats.Ready4, stats.Ready6, stats.Unready, stats.Skipped = time.Now(), false, false, t.Unready(), ""
	stats.Announced, stats.Err, stats.judged = nil, "", nil
	if err != nil {
		stats.Err = err.Error()
	}
	t.stats.Store(&stats)
}

// withdraw removes the chains, sets and objects this translator owns, as its
// backend's Withdraw does, and what is already gone is not an error
func (t *Translator) withdraw() error {
	if err := t.be.Withdraw(); err != nil {
		return fmt.Errorf("withdraw %s: %w", t.where(), err)
	}
	slog.Info("egress translator withdrawn", "where", t.where())
	return nil
}
