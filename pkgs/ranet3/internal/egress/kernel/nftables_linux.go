// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/nftables"
)

// natTables is the linux backend: the tables named after this tool, one per
// address family in use, and the limit their sets count each source's flows
// against.
type natTables struct {
	conn     *nftables.Conn
	monitor  *nftables.Monitor
	families []uint8
	limit    int
}

// New validates the capability and opens the tables the backend owns, so a
// deployment that cannot have it fails at startup rather than on the first
// packet. It installs nothing. Run does that.
func New(cfg egress.Egress, rt Runtime) (*Translator, error) {
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
	if err := cfg.CheckReturn(rt.MeshAddresses); err != nil {
		return nil, err
	}
	if rt.Lookup == nil || rt.Sysctl == nil {
		return nil, errors.New("egress: a route lookup and a sysctl reader are required")
	}
	if rt.Write == nil {
		return nil, errors.New("egress: the mesh's tun writer is required")
	}
	be, err := newBackend(cfg, rt)
	if err != nil {
		return nil, err
	}
	return newTranslator(cfg, rt, be), nil
}

func newBackend(cfg egress.Egress, rt Runtime) (backend, error) {
	conn, err := nftables.Dial()
	if err != nil {
		return nil, err
	}
	be := &natTables{conn: conn, families: cfg.Translated(rt.Steered), limit: cfg.SourceLimit()}
	// A table this tool left behind in a family the configuration no longer
	// covers would go on translating under the old rules for as long as the
	// node ran, and nothing else here would ever look at it: every dump below
	// asks only about the families in use. It is removed once, at startup,
	// which is the only moment the set can have changed.
	if err := be.removeUnusedTables(); err != nil {
		conn.Close()
		return nil, err
	}
	if be.monitor, err = nftables.OpenMonitor(conn, translatorTables); err != nil {
		conn.Close()
		return nil, err
	}
	return be, nil
}

func (n *natTables) Close() error { return errors.Join(n.monitor.Close(), n.conn.Close()) }

func (n *natTables) Changed() <-chan struct{} { return n.monitor.Changed() }

func (n *natTables) Missed() <-chan struct{} { return n.monitor.Missed() }

var (
	// translatorTables is the translator's ip and ip6 tables
	translatorTables = nftables.Scope{Name: TableName, Families: []uint8{unix.NFPROTO_IPV4, unix.NFPROTO_IPV6}}
	// borderTables is the border filter's inet table, which shares the name
	borderTables = nftables.Scope{Name: TableName, Families: []uint8{unix.NFPROTO_INET}}
)

// where names the tables this backend owns, for a log line.
func (n *natTables) where(egress.Egress) string {
	names := make([]string, 0, len(n.families))
	for _, family := range n.families {
		names = append(names, tableFamilyName(family))
	}
	return fmt.Sprintf("nftables table %s %s chains %s and %s", strings.Join(names, " and "), TableName, LimitChain, ChainName)
}

// tableFamilyName is the family as `nft` spells it. The two are separate
// tables rather than one inet table because inet nat arrived long after
// nftables did, and a node whose kernel predates it would refuse the chain
// rather than the capability.
func tableFamilyName(family uint8) string {
	if family == egress.FamilyIPv4 {
		return "ip"
	}
	return "ip6"
}

// nftFamily is the NFPROTO_ value for one of this package's families.
func nftFamily(family uint8) uint8 {
	if family == egress.FamilyIPv4 {
		return unix.NFPROTO_IPV4
	}
	return unix.NFPROTO_IPV6
}

// Rules reads back the chains this tool owns in each family's table, with the
// table, the set and the timeout objects, the rules in the order desired writes
// them with the family each was read from and the counter it has carried. A
// rule another writer put in one of this tool's chains changes what the chain
// does to a packet, so it is read back too, one with no comment as an empty
// spec. Its family is not ready while it stays, and the next pass rewrites the
// chain without it. A rule in any other table or chain is skipped. This
// backend never removes one in another table, and one in another chain of its
// table goes with the table whenever the table is removed whole.
func (n *natTables) Rules() (map[uint8]chainReadback, error) {
	tables, err := nftables.Tables(n.conn, TableName)
	if err != nil {
		return nil, err
	}
	out := make(map[uint8]chainReadback, len(n.families))
	for _, family := range n.families {
		read, err := nftables.Contents{
			Chains: translatorChains, Sets: []nftables.Set{flowSet(family, n.limit)}, Timeouts: timeoutObjects(family),
		}.Read(n.conn, tables, nftFamily(family))
		if err != nil {
			return nil, fmt.Errorf("egress: read table %s %s: %w", tableFamilyName(family), TableName, err)
		}
		out[family] = readback(read, family)
	}
	return out, nil
}

// readback is a chain as read, its rules placed in family
func readback(read nftables.Readback, family uint8) chainReadback {
	rules := make([]Installed, 0, len(read.Rules))
	for _, rule := range read.Rules {
		rules = append(rules, Installed{Spec: rule.Spec, Family: family, Packets: rule.Packets, Bytes: rule.Bytes})
	}
	return chainReadback{rules: rules, fault: read.Fault, remake: read.Remake}
}

// Apply brings this tool's own chains to rules, in one transaction. Each chain
// is emptied and rewritten rather than edited rule by rule, because a batch
// commits atomically: no packet is ever evaluated against half a ruleset, and
// the alternative is a window in which a flow leaves untranslated and
// conntrack then holds that decision for its whole lifetime. The table of a
// family in remake is deleted first in the same transaction, with every chain,
// set and timeout object in it, and made again.
//
// The timeout objects and the set are written on every apply and changed by
// none. nf_tables has no update for a ct timeout, so a write of an object that
// exists leaves it as it is, and a set keeps its elements, each source's count
// of flows. A deleted object detaches from every flow it timed, which then
// takes the host's timeouts, and a deleted set forgets every count, so only a
// remake deletes either, and one that reads back other than written asks for
// that remake.
func (n *natTables) Apply(rules []Rule, remake []uint8) error {
	requests, err := translatorBatch(n.families, n.limit, rules, remake)
	if err != nil {
		return err
	}
	return n.conn.Batch(requests)
}

// translatorBatch is the transaction Apply sends over families, their sets
// made under limit
func translatorBatch(families []uint8, limit int, rules []Rule, remake []uint8) ([]nftables.Request, error) {
	var requests []nftables.Request
	for _, family := range families {
		proto := nftFamily(family)
		if slices.Contains(remake, family) {
			requests = append(requests, delTable(family))
		}
		requests = append(requests, nftables.NewTable(proto, TableName))
		for _, object := range timeoutObjects(family) {
			requests = append(requests, object.Create(proto))
		}
		set, err := flowSet(family, limit).Create(proto)
		if err != nil {
			return nil, err
		}
		requests = append(requests, set)
		for _, chain := range translatorChains {
			// The flush names no handle, which is how nf_tables spells "every
			// rule in this chain". It reaches only the chain named here, in the
			// table named here, both of which this tool created.
			requests = append(requests, chain.Create(proto), chain.Flush(proto))
		}
		for _, rule := range rules {
			if rule.Family != family {
				continue
			}
			request, err := newRule(rule)
			if err != nil {
				return nil, err
			}
			requests = append(requests, request)
		}
	}
	return requests, nil
}

// Withdraw removes the tables this tool created, and only those, each whole
// with every chain in it: the dump names them, and a name that is not this
// tool's is never deleted. Both families are swept rather than the configured
// ones alone, so a table left behind by an instance with a different
// configuration leaves with the rest.
func (n *natTables) Withdraw() error {
	return n.removeTables(func(uint8) bool { return true })
}

// removeUnusedTables is Withdraw narrowed to the families this configuration
// does not cover. See newBackend.
func (n *natTables) removeUnusedTables() error {
	return n.removeTables(func(family uint8) bool { return !slices.Contains(n.families, family) })
}

// removeTables deletes this tool's table in each family the predicate takes.
// The tables are listed first rather than deleted blind, because a delete of a
// table that is not there fails the whole transaction and would turn every
// shutdown on a node that never installed anything into an error. A table that
// goes away between the listing and the delete fails the same way, which only
// something else writing under this tool's own name can cause.
func (n *natTables) removeTables(match func(uint8) bool) error {
	held, err := nftables.Tables(n.conn, TableName)
	if err != nil {
		return err
	}
	var requests []nftables.Request
	for _, family := range []uint8{egress.FamilyIPv4, egress.FamilyIPv6} {
		if _, ok := held[nftFamily(family)]; ok && match(family) {
			requests = append(requests, delTable(family))
		}
	}
	return n.conn.Batch(requests)
}

// Conflicts names the other source translation this node's traffic can meet
// first: a nat chain at the postrouting hook in a table this tool did not
// create, at natPriority or below. One past natPriority runs after this tool's
// chain, which has bound every flow it takes by then. They are reported rather
// than removed. Several such chains coexist, the first to translate a
// connection keeps it, and a tool that deleted its neighbors' rules to win
// that race would break docker, an SD-WAN agent or the operator's own ruleset,
// which is exactly the failure internal/kernel's ownership rules exist to
// avoid.
//
// A host still running legacy iptables rather than iptables-nft is invisible
// here, because the two are separate registries in the kernel. An iptables-nft
// rule is an ordinary nftables table and does show up.
func (n *natTables) Conflicts() ([]string, error) {
	replies, err := n.conn.Dump(nftables.Command(unix.NFT_MSG_GETCHAIN), nftables.PutNfgenmsg(nil, unix.NFPROTO_UNSPEC))
	if err != nil {
		return nil, fmt.Errorf("egress: dump chains: %w", err)
	}
	var out []string
	for _, reply := range replies {
		if len(reply.Data) < nftables.SizeofNfgenmsg {
			continue
		}
		var family uint8
		switch reply.Data[0] {
		case unix.NFPROTO_IPV4:
			family = egress.FamilyIPv4
		case unix.NFPROTO_IPV6:
			family = egress.FamilyIPv6
		default:
			// An inet, bridge, arp or netdev chain cannot carry a nat hook
			// this node's forwarded traffic would meet before its own.
			continue
		}
		if !slices.Contains(n.families, family) {
			continue
		}
		table, chain, kind, hook, priority := nftables.DecodeChain(reply)
		if table == TableName || kind != "nat" || hook != unix.NF_INET_POST_ROUTING || priority > natPriority {
			continue
		}
		out = append(out, fmt.Sprintf("%s table %s chain %s at priority %d",
			tableFamilyName(family), table, chain, priority))
	}
	slices.Sort(out)
	return out, nil
}

func delTable(family uint8) nftables.Request {
	return nftables.DeleteTable(nftFamily(family), TableName)
}

// postrouting is the translator's chain, at the source translation hook at
// natPriority
var postrouting = nftables.Chain{Table: TableName, Name: ChainName, Type: "nat", Hook: unix.NF_INET_POST_ROUTING, Priority: natPriority}

// forward is the chain of the limit and of the packets no flow is tracked for,
// at the forward hook a forwarded packet meets before the translation's, at
// the priority of the host's own filters
var forward = nftables.Chain{Table: TableName, Name: LimitChain, Type: "filter", Hook: unix.NF_INET_FORWARD, Priority: filterPriority}

// translatorChains is a family's chains in the order desired writes their rules
var translatorChains = []nftables.Chain{forward, postrouting}

// flowSet is the set the limit rule of family keeps each source's count of
// flows in, a source to an element. Each element keeps the limit of the rule
// that added it, nft_dynset.c copying the rule's connlimit into it, so the
// set's comment names the limit and a set read back under another is remade.
func flowSet(family uint8, limit int) nftables.Set {
	set := nftables.Set{Table: TableName, Name: flowsSet + "6", ID: 1, KeyType: nftables.TypeIPv6Addr, KeyLen: net.IPv6len, Flags: unix.NFT_SET_EVAL, Size: setSize,
		Comment: fmt.Sprintf("limit %d", limit)}
	if family == egress.FamilyIPv4 {
		set.Name, set.KeyType, set.KeyLen = flowsSet+"4", nftables.TypeIPv4Addr, net.IPv4len
	}
	return set
}

// newRule's expressions come in the order `nft list ruleset` prints them
func newRule(rule Rule) (nftables.Request, error) {
	if err := nftables.DeviceName(rule.Interface); err != nil {
		return nftables.Request{}, err
	}
	// a rule reading the flow's state reads it first, so a packet of an
	// established flow fails the rule at its first compare
	var expressions [][]byte
	if rule.Limit != 0 {
		// Only the packet that creates a connection's entry is judged. A UDP
		// flow nothing has answered stays in state new, and nf_conncount ends
		// its walk at the flow's own tuple, before the stale tuples the refused
		// flows leave behind, so a later datagram of a flow admitted at the
		// limit would read their count and be refused.
		expressions = append(expressions, nftables.CTMatch(unix.NFT_CT_STATE, nftables.CTStateNew, unix.NFT_CMP_NEQ)...)
		expressions = append(expressions, nftables.CTMatch(unix.NFT_CT_STATUS, nftables.CTStatusConfirmed, unix.NFT_CMP_EQ)...)
	}
	if rule.Untracked {
		// ct state reads invalid for a packet conntrack gave no entry and
		// untracked for one conntrack does not track, a notrack rule's among
		// them, and nf_nat passes either unchanged.
		expressions = append(expressions, nftables.CTMatch(unix.NFT_CT_STATE, nftables.CTStateInvalid|nftables.CTStateUntracked, unix.NFT_CMP_NEQ)...)
	}
	// Out and In match both interfaces, never one. An outbound rule that
	// checked only the arrival interface would also translate mesh transit,
	// which arrives on the mesh device and leaves by it again, and would
	// rewrite a relayed packet's source to this node. A Local rule matches the
	// departure and its own address, and a packet arriving on the mesh device
	// from that address has met the Out rules first.
	switch rule.Direction {
	case Out:
		expressions = append(expressions, nftables.MetaCompare(unix.NFT_META_IIFNAME, unix.NFT_CMP_EQ, rule.Interface)...)
	case In:
		// A packet this host generated itself has no arrival interface, which
		// nf_tables reports as the empty name rather than as a failure to
		// read, so "iifname != the mesh device" is true of it. Left at that,
		// an inbound rule would translate this node's own mesh traffic to the
		// return source, which for an exit is an address belonging to somebody
		// else. Ruling it out by index says so in one test that means the same
		// thing on a kernel that breaks the rule instead: a locally generated
		// packet reads as interface zero either way.
		expressions = append(expressions, nftables.MetaCompareValue(unix.NFT_META_IIF, unix.NFT_CMP_NEQ, make([]byte, 4))...)
		expressions = append(expressions, nftables.MetaCompare(unix.NFT_META_IIFNAME, unix.NFT_CMP_NEQ, rule.Interface)...)
	}
	departure := unix.NFT_CMP_NEQ
	if rule.Direction == In {
		departure = unix.NFT_CMP_EQ
	}
	expressions = append(expressions, nftables.MetaCompare(unix.NFT_META_OIFNAME, departure, rule.Interface)...)
	if rule.From.IsValid() {
		expressions = append(expressions, nftables.SourcePrefix(rule.From)...)
	}
	proto := nftFamily(rule.Family)
	switch {
	case rule.Limit != 0:
		// The counter counts every refusal, of which the host's rate limit on ICMP
		// errors answers some. Code 1 is IPv6's administratively prohibited, RFC
		// 4443's, and IPv4's host unreachable, which RFC 6888 REQ-11 asks of a NAT
		// refusing a source past its quota, since RFC 1122 section 4.2.3.9 has TCP
		// keep a connection open on it.
		expressions = append(expressions, nftables.SourceLoad(proto), nftables.ConnectionsOver(flowSet(rule.Family, rule.Limit).Name, uint32(rule.Limit)),
			nftables.Expression("counter", nil), nftables.RejectUnreachable(1))
		return forward.Rule(proto, rule.String(), expressions)
	case rule.Untracked && rule.None:
		// a class of none's packet goes on as the host forwards it, past the
		// drops of the shorter classes after this rule
		return forward.Rule(proto, rule.String(), append(expressions, verdict(nftables.Accept)))
	case rule.Untracked:
		expressions = append(expressions, nftables.Expression("counter", nil), verdict(verdictDrop))
		return forward.Rule(proto, rule.String(), expressions)
	case rule.Timeouts != NoTimeouts:
		// no counter, so a flow is counted once, by the translation after it
		expressions = append(expressions, attachTimeouts(rule.Timeouts)...)
		return postrouting.Rule(proto, rule.String(), expressions)
	}
	expressions = append(expressions, nftables.Expression("counter", nil))
	expressions = append(expressions, translate(rule)...)
	return postrouting.Rule(proto, rule.String(), expressions)
}

// attachTimeouts matches a timeout rule's protocol and attaches its object,
// which the kernel does on a flow's first packet alone, leaving a confirmed
// flow's timeouts as they are. UDP to port 53 is not matched, so a query keeps
// the host's timeout, as RFC 4787 REQ-5a lets it.
func attachTimeouts(timeouts Timeouts) [][]byte {
	protocol, _ := timeoutPolicy(timeouts)
	out := nftables.MetaCompareValue(unix.NFT_META_L4PROTO, unix.NFT_CMP_EQ, []byte{protocol})
	if timeouts == UDPTimeouts {
		out = append(out, nftables.TransportLoad(udpDestinationOffset, 2),
			nftables.Expression("cmp", nftables.Compare(unix.NFT_CMP_NEQ, binary.BigEndian.AppendUint16(nil, 53))))
	}
	return append(out, nftables.ObjectReference(unix.NFT_OBJECT_CT_TIMEOUT, timeoutObject+timeouts.String()))
}

func timeoutObjects(family uint8) []nftables.Timeout {
	var out []nftables.Timeout
	for _, timeouts := range familyTimeouts(family) {
		protocol, policy := timeoutPolicy(timeouts)
		out = append(out, nftables.Timeout{
			Table: TableName, Name: timeoutObject + timeouts.String(), L3Proto: uint16(nftFamily(family)), L4Proto: protocol, Policy: policy,
		})
	}
	return out
}

// timeoutPolicy is the protocol timeouts names and the seconds of each of its
// states in the order of their CTA_TIMEOUT_ attributes: for TCP SYN_SENT,
// SYN_RECV, ESTABLISHED, FIN_WAIT, CLOSE_WAIT, LAST_ACK, TIME_WAIT, CLOSE,
// SYN_SENT2, RETRANS and UNACK, and for UDP UNREPLIED and REPLIED
func timeoutPolicy(timeouts Timeouts) (protocol uint8, policy []uint32) {
	switch timeouts {
	case UDPTimeouts:
		return unix.IPPROTO_UDP, []uint32{udpUnrepliedTimeout, udpRepliedTimeout}
	case TCPTimeouts:
		return unix.IPPROTO_TCP, []uint32{transitoryTimeout, transitoryTimeout, establishedTimeout, establishedFloor, establishedFloor,
			transitoryTimeout, timeWaitTimeout, closeTimeout, transitoryTimeout, establishedFloor, establishedFloor}
	case ICMPTimeouts:
		return unix.IPPROTO_ICMP, []uint32{icmpTimeout}
	}
	return unix.IPPROTO_ICMPV6, []uint32{icmpTimeout}
}

// translate is the statement that rewrites the source: the address written in
// the configuration, or the one the host's own routes would have used, which
// nf_tables spells as masquerade and decides per packet. A class of none
// translates the source to itself, the binding nf_nat makes for a connection
// no chain at the hook translated, made here so that a chain that runs after
// this one cannot translate it. See natPriority for which chains run after.
func translate(rule Rule) [][]byte {
	proto := nftFamily(rule.Family)
	switch {
	case rule.None:
		return [][]byte{nftables.SourceLoad(proto), nftables.SourceNAT(proto)}
	case !rule.Source.IsValid():
		return [][]byte{nftables.Expression("masq", nil)}
	}
	immediate := nftables.PutAttrBE32(nil, unix.NFTA_IMMEDIATE_DREG, unix.NFT_REG_1)
	immediate = nftables.PutAttr(immediate, unix.NFTA_IMMEDIATE_DATA|unix.NLA_F_NESTED,
		nftables.PutAttr(nil, unix.NFTA_DATA_VALUE, nftables.AddressBytes(rule.Source)))
	return [][]byte{nftables.Expression("immediate", immediate), nftables.SourceNAT(proto)}
}
