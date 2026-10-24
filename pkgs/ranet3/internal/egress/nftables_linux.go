// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package egress

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/nftables"
)

// natTables is the linux backend: the tables named after this tool, one per
// address family in use.
type natTables struct {
	conn     *nftables.Conn
	monitor  *nftables.Monitor
	families []uint8
}

func newBackend(cfg Egress, rt Runtime) (backend, error) {
	conn, err := nftables.Dial()
	if err != nil {
		return nil, err
	}
	be := &natTables{conn: conn, families: cfg.translated(rt.Steered)}
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
func (n *natTables) where(Egress) string {
	names := make([]string, 0, len(n.families))
	for _, family := range n.families {
		names = append(names, tableFamilyName(family))
	}
	return fmt.Sprintf("nftables table %s %s chain %s", strings.Join(names, " and "), TableName, ChainName)
}

// tableFamilyName is the family as `nft` spells it. The two are separate
// tables rather than one inet table because inet nat arrived long after
// nftables did, and a node whose kernel predates it would refuse the chain
// rather than the capability.
func tableFamilyName(family uint8) string {
	if family == FamilyIPv4 {
		return "ip"
	}
	return "ip6"
}

// nftFamily is the NFPROTO_ value for one of this package's families.
func nftFamily(family uint8) uint8 {
	if family == FamilyIPv4 {
		return unix.NFPROTO_IPV4
	}
	return unix.NFPROTO_IPV6
}

// Rules reads back the chain this tool owns and its table in each family, the
// rules in order with the family each was read from and the flow counter it
// has carried. A rule another writer put in this tool's chain changes what the
// chain does to a packet, so it is read back too, one with no comment as an
// empty spec. Its family is not ready while it stays, and the next pass
// rewrites the chain without it. A rule in any other table or chain is
// skipped. This backend never removes one in another table, and one in
// another chain of its table goes with the table whenever the table is
// removed whole.
func (n *natTables) Rules() (map[uint8]chainReadback, error) {
	tables, err := nftables.Tables(n.conn, TableName)
	if err != nil {
		return nil, err
	}
	out := make(map[uint8]chainReadback, len(n.families))
	for _, family := range n.families {
		read, err := postrouting.Read(n.conn, tables, nftFamily(family))
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

// Apply brings this tool's own chain to rules, in one transaction. The chain
// is emptied and rewritten rather than edited rule by rule, because a batch
// commits atomically: no packet is ever evaluated against half a ruleset, and
// the alternative is a window in which a flow leaves untranslated and
// conntrack then holds that decision for its whole lifetime. The table of a
// family in remake is deleted first in the same transaction, with every chain
// in it, and made again.
func (n *natTables) Apply(rules []Rule, remake []uint8) error {
	requests, err := translatorBatch(n.families, rules, remake)
	if err != nil {
		return err
	}
	return n.conn.Batch(requests)
}

// translatorBatch is the transaction Apply sends over families
func translatorBatch(families []uint8, rules []Rule, remake []uint8) ([]nftables.Request, error) {
	var requests []nftables.Request
	for _, family := range families {
		if slices.Contains(remake, family) {
			requests = append(requests, delTable(family))
		}
		requests = append(requests,
			nftables.NewTable(nftFamily(family), TableName),
			newChain(family),
			// No handle, which is how nf_tables spells "every rule in this
			// chain". It reaches only the chain named here, in the table named
			// here, both of which this tool created.
			flushChain(family))
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
	for _, family := range []uint8{FamilyIPv4, FamilyIPv6} {
		if _, ok := held[nftFamily(family)]; ok && match(family) {
			requests = append(requests, delTable(family))
		}
	}
	return n.conn.Batch(requests)
}

// Conflicts names the other source translation this node's traffic can meet: a
// nat chain at the postrouting hook in a table this tool did not create. They
// are reported rather than removed. Several such chains coexist, the first to
// translate a connection keeps it, and a tool that deleted its neighbors'
// rules to win that race would break docker, an SD-WAN agent or the operator's
// own ruleset, which is exactly the failure internal/kernel's ownership rules
// exist to avoid.
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
			family = FamilyIPv4
		case unix.NFPROTO_IPV6:
			family = FamilyIPv6
		default:
			// An inet, bridge, arp or netdev chain cannot carry a nat hook
			// this node's forwarded traffic would meet before its own.
			continue
		}
		if !slices.Contains(n.families, family) {
			continue
		}
		table, chain, kind, hook, priority := nftables.DecodeChain(reply)
		if table == TableName || kind != "nat" || hook != unix.NF_INET_POST_ROUTING {
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

// postrouting is the translator's chain, at the source translation hook and
// the priority every other source translation on the host also runs at. A
// different priority would not avoid the overlap, only reorder it, and a
// number nothing else uses would put this node's translation either before or
// after whatever the operator arranged on purpose.
var postrouting = nftables.Chain{Table: TableName, Name: ChainName, Type: "nat", Hook: unix.NF_INET_POST_ROUTING, Priority: natSrcPriority}

func newChain(family uint8) nftables.Request { return postrouting.Create(nftFamily(family)) }

func flushChain(family uint8) nftables.Request { return postrouting.Flush(nftFamily(family)) }

// newRule's expressions come in the order `nft list ruleset` prints them
func newRule(rule Rule) (nftables.Request, error) {
	if err := nftables.DeviceName(rule.Interface); err != nil {
		return nftables.Request{}, err
	}
	inbound, outbound := unix.NFT_CMP_EQ, unix.NFT_CMP_NEQ
	if rule.Direction == In {
		inbound, outbound = unix.NFT_CMP_NEQ, unix.NFT_CMP_EQ
	}
	// Both interfaces are matched, never one. An outbound rule that checked
	// only the arrival interface would also translate mesh transit, which
	// arrives on the mesh device and leaves by it again, and would rewrite a
	// relayed packet's source to this node.
	var expressions [][]byte
	if rule.Direction == In {
		// A packet this host generated itself has no arrival interface, which
		// nf_tables reports as the empty name rather than as a failure to
		// read, so "iifname != the mesh device" is true of it. Left at that,
		// an inbound rule would translate this node's own mesh traffic to the
		// return source, which for an exit is an address belonging to somebody
		// else. Ruling it out by index says so in one test that means the same
		// thing on a kernel that breaks the rule instead: a locally generated
		// packet reads as interface zero either way.
		expressions = append(expressions, nftables.MetaCompareValue(unix.NFT_META_IIF, unix.NFT_CMP_NEQ, make([]byte, 4))...)
	}
	expressions = append(expressions, nftables.MetaCompare(unix.NFT_META_IIFNAME, inbound, rule.Interface)...)
	expressions = append(expressions, nftables.MetaCompare(unix.NFT_META_OIFNAME, outbound, rule.Interface)...)
	if rule.From.IsValid() {
		expressions = append(expressions, nftables.SourcePrefix(rule.From)...)
	}
	expressions = append(expressions, nftables.Expression("counter", nil))
	expressions = append(expressions, translate(rule)...)
	return postrouting.Rule(nftFamily(rule.Family), rule.String(), expressions)
}

// translate is the statement that rewrites the source: the address written in
// the configuration, or the one the host's own routes would have used, which
// nf_tables spells as masquerade and decides per packet.
func translate(rule Rule) [][]byte {
	if !rule.Source.IsValid() {
		return [][]byte{nftables.Expression("masq", nil)}
	}
	immediate := nftables.PutAttrBE32(nil, unix.NFTA_IMMEDIATE_DREG, unix.NFT_REG_1)
	immediate = nftables.PutAttr(immediate, unix.NFTA_IMMEDIATE_DATA|unix.NLA_F_NESTED,
		nftables.PutAttr(nil, unix.NFTA_DATA_VALUE, nftables.AddressBytes(rule.Source)))
	nat := nftables.PutAttrBE32(nil, unix.NFTA_NAT_TYPE, unix.NFT_NAT_SNAT)
	nat = nftables.PutAttrBE32(nat, unix.NFTA_NAT_FAMILY, uint32(nftFamily(rule.Family)))
	nat = nftables.PutAttrBE32(nat, unix.NFTA_NAT_REG_ADDR_MIN, unix.NFT_REG_1)
	return [][]byte{nftables.Expression("immediate", immediate), nftables.Expression("nat", nat)}
}
