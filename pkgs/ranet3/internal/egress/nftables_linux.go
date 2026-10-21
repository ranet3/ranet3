// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package egress

import (
	"encoding/binary"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"net/netip"
	"os"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

// This file speaks nf_tables over NETLINK_NETFILTER directly, the way
// internal/kernel speaks rtnetlink: no `nft` to shell out to, no library to
// add, and the same request and reply discipline on one socket used by one
// goroutine.
//
// Two things about nf_tables differ from rtnetlink and both are used here.
// Every integer in an NFTA_ attribute is big endian, header fields included,
// while the netlink header itself stays native. And every write is a
// transaction: a batch between NFNL_MSG_BATCH_BEGIN and NFNL_MSG_BATCH_END
// commits whole or not at all, which is how a chain is replaced with no window
// in which a packet leaves untranslated.

const (
	// sizeofNfgenmsg is struct nfgenmsg: family, version and a big-endian
	// res_id. Named here rather than taken from x/sys, which does not carry it.
	sizeofNfgenmsg = 4
	// nfnetlinkV0 is NFNETLINK_V0, the only version there is.
	nfnetlinkV0 = 0
	// natSrcPriority is NF_IP_PRI_NAT_SRC, where source translation runs.
	// Chains of several writers coexist there. See Conflicts.
	natSrcPriority = 100
	// chainAccept is NF_ACCEPT, the only policy a nat base chain may carry
	// here: this package translates and never decides whether a packet lives.
	// The border chain carries it too, and its accept rules end with it.
	chainAccept = 1
	// verdictDrop is NF_DROP, which a border chain drop rule ends with
	verdictDrop = 0
	// nlaNested and nlaTypeMask are NLA_F_NESTED and NLA_TYPE_MASK. libnftnl
	// sets the flag, so it is set on the way out and masked off on the way in.
	nlaNested   = 0x8000
	nlaTypeMask = 0x3fff
	// udataComment is NFTNL_UDATA_RULE_COMMENT, the userdata type `nft` prints
	// as a rule's comment. This package writes Rule.String there and diffs on
	// it, so a rule reads in `nft list ruleset` exactly as the diff key spells
	// it.
	udataComment = 0
	// udataCommentMax is the comment length nft itself accepts.
	udataCommentMax = 128
	// ifNameSize is IFNAMSIZ. meta iifname and oifname load a NUL-padded name
	// of exactly this width, so a comparison has to be the same width or it
	// matches a prefix of another device's name.
	ifNameSize = 16
	// ipv4SourceOffset and ipv6SourceOffset are where the source address sits
	// in each network header, with the length that follows it, and
	// ipv6DestinationOffset where the IPv6 destination does.
	ipv4SourceOffset, ipv4AddressLen = 12, 4
	ipv6SourceOffset, ipv6AddressLen = 8, 16
	ipv6DestinationOffset            = 24
)

// nftables is the linux backend: the tables named after this tool, one per
// address family in use.
type nftables struct {
	conn     *nftConn
	monitor  *changeMonitor
	families []uint8
}

func newBackend(cfg Egress, rt Runtime) (backend, error) {
	conn, err := dialNetfilter()
	if err != nil {
		return nil, err
	}
	be := &nftables{conn: conn, families: cfg.translated(rt.Egress)}
	// A table this tool left behind in a family the configuration no longer
	// covers would go on translating under the old rules for as long as the
	// node ran, and nothing else here would ever look at it: every dump below
	// asks only about the families in use. It is removed once, at startup,
	// which is the only moment the set can have changed.
	if err := be.removeUnusedTables(); err != nil {
		conn.Close()
		return nil, err
	}
	if be.monitor, err = openChangeMonitor(conn.pid, translatorTables); err != nil {
		conn.Close()
		return nil, err
	}
	return be, nil
}

func (n *nftables) Close() error { return errors.Join(n.monitor.Close(), n.conn.Close()) }

func (n *nftables) Changed() <-chan struct{} { return n.monitor.changed }

func (n *nftables) Missed() <-chan struct{} { return n.monitor.missed }

// tableScope is one table name in a set of nf_tables families, the tables one
// owner holds and its change monitor watches
type tableScope struct {
	name     string
	families []uint8
}

var (
	// translatorTables is the translator's ip and ip6 tables
	translatorTables = tableScope{TableName, []uint8{unix.NFPROTO_IPV4, unix.NFPROTO_IPV6}}
	// borderTables is the border filter's inet table, which shares the name
	borderTables = tableScope{TableName, []uint8{unix.NFPROTO_INET}}
)

// changeMonitor wakes changed once per datagram of nf_tables notifications
// that holds another writer's change to its owner's tables, and missed once
// per overflow or datagram it cannot parse. A NixOS firewall reload flushes
// the whole ruleset, which takes the steered rule and the border chain with it
// until the next pass. A rule another writer adds, or a table it sets dormant,
// bypasses the chain as surely.
type changeMonitor struct {
	file    *os.File
	read    func([]byte) (int, error)
	pid     uint32
	scope   tableScope
	changed chan struct{}
	missed  chan struct{}
	done    chan struct{}
}

// openChangeMonitor joins the nf_tables notification group. pid is the
// socket the owner writes through, whose own changes the kernel stamps with
// it and which are not another writer's.
func openChangeMonitor(pid uint32, scope tableScope) (*changeMonitor, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_NETFILTER)
	if err != nil {
		return nil, fmt.Errorf("egress: open netfilter notification socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: 1 << (unix.NFNLGRP_NFTABLES - 1)}); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("egress: join the nf_tables notification group: %w", err)
	}
	growReceiveBuffer(fd)
	// nonblocking, so os.NewFile registers it with the runtime poller and Close unblocks the reader
	file := os.NewFile(uintptr(fd), "nftables-monitor")
	m := &changeMonitor{
		file:    file,
		read:    file.Read,
		pid:     pid,
		scope:   scope,
		changed: make(chan struct{}, 1),
		missed:  make(chan struct{}, 1),
		done:    make(chan struct{}),
	}
	go m.run()
	return m, nil
}

func (m *changeMonitor) run() {
	defer close(m.done)
	buf := make([]byte, notificationReadSize)
	for {
		n, err := m.read(buf)
		switch {
		case errors.Is(err, os.ErrClosed):
			return
		case errors.Is(err, unix.ENOBUFS):
			notify(m.missed)
			continue
		case err != nil:
			notify(m.missed)
			slog.Warn("egress stopped reading nf_tables notifications", "err", err)
			return
		}
		messages, err := parseMessages(buf[:n])
		switch {
		case err != nil:
			notify(m.missed)
		case slices.ContainsFunc(messages, func(message nftMessage) bool { return changedByAnother(message, m.pid, m.scope) }):
			notify(m.changed)
		}
	}
}

// growReceiveBuffer asks for receiveBuffer bytes of receive buffer on fd, past
// rmem_max where it can. Best effort: the forced form needs the capability
// this process already holds to write a rule at all, and a kernel that refuses
// both leaves the smaller buffer rather than a failure to start.
func growReceiveBuffer(fd int) {
	if unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, receiveBuffer) != nil {
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, receiveBuffer)
	}
}

func notify(signal chan<- struct{}) {
	select {
	case signal <- struct{}{}:
	default:
	}
}

func (m *changeMonitor) Close() error {
	err := m.file.Close()
	<-m.done
	return err
}

func changedByAnother(message nftMessage, pid uint32, scope tableScope) bool {
	if message.Pid == pid || message.Kind>>8 != unix.NFNL_SUBSYS_NFTABLES || len(message.Data) < sizeofNfgenmsg {
		return false
	}
	if !slices.Contains(scope.families, message.Data[0]) {
		return false
	}
	var naming uint16
	switch message.Kind & 0xff {
	case unix.NFT_MSG_NEWTABLE, unix.NFT_MSG_DELTABLE:
		naming = unix.NFTA_TABLE_NAME
	case unix.NFT_MSG_NEWCHAIN, unix.NFT_MSG_DELCHAIN:
		naming = unix.NFTA_CHAIN_TABLE
	case unix.NFT_MSG_NEWRULE, unix.NFT_MSG_DELRULE:
		naming = unix.NFTA_RULE_TABLE
	default:
		return false
	}
	for kind, value := range message.attributes(sizeofNfgenmsg) {
		if kind == naming && unix.ByteSliceToString(value) == scope.name {
			return true
		}
	}
	return false
}

// where names the tables this backend owns, for a log line.
func (n *nftables) where(Egress) string {
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
func (n *nftables) Rules() (map[uint8]chainReadback, error) {
	tables, err := ownTables(n.conn)
	if err != nil {
		return nil, err
	}
	out := make(map[uint8]chainReadback, len(n.families))
	for _, family := range n.families {
		read, err := readChain(n.conn, tables, nftFamily(family), postrouting)
		if err != nil {
			return nil, fmt.Errorf("egress: read table %s %s: %w", tableFamilyName(family), TableName, err)
		}
		for i := range read.rules {
			read.rules[i].Family = family
		}
		out[family] = read
	}
	return out, nil
}

// chainRules dumps every rule of chain in this tool's table of the nf_tables
// family proto, in order, one with no comment as an empty spec
func chainRules(conn *nftConn, proto uint8, chain string) ([]Installed, error) {
	replies, err := conn.dump(nftCommand(unix.NFT_MSG_GETRULE), putNfgenmsg(nil, proto))
	if err != nil {
		return nil, err
	}
	var out []Installed
	for _, reply := range replies {
		if table, name, spec, packets, bytes := decodeRule(reply); table == TableName && name == chain {
			out = append(out, Installed{Spec: spec, Packets: packets, Bytes: bytes})
		}
	}
	return out, nil
}

// decodeRule reads the fields a diff and a report need: where the rule lives,
// the comment this package wrote as its identity, and the counter. The
// expressions are walked only far enough to find that counter, because the
// comment already says what the rule does and re-deriving it from the
// expressions would be a second encoder to keep in step with the first.
func decodeRule(message nftMessage) (table, chain, spec string, packets, bytes uint64) {
	for kind, value := range message.attributes(sizeofNfgenmsg) {
		switch kind {
		case unix.NFTA_RULE_TABLE:
			table = unix.ByteSliceToString(value)
		case unix.NFTA_RULE_CHAIN:
			chain = unix.ByteSliceToString(value)
		case unix.NFTA_RULE_USERDATA:
			spec = comment(value)
		case unix.NFTA_RULE_EXPRESSIONS:
			packets, bytes = counters(value)
		}
	}
	return table, chain, spec, packets, bytes
}

// comment is the rule's identity as this package wrote it, out of the
// libnftnl userdata format: a sequence of type, length and value triples, of
// which this package writes exactly one.
func comment(userdata []byte) string {
	for len(userdata) >= 2 {
		kind, length := userdata[0], int(userdata[1])
		if len(userdata) < 2+length {
			return ""
		}
		if kind == udataComment {
			return strings.TrimRight(string(userdata[2:2+length]), "\x00")
		}
		userdata = userdata[2+length:]
	}
	return ""
}

// counters walks the expression list for the counter this package puts in
// every rule. The count is of flows rather than of packets: a nat chain is
// evaluated once per connection, when conntrack first sees it, and every
// packet after that is translated without the chain being consulted.
func counters(expressions []byte) (packets, bytes uint64) {
	for _, element := range nested(expressions) {
		if element.kind != unix.NFTA_LIST_ELEM {
			continue
		}
		var name string
		var data []byte
		for _, field := range nested(element.value) {
			switch field.kind {
			case unix.NFTA_EXPR_NAME:
				name = unix.ByteSliceToString(field.value)
			case unix.NFTA_EXPR_DATA:
				data = field.value
			}
		}
		if name != "counter" {
			continue
		}
		for _, field := range nested(data) {
			if len(field.value) != 8 {
				continue
			}
			switch field.kind {
			case unix.NFTA_COUNTER_BYTES:
				bytes = binary.BigEndian.Uint64(field.value)
			case unix.NFTA_COUNTER_PACKETS:
				packets = binary.BigEndian.Uint64(field.value)
			}
		}
	}
	return packets, bytes
}

// Apply brings this tool's own chain to rules, in one transaction. The chain
// is emptied and rewritten rather than edited rule by rule, because a batch
// commits atomically: no packet is ever evaluated against half a ruleset, and
// the alternative is a window in which a flow leaves untranslated and
// conntrack then holds that decision for its whole lifetime. The table of a
// family in remake is deleted first in the same transaction, with every chain
// in it, and made again.
func (n *nftables) Apply(rules []Rule, remake []uint8) error {
	requests, err := translatorBatch(n.families, rules, remake)
	if err != nil {
		return err
	}
	return n.conn.batch(requests)
}

// translatorBatch is the transaction Apply sends over families
func translatorBatch(families []uint8, rules []Rule, remake []uint8) ([]nftRequest, error) {
	var requests []nftRequest
	for _, family := range families {
		if slices.Contains(remake, family) {
			requests = append(requests, delTable(family))
		}
		requests = append(requests,
			newTable(nftFamily(family)),
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
func (n *nftables) Withdraw() error {
	return n.removeTables(func(uint8) bool { return true })
}

// removeUnusedTables is Withdraw narrowed to the families this configuration
// does not cover. See newBackend.
func (n *nftables) removeUnusedTables() error {
	return n.removeTables(func(family uint8) bool { return !slices.Contains(n.families, family) })
}

// removeTables deletes this tool's table in each family the predicate takes.
// The tables are listed first rather than deleted blind, because a delete of a
// table that is not there fails the whole transaction and would turn every
// shutdown on a node that never installed anything into an error. A table that
// goes away between the listing and the delete fails the same way, which only
// something else writing under this tool's own name can cause.
func (n *nftables) removeTables(match func(uint8) bool) error {
	held, err := ownTables(n.conn)
	if err != nil {
		return err
	}
	var requests []nftRequest
	for _, family := range []uint8{FamilyIPv4, FamilyIPv6} {
		if _, ok := held[nftFamily(family)]; ok && match(family) {
			requests = append(requests, delTable(family))
		}
	}
	return n.conn.batch(requests)
}

// ownTables is the flags of each table of this tool's name, keyed by its
// nf_tables family, which every caller reads its own of
func ownTables(conn *nftConn) (map[uint8]uint32, error) {
	replies, err := conn.dump(nftCommand(unix.NFT_MSG_GETTABLE), putNfgenmsg(nil, unix.NFPROTO_UNSPEC))
	if err != nil {
		return nil, fmt.Errorf("egress: dump tables: %w", err)
	}
	held := make(map[uint8]uint32)
	for _, reply := range replies {
		if len(reply.Data) < sizeofNfgenmsg {
			continue
		}
		var name string
		var flags uint32
		for kind, value := range reply.attributes(sizeofNfgenmsg) {
			switch {
			case kind == unix.NFTA_TABLE_NAME:
				name = unix.ByteSliceToString(value)
			case kind == unix.NFTA_TABLE_FLAGS && len(value) == 4:
				flags = binary.BigEndian.Uint32(value)
			}
		}
		if name == TableName {
			held[reply.Data[0]] = flags
		}
	}
	return held, nil
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
func (n *nftables) Conflicts() ([]string, error) {
	replies, err := n.conn.dump(nftCommand(unix.NFT_MSG_GETCHAIN), putNfgenmsg(nil, unix.NFPROTO_UNSPEC))
	if err != nil {
		return nil, fmt.Errorf("egress: dump chains: %w", err)
	}
	var out []string
	for _, reply := range replies {
		if len(reply.Data) < sizeofNfgenmsg {
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
		table, chain, kind, hook, priority := decodeChain(reply)
		if table == TableName || kind != "nat" || hook != unix.NF_INET_POST_ROUTING {
			continue
		}
		out = append(out, fmt.Sprintf("%s table %s chain %s at priority %d",
			tableFamilyName(family), table, chain, priority))
	}
	slices.Sort(out)
	return out, nil
}

func decodeChain(message nftMessage) (table, chain, kind string, hook uint32, priority int32) {
	// A chain with no hook is a regular chain, reached by a jump rather than
	// by the packet path, so the absent hook is reported as one no packet
	// enters at.
	hook = ^uint32(0)
	for attribute, value := range message.attributes(sizeofNfgenmsg) {
		switch attribute {
		case unix.NFTA_CHAIN_TABLE:
			table = unix.ByteSliceToString(value)
		case unix.NFTA_CHAIN_NAME:
			chain = unix.ByteSliceToString(value)
		case unix.NFTA_CHAIN_TYPE:
			kind = unix.ByteSliceToString(value)
		case unix.NFTA_CHAIN_HOOK:
			for _, field := range nested(value) {
				if len(field.value) != 4 {
					continue
				}
				switch field.kind {
				case unix.NFTA_HOOK_HOOKNUM:
					hook = binary.BigEndian.Uint32(field.value)
				case unix.NFTA_HOOK_PRIORITY:
					priority = int32(binary.BigEndian.Uint32(field.value))
				}
			}
		}
	}
	return table, chain, kind, hook, priority
}

// newTable creates the table in the nf_tables family proto if it is absent
// and adopts it if it is there, which is how a table a previous instance left
// behind is taken over. It writes the flags as none over whatever another
// writer set, so a dormant table is woken.
func newTable(proto uint8) nftRequest {
	table := tableRequest(unix.NFT_MSG_NEWTABLE, unix.NLM_F_CREATE, proto)
	table.body = putAttrBE32(table.body, unix.NFTA_TABLE_FLAGS, 0)
	return table
}

func delTable(family uint8) nftRequest {
	return tableRequest(unix.NFT_MSG_DELTABLE, 0, nftFamily(family))
}

// tableRequest is one command on this tool's table in the nf_tables family proto
func tableRequest(command int, flags uint16, proto uint8) nftRequest {
	body := putNfgenmsg(nil, proto)
	body = putAttrString(body, unix.NFTA_TABLE_NAME, TableName)
	return nftRequest{kind: nftCommand(command), flags: flags, body: body}
}

// hookedChain is the base chain one owner writes in this tool's table, which
// accepts what no rule decides
type hookedChain struct {
	name     string
	kind     string
	hook     uint32
	priority int32
}

var (
	// postrouting is the translator's chain, at the source translation hook
	// and the priority every other source translation on the host also runs
	// at. A different priority would not avoid the overlap, only reorder it,
	// and a number nothing else uses would put this node's translation either
	// before or after whatever the operator arranged on purpose.
	postrouting = hookedChain{ChainName, "nat", unix.NF_INET_POST_ROUTING, natSrcPriority}
	prerouting  = hookedChain{BorderChain, "filter", unix.NF_INET_PRE_ROUTING, rawPriority}
)

func newChain(family uint8) nftRequest { return baseChain(nftFamily(family), postrouting) }

// baseChain creates chain in this tool's table of the family proto, and
// writes its policy over whatever another writer set
func baseChain(proto uint8, chain hookedChain) nftRequest {
	hooked := putAttrBE32(nil, unix.NFTA_HOOK_HOOKNUM, chain.hook)
	hooked = putAttrBE32(hooked, unix.NFTA_HOOK_PRIORITY, uint32(chain.priority))
	body := putNfgenmsg(nil, proto)
	body = putAttrString(body, unix.NFTA_CHAIN_TABLE, TableName)
	body = putAttrString(body, unix.NFTA_CHAIN_NAME, chain.name)
	body = putAttr(body, unix.NFTA_CHAIN_HOOK|nlaNested, hooked)
	body = putAttrBE32(body, unix.NFTA_CHAIN_POLICY, chainAccept)
	body = putAttrString(body, unix.NFTA_CHAIN_TYPE, chain.kind)
	return nftRequest{kind: nftCommand(unix.NFT_MSG_NEWCHAIN), flags: unix.NLM_F_CREATE, body: body}
}

// fault names how the chain a dump holds differs from c as baseChain writes
// it, empty for that chain as written and for any other. remake holds where
// it differs in what nf_tables will not change in place: its type, hook or
// priority, or a hook at all, since a regular chain cannot become a base
// chain.
func (c hookedChain) fault(message nftMessage) (fault string, remake bool) {
	table, chain, kind, hook, priority := decodeChain(message)
	if table != TableName || chain != c.name {
		return "", false
	}
	policy := ^uint32(0)
	for attribute, value := range message.attributes(sizeofNfgenmsg) {
		if attribute == unix.NFTA_CHAIN_POLICY && len(value) == 4 {
			policy = binary.BigEndian.Uint32(value)
		}
	}
	remake = kind != c.kind || hook != c.hook || priority != c.priority
	if !remake && policy == chainAccept {
		return "", false
	}
	return fmt.Sprintf("its chain reads back as type %q at hook %d, priority %d, policy %d, where a %s chain at hook %d, priority %d, policy accept was written",
		kind, int32(hook), priority, int32(policy), c.kind, c.hook, c.priority), remake
}

// readChain reads back c whole with the table of this tool's name holding it
// in the nf_tables family proto, whose flags tables holds as ownTables read
// them: every rule in order with its counter, the chain's type, hook,
// priority and policy, and the table's flags
func readChain(conn *nftConn, tables map[uint8]uint32, proto uint8, c hookedChain) (chainReadback, error) {
	flags, held := tables[proto]
	if !held {
		return chainReadback{}, nil
	}
	var read chainReadback
	if flags != 0 {
		read.fault = fmt.Sprintf("its table carries flags %#x, where none are written and 0x1 is dormant", flags)
	}
	// nf_tables clears no flag of a table in place but dormant
	read.remake = flags&^unix.NFT_TABLE_F_DORMANT != 0
	chains, err := conn.dump(nftCommand(unix.NFT_MSG_GETCHAIN), putNfgenmsg(nil, proto))
	if err != nil {
		return chainReadback{}, fmt.Errorf("dump chains: %w", err)
	}
	for _, reply := range chains {
		fault, remake := c.fault(reply)
		if read.fault == "" {
			read.fault = fault
		}
		read.remake = read.remake || remake
	}
	if read.rules, err = chainRules(conn, proto, c.name); err != nil {
		return chainReadback{}, fmt.Errorf("dump rules: %w", err)
	}
	return read, nil
}

func flushChain(family uint8) nftRequest { return chainFlush(nftFamily(family), ChainName) }

// chainFlush empties chain in this tool's table of the family proto. It names
// a table and a chain and no handle, which nf_tables reads as every rule in
// that chain.
func chainFlush(proto uint8, chain string) nftRequest {
	body := putNfgenmsg(nil, proto)
	body = putAttrString(body, unix.NFTA_RULE_TABLE, TableName)
	body = putAttrString(body, unix.NFTA_RULE_CHAIN, chain)
	return nftRequest{kind: nftCommand(unix.NFT_MSG_DELRULE), body: body}
}

// newRule encodes one translation. The expressions read as the rule does in
// `nft list ruleset`: match the direction by interface, narrow an inbound rule
// to the prefix it was written for, count, and translate.
func newRule(rule Rule) (nftRequest, error) {
	spec := rule.String()
	if err := commentFits(spec); err != nil {
		return nftRequest{}, err
	}
	for _, name := range []string{rule.Interface, rule.Egress} {
		if err := deviceName(name); err != nil {
			return nftRequest{}, err
		}
	}
	// a steered packet routed back into the mesh keeps its source, so departure is still tested against the mesh device
	arrival := rule.Interface
	if rule.Egress != "" && rule.Direction == Out {
		arrival = rule.Egress
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
		expressions = append(expressions, metaCompareValue(unix.NFT_META_IIF, unix.NFT_CMP_NEQ, make([]byte, 4))...)
		if rule.Egress != "" {
			expressions = append(expressions, metaCompare(unix.NFT_META_IIFNAME, unix.NFT_CMP_NEQ, rule.Egress)...)
		}
	}
	expressions = append(expressions, metaCompare(unix.NFT_META_IIFNAME, inbound, arrival)...)
	expressions = append(expressions, metaCompare(unix.NFT_META_OIFNAME, outbound, rule.Interface)...)
	if rule.From.IsValid() {
		expressions = append(expressions, sourcePrefix(rule.From)...)
	}
	expressions = append(expressions, expression("counter", nil))
	expressions = append(expressions, translate(rule)...)
	return ruleRequest(nftFamily(rule.Family), ChainName, spec, expressions), nil
}

// commentFits refuses a spelling longer than the comment that carries it,
// which is truncated rather than refused by the host and would then never
// read back as the rule it names
func commentFits(spec string) error {
	if len(spec) >= udataCommentMax {
		return fmt.Errorf("egress: rule %s does not fit in a %d byte comment, which is its identity on the host", spec, udataCommentMax)
	}
	return nil
}

// deviceName refuses a name too long to be a device's. The kernel caps one at
// IFNAMSIZ-1, and a comparison of 16 bytes with no terminator equals no
// interface register: the rule would install and then match nothing, or
// through a "not" everything.
func deviceName(name string) error {
	if len(name) >= ifNameSize {
		return fmt.Errorf("egress: interface %q is %d bytes, and a device name is at most %d", name, len(name), ifNameSize-1)
	}
	return nil
}

// ruleRequest appends one rule of expressions to chain in this tool's table of
// the family proto, carrying spec as its comment and identity
func ruleRequest(proto uint8, chain, spec string, expressions [][]byte) nftRequest {
	body := putNfgenmsg(nil, proto)
	body = putAttrString(body, unix.NFTA_RULE_TABLE, TableName)
	body = putAttrString(body, unix.NFTA_RULE_CHAIN, chain)
	body = putAttr(body, unix.NFTA_RULE_EXPRESSIONS|nlaNested, slices.Concat(expressions...))
	body = putAttr(body, unix.NFTA_RULE_USERDATA, userdata(spec))
	return nftRequest{kind: nftCommand(unix.NFT_MSG_NEWRULE), flags: unix.NLM_F_CREATE | unix.NLM_F_APPEND, body: body}
}

// translate is the statement that rewrites the source: the address written in
// the configuration, or the one the host's own routes would have used, which
// nf_tables spells as masquerade and decides per packet.
func translate(rule Rule) [][]byte {
	if !rule.Source.IsValid() {
		return [][]byte{expression("masq", nil)}
	}
	immediate := putAttrBE32(nil, unix.NFTA_IMMEDIATE_DREG, unix.NFT_REG_1)
	immediate = putAttr(immediate, unix.NFTA_IMMEDIATE_DATA|nlaNested,
		putAttr(nil, unix.NFTA_DATA_VALUE, addressBytes(rule.Source)))
	nat := putAttrBE32(nil, unix.NFTA_NAT_TYPE, unix.NFT_NAT_SNAT)
	nat = putAttrBE32(nat, unix.NFTA_NAT_FAMILY, uint32(nftFamily(rule.Family)))
	nat = putAttrBE32(nat, unix.NFTA_NAT_REG_ADDR_MIN, unix.NFT_REG_1)
	return [][]byte{expression("immediate", immediate), expression("nat", nat)}
}

// metaCompare loads one interface name and compares it, over the full
// IFNAMSIZ the kernel pads it to. A shorter comparison would match every
// device whose name starts the same way.
func metaCompare(key uint32, op int, name string) [][]byte {
	padded := make([]byte, ifNameSize)
	copy(padded, name)
	return metaCompareValue(key, op, padded)
}

// metaCompareValue loads one packet metadatum and compares it against a
// literal, which is the shape every direction test here takes.
func metaCompareValue(key uint32, op int, value []byte) [][]byte {
	meta := putAttrBE32(nil, unix.NFTA_META_KEY, key)
	meta = putAttrBE32(meta, unix.NFTA_META_DREG, unix.NFT_REG_1)
	return [][]byte{expression("meta", meta), expression("cmp", compare(op, value))}
}

// sourcePrefix narrows a rule to packets sourced from one prefix: load the
// source out of the network header, mask it where the prefix is shorter than
// the address, and compare.
func sourcePrefix(prefix netip.Prefix) [][]byte {
	offset, length := uint32(ipv6SourceOffset), uint32(ipv6AddressLen)
	if prefix.Addr().Is4() {
		offset, length = ipv4SourceOffset, ipv4AddressLen
	}
	out := [][]byte{networkLoad(offset, length)}
	if int(prefix.Bits()) < int(length)*8 {
		mask := prefixMask(prefix)
		bitwise := putAttrBE32(nil, unix.NFTA_BITWISE_SREG, unix.NFT_REG_1)
		bitwise = putAttrBE32(bitwise, unix.NFTA_BITWISE_DREG, unix.NFT_REG_1)
		bitwise = putAttrBE32(bitwise, unix.NFTA_BITWISE_LEN, length)
		bitwise = putAttr(bitwise, unix.NFTA_BITWISE_MASK|nlaNested, putAttr(nil, unix.NFTA_DATA_VALUE, mask))
		bitwise = putAttr(bitwise, unix.NFTA_BITWISE_XOR|nlaNested,
			putAttr(nil, unix.NFTA_DATA_VALUE, make([]byte, length)))
		out = append(out, expression("bitwise", bitwise))
	}
	return append(out, expression("cmp", compare(unix.NFT_CMP_EQ, addressBytes(prefix.Masked().Addr()))))
}

// networkLoad loads length bytes at offset into the network header
func networkLoad(offset, length uint32) []byte {
	load := putAttrBE32(nil, unix.NFTA_PAYLOAD_DREG, unix.NFT_REG_1)
	load = putAttrBE32(load, unix.NFTA_PAYLOAD_BASE, unix.NFT_PAYLOAD_NETWORK_HEADER)
	load = putAttrBE32(load, unix.NFTA_PAYLOAD_OFFSET, offset)
	load = putAttrBE32(load, unix.NFTA_PAYLOAD_LEN, length)
	return expression("payload", load)
}

// prefixMask is the prefix length as the bytes a bitwise expression masks
// with.
func prefixMask(prefix netip.Prefix) []byte {
	length := ipv6AddressLen
	if prefix.Addr().Is4() {
		length = ipv4AddressLen
	}
	mask := make([]byte, length)
	bits := prefix.Bits()
	for i := range mask {
		switch {
		case bits >= 8:
			mask[i] = 0xff
			bits -= 8
		case bits > 0:
			mask[i] = byte(0xff << (8 - bits))
			bits = 0
		}
	}
	return mask
}

func compare(op int, value []byte) []byte {
	body := putAttrBE32(nil, unix.NFTA_CMP_SREG, unix.NFT_REG_1)
	body = putAttrBE32(body, unix.NFTA_CMP_OP, uint32(op))
	return putAttr(body, unix.NFTA_CMP_DATA|nlaNested, putAttr(nil, unix.NFTA_DATA_VALUE, value))
}

// expression is one element of a rule's expression list: a name and the
// attributes that expression takes. The data attribute is emitted even when
// empty, as libnftnl emits it, so an expression carrying no parameters still
// reads as one.
func expression(name string, data []byte) []byte {
	body := putAttrString(nil, unix.NFTA_EXPR_NAME, name)
	body = putAttr(body, unix.NFTA_EXPR_DATA|nlaNested, data)
	return putAttr(nil, unix.NFTA_LIST_ELEM|nlaNested, body)
}

// userdata is the comment in the format libnftnl reads, so `nft list ruleset`
// prints this package's own spelling of the rule beside it.
func userdata(spec string) []byte {
	value := append([]byte(spec), 0)
	return append([]byte{udataComment, byte(len(value))}, value...)
}

// addressBytes is the wire form of an address, four bytes or sixteen, never
// the 4-in-6 form: a table is per family here, so the family is already
// decided by the time an address is encoded.
func addressBytes(address netip.Addr) []byte {
	if address.Is4() {
		raw := address.As4()
		return raw[:]
	}
	raw := address.As16()
	return raw[:]
}

// nftConn is one NETLINK_NETFILTER socket used for synchronous request and
// reply. The single reconcile goroutine is its only caller, so it needs no
// locking, and nothing subscribes to a notification group, so an unsolicited
// message can never arrive on it.
type nftConn struct {
	fd  int
	pid uint32
	seq uint32
	buf []byte
}

// replyTimeout bounds a wait on the kernel. A batch is acknowledged message by
// message and a dump ends at NLMSG_DONE, so a reply that never comes is a
// kernel that did not understand the request, and blocking on it forever would
// stop the reconcile loop with no error to report.
const replyTimeout = 10

// receiveBuffer is asked for so that a whole transaction's acknowledgments
// fit while the sender is still sending. See dialNetfilter.
const receiveBuffer = 1 << 20

func dialNetfilter() (*nftConn, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_NETFILTER)
	if err != nil {
		return nil, fmt.Errorf("egress: open netfilter netlink socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("egress: bind netfilter netlink socket: %w", err)
	}
	name, err := unix.Getsockname(fd)
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("egress: read netfilter netlink socket name: %w", err)
	}
	local, ok := name.(*unix.SockaddrNetlink)
	if !ok {
		_ = unix.Close(fd)
		return nil, errors.New("egress: netfilter socket is not a netlink socket")
	}
	timeout := unix.Timeval{Sec: replyTimeout}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("egress: set netfilter netlink receive timeout: %w", err)
	}
	// Every message in a transaction is acknowledged, and the kernel queues
	// all of those acks while this process is still inside its one send, with
	// nothing draining them. The default receive buffer holds a few hundred,
	// which a node advertising a few hundred prefixes would exceed, and the
	// overflow arrives as an ENOBUFS that explains nothing.
	growReceiveBuffer(fd)
	return &nftConn{fd: fd, pid: local.Pid, buf: make([]byte, 64*1024)}, nil
}

func (c *nftConn) Close() error { return unix.Close(c.fd) }

// nftRequest is one message inside a transaction.
type nftRequest struct {
	kind  uint16
	flags uint16
	body  []byte
}

// nftCommand is the netlink message type for one nf_tables command.
func nftCommand(command int) uint16 {
	return uint16(unix.NFNL_SUBSYS_NFTABLES)<<8 | uint16(command)
}

// nftMessage is one parsed reply: the header fields this package reads plus
// the body, which holds a struct nfgenmsg and the attributes after it.
type nftMessage struct {
	Kind uint16
	Seq  uint32
	Pid  uint32
	Data []byte
}

// batch sends one transaction and waits for the kernel to acknowledge every
// message in it. Everything between the batch markers commits together or not
// at all, so a failure leaves the host holding exactly what it held before.
//
// A failure inside the batch is reported against the message that caused it,
// and a failure of the commit itself against the batch marker, so any nonzero
// error in the range this call owns ends it. Acknowledgments left in the
// socket by an earlier call carry earlier sequence numbers and are ignored
// rather than mistaken for this call's.
func (c *nftConn) batch(requests []nftRequest) error {
	if len(requests) == 0 {
		return nil
	}
	marker := putNfgenmsgSubsys(nil, unix.NFPROTO_UNSPEC)
	begin := c.next()
	var buf []byte
	buf = c.appendMessage(buf, unix.NFNL_MSG_BATCH_BEGIN, 0, begin, marker)
	expected := make(map[uint32]bool, len(requests))
	first, last := begin, begin
	for _, request := range requests {
		seq := c.next()
		expected[seq] = true
		last = seq
		buf = c.appendMessage(buf, request.kind, request.flags|unix.NLM_F_ACK, seq, request.body)
	}
	end := c.next()
	last = end
	buf = c.appendMessage(buf, unix.NFNL_MSG_BATCH_END, 0, end, marker)
	if err := unix.Sendto(c.fd, buf, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	for len(expected) > 0 {
		messages, err := c.receive()
		if err != nil {
			return err
		}
		for _, message := range messages {
			// Subtracted rather than compared, so a sequence number that
			// wraps inside one transaction narrows the window rather than
			// inverting it.
			if message.Pid != c.pid || message.Seq-first > last-first {
				continue
			}
			if message.Kind != unix.NLMSG_ERROR {
				continue
			}
			if len(message.Data) < 4 {
				return errors.New("egress: truncated netlink error")
			}
			if code := int32(binary.NativeEndian.Uint32(message.Data)); code != 0 {
				return unix.Errno(-code)
			}
			delete(expected, message.Seq)
		}
	}
	return nil
}

// dump sends one query and collects every reply to it, ending at NLMSG_DONE.
func (c *nftConn) dump(kind uint16, body []byte) ([]nftMessage, error) {
	seq := c.next()
	buf := c.appendMessage(nil, kind, unix.NLM_F_DUMP, seq, body)
	if err := unix.Sendto(c.fd, buf, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	var replies []nftMessage
	for {
		messages, err := c.receive()
		if err != nil {
			return nil, err
		}
		for _, message := range messages {
			if message.Seq != seq || message.Pid != c.pid {
				continue
			}
			switch message.Kind {
			case unix.NLMSG_NOOP:
			case unix.NLMSG_DONE:
				return replies, nil
			case unix.NLMSG_ERROR:
				if len(message.Data) < 4 {
					return nil, errors.New("egress: truncated netlink error")
				}
				if code := int32(binary.NativeEndian.Uint32(message.Data)); code != 0 {
					return nil, unix.Errno(-code)
				}
				return replies, nil
			default:
				replies = append(replies, message)
			}
		}
	}
}

func (c *nftConn) next() uint32 {
	c.seq++
	return c.seq
}

// appendMessage writes one netlink message, header and body, padded as the
// kernel expects. The header fields are native endian, but everything inside an
// NFTA attribute is not.
func (c *nftConn) appendMessage(buf []byte, kind, flags uint16, seq uint32, body []byte) []byte {
	length := unix.SizeofNlMsghdr + len(body)
	start := len(buf)
	buf = append(buf, make([]byte, nlmsgAlign(length))...)
	binary.NativeEndian.PutUint32(buf[start:], uint32(length))
	binary.NativeEndian.PutUint16(buf[start+4:], kind)
	binary.NativeEndian.PutUint16(buf[start+6:], flags|unix.NLM_F_REQUEST)
	binary.NativeEndian.PutUint32(buf[start+8:], seq)
	binary.NativeEndian.PutUint32(buf[start+12:], c.pid)
	copy(buf[start+unix.SizeofNlMsghdr:], body)
	return buf
}

// receive reads one datagram whole, growing the buffer when the kernel has
// more to say than it currently holds, exactly as internal/kernel does.
func (c *nftConn) receive() ([]nftMessage, error) {
	for {
		n, _, err := unix.Recvfrom(c.fd, c.buf, unix.MSG_PEEK|unix.MSG_TRUNC)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if errors.Is(err, unix.EAGAIN) {
			return nil, errors.New("egress: the kernel did not answer a netfilter netlink request")
		}
		if err != nil {
			return nil, err
		}
		if n <= len(c.buf) {
			break
		}
		c.buf = make([]byte, n)
	}
	for {
		n, from, err := unix.Recvfrom(c.fd, c.buf, 0)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if sender, ok := from.(*unix.SockaddrNetlink); !ok || sender.Pid != 0 {
			return nil, errors.New("egress: netfilter reply did not come from the kernel")
		}
		return parseMessages(slices.Clone(c.buf[:n]))
	}
}

// parseMessages splits one datagram into messages. A length running past the
// buffer is an error rather than a short read, so a truncated dump can never
// look like a complete one.
func parseMessages(buf []byte) ([]nftMessage, error) {
	var out []nftMessage
	for len(buf) >= unix.SizeofNlMsghdr {
		length := int(binary.NativeEndian.Uint32(buf[0:]))
		if length < unix.SizeofNlMsghdr || length > len(buf) {
			return nil, errors.New("egress: malformed netlink message length")
		}
		out = append(out, nftMessage{
			Kind: binary.NativeEndian.Uint16(buf[4:]),
			Seq:  binary.NativeEndian.Uint32(buf[8:]),
			Pid:  binary.NativeEndian.Uint32(buf[12:]),
			Data: buf[unix.SizeofNlMsghdr:length],
		})
		next := nlmsgAlign(length)
		if next >= len(buf) {
			break
		}
		buf = buf[next:]
	}
	return out, nil
}

// attributes iterates the attributes that follow a fixed header of offset
// bytes. A malformed attribute ends the iteration: the kernel emits none, and
// a half-decoded message fails the name checks that follow rather than being
// acted on.
func (m nftMessage) attributes(offset int) iter.Seq2[uint16, []byte] {
	return func(yield func(uint16, []byte) bool) {
		if len(m.Data) < offset {
			return
		}
		for _, field := range nested(m.Data[offset:]) {
			if !yield(field.kind, field.value) {
				return
			}
		}
	}
}

// attribute is one decoded netlink attribute, with the nested flag already
// masked off its type.
type attribute struct {
	kind  uint16
	value []byte
}

// nested splits an attribute's payload into the attributes inside it.
func nested(buf []byte) []attribute {
	var out []attribute
	for len(buf) >= unix.SizeofRtAttr {
		length := int(binary.NativeEndian.Uint16(buf[0:]))
		kind := binary.NativeEndian.Uint16(buf[2:]) & nlaTypeMask
		if length < unix.SizeofRtAttr || length > len(buf) {
			return out
		}
		out = append(out, attribute{kind: kind, value: buf[unix.SizeofRtAttr:length]})
		next := rtaAlign(length)
		if next >= len(buf) {
			return out
		}
		buf = buf[next:]
	}
	return out
}

// putNfgenmsg writes struct nfgenmsg for an nf_tables message.
func putNfgenmsg(buf []byte, family uint8) []byte {
	return append(buf, family, nfnetlinkV0, 0, 0)
}

// putNfgenmsgSubsys writes the same header for a batch marker, whose res_id
// names the subsystem the transaction belongs to. It is big endian, unlike the
// netlink header around it.
func putNfgenmsgSubsys(buf []byte, family uint8) []byte {
	buf = append(buf, family, nfnetlinkV0, 0, 0)
	binary.BigEndian.PutUint16(buf[len(buf)-2:], uint16(unix.NFNL_SUBSYS_NFTABLES))
	return buf
}

func putAttr(buf []byte, kind uint16, value []byte) []byte {
	length := unix.SizeofRtAttr + len(value)
	start := len(buf)
	buf = append(buf, make([]byte, rtaAlign(length))...)
	binary.NativeEndian.PutUint16(buf[start:], uint16(length))
	binary.NativeEndian.PutUint16(buf[start+2:], kind)
	copy(buf[start+unix.SizeofRtAttr:], value)
	return buf
}

// putAttrBE32 writes a 32-bit attribute in network byte order, which is how
// nf_tables carries every number in an NFTA attribute.
func putAttrBE32(buf []byte, kind uint16, value uint32) []byte {
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], value)
	return putAttr(buf, kind, raw[:])
}

func putAttrString(buf []byte, kind uint16, value string) []byte {
	return putAttr(buf, kind, append([]byte(value), 0))
}

func nlmsgAlign(n int) int { return (n + unix.NLMSG_ALIGNTO - 1) &^ (unix.NLMSG_ALIGNTO - 1) }

func rtaAlign(n int) int { return (n + unix.RTA_ALIGNTO - 1) &^ (unix.RTA_ALIGNTO - 1) }
