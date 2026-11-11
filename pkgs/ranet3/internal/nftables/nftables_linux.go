// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

// Package nftables speaks nf_tables over a NETLINK_NETFILTER socket of
// internal/netlink: no `nft` to shell out to, no library to add, and a request
// and reply discipline on one socket used by one goroutine.
//
// Two things about nf_tables differ from rtnetlink. Every integer in an NFTA_
// attribute is big endian, header fields included, while the netlink header
// itself stays native. And every write is a transaction: a batch between
// NFNL_MSG_BATCH_BEGIN and NFNL_MSG_BATCH_END commits whole or not at all,
// which is how a chain is replaced with no window in which a packet meets
// half of it.
package nftables

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/netlink"
)

// Tables is the flags of each table named name, keyed by its nf_tables
// family
func Tables(conn *Conn, name string) (map[uint8]uint32, error) {
	replies, err := conn.Dump(Command(unix.NFT_MSG_GETTABLE), PutNfgenmsg(nil, unix.NFPROTO_UNSPEC))
	if err != nil {
		return nil, fmt.Errorf("nftables: dump tables: %w", err)
	}
	held := make(map[uint8]uint32)
	for _, reply := range replies {
		if len(reply.Data) < SizeofNfgenmsg {
			continue
		}
		var table string
		var flags uint32
		for kind, value := range reply.Attributes(SizeofNfgenmsg) {
			switch {
			case kind == unix.NFTA_TABLE_NAME:
				table = unix.ByteSliceToString(value)
			case kind == unix.NFTA_TABLE_FLAGS && len(value) == 4:
				flags = binary.BigEndian.Uint32(value)
			}
		}
		if table == name {
			held[reply.Data[0]] = flags
		}
	}
	return held, nil
}

// TableChains is the name of every chain of the table named table in the
// nf_tables family proto, none where the table is not there. The kernel dumps
// the chains of every table of the family.
func TableChains(conn *Conn, proto uint8, table string) ([]string, error) {
	replies, err := conn.Dump(Command(unix.NFT_MSG_GETCHAIN), PutNfgenmsg(nil, proto))
	if err != nil {
		return nil, fmt.Errorf("nftables: dump chains: %w", err)
	}
	var out []string
	for _, reply := range replies {
		if held, name, _, _, _ := DecodeChain(reply); held == table {
			out = append(out, name)
		}
	}
	return out, nil
}

// TableRules is every rule of every chain of the table named table in the
// nf_tables family proto, which the kernel filters by the table the request
// names
func TableRules(conn *Conn, proto uint8, table string) ([]Installed, error) {
	replies, err := conn.Dump(Command(unix.NFT_MSG_GETRULE), netlink.PutAttrString(PutNfgenmsg(nil, proto), unix.NFTA_RULE_TABLE, table))
	if err != nil {
		return nil, fmt.Errorf("nftables: dump rules: %w", err)
	}
	var out []Installed
	for _, reply := range replies {
		if held, rule := decodeInstalled(reply); held == table {
			out = append(out, rule)
		}
	}
	return out, nil
}

// decodeInstalled reads a rule out of a dump, with the table it lives in
func decodeInstalled(reply netlink.Message) (table string, rule Installed) {
	table, rule.Chain, rule.Spec, rule.Packets, rule.Bytes, rule.Counted = DecodeRule(reply)
	for kind, value := range reply.Attributes(SizeofNfgenmsg) {
		if kind == unix.NFTA_RULE_EXPRESSIONS {
			rule.Expressions = value
		}
	}
	return table, rule
}

// NewTable creates the table name in the nf_tables family proto if it is
// absent and adopts it if it is there, which is how a table a previous
// instance left behind is taken over. It writes the flags as none over
// whatever another writer set, so a dormant table is woken.
func NewTable(proto uint8, name string) Request {
	table := tableRequest(unix.NFT_MSG_NEWTABLE, unix.NLM_F_CREATE, proto, name)
	table.Body = PutAttrBE32(table.Body, unix.NFTA_TABLE_FLAGS, 0)
	return table
}

// DeleteTable's request takes every chain in the table with it
func DeleteTable(proto uint8, name string) Request {
	return tableRequest(unix.NFT_MSG_DELTABLE, 0, proto, name)
}

func tableRequest(command int, flags uint16, proto uint8, name string) Request {
	body := PutNfgenmsg(nil, proto)
	body = netlink.PutAttrString(body, unix.NFTA_TABLE_NAME, name)
	return Request{Kind: Command(command), Flags: flags, Body: body}
}

// Chain is a chain one owner writes in its table: a base chain, which accepts
// what no rule decides, or with Hook NoHook and no Type a regular chain, which
// a packet enters by a rule's Goto alone
type Chain struct {
	Table    string
	Name     string
	Type     string
	Hook     uint32
	Priority int32
}

// NoHook is the hook DecodeChain reads for a regular chain, one no packet
// enters at
const NoHook = ^uint32(0)

// Create writes c's policy over whatever another writer set
func (c Chain) Create(proto uint8) Request {
	body := PutNfgenmsg(nil, proto)
	body = netlink.PutAttrString(body, unix.NFTA_CHAIN_TABLE, c.Table)
	body = netlink.PutAttrString(body, unix.NFTA_CHAIN_NAME, c.Name)
	if c.Hook != NoHook {
		hooked := PutAttrBE32(nil, unix.NFTA_HOOK_HOOKNUM, c.Hook)
		hooked = PutAttrBE32(hooked, unix.NFTA_HOOK_PRIORITY, uint32(c.Priority))
		body = netlink.PutAttr(body, unix.NFTA_CHAIN_HOOK|unix.NLA_F_NESTED, hooked)
		body = PutAttrBE32(body, unix.NFTA_CHAIN_POLICY, Accept)
		body = netlink.PutAttrString(body, unix.NFTA_CHAIN_TYPE, c.Type)
	}
	return Request{Kind: Command(unix.NFT_MSG_NEWCHAIN), Flags: unix.NLM_F_CREATE, Body: body}
}

// Delete takes the chain's rules with it, and fails while a rule another
// chain holds sends packets to it
func (c Chain) Delete(proto uint8) Request {
	body := PutNfgenmsg(nil, proto)
	body = netlink.PutAttrString(body, unix.NFTA_CHAIN_TABLE, c.Table)
	body = netlink.PutAttrString(body, unix.NFTA_CHAIN_NAME, c.Name)
	return Request{Kind: Command(unix.NFT_MSG_DELCHAIN), Body: body}
}

// Flush names no handle, which nf_tables reads as every rule in the chain
func (c Chain) Flush(proto uint8) Request {
	body := PutNfgenmsg(nil, proto)
	body = netlink.PutAttrString(body, unix.NFTA_RULE_TABLE, c.Table)
	body = netlink.PutAttrString(body, unix.NFTA_RULE_CHAIN, c.Name)
	return Request{Kind: Command(unix.NFT_MSG_DELRULE), Body: body}
}

// Rule carries spec as the rule's comment, which names the line in `nft list
// ruleset` and in a readback
func (c Chain) Rule(proto uint8, spec string, expressions [][]byte) (Request, error) {
	// a longer comment still lists in `nft list ruleset`, but nft -f will not load that listing back
	if len(spec) > udataCommentMax {
		return Request{}, fmt.Errorf("nftables: rule %s does not fit in a %d byte comment", spec, udataCommentMax)
	}
	body := PutNfgenmsg(nil, proto)
	body = netlink.PutAttrString(body, unix.NFTA_RULE_TABLE, c.Table)
	body = netlink.PutAttrString(body, unix.NFTA_RULE_CHAIN, c.Name)
	body = netlink.PutAttr(body, unix.NFTA_RULE_EXPRESSIONS|unix.NLA_F_NESTED, slices.Concat(expressions...))
	body = netlink.PutAttr(body, unix.NFTA_RULE_USERDATA, userdata(udataComment, spec))
	return Request{Kind: Command(unix.NFT_MSG_NEWRULE), Flags: unix.NLM_F_CREATE | unix.NLM_F_APPEND, Body: body}, nil
}

// Fault names how the chain a dump holds differs from c as Create writes it,
// empty for that chain as written and for any other. remake holds where it
// differs in what nf_tables will not change in place: its type, hook or
// priority, or a hook at all, since a regular chain cannot become a base
// chain.
func (c Chain) Fault(message netlink.Message) (fault string, remake bool) {
	table, chain, kind, hook, priority := DecodeChain(message)
	if table != c.Table || chain != c.Name {
		return "", false
	}
	// a regular chain carries no policy, which reads as none
	policy, written := ^uint32(0), ^uint32(0)
	for attribute, value := range message.Attributes(SizeofNfgenmsg) {
		if attribute == unix.NFTA_CHAIN_POLICY && len(value) == 4 {
			policy = binary.BigEndian.Uint32(value)
		}
	}
	if c.Hook != NoHook {
		written = Accept
	}
	remake = kind != c.Type || hook != c.Hook || priority != c.Priority
	if !remake && policy == written {
		return "", false
	}
	want := fmt.Sprintf("a %s chain at hook %d, priority %d, policy accept", c.Type, c.Hook, c.Priority)
	if c.Hook == NoHook {
		want = "the regular chain " + c.Name
	}
	return fmt.Sprintf("its chain reads back as type %q at hook %d, priority %d, policy %d, where %s was written",
		kind, int32(hook), priority, int32(policy), want), remake
}

// Installed is one rule as a dump read it back: the comment it was written
// under, empty for a rule with none, the chain it was read from, its counter
// where Counted says it keeps one, and its expressions as the kernel lists them
type Installed struct {
	Spec        string
	Chain       string
	Packets     uint64
	Bytes       uint64
	Counted     bool
	Expressions []byte
}

// Contents names the chains, sets and ct timeout objects one owner writes in a
// table in one nf_tables family, each read back by its name. Any other in the
// table is another writer's.
type Contents struct {
	Chains   []Chain
	Sets     []Set
	Timeouts []Timeout
	// Elements holds the keys its owner fills each named set of Sets with,
	// whole. A set it does not name, one the datapath fills, has its elements
	// unread.
	Elements map[string][]Interval
}

// Readback is a table and what Contents holds of it in one nf_tables family,
// as a dump finds them
type Readback struct {
	// Rules is every rule of each chain in order, the chains in the order
	// Contents lists them
	Rules []Installed
	// Fault names the first way the table, a chain, a set or an object differs
	// from what NewTable and the Create methods write, a missing set or object
	// among them, empty where none does
	Fault string
	// Stale is each chain, set and object of Contents that differs in what
	// nf_tables will not change in place, which Rewrite deletes and its owner
	// makes again in one transaction
	Stale Contents
	// Chains is the name of each chain the table holds, as the dump finds
	// them, those Contents names and those it does not
	Chains []string
	// Held is whether the table holds any chain, set or object Contents names
	Held bool
}

// Remake is whether the read found anything stale
func (r Readback) Remake() bool {
	return len(r.Stale.Chains) > 0 || len(r.Stale.Sets) > 0 || len(r.Stale.Timeouts) > 0
}

// Read takes tables as Tables read them
func (c Contents) Read(conn *Conn, tables map[uint8]uint32, proto uint8) (Readback, error) {
	flags, held := tables[proto]
	if !held {
		return Readback{}, nil
	}
	var read Readback
	note := func(fault string) {
		if read.Fault == "" {
			read.Fault = fault
		}
	}
	if flags != 0 {
		// NewTable clears a dormant flag in place, and only deleting the table, with every other owner's chains in it, clears another
		fault := fmt.Sprintf("its table carries flags %#x, where none are written and 0x1 is dormant", flags)
		if flags&^unix.NFT_TABLE_F_DORMANT != 0 {
			fault += fmt.Sprintf(", and only nft delete table inet %s clears another", c.table())
		}
		note(fault)
	}
	// the kernel dumps the sets, objects and rules of the table and chain a
	// request names alone, but the chains of every table of the family
	if len(c.Chains) > 0 {
		chains, err := conn.Dump(Command(unix.NFT_MSG_GETCHAIN), netlink.PutAttrString(PutNfgenmsg(nil, proto), unix.NFTA_CHAIN_TABLE, c.Chains[0].Table))
		if err != nil {
			return Readback{}, fmt.Errorf("dump chains: %w", err)
		}
		for _, reply := range chains {
			table, name, _, _, _ := DecodeChain(reply)
			if table != c.Chains[0].Table {
				continue
			}
			read.Chains = append(read.Chains, name)
			for _, chain := range c.Chains {
				if chain.Name != name {
					continue
				}
				read.Held = true
				fault, remake := chain.Fault(reply)
				note(fault)
				if remake {
					read.Stale.Chains = append(read.Stale.Chains, chain)
				}
			}
		}
	}
	if len(c.Sets) > 0 {
		sets, err := conn.Dump(Command(unix.NFT_MSG_GETSET), netlink.PutAttrString(PutNfgenmsg(nil, proto), unix.NFTA_SET_TABLE, c.Sets[0].Table))
		if err != nil {
			return Readback{}, fmt.Errorf("dump sets: %w", err)
		}
		for _, set := range c.Sets {
			found := slices.IndexFunc(sets, func(reply netlink.Message) bool {
				held := DecodeSet(reply)
				return held.Table == set.Table && held.Name == set.Name
			})
			if found < 0 {
				note(fmt.Sprintf("its set %s is missing", set.Name))
				continue
			}
			read.Held = true
			fault, remake := set.Fault(sets[found])
			note(fault)
			if remake {
				read.Stale.Sets = append(read.Stale.Sets, set)
				continue
			}
			written, filled := c.Elements[set.Name]
			if !filled {
				continue
			}
			held, err := set.Elements(conn, proto)
			if err != nil {
				return Readback{}, err
			}
			if fault := set.elementFault(written, held); fault != "" {
				note(fault)
			}
		}
	}
	if len(c.Timeouts) > 0 {
		objects, err := conn.Dump(Command(unix.NFT_MSG_GETOBJ), netlink.PutAttrString(PutNfgenmsg(nil, proto), unix.NFTA_OBJ_TABLE, c.Timeouts[0].Table))
		if err != nil {
			return Readback{}, fmt.Errorf("dump objects: %w", err)
		}
		for _, timeout := range c.Timeouts {
			fault, remake, found := readTimeout(timeout, objects)
			note(fault)
			read.Held = read.Held || found
			if remake {
				read.Stale.Timeouts = append(read.Stale.Timeouts, timeout)
			}
		}
	}
	rules, err := c.rules(conn, proto)
	if err != nil {
		return Readback{}, fmt.Errorf("dump rules: %w", err)
	}
	read.Rules = rules
	return read, nil
}

// Scope is c's chains, sets and timeout objects by name
func (c Contents) Scope() Scope {
	var s Scope
	for _, chain := range c.Chains {
		s.Chains = append(s.Chains, chain.Name)
	}
	for _, set := range c.Sets {
		s.Sets = append(s.Sets, set.Name)
	}
	for _, timeout := range c.Timeouts {
		s.Timeouts = append(s.Timeouts, timeout.Name)
	}
	return s
}

// table is the table c's objects live in
func (c Contents) table() string {
	switch {
	case len(c.Chains) > 0:
		return c.Chains[0].Table
	case len(c.Sets) > 0:
		return c.Sets[0].Table
	case len(c.Timeouts) > 0:
		return c.Timeouts[0].Table
	}
	return ""
}

// Rewrite is the head of the one transaction that writes c over what its read
// found stale: Table, adopted where it is there, each chain of stale deleted
// with its rules, each chain of c made and flushed, which makes a deleted one
// again, each of strays flushed, then each set and object of stale deleted.
// strays are the owner's chains the table holds that c does not write, which
// the owner deletes after the head. Every chain of the owner's is flushed
// before any set or object goes, since nf_tables refuses to delete one a rule
// still uses, so only another writer's rule using one fails the transaction.
// Its owner then makes c's sets and objects, fills the sets and writes its
// rules, which makes every one stale named again.
func (c Contents) Rewrite(proto uint8, stale Contents, strays []string) []Request {
	requests := []Request{NewTable(proto, Table)}
	for _, chain := range stale.Chains {
		requests = append(requests, chain.Delete(proto))
	}
	for _, chain := range c.Chains {
		requests = append(requests, chain.Create(proto), chain.Flush(proto))
	}
	for _, name := range strays {
		requests = append(requests, Chain{Table: Table, Name: name}.Flush(proto))
	}
	for _, set := range stale.Sets {
		requests = append(requests, set.Delete(proto))
	}
	for _, timeout := range stale.Timeouts {
		requests = append(requests, timeout.Delete(proto))
	}
	return requests
}

// listing is Table as a withdrawal finds it: its flags, the name of each
// chain and named set, each object by type and name, every rule and every
// verdict map, which say what goes to a chain
type listing struct {
	flags   uint32
	chains  []string
	sets    []string
	objects []object
	rules   []Installed
	maps    []VerdictMap
}

type object struct {
	kind uint32
	name string
}

func list(conn *Conn, flags uint32) (listing, error) {
	l := listing{flags: flags}
	var err error
	if l.chains, err = TableChains(conn, unix.NFPROTO_INET, Table); err != nil {
		return listing{}, err
	}
	sets, err := conn.Dump(Command(unix.NFT_MSG_GETSET), netlink.PutAttrString(PutNfgenmsg(nil, unix.NFPROTO_INET), unix.NFTA_SET_TABLE, Table))
	if err != nil {
		return listing{}, fmt.Errorf("nftables: dump sets: %w", err)
	}
	for _, reply := range sets {
		if set := DecodeSet(reply); set.Table == Table && set.Flags&unix.NFT_SET_ANONYMOUS == 0 {
			l.sets = append(l.sets, set.Name)
		}
	}
	objects, err := conn.Dump(Command(unix.NFT_MSG_GETOBJ), netlink.PutAttrString(PutNfgenmsg(nil, unix.NFPROTO_INET), unix.NFTA_OBJ_TABLE, Table))
	if err != nil {
		return listing{}, fmt.Errorf("nftables: dump objects: %w", err)
	}
	for _, reply := range objects {
		var table string
		var o object
		for kind, value := range reply.Attributes(SizeofNfgenmsg) {
			switch {
			case kind == unix.NFTA_OBJ_TABLE:
				table = unix.ByteSliceToString(value)
			case kind == unix.NFTA_OBJ_NAME:
				o.name = unix.ByteSliceToString(value)
			case kind == unix.NFTA_OBJ_TYPE && len(value) == 4:
				o.kind = binary.BigEndian.Uint32(value)
			}
		}
		if table == Table {
			l.objects = append(l.objects, o)
		}
	}
	if l.rules, err = TableRules(conn, unix.NFPROTO_INET, Table); err != nil {
		return listing{}, err
	}
	if l.maps, err = VerdictMaps(conn, unix.NFPROTO_INET, Table); err != nil {
		return listing{}, err
	}
	return l, nil
}

// withdrawal is the transaction Hold.Withdraw sends over l, none where l
// holds nothing of s's, ending in the table's deletion where last, s being
// the table's last holder, and l shows no flag but dormant and nothing but s's
func (s Scope) withdrawal(l listing, last bool) []Request {
	timeout := func(o object) bool {
		return o.kind == unix.NFT_OBJECT_CT_TIMEOUT && slices.Contains(s.Timeouts, o.name)
	}
	chains := slices.DeleteFunc(slices.Clone(l.chains), func(name string) bool { return !s.chain(name) })
	sets := slices.DeleteFunc(slices.Clone(l.sets), func(name string) bool { return !s.set(name) })
	objects := slices.DeleteFunc(slices.Clone(l.objects), func(o object) bool { return !timeout(o) })
	if len(chains) == 0 && len(sets) == 0 && len(objects) == 0 {
		return nil
	}
	var requests []Request
	// every chain is flushed before any is deleted, since a goto in one keeps another it names from being deleted
	for _, name := range chains {
		requests = append(requests, Chain{Table: Table, Name: name}.Flush(unix.NFPROTO_INET))
	}
	for _, name := range chains {
		if Holder(name, l.rules, l.maps, s.chain) == "" {
			requests = append(requests, Chain{Table: Table, Name: name}.Delete(unix.NFPROTO_INET))
		}
	}
	for _, name := range sets {
		requests = append(requests, Set{Table: Table, Name: name}.Delete(unix.NFPROTO_INET))
	}
	for _, o := range objects {
		requests = append(requests, Timeout{Table: Table, Name: o.name}.Delete(unix.NFPROTO_INET))
	}
	if last && l.flags&^unix.NFT_TABLE_F_DORMANT == 0 && len(chains) == len(l.chains) && len(sets) == len(l.sets) && len(objects) == len(l.objects) {
		requests = append(requests, DeleteTable(unix.NFPROTO_INET, Table))
	}
	return requests
}

// Holder names what goes to the chain named chain from a chain flushed does
// not take: "chain c" for a rule of chain c, by a goto, a jump or its vmap,
// "map m" for an element of the named map m, empty where nothing does.
// nf_tables refuses to delete a chain either holds.
func Holder(chain string, rules []Installed, maps []VerdictMap, flushed func(chain string) bool) string {
	goesTo := func(m VerdictMap) bool { return slices.Contains(m.Chains, chain) }
	for _, rule := range rules {
		if flushed(rule.Chain) {
			continue
		}
		vmap := slices.ContainsFunc(LookupSets(rule.Expressions), func(set string) bool {
			return slices.ContainsFunc(maps, func(m VerdictMap) bool { return m.Anonymous && m.Name == set && goesTo(m) })
		})
		if vmap || slices.Contains(VerdictChains(rule.Expressions), chain) {
			return "chain " + rule.Chain
		}
	}
	if i := slices.IndexFunc(maps, func(m VerdictMap) bool { return !m.Anonymous && goesTo(m) }); i >= 0 {
		return "map " + maps[i].Name
	}
	return ""
}

// rules dumps each chain's rules alone, which the kernel filters by the table
// and the chain the request names
func (c Contents) rules(conn *Conn, proto uint8) ([]Installed, error) {
	var out []Installed
	for _, chain := range c.Chains {
		replies, err := conn.Dump(Command(unix.NFT_MSG_GETRULE), netlink.PutAttrString(netlink.PutAttrString(PutNfgenmsg(nil, proto), unix.NFTA_RULE_TABLE, chain.Table), unix.NFTA_RULE_CHAIN, chain.Name))
		if err != nil {
			return nil, err
		}
		for _, reply := range replies {
			if table, installed := decodeInstalled(reply); table == chain.Table && installed.Chain == chain.Name {
				out = append(out, installed)
			}
		}
	}
	return out, nil
}

// ExpressionFault names how a rule's expressions as a dump lists them differ
// from written, empty where they do not, leaving out what a dump adds or spells
// otherwise and what a counter counts. An anonymous set's elements are read
// apart, by the name LookupSets gives.
func ExpressionFault(written [][]byte, held []byte) string {
	want, got := canonical(slices.Concat(written...)), canonical(held)
	if slices.Equal(want, got) {
		return ""
	}
	return fmt.Sprintf("its expressions read back as [%s], where [%s] were written", strings.Join(got, "; "), strings.Join(want, "; "))
}

// Line is a rule as its owner writes it: the comment it is written under, its
// expressions, and where its owner reads more of it, such as an anonymous
// set's elements, Then, which names how the rule held differs, empty where it
// does not
type Line struct {
	Spec        string
	Expressions [][]byte
	Then        func(held Installed) (string, error)
}

// ChainFault names how the chain named chain holds lines other than want,
// read from every chain's lines in held, empty where it does not: the count
// and each comment, then line by line its expressions and its Then, so the
// first line that differs is the one named
func ChainFault(chain string, want []Line, held []Installed) (string, error) {
	held = slices.DeleteFunc(slices.Clone(held), func(rule Installed) bool { return rule.Chain != chain })
	var wantSpecs, heldSpecs []string
	for _, rule := range want {
		wantSpecs = append(wantSpecs, rule.Spec)
	}
	for _, rule := range held {
		heldSpecs = append(heldSpecs, rule.Spec)
	}
	if !slices.Equal(heldSpecs, wantSpecs) {
		return fmt.Sprintf("its chain %s holds [%s], where [%s] was written", chain, strings.Join(heldSpecs, "; "), strings.Join(wantSpecs, "; ")), nil
	}
	// a line edited under the comment it was written with reads as its comment says, so each is read by what it does
	for i, rule := range want {
		if fault := ExpressionFault(rule.Expressions, held[i].Expressions); fault != "" {
			return fmt.Sprintf("its chain %s's line %s: %s", chain, rule.Spec, fault), nil
		}
		if rule.Then == nil {
			continue
		}
		if fault, err := rule.Then(held[i]); fault != "" || err != nil {
			return fault, err
		}
	}
	return "", nil
}

// LookupSets is the set each lookup of a dumped rule's expressions names, in order
func LookupSets(held []byte) []string {
	var out []string
	for _, element := range Nested(held) {
		name, data := expressionParts(element.Value)
		if name != "lookup" {
			continue
		}
		for _, field := range Nested(data) {
			if field.Kind == unix.NFTA_LOOKUP_SET {
				out = append(out, unix.ByteSliceToString(field.Value))
			}
		}
	}
	return out
}

// VerdictChains is the chain each verdict of a dumped rule's expressions sends
// a packet on to, a goto's or a jump's, in order
func VerdictChains(held []byte) []string {
	var out []string
	for _, element := range Nested(held) {
		name, data := expressionParts(element.Value)
		if name != "immediate" {
			continue
		}
		for _, field := range Nested(data) {
			if field.Kind != unix.NFTA_IMMEDIATE_DATA {
				continue
			}
			for _, inner := range Nested(field.Value) {
				if inner.Kind != unix.NFTA_DATA_VERDICT {
					continue
				}
				for _, verdict := range Nested(inner.Value) {
					if verdict.Kind == unix.NFTA_VERDICT_CHAIN {
						out = append(out, unix.ByteSliceToString(verdict.Value))
					}
				}
			}
		}
	}
	return out
}

func expressionParts(element []byte) (name string, data []byte) {
	for _, field := range Nested(element) {
		switch field.Kind {
		case unix.NFTA_EXPR_NAME:
			name = unix.ByteSliceToString(field.Value)
		case unix.NFTA_EXPR_DATA:
			data = field.Value
		}
	}
	return name, data
}

// canonical renders each expression of list as its name and its attributes
// by kind, the ones a dump spells otherwise left out or made alike
func canonical(list []byte) []string {
	var out []string
	for _, element := range Nested(list) {
		name, data := expressionParts(element.Value)
		var fields []string
		if name != "counter" {
			fields = canonicalAttributes(name, data)
		}
		out = append(out, name+" "+strings.Join(fields, " "))
	}
	return out
}

// bitwiseOp is NFTA_BITWISE_OP, which a dump writes for a bitwise expression
// written with none, and bitwiseBool its value for the mask and xor such an
// expression takes (nft_bitwise_init, nf_tables.h)
const bitwiseOp, bitwiseBool = 6, 0

func canonicalAttributes(name string, data []byte) []string {
	var out []string
	fields := Nested(data)
	// nft_nat_init takes an address range of one where only its first register
	// is given, and maps addresses wherever one is
	var natMin []byte
	for _, field := range fields {
		if name == "nat" && field.Kind == unix.NFTA_NAT_REG_ADDR_MIN {
			natMin = field.Value
		}
	}
	for _, field := range fields {
		kind := field.Kind
		value := field.Value
		switch {
		case name == "lookup" && kind == unix.NFTA_LOOKUP_SET_ID:
			continue
		case name == "lookup" && kind == unix.NFTA_LOOKUP_FLAGS && len(value) == 4 && binary.BigEndian.Uint32(value) == 0:
			continue
		case name == "bitwise" && kind == bitwiseOp && len(value) == 4 && binary.BigEndian.Uint32(value) == bitwiseBool:
			continue
		case name == "nat" && kind == unix.NFTA_NAT_REG_ADDR_MAX && natMin != nil && slices.Equal(value, natMin):
			continue
		case name == "nat" && kind == unix.NFTA_NAT_FLAGS && natMin != nil && len(value) == 4 && binary.BigEndian.Uint32(value) == unix.NF_NAT_RANGE_MAP_IPS:
			continue
		// nft_dynset_dump writes a timeout and flags of zero for a dynset written with neither
		case name == "dynset" && kind == unix.NFTA_DYNSET_TIMEOUT && len(value) == 8 && binary.BigEndian.Uint64(value) == 0:
			continue
		case name == "dynset" && kind == unix.NFTA_DYNSET_FLAGS && len(value) == 4 && binary.BigEndian.Uint32(value) == 0:
			continue
		case name == "dynset" && kind == unix.NFTA_DYNSET_EXPR:
			inner, attributes := expressionParts(value)
			out = append(out, fmt.Sprintf("%d{%s %s}", kind, inner, strings.Join(canonicalAttributes(inner, attributes), " ")))
			continue
		case name == "lookup" && kind == unix.NFTA_LOOKUP_SET:
			// the kernel completes the anonymous name a rule's own set is made under
			if value = []byte(unix.ByteSliceToString(value)); strings.HasPrefix(string(value), "__set") {
				value = []byte("__set")
			}
		case nested(name, kind) != "":
			out = append(out, fmt.Sprintf("%d{%s}", kind, strings.Join(canonicalAttributes(nested(name, kind), value), " ")))
			continue
		}
		out = append(out, fmt.Sprintf("%d=%x", kind, value))
	}
	slices.Sort(out)
	return out
}

// nested names what an attribute holding others holds in the expressions
// written here, data in a comparison's and an immediate's data and in a mask,
// and a verdict within data, and is empty for any other. A verdict's chain
// shares its kind with data's verdict, so it is read as a value.
func nested(name string, kind uint16) string {
	switch {
	case name == "cmp" && kind == unix.NFTA_CMP_DATA, name == "immediate" && kind == unix.NFTA_IMMEDIATE_DATA,
		name == "bitwise" && (kind == unix.NFTA_BITWISE_MASK || kind == unix.NFTA_BITWISE_XOR):
		return "data"
	case name == "data" && kind == unix.NFTA_DATA_VERDICT:
		return "verdict"
	}
	return ""
}

// DecodeChain reads where a chain lives and how it is hooked. A chain with no
// hook is a regular chain, reached by a jump rather than by the packet path,
// so the absent hook reads as NoHook.
func DecodeChain(message netlink.Message) (table, chain, kind string, hook uint32, priority int32) {
	hook = NoHook
	for attribute, value := range message.Attributes(SizeofNfgenmsg) {
		switch attribute {
		case unix.NFTA_CHAIN_TABLE:
			table = unix.ByteSliceToString(value)
		case unix.NFTA_CHAIN_NAME:
			chain = unix.ByteSliceToString(value)
		case unix.NFTA_CHAIN_TYPE:
			kind = unix.ByteSliceToString(value)
		case unix.NFTA_CHAIN_HOOK:
			for _, field := range Nested(value) {
				if len(field.Value) != 4 {
					continue
				}
				switch field.Kind {
				case unix.NFTA_HOOK_HOOKNUM:
					hook = binary.BigEndian.Uint32(field.Value)
				case unix.NFTA_HOOK_PRIORITY:
					priority = int32(binary.BigEndian.Uint32(field.Value))
				}
			}
		}
	}
	return table, chain, kind, hook, priority
}

// DecodeRule reads where a rule lives, the comment its owner wrote, and the
// counter, counted where the rule keeps one
func DecodeRule(message netlink.Message) (table, chain, spec string, packets, bytes uint64, counted bool) {
	for kind, value := range message.Attributes(SizeofNfgenmsg) {
		switch kind {
		case unix.NFTA_RULE_TABLE:
			table = unix.ByteSliceToString(value)
		case unix.NFTA_RULE_CHAIN:
			chain = unix.ByteSliceToString(value)
		case unix.NFTA_RULE_USERDATA:
			spec = comment(udataComment, value)
		case unix.NFTA_RULE_EXPRESSIONS:
			packets, bytes, counted = counters(value)
		}
	}
	return table, chain, spec, packets, bytes, counted
}

// comment is the comment of type kind out of the libnftnl userdata format: a
// sequence of type, length and value triples, of which Rule and Set.Create
// write exactly one
func comment(kind byte, userdata []byte) string {
	for len(userdata) >= 2 {
		held, length := userdata[0], int(userdata[1])
		if len(userdata) < 2+length {
			return ""
		}
		if held == kind {
			return strings.TrimRight(string(userdata[2:2+length]), "\x00")
		}
		userdata = userdata[2+length:]
	}
	return ""
}

// counters walks the expression list for a counter, counted where it finds
// one. In a nat chain the count is of flows rather than of packets: such a
// chain is evaluated once per connection, when conntrack first sees it.
func counters(expressions []byte) (packets, bytes uint64, counted bool) {
	for _, element := range Nested(expressions) {
		if element.Kind != unix.NFTA_LIST_ELEM {
			continue
		}
		var name string
		var data []byte
		for _, field := range Nested(element.Value) {
			switch field.Kind {
			case unix.NFTA_EXPR_NAME:
				name = unix.ByteSliceToString(field.Value)
			case unix.NFTA_EXPR_DATA:
				data = field.Value
			}
		}
		if name != "counter" {
			continue
		}
		counted = true
		for _, field := range Nested(data) {
			if len(field.Value) != 8 {
				continue
			}
			switch field.Kind {
			case unix.NFTA_COUNTER_BYTES:
				bytes = binary.BigEndian.Uint64(field.Value)
			case unix.NFTA_COUNTER_PACKETS:
				packets = binary.BigEndian.Uint64(field.Value)
			}
		}
	}
	return packets, bytes, counted
}

// userdata is the comment of type kind in the format libnftnl reads, so `nft
// list ruleset` prints it beside the rule or the set
func userdata(kind byte, text string) []byte {
	value := append([]byte(text), 0)
	return append([]byte{kind, byte(len(value))}, value...)
}

// DeviceName refuses a name too long to be a device's. The kernel caps one at
// IFNAMSIZ-1, and a comparison of 16 bytes with no terminator equals no
// interface register: the rule would install and then match nothing, or
// through a "not" everything.
func DeviceName(name string) error {
	if len(name) >= unix.IFNAMSIZ {
		return fmt.Errorf("nftables: interface %q is %d bytes, and a device name is at most %d", name, len(name), unix.IFNAMSIZ-1)
	}
	return nil
}

// MetaCompare loads one interface name and compares it, over the full
// IFNAMSIZ the kernel pads it to. A shorter comparison would match every
// device whose name starts the same way.
func MetaCompare(key uint32, op int, name string) [][]byte {
	return MetaCompareValue(key, op, InterfaceName(name))
}

// InterfaceName is name as the kernel loads one, padded to IFNAMSIZ
func InterfaceName(name string) []byte {
	padded := make([]byte, unix.IFNAMSIZ)
	copy(padded, name)
	return padded
}

func MetaCompareValue(key uint32, op int, value []byte) [][]byte {
	return [][]byte{MetaLoad(key), Expression("cmp", Compare(op, value))}
}

// MetaLoad loads the packet's meta key into register 1. NFT_META_MARK and
// NFT_META_IIF load host order words, an interface name its IFNAMSIZ bytes.
func MetaLoad(key uint32) []byte {
	meta := PutAttrBE32(nil, unix.NFTA_META_KEY, key)
	meta = PutAttrBE32(meta, unix.NFTA_META_DREG, unix.NFT_REG_1)
	return Expression("meta", meta)
}

func SourcePrefix(prefix netip.Prefix) [][]byte {
	return addressPrefix(SourceLoad, prefix)
}

func DestinationPrefix(prefix netip.Prefix) [][]byte {
	return addressPrefix(DestinationLoad, prefix)
}

// addressPrefix matches the address load reads against prefix
func addressPrefix(load func(proto uint8) []byte, prefix netip.Prefix) [][]byte {
	proto := uint8(unix.NFPROTO_IPV6)
	if prefix.Addr().Is4() {
		proto = unix.NFPROTO_IPV4
	}
	out := [][]byte{load(proto)}
	if mask := prefixMask(prefix); prefix.Bits() < len(mask)*8 {
		out = append(out, Bitwise(mask))
	}
	return append(out, Expression("cmp", Compare(unix.NFT_CMP_EQ, netlink.AddressBytes(prefix.Masked().Addr()))))
}

// SourceLoad loads a packet's source address into register 1, of the
// nf_tables family proto
func SourceLoad(proto uint8) []byte {
	if proto == unix.NFPROTO_IPV4 {
		return NetworkLoad(ipv4SourceOffset, net.IPv4len)
	}
	return NetworkLoad(ipv6SourceOffset, net.IPv6len)
}

// DestinationLoad loads a packet's destination address into register 1, of
// the nf_tables family proto
func DestinationLoad(proto uint8) []byte {
	if proto == unix.NFPROTO_IPV4 {
		return NetworkLoad(ipv4DestinationOffset, net.IPv4len)
	}
	return NetworkLoad(ipv6DestinationOffset, net.IPv6len)
}

// FibDestinationType loads the type the routing tables give a packet's
// destination address into register 1, an RTN_ value as a host order word,
// RTN_LOCAL for an address of the host's own
func FibDestinationType() []byte {
	fib := PutAttrBE32(nil, unix.NFTA_FIB_DREG, unix.NFT_REG_1)
	fib = PutAttrBE32(fib, unix.NFTA_FIB_RESULT, unix.NFT_FIB_RESULT_ADDRTYPE)
	fib = PutAttrBE32(fib, unix.NFTA_FIB_FLAGS, unix.NFTA_FIB_F_DADDR)
	return Expression("fib", fib)
}

func NetworkLoad(offset, length uint32) []byte {
	return payloadLoad(unix.NFT_PAYLOAD_NETWORK_HEADER, offset, length)
}

func TransportLoad(offset, length uint32) []byte {
	return payloadLoad(unix.NFT_PAYLOAD_TRANSPORT_HEADER, offset, length)
}

func payloadLoad(base, offset, length uint32) []byte {
	load := PutAttrBE32(nil, unix.NFTA_PAYLOAD_DREG, unix.NFT_REG_1)
	load = PutAttrBE32(load, unix.NFTA_PAYLOAD_BASE, base)
	load = PutAttrBE32(load, unix.NFTA_PAYLOAD_OFFSET, offset)
	load = PutAttrBE32(load, unix.NFTA_PAYLOAD_LEN, length)
	return Expression("payload", load)
}

// Bitwise masks register 1 by mask, of the register's length
func Bitwise(mask []byte) []byte {
	bitwise := PutAttrBE32(nil, unix.NFTA_BITWISE_SREG, unix.NFT_REG_1)
	bitwise = PutAttrBE32(bitwise, unix.NFTA_BITWISE_DREG, unix.NFT_REG_1)
	bitwise = PutAttrBE32(bitwise, unix.NFTA_BITWISE_LEN, uint32(len(mask)))
	bitwise = netlink.PutAttr(bitwise, unix.NFTA_BITWISE_MASK|unix.NLA_F_NESTED, netlink.PutAttr(nil, unix.NFTA_DATA_VALUE, mask))
	bitwise = netlink.PutAttr(bitwise, unix.NFTA_BITWISE_XOR|unix.NLA_F_NESTED, netlink.PutAttr(nil, unix.NFTA_DATA_VALUE, make([]byte, len(mask))))
	return Expression("bitwise", bitwise)
}

// CTMatch takes a packet whose connection's key, NFT_CT_STATE or
// NFT_CT_STATUS, has a bit of mask set for NFT_CMP_NEQ, or none of them for
// NFT_CMP_EQ. Both keys are host order words.
func CTMatch(key, mask uint32, op int) [][]byte {
	return [][]byte{
		CTLoad(key),
		Bitwise(binary.NativeEndian.AppendUint32(nil, mask)),
		Expression("cmp", Compare(op, make([]byte, 4))),
	}
}

// CTLoad loads the key of the packet's connection into register 1. A packet
// with no connection ends the rule. NFT_CT_DIRECTION and NFT_CT_PROTOCOL
// load one byte, the direction CTOriginal or CTReply and the transport
// protocol.
func CTLoad(key uint32) []byte {
	ct := PutAttrBE32(nil, unix.NFTA_CT_DREG, unix.NFT_REG_1)
	ct = PutAttrBE32(ct, unix.NFTA_CT_KEY, key)
	return Expression("ct", ct)
}

// CTReplyMatch goes on only for a packet of its connection's reply direction,
// nft's `ct direction reply`
func CTReplyMatch() [][]byte {
	return [][]byte{CTLoad(unix.NFT_CT_DIRECTION), Expression("cmp", Compare(unix.NFT_CMP_EQ, []byte{CTReply}))}
}

// CTLoadDirection loads the key of one direction of the packet's connection,
// CTOriginal or CTReply, which the kernel requires of an address or a port
// (nft_ct.c, nft_ct_get_init). NFT_CT_PROTO_DST loads the port in network
// order.
func CTLoadDirection(key uint32, direction uint8) []byte {
	ct := PutAttrBE32(nil, unix.NFTA_CT_DREG, unix.NFT_REG_1)
	ct = PutAttrBE32(ct, unix.NFTA_CT_KEY, key)
	ct = netlink.PutAttr(ct, unix.NFTA_CT_DIRECTION, []byte{direction})
	return Expression("ct", ct)
}

// Lookup goes on only while set holds the key register 1 does, or with
// invert only while it does not. It names the set by name and ID, so it
// finds one made earlier in its own transaction, an anonymous one among them.
func Lookup(set Set, invert bool) []byte {
	lookup := netlink.PutAttrString(nil, unix.NFTA_LOOKUP_SET, set.Name)
	lookup = PutAttrBE32(lookup, unix.NFTA_LOOKUP_SREG, unix.NFT_REG_1)
	lookup = PutAttrBE32(lookup, unix.NFTA_LOOKUP_SET_ID, set.ID)
	if invert {
		lookup = PutAttrBE32(lookup, unix.NFTA_LOOKUP_FLAGS, unix.NFT_LOOKUP_F_INV)
	}
	return Expression("lookup", lookup)
}

// Verdict ends the chain for a packet with code, Accept, Drop or Return
func Verdict(code uint32) []byte {
	data := netlink.PutAttr(nil, unix.NFTA_DATA_VERDICT|unix.NLA_F_NESTED, PutAttrBE32(nil, unix.NFTA_VERDICT_CODE, code))
	immediate := PutAttrBE32(nil, unix.NFTA_IMMEDIATE_DREG, unix.NFT_REG_VERDICT)
	immediate = netlink.PutAttr(immediate, unix.NFTA_IMMEDIATE_DATA|unix.NLA_F_NESTED, data)
	return Expression("immediate", immediate)
}

// Goto sends the packet on to the regular chain named chain, at whose end the
// base chain's policy decides it, as at the base chain's own end
func Goto(chain string) []byte {
	verdict := PutAttrBE32(nil, unix.NFTA_VERDICT_CODE, gotoCode)
	verdict = netlink.PutAttrString(verdict, unix.NFTA_VERDICT_CHAIN, chain)
	immediate := PutAttrBE32(nil, unix.NFTA_IMMEDIATE_DREG, unix.NFT_REG_VERDICT)
	immediate = netlink.PutAttr(immediate, unix.NFTA_IMMEDIATE_DATA|unix.NLA_F_NESTED, netlink.PutAttr(nil, unix.NFTA_DATA_VERDICT|unix.NLA_F_NESTED, verdict))
	return Expression("immediate", immediate)
}

// NFProto tests the packet's family, the nf_tables family an inet chain saw
// it in. Unlike nft, which adds the test itself, the raw encoder spells it, or
// an IPv4 match in an inet chain would read an IPv6 header's bytes.
func NFProto(proto uint8) [][]byte {
	return MetaCompareValue(unix.NFT_META_NFPROTO, unix.NFT_CMP_EQ, []byte{proto})
}

// CountedDrop counts the packet and drops it
func CountedDrop() [][]byte {
	return [][]byte{Expression("counter", nil), Verdict(Drop)}
}

// ObjectReference applies the object of objType named name to the packet
func ObjectReference(objType uint32, name string) []byte {
	objref := PutAttrBE32(nil, unix.NFTA_OBJREF_IMM_TYPE, objType)
	objref = netlink.PutAttrString(objref, unix.NFTA_OBJREF_IMM_NAME, name)
	return Expression("objref", objref)
}

// ConnectionsOver adds the key register 1 holds to the named set, counting the
// connections each key's packets open, and goes on only while that count is
// over limit. A full set adds no key, which ends the rule as a count within
// the limit does.
func ConnectionsOver(set string, limit uint32) []byte {
	connlimit := PutAttrBE32(nil, connlimitCount, limit)
	connlimit = PutAttrBE32(connlimit, connlimitFlags, connlimitInvert)
	dynset := PutAttrBE32(nil, unix.NFTA_DYNSET_SREG_KEY, unix.NFT_REG_1)
	dynset = PutAttrBE32(dynset, unix.NFTA_DYNSET_OP, unix.NFT_DYNSET_OP_ADD)
	dynset = netlink.PutAttrString(dynset, unix.NFTA_DYNSET_SET_NAME, set)
	dynset = netlink.PutAttr(dynset, unix.NFTA_DYNSET_EXPR|unix.NLA_F_NESTED, expressionBody("connlimit", connlimit))
	return Expression("dynset", dynset)
}

// RejectICMPX answers a packet with a destination unreachable and drops it,
// code being an NFT_REJECT_ICMPX_ value, which the kernel gives as its own
// family's code, ICMP's for an IPv4 packet and ICMPv6's for an IPv6 one
// (nft_reject.c, nft_reject_icmp_code and nft_reject_icmpv6_code). nft lists
// it with no family named, as it can a rule that tests none.
func RejectICMPX(code uint8) []byte {
	reject := PutAttrBE32(nil, unix.NFTA_REJECT_TYPE, unix.NFT_REJECT_ICMPX_UNREACH)
	reject = netlink.PutAttr(reject, unix.NFTA_REJECT_ICMP_CODE, []byte{code})
	return Expression("reject", reject)
}

// SourceNAT translates a connection's source to the address register 1 holds,
// of the nf_tables family proto
func SourceNAT(proto uint8) []byte {
	nat := PutAttrBE32(nil, unix.NFTA_NAT_TYPE, unix.NFT_NAT_SNAT)
	nat = PutAttrBE32(nat, unix.NFTA_NAT_FAMILY, uint32(proto))
	nat = PutAttrBE32(nat, unix.NFTA_NAT_REG_ADDR_MIN, unix.NFT_REG_1)
	return Expression("nat", nat)
}

func prefixMask(prefix netip.Prefix) []byte {
	length := net.IPv6len
	if prefix.Addr().Is4() {
		length = net.IPv4len
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

func Compare(op int, value []byte) []byte {
	body := PutAttrBE32(nil, unix.NFTA_CMP_SREG, unix.NFT_REG_1)
	body = PutAttrBE32(body, unix.NFTA_CMP_OP, uint32(op))
	return netlink.PutAttr(body, unix.NFTA_CMP_DATA|unix.NLA_F_NESTED, netlink.PutAttr(nil, unix.NFTA_DATA_VALUE, value))
}

// Expression emits the data attribute even when empty, as libnftnl does, so
// an expression carrying no parameters still reads as one
func Expression(name string, data []byte) []byte {
	return netlink.PutAttr(nil, unix.NFTA_LIST_ELEM|unix.NLA_F_NESTED, expressionBody(name, data))
}

// expressionBody is an expression without the list element a rule wraps it
// in, as dynset takes the one it attaches to each key
func expressionBody(name string, data []byte) []byte {
	body := netlink.PutAttrString(nil, unix.NFTA_EXPR_NAME, name)
	return netlink.PutAttr(body, unix.NFTA_EXPR_DATA|unix.NLA_F_NESTED, data)
}

// Conn is one NETLINK_NETFILTER socket used for synchronous request and reply.
// Its owner's one goroutine is its only caller, so it needs no locking, and
// nothing subscribes to a notification group, so an unsolicited message can
// never arrive on it.
type Conn struct {
	link *netlink.Conn
}

// Dial opens a socket whose waits end at replyTimeout. Every message in a
// transaction is acknowledged, and the kernel queues all of those acks while
// this process is still inside its one send, with nothing draining them. The
// default receive buffer holds a few hundred, which a few hundred rules would
// exceed, and the overflow arrives as an ENOBUFS that explains nothing.
func Dial() (*Conn, error) {
	link, err := netlink.Dial(unix.NETLINK_NETFILTER, netlink.Options{Timeout: replyTimeout, ReceiveBuffer: receiveBuffer})
	if err != nil {
		return nil, err
	}
	return &Conn{link: link}, nil
}

func (c *Conn) Close() error { return c.link.Close() }

// Request is one message inside a transaction
type Request struct {
	Kind  uint16
	Flags uint16
	Body  []byte
}

func Command(command int) uint16 {
	return uint16(unix.NFNL_SUBSYS_NFTABLES)<<8 | uint16(command)
}

// fitSendBuffer grows the socket's send buffer to hold a batch of size bytes,
// since netlink refuses a message longer than the buffer whole (EMSGSIZE), as
// a set of thousands of elements is. SO_SNDBUFFORCE passes net.core.wmem_max
// where the process holds CAP_NET_ADMIN, as nft's own socket does.
func (c *Conn) fitSendBuffer(size int) error {
	// the kernel reports the buffer doubled, its own overhead included
	held, err := unix.GetsockoptInt(c.link.Fd(), unix.SOL_SOCKET, unix.SO_SNDBUF)
	if err != nil || held/2 >= size {
		return err
	}
	if err := unix.SetsockoptInt(c.link.Fd(), unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, size); err == nil {
		return nil
	}
	return unix.SetsockoptInt(c.link.Fd(), unix.SOL_SOCKET, unix.SO_SNDBUF, size)
}

// Batch sends one transaction and waits for the kernel to acknowledge every
// message in it. Everything between the batch markers commits together or not
// at all, so a failure leaves the host holding exactly what it held before.
//
// A failure inside the batch is reported against the message that caused it,
// and a failure of the commit itself against the batch marker, so any nonzero
// error in the range this call owns ends it. Acknowledgments left in the
// socket by an earlier call carry earlier sequence numbers and are ignored
// rather than mistaken for this call's.
func (c *Conn) Batch(requests []Request) error {
	if len(requests) == 0 {
		return nil
	}
	marker := putNfgenmsgSubsys(nil, unix.NFPROTO_UNSPEC)
	pid := c.link.Pid()
	begin := c.link.Next()
	var buf []byte
	buf = netlink.AppendMessage(buf, unix.NFNL_MSG_BATCH_BEGIN, unix.NLM_F_REQUEST, begin, pid, marker)
	expected := make(map[uint32]bool, len(requests))
	first, last := begin, begin
	for _, request := range requests {
		seq := c.link.Next()
		expected[seq] = true
		last = seq
		buf = netlink.AppendMessage(buf, request.Kind, request.Flags|unix.NLM_F_REQUEST|unix.NLM_F_ACK, seq, pid, request.Body)
	}
	end := c.link.Next()
	last = end
	buf = netlink.AppendMessage(buf, unix.NFNL_MSG_BATCH_END, unix.NLM_F_REQUEST, end, pid, marker)
	if err := c.fitSendBuffer(len(buf)); err != nil {
		return err
	}
	if err := c.link.Send(buf); err != nil {
		return err
	}
	for len(expected) > 0 {
		messages, err := c.link.Receive()
		if err != nil {
			return err
		}
		for _, message := range messages {
			// subtracted rather than compared, so a sequence number that wraps
			// inside one transaction narrows the window rather than inverting it
			if message.Pid != pid || message.Seq-first > last-first {
				continue
			}
			if message.Kind != unix.NLMSG_ERROR {
				continue
			}
			if len(message.Data) < 4 {
				return errors.New("nftables: truncated netlink error")
			}
			if code := int32(binary.NativeEndian.Uint32(message.Data)); code != 0 {
				return unix.Errno(-code)
			}
			delete(expected, message.Seq)
		}
	}
	return nil
}

// Dump reads every object of kind body names. A dump the kernel flags
// interrupted is not returned: it is asked again, and once the leaf's bounded
// asks are spent it fails with netlink.ErrDumpInterrupted.
func (c *Conn) Dump(kind uint16, body []byte) ([]netlink.Message, error) {
	return c.link.Execute(kind, unix.NLM_F_DUMP, body)
}

// Attribute's Kind has NLA_F_NESTED and NLA_F_NET_BYTEORDER masked off
type Attribute struct {
	Kind  uint16
	Value []byte
}

// Nested is the attributes in buf, in order
func Nested(buf []byte) []Attribute {
	var out []Attribute
	for kind, value := range netlink.Attributes(buf) {
		out = append(out, Attribute{Kind: kind, Value: value})
	}
	return out
}

func PutNfgenmsg(buf []byte, family uint8) []byte {
	return append(buf, family, nfnetlinkV0, 0, 0)
}

// putNfgenmsgSubsys writes struct nfgenmsg for a batch marker, whose res_id
// names the subsystem the transaction belongs to. It is big endian, unlike the
// netlink header around it.
func putNfgenmsgSubsys(buf []byte, family uint8) []byte {
	buf = append(buf, family, nfnetlinkV0, 0, 0)
	binary.BigEndian.PutUint16(buf[len(buf)-2:], uint16(unix.NFNL_SUBSYS_NFTABLES))
	return buf
}

// PutAttrBE32 writes a 32-bit attribute in network byte order, which is how
// nf_tables carries every number in an NFTA attribute
func PutAttrBE32(buf []byte, kind uint16, value uint32) []byte {
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], value)
	return netlink.PutAttr(buf, kind, raw[:])
}
