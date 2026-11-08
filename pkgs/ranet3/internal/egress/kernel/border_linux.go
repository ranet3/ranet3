// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/nftables"
)

// borderTable is the antispoof filter's linux backend: the antispoof chain at
// prerouting, the entry chain at postrouting and their sets, in
// nftables.Table. An inet chain sees both families, so every rule matching an
// address tests the family first (nftables.NFProto).
type borderTable struct {
	conn    *nftables.Conn
	monitor *nftables.Monitor
}

// Filters reports that the filter runs on every node here, its entry chain
// with overlay written or not
func Filters(*egress.Border) bool { return true }

// RefuseBorder refuses nothing, since nftables writes every interface name the
// loader takes
func RefuseBorder(*egress.Border) error { return nil }

// newBorderBackend opens the netlink socket and the monitor of the filter's
// chains and sets, with overlay written or not, since the entry chain runs on
// every node here
func newBorderBackend(*egress.Border, egress.BorderRuntime) (borderBackend, error) {
	conn, err := nftables.Dial()
	if err != nil {
		return nil, err
	}
	monitor, err := nftables.OpenMonitor(conn, borderScope)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return &borderTable{conn: conn, monitor: monitor}, nil
}

func (b *borderTable) Close() error { return errors.Join(b.monitor.Close(), b.conn.Close()) }

// Leave is Close, since the chains and sets are all the backend holds for the
// filter
func (b *borderTable) Leave() error { return b.Close() }

func (b *borderTable) Changed() <-chan struct{} { return b.monitor.Changed() }

func (b *borderTable) Missed() <-chan struct{} { return b.monitor.Missed() }

func (b *borderTable) where(cfg *egress.Border) string {
	if cfg == nil {
		return fmt.Sprintf("nftables table inet %s chain %s", nftables.Table, EntryChain)
	}
	return fmt.Sprintf("nftables table inet %s chains %s and %s", nftables.Table, BorderChain, EntryChain)
}

// writes every rule, each a line of its chain
func (b *borderTable) writes(BorderRule) bool { return true }

// holds every set, each a set its chains read
func (b *borderTable) holds(string) bool { return true }

// sweep is the default, since the monitor wakes a pass for another writer's
// change
func (b *borderTable) sweep() time.Duration { return 0 }

// wildcards is true, since nft matches iifname "wl*" by the bytes before the *
func (b *borderTable) wildcards() bool { return true }

func (b *borderTable) chain(name string) egress.BorderChainReading {
	hook, priority := "prerouting", rawPriority
	if name == EntryChain {
		hook, priority = "postrouting", entryPriority
	}
	return egress.BorderChainReading{Name: name, Hook: hook, Priority: &priority}
}

func (b *borderTable) readings(sets borderSets) []egress.BorderSetReading { return sets.readings() }

func (b *borderTable) Rules(rules []BorderRule, sets borderSets) (chainReadback, error) {
	return readBorder(b.conn, rules, sets)
}

// Read dumps through a socket of its own, so the run goroutine's stays with
// its one user, and names each line by its comment alone
func (b *borderTable) Read([]BorderRule) (chainReadback, error) {
	conn, err := nftables.Dial()
	if err != nil {
		return chainReadback{}, err
	}
	defer conn.Close()
	return readBorder(conn, nil, nil)
}

// readBorder reads the filter's chains and sets back, each chain's lines
// against rules and each set's elements against sets where it is not nil
func readBorder(conn *nftables.Conn, rules []BorderRule, sets borderSets) (chainReadback, error) {
	contents := borderContents
	if sets != nil {
		contents.Elements = sets.elements()
	}
	read, err := readBorderContents(conn, contents)
	if err != nil {
		return chainReadback{}, err
	}
	out := chainReadback{fault: read.Fault, remake: read.Remake(), held: read.Held}
	for _, rule := range read.Rules {
		out.rules = append(out.rules, Installed{Spec: rule.Spec, Chain: rule.Chain, Counted: rule.Counted, Packets: rule.Packets, Bytes: rule.Bytes})
	}
	if rules != nil && out.fault == "" {
		if out.fault, err = borderRulesFault(rules, read.Rules); err != nil {
			return chainReadback{}, err
		}
	}
	return out, nil
}

func readBorderContents(conn *nftables.Conn, contents nftables.Contents) (nftables.Readback, error) {
	tables, err := nftables.Tables(conn, nftables.Table)
	if err != nil {
		return nftables.Readback{}, err
	}
	read, err := contents.Read(conn, tables, unix.NFPROTO_INET)
	if err != nil {
		return nftables.Readback{}, fmt.Errorf("egress: read table inet %s: %w", nftables.Table, err)
	}
	return read, nil
}

// borderRulesFault names how either chain holds lines other than rules write,
// empty where neither does
func borderRulesFault(rules []BorderRule, held []nftables.Installed) (string, error) {
	for _, chain := range []nftables.Chain{prerouting, entry} {
		var want []nftables.Line
		for _, rule := range rules {
			if rule.Chain() != chain.Name {
				continue
			}
			line, err := borderLine(rule)
			if err != nil {
				return "", err
			}
			want = append(want, line)
		}
		if fault, err := nftables.ChainFault(chain.Name, want, held); fault != "" || err != nil {
			return fault, err
		}
	}
	return "", nil
}

// prerouting is the antispoof chain
var prerouting = nftables.Chain{Table: nftables.Table, Name: BorderChain, Type: "filter", Hook: unix.NF_INET_PRE_ROUTING, Priority: rawPriority}

// entry is the entry chain
var entry = nftables.Chain{Table: nftables.Table, Name: EntryChain, Type: "filter", Hook: unix.NF_INET_POST_ROUTING, Priority: entryPriority}

// borderNamed is the filter's sets, the IDs naming them to the rules of the
// transaction that makes them
var borderNamed = []nftables.Set{
	{Table: nftables.Table, Name: carvedSet + "4", ID: 1, KeyType: nftables.TypeIPv4Addr, KeyLen: 4, Flags: unix.NFT_SET_INTERVAL},
	{Table: nftables.Table, Name: carvedSet + "6", ID: 2, KeyType: nftables.TypeIPv6Addr, KeyLen: 16, Flags: unix.NFT_SET_INTERVAL},
	{Table: nftables.Table, Name: ownedSet + "4", ID: 3, KeyType: nftables.TypeIPv4Addr, KeyLen: 4, Flags: unix.NFT_SET_INTERVAL},
	{Table: nftables.Table, Name: ownedSet + "6", ID: 4, KeyType: nftables.TypeIPv6Addr, KeyLen: 16, Flags: unix.NFT_SET_INTERVAL},
	{Table: nftables.Table, Name: noneSet + "4", ID: 5, KeyType: nftables.TypeIPv4Addr, KeyLen: 4, Flags: unix.NFT_SET_INTERVAL},
	{Table: nftables.Table, Name: noneSet + "6", ID: 6, KeyType: nftables.TypeIPv6Addr, KeyLen: 16, Flags: unix.NFT_SET_INTERVAL},
}

// borderContents is the filter's chains and sets as a readback reads them
var borderContents = nftables.Contents{Chains: []nftables.Chain{prerouting, entry}, Sets: borderNamed}

var borderScope = borderContents.Scope()

func borderSet(name string) nftables.Set {
	return borderNamed[slices.IndexFunc(borderNamed, func(set nftables.Set) bool { return set.Name == name })]
}

// elements is each set's elements for s, an empty set for one s leaves out
func (s borderSets) elements() map[string][]nftables.Interval {
	out := make(map[string][]nftables.Interval, len(borderNamed))
	for _, set := range borderNamed {
		out[set.Name] = intervals(s[set.Name])
	}
	return out
}

// intervals is ranges as a set's keys, the one place a range becomes bytes
func intervals(ranges []egress.Range) []nftables.Interval {
	out := make([]nftables.Interval, 0, len(ranges))
	for _, r := range ranges {
		out = append(out, nftables.Interval{First: nftables.AddressBytes(r.First), Last: nftables.AddressBytes(r.Last)})
	}
	return out
}

// Apply writes the filter's chains and sets in one transaction, so no packet
// meets half a chain or a set half filled, reading them first for each that
// nf_tables will not change in place, which the transaction deletes and makes
// again
func (b *borderTable) Apply(rules []BorderRule, sets borderSets) error {
	read, err := readBorderContents(b.conn, borderContents)
	if err != nil {
		return err
	}
	requests, err := borderBatch(rules, sets, read.Stale, read.Chains)
	if err != nil {
		return err
	}
	return b.conn.Batch(requests)
}

// borderBatch is the transaction Apply sends over the chains the table holds,
// held, and those of the filter's chains and sets stale names: the table with
// no owner flag, so it outlives this process, the chains the rules sit in made
// and emptied, a chain of the filter's no rule sits in deleted where it is
// held, the sets made, emptied and filled, and the rules
func borderBatch(rules []BorderRule, sets borderSets, stale nftables.Contents, held []string) ([]nftables.Request, error) {
	var written nftables.Contents
	for _, chain := range borderContents.Chains {
		switch {
		case slices.ContainsFunc(rules, func(rule BorderRule) bool { return rule.Chain() == chain.Name }):
			written.Chains = append(written.Chains, chain)
		case slices.Contains(held, chain.Name) && !slices.Contains(stale.Chains, chain):
			stale.Chains = append(stale.Chains, chain)
		}
	}
	requests := written.Rewrite(unix.NFPROTO_INET, stale, nil)
	elements := sets.elements()
	for _, set := range borderNamed {
		replaced, err := set.Replace(unix.NFPROTO_INET, elements[set.Name])
		if err != nil {
			return nil, err
		}
		requests = append(requests, replaced...)
	}
	for _, rule := range rules {
		request, err := newBorderRule(rule)
		if err != nil {
			return nil, err
		}
		requests = append(requests, request)
	}
	return requests, nil
}

// Fill sends the sets' changed ranges in one transaction, which nf_tables
// commits whole, so a lookup meets the old elements or the new
func (b *borderTable) Fill(_ []BorderRule, was, sets borderSets) error {
	requests, err := fillBatch(was, sets)
	if err != nil {
		return err
	}
	return b.conn.Batch(requests)
}

// fillBatch is the transaction Fill sends: each set sets names moved from what
// was gives it by the ranges that differ
func fillBatch(was, sets borderSets) ([]nftables.Request, error) {
	var requests []nftables.Request
	for _, set := range borderNamed {
		ranges, named := sets[set.Name]
		if !named {
			continue
		}
		moved, err := set.Update(unix.NFPROTO_INET, intervals(was[set.Name]), intervals(ranges))
		if err != nil {
			return nil, err
		}
		requests = append(requests, moved...)
	}
	return requests, nil
}

// Withdraw removes the filter's chains and sets, and the table with them
// where nothing else is in it
func (b *borderTable) Withdraw() (bool, error) { return nftables.Withdraw(b.conn, borderScope) }

func newBorderRule(rule BorderRule) (nftables.Request, error) {
	line, err := borderLine(rule)
	if err != nil {
		return nftables.Request{}, err
	}
	chain := prerouting
	if rule.Chain() == EntryChain {
		chain = entry
	}
	return chain.Rule(unix.NFPROTO_INET, line.Spec, line.Expressions)
}

// borderLine counts only a drop, since a counter on an accept or a return
// would be an update on every packet it passes
func borderLine(rule BorderRule) (nftables.Line, error) {
	proto := uint8(unix.NFPROTO_IPV4)
	if rule.Family() == "ipv6" {
		proto = unix.NFPROTO_IPV6
	}
	accept, ret := nftables.Verdict(nftables.Accept), nftables.Verdict(nftables.Return)
	var expressions [][]byte
	switch rule.Class {
	case BorderInside, BorderCarveOut:
		if err := nftables.DeviceName(rule.Device); err != nil {
			return nftables.Line{}, err
		}
		expressions = nftables.MetaCompare(unix.NFT_META_IIFNAME, unix.NFT_CMP_EQ, rule.Device)
		if rule.Class == BorderCarveOut {
			expressions = slices.Concat(expressions, nftables.NFProto(proto), nftables.SourcePrefix(rule.Source))
		}
		expressions = append(expressions, accept)
	case BorderExempt:
		expressions = slices.Concat(interfaceMatch(rule.Device), nftables.NFProto(proto), nftables.SourcePrefix(rule.Source), [][]byte{accept})
	case BorderCarved:
		expressions = slices.Concat(nftables.NFProto(proto), [][]byte{nftables.SourceLoad(proto), nftables.Lookup(borderSet(rule.Set()), false)}, nftables.CountedDrop())
	case BorderSource:
		expressions = slices.Concat(nftables.NFProto(proto), nftables.SourcePrefix(rule.Source), nftables.CountedDrop())
	case EntryOutside:
		if err := nftables.DeviceName(rule.Device); err != nil {
			return nftables.Line{}, err
		}
		expressions = append(nftables.MetaCompare(unix.NFT_META_OIFNAME, unix.NFT_CMP_NEQ, rule.Device), ret)
	case EntryReply:
		expressions = append(nftables.CTReplyMatch(), ret)
	case EntryLinkLocal:
		expressions = slices.Concat(nftables.NFProto(proto), nftables.DestinationPrefix(rule.Destination), [][]byte{ret})
	case EntryOwned:
		expressions = slices.Concat(nftables.NFProto(proto), [][]byte{nftables.SourceLoad(proto), nftables.Lookup(borderSet(rule.Set()), false), ret})
	case EntryNone:
		expressions = slices.Concat(nftables.NFProto(proto), [][]byte{nftables.DestinationLoad(proto), nftables.Lookup(borderSet(rule.Set()), false), ret})
	default:
		expressions = slices.Concat(nftables.NFProto(proto), nftables.CountedDrop())
	}
	return nftables.Line{Spec: rule.String(), Expressions: expressions}, nil
}

// interfaceMatch matches an exemption's interface: nothing for one that names
// none, the bytes before the * for a name ending in one, as nft compiles
// iifname "wl*", and the name over IFNAMSIZ for any other
func interfaceMatch(name string) [][]byte {
	if pattern, wildcard := egress.InterfacePattern(name); wildcard {
		return nftables.MetaCompareValue(unix.NFT_META_IIFNAME, unix.NFT_CMP_EQ, []byte(pattern))
	}
	if name == "" {
		return nil
	}
	return nftables.MetaCompare(unix.NFT_META_IIFNAME, unix.NFT_CMP_EQ, name)
}
