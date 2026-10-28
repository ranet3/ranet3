// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/nftables"
	"ranet3.com/pkgs/ranet3/schema"
)

var _ switcher = (*netlinkPlatform)(nil)

// fallbackPriority runs the chain after every priority nft and iptables name
// and ahead of conntrack's confirmation at the last one, so a packet it drops
// confirms no entry
const fallbackPriority = 2147483646

// fallbackDrop is the chain's last line, whose counter status reads
const fallbackDrop = "counter drop"

// fallbackChain is the table's one chain, at postrouting, which sees the
// device every packet leaves by after every route chain and NAT has moved it
var fallbackChain = nftables.Chain{Table: FallbackTable, Name: "fallback", Type: "filter", Hook: unix.NF_INET_POST_ROUTING, Priority: fallbackPriority}

// fallbackNamed is the table's named sets, the IDs naming them to the rules of
// the transaction that makes them
var fallbackNamed = []nftables.Set{
	{Table: FallbackTable, Name: "forwarded", ID: 1, KeyType: nftables.TypeIfname, KeyLen: unix.IFNAMSIZ},
	{Table: FallbackTable, Name: "lan4", ID: 2, KeyType: nftables.TypeIPv4Addr, KeyLen: 4, Flags: unix.NFT_SET_INTERVAL},
	{Table: FallbackTable, Name: "lan6", ID: 3, KeyType: nftables.TypeIPv6Addr, KeyLen: 16, Flags: unix.NFT_SET_INTERVAL},
	{Table: FallbackTable, Name: "own4", ID: 4, KeyType: nftables.TypeIPv4Addr, KeyLen: 4, Flags: unix.NFT_SET_INTERVAL},
	{Table: FallbackTable, Name: "own6", ID: 5, KeyType: nftables.TypeIPv6Addr, KeyLen: 16, Flags: unix.NFT_SET_INTERVAL},
	// inbound's ports of each protocol, named so the line reading them is
	// spelled the same however many inbound lists, within the comment's 128
	// bytes. nft reads tcp and udp as keywords, so neither names a set.
	{Table: FallbackTable, Name: "tcp_ports", ID: 6, KeyType: nftables.TypeInetService, KeyLen: 2, Flags: unix.NFT_SET_INTERVAL},
	{Table: FallbackTable, Name: "udp_ports", ID: 7, KeyType: nftables.TypeInetService, KeyLen: 2, Flags: unix.NFT_SET_INTERVAL},
}

// linkLocal4 and linkLocal6 are the link-local, multicast and broadcast
// destinations that carry neighbor and router discovery and DHCP
var (
	linkLocal4 = []netip.Prefix{netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("255.255.255.255/32")}
	linkLocal6 = []netip.Prefix{netip.MustParsePrefix("fe80::/10"), netip.MustParsePrefix("ff00::/8")}
)

// elements is each named set's elements for sets
func (s fallbackSets) elements() map[string][]nftables.Interval {
	var forwarded []nftables.Interval
	for _, name := range s.forwarded {
		forwarded = append(forwarded, nftables.Key(nftables.InterfaceName(name)))
	}
	return map[string][]nftables.Interval{
		"forwarded": forwarded,
		"lan4":      nftables.Prefixes(s.lan4),
		"lan6":      nftables.Prefixes(s.lan6),
		"own4":      nftables.Prefixes(s.own4),
		"own6":      nftables.Prefixes(s.own6),
		"tcp_ports": ports(s.tcp),
		"udp_ports": ports(s.udp),
	}
}

// ports is each service's range of ports as an interval of network order keys
func ports(services []Service) []nftables.Interval {
	var out []nftables.Interval
	for _, service := range services {
		out = append(out, nftables.Interval{First: binary.BigEndian.AppendUint16(nil, service.First), Last: binary.BigEndian.AppendUint16(nil, service.Last)})
	}
	return out
}

// fallbackRule is one line of the chain: its text as nft lists it, the
// comment the readback knows it by, its expressions and the anonymous set it
// reads, if any, with that set's elements
type fallbackRule struct {
	spec        string
	expressions [][]byte
	anonymous   *nftables.Set
	members     []nftables.Interval
}

// rules is the chain's lines in order
func (s fallbackSets) rules() ([]fallbackRule, error) {
	named := func(name string) nftables.Set {
		return fallbackNamed[slices.IndexFunc(fallbackNamed, func(set nftables.Set) bool { return set.Name == name })]
	}
	accept := nftables.Verdict(nftables.Accept)
	id := uint32(10)
	anonymous := func(keyType, keyLen, flags uint32) *nftables.Set {
		set := nftables.Anonymous(FallbackTable, id, keyType, keyLen, flags)
		id++
		return &set
	}
	if err := nftables.DeviceName(s.tun); err != nil {
		return nil, err
	}
	for _, name := range s.forwarded {
		if err := nftables.DeviceName(name); err != nil {
			return nil, err
		}
	}
	oif := anonymous(nftables.TypeIfname, unix.IFNAMSIZ, 0)
	var out []fallbackRule
	out = append(out,
		fallbackRule{
			// unquoted, since nft prints a comment as written and a quote in one would end it
			spec:        fmt.Sprintf("oifname { %s, %s } accept", loopback, s.tun),
			expressions: [][]byte{nftables.MetaLoad(unix.NFT_META_OIFNAME), nftables.Lookup(*oif, false), accept},
			anonymous:   oif, members: []nftables.Interval{nftables.Key(nftables.InterfaceName(loopback)), nftables.Key(nftables.InterfaceName(s.tun))},
		},
		fallbackRule{
			spec:        fmt.Sprintf("meta mark %#08x accept", schema.UnderlayMark),
			expressions: append(nftables.MetaCompareValue(unix.NFT_META_MARK, unix.NFT_CMP_EQ, binary.NativeEndian.AppendUint32(nil, schema.UnderlayMark)), accept),
		},
		fallbackRule{
			spec: "meta iif != 0 iifname != @forwarded accept",
			expressions: slices.Concat(nftables.MetaCompareValue(unix.NFT_META_IIF, unix.NFT_CMP_NEQ, make([]byte, 4)),
				[][]byte{nftables.MetaLoad(unix.NFT_META_IIFNAME), nftables.Lookup(named("forwarded"), true), accept}),
		},
	)
	for _, line := range []struct {
		proto uint8
		set   string
	}{{unix.NFPROTO_IPV4, "lan4"}, {unix.NFPROTO_IPV6, "lan6"}} {
		out = append(out, addressLine(line.proto, "@"+line.set, nftables.Lookup(named(line.set), false), nil, nil))
	}
	link4 := anonymous(nftables.TypeIPv4Addr, 4, unix.NFT_SET_INTERVAL)
	out = append(out, addressLine(unix.NFPROTO_IPV4, "{ 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255 }", nftables.Lookup(*link4, false), link4, nftables.Prefixes(linkLocal4)))
	link6 := anonymous(nftables.TypeIPv6Addr, 16, unix.NFT_SET_INTERVAL)
	out = append(out, addressLine(unix.NFPROTO_IPV6, "{ fe80::/10, ff00::/8 }", nftables.Lookup(*link6, false), link6, nftables.Prefixes(linkLocal6)))
	for _, line := range []struct {
		proto uint8
		set   string
	}{{unix.NFPROTO_IPV4, "own4"}, {unix.NFPROTO_IPV6, "own6"}} {
		out = append(out, addressLine(line.proto, "@"+line.set, nftables.Lookup(named(line.set), false), nil, nil))
	}
	for _, line := range []struct {
		name     string
		protocol uint8
		services []Service
	}{{"tcp", unix.IPPROTO_TCP, s.tcp}, {"udp", unix.IPPROTO_UDP, s.udp}} {
		if len(line.services) == 0 {
			continue
		}
		out = append(out, fallbackRule{
			spec: fmt.Sprintf("ct direction reply ct protocol %s ct original proto-dst @%s_ports accept", line.name, line.name),
			expressions: []([]byte){
				nftables.CTLoad(unix.NFT_CT_DIRECTION), nftables.Expression("cmp", nftables.Compare(unix.NFT_CMP_EQ, []byte{nftables.CTReply})),
				nftables.CTLoad(unix.NFT_CT_PROTOCOL), nftables.Expression("cmp", nftables.Compare(unix.NFT_CMP_EQ, []byte{line.protocol})),
				nftables.CTLoadDirection(unix.NFT_CT_PROTO_DST, nftables.CTOriginal), nftables.Lookup(named(line.name+"_ports"), false), accept,
			},
		})
	}
	out = append(out, fallbackRule{spec: fallbackDrop, expressions: nftables.CountedDrop()})
	return out, nil
}

// addressLine is a line passing one family's destinations in a set
func addressLine(proto uint8, set string, lookup []byte, anonymous *nftables.Set, members []nftables.Interval) fallbackRule {
	family := "ip6"
	if proto == unix.NFPROTO_IPV4 {
		family = "ip"
	}
	return fallbackRule{
		spec:        fmt.Sprintf("%s daddr %s accept", family, set),
		expressions: slices.Concat(nftables.NFProto(proto), [][]byte{nftables.DestinationLoad(proto), lookup, nftables.Verdict(nftables.Accept)}),
		anonymous:   anonymous, members: members,
	}
}

// fallbackBatch is the table in one transaction: the table with no owner
// flag, its named sets made, flushed and filled, the chain made and flushed,
// and each line behind the anonymous set it reads. remake deletes the table
// first, for one holding what nf_tables will not change in place.
func fallbackBatch(s fallbackSets, remake bool) ([]nftables.Request, error) {
	var requests []nftables.Request
	if remake {
		requests = append(requests, nftables.DeleteTable(unix.NFPROTO_INET, FallbackTable))
	}
	requests = append(requests, nftables.NewTable(unix.NFPROTO_INET, FallbackTable))
	elements := s.elements()
	for _, set := range fallbackNamed {
		made, err := set.Create(unix.NFPROTO_INET)
		if err != nil {
			return nil, err
		}
		filled, err := set.Fill(unix.NFPROTO_INET, elements[set.Name])
		if err != nil {
			return nil, err
		}
		requests = append(append(requests, made, set.Flush(unix.NFPROTO_INET)), filled...)
	}
	requests = append(requests, fallbackChain.Create(unix.NFPROTO_INET), fallbackChain.Flush(unix.NFPROTO_INET))
	rules, err := s.rules()
	if err != nil {
		return nil, err
	}
	for _, rule := range rules {
		if rule.anonymous != nil {
			made, err := rule.anonymous.Create(unix.NFPROTO_INET)
			if err != nil {
				return nil, err
			}
			filled, err := rule.anonymous.Fill(unix.NFPROTO_INET, rule.members)
			if err != nil {
				return nil, err
			}
			requests = append(append(requests, made), filled...)
		}
		request, err := fallbackChain.Rule(unix.NFPROTO_INET, rule.spec, rule.expressions)
		if err != nil {
			return nil, err
		}
		requests = append(requests, request)
	}
	return requests, nil
}

// fallbackTables is the scope another writer's change wakes the reconciler in
var fallbackTables = nftables.Scope{Name: FallbackTable, Families: []uint8{unix.NFPROTO_INET}}

// fallbackWatch is the socket the table is written through and the monitor of
// every other writer's change to it. A pass that finds the table changed
// leaves 5405 and 5435 out until it reads back, so the change is answered at
// once rather than at the next periodic pass.
type fallbackWatch struct {
	conn    *nftables.Conn
	monitor *nftables.Monitor
	stop    chan struct{}
	done    chan struct{}
}

// watchFallback is the socket the table is written through, opening it with
// its monitor at the first call
func (p *netlinkPlatform) watchFallback() (*nftables.Conn, error) {
	if p.fallback != nil {
		return p.fallback.conn, nil
	}
	conn, err := nftables.Dial()
	if err != nil {
		return nil, err
	}
	monitor, err := nftables.OpenMonitor(conn, fallbackTables)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	w := &fallbackWatch{conn: conn, monitor: monitor, stop: make(chan struct{}), done: make(chan struct{})}
	go w.forward(monitor.Changed(), monitor.Missed(), p.monitor.wake)
	p.fallback = w
	return conn, nil
}

// forward wakes the reconciler on each change the monitor reports and on each
// it may have missed
func (w *fallbackWatch) forward(changed, missed <-chan struct{}, wake func()) {
	defer close(w.done)
	for {
		select {
		case <-w.stop:
			return
		case <-changed:
		case <-missed:
		}
		wake()
	}
}

func (p *netlinkPlatform) unwatchFallback() error {
	w := p.fallback
	if w == nil {
		return nil
	}
	p.fallback = nil
	close(w.stop)
	<-w.done
	return errors.Join(w.monitor.Close(), w.conn.Close())
}

func (p *netlinkPlatform) writeFallback(s fallbackSets) error {
	conn, err := p.watchFallback()
	if err != nil {
		return err
	}
	read, err := readFallback(conn, s)
	if err != nil {
		return err
	}
	requests, err := fallbackBatch(s, read.Remake)
	if err != nil {
		return err
	}
	return conn.Batch(requests)
}

func (p *netlinkPlatform) readFallback(s fallbackSets) (fallbackRead, error) {
	conn, err := p.watchFallback()
	if err != nil {
		return fallbackRead{}, err
	}
	return fallbackFault(conn, s)
}

// fallbackFault reads the table conn holds against what writeFallback writes
// for s
func fallbackFault(conn *nftables.Conn, s fallbackSets) (fallbackRead, error) {
	read, err := readFallback(conn, s)
	if err != nil {
		return fallbackRead{}, err
	}
	var out fallbackRead
	for _, rule := range read.Rules {
		if rule.Spec == fallbackDrop {
			out.dropped, out.bytes = rule.Packets, rule.Bytes
		}
	}
	if read.Fault != "" {
		out.fault = read.Fault
		return out, nil
	}
	rules, err := s.rules()
	if err != nil {
		return fallbackRead{}, err
	}
	var want, held []string
	for _, rule := range rules {
		want = append(want, rule.spec)
	}
	for _, rule := range read.Rules {
		held = append(held, rule.Spec)
	}
	if !slices.Equal(held, want) {
		out.fault = fmt.Sprintf("its chain holds [%s], where [%s] was written", strings.Join(held, "; "), strings.Join(want, "; "))
	}
	return out, nil
}

// ReadFallback reads the table through a socket of its own, so the
// reconciler's stays with its one user
func ReadFallback() (FallbackDebug, error) {
	out := FallbackDebug{Where: "nftables table inet " + FallbackTable + " chain " + fallbackChain.Name, Hook: "postrouting", Priority: fallbackPriority}
	conn, err := nftables.Dial()
	if err != nil {
		return out, err
	}
	defer conn.Close()
	tables, err := nftables.Tables(conn, FallbackTable)
	if err != nil {
		return out, err
	}
	if _, out.Held = tables[unix.NFPROTO_INET]; !out.Held {
		return out, nil
	}
	read, err := nftables.Contents{Chains: []nftables.Chain{fallbackChain}}.Read(conn, tables, unix.NFPROTO_INET)
	if err != nil {
		return out, err
	}
	for _, rule := range read.Rules {
		out.Rules = append(out.Rules, FallbackDebugRule{Spec: rule.Spec, Packets: rule.Packets, Bytes: rule.Bytes})
	}
	for _, set := range fallbackNamed {
		held, err := set.Elements(conn, unix.NFPROTO_INET)
		if err != nil {
			return out, err
		}
		elements := []string{}
		for _, interval := range held {
			elements = append(elements, intervalText(set, interval))
		}
		out.Sets = append(out.Sets, FallbackDebugSet{Name: set.Name, Elements: elements})
	}
	return out, nil
}

// intervalText is an element as nft lists it: a link's name, a port or a
// range of ports, an address, a prefix, or a range's first and last address
func intervalText(set nftables.Set, interval nftables.Interval) string {
	switch {
	case set.KeyType == nftables.TypeIfname:
		return unix.ByteSliceToString(interval.First)
	case set.KeyType == nftables.TypeInetService && len(interval.First) == 2 && len(interval.Last) == 2:
		first, last := binary.BigEndian.Uint16(interval.First), binary.BigEndian.Uint16(interval.Last)
		if first == last {
			return fmt.Sprint(first)
		}
		return fmt.Sprintf("%d-%d", first, last)
	}
	first, okFirst := netip.AddrFromSlice(interval.First)
	last, okLast := netip.AddrFromSlice(interval.Last)
	if !okFirst || !okLast {
		return fmt.Sprintf("%x-%x", interval.First, interval.Last)
	}
	for bits := 0; bits <= first.BitLen(); bits++ {
		prefix := netip.PrefixFrom(first, bits)
		if prefix.Masked().Addr() == first && lastOf(prefix) == last {
			if bits == first.BitLen() {
				return first.String()
			}
			return prefix.String()
		}
	}
	return first.String() + "-" + last.String()
}

// lastOf is the last address of prefix
func lastOf(prefix netip.Prefix) netip.Addr {
	raw := prefix.Addr().AsSlice()
	for i := prefix.Bits(); i < len(raw)*8; i++ {
		raw[i/8] |= 0x80 >> (i % 8)
	}
	last, _ := netip.AddrFromSlice(raw)
	return last
}

// readFallback reads the table back, a missing one as a fault
func readFallback(conn *nftables.Conn, s fallbackSets) (nftables.Readback, error) {
	tables, err := nftables.Tables(conn, FallbackTable)
	if err != nil {
		return nftables.Readback{}, err
	}
	if _, held := tables[unix.NFPROTO_INET]; !held {
		return nftables.Readback{Fault: "the table is missing"}, nil
	}
	read, err := nftables.Contents{Chains: []nftables.Chain{fallbackChain}, Sets: fallbackNamed, Elements: s.elements()}.Read(conn, tables, unix.NFPROTO_INET)
	if err != nil {
		return nftables.Readback{}, fmt.Errorf("kernel: read table inet %s: %w", FallbackTable, err)
	}
	return read, nil
}

// deleteFallback deletes through the watch's socket, so its own delete wakes
// nothing. It lists first, since deleting a table that is not there fails the
// batch.
func (p *netlinkPlatform) deleteFallback() error {
	conn, err := p.watchFallback()
	if err != nil {
		return err
	}
	tables, err := nftables.Tables(conn, FallbackTable)
	if err != nil {
		return err
	}
	if _, held := tables[unix.NFPROTO_INET]; !held {
		return nil
	}
	return conn.Batch([]nftables.Request{nftables.DeleteTable(unix.NFPROTO_INET, FallbackTable)})
}
