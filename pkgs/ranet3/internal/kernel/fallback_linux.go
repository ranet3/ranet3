// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"encoding/binary"
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
	}
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
		ports := anonymous(nftables.TypeInetService, 2, unix.NFT_SET_INTERVAL)
		var members []nftables.Interval
		var spelled []string
		for _, service := range line.services {
			members = append(members, nftables.Interval{First: binary.BigEndian.AppendUint16(nil, service.First), Last: binary.BigEndian.AppendUint16(nil, service.Last)})
			spelled = append(spelled, strings.TrimSuffix(service.String(), "/"+service.Protocol))
		}
		out = append(out, fallbackRule{
			spec: fmt.Sprintf("ct direction reply ct protocol %s ct original proto-dst { %s } accept", line.name, strings.Join(spelled, ", ")),
			expressions: []([]byte){
				nftables.CTLoad(unix.NFT_CT_DIRECTION), nftables.Expression("cmp", nftables.Compare(unix.NFT_CMP_EQ, []byte{nftables.CTReply})),
				nftables.CTLoad(unix.NFT_CT_PROTOCOL), nftables.Expression("cmp", nftables.Compare(unix.NFT_CMP_EQ, []byte{line.protocol})),
				nftables.CTLoadDirection(unix.NFT_CT_PROTO_DST, nftables.CTOriginal), nftables.Lookup(*ports, false), accept,
			},
			anonymous: ports, members: members,
		})
	}
	out = append(out, fallbackRule{spec: "counter drop", expressions: nftables.CountedDrop()})
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

func (p *netlinkPlatform) writeFallback(s fallbackSets) error {
	conn, err := nftables.Dial()
	if err != nil {
		return err
	}
	defer conn.Close()
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

func (p *netlinkPlatform) readFallback(s fallbackSets) (string, error) {
	conn, err := nftables.Dial()
	if err != nil {
		return "", err
	}
	defer conn.Close()
	read, err := readFallback(conn, s)
	if err != nil {
		return "", err
	}
	if read.Fault != "" {
		return read.Fault, nil
	}
	rules, err := s.rules()
	if err != nil {
		return "", err
	}
	var want, held []string
	for _, rule := range rules {
		want = append(want, rule.spec)
	}
	for _, rule := range read.Rules {
		held = append(held, rule.Spec)
	}
	if !slices.Equal(held, want) {
		return fmt.Sprintf("its chain holds [%s], where [%s] was written", strings.Join(held, "; "), strings.Join(want, "; ")), nil
	}
	return "", nil
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

// deleteFallback lists first, since deleting a table that is not there fails
// the batch
func (p *netlinkPlatform) deleteFallback() error {
	conn, err := nftables.Dial()
	if err != nil {
		return err
	}
	defer conn.Close()
	tables, err := nftables.Tables(conn, FallbackTable)
	if err != nil {
		return err
	}
	if _, held := tables[unix.NFPROTO_INET]; !held {
		return nil
	}
	return conn.Batch([]nftables.Request{nftables.DeleteTable(unix.NFPROTO_INET, FallbackTable)})
}
