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

// fallbackDrop is each chain's last line, whose counters status reads summed
const fallbackDrop = "counter drop"

// fallbackChain is the table's chain at postrouting, which reads the device a
// packet leaves by (ip_output in ip_output.c, ip6_output in ip6_output.c)
var fallbackChain = nftables.Chain{Table: FallbackTable, Name: "fallback", Type: "filter", Hook: unix.NF_INET_POST_ROUTING, Priority: fallbackPriority}

// fallbackOutput holds postrouting's lines for the packets reaching output,
// which carry no input link there (__ip_local_out in ip_output.c,
// __ip6_local_out in output_core.c). At postrouting a packet's input link is
// its device before its route (ip_output in ip_output.c, ip6_output in
// ip6_output.c), a kernel
// tunnel's for its outer packet, which the forwarded line's iif match reads as
// forwarded.
var fallbackOutput = nftables.Chain{Table: FallbackTable, Name: "output", Type: "filter", Hook: unix.NF_INET_LOCAL_OUT, Priority: fallbackPriority}

// fallbackChains is the table's chains, in the order the readback lists their lines
var fallbackChains = []nftables.Chain{fallbackChain, fallbackOutput}

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

func (s fallbackSets) elements() map[string][]nftables.Interval {
	// lo counts as a link forward names, as 5450 does, so a packet looped back through it and forwarded meets the lines
	var forwarded []nftables.Interval
	for _, name := range append([]string{loopback}, s.forwarded...) {
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

func ports(services []Service) []nftables.Interval {
	var out []nftables.Interval
	for _, service := range services {
		out = append(out, nftables.Interval{First: binary.BigEndian.AppendUint16(nil, service.First), Last: binary.BigEndian.AppendUint16(nil, service.Last)})
	}
	return out
}

type fallbackRule struct {
	// spec is the line as nft lists it and also its comment
	spec        string
	expressions [][]byte
	anonymous   *nftables.Set
	members     []nftables.Interval
}

// rules is the lines in order of the chain at index chain of fallbackChains,
// the anonymous sets they read numbered from chainFirstSet, so each chain's
// sets take IDs of their own in one transaction
func (s fallbackSets) rules(chain int) ([]fallbackRule, error) {
	named := func(name string) nftables.Set {
		return fallbackNamed[slices.IndexFunc(fallbackNamed, func(set nftables.Set) bool { return set.Name == name })]
	}
	accept := nftables.Verdict(nftables.Accept)
	id := chainFirstSet(chain)
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
			// a forwarded packet from a link outside forwarded whose destination the fib does not type local (nft_fib4_eval_type in
			// nft_fib_ipv4.c, __nft_fib6_eval_type in nft_fib_ipv6.c). The type keeps the line off a packet a rule ahead of the
			// local table sends on toward a destination it types local, and off a kernel tunnel's outer packet bound to a link toward
			// an address another link holds, whose lookup passes over that address's local route (fib_trie.c, fib_lookup_good_nhc).
			spec: "meta iif != 0 iifname != @forwarded fib daddr type != local accept",
			expressions: slices.Concat(nftables.MetaCompareValue(unix.NFT_META_IIF, unix.NFT_CMP_NEQ, make([]byte, 4)),
				[][]byte{nftables.MetaLoad(unix.NFT_META_IIFNAME), nftables.Lookup(named("forwarded"), true), nftables.FibDestinationType(),
					nftables.Expression("cmp", nftables.Compare(unix.NFT_CMP_NEQ, binary.NativeEndian.AppendUint32(nil, unix.RTN_LOCAL))), accept}),
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
	// neighbor and router discovery, which RFC 4890 section 4.4.1 says must not be dropped, at the hop limit of 255 RFC 4861
	// sections 6.1 and 7.1 require, to any destination, since a solicited advertisement goes to the solicitation's source
	discovery := anonymous(nftables.TypeICMPv6Type, 1, 0)
	var discoveryTypes []nftables.Interval
	for icmpType := byte(133); icmpType <= 136; icmpType++ {
		discoveryTypes = append(discoveryTypes, nftables.Key([]byte{icmpType}))
	}
	icmp := func(proto, l4 uint8) [][]byte {
		return slices.Concat(nftables.NFProto(proto), nftables.MetaCompareValue(unix.NFT_META_L4PROTO, unix.NFT_CMP_EQ, []byte{l4}))
	}
	// a packet with no input link at postrouting (ip_output in ip_output.c, ip6_output in ip6_output.c), such as the host's own,
	// where a forwarded one reads its own
	own := nftables.MetaCompareValue(unix.NFT_META_IIF, unix.NFT_CMP_EQ, make([]byte, 4))
	out = append(out,
		fallbackRule{
			spec: "icmpv6 type { nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } ip6 hoplimit 255 accept",
			expressions: slices.Concat(icmp(unix.NFPROTO_IPV6, unix.IPPROTO_ICMPV6), [][]byte{
				nftables.TransportLoad(0, 1), nftables.Lookup(*discovery, false),
				nftables.NetworkLoad(7, 1), nftables.Expression("cmp", nftables.Compare(unix.NFT_CMP_EQ, []byte{255})), accept,
			}),
			anonymous: discovery, members: discoveryTypes,
		},
		// the errors path MTU discovery reads, Packet Too Big of RFC 4443 and fragmentation needed of RFC 792, which the kernel sends
		// only to the source of a packet too big for its next hop, a forwarded one among them, and the host's own alone
		fallbackRule{
			spec: "meta iif 0 icmpv6 type packet-too-big accept",
			expressions: slices.Concat(own, icmp(unix.NFPROTO_IPV6, unix.IPPROTO_ICMPV6), [][]byte{
				nftables.TransportLoad(0, 1), nftables.Expression("cmp", nftables.Compare(unix.NFT_CMP_EQ, []byte{2})), accept,
			}),
		},
		fallbackRule{
			spec: "meta iif 0 icmp type destination-unreachable icmp code 4 accept",
			expressions: slices.Concat(own, icmp(unix.NFPROTO_IPV4, unix.IPPROTO_ICMP), [][]byte{
				nftables.TransportLoad(0, 2), nftables.Expression("cmp", nftables.Compare(unix.NFT_CMP_EQ, []byte{3, 4})), accept,
			}),
		},
	)
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
	if fallbackChains[chain].Hook == unix.NF_INET_LOCAL_OUT {
		// oifname reads the device of the packet's first route (__ip_local_out in ip_output.c, __ip6_local_out in output_core.c),
		// so a packet whose destination the fib types local (nft_fib4_eval_type in nft_fib_ipv4.c, __nft_fib6_eval_type in
		// nft_fib_ipv6.c), whatever gave it that destination, passes on that type and meets postrouting's lines by the link it
		// leaves by, which the reroute at output looks up again (ip_route_me_harder and ip6_route_me_harder in each family's
		// netfilter.c)
		out = append(out, fallbackRule{
			spec: "fib daddr type local accept",
			expressions: []([]byte){
				nftables.FibDestinationType(), nftables.Expression("cmp", nftables.Compare(unix.NFT_CMP_EQ, binary.NativeEndian.AppendUint32(nil, unix.RTN_LOCAL))), accept,
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
// flag, its named sets made, flushed and filled, each chain made and flushed,
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
	for i, chain := range fallbackChains {
		requests = append(requests, chain.Create(unix.NFPROTO_INET), chain.Flush(unix.NFPROTO_INET))
		rules, err := s.rules(i)
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
			request, err := chain.Rule(unix.NFPROTO_INET, rule.spec, rule.expressions)
			if err != nil {
				return nil, err
			}
			requests = append(requests, request)
		}
	}
	return requests, nil
}

// chainFirstSet is the ID of the first anonymous set the lines of the chain
// at index i of fallbackChains read, past the named sets' and the sets of the
// chains before it
func chainFirstSet(i int) uint32 { return uint32(fallbackSetIDs * (i + 1)) }

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

func (p *netlinkPlatform) writeFallback(s fallbackSets, remake bool) error {
	conn, err := p.watchFallback()
	if err != nil {
		return err
	}
	requests, err := fallbackBatch(s, remake)
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
	out := fallbackRead{remake: read.Remake}
	for _, rule := range read.Rules {
		if rule.Spec == fallbackDrop {
			out.dropped, out.bytes = out.dropped+rule.Packets, out.bytes+rule.Bytes
		}
	}
	if read.Fault != "" {
		out.fault = read.Fault
		return out, nil
	}
	for i := range fallbackChains {
		if out.fault, err = chainFault(conn, s, i, read.Rules); err != nil {
			return fallbackRead{}, err
		}
		if out.fault != "" {
			break
		}
	}
	return out, nil
}

// chainFault names how the chain at index chain of fallbackChains holds lines
// other than those written for s, read from every chain's lines in held,
// empty where it does not
func chainFault(conn *nftables.Conn, s fallbackSets, chain int, held []nftables.Installed) (string, error) {
	want, err := s.rules(chain)
	if err != nil {
		return "", err
	}
	name := fallbackChains[chain].Name
	held = slices.DeleteFunc(slices.Clone(held), func(rule nftables.Installed) bool { return rule.Chain != name })
	var wantSpecs, heldSpecs []string
	for _, rule := range want {
		wantSpecs = append(wantSpecs, rule.spec)
	}
	for _, rule := range held {
		heldSpecs = append(heldSpecs, rule.Spec)
	}
	if !slices.Equal(heldSpecs, wantSpecs) {
		return fmt.Sprintf("its chain %s holds [%s], where [%s] was written", name, strings.Join(heldSpecs, "; "), strings.Join(wantSpecs, "; ")), nil
	}
	// a line edited under the comment it was written with reads as its comment says, so each is read by what it does
	for i, rule := range want {
		if fault := nftables.ExpressionFault(rule.expressions, held[i].Expressions); fault != "" {
			return fmt.Sprintf("its chain %s's line %s: %s", name, rule.spec, fault), nil
		}
		if rule.anonymous == nil {
			continue
		}
		sets := nftables.LookupSets(held[i].Expressions)
		if len(sets) != 1 {
			return fmt.Sprintf("its chain %s's line %s looks up %v, where one set was written", name, rule.spec, sets), nil
		}
		set := *rule.anonymous
		set.Name = sets[0]
		fault, err := set.ElementFault(conn, unix.NFPROTO_INET, rule.members)
		if err != nil {
			return "", err
		}
		if fault != "" {
			return fmt.Sprintf("its chain %s's line %s: %s", name, rule.spec, fault), nil
		}
	}
	return "", nil
}

// ReadFallback reads the table through a socket of its own, so the
// reconciler's stays with its one user
func ReadFallback() (FallbackDebug, error) {
	out := FallbackDebug{Where: "nftables table inet " + FallbackTable + " chains " + fallbackChain.Name + " and " + fallbackOutput.Name, Hook: "postrouting and output", Priority: fallbackPriority}
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
	for _, chain := range fallbackChains {
		read, err := nftables.Contents{Chains: []nftables.Chain{chain}}.Read(conn, tables, unix.NFPROTO_INET)
		if err != nil {
			return out, err
		}
		for _, rule := range read.Rules {
			out.Rules = append(out.Rules, FallbackDebugRule{Chain: chain.Name, Spec: rule.Spec, Packets: rule.Packets, Bytes: rule.Bytes})
		}
	}
	for _, set := range fallbackNamed {
		held, err := set.Elements(conn, unix.NFPROTO_INET)
		if err != nil {
			return out, err
		}
		elements := []string{}
		for _, interval := range held {
			elements = append(elements, set.Text(interval))
		}
		out.Sets = append(out.Sets, FallbackDebugSet{Name: set.Name, Elements: elements})
	}
	return out, nil
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
	read, err := nftables.Contents{Chains: fallbackChains, Sets: fallbackNamed, Elements: s.elements()}.Read(conn, tables, unix.NFPROTO_INET)
	if err != nil {
		return nftables.Readback{}, fmt.Errorf("kernel: read table inet %s: %w", FallbackTable, err)
	}
	return read, nil
}

// deleteFallback deletes through the watch's socket, so its own delete wakes
// nothing
func (p *netlinkPlatform) deleteFallback() error {
	conn, err := p.watchFallback()
	if err != nil {
		return err
	}
	return deleteFallback(conn)
}

// deleteFallback lists first, since deleting a table that is not there fails
// the batch
func deleteFallback(conn *nftables.Conn) error {
	tables, err := nftables.Tables(conn, FallbackTable)
	if err != nil {
		return err
	}
	if _, held := tables[unix.NFPROTO_INET]; !held {
		return nil
	}
	return conn.Batch([]nftables.Request{nftables.DeleteTable(unix.NFPROTO_INET, FallbackTable)})
}

// DeleteFallback deletes the table an earlier instance left, for a start that
// runs no reconciler to delete it. A kernel without nf_tables holds none. A
// start without CAP_NET_ADMIN, which nfnetlink refuses with EPERM, cannot
// tell whether one is held, and warns as any other refusal.
func DeleteFallback() {
	conn, err := nftables.Dial()
	if err == nil {
		err = deleteFallback(conn)
		_ = conn.Close()
	}
	if err != nil && !withoutNFTables(err) {
		warnFallbackLeft(err)
	}
}
