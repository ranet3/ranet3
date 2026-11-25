// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"cmp"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/nftables"
	"ranet3.com/pkgs/ranet3/schema"
)

var (
	_ switcher      = (*netlinkPlatform)(nil)
	_ switchWatcher = (*netlinkPlatform)(nil)
)

// tableForm is the switch's chains in nftables.Table as a log line and a
// status read them
var tableForm = fallbackForm{
	where:  "nftables table inet " + nftables.Table + " chains " + fallbackChain.Name + ", " + fallbackOutput.Name + " and " + fallbackRouted.Name,
	fix:    "nft delete chain inet " + nftables.Table + " " + fallbackRouted.Name + ", nft delete chain inet " + nftables.Table + " " + fallbackChain.Name + " and nft delete chain inet " + nftables.Table + " " + fallbackOutput.Name,
	unheld: "the host's own lookups from the uplink's addresses reach main only for its routes longer than /0",
}

func (p *netlinkPlatform) form() fallbackForm { return tableForm }

// fallbackDrop is each chain's last line, whose counters status reads summed
const fallbackDrop = "counter drop"

// fallbackChain is the switch's chain at postrouting, which reads the device a
// packet leaves by (ip_output in ip_output.c, ip6_output in ip6_output.c)
var fallbackChain = nftables.Chain{Table: nftables.Table, Name: "fallback", Type: "filter", Hook: unix.NF_INET_POST_ROUTING, Priority: fallbackPriority}

// fallbackOutput holds postrouting's lines for the packets reaching output,
// which carry no input link there (__ip_local_out in ip_output.c,
// __ip6_local_out in output_core.c). At postrouting a packet's input link is
// its device before its route (ip_output in ip_output.c, ip6_output in
// ip6_output.c), a kernel
// tunnel's for its outer packet, which the forwarded line's iif match reads as
// forwarded.
var fallbackOutput = nftables.Chain{Table: nftables.Table, Name: "output", Type: "filter", Hook: unix.NF_INET_LOCAL_OUT, Priority: fallbackPriority}

var fallbackRouted = nftables.Chain{Table: nftables.Table, Name: "routed", Type: "filter", Hook: unix.NF_INET_FORWARD, Priority: fallbackPriority}

// fallbackChains is the switch's chains, in the order the readback lists their lines
var fallbackChains = []nftables.Chain{fallbackChain, fallbackOutput, fallbackRouted}

// fallbackNamed is the switch's named sets, the IDs naming them to the rules
// of the transaction that makes them
var fallbackNamed = []nftables.Set{
	{Table: nftables.Table, Name: "forwarded", ID: 1, KeyType: nftables.TypeIfname, KeyLen: unix.IFNAMSIZ},
	{Table: nftables.Table, Name: "lan4", ID: 2, KeyType: nftables.TypeIPv4Addr, KeyLen: 4, Flags: unix.NFT_SET_INTERVAL},
	{Table: nftables.Table, Name: "lan6", ID: 3, KeyType: nftables.TypeIPv6Addr, KeyLen: 16, Flags: unix.NFT_SET_INTERVAL},
	{Table: nftables.Table, Name: "self4", ID: 4, KeyType: nftables.TypeIPv4Addr, KeyLen: 4, Flags: unix.NFT_SET_INTERVAL},
	{Table: nftables.Table, Name: "self6", ID: 5, KeyType: nftables.TypeIPv6Addr, KeyLen: 16, Flags: unix.NFT_SET_INTERVAL},
	// inbound's ports of each protocol, named so the line reading them is
	// spelled the same however many inbound lists, within the comment's 128
	// bytes. nft reads tcp and udp as keywords, so neither names a set.
	{Table: nftables.Table, Name: "tcpports", ID: 6, KeyType: nftables.TypeInetService, KeyLen: 2, Flags: unix.NFT_SET_INTERVAL},
	{Table: nftables.Table, Name: "udpports", ID: 7, KeyType: nftables.TypeInetService, KeyLen: 2, Flags: unix.NFT_SET_INTERVAL},
	{Table: nftables.Table, Name: "from4", ID: 8, KeyType: nftables.TypeIPv4Addr, KeyLen: 4, Flags: unix.NFT_SET_INTERVAL},
	{Table: nftables.Table, Name: "from6", ID: 9, KeyType: nftables.TypeIPv6Addr, KeyLen: 16, Flags: unix.NFT_SET_INTERVAL},
}

// fallbackRetired is the names an earlier switch gave the sets self4, self6,
// tcpports and udpports, in that order
var fallbackRetired = nftables.Scope{Sets: []string{"own4", "own6", "tcp_ports", "udp_ports"}}

// fallbackContents is the switch's chains and sets as a readback reads them
var fallbackContents = nftables.Contents{Chains: fallbackChains, Sets: fallbackNamed}

// linkLocal4 and linkLocal6 are the link-local, multicast and broadcast
// destinations that carry neighbor and router discovery and DHCP
var (
	linkLocal4 = []netip.Prefix{netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("255.255.255.255/32")}
	linkLocal6 = []netip.Prefix{netip.MustParsePrefix("fe80::/10"), netip.MustParsePrefix("ff00::/8")}
)

func (s fallbackSets) elements() map[string][]nftables.Interval {
	// lo counts as a link forward names, as 5450 does, so a packet looped back through it and forwarded meets the lines
	var forwarded []nftables.Interval
	for _, name := range append([]string{Loopback}, s.forwarded...) {
		forwarded = append(forwarded, nftables.Key(nftables.InterfaceName(name)))
	}
	return map[string][]nftables.Interval{
		"forwarded": forwarded,
		"lan4":      nftables.Prefixes(s.lan4),
		"lan6":      nftables.Prefixes(s.lan6),
		"self4":     nftables.Prefixes(s.self4),
		"self6":     nftables.Prefixes(s.self6),
		"from4":     nftables.Prefixes(s.from4),
		"from6":     nftables.Prefixes(s.from6),
		"tcpports":  ports(s.tcp),
		"udpports":  ports(s.udp),
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
	// spec is the readback's comment. Most lines use their nft text directly,
	// but ICMP's full conditions exceed nft's 128-byte comment limit
	spec         string
	expressions  [][]byte
	anonymous    *nftables.Set
	members      []nftables.Interval
	namedLookups int
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
		set := nftables.Anonymous(nftables.Table, id, keyType, keyLen, flags)
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
	routed := fallbackChains[chain].Hook == unix.NF_INET_FORWARD
	oif := anonymous(nftables.TypeIfname, unix.IFNAMSIZ, 0)
	var out []fallbackRule
	out = append(out,
		fallbackRule{
			// unquoted, since nft prints a comment as written and a quote in one would end it
			spec:        fmt.Sprintf("oifname { %s, %s } accept", Loopback, s.tun),
			expressions: [][]byte{nftables.MetaLoad(unix.NFT_META_OIFNAME), nftables.Lookup(*oif, false), accept},
			anonymous:   oif, members: []nftables.Interval{nftables.Key(nftables.InterfaceName(Loopback)), nftables.Key(nftables.InterfaceName(s.tun))},
		},
		fallbackRule{
			spec:        fmt.Sprintf("meta mark %#08x accept", schema.UnderlayMark),
			expressions: append(nftables.MetaCompareValue(unix.NFT_META_MARK, unix.NFT_CMP_EQ, binary.NativeEndian.AppendUint32(nil, schema.UnderlayMark)), accept),
		},
	)
	if routed {
		out = append(out, fallbackRule{
			spec:        "iifname @forwarded accept",
			expressions: [][]byte{nftables.MetaLoad(unix.NFT_META_IIFNAME), nftables.Lookup(named("forwarded"), false), accept},
		})
		for _, family := range []struct {
			proto uint8
			set   string
			spec  string
		}{{unix.NFPROTO_IPV4, "from4", "ip saddr != @from4 accept"}, {unix.NFPROTO_IPV6, "from6", "ip6 saddr != @from6 accept"}} {
			out = append(out, fallbackRule{
				spec: family.spec,
				expressions: slices.Concat(nftables.NFProto(family.proto), [][]byte{
					nftables.SourceLoad(family.proto), nftables.Lookup(named(family.set), true), accept,
				}),
			})
		}
	} else {
		out = append(out, fallbackRule{
			spec: "meta iif != 0 iifname != @forwarded fib daddr type != local accept",
			expressions: slices.Concat(nftables.MetaCompareValue(unix.NFT_META_IIF, unix.NFT_CMP_NEQ, make([]byte, 4)),
				[][]byte{nftables.MetaLoad(unix.NFT_META_IIFNAME), nftables.Lookup(named("forwarded"), true), nftables.FibDestinationType(),
					nftables.Expression("cmp", nftables.Compare(unix.NFT_CMP_NEQ, binary.NativeEndian.AppendUint32(nil, unix.RTN_LOCAL))), accept}),
		})
	}
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
	icmp := func(proto, l4 uint8) [][]byte {
		return slices.Concat(nftables.NFProto(proto), nftables.MetaCompareValue(unix.NFT_META_L4PROTO, unix.NFT_CMP_EQ, []byte{l4}))
	}
	if !routed {
		// neighbor and router discovery at the hop limit required by RFC 4861
		discovery := anonymous(nftables.TypeICMPv6Type, 1, 0)
		var discoveryTypes []nftables.Interval
		for icmpType := byte(133); icmpType <= 136; icmpType++ {
			discoveryTypes = append(discoveryTypes, nftables.Key([]byte{icmpType}))
		}
		// a packet with no input link at postrouting (ip_output in ip_output.c, ip6_output in output_core.c)
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
	}
	for _, line := range []struct {
		proto uint8
		set   string
	}{{unix.NFPROTO_IPV4, "self4"}, {unix.NFPROTO_IPV6, "self6"}} {
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
			spec: fmt.Sprintf("ct direction reply ct protocol %s ct original proto-dst @%sports accept", line.name, line.name),
			expressions: append(nftables.CTReplyMatch(),
				nftables.CTLoad(unix.NFT_CT_PROTOCOL), nftables.Expression("cmp", nftables.Compare(unix.NFT_CMP_EQ, []byte{line.protocol})),
				nftables.CTLoadDirection(unix.NFT_CT_PROTO_DST, nftables.CTOriginal), nftables.Lookup(named(line.name+"ports"), false), accept,
			),
		})
	}
	if routed {
		for _, family := range []struct {
			proto   uint8
			l4      uint8
			key     uint32
			set     string
			spec    string
			types   []byte
			setType uint32
		}{
			{unix.NFPROTO_IPV4, unix.IPPROTO_ICMP, unix.NFT_CT_SRC_IP, "from4",
				"icmp errors 3/11/12 related outside from4 counter accept", []byte{3, 11, 12}, 14},
			{unix.NFPROTO_IPV6, unix.IPPROTO_ICMPV6, unix.NFT_CT_SRC_IP6, "from6",
				"icmpv6 errors 1-4 related outside from6 counter accept", []byte{1, 2, 3, 4}, nftables.TypeICMPv6Type},
		} {
			types := anonymous(family.setType, 1, 0)
			members := make([]nftables.Interval, 0, len(family.types))
			for _, kind := range family.types {
				members = append(members, nftables.Key([]byte{kind}))
			}
			out = append(out, fallbackRule{
				spec: family.spec, namedLookups: 2,
				expressions: slices.Concat(icmp(family.proto, family.l4), [][]byte{
					nftables.TransportLoad(0, 1), nftables.Lookup(*types, false),
				}, nftables.CTMatch(unix.NFT_CT_STATE, 1<<2, unix.NFT_CMP_NEQ), [][]byte{
					nftables.CTLoadDirection(family.key, nftables.CTOriginal), nftables.Lookup(named(family.set), true),
					nftables.CTLoadDirection(family.key, nftables.CTReply), nftables.Lookup(named(family.set), true),
					nftables.Expression("counter", nil), accept,
				}),
				anonymous: types, members: members,
			})
		}
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

// fallbackBatch is the switch in one transaction: the table with no owner
// flag, each chain made and flushed, its named sets made, flushed and filled,
// and each line behind the anonymous set it reads, deleting first each chain
// and set of stale, and leftovers retired last
func fallbackBatch(s fallbackSets, stale nftables.Contents, leftovers []nftables.Retired) ([]nftables.Request, error) {
	requests := nftables.Contents{Chains: fallbackChains}.Rewrite(unix.NFPROTO_INET, stale, nil)
	elements := s.elements()
	for _, set := range fallbackNamed {
		replaced, err := set.Replace(unix.NFPROTO_INET, elements[set.Name])
		if err != nil {
			return nil, err
		}
		requests = append(requests, replaced...)
	}
	for i, chain := range fallbackChains {
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
	return append(requests, nftables.Retire(leftovers)...), nil
}

// chainFirstSet is the ID of the first anonymous set the lines of the chain
// at index i of fallbackChains read, past the named sets' and the sets of the
// chains before it
func chainFirstSet(i int) uint32 { return uint32(fallbackSetIDs * (i + 1)) }

// fallbackScope is the switch's chains and sets and fallbackRetired, whose
// change by another writer wakes the reconciler, as the table's deletion or a
// flag set on it does, and any chain made or deleted in the table, since a
// chain of the switch renamed out of its names carries its new name
var fallbackScope = func() nftables.Scope {
	scope := fallbackContents.Scope()
	scope.Sets = append(scope.Sets, fallbackRetired.Sets...)
	scope.AnyChain = true
	return scope
}()

// fallbackWatch is the socket the switch is written through and the monitor
// of every other writer's change to it, which reports to rec. A pass that
// finds the switch changed leaves 5405 and 5435 out until it reads back, so
// the change is answered at once rather than at the next periodic pass.
type fallbackWatch struct {
	conn    *nftables.Conn
	monitor *nftables.Monitor
	rec     switchRecord
	stop    chan struct{}
	done    chan struct{}
	// written is a write through conn that no read has followed yet, whose
	// readback takes no table gone
	written bool
}

// liveRecord is the open watch's record, nil where no watch is open or its
// monitor has stopped, which no pass opens again while the switch is asked for
func (p *netlinkPlatform) liveRecord() *switchRecord {
	w := p.fallback
	if w == nil {
		return nil
	}
	select {
	case <-w.monitor.Done():
		return nil
	default:
		return &w.rec
	}
}

// watchFallback is the socket the switch is written through, opening it with
// its monitor where none is open
func (p *netlinkPlatform) watchFallback() (*nftables.Conn, error) {
	if p.fallback != nil {
		return p.fallback.conn, nil
	}
	conn, err := nftables.Dial()
	if err != nil {
		return nil, err
	}
	monitor, err := nftables.OpenMonitor(conn, fallbackScope)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	w := &fallbackWatch{conn: conn, monitor: monitor, stop: make(chan struct{}), done: make(chan struct{})}
	go w.forward(monitor.Changed(), monitor.Missed(), p.monitor.wake)
	p.fallback = w
	return conn, nil
}

// forward reports to the record and then wakes the reconciler on each change the
// monitor reports and on each it may have missed
func (w *fallbackWatch) forward(changed, missed <-chan struct{}, wake func()) {
	defer close(w.done)
	for {
		select {
		case <-w.stop:
			return
		case <-changed:
		case <-missed:
		}
		w.rec.moved.Store(true)
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

// writeFallback reads the switch again where remake, for the chains and sets
// the batch deletes first, and writes it as nftables.Hold.Rewrite does
func (p *netlinkPlatform) writeFallback(s fallbackSets, remake bool) error {
	conn, err := p.watchFallback()
	if err != nil {
		return err
	}
	var tables map[uint8]uint32
	var stale nftables.Contents
	if remake {
		if tables, err = nftables.Tables(conn, nftables.Table); err != nil {
			return err
		}
		read, err := readFallback(conn, s, tables)
		if err != nil {
			return err
		}
		stale = read.Stale
	}
	leftovers, err := nftables.Leftovers(conn, tables, fallbackRetired, fallbackScope)
	if err != nil {
		return err
	}
	err = p.fallbackHeld.Rewrite(conn, fallbackNamed, stale, func(stale nftables.Contents) ([]nftables.Request, error) {
		return fallbackBatch(s, stale, leftovers)
	})
	p.fallback.written = err == nil
	return err
}

// readFallback is readFallbackThrough over nftables.Tables
func (p *netlinkPlatform) readFallback(s fallbackSets) (fallbackRead, error) {
	return p.readFallbackThrough(s, func(conn *nftables.Conn) (map[uint8]uint32, error) { return nftables.Tables(conn, nftables.Table) })
}

// readFallbackThrough reads the switch the watch's socket holds against what
// writeFallback writes for s over tables dumped through dump, and counts the
// switch among the table's holders where it finds any of its chains or sets,
// as a start that takes them over keeps them. A readback of a write takes no
// table gone, so a deletion after the write fails the pass.
func (p *netlinkPlatform) readFallbackThrough(s fallbackSets, dump func(conn *nftables.Conn) (map[uint8]uint32, error)) (fallbackRead, error) {
	conn, err := p.watchFallback()
	if err != nil {
		return fallbackRead{}, err
	}
	readback := p.fallback.written
	p.fallback.written = false
	reads := connReads(conn, s)
	tables := func() (map[uint8]uint32, error) { return dump(conn) }
	read := func(tables map[uint8]uint32) (fallbackRead, bool, error) { return faultOver(reads, tables) }
	out, found, err := readOrGone(tables, read, !readback)
	if err == nil && found {
		err = p.fallbackHeld.Found(conn)
	}
	return out, err
}

// readOrGone reads the switch over a dump of the tables. A dump of a table's
// sets or of a set's elements fails ENOENT where the table is gone
// (nft_table_lookup in nf_tables_api.c) and where the set alone is, so, where
// confirm holds, a read that fails ENOENT reads again over a fresh dump that
// holds no inet table, as over a table never there, and says so. Any other
// failure is the read's. Where confirm does not hold, the read is a write's
// readback, and a dump holding no inet table fails it ENOENT.
func readOrGone(dump func() (map[uint8]uint32, error), read func(tables map[uint8]uint32) (fallbackRead, bool, error), confirm bool) (fallbackRead, bool, error) {
	tables, err := dump()
	if err != nil {
		return fallbackRead{}, false, err
	}
	if _, held := tables[unix.NFPROTO_INET]; !held && !confirm {
		return fallbackRead{}, false, fmt.Errorf("kernel: read table inet %s back after its write: %w", nftables.Table, unix.ENOENT)
	}
	out, found, err := read(tables)
	if !confirm || !errors.Is(err, unix.ENOENT) {
		return out, found, err
	}
	if now, dumpErr := dump(); dumpErr == nil {
		if _, held := now[unix.NFPROTO_INET]; !held {
			slog.Warn("kernel's kill switch table was deleted during its read, and the pass writes the switch again", "where", tableForm.where, "err", err)
			return read(now)
		}
	}
	return out, found, err
}

// fallbackReads is the three reads of the switch faultOver folds, each over
// the tables a dump gave or the lines the first read found
type fallbackReads struct {
	contents   func(tables map[uint8]uint32) (nftables.Readback, error)
	leftovers  func(tables map[uint8]uint32) ([]nftables.Retired, error)
	chainFault func(chain int, held []nftables.Installed) (string, error)
}

// connReads is fallbackReads through conn against what writeFallback writes
// for s
func connReads(conn *nftables.Conn, s fallbackSets) fallbackReads {
	return fallbackReads{
		contents: func(tables map[uint8]uint32) (nftables.Readback, error) { return readFallback(conn, s, tables) },
		leftovers: func(tables map[uint8]uint32) ([]nftables.Retired, error) {
			return nftables.Leftovers(conn, tables, fallbackRetired, fallbackScope)
		},
		chainFault: func(chain int, held []nftables.Installed) (string, error) { return chainFault(conn, s, chain, held) },
	}
}

// faultOver folds the switch's reads over tables into a fallbackRead, and
// reports whether it found any of the switch's chains or sets
func faultOver(r fallbackReads, tables map[uint8]uint32) (out fallbackRead, found bool, err error) {
	read, err := r.contents(tables)
	if err != nil {
		return fallbackRead{}, false, err
	}
	leftovers, err := r.leftovers(tables)
	if err != nil {
		return fallbackRead{}, false, err
	}
	found = read.Held
	out = fallbackRead{remake: read.Remake()}
	for _, rule := range read.Rules {
		if rule.Spec == fallbackDrop {
			out.dropped, out.bytes = out.dropped+rule.Packets, out.bytes+rule.Bytes
		}
	}
	switch {
	case read.Fault != "":
		// the fault of a set the pass is refused on, which names what holds it, leads
		out.fault = cmp.Or(read.Refused, read.Fault)
		return out, found, nil
	case len(leftovers) > 0:
		out.fault = leftovers[0].Fault("the kill switch")
		return out, found, nil
	}
	for i := range fallbackChains {
		if out.fault, err = r.chainFault(i, read.Rules); err != nil {
			return fallbackRead{}, false, err
		}
		if out.fault != "" {
			break
		}
	}
	return out, found, nil
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
	lines := make([]nftables.Line, 0, len(want))
	for _, rule := range want {
		line := nftables.Line{Spec: rule.spec, Expressions: rule.expressions}
		if rule.anonymous != nil {
			line.Then = func(held nftables.Installed) (string, error) {
				sets := nftables.LookupSets(held.Expressions)
				if len(sets) != 1+rule.namedLookups {
					return fmt.Sprintf("its chain %s's line %s looks up %v, where %d lookups were written", name, rule.spec, sets, 1+rule.namedLookups), nil
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
				return "", nil
			}
		}
		lines = append(lines, line)
	}
	return nftables.ChainFault(name, lines, held)
}

// ReadFallback lists the switch through a socket of its own, independent of
// the reconciler's watch and its last read.
func ReadFallback() (FallbackDebug, error) {
	out := FallbackDebug{Where: tableForm.where, Hook: "postrouting, output and forward", Priority: fallbackPriority}
	conn, err := nftables.Dial()
	if err != nil {
		return out, err
	}
	defer conn.Close()
	tables, err := nftables.Tables(conn, nftables.Table)
	if err != nil {
		return out, err
	}
	read, err := nftables.Contents{Chains: fallbackChains}.Read(conn, tables, unix.NFPROTO_INET, fallbackScope)
	if err != nil {
		return out, err
	}
	if out.Held = read.Held; !out.Held {
		return out, nil
	}
	for _, rule := range read.Rules {
		out.Rules = append(out.Rules, FallbackDebugRule{Chain: rule.Chain, Spec: rule.Spec, Packets: rule.Packets, Bytes: rule.Bytes})
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

// readFallback reads the switch back, its chains missing from the table, or
// the table missing from tables, as a fault
func readFallback(conn *nftables.Conn, s fallbackSets, tables map[uint8]uint32) (nftables.Readback, error) {
	contents := fallbackContents
	contents.Elements = s.elements()
	read, err := contents.Read(conn, tables, unix.NFPROTO_INET, fallbackScope)
	if err != nil {
		return nftables.Readback{}, fmt.Errorf("kernel: read table inet %s: %w", nftables.Table, err)
	}
	// a flag on the table keeps the read's fault, which says whether a rewrite can mend the table
	if !holdsSwitch(read.Chains) && tables[unix.NFPROTO_INET] == 0 {
		read.Fault = "its chains are missing"
	}
	return read, nil
}

// holdsSwitch is whether chains, a table's, hold any chain of the switch
func holdsSwitch(chains []string) bool {
	return slices.ContainsFunc(fallbackChains, func(chain nftables.Chain) bool { return slices.Contains(chains, chain.Name) })
}

// deleteFallback removes the switch's chains and sets as
// nftables.Hold.Withdraw does, through the watch's socket, so its own delete
// wakes nothing, and closes the watch, which the next pass that asks for the
// switch opens again
func (p *netlinkPlatform) deleteFallback() error {
	conn, err := p.watchFallback()
	if err != nil {
		return err
	}
	_, err = p.fallbackHeld.Withdraw(conn, fallbackScope)
	return errors.Join(err, p.unwatchFallback())
}

// holdsFallback lists the table's chains through the watch's socket
func (p *netlinkPlatform) holdsFallback() (bool, error) {
	conn, err := p.watchFallback()
	if err != nil {
		return false, err
	}
	chains, err := nftables.TableChains(conn, unix.NFPROTO_INET, nftables.Table)
	if err != nil {
		return false, err
	}
	return holdsSwitch(chains), nil
}

// DeleteFallback deletes the switch an earlier instance left, for a start that
// runs no reconciler to delete it, and leaves the table, which such a start
// never held. A kernel without nf_tables holds none. A
// start without CAP_NET_ADMIN, which nfnetlink refuses with EPERM, cannot
// tell whether one is held, and warns as any other refusal. The overlay names
// darwin's holds and nothing here, where the holds are routes of ranet3's
// table, which no start without a reconciler touches.
func DeleteFallback(_ []schema.Prefix) {
	conn, err := nftables.Dial()
	if err == nil {
		var never nftables.Hold
		_, err = never.Withdraw(conn, fallbackScope)
		_ = conn.Close()
	}
	if err != nil && !withoutNFTables(err) {
		warnFallbackLeft(tableForm, err)
	}
}
