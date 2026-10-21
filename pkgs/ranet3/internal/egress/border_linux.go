// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package egress

import (
	"errors"
	"fmt"
	"net"
	"slices"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/nftables"
)

// borderTable is the border filter's linux backend: the inet table of this
// tool's name, holding the one filter chain at prerouting. An inet chain sees
// both families, so every rule matching an address tests the family first:
// unlike nft, which adds that test implicitly, the raw encoder spells it, or
// an IPv4 rule would read bytes 12 to 15 of an IPv6 header.
type borderTable struct {
	conn    *nftables.Conn
	monitor *nftables.Monitor
}

func newBorderBackend() (borderBackend, error) {
	conn, err := nftables.Dial()
	if err != nil {
		return nil, err
	}
	monitor, err := nftables.OpenMonitor(conn, borderTables)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return &borderTable{conn: conn, monitor: monitor}, nil
}

func (b *borderTable) Close() error { return errors.Join(b.monitor.Close(), b.conn.Close()) }

func (b *borderTable) Changed() <-chan struct{} { return b.monitor.Changed() }

func (b *borderTable) Missed() <-chan struct{} { return b.monitor.Missed() }

func (b *borderTable) Rules() (chainReadback, error) { return readBorder(b.conn) }

// Read dumps through a socket of its own, so the run goroutine's stays with
// its one user
func (b *borderTable) Read() (chainReadback, error) {
	conn, err := nftables.Dial()
	if err != nil {
		return chainReadback{}, err
	}
	defer conn.Close()
	return readBorder(conn)
}

func readBorder(conn *nftables.Conn) (chainReadback, error) {
	tables, err := nftables.Tables(conn, TableName)
	if err != nil {
		return chainReadback{}, err
	}
	read, err := prerouting.Read(conn, tables, unix.NFPROTO_INET)
	if err != nil {
		return chainReadback{}, fmt.Errorf("egress: read table inet %s: %w", TableName, err)
	}
	return readback(read, 0), nil
}

// prerouting is the border chain
var prerouting = nftables.Chain{Table: TableName, Name: BorderChain, Type: "filter", Hook: unix.NF_INET_PRE_ROUTING, Priority: rawPriority}

// Apply creates the table and the chain and rewrites the chain in one
// transaction, so no packet meets half a chain
func (b *borderTable) Apply(rules []BorderRule, remake bool) error {
	requests, err := borderBatch(rules, remake)
	if err != nil {
		return err
	}
	return b.conn.Batch(requests)
}

// borderBatch is the transaction Apply sends
func borderBatch(rules []BorderRule, remake bool) ([]nftables.Request, error) {
	var requests []nftables.Request
	if remake {
		requests = append(requests, delBorderTable())
	}
	requests = append(requests,
		nftables.NewTable(unix.NFPROTO_INET, TableName),
		prerouting.Create(unix.NFPROTO_INET),
		prerouting.Flush(unix.NFPROTO_INET))
	for _, rule := range rules {
		request, err := newBorderRule(rule)
		if err != nil {
			return nil, err
		}
		requests = append(requests, request)
	}
	return requests, nil
}

// Withdraw lists first, since deleting a table that is not there fails the
// batch
func (b *borderTable) Withdraw() error {
	tables, err := nftables.Tables(b.conn, TableName)
	if err != nil {
		return err
	}
	if _, held := tables[unix.NFPROTO_INET]; !held {
		return nil
	}
	return b.conn.Batch([]nftables.Request{delBorderTable()})
}

func delBorderTable() nftables.Request { return nftables.DeleteTable(unix.NFPROTO_INET, TableName) }

// newBorderRule counts only a drop, since a counter on an accept would be an
// update on every mesh packet
func newBorderRule(rule BorderRule) (nftables.Request, error) {
	var expressions [][]byte
	switch rule.Class {
	case BorderInside:
		if err := nftables.DeviceName(rule.Device); err != nil {
			return nftables.Request{}, err
		}
		expressions = append(nftables.MetaCompare(unix.NFT_META_IIFNAME, unix.NFT_CMP_EQ, rule.Device), verdict(nftables.Accept))
	case BorderSource:
		proto := uint8(unix.NFPROTO_IPV6)
		if rule.Source.Addr().Is4() {
			proto = unix.NFPROTO_IPV4
		}
		expressions = slices.Concat(nfproto(proto), nftables.SourcePrefix(rule.Source), countedDrop())
	case BorderRoutingHeader:
		// whether any routing header is present rather than its type: the
		// kernel's search finds only the first routing header, so a test of
		// the type would let one of type 0 or 2 hide a segment routing header
		// behind it. From Linux 7.1 the search gives up at the thirteenth
		// extension header, so one behind twelve others passes, and before
		// 7.1 it finds one anywhere
		exthdr := nftables.PutAttrBE32(nil, unix.NFTA_EXTHDR_DREG, unix.NFT_REG_1)
		exthdr = nftables.PutAttr(exthdr, unix.NFTA_EXTHDR_TYPE, []byte{unix.IPPROTO_ROUTING})
		exthdr = nftables.PutAttrBE32(exthdr, unix.NFTA_EXTHDR_OFFSET, 0)
		exthdr = nftables.PutAttrBE32(exthdr, unix.NFTA_EXTHDR_LEN, 1)
		exthdr = nftables.PutAttrBE32(exthdr, unix.NFTA_EXTHDR_FLAGS, unix.NFT_EXTHDR_F_PRESENT)
		expressions = slices.Concat(nfproto(unix.NFPROTO_IPV6),
			[][]byte{nftables.Expression("exthdr", exthdr), nftables.Expression("cmp", nftables.Compare(unix.NFT_CMP_EQ, []byte{1}))}, countedDrop())
	default:
		expressions = slices.Concat(nfproto(unix.NFPROTO_IPV6),
			[][]byte{nftables.NetworkLoad(ipv6DestinationOffset, net.IPv6len), nftables.Expression("cmp", nftables.Compare(unix.NFT_CMP_EQ, nftables.AddressBytes(rule.Destination)))},
			countedDrop())
	}
	return prerouting.Rule(unix.NFPROTO_INET, rule.String(), expressions)
}

// nfproto tests the packet's family, the nf_tables family an inet chain saw it in
func nfproto(proto uint8) [][]byte {
	return nftables.MetaCompareValue(unix.NFT_META_NFPROTO, unix.NFT_CMP_EQ, []byte{proto})
}

func countedDrop() [][]byte {
	return [][]byte{nftables.Expression("counter", nil), verdict(verdictDrop)}
}

// verdict ends the chain for a packet with code, NF_ACCEPT or NF_DROP
func verdict(code uint32) []byte {
	data := nftables.PutAttr(nil, unix.NFTA_DATA_VERDICT|unix.NLA_F_NESTED, nftables.PutAttrBE32(nil, unix.NFTA_VERDICT_CODE, code))
	immediate := nftables.PutAttrBE32(nil, unix.NFTA_IMMEDIATE_DREG, unix.NFT_REG_VERDICT)
	immediate = nftables.PutAttr(immediate, unix.NFTA_IMMEDIATE_DATA|unix.NLA_F_NESTED, data)
	return nftables.Expression("immediate", immediate)
}
