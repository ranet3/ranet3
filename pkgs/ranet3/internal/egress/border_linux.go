// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package egress

import (
	"errors"
	"fmt"
	"slices"

	"golang.org/x/sys/unix"
)

// borderTable is the border filter's linux backend: the inet table of this
// tool's name, holding the one filter chain at prerouting. An inet chain sees
// both families, so every rule matching an address tests the family first:
// unlike nft, which adds that test implicitly, the raw encoder spells it, or
// an IPv4 rule would read bytes 12 to 15 of an IPv6 header.
type borderTable struct {
	conn    *nftConn
	monitor *changeMonitor
}

func newBorderBackend() (borderBackend, error) {
	conn, err := dialNetfilter()
	if err != nil {
		return nil, err
	}
	monitor, err := openChangeMonitor(conn.pid, borderTables)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return &borderTable{conn: conn, monitor: monitor}, nil
}

func (b *borderTable) Close() error { return errors.Join(b.monitor.Close(), b.conn.Close()) }

func (b *borderTable) Changed() <-chan struct{} { return b.monitor.changed }

func (b *borderTable) Missed() <-chan struct{} { return b.monitor.missed }

func (b *borderTable) Rules() (chainReadback, error) { return readBorder(b.conn) }

// Read dumps through a socket of its own, so the run goroutine's stays with
// its one user
func (b *borderTable) Read() (chainReadback, error) {
	conn, err := dialNetfilter()
	if err != nil {
		return chainReadback{}, err
	}
	defer conn.Close()
	return readBorder(conn)
}

func readBorder(conn *nftConn) (chainReadback, error) {
	tables, err := ownTables(conn)
	if err != nil {
		return chainReadback{}, err
	}
	read, err := readChain(conn, tables, unix.NFPROTO_INET, prerouting)
	if err != nil {
		return chainReadback{}, fmt.Errorf("egress: read table inet %s: %w", TableName, err)
	}
	return read, nil
}

// Apply creates the table and the chain and rewrites the chain in one
// transaction, so no packet meets half a chain
func (b *borderTable) Apply(rules []BorderRule, remake bool) error {
	requests, err := borderBatch(rules, remake)
	if err != nil {
		return err
	}
	return b.conn.batch(requests)
}

// borderBatch is the transaction Apply sends: the table deleted first where
// remake holds, the table and the chain created where absent and adopted
// where present, the table's flags and the chain's policy written over
// whatever another writer set, the chain emptied, then rules
func borderBatch(rules []BorderRule, remake bool) ([]nftRequest, error) {
	var requests []nftRequest
	if remake {
		requests = append(requests, tableRequest(unix.NFT_MSG_DELTABLE, 0, unix.NFPROTO_INET))
	}
	requests = append(requests,
		newTable(unix.NFPROTO_INET),
		baseChain(unix.NFPROTO_INET, prerouting),
		chainFlush(unix.NFPROTO_INET, BorderChain))
	for _, rule := range rules {
		request, err := newBorderRule(rule)
		if err != nil {
			return nil, err
		}
		requests = append(requests, request)
	}
	return requests, nil
}

// Withdraw deletes the inet table of this tool's name where one exists. It
// lists first, since deleting a table that is not there fails the batch.
func (b *borderTable) Withdraw() error {
	tables, err := ownTables(b.conn)
	if err != nil {
		return err
	}
	if _, held := tables[unix.NFPROTO_INET]; !held {
		return nil
	}
	return b.conn.batch([]nftRequest{tableRequest(unix.NFT_MSG_DELTABLE, 0, unix.NFPROTO_INET)})
}

// newBorderRule encodes one rule of the chain. Only a drop carries a counter,
// since a counter on an accept would be an update on every mesh packet. A
// rule whose device name fits spells a comment well inside the limit, so the
// device is the one length checked.
func newBorderRule(rule BorderRule) (nftRequest, error) {
	var expressions [][]byte
	switch rule.Class {
	case BorderInside:
		if err := deviceName(rule.Device); err != nil {
			return nftRequest{}, err
		}
		expressions = append(metaCompare(unix.NFT_META_IIFNAME, unix.NFT_CMP_EQ, rule.Device), verdict(chainAccept))
	case BorderSource:
		proto := uint8(unix.NFPROTO_IPV6)
		if rule.Source.Addr().Is4() {
			proto = unix.NFPROTO_IPV4
		}
		expressions = slices.Concat(nfproto(proto), sourcePrefix(rule.Source), countedDrop())
	case BorderRoutingHeader:
		// whether any routing header is present rather than its type: the
		// kernel's search finds only the first routing header, so a test of
		// the type would let one of type 0 or 2 hide a segment routing header
		// behind it. From Linux 7.1 the search gives up at the thirteenth
		// extension header, so one behind twelve others passes, and before
		// 7.1 it finds one anywhere
		exthdr := putAttrBE32(nil, unix.NFTA_EXTHDR_DREG, unix.NFT_REG_1)
		exthdr = putAttr(exthdr, unix.NFTA_EXTHDR_TYPE, []byte{unix.IPPROTO_ROUTING})
		exthdr = putAttrBE32(exthdr, unix.NFTA_EXTHDR_OFFSET, 0)
		exthdr = putAttrBE32(exthdr, unix.NFTA_EXTHDR_LEN, 1)
		exthdr = putAttrBE32(exthdr, unix.NFTA_EXTHDR_FLAGS, unix.NFT_EXTHDR_F_PRESENT)
		expressions = slices.Concat(nfproto(unix.NFPROTO_IPV6),
			[][]byte{expression("exthdr", exthdr), expression("cmp", compare(unix.NFT_CMP_EQ, []byte{1}))}, countedDrop())
	default:
		expressions = slices.Concat(nfproto(unix.NFPROTO_IPV6),
			[][]byte{networkLoad(ipv6DestinationOffset, ipv6AddressLen), expression("cmp", compare(unix.NFT_CMP_EQ, addressBytes(rule.Destination)))},
			countedDrop())
	}
	return ruleRequest(unix.NFPROTO_INET, BorderChain, rule.String(), expressions), nil
}

// nfproto tests the packet's family, the nf_tables family an inet chain saw it in
func nfproto(proto uint8) [][]byte {
	return metaCompareValue(unix.NFT_META_NFPROTO, unix.NFT_CMP_EQ, []byte{proto})
}

func countedDrop() [][]byte { return [][]byte{expression("counter", nil), verdict(verdictDrop)} }

// verdict ends the chain for a packet with code, NF_ACCEPT or NF_DROP
func verdict(code uint32) []byte {
	data := putAttr(nil, unix.NFTA_DATA_VERDICT|nlaNested, putAttrBE32(nil, unix.NFTA_VERDICT_CODE, code))
	immediate := putAttrBE32(nil, unix.NFTA_IMMEDIATE_DREG, unix.NFT_REG_VERDICT)
	immediate = putAttr(immediate, unix.NFTA_IMMEDIATE_DATA|nlaNested, data)
	return expression("immediate", immediate)
}
