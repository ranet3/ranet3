// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package nftables

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
)

// A prefix's mask reads back with the boolean operation a dump writes for a
// bitwise expression written with none, as Linux does since it took
// NFTA_BITWISE_OP, and reads as written. A shift in its place does not.
func TestExpressionFaultReadsABitwiseBooleanOperationAsWritten(t *testing.T) {
	written := append(SourcePrefix(netip.MustParsePrefix("198.18.0.0/15")), CountedDrop()...)
	dumped := func(op uint32) []byte {
		var held []byte
		for _, expression := range written {
			name, data := expressionParts(Nested(expression)[0].Value)
			if name == "bitwise" {
				data = PutAttrBE32(data, bitwiseOp, op)
			}
			held = append(held, Expression(name, data)...)
		}
		return held
	}
	if fault := ExpressionFault(written, dumped(bitwiseBool)); fault != "" {
		t.Errorf("a mask dumped with its boolean operation reads %s", fault)
	}
	// NFT_BITWISE_LSHIFT
	if fault := ExpressionFault(written, dumped(1)); fault == "" {
		t.Error("a mask dumped as a shift reads as written")
	}
}

// A source translation to register 1 reads back with the range and the address
// mapping the kernel gives it, and the limit's dynset with the zero timeout and
// flags a dump writes and its connlimit nested with no NLA_F_NESTED, as nft_nat
// and nft_dynset dump them, and each reads as written. Another register's
// range, another flag, an inversion, a timeout or another count does not.
func TestExpressionFaultReadsANatAndADynsetAsTheKernelDumpsThem(t *testing.T) {
	nat := [][]byte{SourceLoad(unix.NFPROTO_IPV4), SourceNAT(unix.NFPROTO_IPV4)}
	natDumped := func(max, flags uint32) []byte {
		data := PutAttrBE32(PutAttrBE32(PutAttrBE32(nil, unix.NFTA_NAT_TYPE, unix.NFT_NAT_SNAT), unix.NFTA_NAT_FAMILY, unix.NFPROTO_IPV4), unix.NFTA_NAT_REG_ADDR_MIN, unix.NFT_REG_1)
		data = PutAttrBE32(PutAttrBE32(data, unix.NFTA_NAT_REG_ADDR_MAX, max), unix.NFTA_NAT_FLAGS, flags)
		return slices.Concat(SourceLoad(unix.NFPROTO_IPV4), dumped("nat", data))
	}
	limit := [][]byte{SourceLoad(unix.NFPROTO_IPV4), ConnectionsOver("flows4", 64)}
	limitDumped := func(timeout uint64, flags, count uint32) []byte {
		connlimit := PutAttrBE32(PutAttrBE32(nil, connlimitCount, count), connlimitFlags, connlimitInvert)
		data := PutAttrBE32(PutAttrBE32(nil, unix.NFTA_DYNSET_SREG_KEY, unix.NFT_REG_1), unix.NFTA_DYNSET_OP, unix.NFT_DYNSET_OP_ADD)
		data = PutAttr(PutAttrString(data, unix.NFTA_DYNSET_SET_NAME, "flows4"), unix.NFTA_DYNSET_TIMEOUT, binary.BigEndian.AppendUint64(nil, timeout))
		data = PutAttr(data, unix.NFTA_DYNSET_EXPR, PutAttr(PutAttrString(nil, unix.NFTA_EXPR_NAME, "connlimit"), unix.NFTA_EXPR_DATA, connlimit))
		return slices.Concat(SourceLoad(unix.NFPROTO_IPV4), dumped("dynset", PutAttrBE32(data, unix.NFTA_DYNSET_FLAGS, flags)))
	}
	for _, c := range []struct {
		name    string
		written [][]byte
		held    []byte
		differs bool
	}{
		{"a translation as the kernel dumps it", nat, natDumped(unix.NFT_REG_1, unix.NF_NAT_RANGE_MAP_IPS), false},
		{"a translation to a range of registers", nat, natDumped(unix.NFT_REG_2, unix.NF_NAT_RANGE_MAP_IPS), true},
		{"a translation of random ports", nat, natDumped(unix.NFT_REG_1, unix.NF_NAT_RANGE_MAP_IPS|unix.NF_NAT_RANGE_PROTO_RANDOM), true},
		{"the limit as the kernel dumps it", limit, limitDumped(0, 0, 64), false},
		{"the limit inverted", limit, limitDumped(0, unix.NFT_DYNSET_F_INV, 64), true},
		{"the limit with a timeout", limit, limitDumped(1000, 0, 64), true},
		{"the limit at another count", limit, limitDumped(0, 0, 65), true},
	} {
		if fault := ExpressionFault(c.written, c.held); (fault != "") != c.differs {
			t.Errorf("%s reads back with the fault %q, want one %v", c.name, fault, c.differs)
		}
	}
}

// A chain whose first line differs in what its Then reads and whose second
// differs in its expressions is named by its first line, and an error the
// first line's Then meets comes before the second line's fault, as a chain is
// read line by line
func TestChainFaultNamesTheFirstLineThatDiffers(t *testing.T) {
	first := append(SourcePrefix(netip.MustParsePrefix("192.0.2.0/24")), CountedDrop()...)
	second := append(SourcePrefix(netip.MustParsePrefix("198.51.100.0/24")), CountedDrop()...)
	other := append(SourcePrefix(netip.MustParsePrefix("203.0.113.0/24")), CountedDrop()...)
	held := []Installed{
		{Chain: "c", Spec: "first", Expressions: slices.Concat(first...)},
		{Chain: "c", Spec: "second", Expressions: slices.Concat(other...)},
	}
	for _, then := range []struct {
		fault string
		err   error
	}{
		{"the first line's set differs", nil},
		{"", errors.New("the first line's set cannot be read")},
	} {
		want := []Line{
			{Spec: "first", Expressions: first, Then: func(Installed) (string, error) { return then.fault, then.err }},
			{Spec: "second", Expressions: second},
		}
		fault, err := ChainFault("c", want, held)
		if fault != then.fault || err != then.err {
			t.Errorf("the chain reads %q, %v, want the first line's %q, %v", fault, err, then.fault, then.err)
		}
	}
}
