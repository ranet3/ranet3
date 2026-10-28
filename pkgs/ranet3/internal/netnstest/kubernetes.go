// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package netnstest

import (
	"encoding/binary"
	"slices"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/nftables"
)

// Cilium's rule sending a lookup marked for its L7 proxy, one whose mark reads CiliumMark under CiliumMask, at CiliumPriority to
// CiliumTable, which delivers every destination to the host itself (cilium/cilium pkg/proxy/routes.go)
const (
	CiliumPriority = 9
	CiliumTable    = 2004
	CiliumMark     = 0x200
	CiliumMask     = 0xf00
)

// KubeProxyBit is kube-proxy's mark of a packet its nat chain at postrouting masquerades
const KubeProxyBit = 0x4000

// KubeProxyNAT is kube-proxy's nat chain, hooked at postrouting at srcnat as its nftables mode hooks it
var KubeProxyNAT = nftables.Chain{Table: "kube-proxy", Name: "nat-postrouting", Type: "nat", Hook: unix.NF_INET_POST_ROUTING, Priority: 100}

// CiliumRule is the body of an RTM_NEWRULE adding Cilium's rule in family
func CiliumRule(family byte) []byte {
	return slices.Concat([]byte{family, 0, 0, 0, 0, 0, 0, unix.FR_ACT_TO_TBL, 0, 0, 0, 0},
		Attr(unix.FRA_PRIORITY, U32(CiliumPriority)), Attr(unix.FRA_TABLE, U32(CiliumTable)),
		Attr(unix.FRA_FWMARK, U32(CiliumMark)), Attr(unix.FRA_FWMASK, U32(CiliumMask)))
}

// CiliumLocal is the body of an RTM_NEWROUTE adding CiliumTable's local default in family, which leaves by the loopback, link 1 in every
// network namespace
func CiliumLocal(family byte) []byte {
	return slices.Concat([]byte{family, 0, 0, 0, unix.RT_TABLE_UNSPEC, unix.RTPROT_BOOT, unix.RT_SCOPE_HOST, unix.RTN_LOCAL, 0, 0, 0, 0},
		Attr(unix.RTA_TABLE, U32(CiliumTable)), Attr(unix.RTA_OIF, U32(1)))
}

// KubeProxyMasquerade is the requests writing kube-proxy's masquerade of a packet whose mark has KubeProxyBit set, fully random, behind a
// counter, in KubeProxyNAT of an inet table
func KubeProxyMasquerade() ([]nftables.Request, error) {
	mark := nftables.PutAttrBE32(nil, unix.NFTA_META_KEY, unix.NFT_META_MARK)
	mark = nftables.PutAttrBE32(mark, unix.NFTA_META_DREG, unix.NFT_REG_1)
	// meta mark is a host order word, which nft masks and compares as written
	bit := binary.NativeEndian.AppendUint32(nil, KubeProxyBit)
	masked := nftables.PutAttrBE32(nil, unix.NFTA_BITWISE_SREG, unix.NFT_REG_1)
	masked = nftables.PutAttrBE32(masked, unix.NFTA_BITWISE_DREG, unix.NFT_REG_1)
	masked = nftables.PutAttrBE32(masked, unix.NFTA_BITWISE_LEN, uint32(len(bit)))
	masked = nftables.PutAttr(masked, unix.NFTA_BITWISE_MASK|unix.NLA_F_NESTED, nftables.PutAttr(nil, unix.NFTA_DATA_VALUE, bit))
	masked = nftables.PutAttr(masked, unix.NFTA_BITWISE_XOR|unix.NLA_F_NESTED, nftables.PutAttr(nil, unix.NFTA_DATA_VALUE, make([]byte, len(bit))))
	random := nftables.PutAttrBE32(nil, unix.NFTA_MASQ_FLAGS, unix.NF_NAT_RANGE_PROTO_RANDOM_FULLY)
	rule, err := KubeProxyNAT.Rule(unix.NFPROTO_INET, "meta mark & 0x4000 != 0 masquerade fully-random", [][]byte{
		nftables.Expression("meta", mark),
		nftables.Expression("bitwise", masked),
		nftables.Expression("cmp", nftables.Compare(unix.NFT_CMP_NEQ, make([]byte, len(bit)))),
		nftables.Expression("counter", nil),
		nftables.Expression("masq", random),
	})
	if err != nil {
		return nil, err
	}
	return []nftables.Request{nftables.NewTable(unix.NFPROTO_INET, KubeProxyNAT.Table), KubeProxyNAT.Create(unix.NFPROTO_INET), rule}, nil
}
