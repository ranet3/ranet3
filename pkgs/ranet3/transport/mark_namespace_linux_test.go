// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package transport

import (
	"encoding/binary"
	"net"
	"net/netip"
	"slices"
	"testing"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/nftables"
)

// Cilium's rule that sends a lookup marked for its L7 proxy, one whose mark reads localMark under localMask, at
// priorityLocal to tableLocal, which delivers every destination to the host itself (cilium/cilium pkg/proxy/routes.go)
const (
	priorityLocal = 9
	tableLocal    = 2004
	localMark     = 0x200
	localMask     = 0xf00
)

// masqueradeBit is kube-proxy's mark of a packet its nat chain at postrouting masquerades
const masqueradeBit = 0x4000

// natTable and natChain are the nat chain's, hooked at postrouting at srcnat as kube-proxy's nftables mode hooks it
const natTable = "kube-proxy"

var natChain = nftables.Chain{Table: natTable, Name: "nat-postrouting", Type: "nat", Hook: unix.NF_INET_POST_ROUTING, Priority: 100}

// the underlay's IKE and ESP datagrams leave by the uplink with the source address and port they were sent from,
// from the shared socket and from a pair's socket, in both families,
// beside Cilium's rule and kube-proxy's masquerade, which read bits of a mark under a mask
// so no bit of the underlay's mark lies in localMask or masqueradeBit,
// and the masquerade's counter, ahead of it in its rule, counts no packet
func TestUnderlayLeavesByTheUplinkPastRulesReadingOtherBitsOfItsMark(t *testing.T) {
	far, _, netlink := vethPair(t, 1, nearAddresses)
	// loopback is link 1 in every network namespace, and tableLocal's routes leave by it
	if err := netlink.configure(1, nil); err != nil {
		t.Fatalf("bring the loopback up: %v", err)
	}
	for _, family := range []byte{unix.AF_INET, unix.AF_INET6} {
		rule := []byte{family, 0, 0, 0, 0, 0, 0, unix.FR_ACT_TO_TBL, 0, 0, 0, 0}
		rule = slices.Concat(rule, attribute(unix.FRA_PRIORITY, word(priorityLocal)), attribute(unix.FRA_TABLE, word(tableLocal)),
			attribute(unix.FRA_FWMARK, word(localMark)), attribute(unix.FRA_FWMASK, word(localMask)))
		if err := netlink.request(unix.RTM_NEWRULE, unix.NLM_F_CREATE|unix.NLM_F_EXCL, rule); err != nil {
			t.Fatalf("add Cilium's rule at %d: %v", priorityLocal, err)
		}
		route := []byte{family, 0, 0, 0, unix.RT_TABLE_UNSPEC, unix.RTPROT_BOOT, unix.RT_SCOPE_HOST, unix.RTN_LOCAL, 0, 0, 0, 0}
		route = slices.Concat(route, attribute(unix.RTA_TABLE, word(tableLocal)), attribute(unix.RTA_OIF, word(1)))
		if err := netlink.request(unix.RTM_NEWROUTE, unix.NLM_F_CREATE|unix.NLM_F_EXCL, route); err != nil {
			t.Fatalf("add the local default in table %d: %v", tableLocal, err)
		}
	}
	conn := masquerade(t)

	hub, err := NewHub(":0", Underlay{}, Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	for i, address := range farAddresses {
		listener := far.listeners[i]
		mux, err := hub.NewMux(address.Addr().AsSlice(), listener.LocalAddr().(*net.UDPAddr).Port)
		if err != nil {
			t.Fatal(err)
		}
		want := netip.AddrPortFrom(nearAddresses[i].Addr(), hub.port)
		sent := func(socket string) {
			t.Helper()
			ike, esp := []byte("an IKE message from "+socket), []byte("an ESP packet from "+socket)
			if err := mux.SendIKE(ike); err != nil {
				t.Fatalf("an IKE message to %s from %s answered %v", address.Addr(), socket, err)
			}
			if from := readFrom(t, listener, slices.Concat(make([]byte, nonESPMarkerLen), ike)); from != want {
				t.Errorf("an IKE message to %s from %s arrived from %s, want %s", address.Addr(), socket, from, want)
			}
			if err := mux.SendESP(esp); err != nil {
				t.Fatalf("an ESP packet to %s from %s answered %v", address.Addr(), socket, err)
			}
			if from := readFrom(t, listener, esp); from != want {
				t.Errorf("an ESP packet to %s from %s arrived from %s, want %s", address.Addr(), socket, from, want)
			}
		}
		sent("the shared socket")
		if openNow(mux).socket.Load() == nil {
			t.Fatalf("the pair to %s opened no socket", address.Addr())
		}
		sent("the pair's socket")
	}
	read, err := nftables.Contents{Chains: []nftables.Chain{natChain}}.Read(conn, map[uint8]uint32{unix.NFPROTO_INET: 0}, unix.NFPROTO_INET)
	if err != nil {
		t.Fatal(err)
	}
	if len(read.Rules) != 1 || read.Rules[0].Packets != 0 {
		t.Errorf("the masquerade's rule reads back as %+v, want one that counted no packet", read.Rules)
	}
}

// masquerade writes kube-proxy's masquerade of a packet whose mark has masqueradeBit set, fully random, behind a counter,
// in natChain of an inet table, and answers the connection it wrote through
func masquerade(t *testing.T) *nftables.Conn {
	t.Helper()
	conn, err := nftables.Dial()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	mark := nftables.PutAttrBE32(nil, unix.NFTA_META_KEY, unix.NFT_META_MARK)
	mark = nftables.PutAttrBE32(mark, unix.NFTA_META_DREG, unix.NFT_REG_1)
	// meta mark is a host order word, which nft masks and compares as written
	bit := binary.NativeEndian.AppendUint32(nil, masqueradeBit)
	masked := nftables.PutAttrBE32(nil, unix.NFTA_BITWISE_SREG, unix.NFT_REG_1)
	masked = nftables.PutAttrBE32(masked, unix.NFTA_BITWISE_DREG, unix.NFT_REG_1)
	masked = nftables.PutAttrBE32(masked, unix.NFTA_BITWISE_LEN, uint32(len(bit)))
	masked = nftables.PutAttr(masked, unix.NFTA_BITWISE_MASK|unix.NLA_F_NESTED, nftables.PutAttr(nil, unix.NFTA_DATA_VALUE, bit))
	masked = nftables.PutAttr(masked, unix.NFTA_BITWISE_XOR|unix.NLA_F_NESTED, nftables.PutAttr(nil, unix.NFTA_DATA_VALUE, make([]byte, len(bit))))
	random := nftables.PutAttrBE32(nil, unix.NFTA_MASQ_FLAGS, unix.NF_NAT_RANGE_PROTO_RANDOM_FULLY)
	rule, err := natChain.Rule(unix.NFPROTO_INET, "meta mark & 0x4000 != 0 masquerade fully-random", [][]byte{
		nftables.Expression("meta", mark),
		nftables.Expression("bitwise", masked),
		nftables.Expression("cmp", nftables.Compare(unix.NFT_CMP_NEQ, make([]byte, len(bit)))),
		nftables.Expression("counter", nil),
		nftables.Expression("masq", random),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Batch([]nftables.Request{nftables.NewTable(unix.NFPROTO_INET, natTable), natChain.Create(unix.NFPROTO_INET), rule}); err != nil {
		t.Fatalf("write the nat chain: %v", err)
	}
	return conn
}
