// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package transport

import (
	"net"
	"net/netip"
	"slices"
	"testing"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/netnstest"
	"ranet3.com/pkgs/ranet3/internal/nftables"
)

// the underlay's IKE and ESP datagrams leave by the uplink with the source address and port they were sent from,
// from the shared socket and from a pair's socket, in both families,
// beside Cilium's rule and kube-proxy's masquerade, which read bits of a mark under a mask
// so no bit of the underlay's mark lies in netnstest.CiliumMask or netnstest.KubeProxyBit,
// and the masquerade's counter, ahead of it in its rule, counts no packet
func TestUnderlayLeavesByTheUplinkPastRulesReadingOtherBitsOfItsMark(t *testing.T) {
	far, _, netlink := vethPair(t, 1, nearAddresses)
	// Cilium's table leaves by the loopback
	if err := netlink.configure(1, nil); err != nil {
		t.Fatalf("bring the loopback up: %v", err)
	}
	for _, family := range []byte{unix.AF_INET, unix.AF_INET6} {
		if err := netlink.request(unix.RTM_NEWRULE, unix.NLM_F_CREATE|unix.NLM_F_EXCL, netnstest.CiliumRule(family)); err != nil {
			t.Fatalf("add Cilium's rule at %d: %v", netnstest.CiliumPriority, err)
		}
		if err := netlink.request(unix.RTM_NEWROUTE, unix.NLM_F_CREATE|unix.NLM_F_EXCL, netnstest.CiliumLocal(family)); err != nil {
			t.Fatalf("add the local default in table %d: %v", netnstest.CiliumTable, err)
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
	read, err := nftables.Contents{Chains: []nftables.Chain{netnstest.KubeProxyNAT}}.Read(conn, map[uint8]uint32{unix.NFPROTO_INET: 0}, unix.NFPROTO_INET)
	if err != nil {
		t.Fatal(err)
	}
	if len(read.Rules) != 1 || read.Rules[0].Packets != 0 {
		t.Errorf("the masquerade's rule reads back as %+v, want one that counted no packet", read.Rules)
	}
}

// masquerade writes kube-proxy's masquerade and answers the connection it wrote through
func masquerade(t *testing.T) *nftables.Conn {
	t.Helper()
	conn, err := nftables.Dial()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	requests, err := netnstest.KubeProxyMasquerade()
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Batch(requests); err != nil {
		t.Fatalf("write the nat chain: %v", err)
	}
	return conn
}
