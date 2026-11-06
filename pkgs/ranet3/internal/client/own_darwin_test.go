// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package client

import (
	"bytes"
	"net"
	"net/netip"
	"testing"
	"time"
)

// the node startUTUN builds reaches utunAddress over UDP once its reconciler has put the address on the utun
// the datagram and its reply each leave by the utun, and the mesh writes each back, the tun holding the address cap.table assigns
func TestNodeOnARealUTUNReachesItsOwnAddress(t *testing.T) {
	requireRealUTUN(t)
	u := startUTUN(t, t.TempDir())
	waitFor(t, utunBudget, "the address on the utun", func() bool {
		address, _ := u.onUTUN(t)
		return address
	})
	own := utunAddress.Addr()
	was := u.node.Mesh.TransitCounters()
	server, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(own, 0)))
	if err != nil {
		t.Fatalf("listen on %s: %v", own, err)
	}
	defer server.Close()
	client, err := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial %s: %v", server.LocalAddr(), err)
	}
	defer client.Close()
	ask, answer := []byte("ask"), []byte("answer")
	if _, err := client.Write(ask); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	if err := server.SetReadDeadline(time.Now().Add(utunBudget)); err != nil {
		t.Fatal(err)
	}
	n, from, err := server.ReadFromUDPAddrPort(buf)
	if err != nil || !bytes.Equal(buf[:n], ask) {
		t.Fatalf("the datagram to %s read %q, %v, the mesh counting %+v", own, buf[:n], err, u.node.Mesh.TransitCounters())
	}
	if _, err := server.WriteToUDPAddrPort(answer, from); err != nil {
		t.Fatal(err)
	}
	if err := client.SetReadDeadline(time.Now().Add(utunBudget)); err != nil {
		t.Fatal(err)
	}
	if n, err := client.Read(buf); err != nil || !bytes.Equal(buf[:n], answer) {
		t.Fatalf("the reply from %s read %q, %v", own, buf[:n], err)
	}
	waitFor(t, utunBudget, "the datagram and its reply counted delivered", func() bool {
		return u.node.Mesh.TransitCounters().Delivered-was.Delivered >= 2
	})
}
