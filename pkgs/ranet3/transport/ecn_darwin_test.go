// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin

package transport

import (
	"encoding/binary"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// setTrafficClass sets the TOS octet or traffic class raw's socket sends with
func setTrafficClass(t *testing.T, raw syscall.RawConn, ipv6 bool, class int) {
	t.Helper()
	level, option := unix.IPPROTO_IP, unix.IP_TOS
	if ipv6 {
		level, option = unix.IPPROTO_IPV6, unix.IPV6_TCLASS
	}
	var setErr error
	if err := raw.Control(func(fd uintptr) { setErr = unix.SetsockoptInt(int(fd), level, option, class) }); err != nil || setErr != nil {
		t.Fatalf("set the traffic class %#x: %v, %v", class, err, setErr)
	}
}

// the receiver's control buffer holds the packet info message and the outer TOS or traffic class of either family
func TestControlMessageSizeHoldsEveryMessage(t *testing.T) {
	for _, family := range []struct {
		name        string
		info, class int
	}{
		{"IPv4", unix.SizeofInet4Pktinfo, 1},
		{"IPv6", unix.SizeofInet6Pktinfo, 4},
	} {
		if need := unix.CmsgSpace(family.info) + unix.CmsgSpace(family.class); controlMessageSize < need {
			t.Errorf("%s needs %d bytes of control messages, the receiver holds %d", family.name, need, controlMessageSize)
		}
	}
}

// the record of each datagram holds the ECN field its sender set, under a DSCP whose bits the record leaves out, in both families
func TestDarwinRecordCarriesTheOuterECN(t *testing.T) {
	for i, family := range []struct{ network, loopback string }{{"udp4", "127.0.0.1"}, {"udp6", "::1"}} {
		t.Run(family.network, func(t *testing.T) {
			opened, receivers, port, err := listenPacketBind(0, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = opened.Close() })
			bind := opened.(*darwinBind)
			socket := []*darwinSocket{bind.v4, bind.v6}[i]
			if socket == nil {
				t.Fatalf("the bind opened no %s socket", family.network)
			}
			if err := socket.conn.SetReadDeadline(time.Now().Add(arrivalBudget)); err != nil {
				t.Fatal(err)
			}
			peer := listenPeer(t, family.network, family.loopback)
			raw, err := peer.SyscallConn()
			if err != nil {
				t.Fatal(err)
			}
			to := netip.AddrPortFrom(netip.MustParseAddr(family.loopback), port)
			bufs, sizes, endpoints, records := make([][]byte, 1), make([]int, 1), make([]Endpoint, 1), make([]receiveRecord, 1)
			for _, codepoint := range codepoints {
				setTrafficClass(t, raw, i == 1, ecnDSCP|int(codepoint))
				datagram := binary.BigEndian.AppendUint32(nil, pairTestSPI)
				if _, err := peer.WriteToUDPAddrPort(append(datagram, byte(codepoint)), to); err != nil {
					t.Fatal(err)
				}
				records[0] = receiveRecord{}
				if n, refused, err := receivers[i](bufs, sizes, endpoints, records); n != 1 || refused != 0 || err != nil {
					t.Fatalf("the read of a datagram sent with %d answered %d datagrams, %d refused and %v", codepoint, n, refused, err)
				}
				if records[0].ecn != codepoint {
					t.Errorf("a datagram sent with the ECN field %d came with %d", codepoint, records[0].ecn)
				}
			}
		})
	}
}
