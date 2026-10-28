// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package transport

import (
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"testing"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/packet"
)

const (
	// ecnFlood is how many datagrams the ECN test's sender sends to each socket
	ecnFlood = 20000
	// ecnRun is how many datagrams in a row the ECN test's sender sends under one codepoint, in one segmented send
	ecnRun = 8
	// ecnDatagram is the size of each datagram the ECN test sends
	ecnDatagram = 64
)

// over a veth with GRO on at the near end, the far end sends ESP to the hub's socket of each family and to a pair, in runs under one ECN field each, cycling through all four under ecnDSCP
// each run leaves as one segmented send, so its datagrams reach the near end together and a message holds many of them
// every datagram's record holds the ECN field it was sent with, which its payload carries, so no message mixes two fields and a read of many messages reads each one's
func TestOuterECNReachesTheRecord(t *testing.T) {
	far, link, _ := vethPair(t, 1, nearAddresses)
	opened, _, port, err := listenPacketBind(0, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	bind := opened.(*udpBind)
	if err := setOffload(bind.v4.raw, link.Name, unix.ETHTOOL_SGRO, 1); err != nil {
		t.Fatalf("turn GRO on at the near end: %v", err)
	}
	// veth_skb_is_eligible_for_gro hands the peer's GRO nothing from a sender with TSO on, and only a socket in the far end's namespace reaches its link
	if err := setOffload(rawOf(t, far.listeners[0]), "far", unix.ETHTOOL_STSO, 0); err != nil {
		t.Fatalf("turn TSO off at the far end: %v", err)
	}
	for family, listener := range []*udpSocket{bind.v4, bind.v6} {
		sender := far.listeners[family]
		from := farAddresses[family].Addr()
		to := netip.AddrPortFrom(nearAddresses[family].Addr(), port)
		recordsHoldTheirECN(t, "the listener", listener, sender, from, to)
		paired, _, err := bind.connectPair(pairKey{remote: netip.AddrPortFrom(from, uint16(sender.LocalAddr().(*net.UDPAddr).Port)), local: to.Addr()})
		if err != nil {
			t.Fatalf("connect a pair to %s: %v", from, err)
		}
		recordsHoldTheirECN(t, "a pair", paired.(*udpPair).socket, sender, from, to)
		_ = paired.Close()
	}
}

// recordsHoldTheirECN floods socket from sender at from and checks the ECN field of each datagram's record and that GRO coalesced some
func recordsHoldTheirECN(t *testing.T, what string, socket *udpSocket, sender *net.UDPConn, from netip.Addr, to netip.AddrPort) {
	t.Helper()
	got := make([]int, len(codepoints))
	read, coalesced := groReader(t, socket, func(datagram []byte, record receiveRecord) {
		sent := packet.ECN(datagram[4])
		if record.ecn != sent {
			t.Fatalf("%s %v: datagram %d, sent with the ECN field %d, came with %d", what, to, binary.BigEndian.Uint32(datagram[8:]), sent, record.ecn)
		}
		got[sent]++
	})
	// the far end drops what it sends while it resolves the near end's address, so one datagram goes first and is read before the flood
	if err := sendECNRuns(sender, from, to, ecnRun); err != nil {
		t.Fatal(err)
	}
	read(1)
	// joined on a failed read as well, so the sender reports nothing after the test ends
	var sending sync.WaitGroup
	defer sending.Wait()
	sending.Go(func() {
		if err := sendECNRuns(sender, from, to, ecnFlood); err != nil {
			t.Error(err)
		}
	})
	read(ecnRun + ecnFlood)
	sending.Wait()
	t.Logf("%s %v: received %v by ECN field of %d sent, %d messages of more than one datagram", what, to, got, ecnRun+ecnFlood, *coalesced)
	for codepoint, n := range got {
		if n == 0 {
			t.Errorf("%s %v: no datagram sent with the ECN field %d arrived", what, to, codepoint)
		}
	}
	if *coalesced == 0 {
		t.Errorf("%s %v: GRO coalesced no datagrams, so no message held more than one", what, to)
	}
}

// sendECNRuns sends count ESP-shaped datagrams from sender at from to to, in runs of ecnRun under one ECN field each, cycling through the four under ecnDSCP
// each run is one send segmented by UDP_SEGMENT, and each datagram carries its ECN field in its fifth octet and its number from its ninth
func sendECNRuns(sender *net.UDPConn, from netip.Addr, to netip.AddrPort, count int) error {
	raw, err := sender.SyscallConn()
	if err != nil {
		return err
	}
	level, option := unix.IPPROTO_IP, unix.IP_TOS
	if from.Is6() {
		level, option = unix.IPPROTO_IPV6, unix.IPV6_TCLASS
	}
	control := appendUDPSegment(sourceControl(from), ecnDatagram)
	run := make([]byte, ecnRun*ecnDatagram)
	for first := 0; first < count; first += ecnRun {
		codepoint := codepoints[first/ecnRun%len(codepoints)]
		var setErr error
		if err := raw.Control(func(fd uintptr) { setErr = unix.SetsockoptInt(int(fd), level, option, ecnDSCP|int(codepoint)) }); err != nil {
			return err
		}
		if setErr != nil {
			return setErr
		}
		datagrams := min(ecnRun, count-first)
		for i := range datagrams {
			datagram := run[i*ecnDatagram : (i+1)*ecnDatagram]
			binary.BigEndian.PutUint32(datagram, pairTestSPI)
			datagram[4] = byte(codepoint)
			binary.BigEndian.PutUint32(datagram[8:], uint32(first+i))
		}
		if _, _, err := sender.WriteMsgUDPAddrPort(run[:datagrams*ecnDatagram], control, to); err != nil {
			return err
		}
	}
	return nil
}
