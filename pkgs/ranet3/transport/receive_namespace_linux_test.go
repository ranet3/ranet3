// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package transport

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

// groFlood is how many datagrams each sender of the GRO test sends, enough that the near end's GRO coalesces some
const groFlood = 10000

// otherFarAddresses are a second address of each family on the far end, which the GRO test's third sender sends from
var otherFarAddresses = []netip.Prefix{netip.MustParsePrefix("192.0.2.4/24"), netip.MustParsePrefix("2001:db8::4/64")}

// three senders on the far end of a veth, two on two ports of one address and a third on another, send ESP at once to the hub's socket of each family
// GRO on the near end coalesces each sender's datagrams into messages of many, and the record of each datagram holds its own sender
func TestReceiveRecordSourcesUnderGRO(t *testing.T) {
	far, link, _ := vethPairTo(t, 3, nearAddresses, slices.Concat(farAddresses, otherFarAddresses))
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
	for family, socket := range []*udpSocket{bind.v4, bind.v6} {
		listeners := far.listeners[family*3 : family*3+3]
		froms := []netip.Addr{farAddresses[family].Addr(), farAddresses[family].Addr(), otherFarAddresses[family].Addr()}
		senders := make([]netip.AddrPort, len(listeners))
		for i, listener := range listeners {
			senders[i] = netip.AddrPortFrom(froms[i], uint16(listener.LocalAddr().(*net.UDPAddr).Port))
		}
		to := netip.AddrPortFrom(nearAddresses[family].Addr(), port)
		messages := receiveVector(espSendBatch)
		reader := newUDPReader(socket.raw, messages)
		coalesced := 0
		receive := socket.walk(messages, func() (int, error) {
			n, err := reader.read()
			for _, m := range messages[:n] {
				if segment, err := udpGROSize(m.OOB[:m.NN]); err == nil && segment > 0 && segment < m.N {
					coalesced++
				}
			}
			return n, err
		})
		bufs, sizes, endpoints, records := make([][]byte, espSendBatch), make([]int, espSendBatch), make([]Endpoint, espSendBatch), make([]receiveRecord, espSendBatch)
		got, total := make([]int, len(senders)), 0
		// read reads until want datagrams arrived in all, or none did for arrivalBudget, and checks the record of each
		read := func(want int) {
			for total < want {
				if err := socket.conn.SetReadDeadline(time.Now().Add(arrivalBudget)); err != nil {
					t.Fatal(err)
				}
				n, _, err := receive(bufs, sizes, endpoints, records)
				if errors.Is(err, os.ErrDeadlineExceeded) {
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				for i := range n {
					sender := bufs[i][4]
					if records[i].source != senders[sender] {
						t.Fatalf("a datagram of %s came with the source %v", senders[sender], records[i].source)
					}
					got[sender]++
				}
				total += n
			}
		}
		// the far end drops what it sends while it resolves the near end's address, so one datagram goes first and is read before the flood
		flood(t, listeners[0], 0, froms[0], to, 1)
		read(1)
		var sending sync.WaitGroup
		for i, listener := range listeners {
			sending.Go(func() { flood(t, listener, byte(i), froms[i], to, groFlood) })
		}
		read(len(senders)*groFlood + 1)
		sending.Wait()
		t.Logf("%v: received %v of %d sent by each, %d messages of more than one datagram", to, got, groFlood, coalesced)
		if slices.Contains(got, 0) {
			t.Errorf("a sender's datagrams never arrived: %v of %d each", got, groFlood)
		}
		if coalesced == 0 {
			t.Error("GRO coalesced no datagrams, so no read held a message of many")
		}
	}
}

// flood sends count ESP-shaped datagrams carrying sender from listener to to, from the address from
func flood(t *testing.T, listener *net.UDPConn, sender byte, from netip.Addr, to netip.AddrPort, count int) {
	var control []byte
	if from.Is4() {
		control = (&ipv4.ControlMessage{Src: from.AsSlice()}).Marshal()
	} else {
		control = (&ipv6.ControlMessage{Src: from.AsSlice()}).Marshal()
	}
	datagram := make([]byte, 64)
	binary.BigEndian.PutUint32(datagram, pairTestSPI)
	datagram[4] = sender
	for i := range count {
		binary.BigEndian.PutUint32(datagram[8:], uint32(i))
		if _, _, err := listener.WriteMsgUDPAddrPort(datagram, control, to); err != nil {
			t.Errorf("sender %d: %v", sender, err)
			return
		}
	}
}

func rawOf(t *testing.T, conn *net.UDPConn) syscall.RawConn {
	t.Helper()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// setOffload sets one of ethtool's legacy offload switches of the link name in the namespace of the socket raw
func setOffload(raw syscall.RawConn, name string, command, value uint32) error {
	setting := struct{ command, value uint32 }{command, value}
	var request struct {
		name [unix.IFNAMSIZ]byte
		data unsafe.Pointer
		_    [24 - unsafe.Sizeof(uintptr(0))]byte
	}
	copy(request.name[:], name)
	request.data = unsafe.Pointer(&setting)
	var errno syscall.Errno
	if err := raw.Control(func(fd uintptr) {
		_, _, errno = unix.Syscall(unix.SYS_IOCTL, fd, unix.SIOCETHTOOL, uintptr(unsafe.Pointer(&request)))
	}); err != nil {
		return err
	}
	if errno != 0 {
		return errno
	}
	return nil
}
