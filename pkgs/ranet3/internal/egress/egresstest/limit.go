// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package egresstest

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/egress"
)

// sourceLimit is row 6, RFC 6888 REQ-4 and REQ-11: a source holds at most the
// share Status says the capability runs, a new flow past it is refused from the
// exit and dropped while the flows it holds and another source's go on, and
// Status counts each refusal. The row will not fill conntrack's table where
// Status reads it.
func (r *rows) sourceLimit(t *testing.T) {
	status := r.exit.Status()
	limit := status.FlowsPerSource
	switch {
	case !r.family.Spare.IsValid():
		t.Fatal("the network gives the leaf no spare address")
	case limit != r.exit.cfg.SourceLimit():
		t.Fatalf("Status reads a limit of %d flows a source, want the %d the capability runs", limit, r.exit.cfg.SourceLimit())
	case limit <= 0 || spareFillPort+limit-1 > math.MaxUint16:
		t.Fatalf("Status reads a limit of %d flows a source, want one from 1 to the %d ports the spare address's flows leave from", limit, math.MaxUint16-spareFillPort+1)
	}
	if rules := status.Rules; rules != nil && rules.ConntrackCount != nil && rules.ConntrackMax != nil {
		count, most := *rules.ConntrackCount, *rules.ConntrackMax
		t.Logf("conntrack holds %d of its %d entries", count, most)
		if count+uint64(limit) >= most {
			t.Fatalf("conntrack holds %d of its %d entries, which a source's %d flows would fill", count, most, limit)
		}
	}
	before, mark := r.refused(status), r.exit.handedCount()
	to, refusedTo := netip.AddrPortFrom(r.family.Server, limitPort), netip.AddrPortFrom(r.family.Server, limitRefusedPort)
	server, refusedServer := r.listenUDP(t, to), r.listenUDP(t, refusedTo)
	if !t.Run("flows up to the limit", func(t *testing.T) { r.fill(t, server, to, limit) }) {
		return
	}
	refused := []byte("past the limit over " + r.family.Name)
	t.Run("the next flow refused", func(t *testing.T) {
		sent := datagram(netip.AddrPortFrom(r.family.Spare, spareRefusedPort), refusedTo, leafTTL, refused)
		r.answered(t, "refusal from the exit", sent, pastTheLimit, r.fromExit, 0)
	})
	t.Run("a later datagram of a flow it holds", func(t *testing.T) { r.later(t, server, to) })
	t.Run("a further flow refused", func(t *testing.T) {
		sent := datagram(netip.AddrPortFrom(r.family.Spare, spareFurtherPort), refusedTo, leafTTL, refused)
		r.answered(t, "refusal from the exit", sent, pastTheLimit, r.fromExit, 0)
		if from, ok := readOnce(refusedServer, refused, quietPeriod); ok {
			t.Errorf("the server read a datagram of a flow the limit refused from %s, which RFC 6888 REQ-11 has the exit drop", from)
		}
	})
	t.Run("a tcp connection refused at once", r.connectionRefused)
	t.Run("another source's flow", func(t *testing.T) {
		leaf := r.dialUDP(t, to)
		sent := []byte("from the leaf's own address over " + r.family.Name)
		if from := receiveFrom(t, udpReader(server), sent, func() { _, _ = leaf.Write(sent) }); from.Addr() != r.seen() {
			t.Errorf("the server read the leaf's own flow from %s, want %s", from, r.seen())
		}
	})
	t.Run("the refusals counted", func(t *testing.T) { r.counted(t, before, mark) })
}

// fill opens the spare address's first count flows to the server at to, a
// datagram each, handed in batches the server's socket holds
func (r *rows) fill(t *testing.T, server *net.UDPConn, to netip.AddrPort, count int) {
	began := time.Now()
	var longest time.Duration
	buf := make([]byte, readSize)
	for first := 0; first < count; first += fillBatch {
		batchBegan := time.Now()
		var batch []string
		unread := map[string][]byte{}
		for i := first; i < min(first+fillBatch, count); i++ {
			data := fmt.Sprintf("flow %d of the spare address over %s", i, r.family.Name)
			batch = append(batch, data)
			unread[data] = datagram(netip.AddrPortFrom(r.family.Spare, uint16(spareFillPort+i)), to, leafTTL, []byte(data))
		}
		if !until(func() {
			var packets [][]byte
			for _, data := range batch {
				if packet, ok := unread[data]; ok {
					packets = append(packets, packet)
				}
			}
			r.exit.hand(packets)
		}, func(by time.Time) bool {
			if err := server.SetReadDeadline(by); err != nil {
				t.Fatal(err)
			}
			for len(unread) > 0 {
				n, _, err := server.ReadFromUDPAddrPort(buf)
				if err != nil {
					return false
				}
				delete(unread, string(buf[:n]))
			}
			return true
		}) {
			t.Fatalf("the server read %d of the spare address's first %d flows within %s", first+len(batch)-len(unread), count, stepBudget)
		}
		longest = max(longest, time.Since(batchBegan))
	}
	t.Logf("the spare address opened its %d flows in %s, its longest batch in %s of the %s a batch may take", count, time.Since(began), longest, stepBudget)
}

// later sends a datagram of the spare address's first flow right after its
// refused one. A limit judging every packet of a flow nothing has answered
// would refuse it while the source's count still holds the refused flow.
func (r *rows) later(t *testing.T, server *net.UDPConn, to netip.AddrPort) {
	data := []byte("a later datagram of the spare address's first flow over " + r.family.Name)
	sent := datagram(netip.AddrPortFrom(r.family.Spare, spareFillPort), to, leafTTL, data)
	back := len(r.network.Back())
	receiveFrom(t, udpReader(server), data, func() { r.exit.hand([][]byte{sent}) })
	for _, packet := range r.network.Back()[back:] {
		if a, ok := readAnswer(packet); ok && quotes(a.quote, sent) {
			t.Errorf("the later datagram was answered with type %d code %d from %s before a copy sent again reached the server", a.kind, a.code, a.from)
		}
	}
}

// connectionRefused connects from the spare address, whose SYN the limit
// refuses as it does a datagram, and the connect fails at once with the error
// a Linux leaf reads from each family's refusal, net/ipv4/icmp.c's for host
// unreachable and net/ipv6/icmp.c's for administratively prohibited, since its
// TCP gives up a connection still opening on either, net/ipv4/tcp_ipv4.c
func (r *rows) connectionRefused(t *testing.T) {
	to := netip.AddrPortFrom(r.family.Server, limitTCPPort)
	want := syscall.EHOSTUNREACH
	if r.v6() {
		want = syscall.EACCES
	}
	began := time.Now()
	conn, err := tryDial(r.network.Leaf, netip.AddrPortFrom(r.family.Spare, 0), to, stepBudget)
	took := time.Since(began)
	if conn != nil {
		_ = conn.Close()
	}
	switch {
	case !errors.Is(err, want):
		t.Errorf("a connection from %s to %s past its limit got %v, want %v", r.family.Spare, to, err, want)
	case took > reconnectBudget:
		t.Errorf("the connection from %s past its limit failed after %s, past %s, so its first SYN went unanswered", r.family.Spare, took, reconnectBudget)
	}
}

// counted holds Status to a count of every packet the limit refused since
// mark, which the backend reads at its next pass
func (r *rows) counted(t *testing.T, before uint64, mark int) {
	for deadline := time.Now().Add(stepBudget); ; time.Sleep(pollInterval) {
		want, got := before+r.refusedPackets(mark), r.refused(r.exit.Status())
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("Status counts %d refused in %s, %d of them before the row, want the %d packets of the flows past the limit since", got, r.family.Name, before, want-before)
		}
	}
}

// refusedPackets is how many packets handed from the mark'th on belong to the
// spare address's flows past its limit: each copy of its refused datagrams and
// each SYN of its connection
func (r *rows) refusedPackets(mark int) uint64 {
	var n uint64
	for _, packet := range r.exit.handedSince(mark) {
		p, ok := parse(packet)
		if !ok || p.src != r.family.Spare || len(p.payload) < 2 {
			continue
		}
		if port := binary.BigEndian.Uint16(p.payload); p.protocol == syscall.IPPROTO_TCP || p.protocol == syscall.IPPROTO_UDP && (port == spareRefusedPort || port == spareFurtherPort) {
			n++
		}
	}
	return n
}

// refused is the family's count of packets refused past the limit in s
func (r *rows) refused(s egress.Status) uint64 {
	if r.v6() {
		return s.Refused6
	}
	return s.Refused4
}
