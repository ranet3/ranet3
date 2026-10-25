// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package egresstest

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

// message is an ICMP error's type and code in IPv4 and in IPv6
type message struct{ kind4, code4, kind6, code6 byte }

var (
	// destination unreachable for a network, a host, a port and a packet past
	// the next hop's MTU, by RFC 792's codes and RFC 4443 sections 3.1 and 3.2
	netUnreachable  = message{3, 0, 1, 0}
	hostUnreachable = message{3, 1, 1, 3}
	portUnreachable = message{3, 3, 1, 4}
	tooBig          = message{3, 4, 2, 0}
	// time exceeded in transit, RFC 792's and RFC 4443 section 3.3's
	hopExceeded = message{11, 0, 3, 0}
)

// rows runs the rows in one family against a running backend
type rows struct {
	network    Network
	family     Family
	class      Class
	exit       *running
	terminates bool
}

func (r *rows) v6() bool { return r.family.Leaf.Is6() }

// seen is the address the server reads the leaf's flows from
func (r *rows) seen() netip.Addr { return r.class.seen(r.family) }

func (r *rows) fromExit(address netip.Addr) bool { return slices.Contains(r.family.Exit, address) }

func (r *rows) fromRouter(address netip.Addr) bool { return address == r.family.Router }

// serverSees is row 1: the server reads the leaf's flows from the class's
// address, their bytes intact both ways, a half-close and a reset carried each
// way, and answers the leaf's echo. The outside port and identifier are the
// backend's to choose, since RFC 4787 section 4.2.1 has applications deal
// with both port preservation and none.
func (r *rows) serverSees(t *testing.T) {
	to := netip.AddrPortFrom(r.family.Server, serverSeesPort)
	listener := r.listen(t, to)
	t.Run("tcp half-closed by the leaf", func(t *testing.T) { r.halfClose(t, listener, to, true) })
	t.Run("tcp half-closed by the server", func(t *testing.T) { r.halfClose(t, listener, to, false) })
	t.Run("tcp reset by the leaf", func(t *testing.T) { r.reset(t, listener, to, true) })
	t.Run("tcp reset by the server", func(t *testing.T) { r.reset(t, listener, to, false) })
	t.Run("udp", func(t *testing.T) { r.udp(t, to) })
	t.Run("echo", func(t *testing.T) { r.echoTo(t, r.family.Server, echoID) })
}

func (r *rows) halfClose(t *testing.T, listener *net.TCPListener, to netip.AddrPort, byLeaf bool) {
	leaf, server := r.connect(t, listener, to, netip.AddrPort{})
	first, second, who := leaf, server, "leaf"
	if !byLeaf {
		first, second, who = server, leaf, "server"
	}
	sent := []byte("sent by the " + who + " before its half-close over " + r.family.Name)
	answered := []byte("answered after the " + who + "'s half-close over " + r.family.Name)
	write(t, first, sent)
	if err := first.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	readToEnd(t, second, sent)
	write(t, second, answered)
	if err := second.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	readToEnd(t, first, answered)
}

func (r *rows) reset(t *testing.T, listener *net.TCPListener, to netip.AddrPort, byLeaf bool) {
	leaf, server := r.connect(t, listener, to, netip.AddrPort{})
	sent := []byte("before the reset over " + r.family.Name)
	write(t, leaf, sent)
	readFull(t, server, sent)
	resetter, other, who := leaf, server, "leaf"
	if !byLeaf {
		resetter, other, who = server, leaf, "server"
	}
	if err := resetter.SetLinger(0); err != nil {
		t.Fatal(err)
	}
	if err := resetter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := other.SetReadDeadline(time.Now().Add(stepBudget)); err != nil {
		t.Fatal(err)
	}
	if _, err := other.Read(make([]byte, 1)); !errors.Is(err, syscall.ECONNRESET) {
		t.Errorf("after the %s's reset the other end read %v, want ECONNRESET", who, err)
	}
}

func (r *rows) udp(t *testing.T, to netip.AddrPort) {
	server := r.listenUDP(t, to)
	leaf := r.dialUDP(t, to)
	sent := []byte("a datagram over " + r.family.Name)
	answered := []byte("its answer over " + r.family.Name)
	from := receiveFrom(t, udpReader(server), sent, func() { _, _ = leaf.Write(sent) })
	if from.Addr() != r.seen() {
		t.Errorf("the server read the datagram from %s, want %s", from, r.seen())
	}
	receiveFrom(t, udpReader(leaf), answered, func() { _, _ = server.WriteToUDPAddrPort(answered, from) })
}

func (r *rows) echoTo(t *testing.T, server netip.Addr, id uint16) uint16 {
	t.Helper()
	protocol, request := syscall.IPPROTO_ICMP, byte(ipv4.ICMPTypeEcho)
	if r.v6() {
		protocol, request = syscall.IPPROTO_ICMPV6, byte(ipv6.ICMPTypeEchoRequest)
	}
	raw := r.serverIP(t, protocol, server)
	data := []byte("an echo to " + server.String())
	sent := echo(r.family.Leaf, server, id, data)
	back := len(r.network.Back())
	if !r.await(func() { r.exit.hand([][]byte{sent}) }, func(packet []byte) bool {
		p, ok := parse(packet)
		return ok && p.src == server && p.dst == r.family.Leaf && echoed(p, r.v6(), id, data)
	}) {
		t.Fatalf("no echo reply from %s came back toward the leaf within %s, only %s", server, stepBudget, answersIn(r.network.Back()[back:]))
	}
	if err := raw.SetReadDeadline(time.Now().Add(stepBudget)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, readSize)
	for {
		n, from, err := raw.ReadFromIP(buf)
		if err != nil {
			t.Fatalf("%s read no echo request: %v", server, err)
		}
		if n < 8 || buf[0] != request || !bytes.Equal(buf[8:n], data) {
			continue
		}
		if got := addrOf(from); got != r.seen() {
			t.Errorf("%s read the echo request from %s, want %s", server, got, r.seen())
		}
		return binary.BigEndian.Uint16(buf[4:])
	}
}

// errorsTowardTheLeaf is row 2: each error a flow of the leaf's meets comes
// back to the leaf from where it was raised, quoting the leaf's packet, the
// leaf's own error reaches the server from the class's address quoting the
// server's packet, and a protocol no rule names is carried rather than
// answered
func (r *rows) errorsTowardTheLeaf(t *testing.T) {
	t.Run("closed udp port", r.closedUDP)
	t.Run("closed tcp port", r.closedTCP)
	t.Run("unreachable host", func(t *testing.T) { r.unreachable(t, "host unreachable", r.family.NoHost, hostUnreachable) })
	t.Run("unreachable network", func(t *testing.T) { r.unreachable(t, "network unreachable", r.family.NoNetwork, netUnreachable) })
	t.Run("error from the leaf", r.leafError)
	t.Run("protocol no rule names", r.otherProtocol)
}

// closedUDP sends to a port nothing listens on, which the leaf's socket reads
// as refused, by a port unreachable from the server quoting a datagram of
// the leaf's
func (r *rows) closedUDP(t *testing.T) {
	to := netip.AddrPortFrom(r.family.Server, closedPort)
	leaf := r.dialUDP(t, to)
	port := addrPort(leaf.LocalAddr()).Port()
	sent := []byte("to a closed port over " + r.family.Name)
	handed, back := r.exit.handedCount(), len(r.network.Back())
	buf := make([]byte, readSize)
	refused := false
	if !until(func() {
		_, err := leaf.Write(sent)
		refused = refused || errors.Is(err, syscall.ECONNREFUSED)
	}, func(by time.Time) bool {
		if refused {
			return true
		}
		if err := leaf.SetReadDeadline(by); err != nil {
			t.Fatal(err)
		}
		_, err := leaf.Read(buf)
		refused = errors.Is(err, syscall.ECONNREFUSED)
		return refused
	}) {
		t.Fatalf("the leaf's socket to %s was not refused within %s, the answers being %s", to, stepBudget, answersIn(r.network.Back()[back:]))
	}
	var datagrams [][]byte
	for _, packet := range r.exit.handedSince(handed) {
		p, ok := parse(packet)
		if ok && p.dst == to.Addr() && p.protocol == syscall.IPPROTO_UDP && len(p.payload) >= 4 &&
			binary.BigEndian.Uint16(p.payload) == port && binary.BigEndian.Uint16(p.payload[2:]) == to.Port() {
			datagrams = append(datagrams, packet)
		}
	}
	if !slices.ContainsFunc(r.network.Back()[back:], func(packet []byte) bool {
		a, ok := readAnswer(packet)
		return ok && a.from == r.family.Server && a.is(r.v6(), portUnreachable) &&
			slices.ContainsFunc(datagrams, func(datagram []byte) bool { return quotes(a.quote, datagram) })
	}) {
		t.Errorf("no port unreachable from %s quoting one of the leaf's %d datagrams came back, only %s", r.family.Server, len(datagrams), answersIn(r.network.Back()[back:]))
	}
}

func (r *rows) closedTCP(t *testing.T) {
	to := netip.AddrPortFrom(r.family.Server, closedPort)
	back := len(r.network.Back())
	conn, err := r.tryDial(netip.AddrPort{}, to)
	if conn != nil {
		_ = conn.Close()
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Errorf("a connection to the closed %s got %v, want ECONNREFUSED", to, err)
	}
	if !slices.ContainsFunc(r.network.Back()[back:], func(packet []byte) bool {
		p, ok := parse(packet)
		// RST is the bit 0x04 of the flags in octet 13, RFC 9293 section 3.1
		return ok && p.src == to.Addr() && p.protocol == syscall.IPPROTO_TCP && len(p.payload) >= 20 &&
			binary.BigEndian.Uint16(p.payload) == to.Port() && p.payload[13]&0x04 != 0
	}) {
		t.Errorf("no reset from %s came back toward the leaf", to)
	}
}

func (r *rows) unreachable(t *testing.T, what string, to netip.Addr, want message) {
	sent := datagram(netip.AddrPortFrom(r.family.Leaf, unreachablePort), netip.AddrPortFrom(to, unreachablePort), leafTTL, []byte("toward "+to.String()))
	r.answered(t, what+" from the router", sent, want, r.fromRouter, 0)
}

// leafError opens a flow from the leaf and closes the leaf's socket, so the
// leaf's stack answers the server's next datagram with a port unreachable,
// which RFC 5508 REQ-5 has the exit carry out translated
func (r *rows) leafError(t *testing.T) {
	to := netip.AddrPortFrom(r.family.Server, leafErrorPort)
	server := r.listenUDP(t, to)
	leaf := r.dialUDP(t, to)
	opened := []byte("opens the flow over " + r.family.Name)
	outside := receiveFrom(t, udpReader(server), opened, func() { _, _ = leaf.Write(opened) })
	if err := leaf.Close(); err != nil {
		t.Fatal(err)
	}
	protocol := syscall.IPPROTO_ICMP
	if r.v6() {
		protocol = syscall.IPPROTO_ICMPV6
	}
	raw := r.serverIP(t, protocol, r.family.Server)
	data := []byte("into the closed flow over " + r.family.Name)
	// the datagram as the server's stack sends it, for the fields quotes compares
	sent := datagram(to, outside, leafTTL, data)
	buf := make([]byte, readSize)
	var from netip.Addr
	if !until(func() { _, _ = server.WriteToUDPAddrPort(data, outside) }, func(by time.Time) bool {
		if err := raw.SetReadDeadline(by); err != nil {
			t.Fatal(err)
		}
		for {
			n, address, err := raw.ReadFromIP(buf)
			if err != nil {
				return false
			}
			if n >= 8 && (answer{kind: buf[0], code: buf[1]}).is(r.v6(), portUnreachable) && quotes(buf[8:n], sent) {
				from = addrOf(address)
				return true
			}
		}
	}) {
		t.Fatalf("the server read no port unreachable quoting its datagram to %s within %s", outside, stepBudget)
	}
	if from != r.seen() {
		t.Errorf("the server read the leaf's port unreachable from %s, want %s", from, r.seen())
	}
}

// otherProtocol sends a packet of protocol 253, which RFC 3692 keeps for
// experiments and no rule of an exit names, and the server reads it from the
// class's address with nothing answering it
func (r *rows) otherProtocol(t *testing.T) {
	raw := r.serverIP(t, 253, r.family.Server)
	data := []byte("protocol 253 over " + r.family.Name)
	sent := ipPacket(r.family.Leaf, r.family.Server, 253, leafTTL, data)
	back := len(r.network.Back())
	if from := receiveFrom(t, ipReader(raw), data, func() { r.exit.hand([][]byte{sent}) }); from.Addr() != r.seen() {
		t.Errorf("the server read the packet of protocol 253 from %s, want %s", from.Addr(), r.seen())
	}
	time.Sleep(quietPeriod)
	for _, packet := range r.network.Back()[back:] {
		if a, ok := readAnswer(packet); ok && quotes(a.quote, sent) {
			t.Errorf("the packet of protocol 253 was answered with type %d code %d from %s", a.kind, a.code, a.from)
		}
	}
}

// pathMTU is row 3: a DF datagram past the exit's uplink answered from the
// exit with the uplink's MTU, an IPv4 datagram without DF past it fragmented
// and reaching the server whole, the answer of a router beyond the exit
// reaching the leaf translated, and a transfer completing over an uplink
// below the mesh's MTU
func (r *rows) pathMTU(t *testing.T) {
	from := netip.AddrPortFrom(r.family.Leaf, leafPathPort)
	t.Run("datagram past the uplink", func(t *testing.T) {
		sent := sized(from, netip.AddrPortFrom(r.family.Server, pathPort), r.family.MeshMTU)
		r.answered(t, "too big from the exit", sent, tooBig, r.fromExit, r.family.UplinkMTU)
	})
	if !r.v6() {
		// RFC 8200 section 4.5 leaves fragmenting to an IPv6 packet's source, so this is IPv4's alone
		t.Run("datagram without df past the uplink", func(t *testing.T) {
			to := netip.AddrPortFrom(r.family.Server, fragmentPort)
			server := r.listenUDP(t, to)
			sent := withoutDF(sized(from, to, r.family.MeshMTU))
			p, _ := parse(sent)
			back := len(r.network.Back())
			if got := receiveFrom(t, udpReader(server), p.payload[8:], func() { r.exit.hand([][]byte{sent}) }); got.Addr() != r.seen() {
				t.Errorf("the server read the datagram from %s, want %s", got, r.seen())
			}
			for _, packet := range r.network.Back()[back:] {
				if a, ok := readAnswer(packet); ok && quotes(a.quote, sent) {
					t.Errorf("the datagram without df was answered with type %d code %d from %s", a.kind, a.code, a.from)
				}
			}
		})
	}
	t.Run("router beyond the exit", func(t *testing.T) {
		sent := sized(from, netip.AddrPortFrom(r.family.Narrow, pathPort), (r.family.NarrowMTU+r.family.UplinkMTU)/2)
		r.answered(t, "too big from the router", sent, tooBig, r.fromRouter, r.family.NarrowMTU)
	})
	t.Run("tcp transfer", r.transfer)
}

func (r *rows) transfer(t *testing.T) {
	to := netip.AddrPortFrom(r.family.Transfer, pathPort)
	listener := r.listen(t, to)
	back := len(r.network.Back())
	leaf, server := r.connect(t, listener, to, netip.AddrPort{})
	deadline := time.Now().Add(transferBudget)
	for _, conn := range []*net.TCPConn{leaf, server} {
		if err := conn.SetDeadline(deadline); err != nil {
			t.Fatal(err)
		}
	}
	data := make([]byte, transferBytes)
	for i := range data {
		data[i] = byte(i)
	}
	echoed, sent := make(chan error, 1), make(chan error, 1)
	go func() { echoed <- echoAll(server) }()
	go func() {
		_, err := leaf.Write(data)
		if err == nil {
			err = leaf.CloseWrite()
		}
		sent <- err
	}()
	got, err := io.ReadAll(leaf)
	if err := errors.Join(err, <-sent, <-echoed); err != nil {
		t.Fatalf("the transfer through the exit: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("the transfer came back as %d bytes not all as sent, want the %d sent", len(got), len(data))
	}
	if r.terminates {
		// the backend's own connection carries the bytes past the uplink, and none of the leaf's segments meets it
		return
	}
	port := addrPort(leaf.LocalAddr()).Port()
	if !slices.ContainsFunc(r.network.Back()[back:], func(packet []byte) bool {
		a, ok := readAnswer(packet)
		if !ok || !a.is(r.v6(), tooBig) || !r.fromExit(a.from) || a.mtu != r.family.UplinkMTU {
			return false
		}
		protocol, src, dst, ok := ports(a.quote)
		return ok && protocol == syscall.IPPROTO_TCP && src == port && dst == to.Port()
	}) {
		t.Errorf("no too big from the exit with the uplink's MTU came back for the transfer's segments, so the transfer never met the uplink: %s", answersIn(r.network.Back()[back:]))
	}
}

// hopLimits is row 4: a datagram toward the server whose TTL or hop limit runs
// out at the exit is answered time exceeded from an address of the exit,
// which keeps the exit in a traceroute
func (r *rows) hopLimits(t *testing.T) {
	sent := datagram(netip.AddrPortFrom(r.family.Leaf, leafHopPort), netip.AddrPortFrom(r.family.Server, hopPort), 1, []byte("one hop over "+r.family.Name))
	r.answered(t, "time exceeded from the exit", sent, hopExceeded, r.fromExit, 0)
}

// portReuse is row 5: a leaf reconnecting from one port to one server just
// after the server closed first connects at once, and one leaf port or echo
// identifier toward two servers is read by both as one outside port or
// identifier, in UDP, in TCP and in echo
func (r *rows) portReuse(t *testing.T) {
	t.Run("reconnect from one port", r.reconnect)
	t.Run("udp from one port to two servers", r.udpPair)
	t.Run("tcp from one port to two servers", r.tcpPair)
	t.Run("echo from one identifier to two servers", r.echoPair)
}

// reconnect closes a connection from the server first, which holds the
// server's end and the exit's entry in TIME_WAIT, and connects again from
// the same port within reconnectBudget
func (r *rows) reconnect(t *testing.T) {
	to := netip.AddrPortFrom(r.family.Server, reconnectPort)
	local := netip.AddrPortFrom(r.family.Leaf, leafReusePort)
	listener := r.listen(t, to)
	leaf, server := r.connect(t, listener, to, local)
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if err := leaf.SetReadDeadline(time.Now().Add(stepBudget)); err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("where the server closed the leaf read %v, want the end", err)
	}
	if err := leaf.Close(); err != nil {
		t.Fatal(err)
	}
	var again *net.TCPConn
	var took time.Duration
	for deadline := time.Now().Add(stepBudget); again == nil; {
		began := time.Now()
		conn, err := r.tryDial(local, to)
		took = time.Since(began)
		switch {
		case err == nil:
			again = conn
		case errors.Is(err, syscall.EADDRNOTAVAIL) && time.Now().Before(deadline):
			// the leaf's own end of the first connection has not gone yet
			time.Sleep(pollInterval)
		default:
			t.Fatalf("reconnect from %s: %v", local, err)
		}
	}
	t.Cleanup(func() { _ = again.Close() })
	if took > reconnectBudget {
		t.Errorf("the reconnect from %s took %s, past %s, so its first SYN was lost", local, took, reconnectBudget)
	}
	if got := addrPort(accept(t, listener).RemoteAddr()); got.Addr() != r.seen() {
		t.Errorf("the server read the reconnect from %s, want %s", got, r.seen())
	}
}

func (r *rows) udpPair(t *testing.T) {
	leaf := r.bindUDP(t, netip.AddrPortFrom(r.family.Leaf, leafPairPort))
	var outside []netip.AddrPort
	for _, server := range []netip.Addr{r.family.Server, r.family.Second} {
		to := netip.AddrPortFrom(server, pairPort)
		conn := r.listenUDP(t, to)
		sent := []byte("from one port to " + server.String())
		outside = append(outside, receiveFrom(t, udpReader(conn), sent, func() { _, _ = leaf.WriteToUDPAddrPort(sent, to) }))
	}
	r.oneMapping(t, "datagrams", outside)
}

func (r *rows) tcpPair(t *testing.T) {
	local := netip.AddrPortFrom(r.family.Leaf, leafPairPort)
	var outside []netip.AddrPort
	for _, server := range []netip.Addr{r.family.Server, r.family.Second} {
		to := netip.AddrPortFrom(server, pairPort)
		_, conn := r.connect(t, r.listen(t, to), to, local)
		outside = append(outside, addrPort(conn.RemoteAddr()))
	}
	r.oneMapping(t, "connections", outside)
}

// echoPair is RFC 5508 REQ-1 a, one outside identifier for the leaf's toward
// every server
func (r *rows) echoPair(t *testing.T) {
	first, second := r.echoTo(t, r.family.Server, pairEchoID), r.echoTo(t, r.family.Second, pairEchoID)
	if first != second {
		t.Errorf("the two servers read the leaf's echo requests under the identifiers %d and %d, want one", first, second)
	}
}

// oneMapping holds the two servers to reading one leaf endpoint's flows from
// one outside endpoint, RFC 4787 REQ-1 and RFC 5382 REQ-1
func (r *rows) oneMapping(t *testing.T, what string, outside []netip.AddrPort) {
	t.Helper()
	if outside[0] != outside[1] || outside[0].Addr() != r.seen() {
		t.Errorf("the two servers read the leaf's %s from %s and %s, want one endpoint of %s", what, outside[0], outside[1], r.seen())
	}
}

// sessions hands the backend datagrams of several flows from as many
// goroutines at once, as each session's receive path calls Egress, and the
// server reads every one from the class's address
func (r *rows) sessions(t *testing.T) {
	to := netip.AddrPortFrom(r.family.Server, sessionsPort)
	server := r.listenUDP(t, to)
	sent := map[string][]byte{}
	for session := range concurrentSessions {
		for i := range sessionDatagrams {
			data := fmt.Sprintf("datagram %d of session %d over %s", i, session, r.family.Name)
			sent[data] = datagram(netip.AddrPortFrom(r.family.Leaf, uint16(leafSessionsPort+session)), to, leafTTL, []byte(data))
		}
	}
	read := map[string]netip.AddrPort{}
	buf := make([]byte, readSize)
	until(func() {
		var sessions sync.WaitGroup
		for session := range concurrentSessions {
			var batch [][]byte
			for i := range sessionDatagrams {
				data := fmt.Sprintf("datagram %d of session %d over %s", i, session, r.family.Name)
				if _, ok := read[data]; !ok {
					batch = append(batch, sent[data])
				}
			}
			sessions.Go(func() { r.exit.hand(batch) })
		}
		sessions.Wait()
	}, func(by time.Time) bool {
		if err := server.SetReadDeadline(by); err != nil {
			t.Fatal(err)
		}
		for len(read) < len(sent) {
			n, from, err := server.ReadFromUDPAddrPort(buf)
			if err != nil {
				return false
			}
			if _, ok := sent[string(buf[:n])]; ok {
				read[string(buf[:n])] = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
			}
		}
		return true
	})
	if len(read) != len(sent) {
		t.Fatalf("the server read %d of the %d datagrams handed from %d sessions at once within %s", len(read), len(sent), concurrentSessions, stepBudget)
	}
	for data, from := range read {
		if from.Addr() != r.seen() {
			t.Errorf("the server read %q from %s, want %s", data, from, r.seen())
		}
	}
}

func (r *rows) answered(t *testing.T, what string, sent []byte, want message, from func(netip.Addr) bool, mtu int) {
	t.Helper()
	back := len(r.network.Back())
	if !r.await(func() { r.exit.hand([][]byte{sent}) }, func(packet []byte) bool {
		a, ok := readAnswer(packet)
		return ok && a.is(r.v6(), want) && from(a.from) && (mtu == 0 || a.mtu == mtu) && quotes(a.quote, sent)
	}) {
		t.Fatalf("no %s quoting the leaf's packet came back within %s, only %s", what, stepBudget, answersIn(r.network.Back()[back:]))
	}
}

func (r *rows) await(send func(), match func(packet []byte) bool) bool {
	seen := len(r.network.Back())
	return until(send, func(by time.Time) bool {
		for ; time.Now().Before(by); time.Sleep(pollInterval) {
			for back := r.network.Back(); seen < len(back); seen++ {
				if match(back[seen]) {
					return true
				}
			}
		}
		return false
	})
}

func until(send func(), try func(by time.Time) bool) bool {
	for deadline := time.Now().Add(stepBudget); time.Now().Before(deadline); {
		send()
		if try(time.Now().Add(retryInterval)) {
			return true
		}
	}
	return false
}

func (r *rows) connect(t *testing.T, listener *net.TCPListener, to, local netip.AddrPort) (leaf, server *net.TCPConn) {
	t.Helper()
	leaf = r.dial(t, local, to)
	server = accept(t, listener)
	if got := addrPort(server.RemoteAddr()); got.Addr() != r.seen() {
		t.Errorf("the server read the connection from %s, want %s", got, r.seen())
	}
	return leaf, server
}

func (r *rows) dial(t *testing.T, local, to netip.AddrPort) *net.TCPConn {
	t.Helper()
	conn, err := r.tryDial(local, to)
	if err != nil {
		t.Fatalf("connect from the leaf to %s: %v", to, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func (r *rows) tryDial(local, to netip.AddrPort) (*net.TCPConn, error) {
	dialer := net.Dialer{Timeout: stepBudget}
	if local.IsValid() {
		dialer.LocalAddr, dialer.Control = net.TCPAddrFromAddrPort(local), reuse
	}
	var conn net.Conn
	var err error
	if inLeaf := r.network.Leaf(func() error {
		conn, err = dialer.Dial("tcp", to.String())
		return nil
	}); inLeaf != nil {
		return nil, inLeaf
	}
	if err != nil {
		return nil, err
	}
	return conn.(*net.TCPConn), nil
}

func (r *rows) listen(t *testing.T, at netip.AddrPort) *net.TCPListener {
	return open(t, r.network.Server, "listen at the server's "+at.String(), func() (*net.TCPListener, error) {
		return net.ListenTCP("tcp", net.TCPAddrFromAddrPort(at))
	})
}

func (r *rows) listenUDP(t *testing.T, at netip.AddrPort) *net.UDPConn {
	return open(t, r.network.Server, "listen at the server's "+at.String(), func() (*net.UDPConn, error) {
		return net.ListenUDP("udp", net.UDPAddrFromAddrPort(at))
	})
}

func (r *rows) dialUDP(t *testing.T, to netip.AddrPort) *net.UDPConn {
	return open(t, r.network.Leaf, "open a socket of the leaf's to "+to.String(), func() (*net.UDPConn, error) {
		return net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(to))
	})
}

func (r *rows) bindUDP(t *testing.T, local netip.AddrPort) *net.UDPConn {
	return open(t, r.network.Leaf, "open a socket of the leaf's at "+local.String(), func() (*net.UDPConn, error) {
		return net.ListenUDP("udp", net.UDPAddrFromAddrPort(local))
	})
}

func (r *rows) serverIP(t *testing.T, protocol int, at netip.Addr) *net.IPConn {
	network := fmt.Sprintf("ip4:%d", protocol)
	if r.v6() {
		network = fmt.Sprintf("ip6:%d", protocol)
	}
	return open(t, r.network.Server, fmt.Sprintf("open a socket of the server's for protocol %d at %s", protocol, at), func() (*net.IPConn, error) {
		return net.ListenIP(network, &net.IPAddr{IP: at.AsSlice()})
	})
}

func open[T io.Closer](t *testing.T, in func(func() error) error, what string, build func() (T, error)) T {
	t.Helper()
	var made T
	if err := in(func() (err error) {
		made, err = build()
		return err
	}); err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	t.Cleanup(func() { _ = made.Close() })
	return made
}

func accept(t *testing.T, listener *net.TCPListener) *net.TCPConn {
	t.Helper()
	if err := listener.SetDeadline(time.Now().Add(stepBudget)); err != nil {
		t.Fatal(err)
	}
	conn, err := listener.AcceptTCP()
	if err != nil {
		t.Fatalf("the server accepted no connection: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func write(t *testing.T, conn *net.TCPConn, data []byte) {
	t.Helper()
	if err := conn.SetWriteDeadline(time.Now().Add(stepBudget)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(data); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// readToEnd reads conn until the other end closed its sending side, which has to have sent data
func readToEnd(t *testing.T, conn *net.TCPConn, data []byte) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(stepBudget)); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read to the half-close: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("read %q up to the half-close, want %q", got, data)
	}
}

func readFull(t *testing.T, conn *net.TCPConn, data []byte) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(stepBudget)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(data))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("read %q, want %q", got, data)
	}
}

// echoAll writes back what conn reads until the other end closes its sending side, then closes its own
func echoAll(conn *net.TCPConn) error {
	buf := make([]byte, readSize)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			if _, werr := conn.Write(buf[:n]); werr != nil {
				return werr
			}
		}
		if err == io.EOF {
			return conn.CloseWrite()
		}
		if err != nil {
			return err
		}
	}
}

// reader reads one packet into buf until by, and where it came from
type reader func(buf []byte, by time.Time) (int, netip.AddrPort, error)

func udpReader(conn *net.UDPConn) reader {
	return func(buf []byte, by time.Time) (int, netip.AddrPort, error) {
		if err := conn.SetReadDeadline(by); err != nil {
			return 0, netip.AddrPort{}, err
		}
		n, from, err := conn.ReadFromUDPAddrPort(buf)
		return n, netip.AddrPortFrom(from.Addr().Unmap(), from.Port()), err
	}
}

// ipReader's packets come from an address alone, its port zero
func ipReader(conn *net.IPConn) reader {
	return func(buf []byte, by time.Time) (int, netip.AddrPort, error) {
		if err := conn.SetReadDeadline(by); err != nil {
			return 0, netip.AddrPort{}, err
		}
		n, from, err := conn.ReadFromIP(buf)
		if err != nil {
			return 0, netip.AddrPort{}, err
		}
		return n, netip.AddrPortFrom(addrOf(from), 0), nil
	}
}

func receiveFrom(t *testing.T, read reader, data []byte, send func()) netip.AddrPort {
	t.Helper()
	buf := make([]byte, readSize)
	var from netip.AddrPort
	if !until(send, func(by time.Time) bool {
		for {
			n, address, err := read(buf, by)
			if err != nil {
				return false
			}
			if bytes.Equal(buf[:n], data) {
				from = address
				return true
			}
		}
	}) {
		t.Fatalf("read no %q within %s", data, stepBudget)
	}
	return from
}

func readOnce(conn *net.UDPConn, data []byte, wait time.Duration) (netip.AddrPort, bool) {
	read, buf, by := udpReader(conn), make([]byte, readSize), time.Now().Add(wait)
	for {
		n, from, err := read(buf, by)
		if err != nil {
			return netip.AddrPort{}, false
		}
		if bytes.Equal(buf[:n], data) {
			return from, true
		}
	}
}

// reuse lets the leaf's sockets share one local port, as row 5 asks of them
func reuse(_, _ string, c syscall.RawConn) error {
	var err error
	if control := c.Control(func(fd uintptr) {
		err = errors.Join(unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1),
			unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1))
	}); control != nil {
		return control
	}
	return err
}

// id is the leaf's own, which the exit puts back in the reply
func echoed(p parsed, v6 bool, id uint16, data []byte) bool {
	protocol, reply := byte(syscall.IPPROTO_ICMP), byte(ipv4.ICMPTypeEchoReply)
	if v6 {
		protocol, reply = syscall.IPPROTO_ICMPV6, byte(ipv6.ICMPTypeEchoReply)
	}
	return p.protocol == protocol && len(p.payload) >= 8 && p.payload[0] == reply &&
		binary.BigEndian.Uint16(p.payload[4:]) == id && bytes.Equal(p.payload[8:], data)
}

// answersIn names each ICMP or ICMPv6 error among back, for a failure's message
func answersIn(back [][]byte) string {
	var named []string
	for _, packet := range back {
		if a, ok := readAnswer(packet); ok {
			named = append(named, fmt.Sprintf("type %d code %d from %s carrying %d", a.kind, a.code, a.from, a.mtu))
		}
	}
	if len(named) == 0 {
		return "none"
	}
	return strings.Join(named, ", ")
}

func addrPort(address net.Addr) netip.AddrPort {
	var ap netip.AddrPort
	switch a := address.(type) {
	case *net.TCPAddr:
		ap = a.AddrPort()
	case *net.UDPAddr:
		ap = a.AddrPort()
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

func addrOf(address *net.IPAddr) netip.Addr {
	a, _ := netip.AddrFromSlice(address.IP)
	return a.Unmap()
}
