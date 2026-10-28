// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package egresstest

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// Flow is a flow a backend tracks, as Arm.Flows reads it
type Flow struct {
	// Protocol is the flow's transport protocol, and From and To its ends as
	// its first packet left its source, an echo's identifier in place of both
	// ports
	Protocol byte
	From, To netip.AddrPort
	// Phase is a TCP flow's
	Phase Phase
	// Left is how long the backend keeps the flow from the reading on with no
	// packet more, rounded down to the second
	Left time.Duration
}

// Phase is where a TCP flow stands, as RFC 5382 section 5 tells its phases
// apart: opening until each end has acknowledged the other's SYN,
// established until a FIN has gone each way, half closed among them, and
// closing after
type Phase int

const (
	// NoPhase is a flow of another protocol, and a TCP flow closed or reset,
	// which REQ-5 leaves out
	NoPhase Phase = iota
	Opening
	Established
	Closing
)

func (p Phase) String() string {
	switch p {
	case Opening:
		return "opening"
	case Established:
		return "established"
	case Closing:
		return "closing"
	}
	return "no phase"
}

// timer is a flow a step opened, the phase it leaves it in and the floor of
// its idle timer, which the backend owes the flow where held is set and keeps
// it below where held is not
type timer struct {
	protocol byte
	from     netip.Addr
	to       netip.AddrPort
	phase    Phase
	floor    time.Duration
	held     bool
}

// timers holds each flow a step leaves idle, read rather than waited out, to
// the floor RFC 4787 REQ-5, RFC 5382 REQ-5 and RFC 5508 REQ-2 set where the
// exit translates it, out of the mesh under a class that translates and into
// it under return whatever the class, and below that floor where it does not
// and for a datagram to a resolver, as REQ-5a lets it.
func (r *rows) timers(t *testing.T) {
	t.Run("udp with no answer", func(t *testing.T) { r.timerOut(t, unansweredPort, r.class != None) })
	t.Run("udp to a resolver", func(t *testing.T) { r.timerOut(t, resolverPort, false) })
	if r.class != None {
		t.Run("udp answered", r.timerAnswered)
	}
	t.Run("tcp opening", r.timerOpening)
	t.Run("tcp holding data unacknowledged", r.timerUnacked)
	t.Run("tcp half closed", r.timerHalfClosed)
	t.Run("tcp closing", r.timerClosing)
	t.Run("echo", r.timerEcho)
	t.Run("udp from the exit's own mesh address", r.timerOwnAddress)
	t.Run("udp into the mesh with no answer", func(t *testing.T) { r.timerInto(t, intoPort, true) })
	t.Run("udp into the mesh to a resolver", func(t *testing.T) { r.timerInto(t, resolverPort, false) })
	t.Run("tcp into the mesh opening", r.timerIntoOpening)
	t.Run("echo into the mesh", r.timerIntoEcho)
}

// timerOut has the leaf send the server a datagram at port, which the server
// reads and never answers
func (r *rows) timerOut(t *testing.T, port uint16, held bool) {
	to := netip.AddrPortFrom(r.family.Server, port)
	began := time.Now()
	r.sendUnanswered(t, r.network.Leaf, netip.Addr{}, to)
	r.keeps(t, began, timer{syscall.IPPROTO_UDP, r.family.Leaf, to, NoPhase, udpFloor, held})
}

// timerAnswered has the server answer the leaf's datagram, and the leaf send
// again once the flow has lasted answeredAge
func (r *rows) timerAnswered(t *testing.T) {
	to := netip.AddrPortFrom(r.family.Server, answeredPort)
	server, leaf := r.listenUDP(t, to), r.dialUDP(t, to)
	sent := []byte("answered over " + r.family.Name)
	outside := receiveFrom(t, udpReader(server), sent, func() { _, _ = leaf.Write(sent) })
	answer := []byte("the answer over " + r.family.Name)
	receiveFrom(t, udpReader(leaf), answer, func() { _, _ = server.WriteToUDPAddrPort(answer, outside) })
	time.Sleep(answeredAge)
	began := time.Now()
	again := []byte("sent again over " + r.family.Name)
	receiveFrom(t, udpReader(server), again, func() { _, _ = leaf.Write(again) })
	r.keeps(t, began, timer{syscall.IPPROTO_UDP, r.family.Leaf, to, NoPhase, udpFloor, true})
}

// timerOpening connects to an address nothing holds, whose SYN the router
// answers host unreachable, so the flow stays as its SYN left it
func (r *rows) timerOpening(t *testing.T) {
	to := netip.AddrPortFrom(r.family.NoHost, openingPort)
	began := time.Now()
	if conn, err := tryDial(r.network.Leaf, netip.AddrPort{}, to, stepBudget); err == nil {
		_ = conn.Close()
		t.Fatalf("the leaf connected to %s, which nothing holds", to)
	}
	r.keeps(t, began, timer{syscall.IPPROTO_TCP, r.family.Leaf, to, Opening, transitoryFloor, r.class != None})
}

// timerUnacked has the server send data whose acknowledgment the leaf's path
// loses
func (r *rows) timerUnacked(t *testing.T) {
	to := netip.AddrPortFrom(r.family.Server, unackedPort)
	leaf, server := r.connect(t, listen(t, r.network.Server, to), to, netip.AddrPort{})
	r.withhold(t, addrPort(leaf.LocalAddr()), addrPort(leaf.RemoteAddr()))
	began := time.Now()
	data := []byte("never acknowledged over " + r.family.Name)
	write(t, server, data)
	readFull(t, leaf, data)
	r.keeps(t, began, timer{syscall.IPPROTO_TCP, r.family.Leaf, to, Established, establishedFloor, r.class != None})
}

// timerHalfClosed has the server close its sending side, after which data can
// still go from the leaf
func (r *rows) timerHalfClosed(t *testing.T) {
	to := netip.AddrPortFrom(r.family.Server, halfClosedPort)
	leaf, server := r.connect(t, listen(t, r.network.Server, to), to, netip.AddrPort{})
	began := time.Now()
	if err := server.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	readToEnd(t, leaf, nil)
	r.keeps(t, began, timer{syscall.IPPROTO_TCP, r.family.Leaf, to, Established, establishedFloor, r.class != None})
}

// timerClosing has the leaf close its sending side, then the server, and the
// leaf's path lose its acknowledgment of the server's FIN, which the
// connection then waits for
func (r *rows) timerClosing(t *testing.T) {
	to := netip.AddrPortFrom(r.family.Server, closingPort)
	leaf, server := r.connect(t, listen(t, r.network.Server, to), to, netip.AddrPort{})
	if err := leaf.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	readToEnd(t, server, nil)
	r.withhold(t, addrPort(leaf.LocalAddr()), addrPort(leaf.RemoteAddr()))
	began := time.Now()
	if err := server.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	readToEnd(t, leaf, nil)
	r.keeps(t, began, timer{syscall.IPPROTO_TCP, r.family.Leaf, to, Closing, transitoryFloor, r.class != None})
}

func (r *rows) timerEcho(t *testing.T) {
	protocol := byte(syscall.IPPROTO_ICMP)
	if r.v6() {
		protocol = syscall.IPPROTO_ICMPV6
	}
	began := time.Now()
	r.echoTo(t, r.family.Server, timersEchoID)
	r.keeps(t, began, timer{protocol, r.family.Leaf, netip.AddrPortFrom(r.family.Server, timersEchoID), NoPhase, queryFloor, r.class != None})
}

// timerOwnAddress sends from the exit's own mesh address of the family, which
// leaves under the class the address falls in, as the leaf's would
func (r *rows) timerOwnAddress(t *testing.T) {
	own, to := r.ownMesh(t), netip.AddrPortFrom(r.family.Server, ownAddressPort)
	want := r.seen()
	if r.class == None {
		want = own
	}
	began := time.Now()
	if from := r.sendUnanswered(t, r.exit.host.Do, own, to); from.Addr() != want {
		t.Errorf("the server read the exit's own datagram from %s, want %s", from, want)
	}
	r.keeps(t, began, timer{syscall.IPPROTO_UDP, own, to, NoPhase, udpFloor, r.class != None})
}

// ownMesh is the exit's own mesh address of the family
func (r *rows) ownMesh(t *testing.T) netip.Addr {
	i := slices.IndexFunc(r.exit.host.Mesh, func(a netip.Addr) bool { return a.Is6() == r.v6() })
	if i < 0 {
		t.Fatalf("the exit holds no mesh address in %s", r.family.Name)
	}
	return r.exit.host.Mesh[i]
}

// returned is the address the leaf reads a flow into the mesh from under
// return: the address of the family's class from every source, and the exit's
// own mesh address where no such class names one
func (r *rows) returned(t *testing.T) netip.Addr {
	if r.class == Address {
		return r.family.Class
	}
	return r.ownMesh(t)
}

// timerInto has the server send the leaf a datagram at port, which the leaf
// reads and never answers
func (r *rows) timerInto(t *testing.T, port uint16, held bool) {
	to := netip.AddrPortFrom(r.family.Leaf, port)
	leaf := r.bindUDP(t, to)
	// from the server's address of the family, of the several it holds
	local := net.UDPAddrFromAddrPort(netip.AddrPortFrom(r.family.Server, 0))
	server := open(t, r.network.Server, "open a socket of the server's to "+to.String(), func() (*net.UDPConn, error) {
		return net.DialUDP("udp", local, net.UDPAddrFromAddrPort(to))
	})
	sent := []byte("never answered into the mesh over " + r.family.Name)
	began := time.Now()
	if from := receiveFrom(t, udpReader(leaf), sent, func() { _, _ = server.Write(sent) }); from.Addr() != r.returned(t) {
		t.Errorf("the leaf read the server's datagram from %s, want %s", from, r.returned(t))
	}
	r.keeps(t, began, timer{syscall.IPPROTO_UDP, r.family.Server, to, NoPhase, udpFloor, held})
}

// timerIntoOpening has the server connect to the leaf, whose answer the leaf's
// path loses, so the flow stays as the server's SYN left it
func (r *rows) timerIntoOpening(t *testing.T) {
	to := netip.AddrPortFrom(r.family.Leaf, intoOpeningPort)
	r.withhold(t, to, netip.AddrPort{})
	dialer := net.Dialer{Timeout: unansweredDial, LocalAddr: net.TCPAddrFromAddrPort(netip.AddrPortFrom(r.family.Server, 0))}
	began := time.Now()
	if err := r.network.Server(func() error {
		if conn, err := dialer.Dial("tcp", to.String()); err == nil {
			_ = conn.Close()
			return fmt.Errorf("the server connected to %s, whose answers are lost", to)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	r.keeps(t, began, timer{syscall.IPPROTO_TCP, r.family.Server, to, Opening, transitoryFloor, true})
}

// timerIntoEcho has the server send the leaf an echo, which the leaf answers
func (r *rows) timerIntoEcho(t *testing.T) {
	protocol, reply := byte(syscall.IPPROTO_ICMP), byte(ipv4.ICMPTypeEchoReply)
	if r.v6() {
		protocol, reply = syscall.IPPROTO_ICMPV6, byte(ipv6.ICMPTypeEchoReply)
	}
	raw := r.serverIP(t, int(protocol), r.family.Server)
	data := []byte("an echo into the mesh over " + r.family.Name)
	request := echo(r.family.Server, r.family.Leaf, intoEchoID, data)
	began := time.Now()
	if !until(func() {
		_, _ = raw.WriteToIP(request[headerLength(request):], &net.IPAddr{IP: r.family.Leaf.AsSlice()})
	}, func(by time.Time) bool {
		buf := make([]byte, readSize)
		for {
			if err := raw.SetReadDeadline(by); err != nil {
				return false
			}
			n, _, err := raw.ReadFromIP(buf)
			if err != nil {
				return false
			}
			if n >= 8 && buf[0] == reply && binary.BigEndian.Uint16(buf[4:]) == intoEchoID && bytes.Equal(buf[8:n], data) {
				return true
			}
		}
	}) {
		t.Fatalf("the server read no echo reply from %s within %s", r.family.Leaf, stepBudget)
	}
	r.keeps(t, began, timer{protocol, r.family.Server, netip.AddrPortFrom(r.family.Leaf, intoEchoID), NoPhase, queryFloor, true})
}

// sendUnanswered sends a datagram to to from a socket opened in, bound to from
// where from is valid, which the server reads and never answers, and returns
// where the server read it from
func (r *rows) sendUnanswered(t *testing.T, in func(func() error) error, from netip.Addr, to netip.AddrPort) netip.AddrPort {
	server := r.listenUDP(t, to)
	var local *net.UDPAddr
	if from.IsValid() {
		local = net.UDPAddrFromAddrPort(netip.AddrPortFrom(from, 0))
	}
	conn := open(t, in, "open a socket to "+to.String(), func() (*net.UDPConn, error) {
		return net.DialUDP("udp", local, net.UDPAddrFromAddrPort(to))
	})
	sent := []byte("never answered over " + r.family.Name)
	return receiveFrom(t, udpReader(server), sent, func() { _, _ = conn.Write(sent) })
}

// withhold has the leaf's path lose each segment the leaf sends from from, to
// to where to is valid, from now until the test ends
func (r *rows) withhold(t *testing.T, from, to netip.AddrPort) {
	set := func(withheld func(packet []byte) bool) {
		r.exit.mu.Lock()
		defer r.exit.mu.Unlock()
		r.exit.withheld = withheld
	}
	set(func(packet []byte) bool {
		p, ok := parse(packet)
		if !ok || p.protocol != syscall.IPPROTO_TCP || p.src != from.Addr() || len(p.payload) < 4 || binary.BigEndian.Uint16(p.payload) != from.Port() {
			return false
		}
		return !to.IsValid() || p.dst == to.Addr() && binary.BigEndian.Uint16(p.payload[2:]) == to.Port()
	})
	t.Cleanup(func() { set(nil) })
}

// keeps reads the flows the backend tracks and holds want's to its phase and
// to its floor, its timer set last since began
func (r *rows) keeps(t *testing.T, began time.Time, want timer) {
	t.Helper()
	flows, err := r.flows(r.exit.host)
	if err != nil {
		t.Fatalf("read the flows the backend tracks: %v", err)
	}
	// what the timer was set to is below what it lists plus this
	bound := time.Since(began) + leftRounding
	i := slices.IndexFunc(flows, func(f Flow) bool { return f.Protocol == want.protocol && f.From.Addr() == want.from && f.To == want.to })
	if i < 0 {
		t.Fatalf("the backend tracks no flow of protocol %d from %s to %s among its %d", want.protocol, want.from, want.to, len(flows))
	}
	got := flows[i]
	if got.Phase != want.phase {
		t.Errorf("the backend holds the flow %s, want %s", got.Phase, want.phase)
	}
	switch reaches := got.Left+bound > want.floor; {
	case want.held && !reaches:
		t.Errorf("the backend keeps the flow idle %s more, which falls short of the %s floor", got.Left, want.floor)
	case !want.held && reaches:
		t.Errorf("the backend keeps the flow idle %s more, which may reach the %s floor it keeps such a flow below", got.Left, want.floor)
	}
	t.Logf("%s left, %s", got.Left, got.Phase)
}
