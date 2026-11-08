// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package userspace

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/netstack"
)

// An echo request's checksum is checked on both of the relay's paths, the
// lane's for a request whole and the stack's for one in fragments: a bad one
// is dropped and counted before any socket is readied. IPv6's stack drops a
// bad checksum itself before its handler, so that arm counts nothing of the
// relay's and readies nothing either. A good one reaches its mapping's socket,
// which the harness refuses, or the host where it gives this process none.
func TestEchoChecksumIsCheckedOnBothPaths(t *testing.T) {
	for _, family := range []struct {
		name         string
		leaf, server netip.Addr
	}{{"ipv4", leaf4, server4}, {"ipv6", leaf6, server6}} {
		refused := echoRefused(family.leaf.Is6())
		for _, bad := range []bool{false, true} {
			for _, fragmented := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s bad %t fragmented %t", family.name, bad, fragmented), func(t *testing.T) {
					h := newRelayHarness(t, nil)
					h.refuseAll = true
					size := 100
					if fragmented {
						size = 3000
					}
					message := echoRequest(family.leaf, family.server, 7, 1, bytes.Repeat([]byte{9}, size))
					if bad {
						message[2] ^= 0x5a
					}
					protocol := icmpProtocol(family.leaf)
					packets := [][]byte{ipPacket(family.leaf, family.server, protocol, message)}
					if fragmented {
						packets = fragments(family.leaf, family.server, protocol, 9, message, 1200)
					}
					for _, raw := range packets {
						h.x.handle(h.lane, raw)
					}
					prepared, dropped := h.preparedSoFar(), h.count(false, reasonICMPChecksum)
					switch {
					case !bad && refused:
						if len(prepared) != 0 || dropped != 0 || h.count(true, reasonEchoSocket) != 1 {
							t.Errorf("readied %v, dropped %d for the checksum and refused %d for the echo socket, want the host's one refusal", prepared, dropped, h.count(true, reasonEchoSocket))
						}
					case !bad:
						if want := []netip.AddrPort{netip.AddrPortFrom(family.server, 0)}; !slices.Equal(prepared, want) || h.count(true, reasonSocket) != 1 {
							t.Errorf("readied %v and refused %d for the socket, want the mapping's socket toward %s readied once", prepared, h.count(true, reasonSocket), family.server)
						}
					case family.leaf.Is6() && fragmented:
						if len(prepared) != 0 || dropped != 0 {
							t.Errorf("readied %v and dropped %d for the checksum, want nothing of the relay's", prepared, dropped)
						}
					default:
						if len(prepared) != 0 || dropped != 1 {
							t.Errorf("readied %v and dropped %d for the checksum, want nothing readied and one dropped", prepared, dropped)
						}
					}
				})
			}
		}
	}
}

// An echo mapping's socket holds the leaf's identifier where the host holds
// it free, and sends to every destination from it (RFC 5508 REQ-1a). Each
// reply comes back to the leaf from its server with the leaf's identifier and
// a checksum the exit computed, at the host's TTL or hop limit, its sequence
// number and data untouched.
// Another leaf with the same identifier has a mapping of its own on another
// identifier, and its replies come back with its own.
func TestEchoIsRelayedFromTheLeafsIdentifier(t *testing.T) {
	for _, family := range []struct {
		name        string
		leaf, other netip.Addr
		servers     []netip.Addr
	}{
		{"ipv4", leaf4, other4, []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.2")}},
		{"ipv6", leaf6, other6, []netip.Addr{netip.IPv6Loopback()}},
	} {
		t.Run(family.name, func(t *testing.T) {
			for _, server := range family.servers {
				_ = loopbackServer(t, server)
			}
			h := newRelayHarness(t, nil)
			h.x.SetHopLimits(hostTTL, hostHopLimit)
			id := freeIdentifiers(t, family.leaf.Is6(), 1)[0]
			seq := uint16(0)
			for _, ping := range []struct{ leaf, server netip.Addr }{
				{family.leaf, family.servers[0]}, {family.leaf, family.servers[len(family.servers)-1]}, {family.other, family.servers[0]},
			} {
				seq++
				payload := fmt.Appendf(nil, "echo %d", seq)
				h.x.echo.take(ipPacket(ping.leaf, ping.server, icmpProtocol(ping.leaf), echoRequest(ping.leaf, ping.server, id, seq, payload)))
				reply := h.waitLaid(t, fmt.Sprintf("reply %d from %s to %s", seq, ping.server, ping.leaf), func(raw []byte) bool {
					return isEchoReply(raw, ping.server, ping.leaf, id, seq, payload)
				})
				if got := hopsOf(reply); got != hostHops(ping.leaf) {
					t.Errorf("reply %d laid at %d, want the host's %d", seq, got, hostHops(ping.leaf))
				}
			}
			h.x.echo.mu.Lock()
			mine, theirs, n := h.x.echo.mappings[echoKey{family.leaf, id}], h.x.echo.mappings[echoKey{family.other, id}], len(h.x.echo.mappings)
			h.x.echo.mu.Unlock()
			if mine == nil || theirs == nil || n != 2 {
				t.Fatalf("%d mappings, the leaf's %t and the other's %t, want one each", n, mine != nil, theirs != nil)
			}
			if got := boundIdentifier(t, mine.socket); got != id {
				t.Errorf("the leaf's mapping took identifier %d for the leaf's %d, which the host held free", got, id)
			}
			if got := boundIdentifier(t, theirs.socket); got == id {
				t.Errorf("both leaves' mappings hold identifier %d", id)
			}
		})
	}
}

// An echo mapping under a class naming an address sends from that address,
// and under auto from the one the route to the server picks, its reply coming
// back to the leaf either way
func TestEchoLeavesFromTheAddressOfTheLeafsClass(t *testing.T) {
	server := netip.MustParseAddr("127.0.0.1")
	for _, c := range []struct {
		name string
		cfg  egress.Egress
		want netip.Addr
	}{
		{"auto", egress.Egress{}, netip.IPv4Unspecified()},
		{"an address", classed(netip.MustParseAddr("127.0.0.2")), netip.MustParseAddr("127.0.0.2")},
	} {
		t.Run(c.name, func(t *testing.T) {
			_ = loopbackServer(t, server)
			id := freeIdentifiers(t, false, 1)[0]
			h := newRelayHarness(t, nil)
			h.x.cfg.Translate = c.cfg.Translate
			h.x.echo.take(ipPacket(leaf4, server, protoICMP, echoRequest(leaf4, server, id, 1, []byte("from a class"))))
			h.waitLaid(t, "reply", func(raw []byte) bool { return isEchoReply(raw, server, leaf4, id, 1, []byte("from a class")) })
			h.x.echo.mu.Lock()
			m := h.x.echo.mappings[echoKey{leaf4, id}]
			h.x.echo.mu.Unlock()
			var sa unix.Sockaddr
			var err error
			if controlErr := m.socket.raw.Control(func(fd uintptr) { sa, err = unix.Getsockname(int(fd)) }); controlErr != nil || err != nil {
				t.Fatalf("the mapping's socket's address: %v %v", controlErr, err)
			}
			if got := sockaddrPort(sa).Addr(); got != c.want {
				t.Errorf("the mapping's socket is bound to %s, want %s", got, c.want)
			}
		})
	}
}

// An echo socket the platform refuses, as Android refuses one to an app
// outside ping_group_range, is answered administratively prohibited from the
// exit and counted, and opens no mapping and holds no flow
func TestRefusedEchoSocketIsAnsweredProhibited(t *testing.T) {
	for _, refusal := range []syscall.Errno{syscall.EACCES, syscall.EPERM} {
		t.Run(refusal.Error(), func(t *testing.T) {
			h := newRelayHarness(t, func(rt *Runtime, _ *egress.Egress) {
				rt.Platform.Prepare = func(string, netip.AddrPort, syscall.RawConn) error { return refusal }
			})
			raw := ipPacket(leaf4, server4, protoICMP, echoRequest(leaf4, server4, 7, 1, []byte("refused")))
			h.x.echo.take(raw)
			answers := h.mesh.answered()
			if len(answers) != 1 || answers[0].kind != netstack.ExitProhibited || !bytes.Equal(answers[0].offending, raw) {
				t.Errorf("answered %v, want administratively prohibited quoting the request", answers)
			}
			if got := h.count(true, reasonEchoSocket); got != 1 {
				t.Errorf("refused %d for the echo socket, want 1", got)
			}
			h.x.echo.mu.Lock()
			n := len(h.x.echo.mappings)
			h.x.echo.mu.Unlock()
			h.x.flows.mu.Lock()
			open := h.x.flows.open
			h.x.flows.mu.Unlock()
			if n != 0 || open != 0 {
				t.Errorf("%d mappings and %d flows after the refusal, want none", n, open)
			}
		})
	}
}

// An ICMP message from a leaf that is neither an echo request nor an error,
// as an extended echo request of RFC 8335, is dropped and counted as no echo
// on the lane's path, where the stack would drop it uncounted, and opens no
// mapping
func TestQueryNoEchoIsDroppedAndCountedOnTheLanesPath(t *testing.T) {
	h := newRelayHarness(t, nil)
	for _, c := range []struct {
		leaf, server netip.Addr
		kind         byte
	}{{leaf4, server4, 42}, {leaf6, server6, 160}} {
		message := echoRequest(c.leaf, c.server, 7, 1, []byte("an extended echo request"))
		message[0] = c.kind
		h.x.handle(h.lane, ipPacket(c.leaf, c.server, icmpProtocol(c.leaf), message))
	}
	if got := h.count(false, reasonNotEcho); got != 2 {
		t.Errorf("counted %d dropped as no echo, want both extended echo requests", got)
	}
	h.x.echo.mu.Lock()
	n := len(h.x.echo.mappings)
	h.x.echo.mu.Unlock()
	if n != 0 {
		t.Errorf("%d echo mappings after the drops, want none", n)
	}
}

// Echo mappings waiting for a reply hold no pooled buffer: a mapping's reader
// takes one only once its socket is readable, and gives it back once the
// reply has moved, so an idle mapping costs no 64 KiB against Within's
// perFlow
func TestIdleEchoMappingsHoldNoBuffer(t *testing.T) {
	server := netip.MustParseAddr("127.0.0.1")
	_ = loopbackServer(t, server)
	h := newRelayHarness(t, nil)
	ids := freeIdentifiers(t, false, 8)
	for i, id := range ids {
		h.x.echo.take(ipPacket(leaf4, server, icmpProtocol(leaf4), echoRequest(leaf4, server, id, 1, []byte("idle"))))
		h.waitLaid(t, fmt.Sprintf("reply %d", i), func(raw []byte) bool {
			return isEchoReply(raw, server, leaf4, id, 1, []byte("idle"))
		})
	}
	deadline := time.Now().Add(exitWait)
	for h.x.echo.out.Load() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("%d of %d idle echo mappings hold a pooled buffer", h.x.echo.out.Load(), len(ids))
		}
		time.Sleep(time.Millisecond)
	}
	h.x.echo.mu.Lock()
	n := len(h.x.echo.mappings)
	h.x.echo.mu.Unlock()
	if n != len(ids) {
		t.Errorf("%d echo mappings, want the %d idle ones", n, len(ids))
	}
}

// An IPv6 echo reply longer than the buffer it is read into past the leaf's
// header is dropped and counted, never carried cut with a checksum over what
// is left: the loopback answers a request of the largest ICMPv6 message
func TestEchoReplyTooLargeForItsBufferIsDropped(t *testing.T) {
	server := netip.IPv6Loopback()
	_ = loopbackServer(t, server)
	h := newRelayHarness(t, nil)
	id := freeIdentifiers(t, true, 1)[0]
	h.x.echo.take(ipPacket(leaf6, server, icmpProtocol(leaf6), echoRequest(leaf6, server, id, 1, make([]byte, 1<<16-1-8))))
	deadline := time.Now().Add(exitWait)
	for h.count(false, reasonEchoTooLarge) == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("no reply dropped as too large within %s, %d packets laid", exitWait, len(h.mesh.laidPackets()))
		}
		time.Sleep(10 * time.Millisecond)
	}
	for _, raw := range h.mesh.laidPackets() {
		if p, ok := parse(raw); ok && p.dst == leaf6 {
			t.Errorf("laid %s toward the leaf, want nothing", p)
		}
	}
}

// An echo mapping ends a minute after its last request out or reply in (RFC
// 5508 REQ-2), and gives its flow back
func TestEchoMappingEndsAMinuteAfterItsLastEcho(t *testing.T) {
	server := netip.MustParseAddr("127.0.0.1")
	_ = loopbackServer(t, server)
	h := newRelayHarness(t, nil)
	id := freeIdentifiers(t, false, 1)[0]
	ping := func(seq uint16) {
		payload := fmt.Appendf(nil, "echo %d", seq)
		h.x.echo.take(ipPacket(leaf4, server, protoICMP, echoRequest(leaf4, server, id, seq, payload)))
		h.waitLaid(t, fmt.Sprintf("reply %d", seq), func(raw []byte) bool { return isEchoReply(raw, server, leaf4, id, seq, payload) })
	}
	live := func() bool {
		h.x.echo.mu.Lock()
		defer h.x.echo.mu.Unlock()
		return h.x.echo.mappings[echoKey{leaf4, id}] != nil
	}
	ping(1)
	h.advance(59 * time.Second)
	if !live() {
		t.Fatal("the mapping ended 59 seconds after its last echo")
	}
	ping(2)
	h.advance(59 * time.Second)
	if !live() {
		t.Fatal("the mapping ended 59 seconds after an echo that kept it")
	}
	h.advance(2 * time.Second)
	if live() {
		t.Error("the mapping outlived a minute with no echo")
	}
	h.x.flows.mu.Lock()
	defer h.x.flows.mu.Unlock()
	if h.x.flows.open != 0 {
		t.Errorf("%d flows held once the mapping ended", h.x.flows.open)
	}
}

// A fragmented echo request in either family toward a server the leaf holds
// a TCP connection to reaches the relay once, through the stack's ICMP
// handler, draws the server's one reply toward the leaf, and nothing of
// gVisor's own. Its one mapping holds the identifier the leaf's kernel gave.
func TestFragmentedEchoWithATCPFlowOpenReachesTheRelayOnce(t *testing.T) {
	r := newLeafRig(t, func(rt Runtime) (*Exit, error) { return New(exitConfig(), rt) })
	r.allowEcho(t)
	for _, family := range rigFamilies {
		t.Run(family.name, func(t *testing.T) {
			server := r.listen(family.servers[0], 7, func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(io.Discard, conn)
			})
			conn, err := r.dial(netip.AddrPortFrom(family.leaf, 0), server, rigSettle)
			if err != nil {
				t.Fatalf("dial %s: %v", server, err)
			}
			defer conn.Close()
			if _, err := conn.Write([]byte("held open\n")); err != nil {
				t.Fatal(err)
			}
			stats := r.exit.stack.Stats().ICMP
			sent := stats.V4.PacketsSent.EchoReply.Value() + stats.V6.PacketsSent.EchoReply.Value()
			received := stats.V4.PacketsReceived.EchoRequest.Value() + stats.V6.PacketsReceived.EchoRequest.Value()
			ping := r.leafEcho(t, family.leaf.Is6())
			payload := bytes.Repeat([]byte{0xec}, leafMTU+200)
			message := make([]byte, 8+len(payload))
			message[0] = 8
			if family.leaf.Is6() {
				message[0] = 128
			}
			binary.BigEndian.PutUint16(message[6:8], 1)
			copy(message[8:], payload)
			var to unix.Sockaddr
			if family.leaf.Is6() {
				to = &unix.SockaddrInet6{Addr: server.Addr().As16()}
			} else {
				to = &unix.SockaddrInet4{Addr: server.Addr().As4()}
			}
			if err := unix.Sendto(ping, message, 0, to); err != nil {
				t.Fatalf("the leaf's echo to %s: %v", server.Addr(), err)
			}
			buf := make([]byte, 1<<16)
			n, _, err := unix.Recvfrom(ping, buf, 0)
			if err != nil {
				t.Fatalf("the leaf read no reply: %v", err)
			}
			if n != len(message) || binary.BigEndian.Uint16(buf[6:8]) != 1 || !bytes.Equal(buf[8:n], payload) {
				t.Errorf("the leaf read %d bytes, sequence %d, want the reply of %d bytes to sequence 1", n, binary.BigEndian.Uint16(buf[6:8]), len(message))
			}
			if got := stats.V4.PacketsSent.EchoReply.Value() + stats.V6.PacketsSent.EchoReply.Value(); got != sent {
				t.Errorf("gVisor sent %d echo replies of its own", got-sent)
			}
			if got := stats.V4.PacketsReceived.EchoRequest.Value() + stats.V6.PacketsReceived.EchoRequest.Value(); got != received+1 {
				t.Errorf("the stack took %d echo requests, want the one it reassembled", got-received)
			}
			bound, err := unix.Getsockname(ping)
			if err != nil {
				t.Fatal(err)
			}
			id := sockaddrPort(bound).Port()
			var mine []*echoMapping
			r.exit.echo.mu.Lock()
			for key, m := range r.exit.echo.mappings {
				if key.leaf == family.leaf {
					mine = append(mine, m)
				}
			}
			r.exit.echo.mu.Unlock()
			if len(mine) != 1 {
				t.Fatalf("%d echo mappings of %s, want one", len(mine), family.leaf)
			}
			if got := boundIdentifier(t, mine[0].socket); mine[0].key.id != id || got != id {
				t.Errorf("the mapping of identifier %d holds %d, want the leaf's %d, which this namespace held free", mine[0].key.id, got, id)
			}
		})
	}
}

// allowEcho lets this process's group open an ICMP datagram socket in this
// namespace and the leaf's, which a new namespace lets no group open. The
// range names only groups the user namespace maps.
func (r *leafRig) allowEcho(t *testing.T) {
	t.Helper()
	group := os.Getegid()
	allow := func() error {
		return os.WriteFile("/proc/sys/net/ipv4/ping_group_range", fmt.Appendf(nil, "%d %d\n", group, group), 0o644)
	}
	if err := allow(); err != nil {
		t.Fatalf("allow echo sockets here: %v", err)
	}
	if err := r.leaf.Do(allow); err != nil {
		t.Fatalf("allow echo sockets in the leaf's namespace: %v", err)
	}
}

// leafEcho is an ICMP datagram socket of the leaf's, opened in its namespace,
// whose reads wait at most exitWait
func (r *leafRig) leafEcho(t *testing.T, ipv6 bool) int {
	t.Helper()
	family, protocol := unix.AF_INET, unix.IPPROTO_ICMP
	if ipv6 {
		family, protocol = unix.AF_INET6, unix.IPPROTO_ICMPV6
	}
	var fd int
	err := r.leaf.Do(func() error {
		var err error
		fd, err = unix.Socket(family, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, protocol)
		return err
	})
	if err != nil {
		t.Fatalf("the leaf's echo socket: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	timeout := unix.NsecToTimeval(exitWait.Nanoseconds())
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout); err != nil {
		t.Fatal(err)
	}
	return fd
}

// freeIdentifiers is n distinct identifiers no ICMP datagram socket of the
// family holds now
func freeIdentifiers(t *testing.T, ipv6 bool, n int) []uint16 {
	t.Helper()
	var ids []uint16
	var held []*echoSocket
	defer func() {
		for _, s := range held {
			_ = s.close()
		}
	}()
	for range n {
		s, err := openEcho(ipv6, netip.Addr{}, 0, func(string, syscall.RawConn) error { return nil })
		if err != nil {
			t.Skipf("no echo socket for this process: %v", err)
		}
		held = append(held, s)
		ids = append(ids, boundIdentifier(t, s))
	}
	return ids
}

// echoRefused is whether the host gives this process no ICMP datagram socket
// of the family, as a new namespace gives none
func echoRefused(ipv6 bool) bool {
	s, err := openEcho(ipv6, netip.Addr{}, 0, func(string, syscall.RawConn) error { return nil })
	if err != nil {
		return true
	}
	_ = s.close()
	return false
}
