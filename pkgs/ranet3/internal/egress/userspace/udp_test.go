// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package userspace

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"syscall"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/schema"
)

// loopbackProbeWait bounds the wait for a loopback server's datagram to itself
const loopbackProbeWait = time.Second

// relayHarness is an exit a test drives through its lanes' handling and its
// relays without Run, on a clock of its own, whose Prepare records each
// socket and readies only those toward loopback and those that only receive
type relayHarness struct {
	x    *Exit
	mesh *fakeMesh
	lane Lane

	mu       sync.Mutex
	clock    time.Time
	prepared []netip.AddrPort
	// refuseAll has Prepare refuse every socket, so none is opened
	refuseAll bool
}

func newRelayHarness(t *testing.T, change func(*Runtime, *egress.Egress)) *relayHarness {
	t.Helper()
	h := &relayHarness{mesh: newFakeMesh(), clock: time.Unix(1_000_000, 0)}
	p := &fakePlatform{routes4: true, routes6: true}
	rt := Runtime{Mesh: h.mesh, Platform: p.platform(), Limits: testLimits()}
	rt.Platform.Prepare = func(_ string, to netip.AddrPort, _ syscall.RawConn) error {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.prepared = append(h.prepared, to)
		if h.refuseAll || to.IsValid() && !to.Addr().IsLoopback() {
			return syscall.ENETUNREACH
		}
		return nil
	}
	cfg := exitConfig()
	if change != nil {
		change(&rt, &cfg)
	}
	x, err := New(cfg, rt)
	if err != nil {
		t.Fatal(err)
	}
	h.x = x
	x.answers = h.mesh.OpenLane()
	h.lane = h.mesh.OpenLane()
	x.udp.now, x.echo.now = h.now, h.now
	t.Cleanup(func() { closeWithin(t, x) })
	return h
}

func (h *relayHarness) now() time.Time {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.clock
}

// holdOnly has rt's platform hold addresses alone, on the link the relay
// harness routes by, as fakePlatform holds them
func holdOnly(rt *Runtime, addresses ...netip.Addr) {
	rt.Platform.Held = (&fakePlatform{held: addresses}).platform().Held
}

// advance moves the clock on by d and ends what is past its time then
func (h *relayHarness) advance(d time.Duration) {
	h.mu.Lock()
	h.clock = h.clock.Add(d)
	now := h.clock
	h.mu.Unlock()
	h.x.expire(now)
}

func (h *relayHarness) preparedSoFar() []netip.AddrPort {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.prepared)
}

// count is the exit's count of reason among the refused or the dropped
func (h *relayHarness) count(refused bool, reason string) uint64 {
	return countOf(h.x, refused, reason)
}

// countOf is x's count of reason among the refused or the dropped
func countOf(x *Exit, refused bool, reason string) uint64 {
	x.counts.mu.Lock()
	defer x.counts.mu.Unlock()
	if refused {
		return x.counts.refused[reason]
	}
	return x.counts.dropped[reason]
}

// fataler fails a test or a property's case
type fataler interface {
	Fatalf(format string, args ...any)
}

// waitLaid waits for a packet the exit sent toward a leaf that match picks,
// and reports it
func (h *relayHarness) waitLaid(t fataler, what string, match func(raw []byte) bool) []byte {
	deadline := time.Now().Add(exitWait)
	for time.Now().Before(deadline) {
		pkt := h.x.link.poll()
		if pkt == nil {
			time.Sleep(time.Millisecond)
			continue
		}
		view := pkt.ToView()
		raw := bytes.Clone(view.AsSlice())
		view.Release()
		h.x.link.release(pkt)
		if match(raw) {
			return raw
		}
	}
	t.Fatalf("no %s toward a leaf within %s", what, exitWait)
	return nil
}

// nextLaid is the next packet the exit sends toward a leaf within exitWait
func (h *relayHarness) nextLaid(t fataler, what string) []byte {
	return h.waitLaid(t, what, func([]byte) bool { return true })
}

// mappingOf is the external port of leaf's mapping, false where it has none
func (h *relayHarness) mappingOf(leaf netip.AddrPort) (uint16, bool) {
	h.x.udp.mu.RLock()
	defer h.x.udp.mu.RUnlock()
	m := h.x.udp.mappings[leaf]
	if m == nil {
		return 0, false
	}
	return m.port, true
}

// loopbackServer is a UDP socket on address's family's loopback, and skips
// the test where that loopback carries no datagram to the socket itself, as
// in a namespace whose loopback is down, which binds the address all the same
func loopbackServer(t *testing.T, address netip.Addr) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP(udpNetwork(address), net.UDPAddrFromAddrPort(netip.AddrPortFrom(address, 0)))
	if err != nil {
		t.Skipf("no loopback of %s to serve on: %v", address, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	probe := []byte("loopback probe")
	if _, err := conn.WriteToUDPAddrPort(probe, serverAt(conn)); err != nil {
		t.Skipf("the loopback of %s carries no datagram: %v", address, err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(loopbackProbeWait))
	buf := make([]byte, len(probe)+1)
	if n, err := conn.Read(buf); err != nil || !bytes.Equal(buf[:n], probe) {
		t.Skipf("the loopback of %s carries no datagram: %v", address, err)
	}
	_ = conn.SetReadDeadline(time.Time{})
	return conn
}

func serverAt(conn *net.UDPConn) netip.AddrPort {
	at := conn.LocalAddr().(*net.UDPAddr).AddrPort()
	return netip.AddrPortFrom(at.Addr().Unmap(), at.Port())
}

// readDatagramFrom reads the datagram holding payload on conn within
// exitWait, and reports where it came from
func readDatagramFrom(t fataler, conn *net.UDPConn, payload []byte) netip.AddrPort {
	buf := make([]byte, 1<<16)
	_ = conn.SetReadDeadline(time.Now().Add(exitWait))
	for {
		n, from, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			t.Fatalf("%s read no datagram of %d bytes: %v", serverAt(conn), len(payload), err)
		}
		if bytes.Equal(buf[:n], payload) {
			return netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		}
	}
}

// freeUDPPort is a port no UDP socket of address's family holds now
func freeUDPPort(t *testing.T, address netip.Addr) uint16 {
	t.Helper()
	conn, err := net.ListenUDP(udpNetwork(address), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	return uint16(conn.LocalAddr().(*net.UDPAddr).Port)
}

// isDatagram is whether raw is a UDP datagram from from to to holding payload
// whose checksum holds
func isDatagram(raw []byte, from, to netip.AddrPort, payload []byte) bool {
	p, ok := parse(raw)
	if !ok || p.protocol != protoUDP || netip.AddrPortFrom(p.src, p.srcPort) != from || netip.AddrPortFrom(p.dst, p.dstPort) != to {
		return false
	}
	header := 20
	if from.Addr().Is6() {
		header = 40
	}
	message := raw[header:]
	return bytes.Equal(message[8:], payload) && fold(sum(pseudo(from.Addr(), to.Addr(), protoUDP, len(message)), message)) == 0
}

// hostHopLimit stands in for a host's default hop limit other than the
// relayedTTL the exit starts at, and other than hostTTL, so a packet of one
// family carrying the other's shows
const hostHopLimit = 202

// hopsOf is raw's TTL, or its hop limit where it is an IPv6 packet
func hopsOf(raw []byte) uint8 {
	if raw[0]>>4 == 6 {
		return raw[7]
	}
	return raw[8]
}

// hostHops is hostTTL, or hostHopLimit where to is an IPv6 address
func hostHops(to netip.Addr) uint8 {
	if to.Is6() {
		return hostHopLimit
	}
	return hostTTL
}

// A UDP datagram's checksum is checked on both of the relay's paths, the
// lane's for a datagram whole and the stack's for one in fragments: a bad one
// and an IPv6 zero one are dropped and counted before any socket is readied,
// and an IPv4 zero one, which carries no checksum, goes on to its mapping
func TestUDPChecksumIsCheckedOnBothPaths(t *testing.T) {
	for _, family := range []struct {
		name         string
		leaf, server netip.Addr
	}{{"ipv4", leaf4, server4}, {"ipv6", leaf6, server6}} {
		for _, c := range []struct {
			name    string
			damage  func(message []byte)
			carried bool
		}{
			{"whole", func([]byte) {}, true},
			{"bad", func(m []byte) { m[6] ^= 0x5a }, false},
			{"zero", func(m []byte) { m[6], m[7] = 0, 0 }, family.leaf.Is4()},
		} {
			for _, fragmented := range []bool{false, true} {
				name := fmt.Sprintf("%s %s fragmented %t", family.name, c.name, fragmented)
				t.Run(name, func(t *testing.T) {
					h := newRelayHarness(t, nil)
					h.refuseAll = true
					leaf, server := netip.AddrPortFrom(family.leaf, 40000), netip.AddrPortFrom(family.server, 5300)
					size := 100
					if fragmented {
						size = 3000
					}
					message := udpMessage(leaf, server, bytes.Repeat([]byte{7}, size))
					c.damage(message)
					packets := [][]byte{ipPacket(family.leaf, family.server, protoUDP, message)}
					if fragmented {
						packets = fragments(family.leaf, family.server, protoUDP, 9, message, 1200)
					}
					for _, raw := range packets {
						h.x.handle(h.lane, raw)
					}
					prepared := h.preparedSoFar()
					if c.carried {
						if len(prepared) != 1 || prepared[0].IsValid() || h.count(true, reasonSocket) != 1 {
							t.Errorf("readied %v and refused %d for the socket, want the mapping's socket that only receives readied once", prepared, h.count(true, reasonSocket))
						}
						return
					}
					if len(prepared) != 0 || h.count(false, reasonUDPChecksum) != 1 {
						t.Errorf("readied %v and dropped %d for the checksum, want nothing readied and one dropped", prepared, h.count(false, reasonUDPChecksum))
					}
					if _, ok := h.mappingOf(leaf); ok {
						t.Error("a datagram whose checksum fails opened a mapping")
					}
				})
			}
		}
	}
}

// A leaf's mapping keeps the leaf's port where the host holds it free, toward
// every server, and takes another the host gives where a socket holds it or
// the process may not bind it. Every socket passes Prepare, the one that only
// receives with no destination, each destination's toward its server, and the
// probe of the route to the first destination toward it.
func TestMappingKeepsTheLeafsPortWhereFree(t *testing.T) {
	servers := []*net.UDPConn{loopbackServer(t, netip.MustParseAddr("127.0.0.1")), loopbackServer(t, netip.MustParseAddr("127.0.0.1"))}
	holder, err := net.ListenUDP("udp4", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	held := uint16(holder.LocalAddr().(*net.UDPAddr).Port)
	for _, c := range []struct {
		name string
		port uint16
		kept bool
	}{{"free", 0, true}, {"held by another socket", held, false}, {"refused to the process", 80, false}} {
		t.Run(c.name, func(t *testing.T) {
			if c.port == 0 {
				c.port = freeUDPPort(t, leaf4)
			}
			h := newRelayHarness(t, nil)
			leaf := netip.AddrPortFrom(leaf4, c.port)
			var outside uint16
			for i, server := range servers {
				payload := []byte(fmt.Sprintf("datagram %d of %s", i, c.name))
				h.x.udp.take(udpDatagram(leaf, serverAt(server), payload), false)
				from := readDatagramFrom(t, server, payload)
				if i == 0 {
					outside = from.Port()
				}
				if from.Port() != outside {
					t.Errorf("%s read the leaf's datagram from port %d, the first server from %d: two mappings", serverAt(server), from.Port(), outside)
				}
			}
			if !c.kept && outside == c.port {
				t.Skipf("this process binds port %d itself", c.port)
			}
			if kept := outside == c.port; kept != c.kept {
				t.Errorf("the mapping took port %d for the leaf's %d, kept %t, want %t", outside, c.port, kept, c.kept)
			}
			prepared := h.preparedSoFar()
			want := []netip.AddrPort{{}}
			if !c.kept {
				want = append(want, netip.AddrPort{})
			}
			// the first destination's route is probed for the mapping's address
			want = append(want, serverAt(servers[0]))
			for _, server := range servers {
				want = append(want, serverAt(server))
			}
			if !slices.Equal(prepared, want) {
				t.Errorf("Prepare readied sockets toward %v, want %v", prepared, want)
			}
		})
	}
}

// A source's share counts each destination one flow, its mapping riding with
// its first (RFC 6888 REQ-4), so a share of n carries n mappings of one
// destination each, and the datagram past it is answered past the limit and
// opens no mapping
func TestShareCountsEachDestinationOneFlow(t *testing.T) {
	const share = 3
	server := loopbackServer(t, netip.MustParseAddr("127.0.0.1"))
	h := newRelayHarness(t, func(_ *Runtime, cfg *egress.Egress) { cfg.FlowsPerSource = share })
	for i := range share {
		leaf := netip.AddrPortFrom(leaf4, freeUDPPort(t, leaf4))
		payload := []byte(fmt.Sprintf("mapping %d of the share", i))
		h.x.udp.take(udpDatagram(leaf, serverAt(server), payload), false)
		readDatagramFrom(t, server, payload)
	}
	if answers := h.mesh.answered(); len(answers) != 0 {
		t.Fatalf("answered %v within the share", answers)
	}
	past := netip.AddrPortFrom(leaf4, freeUDPPort(t, leaf4))
	raw := udpDatagram(past, serverAt(server), []byte("past the share"))
	h.x.udp.take(raw, false)
	answers := h.mesh.answered()
	if len(answers) != 1 || answers[0].kind != netstack.ExitPastLimit || !bytes.Equal(answers[0].offending, raw) {
		t.Errorf("answered %v past the share, want one past the limit quoting the datagram", answers)
	}
	if _, ok := h.mappingOf(past); ok {
		t.Error("the datagram past the share opened a mapping")
	}
}

// The exit's total bounds every source's flows together: with each source
// within its share, the flow past Limits.Flows is refused for the total,
// answered past the limit and opens no mapping, and a flow given back makes
// room for the next
func TestFlowPastTheTotalIsRefusedForTheTotal(t *testing.T) {
	const total = 2
	server := loopbackServer(t, netip.MustParseAddr("127.0.0.1"))
	h := newRelayHarness(t, func(rt *Runtime, _ *egress.Egress) { rt.Limits.Flows = total })
	for i, source := range []netip.Addr{leaf4, other4} {
		leaf := netip.AddrPortFrom(source, freeUDPPort(t, leaf4))
		payload := []byte(fmt.Sprintf("flow %d of the total", i))
		h.x.udp.take(udpDatagram(leaf, serverAt(server), payload), false)
		readDatagramFrom(t, server, payload)
	}
	past := netip.AddrPortFrom(leaf4, freeUDPPort(t, leaf4))
	raw := udpDatagram(past, serverAt(server), []byte("past the total"))
	h.x.udp.take(raw, false)
	answers := h.mesh.answered()
	if len(answers) != 1 || answers[0].kind != netstack.ExitPastLimit || !bytes.Equal(answers[0].offending, raw) {
		t.Errorf("answered %v past the total, want one past the limit quoting the datagram", answers)
	}
	if got := h.count(true, reasonTotal); got != 1 {
		t.Errorf("counted %d refused for the total, want 1", got)
	}
	if got := h.count(true, reasonShare); got != 0 {
		t.Errorf("counted %d refused for a share, want none within the shares", got)
	}
	if _, ok := h.mappingOf(past); ok {
		t.Error("the datagram past the total opened a mapping")
	}
	h.advance(mappingTimeout + mappingSweep)
	payload := []byte("after the flows ended")
	h.x.udp.take(udpDatagram(past, serverAt(server), payload), false)
	readDatagramFrom(t, server, payload)
	if _, ok := h.mappingOf(past); !ok {
		t.Error("the flows given back made no room for the next")
	}
}

// A mapping under a class naming an address sends from that address, its
// socket that only receives bound to it as well, and under auto from the
// address the route to the server picks
func TestMappingLeavesFromTheAddressOfTheLeafsClass(t *testing.T) {
	server := loopbackServer(t, netip.MustParseAddr("127.0.0.1"))
	for _, c := range []struct {
		name string
		cfg  egress.Egress
		want netip.Addr
	}{
		{"auto", egress.Egress{}, serverAt(server).Addr()},
		{"an address", classed(netip.MustParseAddr("127.0.0.2")), netip.MustParseAddr("127.0.0.2")},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newRelayHarness(t, nil)
			h.x.cfg.Translate = c.cfg.Translate
			leaf := netip.AddrPortFrom(leaf4, freeUDPPort(t, leaf4))
			payload := []byte("from the class of " + c.name)
			h.x.udp.take(udpDatagram(leaf, serverAt(server), payload), false)
			if from := readDatagramFrom(t, server, payload); from.Addr() != c.want {
				t.Errorf("the server read the datagram from %s, want %s", from, c.want)
			}
			h.x.udp.mu.RLock()
			m := h.x.udp.mappings[leaf]
			h.x.udp.mu.RUnlock()
			listening := netip.IPv4Unspecified()
			if c.cfg.Translate != nil {
				listening = c.want
			}
			if got := m.wildcard.LocalAddr().(*net.UDPAddr).AddrPort().Addr().Unmap(); got != listening {
				t.Errorf("the mapping receives on %s, want %s", got, listening)
			}
		})
	}
}

// pairedOf sets leaf's mapping's paired address to paired where it is valid,
// and reports the mapping and the address it held before
func (h *relayHarness) pairedOf(t *testing.T, leaf netip.AddrPort, paired netip.Addr) (*mapping, netip.Addr) {
	t.Helper()
	h.x.udp.mu.RLock()
	m := h.x.udp.mappings[leaf]
	h.x.udp.mu.RUnlock()
	if m == nil {
		t.Fatalf("%s holds no mapping", leaf)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	was := m.paired
	if paired.IsValid() {
		m.paired = paired
	}
	return m, was
}

// Under auto a mapping sends to every later destination from the address the
// route to its first picked, whatever the route to the later one picks, so one
// leaf's mapping leaves from one address (RFC 4787 REQ-2)
func TestMappingUnderAutoLeavesFromItsFirstDestinationsAddress(t *testing.T) {
	first := loopbackServer(t, netip.MustParseAddr("127.0.0.1"))
	later := loopbackServer(t, netip.MustParseAddr("127.0.0.2"))
	h := newRelayHarness(t, nil)
	leaf := netip.AddrPortFrom(leaf4, freeUDPPort(t, leaf4))
	h.x.udp.take(udpDatagram(leaf, serverAt(first), []byte("first")), false)
	from := readDatagramFrom(t, first, []byte("first"))
	// the address the route to the first destination picked, which on loopback
	// is the one every route picks, so it stands in for another
	paired := netip.MustParseAddr("127.0.0.3")
	if _, was := h.pairedOf(t, leaf, paired); was != from.Addr() {
		t.Fatalf("the mapping pairs %s, want %s, the address its first datagram left from", was, from.Addr())
	}
	h.x.udp.take(udpDatagram(leaf, serverAt(later), []byte("later")), false)
	if got := readDatagramFrom(t, later, []byte("later")); got != netip.AddrPortFrom(paired, from.Port()) {
		t.Errorf("the later destination read the datagram from %s, want %s, the mapping's address and port", got, netip.AddrPortFrom(paired, from.Port()))
	}
}

// A mapping under auto whose address the host no longer holds ends at its next
// destination rather than leave from another address, and the datagram opens
// a new mapping from the address the route picks
func TestMappingWhoseAddressIsGoneEnds(t *testing.T) {
	first := loopbackServer(t, netip.MustParseAddr("127.0.0.1"))
	later := loopbackServer(t, netip.MustParseAddr("127.0.0.2"))
	h := newRelayHarness(t, nil)
	leaf := netip.AddrPortFrom(leaf4, freeUDPPort(t, leaf4))
	h.x.udp.take(udpDatagram(leaf, serverAt(first), []byte("first")), false)
	from := readDatagramFrom(t, first, []byte("first"))
	// a documentation address no host holds
	gone, _ := h.pairedOf(t, leaf, netip.MustParseAddr("192.0.2.77"))
	h.x.udp.take(udpDatagram(leaf, serverAt(later), []byte("later")), false)
	if got := readDatagramFrom(t, later, []byte("later")); got.Addr() != from.Addr() {
		t.Errorf("the later destination read the datagram from %s, want an address of %s, the route's", got, from.Addr())
	}
	m, paired := h.pairedOf(t, leaf, netip.Addr{})
	gone.mu.RLock()
	closed := gone.closed
	gone.mu.RUnlock()
	if m == gone || !closed || paired != from.Addr() {
		t.Errorf("the mapping is the old one %t, the old one closed %t, pairing %s, want a new mapping pairing %s", m == gone, closed, paired, from.Addr())
	}
}

// Two classes' mappings hold one port, each on its own class's address, and
// the index finds each on its address and neither on an address no class
// names. Ending one leaves the other found.
func TestTwoClassesHoldOnePortEachOnItsAddress(t *testing.T) {
	first, second := netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("127.0.0.3")
	server := loopbackServer(t, netip.MustParseAddr("127.0.0.1"))
	port := freeUDPPortOn(t, first, second)
	h := newRelayHarness(t, nil)
	h.x.cfg.Translate = []egress.Class{
		{From: schema.PrefixFrom(netip.PrefixFrom(leaf4, 32)), To: egress.Translation{Addr: first}},
		{From: schema.PrefixFrom(netip.PrefixFrom(other4, 32)), To: egress.Translation{Addr: second}},
	}
	firstLeaf, secondLeaf := netip.AddrPortFrom(leaf4, port), netip.AddrPortFrom(other4, port)
	h.x.udp.take(udpDatagram(firstLeaf, serverAt(server), []byte("first")), false)
	readDatagramFrom(t, server, []byte("first"))
	h.advance(time.Minute)
	h.x.udp.take(udpDatagram(secondLeaf, serverAt(server), []byte("second")), false)
	readDatagramFrom(t, server, []byte("second"))
	found := func(address netip.Addr) netip.AddrPort {
		h.x.udp.mu.RLock()
		defer h.x.udp.mu.RUnlock()
		if m := h.x.udp.holding(address, port); m != nil {
			return m.leaf
		}
		return netip.AddrPort{}
	}
	if got := found(first); got != firstLeaf {
		t.Errorf("port %d on %s is %s's, want %s's", port, first, got, firstLeaf)
	}
	if got := found(second); got != secondLeaf {
		t.Errorf("port %d on %s is %s's, want %s's", port, second, got, secondLeaf)
	}
	if got := found(netip.MustParseAddr("127.0.0.4")); got.IsValid() {
		t.Errorf("port %d on an address no class names is %s's, want no mapping's", port, got)
	}
	h.advance(mappingTimeout - time.Minute + mappingSweep)
	if _, ok := h.mappingOf(firstLeaf); ok {
		t.Fatal("the first mapping outlived its time")
	}
	if got := found(second); got != secondLeaf {
		t.Errorf("once the first mapping ended, port %d on %s is %s's, want %s's", port, second, got, secondLeaf)
	}
}

// Under a class naming one address the host holds, a leaf's datagram to a
// second address the host holds, at the port the class's mapping holds on the
// first, is refused as toward the host itself, answered administratively
// prohibited, and opens no mapping
func TestHairpinToAnotherHeldAddressMeetsNoClassMapping(t *testing.T) {
	class, second := netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("127.0.0.3")
	server := loopbackServer(t, netip.MustParseAddr("127.0.0.1"))
	_ = loopbackServer(t, class)
	h := newRelayHarness(t, func(rt *Runtime, _ *egress.Egress) {
		holdOnly(rt, class, second)
	})
	h.x.cfg.Translate = classed(class).Translate
	listener := netip.AddrPortFrom(leaf4, freeUDPPort(t, leaf4))
	h.x.udp.take(udpDatagram(listener, serverAt(server), []byte("opens a mapping")), false)
	readDatagramFrom(t, server, []byte("opens a mapping"))
	port, _ := h.mappingOf(listener)
	sender := netip.AddrPortFrom(leaf4.Next(), freeUDPPort(t, leaf4))
	raw := udpDatagram(sender, netip.AddrPortFrom(second, port), []byte("to the second address"))
	h.x.handle(h.lane, raw)
	if _, ok := h.mappingOf(sender); ok || h.count(true, reasonDestination) != 1 {
		t.Errorf("a datagram to %s at the port the class's mapping holds on %s opened a mapping %t, refused %d times", second, class, ok, h.count(true, reasonDestination))
	}
	answers := h.mesh.answered()
	if len(answers) == 0 || answers[len(answers)-1].kind != netstack.ExitProhibited || !bytes.Equal(answers[len(answers)-1].offending, raw) {
		t.Errorf("answered %v, want administratively prohibited quoting the datagram", answers)
	}
}

// anchor is the port of a mapping that sent to a server on loopback alone,
// which unpaired hairpins through
func (h *relayHarness) anchor(t *testing.T) uint16 {
	t.Helper()
	server := loopbackServer(t, netip.MustParseAddr("127.0.0.1"))
	leaf := netip.AddrPortFrom(leaf4.Next().Next(), freeUDPPort(t, leaf4))
	h.x.udp.take(udpDatagram(leaf, serverAt(server), []byte("anchors")), false)
	readDatagramFrom(t, server, []byte("anchors"))
	port, _ := h.mappingOf(leaf)
	return port
}

// unpaired is the port of leaf's mapping opened with no destination, so under
// auto it pairs with no address and hairpins from the host's address its
// datagram went to, as a mapping whose host's address a test holds would: leaf
// hairpins a datagram to anchor's port at spare, a held address the anchor
// never sent to, which filters it. leaf's filter lets spare in from then on.
func (h *relayHarness) unpaired(t *testing.T, leaf netip.AddrPort, spare netip.Addr, anchor uint16) uint16 {
	t.Helper()
	h.x.handle(h.lane, udpDatagram(leaf, netip.AddrPortFrom(spare, anchor), []byte("opens a mapping")))
	port, ok := h.mappingOf(leaf)
	if !ok {
		t.Fatalf("%s holds no mapping after its hairpinned datagram", leaf)
	}
	return port
}

// A hairpinned datagram meets the target mapping's filter as one from outside
// would (RFC 4787 REQ-8): to a mapping that never sent to the host's address
// it is dropped and counted as filtered, laying nothing, while the sender's
// filter lets the host's address in from then on. The target's answer to the
// host's address so reaches the sender, and the sender's next datagram the
// target, as two leaves punching through a filter by address do.
func TestHairpinMeetsTheTargetsFilter(t *testing.T) {
	host, spare := netip.MustParseAddr("198.51.100.9"), netip.MustParseAddr("198.51.100.11")
	h := newRelayHarness(t, func(rt *Runtime, _ *egress.Egress) {
		holdOnly(rt, host, spare)
	})
	anchor := h.anchor(t)
	target := netip.AddrPortFrom(leaf4, freeUDPPort(t, leaf4))
	sender := netip.AddrPortFrom(other4, freeUDPPort(t, other4))
	port, senderPort := h.unpaired(t, target, spare, anchor), h.unpaired(t, sender, spare, anchor)
	filtered := h.count(false, reasonFiltered)
	h.x.handle(h.lane, udpDatagram(sender, netip.AddrPortFrom(host, port), []byte("unasked")))
	if got := h.count(false, reasonFiltered) - filtered; got != 1 {
		t.Errorf("filtered %d hairpinned datagrams, want the one to a mapping that never sent to %s", got, host)
	}
	h.x.handle(h.lane, udpDatagram(target, netip.AddrPortFrom(host, senderPort), []byte("answers")))
	h.waitLaid(t, "the target's answer to the sender, which sent to the host", func(raw []byte) bool {
		return isDatagram(raw, netip.AddrPortFrom(host, port), sender, []byte("answers"))
	})
	h.x.handle(h.lane, udpDatagram(sender, netip.AddrPortFrom(host, port), []byte("asked")))
	h.waitLaid(t, "hairpinned datagram once the target sent to the host", func(raw []byte) bool {
		return isDatagram(raw, netip.AddrPortFrom(host, senderPort), target, []byte("asked"))
	})
	for _, raw := range h.mesh.laidPackets() {
		if isDatagram(raw, netip.AddrPortFrom(host, senderPort), target, []byte("unasked")) {
			t.Error("laid the datagram the target never asked for")
		}
	}
}

// freeUDPPortOn is a port no UDP socket holds on any of addresses now
func freeUDPPortOn(t *testing.T, addresses ...netip.Addr) uint16 {
	t.Helper()
	for range 16 {
		port := freeUDPPort(t, addresses[0])
		free := true
		for _, address := range addresses {
			conn, err := net.ListenUDP(udpNetwork(address), net.UDPAddrFromAddrPort(netip.AddrPortFrom(address, port)))
			if err != nil {
				free = false
				break
			}
			_ = conn.Close()
		}
		if free {
			return port
		}
	}
	t.Skipf("no port free on all of %v", addresses)
	return 0
}

// Each server's reply comes back to the leaf from that server, as a datagram
// the exit built with its checksum at the host's TTL or hop limit, and an
// IPv6 reply larger than the leaf's session comes back cut as its source cuts
// it
func TestRepliesComeBackFromTheirServer(t *testing.T) {
	for _, c := range []struct {
		name   string
		leaf   netip.Addr
		loop   string
		size   int
		mtu    int
		pieces int
	}{
		{"ipv4", leaf4, "127.0.0.1", 200, 0, 1},
		{"ipv4 past the session", leaf4, "127.0.0.1", 3000, 1280, 1},
		{"ipv6", leaf6, "::1", 200, 0, 1},
		{"ipv6 past the session", leaf6, "::1", 3000, 1280, 3},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newRelayHarness(t, nil)
			h.mesh.mtu = c.mtu
			h.x.SetHopLimits(hostTTL, hostHopLimit)
			server := loopbackServer(t, netip.MustParseAddr(c.loop))
			leaf := netip.AddrPortFrom(c.leaf, freeUDPPort(t, c.leaf))
			h.x.udp.take(udpDatagram(leaf, serverAt(server), []byte("request")), false)
			outside := readDatagramFrom(t, server, []byte("request"))
			reply := bytes.Repeat([]byte{0xa5}, c.size)
			if _, err := server.WriteToUDPAddrPort(reply, outside); err != nil {
				t.Fatal(err)
			}
			var laid [][]byte
			for range c.pieces {
				laid = append(laid, h.nextLaid(t, "reply"))
				if got := hopsOf(laid[len(laid)-1]); got != hostHops(c.leaf) {
					t.Errorf("laid a reply at %d, want the host's %d", got, hostHops(c.leaf))
				}
			}
			whole := laid[0]
			if c.pieces > 1 {
				for _, piece := range laid {
					if len(piece) > c.mtu {
						t.Errorf("a fragment of %d bytes past the session's %d", len(piece), c.mtu)
					}
				}
				var ok bool
				if whole, ok = reassemble6(laid); !ok {
					t.Fatalf("the %d fragments laid do not reassemble", len(laid))
				}
			}
			if !isDatagram(whole, serverAt(server), leaf, reply) {
				p, _ := parse(whole)
				t.Errorf("laid %s, want the reply from %s to %s whole with its checksum", p, serverAt(server), leaf)
			}
		})
	}
}

// A leaf's datagram to the host's own address at a port a mapping holds
// reaches that mapping's leaf from the sender's own mapping on that address
// (RFC 4787 REQ-9), at the host's TTL, and one to a port no mapping holds is
// refused as toward the host itself, opening nothing
func TestHairpinReachesAnotherMappingFromTheSendersOwn(t *testing.T) {
	host := netip.MustParseAddr("198.51.100.9")
	h := newRelayHarness(t, func(rt *Runtime, _ *egress.Egress) {
		rt.Platform.Held = func(address netip.Addr) bool { return address == host }
	})
	h.x.SetHopLimits(hostTTL, hostHopLimit)
	anchor := h.anchor(t)
	listener := netip.AddrPortFrom(leaf4, freeUDPPort(t, leaf4))
	port := h.unpaired(t, listener, host, anchor)
	sender := netip.AddrPortFrom(other4, freeUDPPort(t, other4))
	opened := h.unpaired(t, sender, host, anchor)
	h.x.handle(h.lane, udpDatagram(listener, netip.AddrPortFrom(host, opened), []byte("lets the host's address in")))
	h.x.handle(h.lane, udpDatagram(sender, netip.AddrPortFrom(host, port), []byte("hairpinned")))
	senderPort, ok := h.mappingOf(sender)
	if !ok {
		t.Fatal("the sender holds no mapping after its hairpinned datagram")
	}
	hairpinned := h.waitLaid(t, "hairpinned datagram", func(raw []byte) bool {
		return isDatagram(raw, netip.AddrPortFrom(host, senderPort), listener, []byte("hairpinned"))
	})
	if got := hopsOf(hairpinned); got != hostTTL {
		t.Errorf("hairpinned at the TTL %d, want the host's %d", got, hostTTL)
	}
	unheld := netip.AddrPortFrom(leaf6, freeUDPPort(t, leaf6))
	h.x.handle(h.lane, udpDatagram(unheld, netip.AddrPortFrom(netip.MustParseAddr("2001:db8::9"), port), []byte("to the host")))
	if h.count(true, reasonDestination) != 0 {
		t.Fatalf("refused %d toward an address the host does not hold", h.count(true, reasonDestination))
	}
	toHost := netip.AddrPortFrom(leaf4, freeUDPPort(t, leaf4))
	raw := udpDatagram(toHost, netip.AddrPortFrom(host, port+1), []byte("to the host's own service"))
	h.x.handle(h.lane, raw)
	if _, ok := h.mappingOf(toHost); ok || h.count(true, reasonDestination) != 1 {
		t.Errorf("a datagram to the host at a port no mapping holds opened a mapping %t, refused %d times", ok, h.count(true, reasonDestination))
	}
	answers := h.mesh.answered()
	if len(answers) == 0 || answers[len(answers)-1].kind != netstack.ExitProhibited || !bytes.Equal(answers[len(answers)-1].offending, raw) {
		t.Errorf("answered %v, want administratively prohibited quoting the datagram to the host", answers)
	}
}

// A hairpinned IPv6 datagram whose payload, past the leaf's header, the exit's
// largest buffer holds only cut is dropped and counted, never carried cut with
// a checksum over what is left
func TestHairpinTooLargeForItsBufferIsDropped(t *testing.T) {
	host := netip.MustParseAddr("2001:db8::9")
	h := newRelayHarness(t, func(rt *Runtime, _ *egress.Egress) {
		holdOnly(rt, host)
	})
	server := loopbackServer(t, netip.IPv6Loopback())
	listener := netip.AddrPortFrom(leaf6, freeUDPPort(t, leaf6))
	h.x.udp.take(udpDatagram(listener, serverAt(server), []byte("opens a mapping")), false)
	readDatagramFrom(t, server, []byte("opens a mapping"))
	port, _ := h.mappingOf(listener)
	sender := netip.AddrPortFrom(other6, freeUDPPort(t, other6))
	h.x.handle(h.lane, udpDatagram(sender, netip.AddrPortFrom(host, port), make([]byte, 1<<16-1-8)))
	if got := h.count(false, reasonTruncated); got != 1 {
		t.Errorf("dropped %d datagrams as truncated, want the one too large for the buffer", got)
	}
	time.Sleep(stackSettle)
	for _, raw := range h.mesh.laidPackets() {
		if p, ok := parse(raw); ok && p.protocol == protoUDP && netip.AddrPortFrom(p.dst, p.dstPort) == listener {
			t.Errorf("laid %s toward the mapping's leaf, want nothing", p)
		}
	}
}

// A mapping lasts 5 minutes past its last datagram out, 30 seconds where it
// sent to port 53 alone, each destination's socket its own time, and nothing
// coming in keeps either: RFC 4787 REQ-5 and REQ-6
func TestMappingTimersFollowOnlyTheDatagramsOut(t *testing.T) {
	h := newRelayHarness(t, nil)
	server := loopbackServer(t, netip.MustParseAddr("127.0.0.1"))
	dns := netip.MustParseAddrPort("127.0.0.1:53")
	leaf := netip.AddrPortFrom(leaf4, freeUDPPort(t, leaf4))
	other := netip.AddrPortFrom(other4, freeUDPPort(t, other4))
	destinations := func(leaf netip.AddrPort) []netip.AddrPort {
		h.x.udp.mu.RLock()
		m := h.x.udp.mappings[leaf]
		h.x.udp.mu.RUnlock()
		if m == nil {
			return nil
		}
		m.mu.RLock()
		defer m.mu.RUnlock()
		var out []netip.AddrPort
		for to := range m.destinations {
			out = append(out, to)
		}
		slices.SortFunc(out, netip.AddrPort.Compare)
		return out
	}

	h.x.udp.take(udpDatagram(other, dns, []byte("a query")), false)
	h.advance(29 * time.Second)
	if got := destinations(other); !slices.Equal(got, []netip.AddrPort{dns}) {
		t.Fatalf("29 seconds after a query alone the mapping holds %v, want the query's destination", got)
	}
	h.advance(2 * time.Second)
	if _, ok := h.mappingOf(other); ok {
		t.Error("a mapping that sent to port 53 alone outlived 30 seconds")
	}

	h.x.udp.take(udpDatagram(leaf, serverAt(server), []byte("first")), false)
	outside := readDatagramFrom(t, server, []byte("first"))
	h.x.udp.take(udpDatagram(leaf, dns, []byte("a query")), false)
	h.advance(4 * time.Minute)
	if _, err := server.WriteToUDPAddrPort([]byte("a reply"), outside); err != nil {
		t.Fatal(err)
	}
	h.waitLaid(t, "reply", func(raw []byte) bool { return isDatagram(raw, serverAt(server), leaf, []byte("a reply")) })
	if got := destinations(leaf); !slices.Equal(got, []netip.AddrPort{serverAt(server)}) {
		t.Errorf("4 minutes on the mapping holds %v, want the server alone, its query's destination ended", got)
	}
	h.advance(time.Minute + time.Second)
	if _, ok := h.mappingOf(leaf); ok {
		t.Error("a reply coming in kept the mapping past 5 minutes from its last datagram out")
	}
	h.x.flows.mu.Lock()
	defer h.x.flows.mu.Unlock()
	if open := h.x.flows.open; open != 0 {
		t.Errorf("%d flows held once every mapping ended", open)
	}
}
