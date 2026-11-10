// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package userspace

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/schema"
)

const (
	// loopbackProbeWait bounds the wait for a loopback server's datagram to
	// itself
	loopbackProbeWait = time.Second
	// datagramAllocRuns is the datagrams an allocation count averages over
	datagramAllocRuns = 100
)

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
	// darwin's New readies its ICMP sockets, which no datagram asked for
	h.mu.Lock()
	h.prepared = nil
	h.mu.Unlock()
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

// mappingOf is the external port of leaf's oldest mapping, false where it has
// none
func (h *relayHarness) mappingOf(leaf netip.AddrPort) (uint16, bool) {
	h.x.udp.mu.RLock()
	defer h.x.udp.mu.RUnlock()
	mappings := h.x.udp.mappings[leaf]
	if len(mappings) == 0 {
		return 0, false
	}
	return mappings[0].port, true
}

// mappingsOf is leaf's mappings, oldest first
func (h *relayHarness) mappingsOf(leaf netip.AddrPort) []*mapping {
	h.x.udp.mu.RLock()
	defer h.x.udp.mu.RUnlock()
	return h.x.udp.mappings[leaf]
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

// routeAddress is the address the host's route toward to picks, the local
// address of a UDP socket connected to it
func routeAddress(t *testing.T, to netip.AddrPort) netip.Addr {
	t.Helper()
	conn, err := net.DialUDP(udpNetwork(to.Addr()), nil, net.UDPAddrFromAddrPort(to))
	if err != nil {
		t.Fatalf("the host's route toward %s: %v", to, err)
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).AddrPort().Addr().Unmap()
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
// and an IPv4 zero one, which carries no checksum, goes on to the probe of its
// route
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
						if len(prepared) != 1 || prepared[0] != server || h.count(true, reasonSocket) != 1 {
							t.Errorf("readied %v and refused %d for the socket, want the probe of the route toward %s readied once", prepared, h.count(true, reasonSocket), server)
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
// the process may not bind it. Every socket passes Prepare: the probe of each
// destination's route toward it, the one that only receives with no
// destination, and each destination's toward its server.
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
			switch c.port {
			case 0:
				c.port = freeUDPPort(t, leaf4)
			case 80:
				// macOS lets any user bind a low port, and a sandbox refuses
				// one with EPERM, which is no port the process may not bind
				probe, err := net.ListenUDP("udp4", &net.UDPAddr{Port: int(c.port)})
				if err == nil {
					_ = probe.Close()
					t.Skipf("this process binds port %d itself", c.port)
				}
				if !errors.Is(err, syscall.EACCES) {
					t.Skipf("port %d is refused to this process with %v, not EACCES", c.port, err)
				}
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
			want := []netip.AddrPort{serverAt(servers[0]), {}}
			if !c.kept {
				want = append(want, netip.AddrPort{})
			}
			want = append(want, serverAt(servers[0]), serverAt(servers[1]), serverAt(servers[1]))
			if !slices.Equal(prepared, want) {
				t.Errorf("Prepare readied sockets toward %v, want %v", prepared, want)
			}
		})
	}
}

// A datagram toward a destination a mapping of its leaf holds open readies no
// socket, so reads no route, and allocates nothing, toward the second of two
// mappings of one leaf as well: a class's, and under auto one on the address
// the route picks
func TestDatagramToAnOpenDestinationReadiesNoSocketAndAllocatesNothing(t *testing.T) {
	class := netip.MustParseAddr("127.0.0.2")
	first, second := loopbackServer(t, netip.MustParseAddr("127.0.0.1")), loopbackServer(t, netip.MustParseAddr("127.0.0.1"))
	_ = loopbackServer(t, class)
	h := newRelayHarness(t, nil)
	leaf := netip.AddrPortFrom(leaf4, freeUDPPort(t, leaf4))
	h.x.cfg.Translate = classed(class).Translate
	h.x.udp.take(udpDatagram(leaf, serverAt(first), []byte("first")), false)
	readDatagramFrom(t, first, []byte("first"))
	h.x.cfg.Translate = nil
	raw := udpDatagram(leaf, serverAt(second), []byte("second"))
	h.x.udp.take(raw, false)
	readDatagramFrom(t, second, []byte("second"))
	readied := len(h.preparedSoFar())
	if allocs := testing.AllocsPerRun(datagramAllocRuns, func() { h.x.udp.take(raw, false) }); allocs != 0 {
		t.Errorf("a datagram toward an open destination allocated %v times", allocs)
	}
	if got := h.preparedSoFar()[readied:]; len(got) != 0 {
		t.Errorf("datagrams toward an open destination readied sockets toward %v, want none", got)
	}
	// both mappings of the leaf end in one sweep
	h.advance(mappingTimeout + mappingSweep)
	if mappings := h.mappingsOf(leaf); len(mappings) != 0 {
		t.Errorf("%s holds %d mappings past their time, want none", leaf, len(mappings))
	}
	h.x.flows.mu.Lock()
	defer h.x.flows.mu.Unlock()
	if open := h.x.flows.open; open != 0 {
		t.Errorf("%d flows held past their time, want none", open)
	}
}

// A datagram whose socket the exit closed after open handed it over, as an
// ended mapping's are, is no refusal of the host's: send counts nothing as
// unsent and reports nothing, so no address is asked after
func TestDatagramOnASocketTheExitClosedIsNotUnsent(t *testing.T) {
	server := loopbackServer(t, netip.MustParseAddr("127.0.0.1"))
	h := newRelayHarness(t, nil)
	leaf := netip.AddrPortFrom(leaf4, freeUDPPort(t, leaf4))
	raw := udpDatagram(leaf, serverAt(server), []byte("first"))
	h.x.udp.take(raw, false)
	readDatagramFrom(t, server, []byte("first"))
	m, dst, reason := h.x.udp.open(leaf, serverAt(server))
	if dst == nil {
		t.Fatalf("open refused an open destination: %s", reason)
	}
	h.x.udp.end(m)
	d, _ := readDatagram(raw)
	if h.x.udp.send(raw, d, dst, false) {
		t.Error("send reported a datagram on a socket the exit closed as refused")
	}
	if got := h.count(false, reasonUnsent); got != 0 {
		t.Errorf("udp unsent %d after a send on a closed socket, want 0", got)
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

// A mapping under a class naming an address sends from that address, and
// under auto from the address the route to the server picks, its socket that
// only receives bound to that address as well
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
			_ = loopbackServer(t, c.want)
			h := newRelayHarness(t, nil)
			h.x.cfg.Translate = c.cfg.Translate
			leaf := netip.AddrPortFrom(leaf4, freeUDPPort(t, leaf4))
			payload := []byte("from the class of " + c.name)
			h.x.udp.take(udpDatagram(leaf, serverAt(server), payload), false)
			if from := readDatagramFrom(t, server, payload); from.Addr() != c.want {
				t.Errorf("the server read the datagram from %s, want %s", from, c.want)
			}
			m := h.mappingsOf(leaf)[0]
			if got := m.receiving.LocalAddr().(*net.UDPAddr).AddrPort().Addr().Unmap(); got != c.want {
				t.Errorf("the mapping receives on %s, want %s", got, c.want)
			}
		})
	}
}

// Under auto each destination's datagram leaves from the address the host's
// route toward it picks, under the leaf's mapping on that address and at the
// leaf's port where free there, and the leaf holds one mapping for each
// address its destinations' routes pick, none ended by another's destination.
// Where loopback holds more than one address, as lo0 does with aliases on
// macOS, the two routes pick two.
func TestMappingUnderAutoLeavesFromEachRoutesAddress(t *testing.T) {
	first := loopbackServer(t, netip.MustParseAddr("127.0.0.1"))
	later := loopbackServer(t, netip.MustParseAddr("127.0.0.2"))
	h := newRelayHarness(t, nil)
	leaf := netip.AddrPortFrom(leaf4, freeUDPPortOn(t, serverAt(first).Addr(), serverAt(later).Addr()))
	routes := map[netip.Addr]bool{}
	for i, server := range []*net.UDPConn{first, later, first} {
		payload := []byte(fmt.Sprintf("datagram %d", i))
		route := routeAddress(t, serverAt(server))
		routes[route] = true
		h.x.udp.take(udpDatagram(leaf, serverAt(server), payload), false)
		if got, want := readDatagramFrom(t, server, payload), netip.AddrPortFrom(route, leaf.Port()); got != want {
			t.Errorf("%s read datagram %d from %s, want %s, the host's route's address at the leaf's port", serverAt(server), i, got, want)
		}
	}
	mappings := h.mappingsOf(leaf)
	if len(mappings) != len(routes) {
		t.Errorf("%s holds %d mappings, want %d, one for each address its destinations' routes pick", leaf, len(mappings), len(routes))
	}
	for _, m := range mappings {
		if ended(m) {
			t.Errorf("the mapping on %s ended", m.external())
		}
	}
}

// Under auto a connect that refuses the address of the mapping its datagram
// opened refuses that datagram once: the route is read once, and the mapping
// closes with no flow held, since only a mapping an earlier datagram opened
// on that address tells the host no longer holds it
func TestNewMappingWhoseAddressIsRefusedRefusesTheDatagramOnce(t *testing.T) {
	server := loopbackServer(t, netip.MustParseAddr("127.0.0.1"))
	h := newRelayHarness(t, nil)
	var prepared int
	h.x.rt.Platform.Prepare = func(_ string, to netip.AddrPort, _ syscall.RawConn) error {
		if to != serverAt(server) {
			return nil
		}
		h.mu.Lock()
		defer h.mu.Unlock()
		// the first socket toward the server probes its route, and the second
		// is its destination's, which a few tries refuse
		if prepared++; prepared%2 == 0 && prepared < 8 {
			return syscall.EADDRNOTAVAIL
		}
		return nil
	}
	leaf := netip.AddrPortFrom(leaf4, freeUDPPort(t, leaf4))
	h.x.udp.take(udpDatagram(leaf, serverAt(server), []byte("refused")), false)
	if got := h.count(true, reasonSocket); got != 1 {
		t.Errorf("refused %d datagrams for their socket, want the one", got)
	}
	h.mu.Lock()
	tries := prepared
	h.mu.Unlock()
	if tries != 2 {
		t.Errorf("readied %d sockets toward the server, want the route's and the destination's once", tries)
	}
	if mappings := h.mappingsOf(leaf); len(mappings) != 0 {
		t.Errorf("%s holds %d mappings, want none", leaf, len(mappings))
	}
	h.x.flows.mu.Lock()
	defer h.x.flows.mu.Unlock()
	if open := h.x.flows.open; open != 0 {
		t.Errorf("%d flows held, want none", open)
	}
}

// Under auto a mapping an earlier datagram opened, on an address the host no
// longer holds, ends where the connect toward its next destination fails, and
// that datagram leaves from the address the host's route picks once read
// again, under a new mapping that holds its flow alone. The leaf's mapping on
// another address, an earlier class's, lives on with its destination. Where
// the host still holds the address, the platform answering for it, the
// failed connect ends nothing and refuses the datagram once.
func TestMappingWhoseAddressTheHostGaveUpEndsAtItsNextConnect(t *testing.T) {
	for _, held := range []bool{false, true} {
		t.Run(fmt.Sprintf("held %t", held), func(t *testing.T) {
			class, loopback := netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("127.0.0.1")
			_ = loopbackServer(t, class)
			earlier, first, later := loopbackServer(t, loopback), loopbackServer(t, loopback), loopbackServer(t, loopback)
			h := newRelayHarness(t, nil)
			var prepared int
			var refused bool
			h.x.rt.Platform.Prepare = func(_ string, to netip.AddrPort, _ syscall.RawConn) error {
				if to != serverAt(later) {
					return nil
				}
				h.mu.Lock()
				defer h.mu.Unlock()
				// the first socket toward later probes its route, and the second
				// is its destination's, which the host refuses its mapping's
				// address
				if prepared++; prepared == 2 {
					refused = true
					return syscall.EADDRNOTAVAIL
				}
				return nil
			}
			// the host holds loopback from the refused connect on where held,
			// so the datagram's own test for an address of the host's does not
			// see it
			h.x.rt.Platform.Held = func(address netip.Addr, _ string) bool {
				h.mu.Lock()
				defer h.mu.Unlock()
				return held && refused && address == loopback
			}
			leaf := netip.AddrPortFrom(leaf4, freeUDPPortOn(t, class, loopback))
			h.x.cfg.Translate = classed(class).Translate
			h.x.udp.take(udpDatagram(leaf, serverAt(earlier), []byte("earlier")), false)
			readDatagramFrom(t, earlier, []byte("earlier"))
			h.x.cfg.Translate = nil
			h.x.udp.take(udpDatagram(leaf, serverAt(first), []byte("first")), false)
			readDatagramFrom(t, first, []byte("first"))
			kept, old := h.mappingsOf(leaf)[0], h.mappingsOf(leaf)[1]
			h.x.udp.take(udpDatagram(leaf, serverAt(later), []byte("later")), false)
			mappings := h.mappingsOf(leaf)
			if held {
				if ended(old) || ended(kept) || !slices.Equal(mappings, []*mapping{kept, old}) || h.count(true, reasonSocket) != 1 {
					t.Errorf("the mapping on a held address ended %t and the class's %t, %s holds %d mappings, and %d datagrams were refused for their socket, want neither ended, both held and the one refused", ended(old), ended(kept), leaf, len(mappings), h.count(true, reasonSocket))
				}
				return
			}
			if !ended(old) || ended(kept) || len(mappings) != 2 || mappings[0] != kept || mappings[1] == old {
				t.Fatalf("the mapping on the gone address ended %t and the class's %t, and %s holds %d mappings, want the first alone ended and one new beside the class's", ended(old), ended(kept), leaf, len(mappings))
			}
			if got, want := readDatagramFrom(t, later, []byte("later")), mappings[1].external(); got != want {
				t.Errorf("later read the datagram from %s, want %s, the new mapping's", got, want)
			}
			h.x.flows.mu.Lock()
			defer h.x.flows.mu.Unlock()
			if open := h.x.flows.open; open != 2 {
				t.Errorf("%d flows held, want the class mapping's destination and the later one", open)
			}
		})
	}
}

// ended is whether m ended
func ended(m *mapping) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.closed
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
		if m := h.x.udp.ports[netip.AddrPortFrom(address, port)]; m != nil {
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

// hairpinning opens leaf's mapping as its first datagram hairpinned to the
// host's address host does, with no destination and nothing let in, and is
// its port. Under auto the mapping binds host, an address of loopback here,
// toward which the lane's judgment lets no leaf's datagram through, so a test
// hands its hairpinned datagrams to the relay itself.
func (h *relayHarness) hairpinning(t *testing.T, leaf netip.AddrPort, host netip.Addr) uint16 {
	t.Helper()
	m, reason := h.x.udp.hairpinFrom(leaf, netip.AddrPortFrom(host, 0), netip.AddrPort{})
	if m == nil {
		t.Fatalf("%s opened no mapping to hairpin from on %s: %s", leaf, host, reason)
	}
	return m.port
}

// A hairpinned datagram meets the target mapping's filter as one from outside
// would (RFC 4787 REQ-8): to a mapping that never sent to the host's address
// it is dropped and counted as filtered, laying nothing, while the sender's
// filter lets the host's address in from then on. The target's answer to the
// host's address so reaches the sender, and the sender's next datagram the
// target, as two leaves punching through a filter by address do.
func TestHairpinMeetsTheTargetsFilter(t *testing.T) {
	host := netip.MustParseAddr("127.0.0.1")
	_ = loopbackServer(t, host)
	h := newRelayHarness(t, func(rt *Runtime, _ *egress.Egress) {
		holdOnly(rt, host)
	})
	target := netip.AddrPortFrom(leaf4, freeUDPPort(t, leaf4))
	sender := netip.AddrPortFrom(other4, freeUDPPort(t, other4))
	port, senderPort := h.hairpinning(t, target, host), h.hairpinning(t, sender, host)
	filtered := h.count(false, reasonFiltered)
	h.x.udp.take(udpDatagram(sender, netip.AddrPortFrom(host, port), []byte("unasked")), false)
	if got := h.count(false, reasonFiltered) - filtered; got != 1 {
		t.Errorf("filtered %d hairpinned datagrams, want the one to a mapping that never sent to %s", got, host)
	}
	h.x.udp.take(udpDatagram(target, netip.AddrPortFrom(host, senderPort), []byte("answers")), false)
	h.waitLaid(t, "the target's answer to the sender, which sent to the host", func(raw []byte) bool {
		return isDatagram(raw, netip.AddrPortFrom(host, port), sender, []byte("answers"))
	})
	h.x.udp.take(udpDatagram(sender, netip.AddrPortFrom(host, port), []byte("asked")), false)
	h.waitLaid(t, "hairpinned datagram once the target sent to the host", func(raw []byte) bool {
		return isDatagram(raw, netip.AddrPortFrom(host, senderPort), target, []byte("asked"))
	})
	for _, raw := range h.mesh.laidPackets() {
		if isDatagram(raw, netip.AddrPortFrom(host, senderPort), target, []byte("unasked")) {
			t.Error("laid the datagram the target never asked for")
		}
	}
}

// Under auto a sender whose mapping the hairpin's order picks sits on an
// address Held does not answer for hairpins from the mapping the order picks
// past it, here one opened on the address the datagram went to, so no
// hairpinned datagram leaves from an address the host gave up. The mapping
// passed over neither ends nor moves its deadline: a lagging answer of Held
// only steers, and the mapping ends by its timers or a send that fails.
func TestHairpinPassesOverAMappingOnAnAddressTheHostGaveUp(t *testing.T) {
	one, two := netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.2")
	_, _ = loopbackServer(t, one), loopbackServer(t, two)
	h := newRelayHarness(t, func(rt *Runtime, _ *egress.Egress) {
		holdOnly(rt, one, two)
	})
	target := netip.AddrPortFrom(leaf4, freeUDPPort(t, leaf4))
	sender := netip.AddrPortFrom(other4, freeUDPPortOn(t, one, two))
	port := h.hairpinning(t, target, two)
	h.hairpinning(t, sender, one)
	old := h.mappingsOf(sender)[0]
	deadline := old.deadline.Load()
	holdOnly(&h.x.rt, two)
	h.advance(time.Second)
	filtered := h.count(false, reasonFiltered)
	h.x.udp.take(udpDatagram(sender, netip.AddrPortFrom(two, port), []byte("after one went")), false)
	mappings := h.mappingsOf(sender)
	if ended(old) || len(mappings) != 2 || mappings[0] != old || mappings[1].source != two || h.count(false, reasonFiltered)-filtered != 1 {
		t.Fatalf("the mapping on %s ended %t, and %s holds %d mappings, want it kept and one opened on %s whose first datagram the target filtered", one, ended(old), sender, len(mappings), two)
	}
	if got := old.deadline.Load(); got != deadline {
		t.Errorf("the mapping on %s, which no datagram left from, moved its deadline by %s", one, time.Duration(got-deadline))
	}
	h.x.udp.take(udpDatagram(target, mappings[1].external(), []byte("answers")), false)
	h.waitLaid(t, "the target's answer to the sender's mapping on "+two.String(), func(raw []byte) bool {
		return isDatagram(raw, netip.AddrPortFrom(two, port), sender, []byte("answers"))
	})
}

// passOverWait bounds the wait for one hairpinned datagram whose order passes
// over a mapping
const passOverWait = 5 * time.Second

// Under auto step 2 leaves out a mapping the order passed over even where the
// target mapping's filter lets its address in: the sender's datagram leaves
// from its other mapping the filter lets in, and the mapping passed over
// neither ends nor moves its deadline. Were the passed mapping taken again,
// the datagram would never leave, which fails here within passOverWait, and
// Held's answer comes back so the relay returns.
func TestHairpinLeavesOutAMappingPassedOverThatTheTargetLetsIn(t *testing.T) {
	one, two, three := netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("127.0.0.3")
	_, _, _ = loopbackServer(t, one), loopbackServer(t, two), loopbackServer(t, three)
	var oneGone atomic.Bool
	h := newRelayHarness(t, func(rt *Runtime, _ *egress.Egress) {
		rt.Platform.Held = func(address netip.Addr, _ string) bool {
			return address == two || address == three || address == one && !oneGone.Load()
		}
	})
	target := netip.AddrPortFrom(leaf4, freeUDPPort(t, leaf4))
	sender := netip.AddrPortFrom(other4, freeUDPPort(t, other4))
	peer := netip.AddrPortFrom(leaf4.Next(), freeUDPPort(t, leaf4))
	open := func(leaf netip.AddrPort, at netip.Addr) netip.AddrPort {
		h.x.cfg.Translate = classed(at).Translate
		defer func() { h.x.cfg.Translate = nil }()
		return netip.AddrPortFrom(at, h.hairpinning(t, leaf, at))
	}
	atTarget := open(target, two)
	open(sender, one)
	atSender := open(sender, three)
	peerOne, peerThree := open(peer, one), open(peer, three)
	h.x.udp.take(udpDatagram(target, peerOne, []byte("lets one in")), false)
	h.x.udp.take(udpDatagram(target, peerThree, []byte("lets three in")), false)
	tm := h.mappingsOf(target)[0]
	if !tm.admits(one) || !tm.admits(three) {
		t.Fatalf("the target's mapping lets in %s %t and %s %t, want both", one, tm.admits(one), three, tm.admits(three))
	}
	passed := h.mappingsOf(sender)[0]
	deadline := passed.deadline.Load()
	oneGone.Store(true)
	h.advance(time.Second)
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.x.udp.take(udpDatagram(sender, atTarget, []byte("after one went")), false)
	}()
	select {
	case <-done:
	case <-time.After(passOverWait):
		oneGone.Store(false)
		<-done
		t.Fatalf("the datagram did not leave within %s, the order taking the mapping on %s it passed over again", passOverWait, one)
	}
	h.waitLaid(t, "the datagram from the sender's mapping on "+three.String(), func(raw []byte) bool {
		return isDatagram(raw, atSender, target, []byte("after one went"))
	})
	if ended(passed) || len(h.mappingsOf(sender)) != 2 {
		t.Errorf("the mapping on %s ended %t, and %s holds %d mappings, want it kept beside the one on %s", one, ended(passed), sender, len(h.mappingsOf(sender)), three)
	}
	if got := passed.deadline.Load(); got != deadline {
		t.Errorf("the mapping on %s, which no datagram left from, moved its deadline by %s", one, time.Duration(got-deadline))
	}
}

// A hairpinned datagram from a mapping on the address it went to asks Held
// nothing past the lane's question of that address, under auto as under a
// class
func TestHairpinOnTheAddressItWentToAsksHeldOnce(t *testing.T) {
	host := netip.MustParseAddr("127.0.0.1")
	_ = loopbackServer(t, host)
	var mu sync.Mutex
	calls := 0
	h := newRelayHarness(t, func(rt *Runtime, _ *egress.Egress) {
		rt.Platform.Held = func(address netip.Addr, _ string) bool {
			mu.Lock()
			defer mu.Unlock()
			calls++
			return address == host
		}
	})
	asked := func() int {
		mu.Lock()
		defer mu.Unlock()
		return calls
	}
	target := netip.AddrPortFrom(leaf4, freeUDPPort(t, leaf4))
	sender := netip.AddrPortFrom(other4, freeUDPPort(t, other4))
	port, senderPort := h.hairpinning(t, target, host), h.hairpinning(t, sender, host)
	h.x.udp.take(udpDatagram(target, netip.AddrPortFrom(host, senderPort), []byte("lets the host in")), false)
	raw := udpDatagram(sender, netip.AddrPortFrom(host, port), []byte("hairpinned"))
	for _, translate := range [][]egress.Class{nil, classed(host).Translate} {
		h.x.cfg.Translate = translate
		h.x.udp.take(raw, false)
		h.drainLaid()
		before := asked()
		h.x.udp.take(raw, false)
		h.drainLaid()
		if got := asked() - before; got != 1 {
			t.Errorf("one hairpinned datagram asked Held %d times with classes %v, want 1", got, translate)
		}
	}
}

// A mapping's filter lets in every host address it hairpinned to while it
// lives, past the hairpinRecord endpoints its record keeps for step 2 and for
// errors (RFC 4787 section 5): a sender that hairpinned to the target at two,
// then to that many peers at one, still lets the target in from two
func TestMappingLetsInAnAddressItHairpinnedToPastItsRecord(t *testing.T) {
	for _, peers := range []int{hairpinRecord - 1, hairpinRecord} {
		t.Run(fmt.Sprintf("%d peers", peers), func(t *testing.T) {
			one, two := netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.2")
			_, _ = loopbackServer(t, one), loopbackServer(t, two)
			h := newRelayHarness(t, func(rt *Runtime, _ *egress.Egress) { holdOnly(rt, one, two) })
			target := netip.AddrPortFrom(leaf4, freeUDPPort(t, leaf4))
			sender := netip.AddrPortFrom(other4, freeUDPPort(t, other4))
			atTarget := netip.AddrPortFrom(two, h.hairpinning(t, target, two))
			atSender := netip.AddrPortFrom(one, h.hairpinning(t, sender, one))
			h.x.udp.take(udpDatagram(sender, atTarget, []byte("asks")), false)
			h.x.udp.take(udpDatagram(target, atSender, []byte("answers")), false)
			h.waitLaid(t, "the target's answer", func(raw []byte) bool { return isDatagram(raw, atTarget, sender, []byte("answers")) })
			for i := range peers {
				peer := netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte(10 + i)}), freeUDPPort(t, leaf4))
				at := netip.AddrPortFrom(one, h.hairpinning(t, peer, one))
				h.x.udp.take(udpDatagram(sender, at, []byte("to a peer")), false)
			}
			h.drainLaid()
			filtered := h.count(false, reasonFiltered)
			h.x.udp.take(udpDatagram(target, atSender, []byte("answers again")), false)
			if got := h.count(false, reasonFiltered) - filtered; got != 0 {
				t.Fatalf("filtered %d of the target's datagrams from %s at the sender's mapping, which hairpinned to %s and lives", got, atTarget, two)
			}
			h.waitLaid(t, "the target's second answer", func(raw []byte) bool { return isDatagram(raw, atTarget, sender, []byte("answers again")) })
		})
	}
}

// A target that only answers stays reachable once its mapping hairpinned to
// more peers than its record keeps: the record no longer names the sender,
// and the target's filter still lets the sender's address in, so the sender's
// datagram leaves from that address by step 2 and is let in
func TestTargetThatOnlyAnswersStaysReachablePastItsRecord(t *testing.T) {
	a, b := netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("127.0.0.1")
	_, _ = loopbackServer(t, a), loopbackServer(t, b)
	h := newRelayHarness(t, func(rt *Runtime, _ *egress.Egress) { holdOnly(rt, a, b) })
	target := netip.AddrPortFrom(leaf4, freeUDPPort(t, leaf4))
	sender := netip.AddrPortFrom(other4, freeUDPPort(t, other4))
	targetB := netip.AddrPortFrom(b, h.hairpinning(t, target, b))
	senderA := netip.AddrPortFrom(a, h.hairpinning(t, sender, a))
	h.x.udp.take(udpDatagram(target, senderA, []byte("target first")), false)
	h.x.udp.take(udpDatagram(sender, targetB, []byte("sender first")), false)
	h.waitLaid(t, "the sender's datagram once the target sent to its address", func(raw []byte) bool {
		return isDatagram(raw, senderA, target, []byte("sender first"))
	})
	for i := range hairpinRecord {
		other := netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte(100 + i)}), freeUDPPort(t, b))
		at := netip.AddrPortFrom(b, h.hairpinning(t, other, b))
		h.x.udp.take(udpDatagram(target, at, []byte("to another peer")), false)
	}
	h.drainLaid()
	h.x.udp.take(udpDatagram(sender, targetB, []byte("after the others")), false)
	h.waitLaid(t, "the sender's datagram after the target hairpinned to "+fmt.Sprint(hairpinRecord)+" others", func(raw []byte) bool {
		return isDatagram(raw, senderA, target, []byte("after the others"))
	})
}

// A mapping's record keeps the last hairpinRecord distinct addresses and
// ports its hairpinned datagrams went to, the latest last: a repeat moves to
// the end, the oldest leaves at one past the bound, and the filter still lets
// in its address, so step 2 still finds the mapping an entry that left named
func TestHairpinRecordKeepsTheLatestDistinctEndpoints(t *testing.T) {
	one, two := netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.2")
	_, _ = loopbackServer(t, one), loopbackServer(t, two)
	h := newRelayHarness(t, func(rt *Runtime, _ *egress.Egress) { holdOnly(rt, one, two) })
	sender := netip.AddrPortFrom(other4, freeUDPPort(t, other4))
	h.hairpinning(t, sender, one)
	m := h.mappingsOf(sender)[0]
	var peers, ats []netip.AddrPort
	for i := range hairpinRecord + 1 {
		host := one
		if i == 0 {
			host = two
		}
		peer := netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte(10 + i)}), freeUDPPort(t, leaf4))
		peers = append(peers, peer)
		ats = append(ats, netip.AddrPortFrom(host, h.hairpinning(t, peer, host)))
	}
	send := func(to netip.AddrPort) { h.x.udp.take(udpDatagram(sender, to, []byte("to a peer")), false) }
	for _, at := range ats[:hairpinRecord] {
		send(at)
	}
	send(ats[3])
	send(ats[hairpinRecord])
	m.mu.RLock()
	got := slices.Clone(m.hairpinnedTo)
	m.mu.RUnlock()
	want := slices.Concat(ats[1:3], ats[4:hairpinRecord], []netip.AddrPort{ats[3], ats[hairpinRecord]})
	if !slices.Equal(got, want) {
		t.Errorf("the record holds %v, want %v", got, want)
	}
	// step 2 for each peer's datagram to the sender's mapping
	if k := known(h.mappingsOf(peers[0]), []*mapping{m}, nil, m.external()); k == nil || k.external() != ats[0] {
		t.Errorf("step 2 found %v for the peer at %s, whose address the filter lets in", k, ats[0])
	}
	if k := known(h.mappingsOf(peers[1]), []*mapping{m}, nil, m.external()); k == nil || k.external() != ats[1] {
		t.Errorf("step 2 found %v for the peer at %s, which the record still names", k, ats[1])
	}
	if !m.admits(two) {
		t.Errorf("the mapping no longer lets in %s, which it hairpinned to and whose entry left its record", two)
	}
}

// hairpinLayout is leaves' mappings on the host's addresses a, b and c, and
// the datagrams they hairpin to each other in turn
type hairpinLayout struct {
	name string
	// opens is each mapping opened in turn, a leaf and the letter of its
	// address: "S a" is leaf S's mapping on a
	opens []string
	// class is a leaf and the letter of the address its class names from the
	// steps on, where given, every leaf under auto otherwise
	class string
	steps []hairpinStep
}

// hairpinStep is one datagram a leaf hairpins to another leaf's mapping, from
// a leaf to a mapping as opens names them: delivered from the mapping want
// names, or filtered where want is empty. Where refused, the target's leaf
// refuses the delivered datagram, and its error reaches the sender from to.
// Where others names an address's letter, from hairpins one datagram to each
// of hairpinRecord other leaves' mappings on it in turn instead, filling the
// record of from's mapping that the order picks.
type hairpinStep struct {
	from, to, want, others string
	refused                bool
}

// Each layout of leaves' mappings on the host's addresses connects both ways
// within three hairpinned datagrams each way, each datagram leaving from the
// mapping the order picks (RFC 4787 REQ-9 (a)) and meeting the target
// mapping's own filter, and stays connected once a mapping has hairpinned to
// more peers than its record keeps (L11 to L13). The order:
//  1. the address the sender's class names (L5)
//  2. else the sender's mapping the target's leaf knows: one the target
//     mapping itself hairpinned to by address and port (L10, L15), else one
//     whose address the target mapping's filter lets in (L6, L11 to L13), else
//     one another mapping of the target's leaf hairpinned to by address and
//     port (L1, L4, L14), of equals the one on the address the datagram went
//     to (L7), then the oldest (L9)
//  3. else the sender's mapping on that address (L2, L3)
//  4. else its oldest (L8)
//  5. else one opened on that address (L0)
//
// The target's error about a datagram reaches the sender from the mapping the
// datagram went to (RFC 5508 REQ-7 (a), L7).
func TestHairpinLayoutsConnectBothWays(t *testing.T) {
	for _, layout := range []hairpinLayout{
		{name: "L0 sender with no mapping", opens: []string{"T a"}, steps: []hairpinStep{
			{from: "S", to: "T a"}, {from: "T", to: "S a", want: "T a"}, {from: "S", to: "T a", want: "S a"},
		}},
		{name: "L1 target on a then b", opens: []string{"T a", "T b", "S a"}, steps: []hairpinStep{
			{from: "S", to: "T b"}, {from: "T", to: "S a", want: "T b"}, {from: "S", to: "T b", want: "S a"},
		}},
		{name: "L1 target on b then a", opens: []string{"T b", "T a", "S a"}, steps: []hairpinStep{
			{from: "S", to: "T b"}, {from: "T", to: "S a", want: "T b"}, {from: "S", to: "T b", want: "S a"},
		}},
		{name: "L1 target first", opens: []string{"T a", "T b", "S a"}, steps: []hairpinStep{
			{from: "T", to: "S a"}, {from: "S", to: "T b"}, {from: "T", to: "S a", want: "T b"}, {from: "S", to: "T b", want: "S a"},
		}},
		{name: "L2 both older on a, punching at b", opens: []string{"S a", "T a", "S b", "T b"}, steps: []hairpinStep{
			{from: "S", to: "T b"}, {from: "T", to: "S b", want: "T b"}, {from: "S", to: "T b", want: "S b"},
		}},
		{name: "L3 sender older on b, punching at a", opens: []string{"S b", "S a", "T a"}, steps: []hairpinStep{
			{from: "S", to: "T a"}, {from: "T", to: "S a", want: "T a"}, {from: "S", to: "T a", want: "S a"},
		}},
		{name: "L3 target first", opens: []string{"S b", "S a", "T a"}, steps: []hairpinStep{
			{from: "T", to: "S a"}, {from: "S", to: "T a", want: "S a"}, {from: "T", to: "S a", want: "T a"},
		}},
		{name: "L4 cross", opens: []string{"S a", "S b", "T a", "T b"}, steps: []hairpinStep{
			{from: "S", to: "T b"}, {from: "T", to: "S a"}, {from: "S", to: "T b", want: "S a"}, {from: "T", to: "S a", want: "T b"},
		}},
		{name: "L5 class naming an address with no mapping", opens: []string{"S a", "T a"}, class: "S b", steps: []hairpinStep{
			{from: "S", to: "T a"}, {from: "T", to: "S b", want: "T a"}, {from: "S", to: "T a", want: "S b"},
		}},
		{name: "L6 target hairpinned to a third leaf", opens: []string{"S a", "S b", "T b", "U a"}, steps: []hairpinStep{
			{from: "T", to: "U a"}, {from: "S", to: "T b", want: "S a"}, {from: "T", to: "S a", want: "T b"}, {from: "S", to: "T b", want: "S a"},
		}},
		{name: "L7 sender to both of the target's", opens: []string{"T b", "T a", "S a"}, steps: []hairpinStep{
			{from: "S", to: "T b"}, {from: "S", to: "T a"}, {from: "T", to: "S a", want: "T a"},
			{from: "S", to: "T a", want: "S a", refused: true}, {from: "S", to: "T b"},
		}},
		{name: "L8 sender on neither, oldest", opens: []string{"S a", "S b", "T c"}, steps: []hairpinStep{
			{from: "S", to: "T c"}, {from: "T", to: "S a", want: "T c"}, {from: "S", to: "T c", want: "S a"},
		}},
		{name: "L9 target knows two of the sender's, oldest", opens: []string{"S a", "S b", "T c"}, steps: []hairpinStep{
			{from: "T", to: "S a"}, {from: "T", to: "S b"}, {from: "S", to: "T c", want: "S a"}, {from: "T", to: "S a", want: "T c"},
		}},
		{name: "L10 target mapping's own record first, sender older on b", opens: []string{"S b", "S a", "T a", "T c"}, steps: []hairpinStep{
			{from: "T", to: "S b"}, {from: "S", to: "T c"}, {from: "T", to: "S a"}, {from: "S", to: "T c", want: "S a"}, {from: "T", to: "S a", want: "T c"},
		}},
		{name: "L10 target mapping's own record first, sender older on a", opens: []string{"S a", "S b", "T a", "T c"}, steps: []hairpinStep{
			{from: "T", to: "S b"}, {from: "S", to: "T c"}, {from: "T", to: "S a"}, {from: "S", to: "T c", want: "S a"}, {from: "T", to: "S a", want: "T c"},
		}},
		{name: "L11 target that only answers, past its record", opens: []string{"S a", "S b", "T c"}, steps: []hairpinStep{
			{from: "T", to: "S b"}, {from: "S", to: "T c", want: "S b"}, {from: "T", to: "S b", want: "T c"},
			{from: "T", others: "c"}, {from: "S", to: "T c", want: "S b"}, {from: "T", to: "S b", want: "T c"},
		}},
		{name: "L12 target that only answers, another target mapping naming the sender", opens: []string{"S a", "S b", "T c", "T b"}, steps: []hairpinStep{
			{from: "T", to: "S b"}, {from: "T", to: "S a"}, {from: "S", to: "T c", want: "S a"}, {from: "T", to: "S a", want: "T c"},
			{from: "T", others: "c"}, {from: "S", to: "T c", want: "S a"}, {from: "T", to: "S a", want: "T c"},
		}},
		{name: "L13 pair past both records", opens: []string{"S b", "S a", "T b", "T c"}, steps: []hairpinStep{
			{from: "T", to: "S a"}, {from: "S", to: "T c"}, {from: "T", to: "S a", want: "T c"}, {from: "S", to: "T c", want: "S a"},
			{from: "T", others: "c"}, {from: "T", others: "b"}, {from: "S", to: "T b", want: "S b"}, {from: "T", to: "S b", want: "T b"},
			{from: "S", others: "a"}, {from: "S", to: "T c", want: "S a"}, {from: "T", to: "S a", want: "T c"},
		}},
		{name: "L14 third leaf's endpoint on the sender's older address", opens: []string{"T c", "T b", "S a", "S b", "U a"}, steps: []hairpinStep{
			{from: "T", to: "U a"}, {from: "S", to: "T b"}, {from: "T", to: "S b", want: "T b"}, {from: "S", to: "T b", want: "S b"},
		}},
		{name: "L15 target mapping's own record before its filter", opens: []string{"S b", "S a", "T c", "U b"}, steps: []hairpinStep{
			{from: "T", to: "U b"}, {from: "T", to: "S a"}, {from: "S", to: "T c", want: "S a"}, {from: "T", to: "S a", want: "T c"},
		}},
	} {
		t.Run(layout.name, func(t *testing.T) {
			addresses := map[string]netip.Addr{"a": netip.MustParseAddr("127.0.0.1"), "b": netip.MustParseAddr("127.0.0.2"), "c": netip.MustParseAddr("127.0.0.3")}
			for _, address := range addresses {
				_ = loopbackServer(t, address)
			}
			h := newRelayHarness(t, func(rt *Runtime, _ *egress.Egress) {
				holdOnly(rt, addresses["a"], addresses["b"], addresses["c"])
			})
			port := freeUDPPortOn(t, addresses["a"], addresses["b"], addresses["c"])
			leaves := map[string]netip.AddrPort{"S": netip.AddrPortFrom(leaf4, port), "T": netip.AddrPortFrom(other4, port), "U": netip.AddrPortFrom(leaf4.Next(), port)}
			for _, open := range layout.opens {
				leaf, at, _ := strings.Cut(open, " ")
				h.x.cfg.Translate = classed(addresses[at]).Translate
				h.hairpinning(t, leaves[leaf], addresses[at])
			}
			h.x.cfg.Translate = nil
			if leaf, at, ok := strings.Cut(layout.class, " "); ok {
				translate := classed(addresses[at]).Translate
				translate[0].From = schema.PrefixFrom(netip.PrefixFrom(leaves[leaf].Addr(), 32))
				h.x.cfg.Translate = translate
			}
			// endpoint is the address and port of the mapping name names
			endpoint := func(name string) netip.AddrPort {
				leaf, at, _ := strings.Cut(name, " ")
				if m := on(h.mappingsOf(leaves[leaf]), addresses[at]); m != nil {
					return m.external()
				}
				t.Fatalf("%s holds no mapping on %s", leaf, addresses[at])
				return netip.AddrPort{}
			}
			peers := 0
			for i, step := range layout.steps {
				payload := []byte(fmt.Sprintf("step %d", i+1))
				if step.others != "" {
					translate := h.x.cfg.Translate
					for range hairpinRecord {
						peer := netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte(10 + peers)}), freeUDPPort(t, leaf4))
						peers++
						h.x.cfg.Translate = classed(addresses[step.others]).Translate
						at := netip.AddrPortFrom(addresses[step.others], h.hairpinning(t, peer, addresses[step.others]))
						h.x.cfg.Translate = translate
						h.x.udp.take(udpDatagram(leaves[step.from], at, payload), false)
					}
					h.drainLaid()
					continue
				}
				target, _, _ := strings.Cut(step.to, " ")
				to := endpoint(step.to)
				filtered := h.count(false, reasonFiltered)
				h.x.udp.take(udpDatagram(leaves[step.from], to, payload), false)
				if step.want == "" {
					if got := h.count(false, reasonFiltered) - filtered; got != 1 {
						t.Fatalf("step %d, %s to %s: filtered %d, want it filtered", i+1, step.from, step.to, got)
					}
					continue
				}
				from := endpoint(step.want)
				laid := h.waitLaid(t, fmt.Sprintf("step %d, %s to %s from %s at %s", i+1, step.from, step.to, step.want, from), func(raw []byte) bool {
					return isDatagram(raw, from, leaves[target], payload)
				})
				if !step.refused {
					continue
				}
				h.x.udp.leafError(leafRefusal(leaves[target].Addr(), from.Addr(), 3, 3, laid))
				out := h.waitLaid(t, fmt.Sprintf("step %d, %s's error to %s", i+1, target, step.from), func(raw []byte) bool {
					p, ok := parse(raw)
					return ok && p.protocol == protoICMP && p.dst == leaves[step.from].Addr()
				})
				checkServerError(t, out, to, leaves[step.from], 3, 3, payload)
			}
		})
	}
}

// A hairpinned datagram between two mappings that let each other in allocates
// no more than the packet it lays toward the target's leaf, where the sender
// holds no mapping on the address it went to and the capability holds a
// class of the family that covers neither leaf, so the class is looked up and
// the target's record read. The race build holds no count exactly and asserts
// none.
func TestHairpinnedDatagramAllocatesOnlyItsPacket(t *testing.T) {
	host, other := netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.2")
	_, _ = loopbackServer(t, host), loopbackServer(t, other)
	h := newRelayHarness(t, func(rt *Runtime, _ *egress.Egress) {
		holdOnly(rt, host, other)
	})
	h.x.cfg.Translate = []egress.Class{{From: schema.PrefixFrom(netip.MustParsePrefix("203.0.113.0/24")), To: egress.Translation{Addr: netip.MustParseAddr("203.0.113.1")}}}
	target := netip.AddrPortFrom(leaf4, freeUDPPort(t, leaf4))
	sender := netip.AddrPortFrom(other4, freeUDPPort(t, other4))
	port, senderPort := h.hairpinning(t, target, other), h.hairpinning(t, sender, host)
	h.x.udp.take(udpDatagram(target, netip.AddrPortFrom(host, senderPort), []byte("lets the host's address in")), false)
	raw := udpDatagram(sender, netip.AddrPortFrom(other, port), []byte("hairpinned"))
	h.x.udp.take(raw, false)
	h.waitLaid(t, "hairpinned datagram", func(laid []byte) bool {
		return isDatagram(laid, netip.AddrPortFrom(host, senderPort), target, []byte("hairpinned"))
	})
	allocs := testing.AllocsPerRun(datagramAllocRuns, func() {
		h.x.udp.take(raw, false)
		h.drainLaid()
	})
	if !raceBuild && allocs > 1 {
		t.Errorf("a hairpinned datagram allocated %v times, want the packet laid alone", allocs)
	}
}

// drainLaid gives back every packet the exit sent toward a leaf so far
func (h *relayHarness) drainLaid() {
	for pkt := h.x.link.poll(); pkt != nil; pkt = h.x.link.poll() {
		h.x.link.release(pkt)
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
	host := netip.MustParseAddr("127.0.0.1")
	_ = loopbackServer(t, host)
	h := newRelayHarness(t, func(rt *Runtime, _ *egress.Egress) {
		holdOnly(rt, host)
	})
	h.x.SetHopLimits(hostTTL, hostHopLimit)
	listener := netip.AddrPortFrom(leaf4, freeUDPPort(t, leaf4))
	port := h.hairpinning(t, listener, host)
	sender := netip.AddrPortFrom(other4, freeUDPPort(t, other4))
	opened := h.hairpinning(t, sender, host)
	h.x.udp.take(udpDatagram(listener, netip.AddrPortFrom(host, opened), []byte("lets the host's address in")), false)
	h.x.udp.take(udpDatagram(sender, netip.AddrPortFrom(host, port), []byte("hairpinned")), false)
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
	h.x.udp.take(raw, false)
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
	host := netip.IPv6Loopback()
	_ = loopbackServer(t, host)
	h := newRelayHarness(t, func(rt *Runtime, _ *egress.Egress) {
		holdOnly(rt, host)
	})
	listener := netip.AddrPortFrom(leaf6, freeUDPPort(t, leaf6))
	port := h.hairpinning(t, listener, host)
	sender := netip.AddrPortFrom(other6, freeUDPPort(t, other6))
	h.x.udp.take(udpDatagram(sender, netip.AddrPortFrom(host, port), make([]byte, 1<<16-1-8)), false)
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
		var out []netip.AddrPort
		for _, m := range h.mappingsOf(leaf) {
			m.mu.RLock()
			for to := range m.destinations {
				out = append(out, to)
			}
			m.mu.RUnlock()
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

// Each of a leaf's two mappings, as two classes in turn give them, lets in a
// datagram only from an address that mapping itself sent to: a server the
// first sent to reaches the leaf at the first mapping's address and port, and
// is filtered at the second's, which sent to another address alone
func TestEachMappingOfALeafFiltersByItsOwnDestinations(t *testing.T) {
	first, second := netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("127.0.0.3")
	_, _ = loopbackServer(t, first), loopbackServer(t, second)
	server := loopbackServer(t, netip.MustParseAddr("127.0.0.1"))
	elsewhere := loopbackServer(t, netip.MustParseAddr("127.0.0.4"))
	h := newRelayHarness(t, nil)
	leaf := netip.AddrPortFrom(leaf4, freeUDPPortOn(t, first, second))
	h.x.cfg.Translate = classed(first).Translate
	h.x.udp.take(udpDatagram(leaf, serverAt(server), []byte("first")), false)
	atFirst := readDatagramFrom(t, server, []byte("first"))
	h.x.cfg.Translate = classed(second).Translate
	h.x.udp.take(udpDatagram(leaf, serverAt(elsewhere), []byte("second")), false)
	atSecond := readDatagramFrom(t, elsewhere, []byte("second"))
	if len(h.mappingsOf(leaf)) != 2 || atSecond.Addr() != second {
		t.Fatalf("%s holds %d mappings and reached the second server from %s, want two and %s", leaf, len(h.mappingsOf(leaf)), atSecond, second)
	}
	filtered := h.count(false, reasonFiltered)
	if _, err := server.WriteToUDPAddrPort([]byte("to the second"), atSecond); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(exitWait)
	for h.count(false, reasonFiltered) == filtered {
		if time.Now().After(deadline) {
			t.Fatalf("the server's datagram to the second mapping, which never sent to it, was not filtered")
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := server.WriteToUDPAddrPort([]byte("to the first"), atFirst); err != nil {
		t.Fatal(err)
	}
	h.waitLaid(t, "the server's datagram to the first mapping", func(raw []byte) bool {
		return isDatagram(raw, serverAt(server), leaf, []byte("to the first"))
	})
	for _, raw := range h.mesh.laidPackets() {
		if isDatagram(raw, serverAt(server), leaf, []byte("to the second")) {
			t.Error("laid the datagram the second mapping never asked for")
		}
	}
}

// Each of a leaf's two mappings, as two classes in turn give them, lasts 5
// minutes past its own last datagram out, neither kept by the other's
// datagrams, and nothing coming in keeps either: RFC 4787 REQ-5 and REQ-6 for
// each mapping
func TestEachMappingOfALeafLastsPastItsOwnDatagramsOut(t *testing.T) {
	first, second := netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("127.0.0.3")
	_, _ = loopbackServer(t, first), loopbackServer(t, second)
	server, later := loopbackServer(t, netip.MustParseAddr("127.0.0.1")), loopbackServer(t, netip.MustParseAddr("127.0.0.1"))
	h := newRelayHarness(t, nil)
	leaf := netip.AddrPortFrom(leaf4, freeUDPPortOn(t, first, second))
	h.x.cfg.Translate = classed(first).Translate
	h.x.udp.take(udpDatagram(leaf, serverAt(server), []byte("first")), false)
	outside := readDatagramFrom(t, server, []byte("first"))
	h.advance(2 * time.Minute)
	h.x.cfg.Translate = classed(second).Translate
	h.x.udp.take(udpDatagram(leaf, serverAt(later), []byte("later")), false)
	readDatagramFrom(t, later, []byte("later"))
	mappings := h.mappingsOf(leaf)
	if len(mappings) != 2 {
		t.Fatalf("%s holds %d mappings, want one on each class's address", leaf, len(mappings))
	}
	h.advance(2 * time.Minute)
	if _, err := server.WriteToUDPAddrPort([]byte("a reply"), outside); err != nil {
		t.Fatal(err)
	}
	h.waitLaid(t, "reply", func(raw []byte) bool { return isDatagram(raw, serverAt(server), leaf, []byte("a reply")) })
	h.advance(time.Minute + time.Second)
	if !ended(mappings[0]) || ended(mappings[1]) {
		t.Errorf("5 minutes past the first mapping's datagram and 3 past the second's, the first ended %t and the second %t, want the first alone", ended(mappings[0]), ended(mappings[1]))
	}
	h.advance(2 * time.Minute)
	if !ended(mappings[1]) {
		t.Error("the second mapping outlived 5 minutes from its last datagram out")
	}
}
