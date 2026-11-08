// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package userspace

import (
	"bytes"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// for any datagram, whole or damaged, of either family, the relay comes to
// the same end whether the lane hands it over whole or the stack reassembles
// it from fragments: one function judges both, so neither path carries what
// the other refuses
func TestBothPathsEndInOneRelay(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		ipv4 := hegel.Draw(ht, hegel.Booleans())
		leaf, server := netip.AddrPortFrom(leaf6, 0), netip.AddrPortFrom(server6, 0)
		if ipv4 {
			leaf, server = netip.AddrPortFrom(leaf4, 0), netip.AddrPortFrom(server4, 0)
		}
		leaf = netip.AddrPortFrom(leaf.Addr(), hegel.Draw(ht, pbt.Spanning[uint16](1, 65535)))
		server = netip.AddrPortFrom(server.Addr(), hegel.Draw(ht, pbt.Spanning[uint16](1, 65535)))
		message := udpMessage(leaf, server, bytes.Repeat([]byte{0x3c}, hegel.Draw(ht, pbt.Spanning(0, 4000))))
		switch hegel.Draw(ht, hegel.Integers(0, 2)) {
		case 1:
			message[hegel.Draw(ht, hegel.Integers(0, len(message)-1))] ^= byte(hegel.Draw(ht, pbt.Spanning(1, 255)))
		case 2:
			message[6], message[7] = 0, 0
		}
		size := 8 * hegel.Draw(ht, pbt.Spanning(1, 150))
		var ends [2]relayEnd
		for i, packets := range [][][]byte{
			{ipPacket(leaf.Addr(), server.Addr(), protoUDP, message)},
			fragments(leaf.Addr(), server.Addr(), protoUDP, 11, message, size),
		} {
			ends[i] = relayEndOf(t, packets)
		}
		if ends[0].String() != ends[1].String() {
			ht.Fatalf("%s to %s, %d bytes: the lane's path ended %s, the stack's in fragments of %d %s", leaf, server, len(message), ends[0], size, ends[1])
		}
	})
}

// relayEnd records the end a datagram came to: the sockets readied for it and
// the counts it moved
type relayEnd struct {
	prepared         []netip.AddrPort
	refused, dropped map[string]uint64
}

func (e relayEnd) String() string {
	return fmt.Sprintf("readied %v refused %v dropped %v", e.prepared, e.refused, e.dropped)
}

// relayEndOf hands packets to a fresh exit's lane whose Prepare refuses every
// socket, so none is opened, and reports what became of them
func relayEndOf(t *testing.T, packets [][]byte) relayEnd {
	h := newRelayHarness(t, nil)
	defer closeWithin(t, h.x)
	h.refuseAll = true
	for _, raw := range packets {
		h.x.handle(h.lane, raw)
	}
	h.x.counts.mu.Lock()
	defer h.x.counts.mu.Unlock()
	return relayEnd{prepared: h.preparedSoFar(), refused: maps.Clone(h.x.counts.refused), dropped: maps.Clone(h.x.counts.dropped)}
}

// mappingModel is RFC 4787's NAT as the relay's mappings must behave: one
// mapping per leaf address and port, shared by every destination it sent to
// (REQ-1), each on a port no other live mapping holds (REQ-3), letting in a
// datagram from any port of an address it sent to and nothing else (REQ-8),
// each destination kept 5 minutes past its last datagram out, 30 seconds
// toward port 53, and the mapping as long as any of them, nothing coming in
// moving either (REQ-5, REQ-6), a new mapping held a sweep's spacing before
// its first datagram's time, and every source within its share of the flows,
// each destination one flow and its mapping riding with it, so a datagram
// past the share opens nothing
type mappingModel struct {
	now      time.Duration
	share    int
	mappings map[netip.AddrPort]*modelMapping
}

type modelMapping struct {
	port         uint16
	deadline     time.Duration
	destinations map[netip.AddrPort]time.Duration
}

func (m *mappingModel) timeout(to netip.AddrPort) time.Duration {
	if to.Port() == 53 {
		return 30 * time.Second
	}
	return 5 * time.Minute
}

// held is the flows source holds
func (m *mappingModel) held(source netip.Addr) int {
	n := 0
	for leaf, mapping := range m.mappings {
		if leaf.Addr() == source {
			n += len(mapping.destinations)
		}
	}
	return n
}

// send is the refusal a datagram from leaf to to meets, empty where it goes,
// and moves the model as the datagram does
func (m *mappingModel) send(leaf, to netip.AddrPort) string {
	mapping := m.mappings[leaf]
	if (mapping == nil || mapping.destinations[to] == 0) && m.held(leaf.Addr()) >= m.share {
		return reasonShare
	}
	if mapping == nil {
		mapping = &modelMapping{deadline: m.now + 5*time.Second, destinations: map[netip.AddrPort]time.Duration{}}
		m.mappings[leaf] = mapping
	}
	mapping.destinations[to] = m.now + m.timeout(to)
	mapping.deadline = max(mapping.deadline, m.now+m.timeout(to))
	return ""
}

// admits is whether leaf's mapping lets in a datagram from from
func (m *mappingModel) admits(leaf, from netip.AddrPort) bool {
	for to := range m.mappings[leaf].destinations {
		if to.Addr() == from.Addr() {
			return true
		}
	}
	return false
}

// advance moves the clock and ends what is past its time
func (m *mappingModel) advance(d time.Duration) {
	m.now += d
	for leaf, mapping := range m.mappings {
		if mapping.deadline <= m.now {
			delete(m.mappings, leaf)
			continue
		}
		for to, deadline := range mapping.destinations {
			if deadline <= m.now {
				delete(mapping.destinations, to)
			}
		}
	}
}

// for any order of datagrams out from a few leaf addresses and ports to a few
// servers, replies, datagrams from other ports and addresses toward the
// mappings, and time passing, the relay's mappings are the model's: the same
// leaves and destinations live, each leaf seen from one port by every server,
// no two live mappings on one port, a datagram coming in carried to the leaf
// exactly where the model lets it in and dropped and counted otherwise, and
// each refusal the model's. Servers and strangers are sockets on addresses of
// the loopback's network.
func TestMappingsAreTheModels(t *testing.T) {
	addresses := []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("127.0.0.3")}
	stranger := netip.MustParseAddr("127.0.0.4")
	port := freeUDPPort(t, leaf4)
	leaves := []netip.AddrPort{netip.AddrPortFrom(leaf4, port), netip.AddrPortFrom(leaf4, freeUDPPort(t, leaf4)), netip.AddrPortFrom(other4, port)}
	delays := []time.Duration{time.Second, 25 * time.Second, 31 * time.Second, 2 * time.Minute, 5*time.Minute + time.Second}
	// a namespace whose loopback is down carries no datagram, and a host whose
	// loopback holds 127.0.0.1 alone serves on none but the first
	for _, address := range append(addresses, stranger) {
		_ = loopbackServer(t, address)
	}
	pbt.Check(t, func(ht *hegel.T) {
		share := hegel.Draw(ht, pbt.Spanning(1, 6))
		h := newRelayHarness(t, func(_ *Runtime, cfg *egress.Egress) { cfg.FlowsPerSource = uint32(share) })
		defer closeWithin(t, h.x)
		var opened []*net.UDPConn
		defer func() {
			for _, conn := range opened {
				_ = conn.Close()
			}
		}()
		listen := func(address netip.Addr) *net.UDPConn {
			conn, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(address, 0)))
			if err != nil {
				ht.Fatalf("a server on %s: %v", address, err)
			}
			opened = append(opened, conn)
			return conn
		}
		var servers []*net.UDPConn
		for _, address := range addresses {
			servers = append(servers, listen(address))
		}
		dns := netip.AddrPortFrom(addresses[0], 53)
		others := []*net.UDPConn{listen(addresses[0]), listen(stranger)}
		model := &mappingModel{share: share, mappings: map[netip.AddrPort]*modelMapping{}}
		steps := hegel.Draw(ht, hegel.Integers(1, 24))
		for step := range steps {
			leaf := leaves[hegel.Draw(ht, hegel.Integers(0, len(leaves)-1))]
			payload := []byte(fmt.Sprintf("step %d", step))
			switch hegel.Draw(ht, hegel.Integers(0, 3)) {
			case 0:
				pick := hegel.Draw(ht, hegel.Integers(0, len(servers)))
				to := dns
				if pick < len(servers) {
					to = serverAt(servers[pick])
				}
				answered := len(h.mesh.answered())
				want := model.send(leaf, to)
				h.x.udp.take(udpDatagram(leaf, to, payload), false)
				if want != "" {
					answers := h.mesh.answered()
					if len(answers) != answered+1 || answers[answered].kind != netstack.ExitPastLimit {
						ht.Fatalf("step %d: %s to %s past its share of %d: answered %v, want one past the limit", step, leaf, to, share, answers[answered:])
					}
					break
				}
				if len(h.mesh.answered()) != answered {
					ht.Fatalf("step %d: %s to %s within its share answered %v", step, leaf, to, h.mesh.answered()[answered:])
				}
				if pick == len(servers) {
					break
				}
				from := readDatagramFrom(ht, servers[pick], payload)
				mapping := model.mappings[leaf]
				if mapping.port == 0 {
					mapping.port = from.Port()
				}
				if from.Port() != mapping.port {
					ht.Fatalf("step %d: %s read %s from port %d, its mapping's other servers from %d", step, to, leaf, from.Port(), mapping.port)
				}
			case 1, 2:
				mapping := model.mappings[leaf]
				if mapping == nil || mapping.port == 0 {
					break
				}
				var conn *net.UDPConn
				if hegel.Draw(ht, hegel.Booleans()) {
					conn = servers[hegel.Draw(ht, hegel.Integers(0, len(servers)-1))]
				} else {
					conn = others[hegel.Draw(ht, hegel.Integers(0, len(others)-1))]
				}
				from := serverAt(conn)
				admitted := model.admits(leaf, from)
				filtered := h.count(false, reasonFiltered)
				if _, err := conn.WriteToUDPAddrPort(payload, netip.AddrPortFrom(from.Addr(), mapping.port)); err != nil {
					ht.Fatalf("step %d: %s sending to %s's mapping: %v", step, from, leaf, err)
				}
				if admitted {
					deadline := time.Now().Add(exitWait)
					for laid := false; !laid; {
						if pkt := h.x.link.poll(); pkt != nil {
							view := pkt.ToView()
							raw := bytes.Clone(view.AsSlice())
							view.Release()
							h.x.link.release(pkt)
							if !isDatagram(raw, from, leaf, payload) {
								p, _ := parse(raw)
								ht.Fatalf("step %d: laid %s, want the datagram from %s to %s", step, p, from, leaf)
							}
							laid = true
							continue
						}
						if h.count(false, reasonFiltered) != filtered {
							ht.Fatalf("step %d: the datagram from %s, an address %s's mapping sent to, was dropped as filtered", step, from, leaf)
						}
						if time.Now().After(deadline) {
							ht.Fatalf("step %d: the datagram from %s to %s's mapping was neither carried nor dropped as filtered", step, from, leaf)
						}
						time.Sleep(time.Millisecond)
					}
					break
				}
				deadline := time.Now().Add(exitWait)
				for h.count(false, reasonFiltered) == filtered {
					if pkt := h.x.link.poll(); pkt != nil {
						h.x.link.release(pkt)
						ht.Fatalf("step %d: the datagram from %s, an address %s's mapping never sent to, was carried to the leaf", step, from, leaf)
					}
					if time.Now().After(deadline) {
						ht.Fatalf("step %d: the datagram from %s to %s's mapping was neither carried nor dropped as filtered", step, from, leaf)
					}
					time.Sleep(time.Millisecond)
				}
			case 3:
				d := delays[hegel.Draw(ht, hegel.Integers(0, len(delays)-1))]
				model.advance(d)
				h.advance(d)
			}
			checkMappings(ht, step, h, model)
		}
	})
}

// checkMappings fails ht where the relay's live mappings and destinations are
// not the model's, two live mappings hold one port, or the flows held are not
// the destinations
func checkMappings(ht *hegel.T, step int, h *relayHarness, model *mappingModel) {
	h.x.udp.mu.RLock()
	defer h.x.udp.mu.RUnlock()
	ports := map[uint16]netip.AddrPort{}
	flows := 0
	for leaf, m := range h.x.udp.mappings {
		want := model.mappings[leaf]
		if want == nil {
			ht.Fatalf("step %d: %s holds a mapping the model ended", step, leaf)
		}
		if other, taken := ports[m.port]; taken {
			ht.Fatalf("step %d: %s and %s both hold port %d", step, leaf, other, m.port)
		}
		ports[m.port] = leaf
		m.mu.RLock()
		var got, wanted []netip.AddrPort
		for to := range m.destinations {
			got = append(got, to)
		}
		m.mu.RUnlock()
		for to := range want.destinations {
			wanted = append(wanted, to)
		}
		slices.SortFunc(got, netip.AddrPort.Compare)
		slices.SortFunc(wanted, netip.AddrPort.Compare)
		if !slices.Equal(got, wanted) {
			ht.Fatalf("step %d: %s's mapping holds destinations %v, the model %v", step, leaf, got, wanted)
		}
		flows += len(got)
	}
	if len(h.x.udp.mappings) != len(model.mappings) {
		ht.Fatalf("step %d: %d mappings live, the model %d", step, len(h.x.udp.mappings), len(model.mappings))
	}
	h.x.flows.mu.Lock()
	defer h.x.flows.mu.Unlock()
	if h.x.flows.open != flows {
		ht.Fatalf("step %d: %d flows held, the mappings %d", step, h.x.flows.open, flows)
	}
}

// for any IPv6 packet the exit builds toward a leaf and any MTU of the leaf's
// session, what it sends is the packet whole where it fits, and otherwise
// fragments of no more than the MTU that reassemble to it (RFC 8200 section
// 4.5), and an IPv4 packet goes whole for the lane to cut
func TestPacketTowardALeafIsCutAsItsSource(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		h := newRelayHarness(t, nil)
		defer closeWithin(t, h.x)
		h.mesh.mtu = hegel.Draw(ht, pbt.Spanning(1280, 9000))
		ipv4 := hegel.Draw(ht, hegel.Booleans())
		from, to := netip.AddrPortFrom(server6, 53), netip.AddrPortFrom(leaf6, 40000)
		if ipv4 {
			from, to = netip.AddrPortFrom(server4, 53), netip.AddrPortFrom(leaf4, 40000)
		}
		payload := bytes.Repeat([]byte{0x96}, hegel.Draw(ht, pbt.Spanning(0, 20000)))
		pkt := udpDatagram(from, to, payload)
		h.x.toLeaf(slices.Clone(pkt), 7)
		var laid [][]byte
		for p := h.x.link.poll(); p != nil; p = h.x.link.poll() {
			view := p.ToView()
			laid = append(laid, bytes.Clone(view.AsSlice()))
			view.Release()
			h.x.link.release(p)
		}
		if ipv4 || len(pkt) <= h.mesh.mtu {
			if len(laid) != 1 || !bytes.Equal(laid[0], pkt) {
				ht.Fatalf("%d bytes at an MTU of %d sent as %d packets, want it whole", len(pkt), h.mesh.mtu, len(laid))
			}
			return
		}
		for _, f := range laid {
			if len(f) > h.mesh.mtu {
				ht.Fatalf("a fragment of %d bytes past the MTU of %d", len(f), h.mesh.mtu)
			}
		}
		whole, ok := reassemble6(laid)
		if !ok || !bytes.Equal(whole, pkt) {
			ht.Fatalf("%d bytes at an MTU of %d cut into %d fragments that do not reassemble to it", len(pkt), h.mesh.mtu, len(laid))
		}
	})
}
