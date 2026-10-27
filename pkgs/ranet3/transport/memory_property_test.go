// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package transport

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// a script holds at most scriptHubs hubs and scriptPeers sockets and runs at most scriptSteps steps
// few enough datagrams that loopback drops none of them
const (
	scriptHubs  = 3
	scriptPeers = 3
	scriptSteps = 24
)

// scriptArrivalBudget is how long a script on loopback waits for a datagram it sent to arrive
const scriptArrivalBudget = 5 * time.Second

// scriptLoopbacks is the loopback address of each family, IPv4 first
var scriptLoopbacks = []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}

// scriptSocket holds the calls a script makes on a socket, net's on loopback and MemoryConn on a memory network
type scriptSocket interface {
	ReadFromUDP(b []byte) (int, *net.UDPAddr, error)
	WriteToUDP(b []byte, addr *net.UDPAddr) (int, error)
	SetReadDeadline(t time.Time) error
	LocalAddr() net.Addr
	Close() error
}

// scriptNetwork is one network a script runs on, and what the script saw there
type scriptNetwork struct {
	newHub    func() (*Hub, error)
	newSocket func(net.IP) (scriptSocket, error)
	// hubs and peers are nil once closed, and closed holds the ports they held
	hubs      []*Hub
	unclaimed []<-chan Unclaimed
	peers     []scriptSocket
	closed    []int
	// muxes holds the mux of each hub and peer a step reached
	muxes map[[2]int]*Mux
	// roles names each hub and peer by its address and port, so that the two networks compare by role
	roles map[netip.AddrPort]string
	// delivered counts the datagrams each hub put in a queue the script drained
	delivered []int
	log       []string
}

func (n *scriptNetwork) role(addr netip.AddrPort) string {
	addr = netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())
	if role, ok := n.roles[addr]; ok {
		return role
	}
	return "unknown " + addr.String()
}

func (n *scriptNetwork) note(format string, args ...any) {
	n.log = append(n.log, fmt.Sprintf(format, args...))
}

// mux is the mux on hub h to peer p, opened the first time a step asks for it
func (n *scriptNetwork) mux(h, p int) (*Mux, error) {
	if m := n.muxes[[2]int{h, p}]; m != nil {
		return m, nil
	}
	local := n.peers[p].LocalAddr().(*net.UDPAddr)
	m, err := n.hubs[h].NewMux(local.IP, local.Port)
	if err == nil {
		n.muxes[[2]int{h, p}] = m
	}
	return m, err
}

// gather drains what hub h delivered to its muxes and its unclaimed queue, until it has delivered or counted want datagrams or the budget ends
func (n *scriptNetwork) gather(h, want int) {
	hub := n.hubs[h]
	deadline := time.Now().Add(scriptArrivalBudget)
	for {
		for p := range n.peers {
			if m := n.muxes[[2]int{h, p}]; m != nil {
				n.drain(h, p, m)
			}
		}
		for drained := true; drained && n.unclaimed[h] != nil; {
			select {
			case u := <-n.unclaimed[h]:
				n.note("hub %d unclaimed %x from %s", h, u.Raw, n.role(u.Endpoint.AddrPort()))
				n.delivered[h]++
			default:
				drained = false
			}
		}
		counted := int(hub.Refused() + hub.Keepalives() + hub.Dropped())
		if n.delivered[h]+counted >= want || time.Now().After(deadline) {
			n.note("hub %d refused %d keepalives %d dropped %d", h, hub.Refused(), hub.Keepalives(), hub.Dropped())
			return
		}
		time.Sleep(time.Millisecond)
	}
}

func (n *scriptNetwork) drain(h, p int, m *Mux) {
	for {
		select {
		case d := <-m.ikeCh:
			n.note("hub %d mux %d IKE %x from %s", h, p, d.Raw, n.role(d.Endpoint.AddrPort()))
			n.delivered[h]++
		case batch := <-m.espCh:
			for _, packet := range m.takeESP(batch) {
				n.note("hub %d mux %d ESP %x", h, p, packet)
				n.delivered[h]++
			}
		default:
			return
		}
	}
}

func (n *scriptNetwork) close() {
	for _, p := range n.peers {
		if p != nil {
			p.Close()
		}
	}
	for _, h := range n.hubs {
		if h != nil {
			h.Close()
		}
	}
}

// scriptDatagram is a datagram of the shape drawn: an IKE message with the non-ESP marker, ESP, a keepalive, under four octets or empty
// IKE and ESP name SPI spi, which no mux holds at 0, and carry step and size more octets
func scriptDatagram(shape, spi, step, size int) []byte {
	switch shape {
	case 0:
		return append(append(make([]byte, 4+7), byte(spi), byte(step)), bytes.Repeat([]byte{byte(size)}, size)...)
	case 1:
		return append([]byte{0, 0, 0, byte(spi), byte(step)}, bytes.Repeat([]byte{byte(size)}, size)...)
	case 2:
		return []byte{natKeepaliveByte}
	case 3:
		return []byte{0x80, 1, 2}[:1+size%3]
	}
	return nil
}

// a memory network carries what loopback carries, over drawn scripts run on both side by side
// hubs and sockets in both families, sends of IKE messages with the non-ESP marker, ESP, keepalives, datagrams under four octets and empty ones,
// SPIs registered or not, Listen on and off, sends to a port nobody holds, a socket's and a hub's sends to port zero, reads shorter than their datagram, and closes
// after each step what each hub's muxes and unclaimed queue received, in order and with the source by role, its counters, and what each socket read are the same on both
func TestMemoryNetworkCarriesWhatLoopbackCarries(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		memory := NewMemoryNetwork()
		networks := []*scriptNetwork{
			{newHub: func() (*Hub, error) { return NewHub(":0", Underlay{}, Runtime{}) },
				newSocket: func(ip net.IP) (scriptSocket, error) { return net.ListenUDP("udp", &net.UDPAddr{IP: ip}) }},
			{newHub: memory.NewHub, newSocket: func(ip net.IP) (scriptSocket, error) { return memory.ListenUDP(ip) }},
		}
		for _, n := range networks {
			n.muxes, n.roles = map[[2]int]*Mux{}, map[netip.AddrPort]string{}
			defer n.close()
		}
		draw := func(lo, hi int) int { return hegel.Draw(ht, hegel.Integers(lo, hi)) }
		// expected is how many datagrams each hub is sent at a loopback address, and pending how many each socket is sent at its own and not read yet
		// families is each socket's family, and open whether each hub and socket is
		var expected, pending, families []int
		var hubOpen, peerOpen []bool
		for step := range draw(1, scriptSteps) {
			hubs, peers := len(expected), len(pending)
			switch kind := draw(0, 8); {
			case kind == 0 && hubs < scriptHubs:
				for _, n := range networks {
					hub, err := n.newHub()
					if err != nil {
						ht.Fatal(err)
					}
					port := uint16(hub.LocalAddr().(*net.UDPAddr).Port)
					for _, ip := range scriptLoopbacks {
						n.roles[netip.AddrPortFrom(netip.MustParseAddr(ip.String()), port)] = fmt.Sprintf("hub %d", hubs)
					}
					n.hubs, n.unclaimed, n.delivered = append(n.hubs, hub), append(n.unclaimed, nil), append(n.delivered, 0)
				}
				expected, hubOpen = append(expected, 0), append(hubOpen, true)
			case kind == 1 && peers < scriptPeers:
				family := draw(0, 1)
				for _, n := range networks {
					peer, err := n.newSocket(scriptLoopbacks[family])
					if err != nil {
						ht.Fatal(err)
					}
					local := peer.LocalAddr().(*net.UDPAddr).AddrPort()
					n.roles[netip.AddrPortFrom(local.Addr().Unmap(), local.Port())] = fmt.Sprintf("peer %d", peers)
					n.peers = append(n.peers, peer)
				}
				pending, families, peerOpen = append(pending, 0), append(families, family), append(peerOpen, true)
			case kind == 2 && hubs > 0 && peers > 0:
				h, p, ike, spi := draw(0, hubs-1), draw(0, peers-1), draw(0, 1) == 0, draw(1, 3)
				if !hubOpen[h] || !peerOpen[p] {
					break
				}
				for _, n := range networks {
					m, err := n.mux(h, p)
					if err == nil && ike {
						err = m.RegisterIKE(uint64(spi))
					} else if err == nil {
						err = m.RegisterESP(uint32(spi))
					}
					n.note("step %d hub %d mux %d registers IKE %v SPI %d: %v", step, h, p, ike, spi, err != nil)
				}
			case kind == 3 && hubs > 0:
				h, on := draw(0, hubs-1), draw(0, 1) == 0
				if !hubOpen[h] {
					break
				}
				for _, n := range networks {
					n.gather(h, expected[h])
					if on {
						n.unclaimed[h] = n.hubs[h].Listen()
					} else {
						n.hubs[h].StopListening()
						n.unclaimed[h] = nil
					}
				}
			case (kind == 4 && hubs > 0 || kind == 5) && peers > 0:
				p, shape, spi, size, zero := draw(0, peers-1), draw(0, 4), draw(0, 3), draw(0, 48), draw(0, 3) == 0
				// a hub, a socket of the sender's family, port zero, or a port nobody holds
				hub, target := -1, -1
				if kind == 4 {
					hub = draw(0, hubs-1)
				} else if target = draw(0, peers); target < peers && families[target] != families[p] {
					break
				}
				if !peerOpen[p] {
					break
				}
				datagram := scriptDatagram(shape, spi, step, size)
				for _, n := range networks {
					var addr *net.UDPAddr
					switch {
					case hub >= 0 && hubOpen[hub]:
						addr = &net.UDPAddr{IP: scriptLoopbacks[families[p]], Port: n.hubs[hub].LocalAddr().(*net.UDPAddr).Port}
					case target >= 0 && target < peers && peerOpen[target]:
						addr = n.peers[target].LocalAddr().(*net.UDPAddr)
					case zero:
						addr = &net.UDPAddr{IP: scriptLoopbacks[families[p]]}
					case len(n.closed) > 0:
						addr = &net.UDPAddr{IP: scriptLoopbacks[families[p]], Port: n.closed[0]}
					default:
						continue
					}
					sent := slices.Clone(datagram)
					written, err := n.peers[p].WriteToUDP(sent, addr)
					// a send keeps nothing of its buffer once it returned
					for i := range sent {
						sent[i] = 0xee
					}
					n.note("step %d peer %d sends %x to %s: %d %v", step, p, datagram, n.role(addr.AddrPort()), written, err != nil)
				}
				switch {
				case hub >= 0 && hubOpen[hub]:
					expected[hub]++
				case target >= 0 && target < peers && peerOpen[target]:
					pending[target]++
				}
			case kind == 6 && hubs > 0 && peers > 0:
				h, p, ike, zero := draw(0, hubs-1), draw(0, peers-1), draw(0, 1) == 0, draw(0, 3) == 0
				payload := append([]byte{1, 2, 3, 4, 5, byte(step)}, bytes.Repeat([]byte{7}, draw(0, 48))...)
				if !hubOpen[h] || !zero && !peerOpen[p] {
					break
				}
				for _, n := range networks {
					var m *Mux
					var err error
					target := fmt.Sprintf("peer %d", p)
					if zero {
						// a mux to port zero at the loopback address of peer p's family
						m, err = n.hubs[h].NewMux(scriptLoopbacks[families[p]], 0)
						target = fmt.Sprintf("port zero of peer %d's family", p)
					} else {
						m, err = n.mux(h, p)
					}
					if err == nil && ike {
						err = m.SendIKE(payload)
					} else if err == nil {
						err = m.SendESP(payload)
					}
					n.note("step %d hub %d sends IKE %v %x to %s: %v", step, h, ike, payload, target, err != nil)
					if zero && m != nil {
						m.Close()
					}
				}
				if !zero {
					pending[p]++
				}
			case kind == 7 && peers > 0:
				p, size := draw(0, peers-1), draw(0, 80)
				if !peerOpen[p] {
					break
				}
				for _, n := range networks {
					for range pending[p] {
						buf := make([]byte, size)
						if err := n.peers[p].SetReadDeadline(time.Now().Add(scriptArrivalBudget)); err != nil {
							ht.Fatal(err)
						}
						read, from, err := n.peers[p].ReadFromUDP(buf)
						source := "none"
						if from != nil {
							source = n.role(from.AddrPort())
						}
						n.note("step %d peer %d reads %x from %s: %v", step, p, buf[:read], source, err != nil)
					}
				}
				pending[p] = 0
			case kind == 8 && draw(0, 1) == 0 && peers > 0:
				p := draw(0, peers-1)
				if !peerOpen[p] {
					break
				}
				for _, n := range networks {
					n.closed = append(n.closed, n.peers[p].LocalAddr().(*net.UDPAddr).Port)
					n.note("step %d peer %d closes: %v", step, p, n.peers[p].Close() != nil)
					n.peers[p] = nil
				}
				peerOpen[p] = false
			case kind == 8 && hubs > 0:
				h := draw(0, hubs-1)
				if !hubOpen[h] {
					break
				}
				for _, n := range networks {
					n.gather(h, expected[h])
					n.closed = append(n.closed, n.hubs[h].LocalAddr().(*net.UDPAddr).Port)
					n.note("step %d hub %d closes: %v", step, h, n.hubs[h].Close() != nil)
					n.hubs[h] = nil
				}
				hubOpen[h] = false
			}
			for h := range expected {
				if hubOpen[h] {
					for _, n := range networks {
						n.gather(h, expected[h])
					}
				}
			}
			if !slices.Equal(networks[0].log, networks[1].log) {
				ht.Fatalf("after step %d the networks differ\non loopback:\n%s\nin memory:\n%s", step, strings.Join(networks[0].log, "\n"), strings.Join(networks[1].log, "\n"))
			}
		}
	})
}
