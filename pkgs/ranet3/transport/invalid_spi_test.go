// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package transport

import (
	"encoding/binary"
	"maps"
	"net"
	"net/netip"
	"runtime"
	"testing"
	"testing/synctest"
	"time"

	"ranet3.com/pkgs/ranet3/internal/bubble"
)

// knownSPI is the first ESP SPI the tests' muxes hold, and strayedSPI one none holds
const (
	knownSPI   = 0x1000
	strayedSPI = 0x2000
)

// lookWait is how long in real time a test waits for the receive loop to start a look, which it starts as soon as it reads the datagram
const lookWait = 5 * time.Second

// invalidSPIHub opens a hub on a memory network with a peer socket at each address and a mux to each, the i-th holding knownSPI+i
func invalidSPIHub(t *testing.T, addresses ...string) (*MemoryNetwork, *Hub, []*MemoryConn, []*Mux) {
	t.Helper()
	network := NewMemoryNetwork()
	hub, err := network.NewHub()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { hub.Close() })
	var peers []*MemoryConn
	var muxes []*Mux
	for i, address := range addresses {
		peer := listenOn(t, network, address)
		at := peer.LocalAddr().(*net.UDPAddr)
		mux, err := hub.NewMux(at.IP, at.Port)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { mux.Close() })
		if err := mux.RegisterESP(knownSPI + uint32(i)); err != nil {
			t.Fatal(err)
		}
		peers, muxes = append(peers, peer), append(muxes, mux)
	}
	return network, hub, peers, muxes
}

// listenOn opens a socket at address on network, closed at cleanup
func listenOn(t *testing.T, network *MemoryNetwork, address string) *MemoryConn {
	t.Helper()
	conn, err := network.ListenUDP(net.ParseIP(address))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// sendESP sends hub one ESP datagram on spi from conn, and waits until the hub has read it
func sendESP(t *testing.T, conn *MemoryConn, hub *Hub, spi uint32) {
	t.Helper()
	datagram := binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, spi), 1)
	if _, err := conn.WriteToUDP(datagram, &net.UDPAddr{IP: net.ParseIP("192.0.2.9"), Port: int(hub.port)}); err != nil {
		t.Fatal(err)
	}
	synctest.Wait()
}

// scriptedArrival is one datagram a test hands a scripted hub's receive loop
type scriptedArrival struct {
	data   []byte
	source netip.AddrPort
}

// scriptedHub opens a hub whose one receive loop reads what is sent on the channel it answers, each datagram from the source it names
func scriptedHub() (*Hub, chan<- scriptedArrival) {
	network := NewMemoryNetwork()
	p := network.hold(netip.Addr{})
	arrivals := make(chan scriptedArrival)
	receive := func(bufs [][]byte, sizes []int, endpoints []Endpoint, records []receiveRecord) (int, int, error) {
		a, ok := <-arrivals
		if !ok {
			return 0, 0, net.ErrClosed
		}
		bufs[0], sizes[0], endpoints[0], records[0] = a.data, len(a.data), nil, receiveRecord{source: a.source}
		return 1, 0, nil
	}
	return startHub(&memoryBind{network: network, port: p}, []receiveFunc{receive}, p.port, Runtime{}), arrivals
}

// told answers the SPI mux's channel holds and takes it, and false where it holds none
func told(mux *Mux) (uint32, bool) {
	select {
	case spi := <-mux.InvalidSPI():
		return spi, true
	default:
		return 0, false
	}
}

// ESP on an SPI no mux holds is handed to the mux whose destination sent it, and counted as refused
// from another port of that address or from another address it is counted alone
func TestUnknownSPIFromASessionsAddressIsReported(t *testing.T) {
	bubble.Run(func(t *testing.T) {
		network, hub, peers, muxes := invalidSPIHub(t, "192.0.2.1")
		for _, stranger := range []string{"192.0.2.1", "192.0.2.2"} {
			from := listenOn(t, network, stranger)
			refused := hub.Refused()
			sendESP(t, from, hub, strayedSPI)
			if spi, ok := told(muxes[0]); ok {
				t.Errorf("ESP on SPI %#x from %s was handed to the session at %s", spi, from.LocalAddr(), peers[0].LocalAddr())
			}
			if hub.Refused() != refused+1 {
				t.Errorf("ESP on an unknown SPI from %s raised refused by %d, want 1", from.LocalAddr(), hub.Refused()-refused)
			}
			time.Sleep(invalidSPIInterval)
		}
		refused := hub.Refused()
		sendESP(t, peers[0], hub, strayedSPI)
		if spi, ok := told(muxes[0]); !ok || spi != strayedSPI {
			t.Errorf("ESP on SPI %#x from the session's own address and port was handed on as %#x (%v)", strayedSPI, spi, ok)
		}
		if hub.Refused() != refused+1 {
			t.Errorf("ESP on an unknown SPI from the session raised refused by %d, want 1", hub.Refused()-refused)
		}
	})(t)
}

// ESP from another address at the session's port is not the session's peer's, and draws nothing
func TestUnknownSPIFromAnotherAddressAtTheSessionsPortIsNotHandedOn(t *testing.T) {
	bubble.Run(func(t *testing.T) {
		hub, arrivals := scriptedHub()
		defer hub.Close()
		defer close(arrivals)
		mux, err := hub.NewMuxTo(newMemoryEndpoint(netip.MustParseAddrPort("192.0.2.1:4500")))
		if err != nil {
			t.Fatal(err)
		}
		for _, source := range []netip.AddrPort{netip.MustParseAddrPort("192.0.2.2:4500"), netip.MustParseAddrPort("192.0.2.1:4500")} {
			arrivals <- scriptedArrival{data: binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, strayedSPI), 1), source: source}
			synctest.Wait()
			spi, ok := told(mux)
			if source != mux.Endpoint().AddrPort() && ok {
				t.Errorf("ESP on SPI %#x from %s was handed to the session at %s as %#x", strayedSPI, source, mux.Endpoint(), spi)
			}
			if source == mux.Endpoint().AddrPort() && (!ok || spi != strayedSPI) {
				t.Errorf("ESP on SPI %#x from the session's own %s was handed on as %#x (%v)", strayedSPI, source, spi, ok)
			}
			time.Sleep(invalidSPIInterval)
		}
	})(t)
}

// two link-local peers sharing one address and port on two interfaces are two destinations, so ESP from one is handed to its own session alone
// a session whose endpoint names no interface, as a dialed one's does, is handed ESP from its address and port on any
func TestUnknownSPIFromALinkLocalPeerIsHandedToItsInterfacesSession(t *testing.T) {
	bubble.Run(func(t *testing.T) {
		hub, arrivals := scriptedHub()
		defer hub.Close()
		defer close(arrivals)
		var muxes []*Mux
		for _, zone := range []string{"1", "2"} {
			mux, err := hub.NewMuxTo(newMemoryEndpoint(netip.MustParseAddrPort("[fe80::1%" + zone + "]:4500")))
			if err != nil {
				t.Fatal(err)
			}
			muxes = append(muxes, mux)
		}
		zoneless, err := hub.NewMux(net.ParseIP("fe80::1"), 4500)
		if err != nil {
			t.Fatal(err)
		}
		source := netip.MustParseAddrPort("[fe80::1%2]:4500")
		arrivals <- scriptedArrival{data: binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, strayedSPI), 1), source: source}
		synctest.Wait()
		if spi, ok := told(muxes[0]); ok {
			t.Errorf("ESP on SPI %#x from %s was handed to the session at %s as %#x", strayedSPI, source, muxes[0].Endpoint(), spi)
		}
		if spi, ok := told(muxes[1]); !ok || spi != strayedSPI {
			t.Errorf("ESP on SPI %#x from %s was handed to the session at %s as %#x (%v)", strayedSPI, source, muxes[1].Endpoint(), spi, ok)
		}
		if spi, ok := told(zoneless); !ok || spi != strayedSPI {
			t.Errorf("ESP on SPI %#x from %s was handed to the session at %s, which names no interface, as %#x (%v)", strayedSPI, source, zoneless.Endpoint(), spi, ok)
		}
	})(t)
}

// a session's peer that moved is matched where it is now, so ESP on an unknown SPI from its old address draws nothing and from its new one is handed on
func TestUnknownSPIFromAMovedPeerIsReportedWhereItIsNow(t *testing.T) {
	bubble.Run(func(t *testing.T) {
		network, hub, peers, muxes := invalidSPIHub(t, "192.0.2.1")
		moved := listenOn(t, network, "192.0.2.2")
		if !muxes[0].AdoptEndpoint(newMemoryEndpoint(moved.LocalAddr().(*net.UDPAddr).AddrPort())) {
			t.Fatalf("the session did not move to %s", moved.LocalAddr())
		}
		sendESP(t, peers[0], hub, strayedSPI)
		if spi, ok := told(muxes[0]); ok {
			t.Errorf("ESP on SPI %#x from %s, where the session's peer was, was handed on as %#x", strayedSPI, peers[0].LocalAddr(), spi)
		}
		time.Sleep(invalidSPIInterval)
		sendESP(t, moved, hub, strayedSPI)
		if spi, ok := told(muxes[0]); !ok || spi != strayedSPI {
			t.Errorf("ESP on SPI %#x from %s, where the session's peer moved to, was handed on as %#x (%v)", strayedSPI, moved.LocalAddr(), spi, ok)
		}
	})(t)
}

// the hub looks once an interval, whoever sent
// a burst of unknown SPIs from one session's peer is handed on once, though the session takes each at once, and another session's peer within the same interval only when it comes again after the interval
func TestUnknownSPIScansAreLimited(t *testing.T) {
	bubble.Run(func(t *testing.T) {
		_, hub, peers, muxes := invalidSPIHub(t, "192.0.2.1", "192.0.2.2")
		for i := range uint32(3) {
			sendESP(t, peers[0], hub, strayedSPI+i)
			spi, ok := told(muxes[0])
			if i == 0 && (!ok || spi != strayedSPI) {
				t.Errorf("the first of a burst was handed on as %#x (%v), want %#x", spi, ok, strayedSPI)
			}
			if i > 0 && ok {
				t.Errorf("datagram %d of a burst within one interval was handed on as %#x", i, spi)
			}
			time.Sleep(invalidSPIInterval / 10)
		}
		sendESP(t, peers[1], hub, strayedSPI+3)
		if spi, ok := told(muxes[1]); ok {
			t.Errorf("the second session's unknown SPI %#x was handed on within the interval of the first's", spi)
		}
		time.Sleep(invalidSPIInterval)
		sendESP(t, peers[1], hub, strayedSPI+3)
		if spi, ok := told(muxes[1]); !ok || spi != strayedSPI+3 {
			t.Errorf("the second session's unknown SPI after the interval was handed on as %#x (%v), want %#x", spi, ok, strayedSPI+3)
		}
	})(t)
}

// ESP on an SPI the mux holds goes to its session and is never handed on as unknown
func TestKnownSPIIsNeverReported(t *testing.T) {
	bubble.Run(func(t *testing.T) {
		_, hub, peers, muxes := invalidSPIHub(t, "192.0.2.1")
		refused := hub.Refused()
		sendESP(t, peers[0], hub, knownSPI)
		if spi, ok := told(muxes[0]); ok {
			t.Errorf("ESP on the session's own SPI %#x was handed on as unknown, %#x", knownSPI, spi)
		}
		if packet, err := muxes[0].RecvESPUntil(time.Now().Add(arrivalBudget)); err != nil || binary.BigEndian.Uint32(packet) != knownSPI {
			t.Errorf("the session read %x, %v, want its ESP on SPI %#x", packet, err, knownSPI)
		}
		if hub.Refused() != refused {
			t.Errorf("ESP on a known SPI raised refused by %d", hub.Refused()-refused)
		}
	})(t)
}

// an SPI a mux took after the hub handed it on is known, so the session that asks before it tells its peer tells nothing
func TestSPITakenAfterItWasHandedOnIsKnown(t *testing.T) {
	bubble.Run(func(t *testing.T) {
		_, hub, peers, muxes := invalidSPIHub(t, "192.0.2.1")
		sendESP(t, peers[0], hub, strayedSPI)
		spi, ok := told(muxes[0])
		if !ok || spi != strayedSPI {
			t.Fatalf("ESP on SPI %#x from the session's own address and port was handed on as %#x (%v)", strayedSPI, spi, ok)
		}
		if muxes[0].KnowsSPI(spi) {
			t.Errorf("SPI %#x is known before any mux took it", spi)
		}
		if err := muxes[0].RegisterESP(spi); err != nil {
			t.Fatal(err)
		}
		if !muxes[0].KnowsSPI(spi) {
			t.Errorf("SPI %#x is unknown once the mux took it", spi)
		}
	})(t)
}

// a mux that takes an SPI after the receive loop loaded the tables for its batch, and before the hub looks, keeps the SPI from being handed on
func TestSPITakenBeforeTheLookIsNotHandedOn(t *testing.T) {
	// made outside the bubble, since the spin below holds the bubble's clock still
	gaveUp := time.After(lookWait)
	bubble.Run(func(t *testing.T) {
		_, hub, peers, muxes := invalidSPIHub(t, "192.0.2.1")
		looked := hub.scanned.Load()
		hub.mu.Lock()
		datagram := binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, strayedSPI), 1)
		if _, err := peers[0].WriteToUDP(datagram, &net.UDPAddr{IP: net.ParseIP("192.0.2.9"), Port: int(hub.port)}); err != nil {
			t.Fatal(err)
		}
		// the receive loop sets scanned after it loaded its tables, and then waits for mu
		for hub.scanned.Load() == looked {
			select {
			case <-gaveUp:
				hub.mu.Unlock()
				t.Fatalf("the hub started no look within %v of real time for ESP on SPI %#x from the session's peer", lookWait, strayedSPI)
			default:
				runtime.Gosched()
			}
		}
		// what RegisterESP does, under the mu this test holds
		next := *hub.tables.Load()
		next.esp = maps.Clone(next.esp)
		next.esp[strayedSPI] = muxes[0]
		hub.tables.Store(&next)
		hub.mu.Unlock()
		synctest.Wait()
		if spi, ok := told(muxes[0]); ok {
			t.Errorf("SPI %#x, which the mux took before the hub looked, was handed on as %#x", strayedSPI, spi)
		}
	})(t)
}

// an SPI an ended session held draws nothing for an interval from the session that replaced it at the same destination, since the peer sends on it until it learns the session ended, and is handed on after that
func TestSPIOfAnEndedSessionDrawsNoReport(t *testing.T) {
	bubble.Run(func(t *testing.T) {
		_, hub, peers, muxes := invalidSPIHub(t, "192.0.2.1")
		at := peers[0].LocalAddr().(*net.UDPAddr)
		next, err := hub.NewMux(at.IP, at.Port)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { next.Close() })
		muxes[0].Close()
		sendESP(t, peers[0], hub, knownSPI)
		if spi, ok := told(next); ok {
			t.Errorf("ESP on SPI %#x, which the session that ended held, was handed to the one that replaced it as %#x", knownSPI, spi)
		}
		time.Sleep(invalidSPIInterval)
		sendESP(t, peers[0], hub, knownSPI)
		if spi, ok := told(next); !ok || spi != knownSPI {
			t.Errorf("ESP on SPI %#x an interval after the session that held it ended was handed on as %#x (%v)", knownSPI, spi, ok)
		}
	})(t)
}

// an SPI the mux let go of draws nothing for an interval, since its peer sends on it until it has read the Delete, and is handed on from the interval's end
func TestRetiredSPIDrawsNoReport(t *testing.T) {
	bubble.Run(func(t *testing.T) {
		for _, after := range []time.Duration{invalidSPIInterval - time.Nanosecond, invalidSPIInterval} {
			_, hub, peers, muxes := invalidSPIHub(t, "192.0.2.1")
			muxes[0].UnregisterESP(knownSPI)
			time.Sleep(after)
			sendESP(t, peers[0], hub, knownSPI)
			spi, ok := told(muxes[0])
			if after < invalidSPIInterval && ok {
				t.Errorf("ESP on SPI %#x %v after the mux let it go was handed on as %#x", knownSPI, after, spi)
			}
			if after == invalidSPIInterval && (!ok || spi != knownSPI) {
				t.Errorf("ESP on SPI %#x %v after the mux let it go was handed on as %#x (%v)", knownSPI, after, spi, ok)
			}
		}
	})(t)
}
