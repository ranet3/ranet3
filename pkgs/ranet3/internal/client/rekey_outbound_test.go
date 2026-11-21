// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/ike"
)

// heldReplacementWatch is how long the test of a served session's hold reads what the answering end sends once the asking end's rekey returns, five hellos of the loopback nodes
const heldReplacementWatch = time.Second

// holdRelay carries every datagram between alpha and bravo, alpha sending to it in place of bravo's port
// once armed and once bravo has answered a CREATE_CHILD_SA, it drops what alpha sends on any Child SA but the armed one and every INFORMATIONAL request of alpha's until release, so bravo hears nothing that ends the hold of its new Child SA, and it reports the SPI of each ESP packet bravo sends
type holdRelay struct {
	alphaSide, bravoSide *net.UDPConn
	bravo                *net.UDPAddr
	// sent gets the SPI of each ESP packet bravo sends once it has answered
	sent chan uint32

	mu                 sync.Mutex
	alpha              *net.UDPAddr
	armed              uint32
	answered, released bool
}

// newHoldRelay starts the relay and points alpha at it, so it must run before either node does
func newHoldRelay(t *testing.T, alpha, bravo *loopbackNode) *holdRelay {
	t.Helper()
	loopback := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
	alphaSide, err := net.ListenUDP("udp4", loopback)
	if err != nil {
		t.Fatal(err)
	}
	bravoSide, err := net.ListenUDP("udp4", loopback)
	if err != nil {
		t.Fatal(err)
	}
	r := &holdRelay{alphaSide: alphaSide, bravoSide: bravoSide, bravo: &net.UDPAddr{IP: loopback.IP, Port: int(bravo.port)}, sent: make(chan uint32, 1024)}
	pointAlphaAt(t, alpha, bravo, alphaSide.LocalAddr().(*net.UDPAddr).Port)
	var relaying sync.WaitGroup
	relaying.Go(r.fromAlpha)
	relaying.Go(r.fromBravo)
	t.Cleanup(func() {
		_ = alphaSide.Close()
		_ = bravoSide.Close()
		relaying.Wait()
	})
	return r
}

// arm has the relay drop, once bravo answers a CREATE_CHILD_SA, what alpha sends on any Child SA but the one bravo receives on as spi
func (r *holdRelay) arm(spi uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.armed = spi
}

// release stops the drops, so alpha's resends of what was dropped reach bravo
func (r *holdRelay) release() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.released = true
}

// ikeExchange is whether datagram is an IKE message of exchange, a response or a request as response says
func ikeExchange(datagram []byte, exchange ike.ExchangeType, response bool) bool {
	// the four zero octets of RFC 3948 section 2.2 come before an IKE header
	if len(datagram) < 4+ike.HeaderLen || binary.BigEndian.Uint32(datagram) != 0 {
		return false
	}
	header := datagram[4:]
	return ike.ExchangeType(header[18]) == exchange && (header[19]&ike.FlagResponse != 0) == response
}

// espSPI is the SPI of datagram as an ESP packet, and 0 for an IKE message or a keepalive
func espSPI(datagram []byte) uint32 {
	if len(datagram) < 8 {
		return 0
	}
	return binary.BigEndian.Uint32(datagram)
}

func (r *holdRelay) fromAlpha() {
	buf := make([]byte, 65536)
	for {
		n, from, err := r.alphaSide.ReadFromUDP(buf)
		if err != nil {
			return
		}
		spi := espSPI(buf[:n])
		r.mu.Lock()
		r.alpha = from
		drop := r.answered && !r.released && (spi != 0 && spi != r.armed || ikeExchange(buf[:n], ike.INFORMATIONAL, false))
		r.mu.Unlock()
		if !drop {
			_, _ = r.bravoSide.WriteToUDP(buf[:n], r.bravo)
		}
	}
}

func (r *holdRelay) fromBravo() {
	buf := make([]byte, 65536)
	for {
		n, _, err := r.bravoSide.ReadFromUDP(buf)
		if err != nil {
			return
		}
		r.mu.Lock()
		if r.armed != 0 && ikeExchange(buf[:n], ike.CREATE_CHILD_SA, true) {
			r.answered = true
		}
		answered, alpha := r.answered, r.alpha
		r.mu.Unlock()
		if spi := espSPI(buf[:n]); answered && spi != 0 {
			select {
			case r.sent <- spi:
			default:
			}
		}
		if alpha != nil {
			_, _ = r.alphaSide.WriteToUDP(buf[:n], alpha)
		}
	}
}

// the answering end of a Child SA rekey, in a session serveSession runs, holds the new Child SA and sends on the one it replaces until the asking end is heard on the new one, which fails where serveSession builds a tunnel the session does not hand its new Child SAs to hold
// the relay keeps from bravo what alpha sends on the new Child SA and alpha's INFORMATIONAL requests, the Delete of the replaced Child SA among them
func TestServedSessionHoldsTheChildSAOfAPeersRekey(t *testing.T) {
	alpha, bravo := newLoopbackMesh(t)
	// bravo answers and never dials, so both ends hold the one session alpha dials
	quiet := *bravo.cfg
	quiet.Dial.To = nil
	bravo.client.cfg.Store(&quiet)
	relay := newHoldRelay(t, alpha, bravo)
	run(t, alpha, bravo)
	waitFor(t, convergeBudget, "each node forwarding to the other's prefix", func() bool {
		return reaches(alpha, bravo) && reaches(bravo, alpha)
	})
	held := alpha.client.sessions.snapshot()
	if len(held) != 1 {
		t.Fatalf("alpha holds %d sessions, want the one it dialed", len(held))
	}
	replaced := held[0].session.Child()
	relay.arm(replaced.RemoteSPI)
	// the rekey returns once its Delete of the replaced Child SA is answered, which the relay keeps from bravo until release
	rekeyed := make(chan error, 1)
	go func() { rekeyed <- held[0].session.RekeyChild() }()
	var child ike.ChildSA
	waitFor(t, convergeBudget, "alpha making the new Child SA current", func() bool {
		child = held[0].session.Child()
		return child.LocalSPI != replaced.LocalSPI
	})
	onReplaced := 0
	watch := time.After(heldReplacementWatch)
	for watching := true; watching; {
		select {
		case spi := <-relay.sent:
			if spi == child.LocalSPI {
				t.Fatalf("bravo sent on the new Child SA of SPI %08x before alpha was heard on it", spi)
			}
			if spi == replaced.LocalSPI {
				onReplaced++
			}
		case <-watch:
			watching = false
		}
	}
	if onReplaced == 0 {
		t.Fatalf("bravo sent nothing on the replaced Child SA of SPI %08x in %v", replaced.LocalSPI, heldReplacementWatch)
	}
	relay.release()
	select {
	case err := <-rekeyed:
		if err != nil {
			t.Fatalf("alpha could not rekey its session: %v", err)
		}
	case <-time.After(convergeBudget):
		t.Fatal("alpha's rekey did not end once its Delete of the replaced Child SA could reach bravo")
	}
}
