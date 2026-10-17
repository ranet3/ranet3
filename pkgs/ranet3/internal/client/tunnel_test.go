// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

package client

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/esp"
	"ranet3.com/pkgs/ranet3/transport"
)

func tunnelChild(id uint32) esp.ChildSA {
	in, out := make([]byte, 20), make([]byte, 20)
	binary.BigEndian.PutUint32(in, id)
	binary.BigEndian.PutUint32(out, id+100)
	return esp.ChildSA{EncrID: esp.ENCRAESGCM16, EncrKeyBits: 128, LocalSPI: 1000 + id, RemoteSPI: 2000 + id, InboundKey: in, OutboundKey: out}
}

func remoteSA(t *testing.T, child esp.ChildSA) *esp.OutboundSA {
	t.Helper()
	child.RemoteSPI, child.OutboundKey = child.LocalSPI, child.InboundKey
	sa, err := esp.NewOutbound(child)
	if err != nil {
		t.Fatal(err)
	}
	return sa
}

func sealTestPacket(t *testing.T, sa *esp.OutboundSA, id uint32) []byte {
	t.Helper()
	plain := make([]byte, 24)
	plain[0], plain[3] = 0x45, 24
	binary.BigEndian.PutUint32(plain[20:24], id)
	raw, err := sa.Seal(plain, esp.NextHeaderIPv4)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestTunnelRekeyPreservesInflightKeys(t *testing.T) {
	tunnel := &tunnel{replayWindow: 4096}
	old, next := tunnelChild(1), tunnelChild(2)
	if err := tunnel.install(old); err != nil {
		t.Fatal(err)
	}
	reserved, err := tunnel.reserve(1)
	if err != nil {
		t.Fatal(err)
	}
	remote := remoteSA(t, old)
	authenticated := tunnel.decryptBatch([][]byte{sealTestPacket(t, remote, 1)}, nil)[0]
	if err := tunnel.install(next); err != nil {
		t.Fatal(err)
	}
	if err := tunnel.install(next); err == nil {
		t.Fatal("duplicate SPI installation overwrote its replay state")
	}
	// A range reserved before replacement stays bound to the old outbound SA.
	packets, err := reserved([][]byte{{1}}, []byte{esp.NextHeaderIPv4}, nil)
	if err != nil || binary.BigEndian.Uint32(packets[0][:4]) != old.RemoteSPI {
		t.Fatalf("reserved range lost its original SA: %v", err)
	}
	if err := tunnel.retire(old.LocalSPI); err != nil {
		t.Fatal(err)
	}
	if _, _, err := authenticated.Commit(); err != nil {
		t.Fatalf("in-flight authenticated packet lost retired keys: %v", err)
	}
	for _, raw := range [][]byte{nil, {0, 1}, sealTestPacket(t, remote, 2)} {
		result := tunnel.decryptBatch([][]byte{raw}, nil)[0]
		if _, _, err := result.Commit(); err == nil {
			t.Fatal("accepted truncated data or a retired SPI")
		}
	}
	result := tunnel.decryptBatch([][]byte{sealTestPacket(t, remoteSA(t, next), 3)}, nil)[0]
	if _, _, err := result.Commit(); err != nil {
		t.Fatalf("retiring old SA disturbed the replacement: %v", err)
	}
	if err := tunnel.retire(next.LocalSPI); err != nil {
		t.Fatal(err)
	}
	if _, err := tunnel.reserve(1); err == nil {
		t.Fatal("reserved a sequence after the active Child SA was deleted")
	}
}

func TestReceiveESPOrderAndShutdown(t *testing.T) {
	for _, workers := range []int{1, 4} {
		t.Run(fmt.Sprintf("workers=%d", workers), func(t *testing.T) {
			remote, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer remote.Close()
			addr := remote.LocalAddr().(*net.UDPAddr)
			mux, err := transport.Dial(":0", addr.IP, addr.Port)
			if err != nil {
				t.Fatal(err)
			}
			defer mux.Close()
			child := tunnelChild(1)
			if err := mux.RegisterESP(child.LocalSPI); err != nil {
				t.Fatal(err)
			}
			tunnel := &tunnel{replayWindow: 4096}
			if err := tunnel.install(child); err != nil {
				t.Fatal(err)
			}
			firstStarted, releaseFirst, secondFinished := make(chan struct{}), make(chan struct{}), make(chan struct{})
			defer func() {
				select {
				case <-releaseFirst:
				default:
					close(releaseFirst)
				}
			}()
			decrypt := func(raw [][]byte, results []inboundDecrypted) []inboundDecrypted {
				if binary.BigEndian.Uint32(raw[0][4:8]) == 1 {
					close(firstStarted)
					<-releaseFirst
				} else {
					defer close(secondFinished)
				}
				return tunnel.decryptBatch(raw, results)
			}
			delivered := make(chan uint32, 2)
			done := make(chan error, 1)
			// Joined whatever the test does. The receiver reports through t,
			// and a t.Fatal below would otherwise finish the test with it
			// still running: its next log line panics the whole package binary
			// instead of printing the failure that caused it.
			finished := make(chan struct{})
			t.Cleanup(func() { _ = mux.Close(); <-finished })
			go func() {
				defer close(finished)
				done <- receiveESP(mux, workers, decrypt, func(results []inboundDecrypted) {
					esp.CommitBatch(results)
					for _, result := range results {
						plain, _, err := result.Plaintext()
						if err != nil {
							t.Error(err)
							continue
						}
						delivered <- binary.BigEndian.Uint32(plain[20:24])
					}
				})
			}()
			peer := remoteSA(t, child)
			destination := &net.UDPAddr{IP: addr.IP, Port: mux.LocalAddr().(*net.UDPAddr).Port}
			if _, err := remote.WriteToUDP(sealTestPacket(t, peer, 1), destination); err != nil {
				t.Fatal(err)
			}
			select {
			case <-firstStarted:
			case <-time.After(time.Second):
				t.Fatal("first batch did not start")
			}
			if _, err := remote.WriteToUDP(sealTestPacket(t, peer, 2), destination); err != nil {
				t.Fatal(err)
			}
			if workers > 1 {
				select {
				case <-secondFinished:
				case <-time.After(time.Second):
					t.Fatal("crypto did not run concurrently")
				}
				if len(delivered) != 0 {
					t.Fatal("later crypto completion overtook the first batch")
				}
			}
			close(releaseFirst)
			for _, want := range []uint32{1, 2} {
				select {
				case got := <-delivered:
					if got != want {
						t.Fatalf("received %d, want %d", got, want)
					}
				case <-time.After(time.Second):
					t.Fatal("packet delivery stalled")
				}
			}
			_ = mux.Close()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("receiver did not join its workers on shutdown")
			}
		})
	}
}

// RFC 7296 section 1.4.1 lets a peer delete the Child SA and keep the IKE SA.
// Sending has to stop and ask for a replacement, not report the kind of error
// that closes the session: the next babel hello would otherwise tear down the
// adjacency and withdraw every route through the peer.
func TestDeletedChildSAAsksForReplacementInsteadOfFailingHard(t *testing.T) {
	child := tunnelChild(1)
	tunnel := &tunnel{}
	asked := make(chan struct{}, 4)
	tunnel.rekey = func() { asked <- struct{}{} }
	if err := tunnel.install(child); err != nil {
		t.Fatal(err)
	}
	if err := tunnel.retire(child.LocalSPI); err != nil {
		t.Fatal(err)
	}

	_, err := tunnel.reserve(1)
	if !errors.Is(err, errNoChildSA) {
		t.Fatalf("reserve after the peer's delete = %v, want errNoChildSA", err)
	}
	select {
	case <-asked:
	case <-time.After(5 * time.Second):
		t.Fatal("no replacement Child SA was requested")
	}
}

// Every packet routed to a peer with no outbound SA reaches reserve, so the
// request has to collapse into one attempt at a time.
func TestReplacementChildSARequestsDoNotPileUp(t *testing.T) {
	tunnel := &tunnel{}
	entered := make(chan struct{}, 128)
	release := make(chan struct{})
	var running, peak atomic.Int32
	tunnel.rekey = func() {
		n := running.Add(1)
		for {
			if seen := peak.Load(); seen >= n || peak.CompareAndSwap(seen, n) {
				break
			}
		}
		entered <- struct{}{}
		<-release
		running.Add(-1)
	}
	for range 100 {
		if _, err := tunnel.reserve(1); !errors.Is(err, errNoChildSA) {
			t.Fatalf("reserve = %v, want errNoChildSA", err)
		}
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("no replacement Child SA was requested")
	}
	close(release)
	if got := peak.Load(); got != 1 {
		t.Fatalf("%d concurrent rekey attempts, want exactly 1", got)
	}
}

// A spent sequence space ends the SA, not the session. RFC 4303 section 3.3.3
// forbids reusing a sequence number, so refusing to send is right. RFC 7296
// section 1.3.1 says what to do about it ("A failed attempt to create a
// Child SA SHOULD NOT tear down the IKE SA"), and the margin
// ProactiveRekeySequence leaves exists precisely for the case where a rekey
// has already failed once. Closing the mux there loses the session at the one
// moment a replacement matters most.
func TestSpentSequenceSpaceAsksForAReplacementAndKeepsTheSession(t *testing.T) {
	child := tunnelChild(1)
	tunnel := &tunnel{}
	asked := make(chan struct{}, 4)
	tunnel.rekey = func() { asked <- struct{}{} }
	if err := tunnel.install(child); err != nil {
		t.Fatal(err)
	}
	// Spent through the same path production uses. Four reservations of 2^30
	// carry the 32-bit space past its end, and 1<<30 still fits an int on a
	// 32-bit build.
	var err error
	for range 4 {
		_, err = tunnel.reserve(1 << 30)
	}
	if !errors.Is(err, esp.ErrSequenceExhausted) {
		t.Fatalf("reserve on a spent SA = %v, want ErrSequenceExhausted", err)
	}
	select {
	case <-asked:
	case <-time.After(5 * time.Second):
		t.Fatal("a spent sequence space asked for no replacement Child SA")
	}
	if fatalReserveError(err) {
		t.Error("a spent sequence space closes the mux, which withdraws every route through the peer")
	}
	// The refusals that are a real transport failure still do.
	if !fatalReserveError(errors.New("the socket is gone")) {
		t.Error("a genuine transport failure no longer closes the mux")
	}
	if fatalReserveError(errNoChildSA) || fatalReserveError(nil) {
		t.Error("a refusal a replacement fixes closes the mux")
	}
}

// markDelay is the delay the jitter test draws for the first ask past the sequence mark, markWatch how long past it the test waits for that ask, and markBatches how often it sends a batch meanwhile
const markDelay, markWatch, markBatches = 200 * time.Millisecond, 5 * time.Second, 10 * time.Millisecond

// RFC 7296 section 2.8.1: "To reduce the probability of this happening, the timing of rekeying requests SHOULD be jittered (delayed by a random amount of time after the need for rekeying is noticed)."
// the batches past the mark ask for no rekey until the delay drawn at the first of them has passed, and then ask as before, and a delay drawn at random stays below its bound
func TestFirstAskPastTheSequenceMarkWaitsItsJitter(t *testing.T) {
	tunnel := &tunnel{started: time.Now()}
	tunnel.askedAt.Store(-int64(rekeyAskInterval))
	var bounds []time.Duration
	tunnel.askJitter = func(bound time.Duration) time.Duration {
		bounds = append(bounds, bound)
		return markDelay
	}
	asked := make(chan time.Time, 8)
	tunnel.rekey = func() { asked <- time.Now() }
	if err := tunnel.install(tunnelChild(1)); err != nil {
		t.Fatal(err)
	}
	// three reservations of 2^30 and the rest up to the mark, each of which fits an int on a 32-bit build
	for range 3 {
		if _, err := tunnel.reserve(1 << 30); err != nil {
			t.Fatal(err)
		}
	}
	marked := time.Now()
	if _, err := tunnel.reserve(int(esp.ProactiveRekeySequence - 3<<30)); err != nil {
		t.Fatal(err)
	}
	var first time.Time
	for deadline := time.Now().Add(markDelay + markWatch); first.IsZero(); time.Sleep(markBatches) {
		if time.Now().After(deadline) {
			t.Fatal("the batches past the sequence mark never asked for a rekey")
		}
		if _, err := tunnel.reserve(1); err != nil {
			t.Fatal(err)
		}
		select {
		case first = <-asked:
		default:
		}
	}
	if early := marked.Add(markDelay); first.Before(early) {
		t.Errorf("the first ask past the sequence mark came %s after it, want no sooner than the %s drawn", first.Sub(marked), markDelay)
	}
	if !slices.Equal(bounds, []time.Duration{proactiveRekeyJitter}) {
		t.Errorf("the delay was drawn with the bounds %v, want once with %s", bounds, proactiveRekeyJitter)
	}
	tunnel.askJitter = nil
	for range 1000 {
		if delay := tunnel.askDelay(proactiveRekeyJitter); delay < 0 || delay >= proactiveRekeyJitter {
			t.Fatalf("a delay drawn at random is %s, want it in [0, %s)", delay, proactiveRekeyJitter)
		}
	}
}

// highestSAPacketRate is above the packet rate esp measured one SA carrying at small packets, in packets a second
// meshRoundTrip is a round trip between two nodes on opposite sides of the earth
const (
	highestSAPacketRate = 20_000_000
	meshRoundTrip       = 300 * time.Millisecond
)

// the first ask's delay leaves the rest of the sequence margin to the exchange and its retries, and still parts two ends that reached the mark in the same round trip
func TestProactiveRekeyJitterStaysFarInsideTheSequenceMargin(t *testing.T) {
	lasts := time.Duration(0xffffffff-esp.ProactiveRekeySequence) * time.Second / highestSAPacketRate
	if 10*proactiveRekeyJitter > lasts {
		t.Errorf("the first ask waits up to %s, more than a tenth of the %s the sequence margin lasts at %d packets a second", proactiveRekeyJitter, lasts, highestSAPacketRate)
	}
	if proactiveRekeyJitter < 3*meshRoundTrip {
		t.Errorf("the first ask waits up to %s, under three round trips of %s", proactiveRekeyJitter, meshRoundTrip)
	}
}

// A reload that drops a peer cancels that dialer's context while the node
// keeps running, and the session it opened has to be told: the peer otherwise
// carries on sending ESP into an SPI nobody answers until its own liveness
// check expires, which is up to seventy seconds. Shutdown is not this case,
// because closeAll has already swept by the time the node's context is
// canceled, and that sweep exists so that no peer is told twice.
func TestOnlyADroppedDialerTellsItsPeer(t *testing.T) {
	live := t.Context()
	dropped, cancelDropped := context.WithCancel(context.Background())
	cancelDropped()
	node, stopNode := context.WithCancel(context.Background())
	stopNode()

	for name, test := range map[string]struct {
		dial, node context.Context
		want       bool
	}{
		"a reload dropped the dialer": {dropped, live, true},
		"the session is still open":   {live, live, false},
		"the node is shutting down":   {dropped, node, false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := dialerWasDropped(test.dial, test.node); got != test.want {
				t.Errorf("dialerWasDropped = %v, want %v", got, test.want)
			}
		})
	}
}
