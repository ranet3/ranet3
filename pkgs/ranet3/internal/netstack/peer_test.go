// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/logtest"
	"ranet3.com/pkgs/ranet3/transport"
)

// endpointTo is the endpoint a mux dialing address sends to, which a path report names
func endpointTo(t *testing.T, address string) transport.Endpoint {
	t.Helper()
	to := netip.MustParseAddrPort(address)
	hub, err := transport.NewHub(0, transport.Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	mux, err := hub.NewMux(net.IP(to.Addr().AsSlice()), int(to.Port()))
	if err != nil {
		t.Fatal(err)
	}
	return mux.Endpoint()
}

// a bare path report refused only the packets past the path, so only the batches holding one fail and only those packets count as lost
// a control packet that went runs no failure, so babel undoes nothing that reached the wire
// the batches meet in one transmit, held behind an earlier one, so each is judged by its own packets
// a report wrapped with a later failure, or any other error, fails every batch of the transmit as before
func TestPathReportFailsOnlyWhatItRefused(t *testing.T) {
	report := &transport.PathMTUError{Endpoint: endpointTo(t, "198.51.100.1:4500"), MTU: 1280}
	// 1252 bytes fit the report's path under IPv4 and UDP headers, 1253 do not
	const fits, past = 1252, 1253
	for _, test := range []struct {
		name string
		err  error
		// failed is which of the two control packets fail, the one past the path and the one within it
		failed [2]bool
		lost   uint64
	}{
		{"bare report", report, [2]bool{true, false}, 1 + 2},
		{"report then another failure", fmt.Errorf("transport: send ESP batch: %w, then %w", report, errors.New("no route")), [2]bool{true, true}, 1 + 1 + 4},
		{"failure that reports no path", errors.New("no route"), [2]bool{true, true}, 1 + 1 + 4},
	} {
		t.Run(test.name, func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			var calls, carried atomic.Int32
			peer := NewPeer("peer", func(int) (BatchSealer, error) { return passThrough, nil }, func(sealed [][]byte) error {
				if calls.Add(1) == 1 {
					close(entered)
					<-release
					return nil
				}
				carried.Add(int32(len(sealed)))
				return test.err
			}, nil)
			t.Cleanup(peer.Close)
			if err := sendOrDrop(peer, []byte{1}, 41); err != nil {
				t.Fatal(err)
			}
			select {
			case <-entered:
			case <-time.After(deliveryTimeout):
				t.Fatalf("waited %s for the first transmit", deliveryTimeout)
			}
			var failures [2]chan error
			for i, size := range []int{past, fits} {
				failures[i] = make(chan error, 1)
				place, err := peer.ReserveRawOrDrop(make([]byte, size), 41)
				if err != nil {
					t.Fatal(err)
				}
				place.OnFailure(func(err error) { failures[i] <- err })
				if err := place.Send(); err != nil {
					t.Fatal(err)
				}
			}
			data := peer.reserveBatchNow(4, fits+past+past+64)
			for _, size := range []int{fits, past, past, 64} {
				data.append(make([]byte, size), 0)
			}
			if err := data.finish(); err != nil {
				t.Fatal(err)
			}
			close(release)
			waitForBudget(t, peer)
			if got := calls.Load(); got != 2 || carried.Load() != 6 {
				t.Fatalf("the sender made %d transmits carrying %d packets after the first, want one carrying the 6 queued behind it", got, carried.Load())
			}
			for i, want := range test.failed {
				select {
				case err := <-failures[i]:
					if !want {
						t.Errorf("control packet %d failed with %v, though it went", i, err)
					}
				default:
					if want {
						t.Errorf("control packet %d never failed, though it was lost", i)
					}
				}
			}
			if got := peer.SendFailed(); got != test.lost {
				t.Errorf("the peer counted %d packets lost in the transport, want %d", got, test.lost)
			}
		})
	}
}

// sentOnce sends one control packet of size through a peer whose transmit answers err, a probe where probe holds,
// and returns the peer's lost count and what the sender logged at info and above once it took the packet
func sentOnce(t *testing.T, size int, probe bool, err error) (uint64, string) {
	t.Helper()
	var logs bytes.Buffer
	logtest.SetDefault(t, slog.New(slog.NewTextHandler(&logs, nil)))
	carried := make(chan struct{})
	peer := NewPeer("peer", func(int) (BatchSealer, error) { return passThrough, nil }, func([][]byte) error {
		close(carried)
		return err
	}, nil)
	place, reserveErr := peer.ReserveRawOrDrop(make([]byte, size), 41)
	if reserveErr != nil {
		t.Fatal(reserveErr)
	}
	if probe {
		place.MarkProbe()
	}
	if err := place.Send(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-carried:
	case <-time.After(deliveryTimeout):
		t.Fatalf("waited %s for the transmit", deliveryTimeout)
	}
	// the sender is done with the packet once Close returns
	peer.Close()
	return peer.SendFailed(), logs.String()
}

// a probe the host refused past the path has its answer, so it counts in no lost packet and warns of nothing
// a probe whose send failed otherwise is lost as any packet is
func TestProbeRefusedPastThePathIsNoFailure(t *testing.T) {
	report := &transport.PathMTUError{Endpoint: endpointTo(t, "198.51.100.1:4500"), MTU: 1280}
	const past = 1253
	for _, test := range []struct {
		name  string
		err   error
		lost  uint64
		warns bool
	}{
		{"bare report", report, 0, false},
		{"report then another failure", fmt.Errorf("transport: send ESP batch: %w, then %w", report, errors.New("no route")), 1, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			lost, logs := sentOnce(t, past, true, test.err)
			if lost != test.lost {
				t.Errorf("the peer counted %d packets lost, want %d", lost, test.lost)
			}
			if warned := strings.Contains(logs, "netstack send batch failed"); warned != test.warns {
				t.Errorf("the sender warned %t, want %t:\n%s", warned, test.warns, logs)
			}
		})
	}
}

// a send at a closed mux and a bare path report are said at debug, and their lost packets still count
// any other error warns, naming the count of packets the transport was handed and lost, which counts it
func TestSendAtAClosedMuxOrPastThePathWarnsNothing(t *testing.T) {
	report := &transport.PathMTUError{Endpoint: endpointTo(t, "198.51.100.1:4500"), MTU: 1280}
	for _, test := range []struct {
		name  string
		err   error
		warns bool
	}{
		{"closed mux", transport.ErrClosed, false},
		{"closed mux under the send", fmt.Errorf("transport: send ESP batch: %w: %w", transport.ErrClosed, net.ErrClosed), false},
		{"bare report", report, false},
		{"another failure", errors.New("sendto: network is unreachable"), true},
	} {
		t.Run(test.name, func(t *testing.T) {
			lost, logs := sentOnce(t, 1253, false, test.err)
			if lost != 1 {
				t.Errorf("the peer counted %d packets lost, want 1", lost)
			}
			if warned := strings.Contains(logs, "netstack send batch failed"); warned != test.warns {
				t.Errorf("the sender warned %t, want %t:\n%s", warned, test.warns, logs)
			}
			if test.warns && (!strings.Contains(logs, "send_failed_total=1") || strings.Contains(logs, "dropped_total")) {
				t.Errorf("the warning names another count than the packets the transport lost:\n%s", logs)
			}
		})
	}
}

// a batch whose seal failed never reached the transport, and its warning names the peer's dropped count, which counts it
func TestSealThatFailedWarnsWithTheDroppedCount(t *testing.T) {
	var logs bytes.Buffer
	logtest.SetDefault(t, slog.New(slog.NewTextHandler(&logs, nil)))
	peer := NewPeer("peer", func(int) (BatchSealer, error) {
		return func([][]byte, []byte, [][]byte) ([][]byte, error) { return nil, errors.New("the SA is gone") }, nil
	}, func([][]byte) error { return nil }, nil)
	place, err := peer.ReserveRawOrDrop(make([]byte, 100), 41)
	if err != nil {
		t.Fatal(err)
	}
	_ = place.Send()
	// the sender gives the budget back as it takes the batch, and has warned once Close returns
	waitForBudget(t, peer)
	peer.Close()
	if peer.Dropped() != 1 || peer.SendFailed() != 0 {
		t.Fatalf("the peer counted %d dropped and %d lost by the transport, want the one dropped", peer.Dropped(), peer.SendFailed())
	}
	if text := logs.String(); !strings.Contains(text, "dropped_total=1") || strings.Contains(text, "send_failed_total") {
		t.Errorf("the warning names another count than the dropped packets:\n%s", text)
	}
}

// the sender marks the peer once it hands the transport a data packet, which tells a search of the path that data flows
// a control packet alone leaves the mark off, and TakeSent takes it away
func TestSenderMarksTheDataItHandsTheTransport(t *testing.T) {
	peer := NewPeer("peer", func(int) (BatchSealer, error) { return passThrough, nil }, func([][]byte) error { return nil }, nil)
	t.Cleanup(peer.Close)
	if err := sendOrDrop(peer, []byte("control"), 41); err != nil {
		t.Fatal(err)
	}
	waitForBudget(t, peer)
	if peer.TakeSent() {
		t.Error("a control packet marked the peer as carrying data")
	}
	data := peer.reserveBatchNow(1, len("data"))
	data.append([]byte("data"), 0)
	if err := data.finish(); err != nil {
		t.Fatal(err)
	}
	waitForBudget(t, peer)
	if !peer.TakeSent() {
		t.Error("a data packet the transport took left the peer unmarked")
	}
	if peer.TakeSent() {
		t.Error("the mark outlived the call that took it")
	}
}

// a reservation takes its place and its sequence range in one section of its peer's reserveMu
// so a second reservation on the peer, made while the first is parked in reserveFn, waits for the first
// and the wire carries the first's sequence numbers before the second's, as their places order them
func TestReservationsOverlappingOnOnePeerLeaveInReservationOrder(t *testing.T) {
	parked, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int64
	var next uint64
	carried := make(chan []uint64, 4)
	peer := NewPeer("peer", func(count int) (BatchSealer, error) {
		if calls.Add(1) == 1 {
			close(parked)
			<-release
		}
		first := next
		next += uint64(count)
		return func(raw [][]byte, _ []byte, out [][]byte) ([][]byte, error) {
			out = out[:0]
			for i := range raw {
				out = append(out, binary.BigEndian.AppendUint64(nil, first+uint64(i)))
			}
			return out, nil
		}, nil
	}, func(sealed [][]byte) error {
		var numbers []uint64
		for _, packet := range sealed {
			numbers = append(numbers, binary.BigEndian.Uint64(packet))
		}
		carried <- numbers
		return nil
	}, nil)
	t.Cleanup(peer.Close)

	var first, second *peerBatch
	firstReserved, secondReserved := make(chan struct{}), make(chan struct{})
	go func() { first = filled(peer, 2); close(firstReserved) }()
	<-parked
	// tried before the second reservation starts, so only the parked one can hold the section
	inSection := !peer.reserveMu.TryLock()
	if !inSection {
		peer.reserveMu.Unlock()
	}
	go func() { second = filled(peer, 2); close(secondReserved) }()
	if inSection {
		// the second has taken its budget and waits on the section the first holds
		waitUntil(t, "the second reservation to take its budget", func() bool { return peer.dataBudget.used.Load() == int64(2*dataCharge(2, 2)) })
	} else {
		// with no section held, the second takes its place and its sequence range before the first takes its range
		<-secondReserved
	}
	close(release)
	<-firstReserved
	<-secondReserved
	for _, b := range []*peerBatch{first, second} {
		if err := b.finish(); err != nil {
			t.Fatalf("an open peer refused the batch: %v", err)
		}
	}

	var wire []uint64
	for len(wire) < 4 {
		select {
		case numbers := <-carried:
			wire = append(wire, numbers...)
		case <-time.After(deliveryTimeout):
			t.Fatalf("the wire carried %v of the 4 packets reserved", wire)
		}
	}
	if !slices.Equal(wire, []uint64{0, 1, 2, 3}) {
		t.Errorf("the wire carried sequence numbers %v in reservation order, want them rising from 0", wire)
	}
}
