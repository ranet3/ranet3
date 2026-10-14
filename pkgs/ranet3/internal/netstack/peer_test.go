// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/transport"
)

// endpointTo is the endpoint a mux dialing address sends to, which a path report names
func endpointTo(t *testing.T, address string) transport.Endpoint {
	t.Helper()
	to := netip.MustParseAddrPort(address)
	mux, err := transport.Dial(":0", net.IP(to.Addr().AsSlice()), int(to.Port()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mux.Close() })
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
			peer := NewPeerReserved("peer", func(int) (BatchSealer, error) { return passThrough, nil }, func(sealed [][]byte) error {
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
			if err := data.enqueue(); err != nil {
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

// the sender marks the peer once it hands the transport a data packet, which tells a search of the path that data flows
// a control packet alone leaves the mark off, and TakeSent takes it away
func TestSenderMarksTheDataItHandsTheTransport(t *testing.T) {
	peer := NewPeerReserved("peer", func(int) (BatchSealer, error) { return passThrough, nil }, func([][]byte) error { return nil }, nil)
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
	if err := data.enqueue(); err != nil {
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
