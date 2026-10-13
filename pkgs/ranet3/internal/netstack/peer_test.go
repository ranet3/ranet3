// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"errors"
	"fmt"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/esp"
	"ranet3.com/pkgs/ranet3/transport"
)

// a transmit the transport answers with a path report lowers the session's budget to what the reported path carries, before the next transmit
// a report of a wider path leaves the budget where it is, and so does an error that is no report
// the report comes wrapped, as a mux answers one a later failure followed, so the batch fails and its failure says the sender read the answer
func TestPathReportNarrowsThePeerAndNeverWidensIt(t *testing.T) {
	ipv4 := netip.MustParseAddrPort("198.51.100.1:4500")
	ipv6 := netip.MustParseAddrPort("[2001:db8::1]:4500")
	for _, test := range []struct {
		name   string
		budget int
		err    error
		want   int
	}{
		{"IPv4 path", DefaultMTU, &transport.PathMTUError{Endpoint: ipv4, MTU: 1280}, esp.Inner(1280, 20)},
		{"IPv6 path", DefaultMTU, &transport.PathMTUError{Endpoint: ipv6, MTU: 1280}, esp.Inner(1280, 40)},
		{"path then a later failure", DefaultMTU,
			fmt.Errorf("%w, then %w", &transport.PathMTUError{Endpoint: ipv4, MTU: 1280}, errors.New("no route")), esp.Inner(1280, 20)},
		{"path wider than the budget", DefaultMTU, &transport.PathMTUError{Endpoint: ipv4, MTU: 9000}, DefaultMTU},
		{"path wider than a budget already lowered", 1000, &transport.PathMTUError{Endpoint: ipv6, MTU: 1280}, 1000},
		{"failure that reports no path", DefaultMTU, errors.New("no route"), DefaultMTU},
	} {
		t.Run(test.name, func(t *testing.T) {
			peer := NewPeerReserved("peer", func(int) (BatchSealer, error) { return passThrough, nil }, func([][]byte) error {
				return fmt.Errorf("transport: send ESP batch: %w", test.err)
			}, nil)
			t.Cleanup(peer.Close)
			peer.SetMTU(test.budget)
			place, err := peer.ReserveRawOrDrop([]byte("packet"), 41)
			if err != nil {
				t.Fatal(err)
			}
			// the sender runs a batch's failure after it read the transmit's answer
			failed := make(chan error, 1)
			place.OnFailure(func(err error) { failed <- err })
			if err := place.Send(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-failed:
			case <-time.After(deliveryTimeout):
				t.Fatalf("waited %s for the transmit to fail", deliveryTimeout)
			}
			if got := peer.MTU(); got != test.want {
				t.Errorf("the session carries %d byte packets after the transmit answered %v, want %d", got, test.err, test.want)
			}
		})
	}
}

// a bare path report refused only the packets past the path, so only the batches holding one fail and only those packets count as lost
// a control packet that went runs no failure, so babel undoes nothing that reached the wire
// the batches meet in one transmit, held behind an earlier one, so each is judged by its own packets
// a report wrapped with a later failure, or any other error, fails every batch of the transmit as before
func TestPathReportFailsOnlyWhatItRefused(t *testing.T) {
	report := &transport.PathMTUError{Endpoint: netip.MustParseAddrPort("198.51.100.1:4500"), MTU: 1280}
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
			data := peer.reserveBatchNow(4)
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
