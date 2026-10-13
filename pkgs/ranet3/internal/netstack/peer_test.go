// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/esp"
	"ranet3.com/pkgs/ranet3/transport"
)

// a transmit the transport answers with a path report lowers the session's budget to what the reported path carries, before the next transmit
// a report of a wider path leaves the budget where it is, and so does an error that is no report
// the report comes wrapped as a mux hands it on, and after it the failure of a later send where one followed
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
