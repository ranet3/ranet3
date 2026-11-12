// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package babel

import (
	"encoding/binary"
	"math"
	"net/netip"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// RFC 8966 section 4.5 has a TLV update the parser state "even if the TLV is otherwise ignored", and section 4.6.9's R flag takes the router-id from "the 8 last octets of the address"
// an AE 3 Update, an address in fe80::/64 whose Prefix field carries the octets of its prefix past those 64 bits, sets the router-id the next Update of its packet takes, and is never learned itself
// the model is the drawn interface identifier with its bits past the prefix length cleared, and one of all zeroes or all ones names no router, so the next Update teaches nothing
// one with a prefix length past 128 or a Prefix field cut short does not decode, so it sets no router-id and the next Update teaches nothing either
func TestLinkLocalUpdateSetsTheRouterIDAndTeachesNothing(t *testing.T) {
	dest := netip.MustParsePrefix("2001:db8:6::/48")
	pbt.Check(t, func(ht *hegel.T) {
		var plen int
		switch hegel.Draw(ht, hegel.Integers(0, 2)) {
		case 0:
			plen = hegel.Draw(ht, hegel.SampledFrom([]int{0, 64, 65, 127, 128, 129, 255}))
		case 1:
			plen = hegel.Draw(ht, hegel.Integers(0, 128))
		default:
			plen = hegel.Draw(ht, pbt.Spanning(129, 255))
		}
		field := max(0, prefixByteLen(plen)-8)
		short := 0
		if plen <= 128 && field > 0 && hegel.Draw(ht, hegel.Booleans()) {
			short = hegel.Draw(ht, hegel.Integers(1, field))
		}
		iid := hegel.Draw(ht, pbt.Spanning[uint64](0, math.MaxUint64))
		kept := max(0, plen-64)
		model := iid
		if kept < 64 {
			model &^= math.MaxUint64 >> kept
		}
		var want [8]byte
		binary.BigEndian.PutUint64(want[:], model)
		decodes := plen <= 128 && short == 0

		sent := make([]byte, max(8, field))
		binary.BigEndian.PutUint64(sent, iid)
		body := []byte{AEIPv6LinkLocal, updateFlagRouterID, byte(plen), 0, 0x17, 0x70, 0, 1, 0, 60}
		body = append(body, sent[:field-short]...)
		speaker, neighbor, _ := captureSpeaker(t, Config{})
		makeNeighborReachable(neighbor)
		speaker.handlePacket(neighbor, EncodePacket([]RawTLV{
			{Type: TLVUpdate, Body: body},
			EncodeUpdate(Update{AE: AEIPv6, Plen: dest.Bits(), Prefix: dest.Addr().AsSlice(), Interval: 6000, Seqno: 1, Metric: 60}),
		}))

		speaker.mu.Lock()
		defer speaker.mu.Unlock()
		for key := range speaker.routes.entries {
			if key.dest != dest {
				ht.Fatalf("an AE 3 Update of length %d taught %s", plen, key.dest)
			}
		}
		route := speaker.routes.route(neighbor, routeKey{dest: dest})
		switch {
		case !decodes && route != nil:
			ht.Fatalf("after an AE 3 Update of length %d with %d octets of its Prefix field cut, %s was learned under %x", plen, short, dest, route.routerID)
		case !decodes:
		case !ValidRouterID(want) && route != nil:
			ht.Fatalf("after an AE 3 Update naming router-id %x at length %d, %s was learned under %x", want, plen, dest, route.routerID)
		case ValidRouterID(want) && route == nil:
			ht.Fatalf("after an AE 3 Update naming router-id %x at length %d, %s was not learned", want, plen, dest)
		case route != nil && route.routerID != want:
			ht.Fatalf("after an AE 3 Update of length %d, %s was learned under %x, want %x", plen, dest, route.routerID, want)
		}
	})
}
