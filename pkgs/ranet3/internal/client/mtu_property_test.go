// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package client

import (
	"math"
	"net/netip"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
)

// a node whose file the loader takes starts its device at link.mtu less the header its longest steering list puts on a packet
// and at link.mtu itself where it steers nothing
// every list length meets its least link.mtu and the most before anything is drawn
func TestDeviceStartsAtLinkMTULessTheLongestSteeringList(t *testing.T) {
	check := func(tb testing.TB, mtu uint16, segments int) {
		tb.Helper()
		cfg := &config.Config{
			Node: config.Node{Org: "example", Name: "node"},
			Auth: config.Auth{Key: "key.pem", Trust: "trust.json"},
			Link: config.Link{Port: 13000, Endpoints: []config.Endpoint{{Serial: "0", Family: "ip4"}}, MTU: mtu},
			Dial: config.Dial{All: true},
		}
		// an outer IPv6 header, the fixed part of the segment routing header and 16 bytes a segment, RFC 8754
		header := 0
		if segments > 0 {
			via := make([]schema.Addr, segments)
			for i := range via {
				via[i] = schema.AddrFrom(netip.AddrFrom16([16]byte{0x3f, 0xff, 0, 1, 15: byte(i + 1)}))
			}
			cfg.Cap.Segment = &srv6.Segments{
				Source: schema.MustAddr("3fff:1:69c:8c0::1"),
				Steer:  []srv6.Steer{{From: schema.MustPrefix("3fff:a::1/128"), Via: via}},
			}
			header = 40 + 8 + 16*segments
		}
		inForce := int(mtu)
		if mtu == 0 {
			inForce = netstack.DefaultMTU
		}
		if err := cfg.Validate(); err != nil {
			if inForce-header >= 1280 && inForce <= 65470 {
				tb.Fatalf("link.mtu %d with a list of %d segments was refused: %v", mtu, segments, err)
			}
			return
		}
		_, steering, err := cfg.Segments().Tables()
		if err != nil {
			tb.Fatalf("a file the loader took built no tables: %v", err)
		}
		device, err := steeredMTU(cfg.Link.SessionMTU(), steering)
		if err != nil {
			tb.Fatalf("link.mtu %d with a list of %d segments loaded and the device would not start: %v", mtu, segments, err)
		}
		if want := inForce - header; device != want {
			tb.Fatalf("link.mtu %d with a list of %d segments starts a %d byte device, want %d", mtu, segments, device, want)
		}
	}
	for segments := range srv6.MaxSegments + 1 {
		least := srv6.MinimumIPv6MTU
		if segments > 0 {
			least += srv6.Overhead(segments)
		}
		for _, mtu := range []int{0, least, 65470} {
			check(t, uint16(mtu), segments)
		}
	}
	pbt.Check(t, func(ht *hegel.T) {
		segments := hegel.Draw(ht, pbt.Spanning(0, srv6.MaxSegments))
		check(ht, hegel.Draw(ht, pbt.Spanning[uint16](0, math.MaxUint16)), segments)
	})
}
