// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package config

import (
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/internal/babel"
	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
)

// egressSIDs are the SIDs the property below gives its egress segments, in order
var egressSIDs = []string{"2a0c:b641:69c:5d26::3", "2a0c:b641:69c:5d26::4", "2a0c:b641:69c:5d26::5"}

// egressExit is an exit with no cap.table and an egress segment at each of the first count egressSIDs
func egressExit(count int) Config {
	var segments []srv6.Segment
	for _, sid := range egressSIDs[:count] {
		segments = append(segments, srv6.Segment{
			SID:      schema.MustAddr(sid),
			Behavior: srv6.BehaviorEndDT46,
			Deliver:  srv6.DeliverEgress,
			Allow:    []schema.Prefix{schema.MustPrefix("3fff:a::/32")},
		})
	}
	return Config{
		Node: identity.MustParse("example/exit"),
		Auth: Auth{Key: "key.pem", Trust: "trust.json"},
		Link: Link{Port: 13000, Endpoints: []Endpoint{{Serial: "0", Family: "ip6"}}},
		Dial: Dial{All: true},
		Cap: Caps{
			Egress:  &egress.Egress{},
			Border:  &egress.Border{Overlay: []schema.Prefix{schema.MustPrefix("3fff::/20")}},
			Segment: &srv6.Segments{Local: segments},
		},
	}
}

// A node with up to three egress segments loads exactly when cap.route
// announces none of their /128s, whatever else it announces, a covering
// prefix included
func TestEgressSIDsRoutesAreLeftToReadiness(t *testing.T) {
	pool := []string{"2a0c:b641:69c:5d20::/60", "2001:db8::/32", "2a0c:b641:69c:5d26::6/128"}
	pbt.Check(t, func(ht *hegel.T) {
		count := hegel.Draw(ht, pbt.Spanning(1, len(egressSIDs)))
		c := egressExit(count)
		var announce []schema.Announce
		sid := false
		for i, address := range egressSIDs {
			if hegel.Draw(ht, hegel.Booleans()) {
				announce = append(announce, schema.Announce{Prefix: schema.MustPrefix(address + "/128")})
				sid = sid || i < count
			}
		}
		for _, prefix := range pool {
			if hegel.Draw(ht, hegel.Booleans()) {
				announce = append(announce, schema.Announce{Prefix: schema.MustPrefix(prefix)})
			}
		}
		if len(announce) != 0 {
			c.Cap.Route = &babel.Routes{Announce: announce}
		}
		if err := c.Validate(); (err == nil) == sid {
			ht.Fatalf("%d egress segments beside cap.route announcing %v loaded with %v, want taken %v", count, announce, err, !sid)
		}
	})
}
