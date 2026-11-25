// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package netstack

import (
	"net/netip"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// A held child outranks a covering peer even when the peer has a longer source selector
// RFC 9079 section 4 orders destination before source, and RFC 8966 section 3.5.4 keeps a retracted prefix from falling back to its cover
func TestSourcedWinnerAndVerdict(t *testing.T) {
	prefix := func(s string) netip.Prefix { return netip.MustParsePrefix(s) }
	address := func(s string) netip.Addr { return netip.MustParseAddr(s) }
	peers := []*Peer{{ID: "first"}, {ID: "second"}}
	for _, scenario := range []struct {
		name     string
		entries  []tableEntry
		from, to netip.Addr
	}{
		{"cover peer", []tableEntry{{destination: prefix("2001:db8::/32"), kind: learnedEntry}}, address("3fff:1::1"), address("2001:db8:1::1")},
		{"held child", []tableEntry{{destination: prefix("2001:db8::/32"), source: prefix("3fff:1::/48"), kind: learnedEntry}, {destination: prefix("2001:db8:1::/48"), kind: heldEntry}}, address("3fff:1::1"), address("2001:db8:1::1")},
		{"source peer", []tableEntry{{destination: prefix("2001:db8:1::/48"), kind: learnedEntry}, {destination: prefix("2001:db8:1::/48"), source: prefix("3fff:1::/48"), kind: learnedEntry, peer: 1}}, address("3fff:1::1"), address("2001:db8:1::1")},
		{"held source", []tableEntry{{destination: prefix("2001:db8:1::/48"), kind: learnedEntry}, {destination: prefix("2001:db8:1::/48"), source: prefix("3fff:1::/48"), kind: heldEntry}}, address("3fff:1::1"), address("2001:db8:1::1")},
		{"other source", []tableEntry{{destination: prefix("2001:db8:1::/48"), source: prefix("3fff:2::/48"), kind: learnedEntry}, {destination: prefix("2001:db8:1::/48"), source: prefix("3fff:1::/48"), kind: heldEntry}}, address("3fff:2::1"), address("2001:db8:1::1")},
		{"local", []tableEntry{{destination: prefix("2001:db8:1::/48"), kind: localEntry}}, address("3fff:1::1"), address("2001:db8:1::1")},
		{"missing source", []tableEntry{{destination: prefix("2001:db8:1::/48"), source: prefix("3fff:2::/48"), kind: learnedEntry}}, address("3fff:1::1"), address("2001:db8:1::1")},
		{"no peer", nil, address("3fff:1::1"), address("2001:db8:1::1")},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			pbt.Check(t, func(ht *hegel.T) {
				m := &routeModel{peers: peers}
				rt := NewRouteTable()
				for _, entry := range scenario.entries {
					value := peers[entry.peer]
					switch entry.kind {
					case heldEntry:
						value = Unreachable
					case localEntry:
						value = Local
					}
					m.set(entry)
					rt.Set(entry.source, entry.destination, value)
				}
				from, to := scenario.from, scenario.to
				if hegel.Draw(ht, pbt.Spanning(0, 1)) == 1 {
					from = address("3fff:2::1")
				}
				if hegel.Draw(ht, pbt.Spanning(0, 1)) == 1 {
					to = address("2001:db8:2::1")
				}
				wantPeer, wantVerdict, wantMatch := m.answer(from, to)
				peer, verdict, match := rt.Resolve(from, to)
				if peer != wantPeer || verdict != wantVerdict || match != wantMatch {
					ht.Fatalf("from %s to %s: got %v %v %+v, want %v %v %+v, entries %#v", from, to, peer, verdict, match, wantPeer, wantVerdict, wantMatch, m.entries)
				}
			})
		})
	}
}
