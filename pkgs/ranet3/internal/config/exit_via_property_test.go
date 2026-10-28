// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package config

import (
	"net/netip"
	"reflect"
	"slices"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
)

// viaTaken is the model of cap.exit via, written from the rules the loader states: the path is taken with no SID twice,
// none of this node's own first or last, an IPv6 overlay prefix, and an outer source inside the overlay
// which is cap.segment source where written, else the first IPv6 cap.table address inside the overlay
// a local segment needs an IPv6 overlay prefix whatever via says
// it reports whether the node loads and the source its path is sent from
func viaTaken(via []netip.Addr, own netip.Addr, local bool, overlay []netip.Prefix, addresses []netip.Prefix, source netip.Addr) (bool, netip.Addr) {
	inside := func(address netip.Addr) bool {
		for _, prefix := range overlay {
			if prefix.Contains(address) {
				return true
			}
		}
		return false
	}
	v6 := false
	for _, prefix := range overlay {
		v6 = v6 || prefix.Addr().Is6()
	}
	if local && !v6 {
		return false, netip.Addr{}
	}
	if len(via) == 0 {
		return true, netip.Addr{}
	}
	for i, sid := range via {
		for _, other := range via[:i] {
			if other == sid {
				return false, netip.Addr{}
			}
		}
	}
	if local && (via[0] == own || via[len(via)-1] == own) || !v6 {
		return false, netip.Addr{}
	}
	if !source.IsValid() {
		for _, address := range addresses {
			if address.Addr().Is6() && inside(address.Addr()) {
				source = address.Addr()
				break
			}
		}
	}
	if !source.IsValid() || !inside(source) {
		return false, netip.Addr{}
	}
	return true, source
}

// over drawn overlays, cap.table addresses, cap.segment sources and local segments, and paths drawn with repeats and this node's own SID
// a node loads exactly where the model takes it, and the steering table's default policy is via in the order written, sent from the model's source
// with its overhead in the table's, and a node with no via has none
func TestExitViaPolicyIsThePathFromTheModelsSource(t *testing.T) {
	overlays := [][]string{{"192.0.2.0/24", "3fff::/20"}, {"192.0.2.0/24"}, {"3fff::/20"}}
	addressPool := []string{"192.0.2.2/24", "2001:db8::2/64", "3fff::2/20", "3fff::7/20", "3fff:0:0:1::5/64"}
	sources := []string{"", "3fff:b:0:100::1", "2001:db8::2"}
	own := netip.MustParseAddr("3fff:b:0:106::1")
	sids := []netip.Addr{netip.MustParseAddr("3fff:b:0:206::1"), netip.MustParseAddr("3fff:b:0:306::3"), netip.MustParseAddr("3fff:b:0:406::4"), own}
	pbt.Check(t, func(ht *hegel.T) {
		var overlay []netip.Prefix
		var border []schema.Prefix
		for _, prefix := range overlays[hegel.Draw(ht, pbt.Spanning(0, len(overlays)-1))] {
			overlay = append(overlay, netip.MustParsePrefix(prefix))
			border = append(border, schema.MustPrefix(prefix))
		}
		var addresses []netip.Prefix
		var written []schema.Prefix
		for _, address := range pbt.Subset(ht, addressPool, 0, len(addressPool)) {
			addresses = append(addresses, netip.MustParsePrefix(address))
			written = append(written, schema.MustPrefix(address))
		}
		var via []netip.Addr
		var path []schema.Addr
		for range hegel.Draw(ht, pbt.Spanning(0, 4)) {
			sid := hegel.Draw(ht, hegel.SampledFrom(sids))
			via = append(via, sid)
			path = append(path, schema.AddrFrom(sid))
		}
		local := hegel.Draw(ht, hegel.Booleans())
		source := sources[hegel.Draw(ht, pbt.Spanning(0, len(sources)-1))]

		cfg := Config{
			Node: identity.MustParse("example/laptop"),
			Auth: Auth{Key: "key.pem", Trust: "trust.json"},
			Link: Link{Port: 13000, Endpoints: []Endpoint{{Serial: "0", Family: "ip4"}}},
			Dial: Dial{To: []identity.Identity{identity.MustParse("example/gateway")}},
			Cap: Caps{
				Table:  &kernel.Table{Addresses: written},
				Border: &egress.Border{Overlay: border},
				Exit:   &kernel.ExitMode{Via: path},
			},
		}
		var written6 netip.Addr
		if source != "" || local {
			cfg.Cap.Segment = &srv6.Segments{}
			if source != "" {
				written6 = netip.MustParseAddr(source)
				cfg.Cap.Segment.Source = schema.AddrFrom(written6)
			}
			if local {
				cfg.Cap.Segment.Local = []srv6.Segment{{SID: schema.AddrFrom(own), Behavior: srv6.BehaviorEnd}}
			}
		}
		taken, want := viaTaken(via, own, local, overlay, addresses, written6)
		err := cfg.Validate()
		if (err == nil) != taken {
			ht.Fatalf("overlay %v, addresses %v, source %q, local %t, via %v: the loader says %v, the model takes it %t", overlay, addresses, source, local, via, err, taken)
		}
		if !taken {
			return
		}
		_, steering, err := cfg.SegmentTables()
		if err != nil {
			ht.Fatal(err)
		}
		policy := steering.Default()
		// handedFrom reports the reconciler's table sending the path from source, which WithPathSource(source) then leaves as it is
		handedFrom := func(source netip.Addr) bool {
			table := cfg.ReconcilerTable()
			if table == nil {
				return !source.IsValid()
			}
			return reflect.DeepEqual(*table, table.WithPathSource(source))
		}
		if len(via) == 0 {
			if policy != nil || !handedFrom(netip.Addr{}) {
				ht.Fatalf("a node with no via steers by default along %v, or hands the reconciler a source for it", policy)
			}
			return
		}
		if policy == nil || policy.Source != want || !slices.Equal(policy.Path, via) {
			ht.Fatalf("overlay %v, addresses %v, source %q: the default policy is %+v, want %v from %s", overlay, addresses, source, policy, via, want)
		}
		// the reconciler resolves the path's SIDs from the source the dataplane sends it from
		if !handedFrom(want) {
			ht.Fatalf("overlay %v, addresses %v, source %q: the reconciler resolves the path from another source than %s", overlay, addresses, source, want)
		}
		if steering.Overhead() != srv6.Overhead(len(via)) {
			ht.Fatalf("a path of %d segments costs the device %d bytes, want %d", len(via), steering.Overhead(), srv6.Overhead(len(via)))
		}
	})
}
