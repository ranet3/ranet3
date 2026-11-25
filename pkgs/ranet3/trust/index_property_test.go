// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package trust

import (
	"fmt"
	"net/netip"
	"reflect"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/internal/pbt"
)

func TestIndexProperty(t *testing.T) {
	key := indexKey(t)
	pbt.Check(t, func(ht *hegel.T) {
		count := hegel.Draw(ht, pbt.Spanning(1, 4))
		document := Document{Nodes: make([]Node, 0, count)}
		for i := range count {
			node := Node{Name: fmt.Sprintf("example/n%d", i), Endpoints: []Endpoint{}}
			if hegel.Draw(ht, pbt.Spanning(0, 1)) == 1 {
				node.Key = &key
			}
			endpoints := hegel.Draw(ht, pbt.Spanning(0, 4))
			for j := range endpoints {
				endpoint := Endpoint{Family: "ip4", Port: 443}
				if hegel.Draw(ht, pbt.Spanning(0, 1)) == 1 {
					endpoint.ID = new(fmt.Sprintf("%d", j))
				}
				switch hegel.Draw(ht, pbt.Spanning(0, 2)) {
				case 1:
					endpoint.Address = new(fmt.Sprintf("192.0.2.%d", 10*i+j+1))
				case 2:
					endpoint.Address = new("a.example")
				}
				node.Endpoints = append(node.Endpoints, endpoint)
			}
			document.Nodes = append(document.Nodes, node)
		}
		index, err := NewIndex(document)
		if err != nil {
			ht.Fatal(err)
		}
		var wantUnderlay []netip.Addr
		for _, node := range document.Nodes {
			id := identity.MustParse(node.Name)
			_, keyErr := index.Key(id)
			if (keyErr == nil) != (node.Key != nil) {
				ht.Fatalf("node %s keyed %v: %v", id, node.Key != nil, keyErr)
			}
			var wantTargets []identity.Identity
			for _, endpoint := range node.Endpoints {
				if node.Key == nil || endpoint.ID == nil {
					continue
				}
				wantTargets = append(wantTargets, id.At(*endpoint.ID))
				if endpoint.Address != nil {
					if addr, err := netip.ParseAddr(*endpoint.Address); err == nil {
						wantUnderlay = append(wantUnderlay, addr)
					}
				}
			}
			got := index.Targets(id)
			if len(got) != len(wantTargets) {
				ht.Fatalf("node %s: %d targets, want %d", id, len(got), len(wantTargets))
			}
			for j, target := range got {
				if target.ID != wantTargets[j] {
					ht.Fatalf("node %s target %d: %s, want %s", id, j, target.ID, wantTargets[j])
				}
				if _, err := index.Key(target.ID); err != nil || len(index.Targets(target.ID)) != 1 {
					ht.Fatalf("node %s endpoint %s not admitted or indexed: %v", id, target.ID, err)
				}
			}
		}
		if !reflect.DeepEqual(index.Underlay(), wantUnderlay) {
			ht.Fatalf("underlay %v, want %v", index.Underlay(), wantUnderlay)
		}
	})
}
