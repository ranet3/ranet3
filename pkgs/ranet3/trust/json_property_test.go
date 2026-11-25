// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package trust

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

func TestDocumentJSONProperty(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		nodes := hegel.Draw(ht, pbt.Spanning(0, 4))
		document := Document{Nodes: make([]Node, 0, nodes)}
		for n := range nodes {
			count := hegel.Draw(ht, pbt.Spanning(0, 4))
			node := Node{Name: fmt.Sprintf("example/node%d", n), Endpoints: make([]Endpoint, 0, count)}
			for i := range count {
				endpoint := Endpoint{Family: "ip4", Port: uint32(i + 1)}
				if hegel.Draw(ht, pbt.Spanning(0, 1)) == 1 {
					endpoint.ID = new(fmt.Sprintf("path%d", i))
				}
				if hegel.Draw(ht, pbt.Spanning(0, 1)) == 1 {
					endpoint.Address = new("192.0.2.1")
				}
				node.Endpoints = append(node.Endpoints, endpoint)
			}
			document.Nodes = append(document.Nodes, node)
		}
		body, err := RenderJSON(document)
		if err != nil {
			ht.Fatal(err)
		}
		decoded, err := ReadJSON(body)
		if err != nil || !reflect.DeepEqual(decoded, document) {
			ht.Fatalf("round trip %q: document %+v, decoded %+v, error %v", body, document, decoded, err)
		}
		again, err := RenderJSON(decoded)
		if err != nil || !bytes.Equal(body, again) {
			ht.Fatalf("unstable JSON: %q and %q: %v", body, again, err)
		}
		if nodes > 0 {
			decoded.Nodes[0].Endpoints = append(decoded.Nodes[0].Endpoints, Endpoint{Family: "ip4", Port: 0})
			if _, err := RenderJSON(decoded); err == nil {
				ht.Fatal("accepted a mutated invalid port")
			}
		}
		for _, port := range [...]uint32{0, 1, 65535, 65536} {
			authored := fmt.Appendf(nil, `{"nodes":[{"endpoints":[{"family":"ip4","port":%d}],"name":"example/port"}]}`, port)
			_, err := ReadJSON(authored)
			want := port >= 1 && port <= 65535
			if (err == nil) != want {
				ht.Fatalf("JSON port %d: error %v, want valid %v", port, err, want)
			}
		}
	})
}
