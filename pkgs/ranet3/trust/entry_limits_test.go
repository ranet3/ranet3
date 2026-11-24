// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package trust

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestEntryCountsBeyondLimit(t *testing.T) {
	for _, test := range []struct {
		name      string
		document  func() Document
		jsonError string
	}{
		{
			name: "nodes",
			document: func() Document {
				result := Document{Nodes: make([]Node, MaxEntries+1)}
				for i := range result.Nodes {
					result.Nodes[i] = Node{Name: fmt.Sprintf("a/n%d", i), Endpoints: []Endpoint{}}
				}
				return result
			},
			jsonError: "nodes must be present and have at most",
		},
		{
			name: "endpoints",
			document: func() Document {
				result := Document{Nodes: []Node{{Name: "a/a", Endpoints: make([]Endpoint, MaxEntries+1)}}}
				for i := range result.Nodes[0].Endpoints {
					result.Nodes[0].Endpoints[i] = Endpoint{Family: "ip4", Port: 1}
				}
				return result
			},
			jsonError: "needs endpoints with at most",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			document := test.document()
			wire := cborDocument{Nodes: make([]cborNode, len(document.Nodes))}
			for i, node := range document.Nodes {
				wire.Nodes[i] = cborNode{Name: node.Name, Endpoints: node.Endpoints}
			}
			mesh := MeshID{6: 0x70, 8: 0x80}
			body, err := marshalCBOR(payloadWire{Height: 1, Document: wire, Mesh: mesh[:]})
			if err != nil {
				t.Fatal(err)
			}
			file, key := signTestFile(t, body, ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)), algorithmEd25519)
			t.Run("CBOR", func(t *testing.T) {
				if _, err := AuthenticateSignedFile(file, []AuthorityKey{key}); err == nil || !strings.Contains(err.Error(), "decode CBOR") {
					t.Fatalf("accepted signed %s with %d entries: %v", test.name, MaxEntries+1, err)
				}
			})
			jsonBody, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			t.Run("JSON", func(t *testing.T) {
				if _, err := ReadJSON(jsonBody); err == nil || !strings.Contains(err.Error(), test.jsonError) {
					t.Fatalf("accepted authored %s with %d entries: %v", test.name, MaxEntries+1, err)
				}
			})
		})
	}
}
