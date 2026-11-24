// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package trust

import (
	"crypto/ed25519"
	"fmt"
	"testing"
)

// Address-free endpoints are the smallest in signed bytes. This document
// fills the signed limit with them.
func TestLimitsWorstSignedSnapshotJSONFits(t *testing.T) {
	const nodeCount = 64
	const reserveEndpoints = 1024
	document := Document{Nodes: make([]Node, nodeCount)}
	for i := range document.Nodes {
		count := MaxEntries
		if i == nodeCount-1 {
			count -= reserveEndpoints
		}
		node := &document.Nodes[i]
		node.Name = fmt.Sprintf("example/n%d", i)
		node.Endpoints = make([]Endpoint, count)
		for j := range node.Endpoints {
			node.Endpoints[j] = Endpoint{Family: "ip4", Port: 1}
		}
	}
	mesh := MeshID{6: 0x70, 8: 0x80}
	payload, err := encodePayload(Payload{Height: 1, Document: document, Mesh: mesh})
	if err != nil {
		t.Fatal(err)
	}
	file, _ := signTestFile(t, payload, ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)), algorithmEd25519)
	if len(file) > MaxSignedBytes || len(file) < MaxSignedBytes-(16<<10) {
		t.Fatalf("signed snapshot has %d bytes, want within 16 KiB of the 64 MiB limit", len(file))
	}
	body, err := RenderJSON(document)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) > MaxJSONBytes {
		t.Fatalf("canonical JSON has %d bytes, exceeds %d", len(body), MaxJSONBytes)
	}
	t.Logf("worst signed snapshot: signed=%d canonical-json=%d, cap=%d bytes", len(file), len(body), MaxJSONBytes)
}

// One-letter host names maximize the JSON expansion at the signed limit.
func TestLimitsMaximalJSONExpansionFits(t *testing.T) {
	const fullNodes = 46
	const endpoints = 6100738
	address := "a"
	document := Document{Nodes: make([]Node, fullNodes+1)}
	for i := range document.Nodes {
		count := MaxEntries
		if i == fullNodes {
			count = endpoints - fullNodes*MaxEntries
		}
		node := &document.Nodes[i]
		node.Name = fmt.Sprintf("%c/%c", 'a'+rune(i%26), 'a'+rune(i/26))
		node.Endpoints = make([]Endpoint, count)
		for j := range node.Endpoints {
			node.Endpoints[j] = Endpoint{Address: &address, Family: "ip4", Port: 10}
		}
	}
	mesh := MeshID{6: 0x70, 8: 0x80}
	payload, err := encodePayload(Payload{Height: 1, Document: document, Mesh: mesh})
	if err != nil {
		t.Fatal(err)
	}
	file, _ := signTestFile(t, payload, ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)), algorithmEd25519)
	if len(file) > MaxSignedBytes || len(file) < MaxSignedBytes-(16<<10) {
		t.Fatalf("maximal-expansion snapshot has %d bytes, want within 16 KiB of the 64 MiB limit", len(file))
	}
	body, err := RenderJSON(document)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) > MaxJSONBytes {
		t.Fatalf("maximal-expansion JSON has %d bytes, exceeds %d", len(body), MaxJSONBytes)
	}
	t.Logf("maximal JSON expansion: nodes=%d endpoints=%d signed=%d canonical-json=%d cap=%d bytes", len(document.Nodes), endpoints, len(file), len(body), MaxJSONBytes)
}
