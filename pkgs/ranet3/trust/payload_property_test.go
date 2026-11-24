// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package trust

import (
	"fmt"
	"reflect"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

func TestPayloadProperty(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		mesh := MeshID{0x01, 0x8e, 0x8c, 0xf0, 0x33, 0x20, 0x7a, 0xbc, 0x8d, 0xef}
		count := hegel.Draw(ht, pbt.Spanning(0, 3))
		document := Document{Nodes: make([]Node, 0, count)}
		for n := range count {
			document.Nodes = append(document.Nodes, Node{Name: fmt.Sprintf("example/n%d", n), Endpoints: []Endpoint{{Family: "ip4", Port: uint32(n + 1)}}})
		}
		payload := Payload{Height: 1, Document: document, Mesh: mesh}
		if hegel.Draw(ht, pbt.Spanning(0, 1)) == 1 {
			payload.Height = MaxHeight
			payload.Previous = new([32]byte)
			payload.Previous[0] = 0x42
		}
		body, err := encodePayload(payload)
		if err != nil {
			ht.Fatal(err)
		}
		decoded, err := decodePayload(body)
		if err != nil || !reflect.DeepEqual(decoded, payload) {
			ht.Fatalf("payload %x: decoded %+v, want %+v: %v", body, decoded, payload, err)
		}
		decoded.Height = 0
		if _, err := encodePayload(decoded); err == nil {
			ht.Fatal("encoded zero height after a valid round trip")
		}
	})
}
