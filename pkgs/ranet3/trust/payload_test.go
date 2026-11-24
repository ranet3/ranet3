// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package trust

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"testing"
)

func payloadExample(t *testing.T) (Payload, []byte) {
	t.Helper()
	mesh := MeshID{0x01, 0x8e, 0x8c, 0xf0, 0x33, 0x20, 0x7a, 0xbc, 0x8d, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab}
	encoded, err := hex.DecodeString("a3010103a101800450018e8cf033207abc8def0123456789ab")
	if err != nil {
		t.Fatal(err)
	}
	return Payload{Height: 1, Document: Document{Nodes: []Node{}}, Mesh: mesh}, encoded
}

func TestPayloadWireSchema(t *testing.T) {
	payload, want := payloadExample(t)
	body, err := encodePayload(payload)
	if err != nil || !bytes.Equal(body, want) {
		t.Fatalf("encoded %x, want %x: %v", body, want, err)
	}
	decoded, err := decodePayload(want)
	if err != nil || !reflect.DeepEqual(decoded, payload) {
		t.Fatalf("decoded %+v, want %+v: %v", decoded, payload, err)
	}
	payload.Height = 2
	payload.Previous = new([32]byte)
	want2 := []byte{0xa4, 0x01, 0x02, 0x02, 0x58, 0x20}
	want2 = append(want2, payload.Previous[:]...)
	want2 = append(want2, 0x03, 0xa1, 0x01, 0x80, 0x04, 0x50)
	want2 = append(want2, payload.Mesh[:]...)
	body, err = encodePayload(payload)
	if err != nil || !bytes.Equal(body, want2) {
		t.Fatalf("height 2 encoded %x, want %x: %v", body, want2, err)
	}
	decoded, err = decodePayload(want2)
	if err != nil || !reflect.DeepEqual(decoded, payload) {
		t.Fatalf("height 2 decoded %+v, want %+v: %v", decoded, payload, err)
	}
	payload.Height = 1
	payload.Previous = nil
	payload.Document.Nodes = []Node{{Name: "a/a", Endpoints: []Endpoint{}}}
	wantNode := []byte{0xa3, 0x01, 0x01, 0x03, 0xa1, 0x01, 0x81, 0xa2, 0x01, 0x63, 'a', '/', 'a', 0x03, 0x80, 0x04, 0x50}
	wantNode = append(wantNode, payload.Mesh[:]...)
	body, err = encodePayload(payload)
	if err != nil || !bytes.Equal(body, wantNode) {
		t.Fatalf("node encoded %x, want %x: %v", body, wantNode, err)
	}
	decoded, err = decodePayload(wantNode)
	if err != nil || !reflect.DeepEqual(decoded, payload) {
		t.Fatalf("node decoded %+v, want %+v: %v", decoded, payload, err)
	}
}

func TestPayloadSchemaRefusals(t *testing.T) {
	payload, wire := payloadExample(t)
	for _, test := range []struct {
		name string
		bad  Payload
	}{
		{"height zero", Payload{Previous: new([32]byte), Document: payload.Document, Mesh: payload.Mesh}},
		{"height overflow", Payload{Height: MaxHeight + 1, Previous: new([32]byte), Document: payload.Document, Mesh: payload.Mesh}},
		{"previous at first", Payload{Height: 1, Previous: new([32]byte), Document: payload.Document, Mesh: payload.Mesh}},
		{"previous absent above first", Payload{Height: 2, Document: payload.Document, Mesh: payload.Mesh}},
		{"nil mesh", Payload{Height: 1, Document: payload.Document}},
		{"no nodes", Payload{Height: 1, Mesh: payload.Mesh}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if body, err := encodePayload(test.bad); err == nil {
				t.Fatalf("encoded invalid payload %x", body)
			}
		})
	}
	bad := bytes.Clone(wire)
	bad[2] = 0
	if _, err := decodePayload(bad); err == nil {
		t.Fatal("accepted height zero")
	}
	bad[2] = 2
	if _, err := decodePayload(bad); err == nil {
		t.Fatal("accepted missing previous at height 2")
	}
	bad = bytes.Clone(wire)
	bad[len(bad)-10] = 0x40
	if _, err := decodePayload(bad); err == nil {
		t.Fatal("accepted wrong mesh version")
	}
	bad = bytes.Clone(wire)
	bad[len(bad)-8] = 0xc0
	if _, err := decodePayload(bad); err == nil {
		t.Fatal("accepted wrong mesh variant")
	}
	bad = bytes.Clone(wire[:len(wire)-1])
	bad[len(bad)-16] = 0x4f
	if _, err := decodePayload(bad); err == nil {
		t.Fatal("accepted short mesh")
	}
	shortPrevious := []byte{0xa4, 0x01, 0x02, 0x02, 0x58, 0x1f}
	shortPrevious = append(shortPrevious, make([]byte, 31)...)
	shortPrevious = append(shortPrevious, wire[3:]...)
	if _, err := decodePayload(shortPrevious); err == nil {
		t.Fatal("accepted a 31-byte previous digest")
	}
	bad = append([]byte{0xa4, 0x01, 0x01, 0x02, 0x40}, wire[3:]...)
	if _, err := decodePayload(bad); err == nil {
		t.Fatal("accepted previous at height 1")
	}
}
