// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package trust

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"strings"
	"testing"
)

var signedLengthBoundaries = [...]int{255, 256, 65535, 65536, 16777215, 16777216}

// payloadAtLength uses valid document fields and real endpoint records, not
// arbitrary padding outside the signed document. Node text fills the remainder.
func payloadAtLength(t *testing.T, size int) (Payload, []byte) {
	t.Helper()
	endpoints := max(0, (size-1024)/8)
	count := max(1, (endpoints+MaxEntries-1)/MaxEntries)
	payload := Payload{Height: 1, Mesh: MeshID{6: 0x70, 8: 0x80}, Document: Document{Nodes: make([]Node, count)}}
	for i := range payload.Document.Nodes {
		node := &payload.Document.Nodes[i]
		node.Name = fmt.Sprintf("example/n%d", i)
		take := min(endpoints, MaxEntries)
		node.Endpoints = make([]Endpoint, take)
		for j := range node.Endpoints {
			node.Endpoints[j] = Endpoint{Family: "ip4", Port: 1}
		}
		endpoints -= take
	}
	body, err := encodePayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) >= size {
		t.Fatalf("base payload of %d bytes leaves no room to reach %d", len(body), size)
	}
	first := &payload.Document.Nodes[0].Name
	*first += strings.Repeat("x", size-len(body))
	body, err = encodePayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) > size {
		*first = (*first)[:len(*first)-(len(body)-size)]
	} else if len(body) < size {
		*first += strings.Repeat("x", size-len(body))
	}
	body, err = encodePayload(payload)
	if err != nil || len(body) != size {
		t.Fatalf("payload length %d, want %d: %v", len(body), size, err)
	}
	return payload, body
}

func TestSignedByteStringWidthBoundaries(t *testing.T) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x6c}, ed25519.SeedSize))
	for _, size := range signedLengthBoundaries {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			payload, body := payloadAtLength(t, size)
			file, key := signTestFile(t, body, private, algorithmEd25519)
			if len(file) > MaxSignedBytes {
				t.Fatalf("signed file has %d bytes, exceeds the cap", len(file))
			}
			authenticated, err := AuthenticateSignedFile(file, []AuthorityKey{key})
			if err != nil {
				t.Fatalf("authenticate %d-byte payload: %v", size, err)
			}
			verified, err := authenticated.Validate()
			if err != nil || len(verified.Payload.Document.Nodes) != len(payload.Document.Nodes) {
				t.Fatalf("validate %d-byte payload: %v", size, err)
			}
		})
	}
}

func TestByteStringWidthForms(t *testing.T) {
	for _, size := range []int{23, 24} {
		body := bytes.Repeat([]byte{0x11}, size)
		encoded := appendBstr(nil, body)
		at := 0
		got, err := takeBstr(encoded, &at)
		if err != nil || !bytes.Equal(got, body) || at != len(encoded) {
			t.Fatalf("canonical length %d: %v", size, err)
		}
	}
	for _, test := range []struct {
		name string
		head []byte
	}{
		{"one byte for 23", []byte{0x58, 0x17}},
		{"two bytes for 255", []byte{0x59, 0x00, 0xff}},
		{"four bytes for 65535", []byte{0x5a, 0x00, 0x00, 0xff, 0xff}},
		{"eight bytes for 4294967295", []byte{0x5b, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff}},
	} {
		t.Run(test.name, func(t *testing.T) {
			at := 0
			if _, err := takeBstr(test.head, &at); err == nil || err.Error() != "nonminimal byte string length" {
				t.Fatalf("accepted overlong length head %x: %v", test.head, err)
			}
		})
	}
}
