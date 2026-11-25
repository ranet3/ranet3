// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package trust

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"reflect"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

func TestVerifiedEnvelopeProperty(t *testing.T) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x17}, ed25519.SeedSize))
	pbt.Check(t, func(ht *hegel.T) {
		var payload Payload
		var body []byte
		choice := hegel.Draw(ht, pbt.Spanning(0, 127))
		if choice <= len(signedLengthBoundaries) {
			// Keep the 16 MiB cases rare while sampling the four-byte head at the span edge.
			size := 65536
			if choice != 0 {
				size = signedLengthBoundaries[choice-1]
			}
			payload, body = payloadAtLength(t, size)
		} else {
			count := hegel.Draw(ht, pbt.Spanning(0, 3))
			payload = Payload{Height: 1, Mesh: MeshID{6: 0x70, 8: 0x80}, Document: Document{Nodes: make([]Node, 0, count)}}
			for i := range count {
				payload.Document.Nodes = append(payload.Document.Nodes, Node{Name: fmt.Sprintf("unit/n%d", i), Endpoints: []Endpoint{{Family: "ip4", Port: uint32(i + 1)}}})
			}
			if hegel.Draw(ht, pbt.Spanning(0, 1)) == 1 {
				payload.Height = MaxHeight
				payload.Previous = new([32]byte)
				payload.Previous[0] = 0x51
			}
			var err error
			body, err = encodePayload(payload)
			if err != nil {
				ht.Fatal(err)
			}
		}
		file, key := signTestFile(t, body, private, algorithmEd25519)
		verified, err := VerifySignedFile(file, []AuthorityKey{key})
		if err != nil || verified.Digest != sha256.Sum256(body) || !reflect.DeepEqual(verified.Payload, payload) {
			ht.Fatalf("verified %+v, want %+v: %v", verified, payload, err)
		}
		tampered := bytes.Clone(file)
		tampered[bytes.Index(tampered, body)+len(body)-1] ^= 1
		if _, err := VerifySignedFile(tampered, []AuthorityKey{key}); err == nil {
			ht.Fatal("accepted a changed payload under the original signature")
		}
	})
}
