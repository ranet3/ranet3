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

func TestDocumentCBORProperty(t *testing.T) {
	const key = "MCowBQYDK2VwAyEAO2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik="
	pbt.Check(t, func(ht *hegel.T) {
		count := hegel.Draw(ht, pbt.Spanning(0, 4))
		document := Document{Nodes: make([]Node, 0, count)}
		for n := range count {
			endpointCount := hegel.Draw(ht, pbt.Spanning(0, 4))
			node := Node{Name: fmt.Sprintf("example/node%d", n), Endpoints: make([]Endpoint, 0, endpointCount)}
			if hegel.Draw(ht, pbt.Spanning(0, 1)) == 1 {
				node.Key = new(key)
			}
			for i := range endpointCount {
				endpoint := Endpoint{Family: "ip4", Port: uint32(i + 1)}
				if hegel.Draw(ht, pbt.Spanning(0, 1)) == 1 {
					endpoint.ID = new(fmt.Sprintf("link%d", i))
				}
				if hegel.Draw(ht, pbt.Spanning(0, 1)) == 1 {
					endpoint.Address = new("192.0.2.1")
				}
				node.Endpoints = append(node.Endpoints, endpoint)
			}
			document.Nodes = append(document.Nodes, node)
		}
		body, err := encodeDocumentCBOR(document)
		if err != nil {
			ht.Fatal(err)
		}
		decoded, err := decodeDocumentCBOR(body)
		if err != nil || !reflect.DeepEqual(decoded, document) {
			ht.Fatalf("CBOR %x round trip: decoded %+v, want %+v: %v", body, decoded, document, err)
		}
		jsonBefore, err := RenderJSON(document)
		if err != nil {
			ht.Fatal(err)
		}
		jsonAfter, err := RenderJSON(decoded)
		if err != nil || !bytes.Equal(jsonBefore, jsonAfter) {
			ht.Fatalf("JSON drift across CBOR: %q and %q: %v", jsonBefore, jsonAfter, err)
		}
		for _, test := range []struct {
			port uint32
			head []byte
		}{
			{0, []byte{0x00}},
			{1, []byte{0x01}},
			{65535, []byte{0x19, 0xff, 0xff}},
			{65536, []byte{0x1a, 0x00, 0x01, 0x00, 0x00}},
		} {
			wire := append([]byte{0xa1, 0x01, 0x81, 0xa2, 0x01, 0x6c}, "example/port"...)
			wire = append(wire, 0x03, 0x81, 0xa2, 0x02, 0x63, 'i', 'p', '4', 0x04)
			wire = append(wire, test.head...)
			_, err := decodeDocumentCBOR(wire)
			want := test.port >= 1 && test.port <= 65535
			if (err == nil) != want {
				ht.Fatalf("CBOR port %d: error %v, want valid %v", test.port, err, want)
			}
		}
	})
}
