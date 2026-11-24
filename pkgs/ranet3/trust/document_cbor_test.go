// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package trust

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"reflect"
	"testing"
)

func TestDocumentCBORSchema(t *testing.T) {
	for _, test := range []struct {
		document Document
		hex      string
	}{
		{Document{Nodes: []Node{}}, "a10180"},
		{Document{Nodes: []Node{{Name: "a/a", Endpoints: []Endpoint{}}}}, "a10181a20163612f610380"},
		{Document{Nodes: []Node{{Name: "a/a", Endpoints: []Endpoint{{Family: "ip4", Port: 1}}}}}, "a10181a20163612f610381a202636970340401"},
		{Document{Nodes: []Node{{Name: "a/a", Endpoints: []Endpoint{{Family: "ip4", Port: 1, ID: new("x"), Address: new("a")}}}}}, "a10181a20163612f610381a401617802636970340361610401"},
	} {
		want, err := hex.DecodeString(test.hex)
		if err != nil {
			t.Fatal(err)
		}
		body, err := encodeDocumentCBOR(test.document)
		if err != nil || !bytes.Equal(body, want) {
			t.Fatalf("document %+v encoded %x, want %x: %v", test.document, body, want, err)
		}
		decoded, err := decodeDocumentCBOR(want)
		if err != nil || !reflect.DeepEqual(decoded, test.document) {
			t.Fatalf("decode %x: %+v, want %+v: %v", want, decoded, test.document, err)
		}
	}
}

func TestDocumentCBORKeyAsDER(t *testing.T) {
	const key = "MCowBQYDK2VwAyEAO2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik="
	der, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		t.Fatal(err)
	}
	document := Document{Nodes: []Node{{Name: "a/a", Key: new(key), Endpoints: []Endpoint{}}}}
	body, err := encodeDocumentCBOR(document)
	if err != nil {
		t.Fatal(err)
	}
	prefix := []byte{0xa1, 0x01, 0x81, 0xa3, 0x01, 0x63, 'a', '/', 'a', 0x02, 0x58, byte(len(der))}
	if len(body) != len(prefix)+len(der)+2 || !bytes.Equal(body[:len(prefix)], prefix) || !bytes.Equal(body[len(prefix):len(prefix)+len(der)], der) || !bytes.Equal(body[len(body)-2:], []byte{0x03, 0x80}) {
		t.Fatalf("key is not DER in a CBOR bstr: %x", body)
	}
}

func TestDocumentCBORRefusals(t *testing.T) {
	for name, encoded := range map[string]string{
		"missing nodes":      "a0",
		"null nodes":         "a101f6",
		"string label":       "a1656e6f64657380",
		"unknown label":      "a201800280",
		"duplicate label":    "a201800180",
		"missing endpoints":  "a10181a10163612f61",
		"null node key":      "a10181a30163612f6102f60380",
		"wrong node order":   "a10181a203800163612f61",
		"missing port":       "a10181a20163612f610381a10263697034",
		"invalid family":     "a10181a20163612f610381a202636970380401",
		"null endpoint id":   "a10181a20163612f610381a301f602636970340401",
		"unknown node label": "a10181a30163612f6103800480",
	} {
		t.Run(name, func(t *testing.T) {
			body, err := hex.DecodeString(encoded)
			if err != nil {
				t.Fatal(err)
			}
			if document, err := decodeDocumentCBOR(body); err == nil {
				t.Fatalf("accepted %x as %+v", body, document)
			}
		})
	}
}
