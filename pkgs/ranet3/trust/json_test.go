// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package trust

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
)

func TestDocumentJSON(t *testing.T) {
	// The independent Nix rendering in the format specification fixes ordering.
	const text = `{"nodes":[{"endpoints":[{"address":"gateway.example.org","family":"ip6","port":13000},{"address":"192.0.2.1","family":"ip4","port":13000}],"key":"MCowBQYDK2VwAyEAO2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=","name":"example/gateway"},{"endpoints":[],"name":"example/my-laptop"}]}`
	document, err := ReadJSON([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	if len(document.Nodes) != 2 || len(document.Nodes[0].Endpoints) != 2 || document.Nodes[1].Key != nil || document.Nodes[0].Endpoints[1].ID != nil {
		t.Fatalf("lost members or order: %+v", document)
	}
	body, err := RenderJSON(document)
	if err != nil || !bytes.Equal(body, []byte(text)) {
		t.Fatalf("render %q, error %v", body, err)
	}
	const nullAsText = `{"nodes":[{"endpoints":[{"address":"null","family":"ip4","port":1}],"name":"example/null"}]}`
	if _, err := ReadJSON([]byte(nullAsText)); err != nil {
		t.Fatalf("rejected null inside a string: %v", err)
	}
}

func TestDocumentJSONRefusals(t *testing.T) {
	const good = `{"nodes":[{"endpoints":[{"address":"192.0.2.1","family":"ip4","id":"alpha","port":13000}],"name":"example/gateway"}]}`
	for name, text := range map[string]string{
		"unknown":        `{"nodes":[],"other":true}`,
		"wrong case":     `{"Nodes":[]}`,
		"case twin":      `{"nodes":[],"Nodes":[]}`,
		"duplicate":      `{"nodes":[],"nodes":[]}`,
		"nested twin":    `{"nodes":[{"endpoints":[],"Name":"example/gateway","name":"example/gateway"}]}`,
		"nested case":    `{"nodes":[{"endpoints":[],"Name":"example/gateway"}]}`,
		"endpoint extra": strings.Replace(good, `"port":13000`, `"port":13000,"extra":true`, 1),
		"endpoint case":  strings.Replace(good, `"port":13000`, `"PORT":13000`, 1),
		"missing nodes":  `{}`,
		"null nodes":     `{"nodes":null}`,
		"missing list":   `{"nodes":[{"name":"example/gateway"}]}`,
		"null list":      `{"nodes":[{"endpoints":null,"name":"example/gateway"}]}`,
		"null id":        strings.Replace(good, `"id":"alpha"`, `"id":null`, 1),
		"null key":       `{"nodes":[{"endpoints":[],"key":null,"name":"example/gateway"}]}`,
		"null address":   strings.Replace(good, `"192.0.2.1"`, `null`, 1),
		"bad id":         strings.Replace(good, `"id":"alpha"`, `"id":"alpha  beta"`, 1),
		"case twin id":   strings.Replace(good, `}],"name"`, `},{"family":"ip4","id":"ALPHA","port":1}],"name"`, 1),
		"empty address":  strings.Replace(good, `"192.0.2.1"`, `""`, 1),
		"bad address":    strings.Replace(good, `"192.0.2.1"`, `"192.0.2.01"`, 1),
		"family":         strings.Replace(good, `"ip4"`, `"ip8"`, 1),
		"port zero":      strings.Replace(good, `"port":13000`, `"port":0`, 1),
		"port high":      strings.Replace(good, `"port":13000`, `"port":65536`, 1),
		"no serial":      strings.Replace(good, `"name":"example/gateway"`, `"name":"example/gateway:x"`, 1),
		"case twin name": `{"nodes":[{"endpoints":[],"name":"example/gateway"},{"endpoints":[],"name":"example/Gateway"}]}`,
		"invalid utf8":   strings.Replace(good, "example/gateway", string([]byte{0xff}), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if document, err := ReadJSON([]byte(text)); err == nil {
				t.Fatalf("accepted %+v from %q", document, text)
			}
		})
	}
}

func TestDocumentJSONRejectsNonzeroKeyPadBits(t *testing.T) {
	const canonical = "MCowBQYDK2VwAyEAO2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik="
	bad := canonical[:len(canonical)-2] + "l="
	goodDER, err := base64.StdEncoding.DecodeString(canonical)
	if err != nil {
		t.Fatal(err)
	}
	badDER, err := base64.StdEncoding.DecodeString(bad)
	if err != nil || !bytes.Equal(goodDER, badDER) {
		t.Fatalf("fixture must differ only in unused base64 bits: %v", err)
	}
	body := []byte(`{"nodes":[{"endpoints":[],"key":"` + bad + `","name":"example/gateway"}]}`)
	if _, err := ReadJSON(body); err == nil || !strings.Contains(err.Error(), "canonical padded base64") {
		t.Fatalf("accepted nonzero key pad bits from JSON: %v", err)
	}
}

func TestDocumentJSONRejectsEveryInvalidEd25519Encoding(t *testing.T) {
	encodings := smallOrderEncodings(t)
	if len(encodings) != 14 {
		t.Fatalf("small-order encodings: %d, want 14", len(encodings))
	}
	y := big.NewInt(2)
	for sign := range uint(2) {
		if _, ok := pointAt(y, sign); ok {
			t.Fatalf("ordinate %v unexpectedly lies on the curve", y)
		}
		encodings = append(encodings, encodeAt(y, sign))
	}
	for _, encoded := range encodings {
		der, err := x509.MarshalPKIXPublicKey(ed25519.PublicKey(encoded[:]))
		if err != nil {
			t.Fatal(err)
		}
		body := []byte(`{"nodes":[{"endpoints":[],"key":"` + base64.StdEncoding.EncodeToString(der) + `","name":"example/gateway"}]}`)
		if document, err := ReadJSON(body); err == nil {
			t.Errorf("accepted invalid Ed25519 key %x in document %+v", encoded, document)
		}
	}
}

func TestNodeKeySharing(t *testing.T) {
	const key = `MCowBQYDK2VwAyEAO2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=`
	for _, test := range []struct {
		names []string
		want  bool
	}{
		{[]string{"example/gateway", "example/laptop"}, true},
		{[]string{"example/gateway", "another/laptop"}, false},
	} {
		nodes := make([]Node, 0, len(test.names))
		for _, name := range test.names {
			nodes = append(nodes, Node{Name: name, Endpoints: []Endpoint{}, Key: new(key)})
		}
		if err := (Document{Nodes: nodes}).Validate(); (err == nil) != test.want {
			t.Fatalf("keys shared by %v: error %v, want valid %v", test.names, err, test.want)
		}
	}
}

func TestNodeKeyMustBeEd25519(t *testing.T) {
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&p256.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	key := base64.StdEncoding.EncodeToString(der)
	document := Document{Nodes: []Node{{Name: "example/gateway", Key: &key, Endpoints: []Endpoint{}}}}
	if err := document.Validate(); err == nil {
		t.Fatal("accepted P-256 node key in Ed25519-only format")
	}
}

func TestEndpointIDProfile(t *testing.T) {
	for _, test := range []struct {
		id   string
		want bool
	}{
		{"a", true},
		{"a b", true},
		{"a'()+,-./:=?z", true},
		{strings.Repeat("a", 64), true},
		{"", false},
		{" a", false},
		{"a ", false},
		{"a  b", false},
		{strings.Repeat("a", 65), false},
		{"a$b", false},
		{"a_b", false},
		{"a\tb", false},
		{"a\"b", false},
		{"a\\b", false},
		{"a\u00e9b", false},
	} {
		t.Run(test.id, func(t *testing.T) {
			e := Endpoint{Family: "ip4", Port: 1, ID: new(test.id)}
			if err := e.validate(); (err == nil) != test.want {
				t.Fatalf("endpoint id %q: error %v, want valid %v", test.id, err, test.want)
			}
		})
	}
}

func TestEndpointAddressProfile(t *testing.T) {
	for _, test := range []struct {
		address string
		family  string
		valid   bool
	}{
		{"gateway.example.org", "ip4", true},
		{"xn--bcher-kva.example", "ip6", true},
		{"192.0.2.1", "ip4", true},
		{"2001:db8::1", "ip6", true},
		{"64:ff9b::c000:201", "ip6", true},
		{"64:ff9b::192.0.2.1", "ip6", false},
		{"::ffff:192.0.2.1", "ip6", false},
		{"192.0.2.1", "ip6", false},
		{"2001:0db8::1", "ip6", false},
		{"2001:db8::1%eth0", "ip6", false},
		{"GATEWAY.example.org", "ip4", false},
		{"123.456", "ip4", false},
		{"xn--a.example", "ip4", false},
		{"host..example", "ip4", false},
		{"-host.example", "ip4", false},
	} {
		t.Run(test.address, func(t *testing.T) {
			e := Endpoint{Family: test.family, Port: 13000, Address: new(test.address)}
			if err := e.validate(); (err == nil) != test.valid {
				t.Fatalf("address %q, family %q: error %v, want valid %v", test.address, test.family, err, test.valid)
			}
		})
	}
}
