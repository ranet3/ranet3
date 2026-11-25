// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package trust

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuthorityOverlapBeforeFieldValidation(t *testing.T) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x52}, ed25519.SeedSize))
	_, sample := payloadExample(t)
	mesh := sample[len(sample)-16:]
	for _, authorityName := range []string{"ed25519", "p256", "p384"} {
		t.Run(authorityName, func(t *testing.T) {
			var authority AuthorityKey
			for _, vector := range independentVectors {
				if vector.name == authorityName {
					var err error
					authority, err = ParseAuthorityKey(vector.key)
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			wire := payloadWire{Height: 1, Document: cborDocument{Nodes: []cborNode{{Name: "example/a:a", Key: authority.DER, Endpoints: []Endpoint{}}}}, Mesh: mesh}
			body, err := marshalCBOR(wire)
			if err != nil {
				t.Fatal(err)
			}
			file, signer := signTestFile(t, body, private, algorithmEd25519)
			authenticated, err := AuthenticateSignedFile(file, []AuthorityKey{signer})
			if err != nil {
				t.Fatal(err)
			}
			if err := CheckOverlap([]AuthorityKey{authority}, authenticated.Payload()); err == nil || !strings.Contains(err.Error(), "authority key") {
				t.Fatalf("overlapping unvalidated snapshot: %v", err)
			}
			if _, err := authenticated.Validate(); err == nil {
				t.Fatal("accepted an invalid node name after overlap check")
			}
			if _, err := VerifySignedFile(file, []AuthorityKey{signer}); err == nil {
				t.Fatal("accepted an invalid signed document")
			}
			path := filepath.Join(t.TempDir(), "offered.cbor")
			if err := os.WriteFile(path, file, 0o600); err != nil {
				t.Fatal(err)
			}
			offered, err := ReadAuthenticatedFile(path, []AuthorityKey{signer})
			if err != nil {
				t.Fatal(err)
			}
			if err := CheckOverlap([]AuthorityKey{authority}, offered.Payload()); err == nil {
				t.Fatal("missed overlapping key in offered file")
			}
			if _, err := ReadSignedFile(path, []AuthorityKey{signer}); err == nil {
				t.Fatal("fully verified an invalid offered file")
			}
		})
	}
}

func TestAuthorityOverlapQuotesUnvalidatedName(t *testing.T) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x53}, ed25519.SeedSize))
	der, err := x509.MarshalPKIXPublicKey(private.Public())
	if err != nil {
		t.Fatal(err)
	}
	name := "example/a\nFORGED-LOG\x1b[31m"
	mesh := MeshID{6: 0x70, 8: 0x80}
	wire := payloadWire{
		Height:   1,
		Document: cborDocument{Nodes: []cborNode{{Name: name, Key: der, Endpoints: []Endpoint{}}}},
		Mesh:     mesh[:],
	}
	body, err := marshalCBOR(wire)
	if err != nil {
		t.Fatal(err)
	}
	file, authority := signTestFile(t, body, private, algorithmEd25519)
	authenticated, err := AuthenticateSignedFile(file, []AuthorityKey{authority})
	if err != nil {
		t.Fatal(err)
	}
	err = CheckOverlap([]AuthorityKey{authority}, authenticated.Payload())
	want := fmt.Sprintf("trust: authority key also belongs to node %q", name)
	if err == nil || err.Error() != want || strings.ContainsAny(err.Error(), "\n\x1b") {
		t.Fatalf("unquoted overlap name: %q, want %q", err, want)
	}
}

func TestAuthorityOverlapSkipsKeylessRecords(t *testing.T) {
	key, err := ParseAuthorityKey(independentVectors[0].key)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ParseAuthorityKey(independentVectors[1].key)
	if err != nil {
		t.Fatal(err)
	}
	absent := Payload{Document: Document{Nodes: []Node{{Name: "example/a", Endpoints: []Endpoint{}}}}}
	if err := CheckOverlap([]AuthorityKey{key}, absent); err != nil {
		t.Fatal(err)
	}
	present := base64.StdEncoding.EncodeToString(key.DER)
	absent.Document.Nodes = append(absent.Document.Nodes, Node{Name: "example/b", Key: &present, Endpoints: []Endpoint{}})
	if err := CheckOverlap([]AuthorityKey{other}, absent); err != nil {
		t.Fatal(err)
	}
	if err := CheckOverlap([]AuthorityKey{other, key}, absent); err == nil {
		t.Fatal("accepted a member's authority key")
	}
}
