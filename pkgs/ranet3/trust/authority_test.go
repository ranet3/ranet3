// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package trust

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func authorityText(t *testing.T, public any) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

func TestAuthorityKeyTypes(t *testing.T) {
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name      string
		private   any
		algorithm int
	}{
		{"ed25519", honestKey("authority", 0), algorithmEd25519},
		{"p256", p256, algorithmESP256},
		{"p384", p384, algorithmESP384},
		{"p521", p521, 0},
		{"rsa", rsaKey, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			der, err := x509.MarshalPKCS8PrivateKey(test.private)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "authority.pem")
			if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
				t.Fatal(err)
			}
			signer, parsed, err := LoadAuthorityPrivateKey(path)
			if test.algorithm == 0 {
				if err == nil {
					t.Fatalf("unsupported key accepted as %+v", parsed)
				}
				return
			}
			if err != nil || signer == nil || parsed.Algorithm != test.algorithm {
				t.Fatalf("key %s: algorithm %d, signer %T, error %v", test.name, parsed.Algorithm, signer, err)
			}
			if fromText, err := ParseAuthorityKey(base64.StdEncoding.EncodeToString(parsed.DER)); err != nil || fromText.Algorithm != test.algorithm {
				t.Fatalf("public key: %+v, %v", fromText, err)
			}
		})
	}
}

func TestAuthorityCanonicalBase64AndSmallOrder(t *testing.T) {
	text := authorityText(t, honestKey("authority", 1).Public().(ed25519.PublicKey))
	if _, err := ParseAuthorityKey(text); err != nil {
		t.Fatal(err)
	}
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	last := len(text) - 2
	mutated := []byte(text)
	for i := range alphabet {
		if alphabet[i] == mutated[last] {
			mutated[last] = alphabet[i+1]
			break
		}
	}
	for _, malformed := range []string{string(mutated), text[:len(text)-1], text + "\n", "!!!"} {
		if _, err := ParseAuthorityKey(malformed); err == nil {
			t.Fatalf("accepted noncanonical base64 %q", malformed)
		}
	}
	encodings := smallOrderEncodings(t)
	if len(encodings) != 14 {
		t.Fatalf("%d small-order encodings, want 14", len(encodings))
	}
	for _, encoded := range encodings {
		if _, err := ParseAuthorityKey(authorityText(t, ed25519.PublicKey(encoded[:]))); err == nil {
			t.Errorf("accepted small-order key %x", encoded)
		}
	}
}

func TestAuthorityPrivateKeyPEMBound(t *testing.T) {
	const expectedLimit = 65536
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name      string
		private   crypto.Signer
		algorithm int
	}{
		{"ed25519", ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)), algorithmEd25519},
		{"p256", p256, algorithmESP256},
		{"p384", p384, algorithmESP384},
	} {
		t.Run(test.name, func(t *testing.T) {
			der, err := x509.MarshalPKCS8PrivateKey(test.private)
			if err != nil {
				t.Fatal(err)
			}
			body := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
			footer := []byte("-----END PRIVATE KEY-----\n")
			if !bytes.HasSuffix(body, footer) {
				t.Fatalf("unexpected PKCS8 PEM footer")
			}
			publicDER, err := x509.MarshalPKIXPublicKey(test.private.Public())
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "authority.pem")
			for _, size := range []int{4097, expectedLimit, expectedLimit + 1} {
				padded := make([]byte, size)
				start := len(body) - len(footer)
				copy(padded, body[:start])
				for i := start; i < size-len(footer); i++ {
					padded[i] = '\n'
				}
				copy(padded[size-len(footer):], footer)
				if err := os.WriteFile(path, padded, 0600); err != nil {
					t.Fatal(err)
				}
				_, key, err := LoadAuthorityPrivateKey(path)
				if size > expectedLimit {
					if err == nil || !strings.Contains(err.Error(), "exceeds 65536 bytes at stat") {
						t.Fatalf("%d-byte key was not refused at stat: %v", size, err)
					}
					continue
				}
				if err != nil || key.Algorithm != test.algorithm || !bytes.Equal(key.DER, publicDER) {
					t.Fatalf("%d-byte %s key: algorithm %d, error %v", size, test.name, key.Algorithm, err)
				}
			}
		})
	}
}
