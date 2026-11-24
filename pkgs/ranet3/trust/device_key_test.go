// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package trust

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestDevicePrivateKeyType(t *testing.T) {
	_, device, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		key  any
		want bool
	}{
		{"ed25519", device, true},
		{"p256", p256, false},
		{"p384", p384, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			der, err := x509.MarshalPKCS8PrivateKey(test.key)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "device.pem")
			if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
				t.Fatal(err)
			}
			loaded, err := LoadPrivateKey(path)
			if (err == nil) != test.want || (test.want && !loaded.Public().(ed25519.PublicKey).Equal(device.Public())) {
				t.Fatalf("device loader returned key %T, error %v, want accepted %v", loaded, err, test.want)
			}
		})
	}
}
