// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package config

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"

	"ranet3.com/pkgs/ranet3/identity"
)

func authorityText(t *testing.T, key any) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

func authorityCurveText(t *testing.T, curve elliptic.Curve) string {
	t.Helper()
	private, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return authorityText(t, private.Public())
}

func TestAuthorityConfigRefusals(t *testing.T) {
	accepted := []string{testAuthority, authorityCurveText(t, elliptic.P256()), authorityCurveText(t, elliptic.P384())}
	cfg := Config{
		Node: identity.MustParse("example/laptop"),
		Auth: Auth{Key: "key.pem", Trust: "trust.json", Authority: accepted},
		Link: Link{Port: 13000, Endpoints: []Endpoint{{Serial: "0", Family: "ip4"}}},
		Dial: Dial{All: true},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("three supported authority key types: %v", err)
	}
	for _, test := range []struct {
		name string
		keys []string
	}{
		{"malformed", []string{"not base64"}},
		{"missing padding", []string{strings.TrimSuffix(testAuthority, "=")}},
		{"duplicate", []string{testAuthority, testAuthority}},
		{"rsa", []string{authorityText(t, &rsa.PublicKey{N: big.NewInt(4295229443), E: 65537})}},
		{"p521", []string{authorityCurveText(t, elliptic.P521())}},
		{"small order", []string{authorityText(t, ed25519.PublicKey(make([]byte, ed25519.PublicKeySize)))}},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg.Auth.Authority = test.keys
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "auth.authority") {
				t.Fatalf("accepted authority keys %q: %v", test.keys, err)
			}
		})
	}
}

func TestAuthorityConfigWithoutKeysLoads(t *testing.T) {
	const nodeJSON = `{"node":"example/laptop","auth":{"key":"key.pem","trust":"trust.json"},` +
		`"link":{"port":13000,"endpoints":[{"serial":"0","family":"ip4"}]},"dial":{"all":true}}`
	for _, format := range []struct {
		extension string
		absent    string
		empty     string
	}{
		{".toml", nodeTOML, strings.Replace(nodeTOML, "trust = \"trust.json\"", "trust = \"trust.json\"\nauthority = []", 1)},
		{".yaml", nodeYAML, strings.Replace(nodeYAML, "  trust: trust.json", "  trust: trust.json\n  authority: []", 1)},
		{".json", nodeJSON, strings.Replace(nodeJSON, `"trust":"trust.json"`, `"trust":"trust.json","authority":[]`, 1)},
	} {
		if format.absent == format.empty {
			t.Fatalf("%s has no empty-list variant", format.extension)
		}
		for _, variant := range []struct {
			name string
			body string
		}{
			{"absent", format.absent},
			{"empty", format.empty},
		} {
			t.Run(format.extension+"/"+variant.name, func(t *testing.T) {
				cfg, err := load(t, format.extension, variant.body)
				if err != nil {
					t.Fatalf("configuration without authority keys: %v", err)
				}
				if len(cfg.Auth.Authority) != 0 {
					t.Fatalf("loaded authority keys: %q", cfg.Auth.Authority)
				}
				if cfg.Auth.Key != "key.pem" || cfg.Auth.Trust != "trust.json" {
					t.Fatalf("lost existing auth configuration: %+v", cfg.Auth)
				}
			})
		}
	}
}
