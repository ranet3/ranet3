// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package config

import (
	"crypto/ed25519"
	"crypto/elliptic"
	"fmt"
	"strings"
	"testing"

	"ranet3.com/pkgs/ranet3/trust"
)

func TestRevokedConfiguration(t *testing.T) {
	for _, format := range []struct {
		extension string
		body      string
	}{
		{".toml", strings.Replace(nodeTOML, "trust = \"trust.json\"", "trust = \"trust.json\"\nrevoked = [{ key = \""+testAuthority+"\", height = 1 }]", 1)},
		{".yaml", strings.Replace(nodeYAML, "  trust: trust.json", "  trust: trust.json\n  revoked: [{ key: \""+testAuthority+"\", height: 1 }]", 1)},
		{".json", fmt.Sprintf(`{"node":"example/laptop","auth":{"key":"key.pem","trust":"trust.json","revoked":[{"key":%q,"height":1}]},"link":{"port":13000,"endpoints":[{"serial":"0","family":"ip4"}]},"dial":{"all":true}}`, testAuthority)},
	} {
		cfg, err := load(t, format.extension, format.body)
		if err != nil || len(cfg.Auth.Revoked) != 1 || cfg.Auth.Revoked[0].Height != 1 {
			t.Fatalf("load revoked in %s: %+v, %v", format.extension, cfg, err)
		}
	}
	for _, entries := range [][]RevokedKey{nil, {}} {
		if err := (Auth{Revoked: entries}).validateTrustKeys(); err != nil {
			t.Fatalf("empty revoked list: %v", err)
		}
	}
	p256 := authorityCurveText(t, elliptic.P256())
	for _, test := range []struct {
		name string
		auth Auth
	}{
		{"intersection", Auth{Authority: []string{testAuthority}, Revoked: []RevokedKey{{Key: testAuthority, Height: 1}}}},
		{"duplicate", Auth{Revoked: []RevokedKey{{Key: testAuthority, Height: 1}, {Key: testAuthority, Height: 2}}}},
		{"zero height", Auth{Revoked: []RevokedKey{{Key: testAuthority}}}},
		{"height overflow", Auth{Revoked: []RevokedKey{{Key: testAuthority, Height: trust.MaxHeight + 1}}}},
		{"malformed", Auth{Revoked: []RevokedKey{{Key: "not base64", Height: 1}}}},
		{"listed curve", Auth{Authority: []string{p256}, Revoked: []RevokedKey{{Key: p256, Height: 1}}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := test.auth.validateTrustKeys(); err == nil || !strings.Contains(err.Error(), "auth.revoked") {
				t.Fatalf("accepted invalid revoked list: %v", err)
			}
		})
	}
	var keys []RevokedKey
	for i := range 65 {
		seed := make([]byte, ed25519.SeedSize)
		seed[0] = byte(i)
		key := ed25519.NewKeyFromSeed(seed)
		keys = append(keys, RevokedKey{Key: authorityText(t, key.Public()), Height: 1})
	}
	if err := (Auth{Revoked: keys[:64]}).validateTrustKeys(); err != nil {
		t.Fatalf("64 distinct keys: %v", err)
	}
	if err := (Auth{Revoked: keys}).validateTrustKeys(); err == nil {
		t.Fatal("accepted 65 distinct keys")
	}
}

func TestRevokedConfigurationWithoutEntries(t *testing.T) {
	for _, format := range []struct {
		extension string
		bodies    []string
	}{
		{".toml", []string{nodeTOML, strings.Replace(nodeTOML, "trust = \"trust.json\"", "trust = \"trust.json\"\nrevoked = []", 1)}},
		{".yaml", []string{nodeYAML, strings.Replace(nodeYAML, "  trust: trust.json", "  trust: trust.json\n  revoked: []", 1), strings.Replace(nodeYAML, "  trust: trust.json", "  trust: trust.json\n  revoked: null", 1)}},
		{".json", []string{
			`{"node":"example/laptop","auth":{"key":"key.pem","trust":"trust.json"},"link":{"port":13000,"endpoints":[{"serial":"0","family":"ip4"}]},"dial":{"all":true}}`,
			`{"node":"example/laptop","auth":{"key":"key.pem","trust":"trust.json","revoked":[]},"link":{"port":13000,"endpoints":[{"serial":"0","family":"ip4"}]},"dial":{"all":true}}`,
			`{"node":"example/laptop","auth":{"key":"key.pem","trust":"trust.json","revoked":null},"link":{"port":13000,"endpoints":[{"serial":"0","family":"ip4"}]},"dial":{"all":true}}`,
		}},
	} {
		for _, body := range format.bodies {
			cfg, err := load(t, format.extension, body)
			if err != nil || len(cfg.Auth.Revoked) != 0 {
				t.Fatalf("%s revoked without entries: %+v, %v", format.extension, cfg, err)
			}
		}
	}
}
