// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"testing"

	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/ike"
	trustdoc "ranet3.com/pkgs/ranet3/trust"
)

func TestTrustReplacementUsesStartupMembershipRefusals(t *testing.T) {
	cfg, privateKey, registryDoc := runtimeFixture(t)
	der, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	key := base64.StdEncoding.EncodeToString(der)
	id := "0"
	peerID := "1"
	document := trustdoc.Document{Nodes: []trustdoc.Node{
		{Name: "example/local", Key: &key, Endpoints: []trustdoc.Endpoint{{ID: &id, Family: "ip4", Port: 13000}}},
		{Name: "example/gateway", Key: &key, Endpoints: []trustdoc.Endpoint{{ID: &peerID, Family: "ip4", Port: 13000}}},
	}}
	x, err := trustdoc.NewIndex(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateTrustReplacement(cfg, privateKey, x); err != nil {
		t.Fatal(err)
	}
	if err := validateRuntimeConfig(cfg, privateKey, trust(t, registryDoc)); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		change func()
		want   string
	}{
		{"peer endpoint", func() { cfg.Dial.To = []identity.Identity{identity.MustParse("example/gateway:missing")} }, "config: peer endpoint example/gateway:missing not found"},
		{"peer node", func() { cfg.Dial.To = []identity.Identity{identity.MustParse("example/unknown")} }, "config: peer node example/unknown not found"},
		{"alias", func() {
			cfg.Auth.Aliases = ike.Aliases{Remote: ike.RemoteAliases{FQDN: map[string]identity.Identity{"missing.example.net": identity.MustParse("example/unknown")}}}
		}, "a node the trust document does not name"},
	} {
		t.Run(test.name, func(t *testing.T) {
			named := *cfg
			named.Dial.To = append([]identity.Identity(nil), cfg.Dial.To...)
			named.Auth.Aliases = cfg.Auth.Aliases
			test.change()
			if err := ValidateTrustReplacement(cfg, privateKey, x); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Errorf("replacement check: %v, want %q", err, test.want)
			}
			*cfg = named
		})
	}
	wrong := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x71}, ed25519.SeedSize))
	if err := ValidateTrustReplacement(cfg, wrong, x); err == nil || !strings.Contains(err.Error(), "auth.key does not match") {
		t.Fatalf("local mismatch: %v", err)
	}
}

func TestTrustMembershipDistinguishesReloadWarnings(t *testing.T) {
	cfg, privateKey, registryDoc := runtimeFixture(t)
	cfg.Dial.To = []identity.Identity{identity.MustParse("example/missing"), identity.MustParse("example/gateway:missing"), identity.MustParse("example/gateway:1")}
	cfg.Auth.Aliases = ike.Aliases{Remote: ike.RemoteAliases{FQDN: map[string]identity.Identity{"missing.example.net": identity.MustParse("example/missing")}}}
	problems, err := checkMembership(cfg, privateKey, registryMembers{trust(t, registryDoc)})
	if err != nil {
		t.Fatal(err)
	}
	if len(problems.refuse) != 2 || len(problems.aliases) != 1 || len(problems.skip) != 1 {
		t.Fatalf("peer/alias categories: %+v", problems)
	}
	written := capturedLog(t)
	warnReloadMembership(problems)
	for _, want := range []string{
		"reload: config: peer node example/missing not found, each dialer toward it gives up at the next pass that finds it unsupported",
		"reload: config: peer endpoint example/gateway:missing not found, each dialer toward it gives up at the next pass that finds it unsupported",
		"reload: config: peer endpoint example/gateway:1 carries no address, each dialer toward it gives up at the next pass that finds it unsupported",
		"reload: config: auth.aliases.remote.fqdn \"missing.example.net\" names example/missing, a node the trust document does not name, so no handshake can use it",
	} {
		if got := written.count(want); got != 1 {
			t.Errorf("reload warned %d times for %q", got, want)
		}
	}
	wrong := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x72}, ed25519.SeedSize))
	if _, err := checkMembership(cfg, wrong, registryMembers{trust(t, registryDoc)}); err == nil {
		t.Error("a reload accepted a mismatched local key")
	}
}
