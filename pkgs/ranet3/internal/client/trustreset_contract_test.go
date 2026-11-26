// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/ike"
	"ranet3.com/pkgs/ranet3/internal/babel"
	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/schema"
	trustdoc "ranet3.com/pkgs/ranet3/trust"
)

func TestTrustResetClosedPrewriteRefusals(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*testing.T, *localTrustFixture, *string)
		want   string
	}{
		{"digest spelling", func(_ *testing.T, _ *localTrustFixture, digest *string) { *digest = strings.Repeat("A", 64) }, "digest must be 64 lowercase hex characters"},
		{"configuration absent", func(t *testing.T, f *localTrustFixture, _ *string) {
			if err := os.Remove(f.configPath); err != nil {
				t.Fatal(err)
			}
		}, "configuration cannot be loaded"},
		{"step 1", func(t *testing.T, f *localTrustFixture, _ *string) {
			if err := os.WriteFile(f.configPath, []byte("unexpected: true\n"), 0600); err != nil {
				t.Fatal(err)
			}
		}, ""},
		{"step 2", func(t *testing.T, f *localTrustFixture, _ *string) {
			f.cfg.Auth.Revoked = []config.RevokedKey{{Key: base64.StdEncoding.EncodeToString(f.newKey.DER), Height: 1}}
			writeConfig(t, f.configPath, f.cfg)
		}, "the configuration refuses the replacement: load step 2, config: auth.revoked[0] also lists an auth.authority key"},
		{"configured file absent", func(t *testing.T, f *localTrustFixture, _ *string) {
			if err := os.Remove(f.cfg.Auth.Trust); err != nil {
				t.Fatal(err)
			}
		}, "configured file absent"},
		{"file not verified", func(t *testing.T, f *localTrustFixture, _ *string) {
			if err := os.WriteFile(f.cfg.Auth.Trust, f.first, 0600); err != nil {
				t.Fatal(err)
			}
		}, "not verified"},
		{"digest mismatch", func(_ *testing.T, f *localTrustFixture, digest *string) {
			*digest = hex.EncodeToString(f.firstProof.Digest[:])
		}, ""},
		{"store absent", func(t *testing.T, f *localTrustFixture, _ *string) {
			if err := os.Remove(filepath.Join(f.dir, trustStoreName)); err != nil {
				t.Fatal(err)
			}
		}, "the store does not exist"},
		{"store unreadable", func(t *testing.T, f *localTrustFixture, _ *string) {
			if err := os.WriteFile(filepath.Join(f.dir, trustStoreName), []byte{0xa0}, 0600); err != nil {
				t.Fatal(err)
			}
		}, "the store is unreadable"},
		{"store without signer", func(t *testing.T, f *localTrustFixture, _ *string) {
			body, err := trustdoc.EncodeStore(trustdoc.StoreImage{Compromised: []trustdoc.CompromisedKey{{Key: f.oldKey}}})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(f.dir, trustStoreName), body, 0600); err != nil {
				t.Fatal(err)
			}
		}, "the store has no stored signer"},
		{"signer outside own L", func(t *testing.T, f *localTrustFixture, _ *string) {
			f.writeStore(t, f.oldKey, f.first, f.firstProof, nil)
		}, ""},
		{"step 3b", func(t *testing.T, f *localTrustFixture, _ *string) {
			list := []trustdoc.CompromisedKey{{Key: f.oldKey}}
			for i := range 63 {
				_, key := localAuthority(t, byte(i))
				list = append(list, trustdoc.CompromisedKey{Key: key})
			}
			slices.SortFunc(list, func(a, b trustdoc.CompromisedKey) int { return bytes.Compare(a.Key.DER, b.Key.DER) })
			f.writeStore(t, f.oldKey, f.first, f.firstProof, list)
			_, extra := localAuthority(t, 0x91)
			f.cfg.Auth.Revoked = []config.RevokedKey{{Key: base64.StdEncoding.EncodeToString(extra.DER), Height: 1}}
			writeConfig(t, f.configPath, f.cfg)
		}, "the configuration refuses the replacement: load step 3b, config: compromised key list has 65 entries, at most 64 allowed"},
		{"step 6", func(t *testing.T, f *localTrustFixture, digest *string) {
			key := base64.StdEncoding.EncodeToString(f.newKey.DER)
			payload := f.newProof.Payload
			payload.Document.Nodes[0].Key = &key
			signed, err := trustdoc.SignPayload(payload, f.newPrivate)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(f.cfg.Auth.Trust, signed, 0600); err != nil {
				t.Fatal(err)
			}
		}, "the configuration refuses the replacement: load step 6, trust: authority key also belongs to node \"example/local\""},
		{"step 8a", func(t *testing.T, f *localTrustFixture, _ *string) {
			exit := schema.MustPrefix("198.51.100.0/24")
			f.cfg.Cap.Route = &babel.Routes{Announce: []schema.Announce{{Prefix: exit}}}
			f.cfg.Cap.Egress = &egress.Egress{Advertise: []schema.Prefix{exit}}
			writeConfig(t, f.configPath, f.cfg)
		}, "the configuration refuses the replacement: load step 8a, config: cap.egress advertise 198.51.100.0/24 is announced by cap.route as well, which would advertise it whether or not its translation rule is installed"},
		{"step 8b", func(t *testing.T, f *localTrustFixture, _ *string) {
			f.cfg.Dial.To = []identity.Identity{identity.MustParse("example/gateway:missing")}
			writeConfig(t, f.configPath, f.cfg)
		}, "the configuration refuses the replacement: load step 8b, config: peer endpoint example/gateway:missing not found"},
		{"alias at step 8b", func(t *testing.T, f *localTrustFixture, _ *string) {
			f.cfg.Auth.Aliases = ike.Aliases{Remote: ike.RemoteAliases{FQDN: map[string]identity.Identity{"missing.example.net": identity.MustParse("example/unknown:1")}}}
			writeConfig(t, f.configPath, f.cfg)
		}, "the configuration refuses the replacement: load step 8b, config: auth.aliases.remote.fqdn \"missing.example.net\" names example/unknown:1, a node the trust document does not name"},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := localTrustFixtureOf(t)
			f.cfg.Auth.Authority = []string{base64.StdEncoding.EncodeToString(f.newKey.DER)}
			writeConfig(t, f.configPath, f.cfg)
			f.writeStore(t, f.oldKey, f.first, f.firstProof, []trustdoc.CompromisedKey{{Key: f.oldKey}})
			if err := os.WriteFile(f.cfg.Auth.Trust, f.replacement, 0600); err != nil {
				t.Fatal(err)
			}
			digest := hex.EncodeToString(f.newProof.Digest[:])
			test.change(t, &f, &digest)
			path := filepath.Join(f.dir, trustStoreName)
			before, err := os.ReadFile(path)
			present := err == nil
			reason := test.want
			switch test.name {
			case "step 1":
				reason = "the configuration refuses the replacement: load step 1, config: parse " + f.configPath + ": yaml: unmarshal errors:\n  line 1: field unexpected not found in type config.Config"
			case "digest mismatch":
				reason = f.cfg.Auth.Trust + " has digest " + hex.EncodeToString(f.newProof.Digest[:]) + ", not the one given"
			case "signer outside own L":
				reason = "the store's signer " + keyFingerprint(f.oldKey.DER) + " is not on its list of compromised keys"
			}
			message, err := ResetTrust(f.configPath, f.dir, digest)
			if want := "reset refused: config " + f.configPath + ", store " + path + ": " + reason; message != "" || err == nil || err.Error() != want {
				t.Fatalf("refusal %q: %q, %v, want %q", test.name, message, err, want)
			}
			after, readErr := os.ReadFile(path)
			if present && (readErr != nil || !bytes.Equal(after, before)) || !present && !os.IsNotExist(readErr) {
				t.Fatalf("refusal changed store: %x, %v", after, readErr)
			}
		})
	}
}
