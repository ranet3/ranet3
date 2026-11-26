// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/config"
	trustdoc "ranet3.com/pkgs/ranet3/trust"
)

func TestTrustLoadedRefusalRowsHaveVerifiedClosedAttributes(t *testing.T) {
	for _, tc := range []struct {
		name         string
		storedHeight uint64
		offerHeight  uint64
		change       string
		retire       bool
		row          trustdoc.Row
		reason       string
	}{
		{"older", 2, 1, "", false, trustdoc.D4, "older"},
		{"retired older", 2, 1, "", true, trustdoc.D22, "older"},
		{"conflict", 1, 1, "document", false, trustdoc.D5, "conflict"},
		{"retired conflict", 2, 2, "document", true, trustdoc.D23, "conflict"},
		{"parent", 1, 2, "parent", false, trustdoc.D6, "parent"},
		{"retired parent", 1, 2, "parent", true, trustdoc.D23, "parent"},
		{"other mesh", 1, 2, "mesh", false, trustdoc.D12, "file of another mesh"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := localTrustFixtureOf(t)
			stored := f.firstProof.Payload
			if tc.storedHeight == 2 {
				stored = f.newProof.Payload
			}
			storedBytes, err := trustdoc.SignPayload(stored, f.oldPrivate)
			if err != nil {
				t.Fatal(err)
			}
			storedProof, err := trustdoc.VerifySignedFile(storedBytes, []trustdoc.AuthorityKey{f.oldKey})
			if err != nil {
				t.Fatal(err)
			}
			before := f.writeStore(t, f.oldKey, storedBytes, storedProof, nil)
			if err := os.WriteFile(f.cfg.Auth.Trust, storedBytes, 0600); err != nil {
				t.Fatal(err)
			}
			first, err := LoadTrust(f.cfg, f.dir, nil, nil, nil)
			if err != nil || first.Row != trustdoc.D3 {
				t.Fatalf("stored fixture: %+v, %v", first, err)
			}
			offered := f.firstProof.Payload
			if tc.offerHeight == 2 {
				offered = f.newProof.Payload
			}
			switch tc.change {
			case "document":
				offered.Document.Nodes = slices.Clone(offered.Document.Nodes)
				offered.Document.Nodes[1].Name = "example/other"
			case "parent":
				wrong := [32]byte{0x55}
				offered.Previous = &wrong
			case "mesh":
				offered.Mesh[0] ^= 1
			}
			signed, err := trustdoc.SignPayload(offered, f.newPrivate)
			if err != nil {
				t.Fatal(err)
			}
			proof, err := trustdoc.VerifySignedFile(signed, []trustdoc.AuthorityKey{f.newKey})
			if err != nil {
				t.Fatal(err)
			}
			if tc.retire {
				f.cfg.Auth.Authority = []string{base64.StdEncoding.EncodeToString(f.newKey.DER)}
			} else {
				f.cfg.Auth.Authority = append(f.cfg.Auth.Authority, base64.StdEncoding.EncodeToString(f.newKey.DER))
			}
			if err := os.WriteFile(f.cfg.Auth.Trust, signed, 0600); err != nil {
				t.Fatal(err)
			}
			result, err := LoadTrust(f.cfg, f.dir, first.Record, first.Held, nil)
			if err != nil || result.Row != tc.row || result.Offered == nil || result.Offered.Verified.Digest != proof.Digest || result.Held != first.Held || result.Prepared != nil || len(result.Events) != 1 || result.Events[0].Kind != "trust.refused" {
				t.Fatalf("loaded row: %+v, %v", result, err)
			}
			attrs := map[string]string{
				"path": f.cfg.Auth.Trust, "reason": tc.reason,
				"held_height": fmt.Sprint(tc.storedHeight), "held_digest": hex.EncodeToString(storedProof.Digest[:]),
				"offered_height": fmt.Sprint(tc.offerHeight), "offered_digest": hex.EncodeToString(proof.Digest[:]),
			}
			if tc.retire {
				attrs["stored_signer_status"] = "signer not listed"
			}
			if !equalTrustAttrs(result.Events[0].Attrs, attrs) || result.Refused == nil || result.Refused.Reason != tc.reason {
				t.Fatalf("closed row attributes: %+v, want %+v", result.Events, attrs)
			}
			if after, err := os.ReadFile(filepath.Join(f.dir, trustStoreName)); err != nil || !bytes.Equal(after, before) {
				t.Fatalf("refused reload changed store: %x, %v", after, err)
			}
		})
	}
}

func TestTrustLoadedD24QualifiersFromVerifiedSnapshots(t *testing.T) {
	for _, tc := range []struct {
		name   string
		height uint64
		field  string
		value  string
	}{
		{"floor not yet recorded", 3, "floor_status", "floor not yet recorded"},
		{"stored height above entry", 1, "stored_height_status", "stored height above the entry's"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := localTrustFixtureOf(t)
			storedBytes, err := trustdoc.SignPayload(f.newProof.Payload, f.oldPrivate)
			if err != nil {
				t.Fatal(err)
			}
			storedProof, err := trustdoc.VerifySignedFile(storedBytes, []trustdoc.AuthorityKey{f.oldKey})
			if err != nil {
				t.Fatal(err)
			}
			f.writeStore(t, f.oldKey, storedBytes, storedProof, nil)
			if err := os.WriteFile(f.cfg.Auth.Trust, storedBytes, 0600); err != nil {
				t.Fatal(err)
			}
			first, err := LoadTrust(f.cfg, f.dir, nil, nil, nil)
			if err != nil || first.Row != trustdoc.D3 {
				t.Fatalf("stored fixture: %+v, %v", first, err)
			}
			f.cfg.Auth.Authority = []string{base64.StdEncoding.EncodeToString(f.newKey.DER)}
			f.cfg.Auth.Revoked = []config.RevokedKey{{Key: base64.StdEncoding.EncodeToString(f.oldKey.DER), Height: tc.height}}
			offered := f.newProof.Payload
			offered.Mesh[0] ^= 1
			signed, err := trustdoc.SignPayload(offered, f.newPrivate)
			if err != nil {
				t.Fatal(err)
			}
			proof, err := trustdoc.VerifySignedFile(signed, []trustdoc.AuthorityKey{f.newKey})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(f.cfg.Auth.Trust, signed, 0600); err != nil {
				t.Fatal(err)
			}
			result, err := LoadTrust(f.cfg, f.dir, first.Record, first.Held, nil)
			if err != nil || result.Row != trustdoc.D24 || result.Offered == nil || result.Offered.Verified.Digest != proof.Digest || result.ResetReady != keyFingerprint(f.oldKey.DER) || len(result.Events) != 1 || result.Events[0].Kind != "trust.refused" {
				t.Fatalf("loaded D24: %+v, %v", result, err)
			}
			attrs := map[string]string{
				"path": f.cfg.Auth.Trust, "reason": "stored signer compromised", "held_height": "2", "held_digest": hex.EncodeToString(storedProof.Digest[:]),
				"offered_height": "2", "offered_digest": hex.EncodeToString(proof.Digest[:]), "stored_signer": keyFingerprint(f.oldKey.DER),
				"reset_ready": keyFingerprint(f.oldKey.DER), "file_mesh_status": "file of another mesh", tc.field: tc.value,
			}
			status := result.Status(f.cfg)
			if !equalTrustAttrs(result.Events[0].Attrs, attrs) || status == nil || status.Reset == nil || status.Reset.Ready != keyFingerprint(f.oldKey.DER) || status.Reset.Waits != "" || status.Refused == nil || status.Refused.Reason != "stored signer compromised" {
				t.Fatalf("D24 fields: %+v, status %+v, want %+v", result.Events, status, attrs)
			}
		})
	}
}
