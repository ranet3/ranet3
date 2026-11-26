// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"slices"
	"testing"

	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/internal/statefile"
	trustdoc "ranet3.com/pkgs/ranet3/trust"
)

func TestTrustStartupFallbackChecksHeldWithSelectedMembership(t *testing.T) {
	for _, tc := range []struct {
		name    string
		acceptS bool
		fail11  bool
	}{
		{"accepted F, rejected S", false, false},
		{"failed write, rejected S", false, true},
		{"failed write, accepted S", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := localTrustFixtureOf(t)
			f.writeStore(t, f.oldKey, f.first, f.firstProof, nil)
			f.cfg.Auth.Authority = append(f.cfg.Auth.Authority, base64.StdEncoding.EncodeToString(f.newKey.DER))
			payload := f.newProof.Payload
			payload.Document.Nodes = slices.Clone(payload.Document.Nodes)
			payload.Document.Nodes[1].Endpoints = slices.Clone(payload.Document.Nodes[1].Endpoints)
			peer := "2"
			payload.Document.Nodes[1].Endpoints[0].ID = &peer
			signed, err := trustdoc.SignPayload(payload, f.newPrivate)
			if err != nil {
				t.Fatal(err)
			}
			verified, err := trustdoc.VerifySignedFile(signed, []trustdoc.AuthorityKey{f.newKey})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(f.cfg.Auth.Trust, signed, 0600); err != nil {
				t.Fatal(err)
			}
			calls := 0
			checks := &TrustChecks{Members: func(index *trustdoc.Index) error {
				calls++
				if tc.acceptS {
					return nil
				}
				_, err := index.Key(identity.MustParse("example/gateway:2"))
				return err
			}}
			persistence := trustPersistence{replace: statefile.ReplaceSynced, syncDir: statefile.SyncDirectory}
			if tc.fail11 {
				persistence.replace = func(string, []byte) error {
					return &statefile.ReplaceError{Stage: statefile.StageWrite, Err: errors.New("synthetic write failure")}
				}
			}
			result, err := loadTrust(f.cfg, f.dir, nil, nil, checks, persistence)
			if err != nil || result.Decision != trustdoc.D7 || result.Held == nil || result.Held.Verified.Digest != f.firstProof.Digest || result.Offered == nil || result.Offered.Verified.Digest != verified.Digest || result.CanFallback != tc.acceptS || calls != 2 {
				t.Fatalf("selected membership: %+v, calls %d, %v", result, calls, err)
			}
			if tc.fail11 {
				if result.Row != trustdoc.D15 || result.Prepared != nil || (result.Status(f.cfg) != nil) != tc.acceptS {
					t.Fatalf("failed snapshot persistence: %+v", result)
				}
			} else if result.Row != trustdoc.D7 || result.Prepared == nil || result.Prepared.Verified.Digest != verified.Digest || result.Refused != nil {
				t.Fatalf("offered snapshot rejected by held check: %+v", result)
			}
		})
	}
}

func TestTrustAcceptedReloadViewsUsePreparedUntilApplyFailure(t *testing.T) {
	f := localTrustFixtureOf(t)
	first, err := LoadTrust(f.cfg, f.dir, nil, nil, nil)
	if err != nil || first.Row != trustdoc.D2 || first.Prepared == nil {
		t.Fatalf("first snapshot: %+v, %v", first, err)
	}
	f.cfg.Auth.Authority = append(f.cfg.Auth.Authority, base64.StdEncoding.EncodeToString(f.newKey.DER))
	if err := os.WriteFile(f.cfg.Auth.Trust, f.replacement, 0600); err != nil {
		t.Fatal(err)
	}
	reload, err := LoadTrust(f.cfg, f.dir, first.Record, first.Prepared, nil)
	if err != nil || reload.Row != trustdoc.D7 || reload.Held != first.Prepared || reload.Prepared == nil || reload.Prepared.Verified.Digest != f.newProof.Digest {
		t.Fatalf("prepared reload: %+v, %v", reload, err)
	}
	status, debug := reload.Status(f.cfg), reload.Debug(f.cfg)
	if status == nil || status.Height == nil || *status.Height != 2 || status.Digest != hex.EncodeToString(f.newProof.Digest[:]) || status.Previous != hex.EncodeToString(f.firstProof.Digest[:]) || debug == nil || debug.Height == nil || *debug.Height != 2 || debug.Digest != status.Digest || debug.Key != keyFingerprint(f.newKey.DER) || debug.Document == nil || debug.Document.Nodes[0].Name != "example/local" {
		t.Fatalf("accepted reload views: %+v, %+v", status, debug)
	}
	reload.ApplyFailure("retable")
	status, debug = reload.Status(f.cfg), reload.Debug(f.cfg)
	if reload.Held != first.Prepared || reload.Prepared != nil || status == nil || status.Height == nil || *status.Height != 1 || status.Digest != hex.EncodeToString(f.firstProof.Digest[:]) || status.Previous != "" || debug == nil || debug.Height == nil || *debug.Height != 1 || debug.Digest != status.Digest || debug.Key != keyFingerprint(f.oldKey.DER) || debug.Refused == nil || debug.Refused.HeldHeight == nil || *debug.Refused.HeldHeight != 1 {
		t.Fatalf("prepublication views: %+v, %+v", status, debug)
	}
}
