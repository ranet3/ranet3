// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/statefile"
	trustdoc "ranet3.com/pkgs/ranet3/trust"
)

func TestTrustReloadC1RetainsRecordAndServing(t *testing.T) {
	f := localTrustFixtureOf(t)
	first, err := LoadTrust(f.cfg, f.dir, nil, nil, nil)
	if err != nil || first.Prepared == nil {
		t.Fatalf("first load: %+v, %v", first, err)
	}
	path := filepath.Join(f.dir, trustStoreName)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	_, extra := localAuthority(t, 0x91)
	for _, test := range []struct {
		name    string
		list    []trustdoc.CompromisedKey
		revoked []config.RevokedKey
	}{
		{"overlap", nil, []config.RevokedKey{{Key: base64.StdEncoding.EncodeToString(f.oldKey.DER), Height: 1}}},
		{"cap", func() []trustdoc.CompromisedKey {
			list := make([]trustdoc.CompromisedKey, 64)
			for i := range list {
				_, key := localAuthority(t, byte(i))
				list[i] = trustdoc.CompromisedKey{Key: key}
			}
			return list
		}(), []config.RevokedKey{{Key: base64.StdEncoding.EncodeToString(extra.DER), Height: 1}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := *f.cfg
			cfg.Auth = f.cfg.Auth
			cfg.Auth.Revoked = test.revoked
			record := &TrustRecord{List: test.list, Marker: first.Record.Marker}
			result, err := LoadTrust(&cfg, f.dir, record, first.Prepared, nil)
			if err != nil || result.Row != trustdoc.C1 || result.Record != record || result.Held != first.Prepared || result.Refused == nil || result.Refused.Reason != "config error" || len(result.Record.List) != len(test.list) || len(result.Events) != 0 {
				t.Fatalf("C1 reload: %+v, %v", result, err)
			}
			if after, err := os.ReadFile(path); err != nil || !bytes.Equal(after, before) {
				t.Fatalf("C1 changed path: %x, %v", after, err)
			}
		})
	}
}

func TestTrustIndependentBaseChecksPrecedeRefusingRow(t *testing.T) {
	f := localTrustFixtureOf(t)
	f.writeStore(t, f.oldKey, f.first, f.firstProof, nil)
	payload := f.newProof.Payload
	payload.Mesh[0] ^= 1
	signed, err := trustdoc.SignPayload(payload, f.newPrivate)
	if err != nil {
		t.Fatal(err)
	}
	f.cfg.Auth.Authority = append(f.cfg.Auth.Authority, base64.StdEncoding.EncodeToString(f.newKey.DER))
	if err := os.WriteFile(f.cfg.Auth.Trust, signed, 0600); err != nil {
		t.Fatal(err)
	}
	first, err := LoadTrust(f.cfg, f.dir, nil, nil, nil)
	if err != nil || first.Row != trustdoc.D12 {
		t.Fatalf("expected another mesh: %+v, %v", first, err)
	}
	old := *f.cfg
	old.Link.Port++
	for _, test := range []struct {
		name string
		base func(*config.Config) error
		want string
	}{
		{"reloadability", func(cfg *config.Config) error { return reloadable(&old, cfg) }, "restart to apply"},
		{"tun plan", func(*config.Config) error { return errors.New("config: tun plan refused") }, "tun plan refused"},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			result, err := LoadTrust(f.cfg, f.dir, first.Record, first.Held, &TrustChecks{
				Base:    func(cfg *config.Config) error { calls++; return test.base(cfg) },
				Members: func(*trustdoc.Index) error { t.Fatal("8b ran for a refusing row"); return nil },
			})
			if err != nil || result.Row != trustdoc.D19 || calls != 1 || result.Refused == nil || result.Refused.Reason != "reload error" || !strings.Contains(result.Failure, test.want) {
				t.Fatalf("8a on refusing row: %+v, calls %d, %v", result, calls, err)
			}
		})
	}
}

func TestTrustRefusedRowsRecordEAndPreserveFloors(t *testing.T) {
	for _, row := range []trustdoc.Row{trustdoc.D16, trustdoc.D19} {
		t.Run(string(row), func(t *testing.T) {
			f := localTrustFixtureOf(t)
			f.cfg.Auth.Revoked = []config.RevokedKey{{Key: base64.StdEncoding.EncodeToString(f.newKey.DER), Height: 3}}
			if row == trustdoc.D16 {
				key := base64.StdEncoding.EncodeToString(f.oldKey.DER)
				payload := f.firstProof.Payload
				payload.Document.Nodes[0].Key = &key
				signed, err := trustdoc.SignPayload(payload, f.oldPrivate)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(f.cfg.Auth.Trust, signed, 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				f.cfg.Link.Endpoints[0].Serial = "other"
			}
			f.writeStore(t, f.oldKey, f.first, f.firstProof, nil)
			result, err := LoadTrust(f.cfg, f.dir, nil, nil, nil)
			if err != nil || result.Row != row || result.Record == nil || len(result.Record.List) != 1 || result.Record.List[0].Floor != 0 || result.Prepared != nil {
				t.Fatalf("refused E: %+v, %v", result, err)
			}
			image, _, err := readTrustStore(filepath.Join(f.dir, trustStoreName))
			if err != nil || len(image.Compromised) != 1 || image.Compromised[0].Floor != 0 {
				t.Fatalf("durable E: %+v, %v", image, err)
			}
		})
	}
}

func TestTrust9bConcurrentRefusalKeepsRowDiagnostic(t *testing.T) {
	f := localTrustFixtureOf(t)
	f.writeStore(t, f.oldKey, f.first, f.firstProof, nil)
	serving, err := LoadTrust(f.cfg, f.dir, nil, nil, nil)
	if err != nil || serving.Row != trustdoc.D3 {
		t.Fatalf("serving: %+v, %v", serving, err)
	}
	f.cfg.Link.Endpoints[0].Serial = "other"
	f.cfg.Auth.Revoked = []config.RevokedKey{{Key: base64.StdEncoding.EncodeToString(f.newKey.DER), Height: 2}}
	path := filepath.Join(f.dir, trustStoreName)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	result, err := loadTrust(f.cfg, f.dir, serving.Record, serving.Held, nil, trustPersistence{
		replace: func(string, []byte) error {
			return &statefile.ReplaceError{Stage: statefile.StageFileSync, Err: errors.New("synthetic file sync refusal")}
		},
		syncDir: statefile.SyncDirectory,
	})
	if err != nil || result.Row != trustdoc.D19 || result.FailureStage != statefile.StageFileSync || result.Refused == nil || result.Refused.Reason != "reload error" || !strings.Contains(result.Failure, "link.endpoints") || result.PersistenceFailure != "compromised keys not persisted: "+keyFingerprint(f.newKey.DER)+", file sync failed" || len(result.Events) != 1 || result.Events[0].Kind != "trust.persistence_failed" {
		t.Fatalf("row and persistence: %+v, %v", result, err)
	}
	if after, err := os.ReadFile(path); err != nil || !bytes.Equal(after, before) {
		t.Fatalf("path changed: %x, %v", after, err)
	}
}

func TestTrustFloorRetainedAcrossLoads(t *testing.T) {
	f := localTrustFixtureOf(t)
	f.cfg.Auth.Authority = []string{base64.StdEncoding.EncodeToString(f.newKey.DER)}
	f.cfg.Auth.Revoked = []config.RevokedKey{{Key: base64.StdEncoding.EncodeToString(f.oldKey.DER), Height: 2}}
	f.writeStore(t, f.oldKey, f.first, f.firstProof, nil)
	if err := os.WriteFile(f.cfg.Auth.Trust, f.replacement, 0600); err != nil {
		t.Fatal(err)
	}
	first, err := LoadTrust(f.cfg, f.dir, nil, nil, nil)
	if err != nil || first.Row != trustdoc.D9 || first.Record.List[0].Floor != 2 {
		t.Fatalf("recorded floor: %+v, %v", first, err)
	}
	f.cfg.Auth.Revoked = nil
	if err := os.WriteFile(f.cfg.Auth.Trust, f.first, 0600); err != nil {
		t.Fatal(err)
	}
	second, err := LoadTrust(f.cfg, f.dir, first.Record, first.Prepared, nil)
	if err != nil || second.Record.List[0].Floor != 2 || second.Prepared != nil || second.Row != trustdoc.D13 {
		t.Fatalf("retained floor: %+v, %v", second, err)
	}
	image, _, err := readTrustStore(filepath.Join(f.dir, trustStoreName))
	if err != nil || image.Compromised[0].Floor != 2 || image.Verified.Digest != f.newProof.Digest {
		t.Fatalf("stored floor: %+v, %v", image, err)
	}
}

func TestTrustConflictAndParentRefuseAtStartAndReload(t *testing.T) {
	for _, row := range []trustdoc.Row{trustdoc.D5, trustdoc.D6} {
		t.Run(string(row), func(t *testing.T) {
			f := localTrustFixtureOf(t)
			before := f.writeStore(t, f.oldKey, f.first, f.firstProof, nil)
			payload := f.firstProof.Payload
			if row == trustdoc.D5 {
				payload.Document.Nodes = slices.Clone(payload.Document.Nodes)
				payload.Document.Nodes[1].Name = "example/other"
			} else {
				payload.Height = 2
				wrong := f.newProof.Digest
				payload.Previous = &wrong
			}
			signed, err := trustdoc.SignPayload(payload, f.oldPrivate)
			if err != nil {
				t.Fatal(err)
			}
			serving, err := LoadTrust(f.cfg, f.dir, nil, nil, nil)
			if err != nil || serving.Row != trustdoc.D3 {
				t.Fatalf("serving: %+v, %v", serving, err)
			}
			if err := os.WriteFile(f.cfg.Auth.Trust, signed, 0600); err != nil {
				t.Fatal(err)
			}
			for _, start := range []bool{true, false} {
				var record *TrustRecord
				var held *TrustHeld
				if !start {
					record, held = serving.Record, serving.Held
				}
				result, err := LoadTrust(f.cfg, f.dir, record, held, nil)
				if err != nil || result.Row != row || result.Prepared != nil || result.Record == nil || result.Record.Marker == nil || result.Record.Marker.Image.Verified.Digest != f.firstProof.Digest {
					t.Fatalf("start %t: %+v, %v", start, result, err)
				}
				if !start && (result.Held != serving.Held || result.Refused == nil) || start && result.Status(f.cfg) != nil {
					t.Fatalf("refusal state at start %t: %+v", start, result)
				}
				if got, err := os.ReadFile(filepath.Join(f.dir, trustStoreName)); err != nil || !bytes.Equal(got, before) {
					t.Fatalf("refusal changed store at start %t: %x, %v", start, got, err)
				}
			}
		})
	}
}
