// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/statefile"
	trustdoc "ranet3.com/pkgs/ranet3/trust"
)

// These synthetic outcomes exercise loader bookkeeping. The statefile tests
// inject failures into the actual staged writer separately.
func TestTrustLoaderPersistenceMatrix(t *testing.T) {
	for _, point := range []string{"9b", "11"} {
		for _, stage := range []statefile.Stage{statefile.StageWrite, statefile.StageFileSync, statefile.StageRename, statefile.StageDirectorySync} {
			t.Run(point+"/"+string(stage), func(t *testing.T) {
				f := localTrustFixtureOf(t)
				path := filepath.Join(f.dir, trustStoreName)
				before := f.writeStore(t, f.oldKey, f.first, f.firstProof, nil)
				var record *TrustRecord
				var serving *TrustHeld
				if point == "9b" {
					f.cfg.Auth.Revoked = []config.RevokedKey{{Key: base64.StdEncoding.EncodeToString(f.newKey.DER), Height: 3}}
				} else {
					first, err := LoadTrust(f.cfg, f.dir, nil, nil, nil)
					if err != nil || first.Row != trustdoc.D3 {
						t.Fatalf("serving: %+v, %v", first, err)
					}
					record, serving = first.Record, first.Held
					f.cfg.Auth.Authority = append(f.cfg.Auth.Authority, base64.StdEncoding.EncodeToString(f.newKey.DER))
					if err := os.WriteFile(f.cfg.Auth.Trust, f.replacement, 0600); err != nil {
						t.Fatal(err)
					}
				}
				calls := 0
				result, err := loadTrust(f.cfg, f.dir, record, serving, nil, trustPersistence{
					replace: func(_ string, image []byte) error {
						calls++
						if stage == statefile.StageDirectorySync {
							// A renamed image is modeled by its bytes, not a successful ReplaceSynced call.
							if err := os.WriteFile(path, image, 0600); err != nil {
								return err
							}
						}
						return &statefile.ReplaceError{Stage: stage, Renamed: stage == statefile.StageDirectorySync, Err: errors.New("synthetic stage failure")}
					},
					syncDir: statefile.SyncDirectory,
				})
				if err != nil || result.Row != trustdoc.D15 || result.FailureStage != stage || calls != 1 || result.Prepared != nil || result.Record.Marker == nil && point == "9b" {
					t.Fatalf("loader outcome: %+v, calls %d, %v", result, calls, err)
				}
				if point == "9b" && result.Decision != trustdoc.D3 || point == "11" && result.Decision != trustdoc.D7 {
					t.Fatalf("wrong decision %s", result.Decision)
				}
				got, err := os.ReadFile(path)
				if err != nil || bytes.Equal(got, before) == (stage == statefile.StageDirectorySync) {
					t.Fatalf("path stage %s: %x, %v", stage, got, err)
				}
				if stage == statefile.StageDirectorySync {
					image, err := trustdoc.DecodeStore(got)
					if err != nil || image.Verified == nil {
						t.Fatalf("renamed image: %+v, %v", image, err)
					}
					if result.Record.Marker.Synced {
						t.Fatal("synthetic renamed image marked durable")
					}
				}
				if point == "9b" && len(result.NotPersisted) != 1 || point == "11" && len(result.NotPersisted) != 0 {
					t.Fatalf("owed keys: %+v", result.NotPersisted)
				}
				keys := []string{}
				if point == "9b" {
					keys = append(keys, base64.StdEncoding.EncodeToString(f.newKey.DER))
				}
				encoded, _ := json.Marshal(keys)
				want := map[string]string{"path": path, "stage": string(stage), "keys": string(encoded)}
				if len(result.Events) != 1 || result.Events[0].Kind != "trust.persistence_failed" || !equalTrustAttrs(result.Events[0].Attrs, want) {
					t.Fatalf("closed persistence event %+v, want %+v", result.Events, want)
				}
			})
		}
	}
}

func equalTrustAttrs(got, want map[string]string) bool {
	if len(got) != len(want) {
		return false
	}
	for key, value := range want {
		if got[key] != value {
			return false
		}
	}
	return true
}
