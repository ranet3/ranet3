// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/statefile"
	trustdoc "ranet3.com/pkgs/ranet3/trust"
)

func TestTrust9bFailureKeepsPriorBytesAndRetriesDirectoryOnly(t *testing.T) {
	f := localTrustFixtureOf(t)
	f.cfg.Auth.Revoked = []config.RevokedKey{{Key: base64.StdEncoding.EncodeToString(f.newKey.DER), Height: 3}}
	original := f.writeStore(t, f.oldKey, f.first, f.firstProof, nil)
	path := filepath.Join(f.dir, trustStoreName)
	failure := errors.New("isolated directory sync failure")
	calls := 0
	persistence := trustPersistence{
		replace: func(path string, raw []byte) error {
			calls++
			if err := os.WriteFile(path, raw, 0600); err != nil {
				return err
			}
			return &statefile.ReplaceError{Stage: statefile.StageDirectorySync, Renamed: true, Err: failure}
		},
		syncDir: statefile.SyncDirectory,
	}
	result, err := loadTrust(f.cfg, f.dir, nil, nil, nil, persistence)
	if err != nil || result.Row != trustdoc.D15 || result.Decision != trustdoc.D3 || result.Refused != nil || result.ClearRefusal || result.FailureStage != statefile.StageDirectorySync || calls != 1 || result.Record.Marker.Synced || len(result.NotPersisted) != 1 {
		t.Fatalf("9b failure: row %s stage %s calls %d marker %+v owed %+v error %v", result.Row, result.FailureStage, calls, result.Record.Marker, result.NotPersisted, err)
	}
	got, err := os.ReadFile(path)
	if err != nil || bytes.Equal(got, original) {
		t.Fatalf("renamed image not visible: %x, %v", got, err)
	}
	image, err := trustdoc.DecodeStore(got)
	if err != nil || len(image.Compromised) != 1 || image.Compromised[0].Floor != 0 {
		t.Fatalf("renamed image: %+v, %v", image, err)
	}
	resyncs := 0
	retry, err := loadTrust(f.cfg, f.dir, result.Record, result.Held, nil, trustPersistence{
		replace: func(string, []byte) error { t.Error("directory-only retry rewrote the image"); return nil },
		syncDir: func(path string) error { resyncs++; return statefile.SyncDirectory(path) },
	})
	if err != nil || resyncs != 1 || retry.Record.Marker == nil || !retry.Record.Marker.Synced || len(retry.NotPersisted) != 0 {
		t.Fatalf("directory-only retry: %+v, syncs %d, %v", retry, resyncs, err)
	}
	if after, err := os.ReadFile(path); err != nil || !bytes.Equal(after, got) {
		t.Fatalf("retry changed the path bytes: %x, %v", after, err)
	}
}

func TestTrust11FailureKeepsFirstSnapshotUnserved(t *testing.T) {
	f := localTrustFixtureOf(t)
	failure := errors.New("isolated file sync failure")
	result, err := loadTrust(f.cfg, f.dir, nil, nil, nil, trustPersistence{
		replace: func(string, []byte) error {
			return &statefile.ReplaceError{Stage: statefile.StageFileSync, Err: failure}
		},
		syncDir: statefile.SyncDirectory,
	})
	if err != nil || result.Row != trustdoc.D15 || result.Held != nil || result.Status(f.cfg) != nil || result.FailureStage != statefile.StageFileSync {
		t.Fatalf("unserved first snapshot: %+v, %v", result, err)
	}
	if _, err := os.Stat(filepath.Join(f.dir, trustStoreName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("step 11 changed the absent store: %v", err)
	}
}

func TestTrustResetStageDiagnosticsAndPathBytes(t *testing.T) {
	failure := errors.New("isolated failure")
	for _, test := range []struct {
		stage   statefile.Stage
		label   string
		reason  string
		renamed bool
	}{
		{statefile.StageWrite, "while writing", "store unchanged", false},
		{statefile.StageFileSync, "at the file sync", "store unchanged", false},
		{statefile.StageRename, "at the rename", "store unchanged", false},
		{statefile.StageDirectorySync, "at the directory sync", "replacement not durable", true},
	} {
		t.Run(string(test.stage), func(t *testing.T) {
			f := localTrustFixtureOf(t)
			f.cfg.Auth.Authority = []string{base64.StdEncoding.EncodeToString(f.newKey.DER)}
			writeConfig(t, f.configPath, f.cfg)
			f.writeStore(t, f.oldKey, f.first, f.firstProof, []trustdoc.CompromisedKey{{Key: f.oldKey}})
			if err := os.WriteFile(f.cfg.Auth.Trust, f.replacement, 0600); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(f.dir, trustStoreName)
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			_, err = resetTrust(f.configPath, f.dir, hex.EncodeToString(f.newProof.Digest[:]), func(path string, raw []byte) error {
				calls++
				if test.renamed {
					if err := os.WriteFile(path, raw, 0600); err != nil {
						return err
					}
				}
				return &statefile.ReplaceError{Stage: test.stage, Renamed: test.renamed, Err: failure}
			})
			if calls != 1 || err == nil || !strings.Contains(err.Error(), "reset failed "+test.label+": config "+f.configPath+", store "+path+": "+test.reason) {
				t.Fatalf("stage error %v, calls %d", err, calls)
			}
			after, err := os.ReadFile(path)
			if err != nil || bytes.Equal(after, before) == test.renamed {
				t.Fatalf("path bytes for %s: %x, %v", test.stage, after, err)
			}
		})
	}
}
