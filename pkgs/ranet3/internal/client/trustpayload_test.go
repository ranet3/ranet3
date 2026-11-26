// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/statefile"
	trustdoc "ranet3.com/pkgs/ranet3/trust"
)

func TestTrustRecoveryPayloadUsesHeldAndOfferedHeights(t *testing.T) {
	f := localTrustFixtureOf(t)
	previous := f.firstProof.Digest
	olderPayload := f.firstProof.Payload
	olderPayload.Height, olderPayload.Previous = 3, &previous
	oldSigned, err := trustdoc.SignPayload(olderPayload, f.oldPrivate)
	if err != nil {
		t.Fatal(err)
	}
	oldVerified, err := trustdoc.VerifySignedFile(oldSigned, []trustdoc.AuthorityKey{f.oldKey})
	if err != nil {
		t.Fatal(err)
	}
	f.writeStore(t, f.oldKey, oldSigned, oldVerified, []trustdoc.CompromisedKey{{Key: f.oldKey, Floor: 2}})
	f.cfg.Auth.Authority = []string{base64.StdEncoding.EncodeToString(f.newKey.DER)}
	f.cfg.Auth.Revoked = []config.RevokedKey{{Key: base64.StdEncoding.EncodeToString(f.oldKey.DER), Height: 2}}
	if err := os.WriteFile(f.cfg.Auth.Trust, f.replacement, 0600); err != nil {
		t.Fatal(err)
	}
	result, err := LoadTrust(f.cfg, f.dir, nil, nil, nil)
	if err != nil || result.Row != trustdoc.D9 || result.Prepared == nil || result.Prepared.Verified.Payload.Height != 2 || len(result.Events) != 1 {
		t.Fatalf("recovery result: %+v, %v", result, err)
	}
	event := result.Events[0]
	if event.Kind != "trust.accepted" || len(event.Attrs) != 6 || event.Attrs["path"] != f.cfg.Auth.Trust || event.Attrs["reason"] != "recovery" || event.Attrs["held_height"] != "3" || event.Attrs["offered_height"] != "2" || event.Attrs["held_digest"] != hex.EncodeToString(oldVerified.Digest[:]) || event.Attrs["offered_digest"] != hex.EncodeToString(f.newProof.Digest[:]) {
		t.Fatalf("recovery attributes: %+v", event)
	}
}

func TestTrustPersistenceEventKeysAreCompactJSONArrayString(t *testing.T) {
	f := localTrustFixtureOf(t)
	f.cfg.Auth.Revoked = []config.RevokedKey{{Key: base64.StdEncoding.EncodeToString(f.newKey.DER), Height: 3}}
	f.writeStore(t, f.oldKey, f.first, f.firstProof, nil)
	failure := &statefile.ReplaceError{Stage: statefile.StageRename, Err: os.ErrPermission}
	result, err := loadTrust(f.cfg, f.dir, nil, nil, nil, trustPersistence{
		replace: func(string, []byte) error { return failure },
		syncDir: statefile.SyncDirectory,
	})
	if err != nil || result.Row != trustdoc.D15 || len(result.Events) != 1 || result.Events[0].Kind != "trust.persistence_failed" {
		t.Fatalf("persistence result: %+v, %v", result, err)
	}
	keys, _ := json.Marshal([]string{base64.StdEncoding.EncodeToString(f.newKey.DER)})
	want := map[string]string{"path": filepath.Join(f.dir, trustStoreName), "stage": "rename", "keys": string(keys)}
	got := result.Events[0].Attrs
	if len(got) != len(want) || got["path"] != want["path"] || got["stage"] != want["stage"] || got["keys"] != want["keys"] {
		t.Fatalf("persistence attributes %+v, want %+v", got, want)
	}
	status := result.Status(f.cfg)
	if status == nil || status.NotPersisted == nil || status.NotPersisted.Stage != statefile.StageRename || len(status.NotPersisted.Keys) != 1 {
		t.Fatalf("status persistence fields: %+v", status)
	}
	debug, err := json.Marshal(result.Debug(f.cfg))
	if err != nil || bytes.Contains(debug, []byte(`"not_persisted"`)) || bytes.Contains(debug, []byte(`"compromised"`)) {
		t.Fatalf("debug JSON added status-only members: %s, %v", debug, err)
	}
}

func TestTrustResetStep2RefusalPreservesStore(t *testing.T) {
	f := localTrustFixtureOf(t)
	before := f.writeStore(t, f.oldKey, f.first, f.firstProof, []trustdoc.CompromisedKey{{Key: f.oldKey}})
	f.cfg.Auth.Revoked = []config.RevokedKey{{Key: base64.StdEncoding.EncodeToString(f.oldKey.DER), Height: 1}}
	writeConfig(t, f.configPath, f.cfg)
	message, err := ResetTrust(f.configPath, f.dir, hex.EncodeToString(f.firstProof.Digest[:]))
	if message != "" || err == nil || !strings.Contains(err.Error(), "load step 2, config: auth.revoked[0] also lists an auth.authority key") {
		t.Fatalf("config-only refusal: %q, %v", message, err)
	}
	got, err := os.ReadFile(filepath.Join(f.dir, trustStoreName))
	if err != nil || !bytes.Equal(got, before) {
		t.Fatalf("step 2 changed store: %x, %v", got, err)
	}
}
