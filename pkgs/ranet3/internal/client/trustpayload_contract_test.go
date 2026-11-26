// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"testing"

	trustdoc "ranet3.com/pkgs/ranet3/trust"
)

func TestTrustClosedRowAttributes(t *testing.T) {
	f := localTrustFixtureOf(t)
	held := &TrustHeld{Verified: f.firstProof}
	offered := &TrustHeld{Verified: f.newProof}
	oldHeight := "1"
	newHeight := "2"
	oldDigest := hex.EncodeToString(f.firstProof.Digest[:])
	newDigest := hex.EncodeToString(f.newProof.Digest[:])
	path := f.cfg.Auth.Trust
	four := map[string]string{"path": path, "held_height": oldHeight, "held_digest": oldDigest, "offered_height": newHeight, "offered_digest": newDigest}
	conflict := &TrustHeld{Verified: f.firstProof}
	conflict.Verified.Digest[0] ^= 1
	conflictAttrs := map[string]string{"path": path, "held_height": oldHeight, "held_digest": oldDigest, "offered_height": oldHeight, "offered_digest": hex.EncodeToString(conflict.Verified.Digest[:])}
	other := &TrustHeld{Verified: f.newProof}
	other.Verified.Payload.Mesh[0] ^= 1
	for _, test := range []struct {
		name   string
		row    trustdoc.Row
		file   *TrustHeld
		absent bool
		want   map[string]string
	}{
		{"older", trustdoc.D4, offered, false, addTrustAttrs(four, "reason", "older")},
		{"conflict", trustdoc.D5, conflict, false, addTrustAttrs(conflictAttrs, "reason", "conflict")},
		{"parent", trustdoc.D6, offered, false, addTrustAttrs(four, "reason", "parent")},
		{"another mesh", trustdoc.D12, other, false, addTrustAttrs(four, "reason", "file of another mesh")},
		{"retired older", trustdoc.D22, offered, false, addTrustAttrs(addTrustAttrs(four, "reason", "older"), "stored_signer_status", "signer not listed")},
		{"retired parent", trustdoc.D23, offered, false, addTrustAttrs(addTrustAttrs(four, "reason", "parent"), "stored_signer_status", "signer not listed")},
		{"not listed absent", trustdoc.D11, nil, true, map[string]string{"path": path, "reason": "configured file absent", "held_height": oldHeight, "held_digest": oldDigest, "stored_signer_status": "signer not listed"}},
		{"listed unverified", trustdoc.D13, nil, false, map[string]string{"path": path, "reason": "not verified", "held_height": oldHeight, "held_digest": oldDigest}},
		{"ordinary accepted", trustdoc.D7, offered, false, map[string]string{"path": path, "height": newHeight, "digest": newDigest, "previous": oldDigest}},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := TrustResult{Row: test.row, Held: held, Offered: test.file}
			result.finishTrust(path, filepath.Join(f.dir, trustStoreName), test.absent, 0, 0, held)
			if len(result.Events) != 1 || !equalTrustAttrs(result.Events[0].Attrs, test.want) {
				t.Fatalf("row %s attributes %+v, want %+v", test.row, result.Events, test.want)
			}
			kind := "trust.refused"
			if test.row == trustdoc.D7 {
				kind = "trust.accepted"
			}
			if result.Events[0].Kind != kind {
				t.Fatalf("event kind %+v", result.Events[0])
			}
		})
	}
	first := TrustResult{Row: trustdoc.D2, Offered: held}
	first.finishTrust(path, filepath.Join(f.dir, trustStoreName), false, 0, 0, nil)
	if len(first.Events) != 1 || !equalTrustAttrs(first.Events[0].Attrs, map[string]string{"path": path, "height": "1", "digest": oldDigest}) {
		t.Fatalf("first acceptance: %+v", first.Events)
	}
}

func addTrustAttrs(base map[string]string, key, value string) map[string]string {
	copy := make(map[string]string, len(base)+1)
	for k, v := range base {
		copy[k] = v
	}
	copy[key] = value
	return copy
}

func TestTrustD24ClosedQualifiersAndReadiness(t *testing.T) {
	f := localTrustFixtureOf(t)
	held := &TrustHeld{Verified: f.firstProof}
	offered := &TrustHeld{Verified: f.newProof}
	offered.Verified.Payload.Mesh[0] ^= 1
	result := TrustResult{Row: trustdoc.D24, Held: held, Offered: offered,
		Record: &TrustRecord{Marker: &TrustMarker{Image: markerImage(held, nil), Synced: true}}}
	result.finishTrust(f.cfg.Auth.Trust, filepath.Join(f.dir, trustStoreName), false, 0, 1, held)
	want := map[string]string{
		"path": f.cfg.Auth.Trust, "reason": "stored signer compromised",
		"held_height": "1", "held_digest": hex.EncodeToString(f.firstProof.Digest[:]),
		"offered_height": "2", "offered_digest": hex.EncodeToString(f.newProof.Digest[:]),
		"stored_signer": keyFingerprint(f.oldKey.DER), "reset_ready": keyFingerprint(f.oldKey.DER),
		"floor_status": "floor not yet recorded", "file_mesh_status": "file of another mesh",
	}
	if len(result.Events) != 1 || result.Events[0].Kind != "trust.refused" || !equalTrustAttrs(result.Events[0].Attrs, want) {
		t.Fatalf("D24: %+v", result.Events)
	}
	result.Record.Marker.Synced = false
	result.Events = nil
	result.finishTrust(f.cfg.Auth.Trust, filepath.Join(f.dir, trustStoreName), false, 0, 1, held)
	delete(want, "reset_ready")
	want["reset_waits"] = "directory sync owed"
	if len(result.Events) != 1 || !equalTrustAttrs(result.Events[0].Attrs, want) {
		t.Fatalf("D24 unsynced: %+v", result.Events)
	}
}

func TestTrustNoSnapshotClosedOmissions(t *testing.T) {
	f := localTrustFixtureOf(t)
	result := TrustResult{Record: &TrustRecord{List: []trustdoc.CompromisedKey{{Key: f.oldKey}}}}
	for _, test := range []struct {
		name  string
		value any
		want  map[string]bool
	}{
		{"status", result.Status(f.cfg), map[string]bool{"path": true, "compromised": true}},
		{"debug", result.Debug(f.cfg), map[string]bool{"path": true}},
	} {
		body, err := json.Marshal(test.value)
		if err != nil {
			t.Fatal(err)
		}
		var got map[string]json.RawMessage
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatal(err)
		}
		if len(got) != len(test.want) {
			t.Fatalf("%s keys: %s", test.name, body)
		}
		for key := range got {
			if !test.want[key] {
				t.Fatalf("%s unexpected %q: %s", test.name, key, body)
			}
		}
	}
}
