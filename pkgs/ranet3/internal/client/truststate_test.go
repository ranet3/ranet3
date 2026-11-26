// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/internal/config"
	trustdoc "ranet3.com/pkgs/ranet3/trust"
)

type localTrustFixture struct {
	cfg         *config.Config
	configPath  string
	dir         string
	oldKey      trustdoc.AuthorityKey
	oldPrivate  ed25519.PrivateKey
	newKey      trustdoc.AuthorityKey
	newPrivate  ed25519.PrivateKey
	first       []byte
	firstProof  trustdoc.Verified
	replacement []byte
	newProof    trustdoc.Verified
}

func localAuthority(t *testing.T, seed byte) (ed25519.PrivateKey, trustdoc.AuthorityKey) {
	t.Helper()
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
	der, err := x509.MarshalPKIXPublicKey(private.Public())
	if err != nil {
		t.Fatal(err)
	}
	key, err := trustdoc.ParseAuthorityKey(base64.StdEncoding.EncodeToString(der))
	if err != nil {
		t.Fatal(err)
	}
	return private, key
}

func localTrustFixtureOf(t *testing.T) localTrustFixture {
	t.Helper()
	dir := t.TempDir()
	device, _ := localAuthority(t, 0x44)
	oldPrivate, oldKey := localAuthority(t, 0x55)
	newPrivate, newKey := localAuthority(t, 0x66)
	deviceDER, err := x509.MarshalPKIXPublicKey(device.Public())
	if err != nil {
		t.Fatal(err)
	}
	deviceText := base64.StdEncoding.EncodeToString(deviceDER)
	local, peer := "0", "1"
	mesh := trustdoc.MeshID{6: 0x70, 8: 0x80}
	firstPayload := trustdoc.Payload{Height: 1, Mesh: mesh, Document: trustdoc.Document{Nodes: []trustdoc.Node{
		{Name: "example/local", Key: &deviceText, Endpoints: []trustdoc.Endpoint{{ID: &local, Family: "ip4", Port: 13000}}},
		{Name: "example/gateway", Key: &deviceText, Endpoints: []trustdoc.Endpoint{{ID: &peer, Family: "ip4", Port: 13000}}},
	}}}
	first, err := trustdoc.SignPayload(firstPayload, oldPrivate)
	if err != nil {
		t.Fatal(err)
	}
	firstProof, err := trustdoc.VerifySignedFile(first, []trustdoc.AuthorityKey{oldKey})
	if err != nil {
		t.Fatal(err)
	}
	previous := firstProof.Digest
	secondPayload := firstPayload
	secondPayload.Height, secondPayload.Previous = 2, &previous
	replacement, err := trustdoc.SignPayload(secondPayload, newPrivate)
	if err != nil {
		t.Fatal(err)
	}
	newProof, err := trustdoc.VerifySignedFile(replacement, []trustdoc.AuthorityKey{newKey})
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Node: identity.MustParse("example/local"),
		Auth: config.Auth{Key: filepath.Join(dir, "device.pem"), Trust: filepath.Join(dir, "trust.cose"), Authority: []string{base64.StdEncoding.EncodeToString(oldKey.DER)}},
		Link: config.Link{Port: 13000, Endpoints: []config.Endpoint{{Serial: "0", Family: "ip4"}}},
		Dial: config.Dial{To: []identity.Identity{identity.MustParse("example/gateway:1")}},
	}
	writeKey(t, cfg.Auth.Key, device)
	if err := os.WriteFile(cfg.Auth.Trust, first, 0600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "config.yaml")
	writeConfig(t, configPath, cfg)
	if _, err := config.Load(configPath); err != nil {
		t.Fatal(err)
	}
	return localTrustFixture{cfg, configPath, dir, oldKey, oldPrivate, newKey, newPrivate, first, firstProof, replacement, newProof}
}

func (f localTrustFixture) writeStore(t *testing.T, signer trustdoc.AuthorityKey, signed []byte, verified trustdoc.Verified, list []trustdoc.CompromisedKey) []byte {
	t.Helper()
	body, err := trustdoc.EncodeStore(trustdoc.StoreImage{Signed: signed, Signer: signer, Verified: &verified, Compromised: list})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.dir, trustStoreName), body, 0600); err != nil {
		t.Fatal(err)
	}
	return body
}

func TestTrustLoadFirstPinAndFreshStore(t *testing.T) {
	f := localTrustFixtureOf(t)
	result, err := LoadTrust(f.cfg, f.dir, nil, nil, nil)
	if err != nil || result.Row != trustdoc.D2 || result.Held != nil || result.Prepared == nil || result.Prepared.Verified.Digest != f.firstProof.Digest {
		t.Fatalf("first load: row %s prepared %+v error %v", result.Row, result.Prepared, err)
	}
	image, present, err := readTrustStore(filepath.Join(f.dir, trustStoreName))
	if err != nil || !present || image.Verified == nil || image.Verified.Digest != f.firstProof.Digest || len(image.Compromised) != 0 {
		t.Fatalf("stored image: %+v, present %t, %v", image, present, err)
	}
	if result.Record.Marker == nil || !result.Record.Marker.Synced || len(result.Events) != 1 || result.Events[0].Kind != "trust.accepted" || result.Events[0].Attrs["path"] != f.cfg.Auth.Trust || !result.ClearRefusal {
		t.Fatalf("marker or event: %+v, %+v", result.Record, result.Events)
	}
	status := result.Status(f.cfg)
	if status == nil || status.Height == nil || *status.Height != 1 || status.Nodes == nil || *status.Nodes != 2 || status.Organizations == nil || *status.Organizations != 1 {
		t.Fatalf("status: %+v", status)
	}
	second, err := LoadTrust(f.cfg, f.dir, result.Record, result.Prepared, nil)
	if err != nil || second.Row != trustdoc.D3 || second.Held != result.Prepared || !second.ClearRefusal {
		t.Fatalf("same signed copy: %+v, %v", second, err)
	}
}

func TestTrustUnreadableStoreLeavesBytesIntact(t *testing.T) {
	f := localTrustFixtureOf(t)
	path := filepath.Join(f.dir, trustStoreName)
	invalid := []byte{0xa1, 0x04, 0x80}
	if err := os.WriteFile(path, invalid, 0600); err != nil {
		t.Fatal(err)
	}
	result, err := LoadTrust(f.cfg, f.dir, nil, nil, nil)
	if err != nil || result.Row != trustdoc.D14 || result.Status(f.cfg) != nil {
		t.Fatalf("unreadable store: %+v, %v", result, err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, invalid) {
		t.Fatalf("store bytes changed: %x, %v", got, err)
	}
}

func TestTrustCompromisedSignerReadinessAndRefusal(t *testing.T) {
	f := localTrustFixtureOf(t)
	f.cfg.Auth.Authority = []string{base64.StdEncoding.EncodeToString(f.newKey.DER)}
	f.cfg.Auth.Revoked = []config.RevokedKey{{Key: base64.StdEncoding.EncodeToString(f.oldKey.DER), Height: 3}}
	f.writeStore(t, f.oldKey, f.first, f.firstProof, nil)
	if err := os.WriteFile(f.cfg.Auth.Trust, f.replacement, 0600); err != nil {
		t.Fatal(err)
	}
	result, err := LoadTrust(f.cfg, f.dir, nil, nil, nil)
	if err != nil || result.Row != trustdoc.D24 || len(result.Record.List) != 1 || result.Record.List[0].Floor != 0 {
		t.Fatalf("compromised signer row and floor: %+v, %v", result, err)
	}
	if result.ResetReady != keyFingerprint(f.oldKey.DER) || result.ResetWaits != "" || len(result.NotPersisted) != 0 {
		t.Fatalf("reset readiness: ready %q waits %q owed %+v", result.ResetReady, result.ResetWaits, result.NotPersisted)
	}
	if len(result.Events) != 1 || result.Events[0].Attrs["floor_status"] != "floor not yet recorded" || result.Events[0].Attrs["reset_ready"] != result.ResetReady {
		t.Fatalf("refusal payload: %+v", result.Events)
	}
	status, debug := result.Status(f.cfg), result.Debug(f.cfg)
	if status == nil || status.Reset == nil || status.Reset.Ready != result.ResetReady || debug == nil || debug.Key != keyFingerprint(f.oldKey.DER) {
		t.Fatalf("status %+v, debug %+v", status, debug)
	}
}

func TestTrustStartOtherMeshCompromisedSignerRefusesWithoutStatus(t *testing.T) {
	f := localTrustFixtureOf(t)
	f.cfg.Auth.Authority = []string{base64.StdEncoding.EncodeToString(f.newKey.DER)}
	f.cfg.Auth.Revoked = []config.RevokedKey{{Key: base64.StdEncoding.EncodeToString(f.oldKey.DER), Height: 3}}
	f.writeStore(t, f.oldKey, f.first, f.firstProof, nil)
	payload := f.newProof.Payload
	payload.Mesh[0] ^= 1
	otherMesh, err := trustdoc.SignPayload(payload, f.newPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.cfg.Auth.Trust, otherMesh, 0600); err != nil {
		t.Fatal(err)
	}
	result, err := LoadTrust(f.cfg, f.dir, nil, nil, nil)
	if err != nil || result.Row != trustdoc.D24 || result.Offered == nil || result.Status(f.cfg) != nil || len(result.Events) != 0 {
		t.Fatalf("start on a different mesh: row %s, status %+v, events %+v, error %v", result.Row, result.Status(f.cfg), result.Events, err)
	}
}

func TestTrustResetRefusesPeerBeforeWritingThenReplaces(t *testing.T) {
	f := localTrustFixtureOf(t)
	f.cfg.Auth.Authority = []string{base64.StdEncoding.EncodeToString(f.newKey.DER)}
	f.writeStore(t, f.oldKey, f.first, f.firstProof, []trustdoc.CompromisedKey{{Key: f.oldKey}})
	if err := os.WriteFile(f.cfg.Auth.Trust, f.replacement, 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.dir, trustStoreName)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	f.cfg.Dial.To = []identity.Identity{identity.MustParse("example/gateway:missing")}
	writeConfig(t, f.configPath, f.cfg)
	digest := hex.EncodeToString(f.newProof.Digest[:])
	message, err := ResetTrust(f.configPath, f.dir, digest)
	if message != "" || err == nil || !strings.Contains(err.Error(), "load step 8b, config: peer endpoint example/gateway:missing not found") {
		t.Fatalf("prewrite refusal: %q, %v", message, err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, before) {
		t.Fatalf("refused reset changed path bytes: %x, %v", after, err)
	}
	f.cfg.Dial.To = []identity.Identity{identity.MustParse("example/gateway:1")}
	writeConfig(t, f.configPath, f.cfg)
	message, err = ResetTrust(f.configPath, f.dir, digest)
	if err != nil || !strings.HasPrefix(message, "reset done: config ") {
		t.Fatalf("valid replacement: %q, %v", message, err)
	}
	image, _, err := readTrustStore(path)
	if err != nil || image.Verified == nil || image.Verified.Digest != f.newProof.Digest || len(image.Compromised) != 1 || !bytes.Equal(image.Compromised[0].Key.DER, f.oldKey.DER) {
		t.Fatalf("replacement did not preserve L: %+v, %v", image, err)
	}
	if _, err := ResetTrust(f.configPath, f.dir, digest); err == nil || !strings.Contains(err.Error(), "is not on its list of compromised keys") {
		t.Fatalf("repeat reset acted on uncompromised image: %v", err)
	}
}

func TestTrustStatusOmissionsAndPersistenceAttributes(t *testing.T) {
	f := localTrustFixtureOf(t)
	result := TrustResult{Record: &TrustRecord{List: []trustdoc.CompromisedKey{{Key: f.oldKey}}}}
	status := result.Status(f.cfg)
	body, err := json.Marshal(status)
	if err != nil || bytes.Contains(body, []byte(`"height"`)) || bytes.Contains(body, []byte(`"nodes"`)) || bytes.Contains(body, []byte(`"digest"`)) {
		t.Fatalf("no-snapshot status %s, %v", body, err)
	}
	result.Row = trustdoc.D24
	result.Held = &TrustHeld{Signed: f.first, Verified: f.firstProof}
	result.NotPersisted = result.Record.List
	result.Record.Marker = &TrustMarker{Image: markerImage(result.Held, result.Record.List)}
	ready, waits := trustReadiness(result.Record.Marker, result.Held, result.NotPersisted)
	if ready != "" || waits != "directory sync owed" {
		t.Fatalf("unsynced marker: %q, %q", ready, waits)
	}
	result.Record.Marker.Synced = true
	ready, waits = trustReadiness(result.Record.Marker, result.Held, result.NotPersisted)
	if ready != "" || waits != keyFingerprint(f.oldKey.DER)+" not persisted" {
		t.Fatalf("unpersisted signer: %q, %q", ready, waits)
	}
	result.Record.Marker.Image.Signer = f.newKey
	ready, waits = trustReadiness(result.Record.Marker, result.Held, result.NotPersisted)
	if ready != "" || waits != "store's signer is "+keyFingerprint(f.newKey.DER) {
		t.Fatalf("other stored signer: %q, %q", ready, waits)
	}
}

func TestTrustCapBeforeFileAndConfigBeforeStore(t *testing.T) {
	f := localTrustFixtureOf(t)
	keys := make([]trustdoc.CompromisedKey, 64)
	for i := range keys {
		_, key := localAuthority(t, byte(i))
		keys[i] = trustdoc.CompromisedKey{Key: key}
	}
	slices.SortFunc(keys, func(a, b trustdoc.CompromisedKey) int { return bytes.Compare(a.Key.DER, b.Key.DER) })
	raw, err := trustdoc.EncodeStore(trustdoc.StoreImage{Compromised: keys})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.dir, trustStoreName)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	_, extra := localAuthority(t, 0x80)
	f.cfg.Auth.Revoked = []config.RevokedKey{{Key: base64.StdEncoding.EncodeToString(extra.DER), Height: 1}}
	result, err := LoadTrust(f.cfg, f.dir, nil, nil, nil)
	if err != nil || result.Row != trustdoc.C1 {
		t.Fatalf("65th distinct key: row %s, error %v", result.Row, err)
	}
	if after, err := os.ReadFile(path); err != nil || !bytes.Equal(after, raw) {
		t.Fatalf("cap rewrote store: %x, %v", after, err)
	}
	f.cfg.Auth.Revoked = []config.RevokedKey{{Key: base64.StdEncoding.EncodeToString(f.oldKey.DER), Height: 1}}
	if err := os.WriteFile(path, []byte{0xa0}, 0600); err != nil {
		t.Fatal(err)
	}
	result, err = LoadTrust(f.cfg, f.dir, nil, nil, nil)
	if err != nil || result.Row != trustdoc.C1 || !strings.Contains(result.Failure, "also lists an auth.authority key") {
		t.Fatalf("step 2 before unreadable store: %+v, %v", result, err)
	}
	if after, err := os.ReadFile(path); err != nil || !bytes.Equal(after, []byte{0xa0}) {
		t.Fatalf("step 2 rewrote store: %x, %v", after, err)
	}
}

func TestTrustAuthenticatedOverlapPrecedesRuntimeChecks(t *testing.T) {
	f := localTrustFixtureOf(t)
	f.cfg.Auth.Authority = []string{base64.StdEncoding.EncodeToString(f.oldKey.DER), base64.StdEncoding.EncodeToString(f.newKey.DER)}
	nodeKey := base64.StdEncoding.EncodeToString(f.oldKey.DER)
	file, err := trustdoc.SignPayload(trustdoc.Payload{
		Height: 1, Mesh: trustdoc.MeshID{6: 0x70, 8: 0x80},
		Document: trustdoc.Document{Nodes: []trustdoc.Node{{Name: "example/overlap", Key: &nodeKey, Endpoints: []trustdoc.Endpoint{}}}},
	}, f.newPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.cfg.Auth.Trust, file, 0600); err != nil {
		t.Fatal(err)
	}
	result, err := LoadTrust(f.cfg, f.dir, nil, nil, nil)
	if err != nil || result.Row != trustdoc.D16 || result.Status(f.cfg) != nil || !strings.Contains(result.Failure, "also belongs to node") {
		t.Fatalf("authenticated overlap: %+v, %v", result, err)
	}
	if _, err := os.Stat(filepath.Join(f.dir, trustStoreName)); !os.IsNotExist(err) {
		t.Fatalf("overlap wrote store: %v", err)
	}
}

func TestTrustSuppliedPrepublicationFailureKeepsServingSnapshot(t *testing.T) {
	f := localTrustFixtureOf(t)
	first, err := LoadTrust(f.cfg, f.dir, nil, nil, nil)
	if err != nil || first.Row != trustdoc.D2 {
		t.Fatalf("first snapshot: %+v, %v", first, err)
	}
	f.cfg.Auth.Authority = []string{base64.StdEncoding.EncodeToString(f.oldKey.DER), base64.StdEncoding.EncodeToString(f.newKey.DER)}
	if err := os.WriteFile(f.cfg.Auth.Trust, f.replacement, 0600); err != nil {
		t.Fatal(err)
	}
	next, err := LoadTrust(f.cfg, f.dir, first.Record, first.Prepared, nil)
	if err != nil || next.Row != trustdoc.D7 || next.Held != first.Prepared || next.Prepared == nil || next.Prepared.Verified.Digest != f.newProof.Digest {
		t.Fatalf("prepared successor: %+v, %v", next, err)
	}
	next.ApplyFailure("retable")
	if next.Row != trustdoc.D15 || next.Held != first.Prepared || next.Prepared != nil || next.ClearRefusal || next.Failure != "apply failed: retable" || next.Record.Marker.Image.Verified.Digest != f.newProof.Digest {
		t.Fatalf("unpublished replacement: %+v", next)
	}
	for _, event := range next.Events {
		if event.Kind == "trust.accepted" {
			t.Fatalf("accepted event for unpublished successor: %+v", next.Events)
		}
	}
	if status := next.Status(f.cfg); status == nil || status.Refused == nil || status.Refused.Reason != "apply failed: retable" {
		t.Fatalf("prepublication status: %+v", status)
	}
}
