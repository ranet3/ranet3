// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ranet3.com/pkgs/ranet3/trust"
)

func TestTrustResetCommandRefusesBeforeWriteThenReplaces(t *testing.T) {
	dir := t.TempDir()
	oldPrivate, oldText := writeTrustTestKey(t, filepath.Join(dir, "old.pem"), 0x31)
	newPrivate, newText := writeTrustTestKey(t, filepath.Join(dir, "new.pem"), 0x32)
	_, deviceText := writeTrustTestKey(t, filepath.Join(dir, "device.pem"), 0x33)
	oldKey, err := trust.ParseAuthorityKey(oldText)
	if err != nil {
		t.Fatal(err)
	}
	newKey, err := trust.ParseAuthorityKey(newText)
	if err != nil {
		t.Fatal(err)
	}
	local, peer := "0", "1"
	payload := trust.Payload{Height: 1, Mesh: trust.MeshID{6: 0x70, 8: 0x80}, Document: trust.Document{Nodes: []trust.Node{
		{Name: "example/local", Key: &deviceText, Endpoints: []trust.Endpoint{{ID: &local, Family: "ip4", Port: 13000}}},
		{Name: "example/gateway", Key: &deviceText, Endpoints: []trust.Endpoint{{ID: &peer, Family: "ip4", Port: 13000}}},
	}}}
	oldSigned, err := trust.SignPayload(payload, oldPrivate)
	if err != nil {
		t.Fatal(err)
	}
	oldVerified, err := trust.VerifySignedFile(oldSigned, []trust.AuthorityKey{oldKey})
	if err != nil {
		t.Fatal(err)
	}
	payload.Height = 2
	payload.Previous = &oldVerified.Digest
	newSigned, err := trust.SignPayload(payload, newPrivate)
	if err != nil {
		t.Fatal(err)
	}
	newVerified, err := trust.VerifySignedFile(newSigned, []trust.AuthorityKey{newKey})
	if err != nil {
		t.Fatal(err)
	}
	storePath := filepath.Join(dir, "trust.store")
	oldStore, err := trust.EncodeStore(trust.StoreImage{Signed: oldSigned, Signer: oldKey, Verified: &oldVerified, Compromised: []trust.CompromisedKey{{Key: oldKey}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(storePath, oldStore, 0600); err != nil {
		t.Fatal(err)
	}
	filePath := filepath.Join(dir, "trust.cose")
	if err := os.WriteFile(filePath, newSigned, 0600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "config.toml")
	writeConfiguration := func(peer string) {
		t.Helper()
		body := fmt.Sprintf("node = %q\n[auth]\nkey = %q\ntrust = %q\nauthority = [%q]\n[link]\nport = 13000\nendpoints = [{serial = \"0\", family = \"ip4\"}]\n[dial]\nto = [%q]\n", "example/local", filepath.Join(dir, "device.pem"), filePath, newText, peer)
		if err := os.WriteFile(configPath, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeConfiguration("example/gateway:missing")
	digest := hex.EncodeToString(newVerified.Digest[:])
	out, stderr, err := runTrustCommand("trust", "reset", "--config", configPath, "--state-dir", dir, "--digest", digest)
	if err == nil || out != "" || !strings.Contains(stderr, "reset refused: config "+configPath+", store "+storePath+": the configuration refuses the replacement: load step 8b, config: peer endpoint example/gateway:missing not found") {
		t.Fatalf("registered reset refusal: stdout %q stderr %q error %v", out, stderr, err)
	}
	if after, err := os.ReadFile(storePath); err != nil || !bytes.Equal(after, oldStore) {
		t.Fatalf("refused command changed store bytes: %x, %v", after, err)
	}
	writeConfiguration("example/gateway:1")
	out, stderr, err = runTrustCommand("trust", "reset", "--config", configPath, "--state-dir", dir, "--digest", digest)
	if err != nil || out != "" || stderr != "reset done: config "+configPath+", store "+storePath+"\n" {
		t.Fatalf("registered reset success: stdout %q stderr %q error %v", out, stderr, err)
	}
	after, err := os.ReadFile(storePath)
	if err != nil {
		t.Fatal(err)
	}
	image, err := trust.DecodeStore(after)
	if err != nil || image.Verified == nil || image.Verified.Digest != newVerified.Digest || len(image.Compromised) != 1 || base64.StdEncoding.EncodeToString(image.Compromised[0].Key.DER) != oldText {
		t.Fatalf("replacement image %+v, %v", image, err)
	}
}

func TestTrustResetCommandSelectsExplicitAndDefaultPathsBeforeAccess(t *testing.T) {
	for _, test := range []struct {
		name   string
		args   []string
		config string
		dir    string
	}{
		{"default", nil, defaultConfig, defaultStateDir},
		{"explicit", []string{"--config", filepath.Join(t.TempDir(), "config.toml"), "--state-dir", t.TempDir()}, "", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.name == "explicit" {
				test.config, test.dir = test.args[1], test.args[3]
			}
			args := append([]string{"trust", "reset"}, test.args...)
			out, stderr, err := runTrustCommand(args...)
			want := "reset refused: config " + test.config + ", store " + filepath.Join(test.dir, "trust.store") + ": digest must be 64 lowercase hex characters"
			if err == nil || out != "" || !strings.Contains(stderr, want) {
				t.Fatalf("selected path: stdout %q stderr %q error %v", out, stderr, err)
			}
			if test.name == "explicit" {
				args = append(args, "--digest", strings.Repeat("0", 64))
				out, stderr, err = runTrustCommand(args...)
				want = "reset refused: config " + test.config + ", store " + filepath.Join(test.dir, "trust.store") + ": configuration cannot be loaded"
				if err == nil || out != "" || stderr != want+"\n" {
					t.Fatalf("selected config access: stdout %q stderr %q error %v", out, stderr, err)
				}
			}
		})
	}
}
