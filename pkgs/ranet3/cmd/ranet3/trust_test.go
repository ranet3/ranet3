// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ranet3.com/pkgs/ranet3/trust"
)

const vectorAuthority = "MCowBQYDK2VwAyEA7vRDY0q9Dah4orYnH+P9+VDDuev6ghmNsdhocuu9duc="
const vectorFile = "d2845827a201320378216170706c69636174696f6e2f766e642e72616e6574332e74727573742b63626f72a05819a3010103a101800450018e8cf033207abc8def0123456789ab5840c9a17ad94a1bc1d5ea0836fce6e7f72c70dbba426e9d09b2bf4bc3c300762ed642883afd53aca59543d31ed21d87c30b38118e46c550770e9eb6134df5dae708"
const vectorPayload = "a3010103a101800450018e8cf033207abc8def0123456789ab"

func runTrustCommand(args ...string) (string, string, error) {
	command := newRoot()
	var out, stderr strings.Builder
	command.SetOut(&out)
	command.SetErr(&stderr)
	command.SetArgs(args)
	err := command.Execute()
	if err != nil {
		fmt.Fprintln(&stderr, err)
	}
	return out.String(), stderr.String(), err
}

func trustVector(t *testing.T) (string, string) {
	t.Helper()
	file, err := hex.DecodeString(vectorFile)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "trust.cose")
	if err := os.WriteFile(path, file, 0600); err != nil {
		t.Fatal(err)
	}
	der, err := base64.StdEncoding.DecodeString(vectorAuthority)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := hex.DecodeString(vectorPayload)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	fingerprint := sha256.Sum256(der)
	facts := fmt.Sprintf("height 1\nprevious none\ndigest %x\nalgorithm Ed25519 (-19)\nkey SHA256:%s\n", digest, base64.RawStdEncoding.EncodeToString(fingerprint[:]))
	return path, facts
}

func TestTrustShowFacts(t *testing.T) {
	path, facts := trustVector(t)
	for _, test := range []struct {
		mesh bool
		want string
	}{
		{false, facts},
		{true, facts + "mesh 018e8cf0-3320-7abc-8def-0123456789ab\n"},
	} {
		args := []string{"trust", "show", "--authority", vectorAuthority}
		if test.mesh {
			args = append(args, "--mesh")
		}
		out, stderr, err := runTrustCommand(append(args, path)...)
		if err != nil || out != `{"nodes":[]}` || stderr != test.want {
			t.Fatalf("show mesh=%v: stdout %q, stderr %q, error %v", test.mesh, out, stderr, err)
		}
	}
}

func TestTrustVerifyFacts(t *testing.T) {
	path, facts := trustVector(t)
	out, stderr, err := runTrustCommand("trust", "verify", "--authority", vectorAuthority, path)
	if err != nil || out != "" || stderr != facts {
		t.Fatalf("verify: stdout %q, stderr %q, error %v", out, stderr, err)
	}
	out, stderr, err = runTrustCommand("trust", "verify", "--authority", vectorAuthority, "--mesh", path)
	if err == nil || out != "" || !strings.Contains(stderr, "unknown flag: --mesh") {
		t.Fatalf("verify accepted mesh flag: stdout %q, stderr %q, error %v", out, stderr, err)
	}
}

func TestTrustAuthoritySources(t *testing.T) {
	path, facts := trustVector(t)
	configPath := filepath.Join(t.TempDir(), "config.toml")
	configuration := fmt.Sprintf("node = \"example/laptop\"\n[auth]\nkey = \"key.pem\"\ntrust = \"trust.cose\"\nauthority = [%q]\n[link]\nport = 13000\nendpoints = [{serial = \"0\", family = \"ip4\"}]\n[dial]\nall = true\n", vectorAuthority)
	if err := os.WriteFile(configPath, []byte(configuration), 0600); err != nil {
		t.Fatal(err)
	}
	out, stderr, err := runTrustCommand("trust", "verify", "--config", configPath, path)
	if err != nil || out != "" || stderr != facts {
		t.Fatalf("config-only verification: stdout %q, stderr %q, error %v", out, stderr, err)
	}
	other := "MCowBQYDK2VwAyEAZ+47jCA4V9l+XpsxLQFHj0OW8zzog0Iw09LCmjad3YY="
	for _, verb := range []string{"show", "verify"} {
		out, stderr, err := runTrustCommand("trust", verb, "--config", configPath, "--authority", other, path)
		if err == nil || out != "" || !strings.Contains(stderr, "signature") {
			t.Fatalf("%s accepted signer from replaced config: stdout %q, stderr %q, error %v", verb, out, stderr, err)
		}
		out, stderr, err = runTrustCommand("trust", verb, "--config", configPath, "--authority", "not base64", path)
		if err == nil || out != "" || !strings.Contains(stderr, "invalid --authority key") {
			t.Fatalf("%s accepted invalid explicit key: stdout %q, stderr %q, error %v", verb, out, stderr, err)
		}
	}
}

func trustSigningFixture(t *testing.T) (string, string, string) {
	t.Helper()
	directory := t.TempDir()
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(directory, "authority.pem")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(private.Public())
	if err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(directory, "document.json")
	if err := os.WriteFile(input, []byte(`{"nodes":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	return keyPath, input, base64.StdEncoding.EncodeToString(spki)
}

func TestTrustInitCreatesSeparateMeshes(t *testing.T) {
	keyPath, input, public := trustSigningFixture(t)
	key, err := trust.ParseAuthorityKey(public)
	if err != nil {
		t.Fatal(err)
	}
	var meshes [2]trust.MeshID
	for i := range meshes {
		output := filepath.Join(t.TempDir(), fmt.Sprintf("trust-%d.cose", i))
		out, stderr, err := runTrustCommand("trust", "init", "--key", keyPath, "--out", output, input)
		if err != nil || out != "" {
			t.Fatalf("init: stdout %q, stderr %q, error %v", out, stderr, err)
		}
		verified, err := trust.ReadSignedFile(output, []trust.AuthorityKey{key})
		if err != nil || verified.Payload.Height != 1 || verified.Payload.Previous != nil {
			t.Fatalf("init file: %+v, %v", verified, err)
		}
		meshes[i] = verified.Payload.Mesh
		fingerprint := sha256.Sum256(key.DER)
		want := fmt.Sprintf("height 1\ndigest %x\nalgorithm Ed25519 (-19)\nkey SHA256:%s\nwritten %s (%d bytes)\n", verified.Digest, base64.RawStdEncoding.EncodeToString(fingerprint[:]), output, fileSize(t, output))
		if stderr != want {
			t.Fatalf("init facts: got %q, want %q", stderr, want)
		}
		shown, _, err := runTrustCommand("trust", "show", "--authority", public, output)
		if err != nil || shown != `{"nodes":[]}` {
			t.Fatalf("show after init: %q, %v", shown, err)
		}
		info, err := os.Stat(output)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("signed file mode %v: %v", info, err)
		}
	}
	if meshes[0] == meshes[1] {
		t.Fatal("two independent inits shared a mesh")
	}
}

func fileSize(t *testing.T, path string) int64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Size()
}

func TestTrustInitRefusalsAndRace(t *testing.T) {
	keyPath, input, public := trustSigningFixture(t)
	output := filepath.Join(t.TempDir(), "trust.cose")
	escaped := []byte(`{"nodes":[{"endpoints":[],"name":"example/\u0061"}]}`)
	if err := os.WriteFile(input, escaped, 0600); err != nil {
		t.Fatal(err)
	}
	out, stderr, err := runTrustCommand("trust", "init", "--key", keyPath, "--out", output, input)
	if err == nil || out != "" || stderr != input+": reviewed bytes differ from the canonical render\n" {
		t.Fatalf("accepted escaped name: stdout %q, stderr %q, error %v", out, stderr, err)
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatalf("noncanonical input left signed output: %v", err)
	}
	if err := os.WriteFile(input, []byte(`{"nodes":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, flag := range []string{"--force", "--first", "--new-mesh"} {
		out, _, err := runTrustCommand("trust", "init", "--key", keyPath, "--out", output, flag, input)
		if err == nil || out != "" {
			t.Fatalf("accepted %s: stdout %q, error %v", flag, out, err)
		}
	}
	for _, current := range []string{"file", "directory", "dangling link"} {
		t.Run(current, func(t *testing.T) {
			target := filepath.Join(t.TempDir(), "trust.cose")
			switch current {
			case "file":
				err = os.WriteFile(target, []byte("kept"), 0600)
			case "directory":
				err = os.Mkdir(target, 0700)
			case "dangling link":
				err = os.Symlink(filepath.Join(t.TempDir(), "absent"), target)
			}
			if err != nil {
				t.Fatal(err)
			}
			out, stderr, err := runTrustCommand("trust", "init", "--key", keyPath, "--out", target, input)
			if err == nil || out != "" || stderr != target+" exists, refusing to replace a mesh\n" {
				t.Fatalf("replaced %s: stdout %q, stderr %q, error %v", current, out, stderr, err)
			}
		})
	}
	type outcome struct {
		out, stderr string
		err         error
	}
	results := make(chan outcome, 2)
	for range 2 {
		go func() {
			out, stderr, err := runTrustCommand("trust", "init", "--key", keyPath, "--out", output, input)
			results <- outcome{out, stderr, err}
		}()
	}
	winners := 0
	for range 2 {
		result := <-results
		if result.err == nil {
			winners++
		} else if result.stderr != output+" exists, refusing to replace a mesh\n" {
			t.Fatalf("race refusal: %+v", result)
		}
		if result.out != "" {
			t.Fatalf("signed bytes printed on stdout: %q", result.out)
		}
	}
	if winners != 1 {
		t.Fatalf("%d race winners, want one", winners)
	}
	key, err := trust.ParseAuthorityKey(public)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := trust.ReadSignedFile(output, []trust.AuthorityKey{key}); err != nil {
		t.Fatalf("race winner did not write a whole signed file: %v", err)
	}
}
