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
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/statefile"
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
	if err := os.WriteFile(configPath, []byte("not valid configuration"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, verb := range []string{"show", "verify"} {
		out, stderr, err := runTrustCommand("trust", verb, "--config", configPath, "--authority", vectorAuthority, path)
		if err == nil || out != "" || !strings.Contains(stderr, configPath) {
			t.Fatalf("%s ignored invalid named configuration: stdout %q, stderr %q, error %v", verb, out, stderr, err)
		}
	}
}

func writeTrustTestKey(t *testing.T, path string, seed byte) (ed25519.PrivateKey, string) {
	t.Helper()
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(private.Public())
	if err != nil {
		t.Fatal(err)
	}
	return private, base64.StdEncoding.EncodeToString(spki)
}

func trustSigningFixture(t *testing.T) (string, string, string) {
	t.Helper()
	directory := t.TempDir()
	keyPath := filepath.Join(directory, "authority.pem")
	_, public := writeTrustTestKey(t, keyPath, 0x42)
	input := filepath.Join(directory, "document.json")
	if err := os.WriteFile(input, []byte(`{"nodes":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	return keyPath, input, public
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
	arrived := make(chan struct{}, 2)
	release := make(chan struct{})
	var order atomic.Int32
	firstDone := make(chan struct{})
	publish := func(path string, body []byte, mode fs.FileMode) error {
		position := order.Add(1)
		arrived <- struct{}{}
		<-release
		if position == 2 {
			<-firstDone
		}
		err := statefile.PublishNew(path, body, mode)
		if position == 1 {
			close(firstDone)
		}
		return err
	}
	for range 2 {
		go func() {
			out, stderr, err := runTrustWithPublisher("init", publish, "--key", keyPath, "--out", output, input)
			results <- outcome{out, stderr, err}
		}()
	}
	for range 2 {
		select {
		case <-arrived:
		case result := <-results:
			close(release)
			t.Fatalf("writer returned before publication: %+v", result)
		}
	}
	close(release)
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

func TestTrustSignSuccessors(t *testing.T) {
	keyA, input, publicA := trustSigningFixture(t)
	directory := t.TempDir()
	keyB := filepath.Join(directory, "authority-b.pem")
	_, publicB := writeTrustTestKey(t, keyB, 0x43)
	parentPath := filepath.Join(directory, "trust-1.cose")
	if out, stderr, err := runTrustCommand("trust", "init", "--key", keyA, "--out", parentPath, input); err != nil || out != "" || !strings.HasPrefix(stderr, "height 1\n") {
		t.Fatalf("init parent: stdout %q, stderr %q, error %v", out, stderr, err)
	}
	key, err := trust.ParseAuthorityKey(publicA)
	if err != nil {
		t.Fatal(err)
	}
	parent, err := trust.ReadSignedFile(parentPath, []trust.AuthorityKey{key})
	if err != nil {
		t.Fatal(err)
	}
	for i, step := range []struct {
		key, parentAuthority, newAuthority, document string
	}{
		{keyB, publicA, publicB, `{"nodes":[{"endpoints":[],"name":"example/gateway"}]}`},
		{keyA, publicB, publicA, `{"nodes":[{"endpoints":[],"name":"example/gateway"},{"endpoints":[],"name":"example/relay"}]}`},
	} {
		if err := os.WriteFile(input, []byte(step.document), 0600); err != nil {
			t.Fatal(err)
		}
		output := filepath.Join(directory, fmt.Sprintf("trust-%d.cose", i+2))
		out, stderr, err := runTrustCommand("trust", "sign", "--key", step.key, "--previous", parentPath, "--authority", step.parentAuthority, "--out", output, input)
		if err != nil || out != "" {
			t.Fatalf("sign height %d: stdout %q, stderr %q, error %v", i+2, out, stderr, err)
		}
		signerKey, err := trust.ParseAuthorityKey(step.newAuthority)
		if err != nil {
			t.Fatal(err)
		}
		verified, err := trust.ReadSignedFile(output, []trust.AuthorityKey{signerKey})
		if err != nil || verified.Payload.Height != uint64(i+2) || verified.Payload.Previous == nil || *verified.Payload.Previous != parent.Digest || verified.Payload.Mesh != parent.Payload.Mesh {
			t.Fatalf("successor %d: %+v, %v", i+2, verified, err)
		}
		fingerprint := sha256.Sum256(signerKey.DER)
		want := fmt.Sprintf("height %d\nprevious %x\ndigest %x\nalgorithm Ed25519 (-19)\nkey SHA256:%s\nwritten %s (%d bytes)\n", i+2, parent.Digest, verified.Digest, base64.RawStdEncoding.EncodeToString(fingerprint[:]), output, fileSize(t, output))
		if stderr != want {
			t.Fatalf("successor facts: got %q, want %q", stderr, want)
		}
		shown, _, err := runTrustCommand("trust", "show", "--authority", step.newAuthority, output)
		if err != nil || shown != step.document {
			t.Fatalf("show successor: %q, %v", shown, err)
		}
		info, err := os.Stat(output)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("signed output mode %v: %v", info, err)
		}
		parentPath, parent = output, verified
	}
}

func TestTrustSignRefusalsAndRace(t *testing.T) {
	keyPath, input, public := trustSigningFixture(t)
	directory := t.TempDir()
	parentPath := filepath.Join(directory, "parent.cose")
	if _, _, err := runTrustCommand("trust", "init", "--key", keyPath, "--out", parentPath, input); err != nil {
		t.Fatal(err)
	}
	parentBytes, err := os.ReadFile(parentPath)
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(directory, "successor.cose")
	out, stderr, err := runTrustCommand("trust", "sign", "--key", keyPath, "--previous", parentPath, "--out", output, input)
	if err == nil || out != "" || stderr != "--previous requires --authority or --config\n" {
		t.Fatalf("signed without authority source: stdout %q, stderr %q, error %v", out, stderr, err)
	}
	_, other := writeTrustTestKey(t, filepath.Join(directory, "other.pem"), 0x43)
	out, stderr, err = runTrustCommand("trust", "sign", "--key", keyPath, "--previous", parentPath, "--authority", other, "--out", output, input)
	if err == nil || out != "" || stderr != parentPath+": parent does not verify under the key given\n" {
		t.Fatalf("accepted wrong parent authority: stdout %q, stderr %q, error %v", out, stderr, err)
	}
	if err := os.WriteFile(input, []byte(`{"nodes":[{"endpoints":[],"name":"example/\u0061"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	out, stderr, err = runTrustCommand("trust", "sign", "--key", keyPath, "--previous", parentPath, "--authority", public, "--out", output, input)
	if err == nil || out != "" || stderr != input+": reviewed bytes differ from the canonical render\n" {
		t.Fatalf("signed escaped input: stdout %q, stderr %q, error %v", out, stderr, err)
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatalf("refused successor left an output: %v", err)
	}
	if after, err := os.ReadFile(parentPath); err != nil || !bytes.Equal(after, parentBytes) {
		t.Fatalf("refused successor changed parent: %v", err)
	}
	if err := os.WriteFile(input, []byte(`{"nodes":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	out, stderr, err = runTrustCommand("trust", "sign", "--key", keyPath, "--previous", parentPath, "--authority", public, "--out", parentPath, input)
	if err == nil || out != "" || stderr != parentPath+" exists, refusing to replace signed output\n" {
		t.Fatalf("replaced distributed parent: stdout %q, stderr %q, error %v", out, stderr, err)
	}
	if after, err := os.ReadFile(parentPath); err != nil || !bytes.Equal(after, parentBytes) {
		t.Fatalf("distribution file changed: %v", err)
	}
	for _, flag := range []string{"--force", "--first", "--new-mesh"} {
		out, _, err := runTrustCommand("trust", "sign", "--key", keyPath, "--previous", parentPath, "--authority", public, "--out", output, flag, input)
		if err == nil || out != "" {
			t.Fatalf("accepted %s: stdout %q, error %v", flag, out, err)
		}
	}
	key, err := trust.ParseAuthorityKey(public)
	if err != nil {
		t.Fatal(err)
	}
	parent, err := trust.ReadSignedFile(parentPath, []trust.AuthorityKey{key})
	if err != nil {
		t.Fatal(err)
	}
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	limitFile, err := trust.SignPayload(trust.Payload{Height: trust.MaxHeight, Previous: &parent.Digest, Mesh: parent.Payload.Mesh, Document: parent.Payload.Document}, private)
	if err != nil {
		t.Fatal(err)
	}
	limitPath := filepath.Join(directory, "limit.cose")
	if err := os.WriteFile(limitPath, limitFile, 0600); err != nil {
		t.Fatal(err)
	}
	out, stderr, err = runTrustCommand("trust", "sign", "--key", keyPath, "--previous", limitPath, "--authority", public, "--out", output, input)
	if err == nil || out != "" || stderr != limitPath+": parent is at the maximum height\n" {
		t.Fatalf("incremented maximum height: stdout %q, stderr %q, error %v", out, stderr, err)
	}
	type outcome struct {
		out, stderr string
		err         error
	}
	results := make(chan outcome, 2)
	arrived := make(chan struct{}, 2)
	release := make(chan struct{})
	var order atomic.Int32
	firstDone := make(chan struct{})
	publish := func(path string, body []byte, mode fs.FileMode) error {
		position := order.Add(1)
		arrived <- struct{}{}
		<-release
		if position == 2 {
			<-firstDone
		}
		err := statefile.PublishNew(path, body, mode)
		if position == 1 {
			close(firstDone)
		}
		return err
	}
	for range 2 {
		go func() {
			out, stderr, err := runTrustWithPublisher("sign", publish, "--key", keyPath, "--previous", parentPath, "--authority", public, "--out", output, input)
			results <- outcome{out, stderr, err}
		}()
	}
	for range 2 {
		select {
		case <-arrived:
		case result := <-results:
			close(release)
			t.Fatalf("writer returned before publication: %+v", result)
		}
	}
	close(release)
	winners := 0
	for range 2 {
		result := <-results
		if result.err == nil {
			winners++
		} else if result.stderr != output+" exists, refusing to replace signed output\n" {
			t.Fatalf("race refusal: %+v", result)
		}
		if result.out != "" {
			t.Fatalf("printed signed output: %q", result.out)
		}
	}
	if winners != 1 {
		t.Fatalf("%d race winners, want one", winners)
	}
	verified, err := trust.ReadSignedFile(output, []trust.AuthorityKey{key})
	if err != nil || verified.Payload.Previous == nil || *verified.Payload.Previous != parent.Digest {
		t.Fatalf("race winner's file: %+v, %v", verified, err)
	}
	if info, err := os.Stat(output); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("race winner's file mode %v: %v", info, err)
	}
}

func TestTrustSigningRejectsMalformedAuthoredJSON(t *testing.T) {
	keyPath, input, public := trustSigningFixture(t)
	parent := filepath.Join(t.TempDir(), "parent.cose")
	if _, _, err := runTrustCommand("trust", "init", "--key", keyPath, "--out", parent, input); err != nil {
		t.Fatal(err)
	}
	invalidPad := strings.TrimSuffix(vectorAuthority, "c=") + "d="
	for _, test := range []struct {
		name, body string
	}{
		{"duplicate", `{"nodes":[],"nodes":[]}`},
		{"case twin", `{"Nodes":[],"nodes":[]}`},
		{"unknown", `{"nodes":[],"unexpected":true}`},
		{"null", `{"nodes":null}`},
		{"base64 pad bits", `{"nodes":[{"endpoints":[],"key":"` + invalidPad + `","name":"example/gateway"}]}`},
		{"missing endpoints", `{"nodes":[{"name":"example/gateway"}]}`},
		{"missing name", `{"nodes":[{"endpoints":[]}]}`},
		{"node names under case folding", `{"nodes":[{"endpoints":[],"name":"example/gateway"},{"endpoints":[],"name":"example/GATEWAY"}]}`},
		{"key shared across organizations", `{"nodes":[{"endpoints":[],"key":"` + public + `","name":"example/gateway"},{"endpoints":[],"key":"` + public + `","name":"other/relay"}]}`},
		{"empty endpoint id", `{"nodes":[{"endpoints":[{"family":"ip4","id":"","port":1}],"name":"example/gateway"}]}`},
		{"long endpoint id", `{"nodes":[{"endpoints":[{"family":"ip4","id":"` + strings.Repeat("x", 65) + `","port":1}],"name":"example/gateway"}]}`},
		{"doubled endpoint spaces", `{"nodes":[{"endpoints":[{"family":"ip4","id":"a  b","port":1}],"name":"example/gateway"}]}`},
		{"endpoint id case twin", `{"nodes":[{"endpoints":[{"family":"ip4","id":"Edge","port":1},{"family":"ip4","id":"edge","port":1}],"name":"example/gateway"}]}`},
		{"invalid family", `{"nodes":[{"endpoints":[{"family":"ip5","port":1}],"name":"example/gateway"}]}`},
		{"zero port", `{"nodes":[{"endpoints":[{"family":"ip4","port":0}],"name":"example/gateway"}]}`},
		{"large port", `{"nodes":[{"endpoints":[{"family":"ip4","port":65536}],"name":"example/gateway"}]}`},
		{"empty address", `{"nodes":[{"endpoints":[{"address":"","family":"ip4","port":1}],"name":"example/gateway"}]}`},
		{"zone in address", `{"nodes":[{"endpoints":[{"address":"2001:db8::1%lo","family":"ip6","port":1}],"name":"example/gateway"}]}`},
		{"mapped address", `{"nodes":[{"endpoints":[{"address":"::ffff:192.0.2.1","family":"ip6","port":1}],"name":"example/gateway"}]}`},
		{"noncanonical ip4", `{"nodes":[{"endpoints":[{"address":"192.000.002.001","family":"ip4","port":1}],"name":"example/gateway"}]}`},
		{"numeric hostname", `{"nodes":[{"endpoints":[{"address":"12345","family":"ip4","port":1}],"name":"example/gateway"}]}`},
		{"invalid alabel", `{"nodes":[{"endpoints":[{"address":"xn--","family":"ip4","port":1}],"name":"example/gateway"}]}`},
		{"nonprintable id", `{"nodes":[{"endpoints":[{"family":"ip4","id":"\u00e9","port":1}],"name":"example/gateway"}]}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := os.WriteFile(input, []byte(test.body), 0600); err != nil {
				t.Fatal(err)
			}
			for _, verb := range []string{"init", "sign"} {
				output := filepath.Join(t.TempDir(), "signed.cose")
				args := []string{"trust", verb, "--key", keyPath, "--out", output}
				if verb == "sign" {
					args = append(args, "--previous", parent, "--authority", public)
				}
				out, stderr, err := runTrustCommand(append(args, input)...)
				if err == nil || out != "" || !strings.Contains(stderr, input) {
					t.Fatalf("%s accepted %s: stdout %q, stderr %q, error %v", verb, test.name, out, stderr, err)
				}
				if _, err := os.Lstat(output); !os.IsNotExist(err) {
					t.Fatalf("%s left output after %s: %v", verb, test.name, err)
				}
			}
		})
	}
}

func TestTrustSignAuthoritySources(t *testing.T) {
	keyPath, input, public := trustSigningFixture(t)
	directory := t.TempDir()
	parent := filepath.Join(directory, "parent.cose")
	output := filepath.Join(directory, "successor.cose")
	stateDir := filepath.Join(directory, "state")
	if err := os.Mkdir(stateDir, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_STATE_HOME", stateDir)
	store := filepath.Join(stateDir, "trust.store")
	sentinel := []byte("not a signed trust document")
	if err := os.WriteFile(store, sentinel, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runTrustCommand("trust", "init", "--key", keyPath, "--out", parent, input); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(directory, "trust.toml")
	configuration := fmt.Sprintf("node = \"example/laptop\"\n[auth]\nkey = \"key.pem\"\ntrust = %q\nauthority = [%q]\n[link]\nport = 13000\nendpoints = [{serial = \"0\", family = \"ip4\"}]\n[dial]\nall = true\n", store, public)
	if err := os.WriteFile(configPath, []byte(configuration), 0600); err != nil {
		t.Fatal(err)
	}
	out, stderr, err := runTrustCommand("trust", "sign", "--key", keyPath, "--previous", parent, "--config", configPath, "--out", output, input)
	if err != nil || out != "" || !strings.HasPrefix(stderr, "height 2\nprevious ") {
		t.Fatalf("config-only parent: stdout %q, stderr %q, error %v", out, stderr, err)
	}
	if after, err := os.ReadFile(store); err != nil || !bytes.Equal(after, sentinel) {
		t.Fatalf("sign changed state trust file: %v", err)
	}
	if entries, err := os.ReadDir(stateDir); err != nil || len(entries) != 1 {
		t.Fatalf("sign created state files: %v, %v", entries, err)
	}
	if err := os.Remove(output); err != nil {
		t.Fatal(err)
	}
	_, other := writeTrustTestKey(t, filepath.Join(directory, "other.pem"), 0x43)
	out, stderr, err = runTrustCommand("trust", "sign", "--key", keyPath, "--previous", parent, "--config", configPath, "--authority", other, "--out", output, input)
	if err == nil || out != "" || stderr != parent+": parent does not verify under the key given\n" {
		t.Fatalf("sign ignored explicit authority: stdout %q, stderr %q, error %v", out, stderr, err)
	}
	configuration = strings.Replace(configuration, fmt.Sprintf("%q", public), fmt.Sprintf("%q", other), 1)
	if err := os.WriteFile(configPath, []byte(configuration), 0600); err != nil {
		t.Fatal(err)
	}
	out, stderr, err = runTrustCommand("trust", "sign", "--key", keyPath, "--previous", parent, "--config", configPath, "--out", output, input)
	if err == nil || out != "" || stderr != parent+": parent does not verify under the eligible keys of "+configPath+"\n" {
		t.Fatalf("sign accepted wrong configured authority: stdout %q, stderr %q, error %v", out, stderr, err)
	}
	if err := os.WriteFile(configPath, []byte("not valid configuration"), 0600); err != nil {
		t.Fatal(err)
	}
	out, stderr, err = runTrustCommand("trust", "sign", "--key", keyPath, "--previous", parent, "--config", configPath, "--authority", public, "--out", output, input)
	if err == nil || out != "" || !strings.Contains(stderr, configPath) {
		t.Fatalf("sign ignored invalid named configuration: stdout %q, stderr %q, error %v", out, stderr, err)
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatalf("failed source left output: %v", err)
	}
}

func TestTrustReadRefusalClasses(t *testing.T) {
	path, _ := trustVector(t)
	for _, verb := range []string{"show", "verify"} {
		out, stderr, err := runTrustCommand("trust", verb, path)
		if err == nil || out != "" || stderr != "no authority key: supply --authority or --config\n" {
			t.Fatalf("%s missing source: stdout %q, stderr %q, error %v", verb, out, stderr, err)
		}
	}
	file, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	file[len(file)-1] ^= 1
	if err := os.WriteFile(path, file, 0600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ verb, message string }{
		{"show", ": bad signature, payload not decoded\n"},
		{"verify", ": signature does not verify under the key given\n"},
	} {
		out, stderr, err := runTrustCommand("trust", test.verb, "--authority", vectorAuthority, path)
		if err == nil || out != "" || stderr != path+test.message {
			t.Fatalf("%s bad signature: stdout %q, stderr %q, error %v", test.verb, out, stderr, err)
		}
	}
	file[len(file)-1] ^= 1
	for _, test := range []struct {
		name string
		body []byte
		want string
	}{
		{"CBOR map", []byte{0xa0}, ": malformed input: not a COSE_Sign1 under tag 18\n"},
		{"JSON", []byte(`{"nodes":[]}`), ": malformed input: not a COSE_Sign1 under tag 18\n"},
		{"empty", nil, ": malformed input: not a COSE_Sign1 under tag 18\n"},
		{"tagged with no protected header", []byte{0xd2, 0x84, 0xa0}, ": malformed envelope\n"},
		{"tagged with wrong protected header", []byte{0xd2, 0x84, 0x40}, ": malformed envelope\n"},
		{"tagged with no unprotected header", append([]byte{0xd2, 0x84}, file[2:43]...), ": malformed envelope\n"},
		{"tagged with no payload", append(append([]byte{0xd2, 0x84}, file[2:43]...), 0xa0, 0xa0), ": malformed envelope\n"},
		{"tagged with no signature", file[:71], ": malformed envelope\n"},
		{"tagged with truncated signature", file[:len(file)-1], ": malformed envelope\n"},
		{"tagged with trailing bytes", append(append([]byte(nil), file...), 0), ": malformed envelope\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := os.WriteFile(path, test.body, 0600); err != nil {
				t.Fatal(err)
			}
			for _, verb := range []string{"show", "verify"} {
				out, stderr, err := runTrustCommand("trust", verb, "--authority", vectorAuthority, path)
				if err == nil || out != "" || stderr != path+test.want {
					t.Fatalf("%s: stdout %q, stderr %q, error %v, want %q", verb, out, stderr, err, path+test.want)
				}
			}
		})
	}
}
