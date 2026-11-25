// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
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

func TestTrustShowFacts(t *testing.T) {
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
