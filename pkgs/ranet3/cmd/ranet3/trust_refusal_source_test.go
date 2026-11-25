// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestTrustShowRefusalClasses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trust.cose")
	file, err := hex.DecodeString(vectorFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, file, 0600); err != nil {
		t.Fatal(err)
	}
	out, stderr, err := runTrustCommand("trust", "show", path)
	if err == nil || out != "" || stderr != "no authority key: supply --authority or --config\n" {
		t.Fatalf("show missing authority: stdout %q, stderr %q, error %v", out, stderr, err)
	}
	file[len(file)-1] ^= 1
	if err := os.WriteFile(path, file, 0600); err != nil {
		t.Fatal(err)
	}
	out, stderr, err = runTrustCommand("trust", "show", "--authority", vectorAuthority, path)
	if err == nil || out != "" || stderr != path+": bad signature, payload not decoded\n" {
		t.Fatalf("show bad signature: stdout %q, stderr %q, error %v", out, stderr, err)
	}
	if err := os.WriteFile(path, []byte{0xff}, 0600); err != nil {
		t.Fatal(err)
	}
	out, stderr, err = runTrustCommand("trust", "show", "--authority", vectorAuthority, path)
	if err == nil || out != "" || stderr != path+": malformed input: not a COSE_Sign1 under tag 18\n" {
		t.Fatalf("show malformed input: stdout %q, stderr %q, error %v", out, stderr, err)
	}
}
