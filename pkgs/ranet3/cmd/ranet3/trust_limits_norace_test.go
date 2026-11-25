// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !race

// The authored 256 MiB byte-limit row has no concurrency and peaks above 2.4 GiB under the race detector.

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ranet3.com/pkgs/ranet3/trust"
)

func TestTrustSigningAuthoredByteLimit(t *testing.T) {
	keyPath, input, public := trustSigningFixture(t)
	parent := filepath.Join(t.TempDir(), "parent.cose")
	if _, _, err := runTrustCommand("trust", "init", "--key", keyPath, "--out", parent, input); err != nil {
		t.Fatal(err)
	}
	for _, size := range []int64{trust.MaxJSONBytes, trust.MaxJSONBytes + 1} {
		if err := os.Truncate(input, size); err != nil {
			t.Fatal(err)
		}
		for _, verb := range []string{"init", "sign"} {
			output := filepath.Join(t.TempDir(), "output.cose")
			args := []string{"trust", verb, "--key", keyPath, "--out", output}
			if verb == "sign" {
				args = append(args, "--previous", parent, "--authority", public)
			}
			out, stderr, err := runTrustCommand(append(args, input)...)
			if err == nil || out != "" {
				t.Fatalf("%s read %d bytes: stdout %q, stderr %q, error %v", verb, size, out, stderr, err)
			}
			if strings.Contains(stderr, "exceeds 256 MiB") != (size > trust.MaxJSONBytes) {
				t.Fatalf("%s size %d wrong refusal: %q", verb, size, stderr)
			}
			if _, err := os.Lstat(output); !os.IsNotExist(err) {
				t.Fatalf("%s published refused JSON: %v", verb, err)
			}
		}
	}
}
