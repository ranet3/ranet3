// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTrustSignRequiresNamedFiles(t *testing.T) {
	key, input, public := trustSigningFixture(t)
	parent := filepath.Join(t.TempDir(), "parent.cose")
	if _, _, err := runTrustCommand("trust", "init", "--key", key, "--out", parent, input); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "successor.cose")
	for _, test := range []struct {
		name string
		args []string
		want string
	}{
		{"key", []string{"--previous", parent, "--authority", public, "--out", output}, "--key is required\n"},
		{"previous", []string{"--key", key, "--authority", public, "--out", output}, "--previous is required\n"},
		{"out", []string{"--key", key, "--previous", parent, "--authority", public}, "--out is required\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			out, stderr, err := runTrustCommand(append([]string{"trust", "sign"}, append(test.args, input)...)...)
			if err == nil || out != "" || stderr != test.want {
				t.Fatalf("sign without %s: stdout %q, stderr %q, error %v", test.name, out, stderr, err)
			}
			if _, err := os.Lstat(output); !os.IsNotExist(err) {
				t.Fatalf("sign without %s published output: %v", test.name, err)
			}
		})
	}
}
