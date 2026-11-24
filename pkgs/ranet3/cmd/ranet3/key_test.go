// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ranet3.com/pkgs/ranet3/trust"
)

func TestKeyGenerateContract(t *testing.T) {
	for _, keyType := range []string{"ed25519", "p256", "p384"} {
		t.Run(keyType, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "authority.pem")
			out, err := execute(t, "key", "generate", "--type", keyType, "--out", path)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasSuffix(out, "\n") || strings.Count(out, "\n") != 1 {
				t.Fatalf("public key output %q", out)
			}
			key, err := trust.ParseAuthorityKey(strings.TrimSuffix(out, "\n"))
			if err != nil {
				t.Fatalf("public key output %q: %v", out, err)
			}
			private, loaded, err := trust.LoadAuthorityPrivateKey(path)
			if err != nil || private == nil || !bytes.Equal(loaded.DER, key.DER) {
				t.Fatalf("private key does not match output: %v", err)
			}
			stat, err := os.Stat(path)
			if err != nil || stat.Mode().Perm() != 0600 {
				t.Fatalf("key file mode %v, error %v", stat, err)
			}
			second, err := execute(t, "key", "generate", "--type", keyType, "--out", path)
			if !errors.Is(err, os.ErrExist) || second != "" {
				t.Fatalf("existing key replaced or public key printed: output %q, error %v", second, err)
			}
		})
	}
}

func TestKeyGeneratePublisherError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authority.pem")
	fault := errors.New("publication failed")
	calls := 0
	publish := func(got string, body []byte, mode fs.FileMode) error {
		calls++
		if got != path || mode != 0600 || len(body) == 0 {
			t.Fatalf("publisher received path %q, mode %o, bytes %d", got, mode, len(body))
		}
		return fault
	}
	command := keyCommandWithPublish(publish)
	command.SilenceErrors = true
	command.SilenceUsage = true
	var out strings.Builder
	command.SetOut(&out)
	command.SetErr(&out)
	command.SetArgs([]string{"generate", "--type", "ed25519", "--out", path})
	err := command.Execute()
	if calls != 1 || !errors.Is(err, fault) {
		t.Fatalf("key generate: publisher calls %d, error %v", calls, err)
	}
	if out.Len() != 0 {
		t.Fatalf("printed public key after publication error: %q", out.String())
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("publisher refusal left a key: %v", err)
	}
}

func TestKeyGenerateRefusesMissingAndUnknownFlags(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authority.pem")
	for _, args := range [][]string{
		{"key", "generate", "--out", path},
		{"key", "generate", "--type", "ed25519"},
		{"key", "generate", "--type", "p521", "--out", path},
		{"key", "generate", "--type", "P256", "--out", path},
		{"key", "generate", "--type", "ed25519", "--out", path, "--force"},
	} {
		out, err := execute(t, args...)
		if err == nil || out != "" {
			t.Fatalf("arguments %q: output %q, error %v", args, out, err)
		}
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("arguments %q created output path: %v", args, err)
		}
	}
}
