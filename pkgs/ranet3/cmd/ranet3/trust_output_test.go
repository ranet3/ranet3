// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ranet3.com/pkgs/ranet3/trust"
)

func runTrustWithPublisher(verb string, publish func(string, []byte, fs.FileMode) error, args ...string) (string, string, error) {
	root := newRoot()
	group, _, _ := root.Find([]string{"trust"})
	original, _, _ := root.Find([]string{"trust", verb})
	group.RemoveCommand(original)
	if verb == "init" {
		group.AddCommand(trustInitWithPublish(publish))
	} else {
		group.AddCommand(trustSignWithPublish(publish))
	}
	var out, stderr strings.Builder
	root.SetOut(&out)
	root.SetErr(&stderr)
	root.SetArgs(append([]string{"trust", verb}, args...))
	err := root.Execute()
	if err != nil {
		fmt.Fprintln(&stderr, err)
	}
	return out.String(), stderr.String(), err
}

func TestTrustSigningPublisherError(t *testing.T) {
	keyPath, input, public := trustSigningFixture(t)
	parent := filepath.Join(t.TempDir(), "parent.cose")
	if _, _, err := runTrustCommand("trust", "init", "--key", keyPath, "--out", parent, input); err != nil {
		t.Fatal(err)
	}
	parentBody, err := os.ReadFile(parent)
	if err != nil {
		t.Fatal(err)
	}
	key, err := trust.ParseAuthorityKey(public)
	if err != nil {
		t.Fatal(err)
	}
	for _, verb := range []string{"init", "sign"} {
		t.Run(verb, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "signed.cose")
			fault := errors.New("publication failed")
			calls := 0
			publish := func(path string, raw []byte, mode fs.FileMode) error {
				calls++
				if path != output || mode != 0600 {
					t.Fatalf("publisher received %s with mode %o", path, mode)
				}
				if _, err := trust.VerifySignedFile(raw, []trust.AuthorityKey{key}); err != nil {
					t.Fatalf("publisher received incomplete signed bytes: %v", err)
				}
				return fault
			}
			args := []string{"--key", keyPath, "--out", output}
			if verb == "sign" {
				args = append(args, "--previous", parent, "--authority", public)
			}
			out, stderr, err := runTrustWithPublisher(verb, publish, append(args, input)...)
			if calls != 1 || !errors.Is(err, fault) || out != "" || stderr != output+": publish signed output: publication failed\n" {
				t.Fatalf("%s: calls %d, stdout %q, stderr %q, error %v", verb, calls, out, stderr, err)
			}
			if _, err := os.Lstat(output); !os.IsNotExist(err) {
				t.Fatalf("publisher refusal left an output: %v", err)
			}
			if after, err := os.ReadFile(parent); err != nil || !bytes.Equal(after, parentBody) {
				t.Fatalf("failure altered parent: %v", err)
			}
		})
	}
}
