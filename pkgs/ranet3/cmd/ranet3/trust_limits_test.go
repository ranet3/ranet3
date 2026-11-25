// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ranet3.com/pkgs/ranet3/trust"
)

func TestTrustSigningEntryLimits(t *testing.T) {
	keyPath, input, public := trustSigningFixture(t)
	parent := filepath.Join(t.TempDir(), "parent.cose")
	if _, _, err := runTrustCommand("trust", "init", "--key", keyPath, "--out", parent, input); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"nodes", "endpoints"} {
		var body strings.Builder
		if field == "nodes" {
			body.WriteString(`{"nodes":[`)
			for i := range trust.MaxEntries + 1 {
				if i > 0 {
					body.WriteByte(',')
				}
				fmt.Fprintf(&body, `{"endpoints":[],"name":"example/n%d"}`, i)
			}
			body.WriteString(`]}`)
		} else {
			body.WriteString(`{"nodes":[{"endpoints":[`)
			for i := range trust.MaxEntries + 1 {
				if i > 0 {
					body.WriteByte(',')
				}
				body.WriteString(`{"family":"ip4","port":1}`)
			}
			body.WriteString(`],"name":"example/gateway"}]}`)
		}
		if err := os.WriteFile(input, []byte(body.String()), 0600); err != nil {
			t.Fatal(err)
		}
		for _, verb := range []string{"init", "sign"} {
			output := filepath.Join(t.TempDir(), "output.cose")
			args := []string{"trust", verb, "--key", keyPath, "--out", output}
			if verb == "sign" {
				args = append(args, "--previous", parent, "--authority", public)
			}
			out, stderr, err := runTrustCommand(append(args, input)...)
			if err == nil || out != "" || !strings.Contains(stderr, "131072") {
				t.Fatalf("%s accepted %d %s: stdout %q, stderr %q, error %v", verb, trust.MaxEntries+1, field, out, stderr, err)
			}
			if _, err := os.Lstat(output); !os.IsNotExist(err) {
				t.Fatalf("%s published over-limit %s: %v", verb, field, err)
			}
		}
	}
}
