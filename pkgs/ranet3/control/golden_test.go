// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package control

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the golden files under testdata/debug from what the code writes now")

// golden holds got to testdata/debug/name, or writes it there under -update
func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", "debug", name)
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v, and go test ./control -update writes it", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s no longer matches, and go test ./control -update rewrites it\n--- golden\n%s\n--- now\n%s", path, want, got)
	}
}

// goldenJSON holds a value's wire form, indented as --json prints it
func goldenJSON(t *testing.T, name string, value any) {
	t.Helper()
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	golden(t, name, append(body, '\n'))
}
