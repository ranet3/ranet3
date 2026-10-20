// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

// Package goldentest holds what a test writes to a golden file, which go test
// -update rewrites from what the code writes now. Test files import it and
// nothing else does, and the one flag it registers serves every test binary
// that does.
package goldentest

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the golden files from what the code writes now")

// Check holds got to the file at path, relative to the directory the test runs
// in, or writes it there under -update. pkg is the package as go test names
// it, which a failure tells the reader to rewrite the file through.
func Check(tb testing.TB, pkg, path string, got []byte) {
	tb.Helper()
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			tb.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			tb.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		tb.Fatalf("%v, and go test %s -update writes it", err, pkg)
	}
	if !bytes.Equal(got, want) {
		tb.Errorf("%s no longer matches, and go test %s -update rewrites it\n--- golden\n%s\n--- now\n%s", path, pkg, want, got)
	}
}
