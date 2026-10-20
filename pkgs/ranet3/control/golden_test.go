// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package control

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/goldentest"
)

// golden holds got to testdata/debug/name, or writes it there under -update
func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	goldentest.Check(t, "./control", filepath.Join("testdata", "debug", name), got)
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
