// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTrustBoundedPathReaderAtAndBeyondSmallLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bounded.store")
	body := []byte("012345678")
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readTrustBytes(path, 8); err == nil || !strings.Contains(err.Error(), "exceeds its size limit") {
		t.Fatalf("nine bytes at eight-byte cap: %v", err)
	}
	if got, err := readTrustBytes(path, 9); err != nil || !bytes.Equal(got, body) {
		t.Fatalf("exact nine-byte cap: %q, %v", got, err)
	}
	if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, body) {
		t.Fatalf("bounded read changed path: %q, %v", got, err)
	}
}
