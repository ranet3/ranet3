// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux

package client

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// net.ipv4.ip_default_ttl is read as Linux shows it under /proc/sys
// and a missing setting, or one holding no TTL a router may send, 0 among them, refuses naming it
func TestDefaultTTLIsReadFromItsSetting(t *testing.T) {
	root := t.TempDir()
	if _, err := readDefaultTTL(root); err == nil || !strings.Contains(err.Error(), "net.ipv4.ip_default_ttl") {
		t.Errorf("a missing setting was read with the error %v", err)
	}
	path := filepath.Join(root, "net", "ipv4", "ip_default_ttl")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		written string
		want    uint8
	}{{"128\n", 128}, {"1\n", 1}, {"255\n", 255}, {"0\n", 0}, {"256\n", 0}, {"-1\n", 0}, {"\n", 0}} {
		if err := os.WriteFile(path, []byte(tc.written), 0o644); err != nil {
			t.Fatal(err)
		}
		ttl, err := readDefaultTTL(root)
		if ttl != tc.want || (err == nil) != (tc.want != 0) || err != nil && !strings.Contains(err.Error(), "net.ipv4.ip_default_ttl") {
			t.Errorf("the setting holding %q was read as %d with the error %v, want %d", tc.written, ttl, err, tc.want)
		}
	}
}
