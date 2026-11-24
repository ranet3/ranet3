// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux

package trust

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestAuthorityPrivateKeyInputBound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authority.pem")
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadAuthorityPrivateKey(path); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("FIFO was read: %v", err)
	}
	link := filepath.Join(t.TempDir(), "link.pem")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadAuthorityPrivateKey(link); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("FIFO link was read: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("not a key"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadAuthorityPrivateKey(link); err == nil || !strings.Contains(err.Error(), "one PKCS8 PEM block") {
		t.Fatalf("regular-file link was refused as nonregular: %v", err)
	}
	if err := os.Truncate(path, maxAuthorityPEMBytes+1); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadAuthorityPrivateKey(path); err == nil || !strings.Contains(err.Error(), "exceeds 65536 bytes at stat") {
		t.Fatalf("oversized key was read: %v", err)
	}
	info, err := os.Stat("/proc/self/smaps")
	if err != nil || !info.Mode().IsRegular() || info.Size() != 0 {
		t.Fatalf("short-stat regular input: %v, %v", info, err)
	}
	// Distinct protections keep smaps entries separate above the key-file cap.
	var mappings [][]byte
	defer func() {
		for _, mapping := range mappings {
			if err := syscall.Munmap(mapping); err != nil {
				t.Errorf("unmap fixture: %v", err)
			}
		}
	}()
	pageSize := os.Getpagesize()
	for i := range 256 {
		protection := syscall.PROT_READ
		if i%2 == 0 {
			protection = syscall.PROT_NONE
		}
		mapping, err := syscall.Mmap(-1, 0, pageSize, protection, syscall.MAP_ANON|syscall.MAP_PRIVATE)
		if err != nil {
			t.Fatal(err)
		}
		mappings = append(mappings, mapping)
	}
	body, err := os.ReadFile("/proc/self/smaps")
	if err != nil || len(body) <= maxAuthorityPEMBytes {
		t.Fatalf("short-stat fixture has %d bytes, need more than %d: %v", len(body), maxAuthorityPEMBytes, err)
	}
	if _, _, err := LoadAuthorityPrivateKey("/proc/self/smaps"); err == nil || !strings.Contains(err.Error(), "exceeds 65536 bytes at read") {
		t.Fatalf("short-stat overlong key was read: %v", err)
	}
}
