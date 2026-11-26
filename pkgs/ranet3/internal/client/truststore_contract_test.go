// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/fxamacker/cbor/v2"
	trustdoc "ranet3.com/pkgs/ranet3/trust"
)

func TestTrustClosedStoreRefusalsLeavePathBytes(t *testing.T) {
	f := localTrustFixtureOf(t)
	mode, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		t.Fatal(err)
	}
	encode := func(v any) []byte {
		t.Helper()
		body, err := mode.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	for _, test := range []struct {
		name string
		body []byte
	}{
		{"only signed", encode(map[uint64]any{1: f.first, 3: []any{}})},
		{"only signer", encode(map[uint64]any{2: f.oldKey.DER, 3: []any{}})},
		{"unknown top", encode(map[uint64]any{3: []any{}, 4: uint64(1)})},
		{"missing list", encode(map[uint64]any{1: f.first, 2: f.oldKey.DER})},
		{"wrong list type", encode(map[uint64]any{3: "not an array"})},
		{"wrong key type", encode(map[uint64]any{3: []any{map[uint64]any{1: "not bytes"}}})},
		{"wrong floor type", encode(map[uint64]any{3: []any{map[uint64]any{1: f.oldKey.DER, 2: "not uint"}}})},
		{"zero floor", encode(map[uint64]any{3: []any{map[uint64]any{1: f.oldKey.DER, 2: uint64(0)}}})},
		{"overheight floor", encode(map[uint64]any{3: []any{map[uint64]any{1: f.oldKey.DER, 2: trustdoc.MaxHeight + 1}}})},
		{"unknown entry", encode(map[uint64]any{3: []any{map[uint64]any{1: f.oldKey.DER, 4: uint64(1)}}})},
		{"duplicate top", []byte{0xa2, 0x03, 0x80, 0x03, 0x80}},
		{"duplicate entry", append(append([]byte{0xa1, 0x03, 0x81, 0xa2, 0x01, 0x58, byte(len(f.oldKey.DER))}, f.oldKey.DER...), append([]byte{0x01, 0x58, byte(len(f.oldKey.DER))}, f.oldKey.DER...)...)},
		{"noncanonical", []byte{0xb8, 0x01, 0x03, 0x80}},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(f.dir, trustStoreName)
			if err := os.WriteFile(path, test.body, 0600); err != nil {
				t.Fatal(err)
			}
			result, err := LoadTrust(f.cfg, f.dir, nil, nil, nil)
			if err != nil || result.Row != trustdoc.D14 || result.Record != nil || result.Status(f.cfg) != nil {
				t.Fatalf("D14: %+v, %v", result, err)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(after, test.body) {
				t.Fatalf("D14 changed bytes: %x, %v", after, err)
			}
		})
	}
}

func TestTrustStorePathReaderCapBeforeDecode(t *testing.T) {
	f := localTrustFixtureOf(t)
	path := filepath.Join(f.dir, trustStoreName)
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(int64(trustdoc.MaxStoreBytes + 1)); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, present, err := readTrustStore(path); err == nil || present {
		t.Fatalf("capped path read: present %t, %v", present, err)
	}
	result, err := LoadTrust(f.cfg, f.dir, nil, nil, nil)
	if err != nil || result.Row != trustdoc.D14 {
		t.Fatalf("oversized path: %+v, %v", result, err)
	}
	stat, err := os.Stat(path)
	if err != nil || stat.Size() != int64(trustdoc.MaxStoreBytes+1) {
		t.Fatalf("path changed: %+v, %v", stat, err)
	}
}
