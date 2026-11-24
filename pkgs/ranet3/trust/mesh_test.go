// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package trust

import (
	"bytes"
	"testing"
)

func TestMeshUUIDProfile(t *testing.T) {
	valid := MeshID{0x01, 0x8e, 0x8c, 0xf0, 0x33, 0x20, 0x7a, 0xbc, 0x8d, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := valid.String(); got != "018e8cf0-3320-7abc-8def-0123456789ab" {
		t.Fatalf("mesh text %q", got)
	}
	for name, bad := range map[string]MeshID{
		"nil":     {},
		"max":     {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		"version": {0x01, 0x8e, 0x8c, 0xf0, 0x33, 0x20, 0x4a, 0xbc, 0x8d, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab},
		"variant": {0x01, 0x8e, 0x8c, 0xf0, 0x33, 0x20, 0x7a, 0xbc, 0x4d, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab},
	} {
		t.Run(name, func(t *testing.T) {
			if err := bad.Validate(); err == nil {
				t.Fatalf("accepted mesh %x", bad)
			}
		})
	}
}

func TestMeshUUIDGenerationFields(t *testing.T) {
	random := []byte{0, 0, 0, 0, 0, 0, 0xfa, 0xbc, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab}
	id, err := newMeshID(0x018e8cf03320, bytes.NewReader(random))
	if err != nil {
		t.Fatal(err)
	}
	want := MeshID{0x01, 0x8e, 0x8c, 0xf0, 0x33, 0x20, 0x7a, 0xbc, 0x8d, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab}
	if id != want {
		t.Fatalf("UUIDv7 generation %x, want %x", id, want)
	}
	if _, err := newMeshID(0, bytes.NewReader(random[:2])); err == nil {
		t.Fatal("accepted truncated entropy")
	}
	for _, bad := range []int64{-1, 1 << 48} {
		if _, err := newMeshID(bad, bytes.NewReader(random)); err == nil {
			t.Fatalf("accepted out-of-range timestamp %d", bad)
		}
	}
}

func TestNewMeshUUID(t *testing.T) {
	first, err := NewMeshID()
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewMeshID()
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := second.Validate(); err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("two new meshes received the same UUID")
	}
}
