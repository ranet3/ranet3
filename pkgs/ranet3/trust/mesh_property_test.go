// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package trust

import (
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

func TestMeshUUIDProfileProperty(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		version := hegel.Draw(ht, pbt.Spanning(0, 15))
		variant := hegel.Draw(ht, pbt.Spanning(0, 3))
		id := MeshID{0x01, 0x8e, 0x8c, 0xf0, 0x33, 0x20, byte(version<<4 | 0x0a), 0xbc, byte(variant<<6 | 0x0d), 0xef}
		want := version == 7 && variant == 2
		if err := id.Validate(); (err == nil) != want {
			ht.Fatalf("version %d, variant %d, mesh %x: %v, want valid %v", version, variant, id, err, want)
		}
	})
}
