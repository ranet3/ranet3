// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package trust

import (
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

func TestOrderIndependentConditionModel(t *testing.T) {
	mesh := MeshID{6: 0x70, 8: 0x80}
	other := mesh
	other[0]++
	held := orderSnapshot(4, 1, mesh, nil)
	pbt.Check(t, func(ht *hegel.T) {
		signer := hegel.Draw(ht, pbt.Spanning(0, 2)) // eligible, retired, compromised
		height := hegel.Draw(ht, pbt.Spanning(0, 8))
		meshChoice := hegel.Draw(ht, pbt.Spanning(0, 1))
		parentChoice := hegel.Draw(ht, pbt.Spanning(0, 2))
		sameDigest := hegel.Draw(ht, pbt.Spanning(0, 1))
		floor := hegel.Draw(ht, pbt.Spanning(0, 6))
		entry := hegel.Draw(ht, pbt.Spanning(0, 6))
		var offered *Verified
		if height != 0 {
			var parent *[32]byte
			match := held.Digest
			wrong := [32]byte{3}
			switch parentChoice {
			case 0:
				parent = &match
			case 1:
				parent = &wrong
			}
			fileMesh := mesh
			if meshChoice == 1 {
				fileMesh = other
			}
			digest := byte(2)
			if sameDigest == 1 {
				digest = 1
			}
			offered = orderSnapshot(uint64(height), digest, fileMesh, parent)
		}
		in := OrderInput{Held: held, Offered: offered, HeldSignerEligible: signer == 0, HeldSignerCompromised: signer == 2, Floor: uint64(floor), EntryHeight: uint64(entry)}
		f := offered != nil
		sameMesh := f && offered.Payload.Mesh == mesh
		equalHeight := f && offered.Payload.Height == held.Payload.Height
		older := f && offered.Payload.Height < held.Payload.Height
		next := f && offered.Payload.Height == held.Payload.Height+1
		parent := next && offered.Payload.Previous != nil && *offered.Payload.Previous == held.Digest
		twin := equalHeight && offered.Digest == held.Digest
		bound := max(uint64(floor), uint64(entry))
		conditions := []struct {
			row   Row
			holds bool
		}{
			{D9, signer == 2 && floor != 0 && sameMesh && offered.Payload.Height >= bound},
			{D24, signer == 2},
			{D13, signer == 0 && !f},
			{D11, signer == 1 && !f},
			{D12, f && !sameMesh},
			{D3, signer == 0 && twin},
			{D4, signer == 0 && older},
			{D5, signer == 0 && equalHeight && !twin},
			{D6, signer == 0 && next && !parent},
			{D7, signer == 0 && next && parent},
			{D8, signer == 0 && f && offered.Payload.Height > held.Payload.Height+1},
			{D20, signer == 1 && twin},
			{D22, signer == 1 && older},
			{D23, signer == 1 && (equalHeight && !twin || next && !parent)},
			{D21, signer == 1 && f && (next && parent || offered.Payload.Height > held.Payload.Height+1)},
		}
		var expected Row
		for _, condition := range conditions {
			if condition.holds {
				expected = condition.row
				break
			}
		}
		if actual := Order(in); expected == "" || actual != expected {
			ht.Fatalf("signer %d, height %d, mesh %d, parent %d, digest %d, floor %d, entry %d: first row %s, model %s", signer, height, meshChoice, parentChoice, sameDigest, floor, entry, actual, expected)
		}
	})
}
