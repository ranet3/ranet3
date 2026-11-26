// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package trust

import "testing"

func orderSnapshot(height uint64, digest byte, mesh MeshID, previous *[32]byte) *Verified {
	v := &Verified{Payload: Payload{Height: height, Previous: previous, Mesh: mesh}}
	v.Digest[0] = digest
	return v
}

func TestOrderFirstHoldingCondition(t *testing.T) {
	mesh := MeshID{6: 0x70, 8: 0x80}
	other := mesh
	other[0] = 1
	s := orderSnapshot(4, 1, mesh, nil)
	parent := s.Digest
	wrong := [32]byte{9}
	for _, test := range []struct {
		name string
		in   OrderInput
		want Row
	}{
		{"first", OrderInput{Start: true, Offered: orderSnapshot(1, 1, mesh, nil)}, D2},
		{"empty", OrderInput{Start: true}, D1},
		{"unreadable before cap", OrderInput{Start: true, StoreUnreadable: true, CapRefused: true}, D14},
		{"cap before overlap", OrderInput{Start: true, CapRefused: true, Overlap: true}, C1},
		{"overlap before config", OrderInput{Held: s, Overlap: true, ConfigChecksRefused: true}, D16},
		{"config before order", OrderInput{Held: s, ConfigChecksRefused: true, Offered: orderSnapshot(5, 2, mesh, &parent)}, D19},
		{"same copy", OrderInput{Held: s, HeldSignerEligible: true, Offered: orderSnapshot(4, 1, mesh, &parent)}, D3},
		{"older", OrderInput{Held: s, HeldSignerEligible: true, Offered: orderSnapshot(3, 2, mesh, &parent)}, D4},
		{"other mesh before older", OrderInput{Held: s, HeldSignerEligible: true, Offered: orderSnapshot(3, 2, other, &parent)}, D12},
		{"conflict", OrderInput{Held: s, HeldSignerEligible: true, Offered: orderSnapshot(4, 2, mesh, &parent)}, D5},
		{"wrong parent", OrderInput{Held: s, HeldSignerEligible: true, Offered: orderSnapshot(5, 2, mesh, &wrong)}, D6},
		{"successor", OrderInput{Held: s, HeldSignerEligible: true, Offered: orderSnapshot(5, 2, mesh, &parent)}, D7},
		{"jump", OrderInput{Held: s, HeldSignerEligible: true, Offered: orderSnapshot(6, 2, mesh, &wrong)}, D8},
		{"retired same copy", OrderInput{Held: s, Offered: orderSnapshot(4, 1, mesh, &parent)}, D20},
		{"retired older", OrderInput{Held: s, Offered: orderSnapshot(3, 2, mesh, &parent)}, D22},
		{"retired wrong parent", OrderInput{Held: s, Offered: orderSnapshot(5, 2, mesh, &wrong)}, D23},
		{"compromised floorless", OrderInput{Held: s, HeldSignerCompromised: true, Offered: orderSnapshot(5, 2, mesh, &parent)}, D24},
		{"compromised below raised entry", OrderInput{Held: s, HeldSignerCompromised: true, Floor: 2, EntryHeight: 6, Offered: orderSnapshot(5, 2, mesh, &parent)}, D24},
		{"compromised another mesh", OrderInput{Held: s, HeldSignerCompromised: true, Floor: 5, Offered: orderSnapshot(3, 2, other, &parent)}, D24},
		{"recovery below held", OrderInput{Held: s, HeldSignerCompromised: true, Floor: 2, EntryHeight: 3, Offered: orderSnapshot(3, 2, mesh, &parent)}, D9},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := Order(test.in); got != test.want {
				t.Fatalf("first row %s, want %s", got, test.want)
			}
		})
	}
}
