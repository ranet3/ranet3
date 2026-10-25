// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package schema

// The shortest prefix a list of the mesh's own sources takes, per family, an
// egress segment's allow list and the border filter's overlay alike. The floor
// is the unit IANA delegates to a regional registry, so a shorter entry holds
// addresses the mesh has nothing to do with.
const (
	MinSourceBits4 = 8
	MinSourceBits6 = 12
)

// The shortest prefix outside the overlay that the mesh routes as a subnet, per
// family. A shorter one counts as a default (see CapturesTheMachine): it takes
// a host's own traffic as a default does, a split internet such as four /2s or
// 2000::/3 among them, and makes the node advertising it an exit. No
// deployment routes a mesh subnet outside its overlay wider than either.
const (
	MinSubnetBits4 = 8
	MinSubnetBits6 = 16
)

// UnderlayMark is SO_MARK on every socket carrying IKE and ESP, on linux.
const UnderlayMark uint32 = 0x726c
