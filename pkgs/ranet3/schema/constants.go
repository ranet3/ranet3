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
