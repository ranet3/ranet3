// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package srv6

// The shortest prefix an egress segment's allow list takes, per family. The
// floor is the unit IANA delegates to a regional registry, so a shorter entry
// admits holders the mesh has nothing to do with.
const (
	minAllowBits4 = 8
	minAllowBits6 = 12
)
