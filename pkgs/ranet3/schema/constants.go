// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package schema

import "time"

// The shortest prefix a list of the mesh's own sources takes, per family, an
// egress segment's allow list and the overlay alike. The floor
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

// MinPassInterval is the least interval cap.egress sweep and cap.table
// reconcile take. Each paces a pass that reads the host's tables again at
// every turn, changed or not, so a shorter one would read them more than once
// a second on a quiet host. Each also caps the backoff on which
// internal/kernel's RetryTimer retries a failed pass of the kernel exit or the
// reconciler, and one under the timer's first delay holds every retry at the
// period. The refusal names the value, so a unit written wrong, "30ns" for
// "30s", shows at load.
const MinPassInterval = time.Second

// UnderlayMark is SO_MARK, on linux and wherever the process may set it, on
// every socket carrying IKE and ESP and on a socket resolving an endpoint's
// name through a nameserver outside the overlay. Under each mask another
// program's rules read at its defaults it reads as an unmarked packet's mark
// does, or as a value none of those rules selects, as coexistence.md's "The
// underlay's mark" lists them.
const UnderlayMark uint32 = 0x72
