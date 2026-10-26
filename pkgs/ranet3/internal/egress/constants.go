// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package egress

import (
	"math"
	"time"
)

const (
	// DefaultSweep is the periodic pass a capability that names none takes.
	DefaultSweep = 30 * time.Second
	// DefaultFlowsPerSource is the share of an exit's flows a capability that
	// names none gives each mesh source address in each family, every
	// backend's, so that the open flows one source holds through the exit take
	// at most that much of the host's connection table.
	DefaultFlowsPerSource = 4096
	// MaxFlowsPerSource is the largest share a capability may name. A share is
	// part of the host's connection table, whose size the kernel takes from
	// nf_conntrack_max up to INT_MAX and no further, so a share past it would
	// refuse nothing on any host.
	MaxFlowsPerSource = math.MaxInt32
)
