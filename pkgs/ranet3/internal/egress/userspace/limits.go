// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package userspace

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// Limits bounds what the exit holds. Each platform's selection file passes
// Within's answer, so no setting picks one.
type Limits struct {
	// Budget is the bytes the exit may hold, and From where it came
	Budget int64
	From   BudgetSource
	// Flows is the most TCP connections, UDP mappings and echo mappings open
	// at once, each source's share of cap.egress inside it
	Flows int
	// Connections is the most TCP connections open at once, the flows that
	// hold gVisor's buffers
	Connections int
	// Dials is the most TCP connections being dialed at once, below the
	// forwarder's in-flight bound
	Dials int
	// TimeWait is the most leaf-side TCP endpoints in TIME_WAIT, the oldest
	// closed past it
	TimeWait int
	// Window is the default and the most bytes one TCP flow's gVisor buffer
	// holds in each direction
	Window int
	// Lanes is the bytes all lanes hold from the sessions, and Link the bytes
	// the stack's link holds toward the lanes
	Lanes, Link int64
}

// BudgetSource names the figure a budget was taken from: half of Go's memory
// limit, or a share of the host's physical memory where no Go limit is set
type BudgetSource int

const (
	// FromGoLimit is a budget of half of Go's memory limit
	FromGoLimit BudgetSource = iota + 1
	// FromHost is a budget of a share of the host's physical memory
	FromHost
)

// check refuses limits under which the exit would hold nothing: a count or a
// queue of zero, and a window below the least buffer gVisor's TCP takes
func (l Limits) check() error {
	for _, bound := range []struct {
		name  string
		value int64
	}{
		{"flows", int64(l.Flows)}, {"connections", int64(l.Connections)}, {"dials", int64(l.Dials)},
		{"TIME_WAIT endpoints", int64(l.TimeWait)}, {"lanes' bytes", l.Lanes}, {"link's bytes", l.Link},
	} {
		if bound.value <= 0 {
			return fmt.Errorf("egress: the userspace exit's limit of %s is %d, so it would carry nothing", bound.name, bound.value)
		}
	}
	if l.Window < tcp.MinBufferSize {
		return fmt.Errorf("egress: the userspace exit's window of %d bytes is below the %d a TCP buffer holds at least", l.Window, tcp.MinBufferSize)
	}
	return nil
}
