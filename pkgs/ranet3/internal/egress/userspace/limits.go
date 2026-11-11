// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package userspace

import (
	"errors"
	"fmt"
	"math"

	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// Limits bounds what the exit holds. Each platform's selection file passes
// Within's answer, so no setting picks one.
type Limits struct {
	// Budget is the bytes the exit may hold, and From where it came
	Budget int64
	From   BudgetSource
	// Flows is the most TCP connections, UDP mappings and echo mappings open
	// at once and TCP connections held closed for a host socket (hostHolds),
	// each source's share of cap.egress inside it
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

// BudgetSource names the figure a budget was taken from: Go's memory limit,
// or a share of the host's physical memory where no Go limit is set
type BudgetSource int

const (
	// FromGoLimit is a budget of half of what Go's memory limit leaves past
	// the node's own heap
	FromGoLimit BudgetSource = iota + 1
	// FromHost is a budget of a share of the host's physical memory
	FromHost
)

// String names the share a budget is of
func (s BudgetSource) String() string {
	switch s {
	case FromGoLimit:
		return "half of what Go's memory limit leaves past the node's heap"
	case FromHost:
		return "a sixteenth of the host's memory"
	}
	return "no figure"
}

// Memory holds the figures that bound a process's memory: Go's limit,
// math.MaxInt64 where none is set, the host's physical memory, zero where the
// caller reads none, and Node, the most Go heap the node holds outside the
// exit, which shares Go's limit with it
type Memory struct {
	GoLimit  int64
	Physical uint64
	Node     int64
}

// Within is the limits a process can hold under memory, with files the most
// descriptors it may open. Go's limit L holds the exit's budget B twice, live
// and as the collector's headroom, and the node's own heap N beside it: L =
// 2B + N. So B is (L - N) / 2 where a limit is set, a limit of zero or less
// read as none, else a sixteenth of the host's physical memory where the
// caller read it, and the caller then sets L to MemoryLimit's 2B + N. The
// rest of B is shared as the constants beside goLimitShare give. Within
// refuses where memory names neither figure, and where the budget or
// the descriptors hold fewer than minConnections connections, naming L, N
// and B where L was given.
func Within(memory Memory, files uint64) (Limits, error) {
	var l Limits
	switch {
	case memory.GoLimit > 0 && memory.GoLimit < math.MaxInt64:
		l.Budget, l.From = max(memory.GoLimit-max(memory.Node, 0), 0)/goLimitShare, FromGoLimit
	case memory.Physical > 0:
		l.Budget, l.From = int64(min(memory.Physical/hostShare, math.MaxInt64)), FromHost
	default:
		return Limits{}, errors.New("egress: the userspace exit was given neither Go's memory limit nor the host's physical memory, so nothing would bound what it holds")
	}
	queue := min(max(l.Budget/queueShare, minQueue), maxQueue)
	l.Lanes, l.Link = queue, queue
	rest := max(l.Budget-reassembly-2*queue, 0)
	mappings := rest / flowShare
	connections := rest - mappings
	l.Window = int(min(max(connections/(2*windowFlows), minWindow), maxWindow))
	l.Connections = int(connections / (2*int64(l.Window) + perConnection + perTimeWait))
	switch {
	case l.Connections >= minConnections:
	case l.From == FromGoLimit:
		return Limits{}, fmt.Errorf("egress: the userspace exit's budget of %d bytes, half of what Go's memory limit of %d bytes leaves past the node's own %d, holds %d TCP connections at a window of %d bytes, fewer than the %d it needs", l.Budget, memory.GoLimit, max(memory.Node, 0), l.Connections, l.Window, minConnections)
	default:
		return Limits{}, fmt.Errorf("egress: the userspace exit's budget of %d bytes, %s, holds %d TCP connections at a window of %d bytes, fewer than the %d it needs", l.Budget, l.From, l.Connections, l.Window, minConnections)
	}
	fit := 0
	if files > daemonFiles {
		fit = int(min((files-daemonFiles)/flowFiles, math.MaxInt32))
	}
	l.Flows = min(l.Connections+int(min(mappings/perFlow, math.MaxInt32)), fit)
	l.Connections = min(l.Connections, l.Flows)
	if l.Connections < minConnections {
		return Limits{}, fmt.Errorf("egress: the userspace exit's %d descriptors, the process's limit past the node's own %d, hold %d flows at the %d one can hold, fewer than the %d TCP connections it needs", max(int64(files)-daemonFiles, 0), daemonFiles, l.Flows, flowFiles, minConnections)
	}
	l.TimeWait = l.Connections
	l.Dials = min(l.Connections, maxDials)
	return l, nil
}

// MemoryLimit is the Go limit L that holds the budget twice, live and as the
// collector's headroom, beside node bytes of the node's own heap: 2B + N
func (l Limits) MemoryLimit(node int64) int64 {
	return goLimitShare*l.Budget + node
}

// MemoryLimit is the Go limit the exit's limits need beside node bytes of
// the node's own heap
func (x *Exit) MemoryLimit(node int64) int64 {
	return x.rt.Limits.MemoryLimit(node)
}

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
