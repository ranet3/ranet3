// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"fmt"
	"log/slog"
	"math"
	"runtime/debug"
	"sync"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/registry"
	"ranet3.com/pkgs/ranet3/transport"
)

// budgeted is an exit sized within a memory budget B, which shares Go's memory limit L with the node's own heap N
type budgeted interface {
	// MemoryLimit is the L that holds the exit's budget twice, live and as the collector's headroom, beside node bytes of the node's own heap: 2B + N
	MemoryLimit(node int64) int64
}

// memoryLimit is Go's memory limit as the node holds it beside a budgeted exit
type memoryLimit struct {
	mu sync.Mutex
	// given is the limit the start found before the node set any, which every reload reads rather than the limit in force, the node's own once it set one
	given int64
	// node is N as last weighed, and set the limit the node set, zero while it holds none
	node, set int64
	// stopped is the exit's Run ended, after which the node sets no limit
	stopped bool
}

// unlimited is whether no limit was given, math.MaxInt64 and a limit of zero or less read as none
func (m *memoryLimit) unlimited() bool {
	return m.given <= 0 || m.given == math.MaxInt64
}

// NodeHeap is N, the most Go heap the node holds outside an exit: transport.HeldBytes for each session config and the trust document allow at once, the receive storage one mux's batches hold, and the mesh's pools
// the socket buffers are the kernel's and not in it
func (c *Client) NodeHeap() int64 {
	return nodeHeap(c.config(), c.index(), c.Mesh)
}

func nodeHeap(cfg *config.Config, x *registry.Index, mesh *netstack.Mesh) int64 {
	return int64(pathCeiling(cfg, x))*transport.HeldBytes + mesh.PoolBytes()
}

// pathCeiling is the most sessions cfg and x allow at once, one a path: each local endpoint with each endpoint of every other node x names where link.listen is on, since any of them may dial in, else the paths this node dials
func pathCeiling(cfg *config.Config, x *registry.Index) int {
	if !cfg.Link.Listen {
		return len(dials(cfg, x))
	}
	remote := 0
	for _, node := range x.Nodes() {
		if node != cfg.Node {
			remote += len(x.Targets(node))
		}
	}
	return len(cfg.Link.Endpoints) * remote
}

// GivenMemoryLimit is Go's memory limit as the node's start found it, before the node set any, math.MaxInt64 where none was given
// an exit's budget reads it beside NodeHeap
func (c *Client) GivenMemoryLimit() int64 {
	if c.memory.unlimited() {
		return math.MaxInt64
	}
	return c.memory.given
}

// weigh takes N again and holds L = 2B + N for exit
// where no limit was given, the node sets L to it, so a reload that changes N sets L again
// where one was, an N past what the exit's budget leaves of it is accepted, logged and recorded as daemon.memory, since the exit was sized at its start and a restart applies the new N
func (c *Client) weigh(exit budgeted, during string) {
	node := c.NodeHeap()
	c.memory.mu.Lock()
	defer c.memory.mu.Unlock()
	if c.memory.stopped {
		return
	}
	c.memory.node = node
	if c.memory.unlimited() {
		c.memory.set = exit.MemoryLimit(node)
		debug.SetMemoryLimit(c.memory.set)
		return
	}
	if room := c.memory.given - exit.MemoryLimit(0); node > room {
		slog.Warn(fmt.Sprintf("%s: the node's own heap of %d bytes is past the %d Go's memory limit of %d leaves it beside the exit's budget, until a restart sizes the exit again", during, node, room, c.memory.given))
		c.events.Emit("daemon.memory", "", slog.Int64("limit", c.memory.given), slog.Int64("node", node), slog.Int64("room", room))
	}
}

// reweigh weighs the exit again where it is budgeted, as a reload does
func (c *Client) reweigh() {
	if exit := c.exit.Load(); exit != nil {
		if b, ok := (*exit).(budgeted); ok {
			c.weigh(b, "reload")
		}
	}
}

// ExitStopped tells the node the exit's Run has ended: a limit the node set goes back to none, and no reload sets one again
func (c *Client) ExitStopped() {
	c.memory.mu.Lock()
	defer c.memory.mu.Unlock()
	c.memory.stopped = true
	if c.memory.set != 0 {
		debug.SetMemoryLimit(math.MaxInt64)
		c.memory.set = 0
	}
}

// memoryReading is Go's memory limit beside exit as a debug read reports it: L in force, given or set by the node, zero once the node holds none, N as last weighed, and L - 2B, what the exit's budget leaves the node
func (c *Client) memoryReading(exit budgeted) *control.EgressMemory {
	c.memory.mu.Lock()
	defer c.memory.mu.Unlock()
	reading := &control.EgressMemory{Limit: c.memory.set, Node: c.memory.node}
	if !c.memory.unlimited() {
		reading.Limit, reading.Given = c.memory.given, true
	}
	if reading.Limit != 0 {
		reading.Room = reading.Limit - exit.MemoryLimit(0)
	}
	return reading
}
