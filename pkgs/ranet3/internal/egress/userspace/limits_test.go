// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package userspace

import (
	"math"
	"runtime/debug"
	"strings"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// for any Go limit, physical figure, node's heap and descriptors, Within takes
// its budget B from Go's limit wherever one is set, half of what it leaves
// past the node's heap, so 2B + N never exceeds L and physical memory is never
// read, else a sixteenth of the physical figure, and refuses with neither.
// Each queue is a thirty-second of B within its bounds, and R, what B leaves
// past gVisor's reassembly and the two queues, goes an eighth to the mappings
// and the rest, T, to TCP. Of what Within gives, the window is the largest
// within its bounds at which windowFlows flows hold two windows inside T, or
// minWindow where none is. Connections is as many as T holds at two windows,
// perConnection and perTimeWait each, and Flows adds as many mappings as their
// share holds at perFlow each, each count less only where the descriptors
// past daemonFiles hold no more at flowFiles a flow, so the node keeps its own
// under any mix of flows. All of it fits B, and Within refuses exactly where
// the budget or the descriptors hold fewer than minConnections. A window past
// its floor leaves T holding windowFlows flows, far past minConnections, so
// the budget refuses only at the floor. Half the cases draw B on the band
// where the window sits at its floor and the floor may still hold
// minConnections.
func TestWithinFitsItsBudget(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		memory := Memory{GoLimit: math.MaxInt64, Node: hegel.Draw(ht, pbt.Spanning[int64](0, 8<<30))}
		if hegel.Draw(ht, hegel.Booleans()) {
			band := hegel.Draw(ht, pbt.Spanning[int64](8<<20, 192<<20))
			if hegel.Draw(ht, hegel.Booleans()) {
				memory.GoLimit = goLimitShare*band + memory.Node
			} else {
				memory.Physical = uint64(band) * hostShare
			}
		} else {
			if hegel.Draw(ht, hegel.Booleans()) {
				memory.GoLimit = hegel.Draw(ht, pbt.Spanning[int64](0, 64<<30))
			}
			if hegel.Draw(ht, hegel.Booleans()) {
				memory.Physical = hegel.Draw(ht, pbt.Spanning[uint64](1, 1<<40))
			}
		}
		files := hegel.Draw(ht, pbt.Spanning[uint64](0, 1<<20))
		l, err := Within(memory, files)
		var budget int64
		var from BudgetSource
		switch {
		case memory.GoLimit > 0 && memory.GoLimit < math.MaxInt64:
			budget, from = max(memory.GoLimit-memory.Node, 0)/goLimitShare, FromGoLimit
		case memory.Physical > 0:
			budget, from = int64(memory.Physical/hostShare), FromHost
		default:
			if err == nil {
				ht.Fatalf("%+v gave %+v, want a refusal naming no figure", memory, l)
			}
			return
		}
		queue := min(max(budget/queueShare, minQueue), maxQueue)
		rest := max(budget-reassembly-2*queue, 0)
		mapped := rest / flowShare
		share := rest - mapped
		spare := int64(0)
		if files > daemonFiles {
			spare = int64(files - daemonFiles)
		}
		if err != nil {
			if minConnections*(2*minWindow+perConnection+perTimeWait) <= share && flowFiles*minConnections <= spare {
				ht.Fatalf("%+v with %d descriptors refused, where T of %d and the descriptors hold %d connections at the floor: %v", memory, files, share, minConnections, err)
			}
			return
		}
		if l.Budget != budget || l.From != from {
			ht.Fatalf("%+v gave a budget of %d from %s, want %d from %s", memory, l.Budget, l.From, budget, from)
		}
		if from == FromGoLimit && l.MemoryLimit(memory.Node) > memory.GoLimit {
			ht.Fatalf("%+v gave a budget of %d, whose 2B + N of %d exceeds the limit", memory, l.Budget, l.MemoryLimit(memory.Node))
		}
		window, connections, flows := int64(l.Window), int64(l.Connections), int64(l.Flows)
		each := 2*window + perConnection + perTimeWait
		held := connections*each + (flows-connections)*perFlow + reassembly + l.Lanes + l.Link
		switch {
		case held > l.Budget:
			ht.Fatalf("%+v holds %d past its budget of %d: %+v", memory, held, l.Budget, l)
		case l.Lanes != queue || l.Link != queue:
			ht.Fatalf("queues of %d and %d, want %d", l.Lanes, l.Link, queue)
		case window < minWindow || window > maxWindow:
			ht.Fatalf("window %d outside %d to %d for T of %d", window, minWindow, maxWindow, share)
		case window > minWindow && 2*windowFlows*window > share:
			ht.Fatalf("window %d past its floor, where %d flows at it pass T of %d", window, windowFlows, share)
		case window < maxWindow && 2*windowFlows*(window+1) <= share:
			ht.Fatalf("window %d, where T of %d holds %d flows at one byte more", window, share, windowFlows)
		case connections < minConnections || connections*each > share:
			ht.Fatalf("%d connections at %d each for T of %d, want at least %d inside it", connections, each, share, minConnections)
		case (connections+1)*each <= share && flowFiles*(connections+1) <= spare:
			ht.Fatalf("%d connections, where T of %d and %d descriptors hold one more", connections, share, spare)
		case flows < connections || flowFiles*flows > spare || (flows-connections)*perFlow > mapped:
			ht.Fatalf("%d flows for %d connections, %d descriptors and a mapping share of %d", flows, connections, spare, mapped)
		case (flows-connections+1)*perFlow <= mapped && flowFiles*(flows+1) <= spare:
			ht.Fatalf("%d flows, where the mapping share of %d and %d descriptors hold one more", flows, mapped, spare)
		case l.TimeWait != l.Connections || l.Dials != min(l.Connections, maxDials):
			ht.Fatalf("TIME_WAIT %d and dials %d for %d connections", l.TimeWait, l.Dials, l.Connections)
		}
		if err := l.check(); err != nil {
			ht.Fatalf("New refuses what Within gave: %v", err)
		}
	})
}

// A phone's extension at 32 MiB of Go limit gets a budget of 16 MiB, of which
// 9 MiB are fixed: 23 connections at a 64 KiB window and 112 mappings, the
// floor of 16 connections held with room. A physical figure beside the Go
// limit changes nothing.
func TestWithinStartsAPhonesExit(t *testing.T) {
	for _, physical := range []uint64{0, 8 << 30} {
		l, err := Within(Memory{GoLimit: 32 << 20, Physical: physical}, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		want := Limits{Budget: 16 << 20, From: FromGoLimit, Flows: 23 + 112, Connections: 23, Dials: 23, TimeWait: 23, Window: 64 << 10, Lanes: 512 << 10, Link: 512 << 10}
		if l != want {
			t.Errorf("physical %d: %+v, want %+v", physical, l, want)
		}
	}
}

// Go's limit L holds the budget twice and the node's heap N: given L, the
// budget is half of L less N, so MemoryLimit gives L back, and
// with no L the budget is a sixteenth of the host whatever N is, and
// MemoryLimit gives the L the caller then sets, 2B + N
func TestWithinTakesTheNodesHeapFromAGivenLimitOnly(t *testing.T) {
	const node = 256 << 20
	for _, c := range []struct {
		name   string
		memory Memory
		budget int64
		from   BudgetSource
		limit  int64
	}{
		{"given", Memory{GoLimit: 1 << 30, Physical: 16 << 30, Node: node}, 384 << 20, FromGoLimit, 1 << 30},
		{"host", Memory{GoLimit: math.MaxInt64, Physical: 16 << 30, Node: node}, 1 << 30, FromHost, 2<<30 + node},
	} {
		l, err := Within(c.memory, 1<<20)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if l.Budget != c.budget || l.From != c.from || l.MemoryLimit(node) != c.limit {
			t.Errorf("%s: a budget of %d from %s and a limit of %d, want %d from %s and %d", c.name, l.Budget, l.From, l.MemoryLimit(node), c.budget, c.from, c.limit)
		}
	}
}

// HostMemory reads the host's physical memory and Go's limit as the runtime
// holds it, and Files the descriptors this process may open
func TestHostMemoryReadsBothFigures(t *testing.T) {
	memory, err := HostMemory()
	if err != nil {
		t.Fatal(err)
	}
	if memory.Physical == 0 || memory.GoLimit != debug.SetMemoryLimit(-1) {
		t.Errorf("read %+v, want the host's memory and Go's limit of %d", memory, debug.SetMemoryLimit(-1))
	}
	if Files() == 0 {
		t.Error("read no descriptors this process may open")
	}
}

// Within refuses a process with no figure to bound it, naming both, and a
// budget the fixed part leaves no room in, naming the budget and its source,
// and where Go's limit was given, the limit and the node's heap: a node whose
// heap crowds the limit, a phone's 32 MiB beside a node of 16 MiB among them
func TestWithinRefusesWhatBoundsNothing(t *testing.T) {
	for _, c := range []struct {
		memory Memory
		names  []string
	}{
		{Memory{GoLimit: math.MaxInt64}, []string{"Go's memory limit", "physical memory"}},
		{Memory{GoLimit: 16 << 20}, []string{"budget of 8388608 bytes", "Go's memory limit of 16777216 bytes", "node's own 0"}},
		{Memory{GoLimit: 64 << 20, Node: 48 << 20}, []string{"budget of 8388608 bytes", "Go's memory limit of 67108864 bytes", "node's own 50331648"}},
		{Memory{GoLimit: 32 << 20, Node: 16 << 20}, []string{"budget of 8388608 bytes", "Go's memory limit of 33554432 bytes", "node's own 16777216"}},
		{Memory{GoLimit: math.MaxInt64, Physical: 64 << 20}, []string{"4194304 bytes", "a sixteenth of the host's memory"}},
	} {
		_, err := Within(c.memory, 1<<20)
		if err == nil {
			t.Errorf("%+v started", c.memory)
			continue
		}
		for _, name := range c.names {
			if !strings.Contains(err.Error(), name) {
				t.Errorf("%+v refused with %q, which names no %q", c.memory, err, name)
			}
		}
	}
}
