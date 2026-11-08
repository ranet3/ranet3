// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"math"
	"runtime/debug"
	"slices"
	"strconv"
	"testing"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/registry"
	"ranet3.com/pkgs/ranet3/transport"
)

// budgetedExit is an exit sized within a budget, whose Go limit holds it
// twice beside the node's heap
type budgetedExit struct {
	fakeExit
	budget int64
}

func (b *budgetedExit) MemoryLimit(node int64) int64 { return 2*b.budget + node }

// noLimit sets Go's memory limit to none for the test, and puts back the one
// it found once the test ends
func noLimit(t *testing.T) {
	t.Helper()
	found := debug.SetMemoryLimit(math.MaxInt64)
	t.Cleanup(func() { debug.SetMemoryLimit(found) })
}

// joinedThird is a reload that adds a third node to the trust document and
// dials it, so the node may hold one session more
func joinedThird(t *testing.T, c *Client, next *config.Config) {
	t.Helper()
	grown := readRegistry(t, c.config().Auth.Trust)
	grown[0].Nodes = append(slices.Clone(grown[0].Nodes), registry.Node{
		CommonName: "third",
		Endpoints:  []registry.Endpoint{{SerialNumber: "1", AddressFamily: "ip4", Port: 13000}},
	})
	writeRegistry(t, next.Auth.Trust, grown)
	next.Dial.To = append(slices.Clone(next.Dial.To), identity.MustParse("example/third:1"))
}

// With no Go limit given, a node sets it to 2B + N for an exit sized within a
// budget before the exit runs, and again at a reload that changes N, though
// the limit in force is by then its own. debug egress shows it. Once the exit
// stops the limit goes back to none, and a reload after sets none.
func TestNodeHoldsTheLimitForAnExitWithinItsBudget(t *testing.T) {
	noLimit(t)
	c, path, _, _ := reloadOf(t, func(*config.Config) {})
	exit := &budgetedExit{budget: 1 << 40}
	c.SetExit(exit)
	if got, want := debug.SetMemoryLimit(-1), exit.MemoryLimit(transport.HeldBytes); got != want {
		t.Fatalf("the exit started under a limit of %d, want 2B + N, %d", got, want)
	}
	next := *c.config()
	joinedThird(t, c, &next)
	writeConfig(t, path, &next)
	if err := c.ReloadFrom(path); err != nil {
		t.Fatalf("the reload was refused: %v", err)
	}
	node := int64(2 * transport.HeldBytes)
	want := exit.MemoryLimit(node)
	if got := debug.SetMemoryLimit(-1); got != want {
		t.Errorf("the reload left a limit of %d, want 2B + N, %d", got, want)
	}
	if got, read := c.DebugEgress().Memory, (control.EgressMemory{Limit: want, Node: node, Room: node}); got == nil || *got != read {
		t.Errorf("debug egress read %+v, want %+v", got, read)
	}
	c.ExitStopped()
	if got := debug.SetMemoryLimit(-1); got != math.MaxInt64 {
		t.Errorf("the stopped exit left a limit of %d", got)
	}
	next.Dial.To = next.Dial.To[:1]
	writeConfig(t, path, &next)
	if err := c.ReloadFrom(path); err != nil {
		t.Fatalf("the reload after the stop was refused: %v", err)
	}
	if got := debug.SetMemoryLimit(-1); got != math.MaxInt64 {
		t.Errorf("a reload after the stop set a limit of %d", got)
	}
}

// With Go's limit given, a node sets none: a reload that raises N past L - 2B
// is taken, logged and recorded as daemon.memory, and debug egress shows N
// against L - 2B
func TestReloadPastTheGivenLimitIsTakenAndRecorded(t *testing.T) {
	noLimit(t)
	c, path, _, bus := reloadOf(t, func(*config.Config) {})
	exit := &budgetedExit{budget: 100 << 20}
	given := exit.MemoryLimit(transport.HeldBytes)
	c.memory.given = given
	c.SetExit(exit)
	if got := recorded(bus, "daemon.memory"); len(got) != 0 {
		t.Fatalf("a start within the limit recorded %v", got)
	}
	next := *c.config()
	joinedThird(t, c, &next)
	writeConfig(t, path, &next)
	if err := c.ReloadFrom(path); err != nil {
		t.Fatalf("the reload past the limit was refused: %v", err)
	}
	if got := debug.SetMemoryLimit(-1); got != math.MaxInt64 {
		t.Errorf("the node set a limit of %d beside a given one", got)
	}
	node, room := int64(2*transport.HeldBytes), int64(transport.HeldBytes)
	records := recorded(bus, "daemon.memory")
	if len(records) != 1 || records[0].Attrs["limit"] != strconv.FormatInt(given, 10) || records[0].Attrs["node"] != strconv.FormatInt(node, 10) || records[0].Attrs["room"] != strconv.FormatInt(room, 10) {
		t.Errorf("recorded %v, want one daemon.memory naming the limit %d, the node's %d and the room %d", records, given, node, room)
	}
	if got, read := c.DebugEgress().Memory, (control.EgressMemory{Limit: given, Given: true, Node: node, Room: room}); got == nil || *got != read {
		t.Errorf("debug egress read %+v, want %+v", got, read)
	}
}

// The sessions a node may hold are each local endpoint with each endpoint of
// every other node the trust document names where link.listen is on, and the
// paths it dials where it is off, each holding an ESP queue in N
func TestPathCeilingCountsWhatConfigAndTrustAllow(t *testing.T) {
	cfg, _, reg := runtimeFixture(t)
	reg[0].Nodes = append(reg[0].Nodes, registry.Node{CommonName: "third", Endpoints: []registry.Endpoint{
		{SerialNumber: "1", AddressFamily: "ip4", Port: 13000}, {SerialNumber: "2", AddressFamily: "ip6", Port: 13000},
	}})
	cfg.Link.Endpoints = append(cfg.Link.Endpoints, config.Endpoint{Serial: "5", Family: "ip6"})
	x := trust(t, reg)
	for _, c := range []struct {
		listen bool
		paths  int
	}{{false, 2}, {true, 6}} {
		cfg.Link.Listen = c.listen
		if got := pathCeiling(cfg, x); got != c.paths {
			t.Errorf("listen %t: %d paths, want %d", c.listen, got, c.paths)
		}
	}
}
