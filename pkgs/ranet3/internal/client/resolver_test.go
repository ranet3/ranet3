// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build (linux && !android) || (darwin && !ios)

package client

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/internal/events"
)

// refusedDials bounds the test's two dials, each refused before any query leaves
const refusedDials = 10 * time.Second

// errRefusedByTheTest is the error the test's prepare refuses a socket with, which no kernel returns
var errRefusedByTheTest = errors.New("refused by the test's prepare")

// A dial resolving its peer's endpoint name, whether it names the endpoint or
// the node, readies at least one query's socket toward a nameserver's port 53
// with the node's own prepare, the one the hub's sockets take. A query the
// prepare refuses fails the dial, and the dial.failed of a dial naming the
// endpoint carries the prepare's refusal with the nameserver it was refused
// toward. The prepare refuses every socket, so no query leaves the host.
func TestEndpointQueryTakesTheNodesPrepare(t *testing.T) {
	cfg, privateKey, reg := runtimeFixture(t)
	name := "gateway.example.org."
	reg[0].Nodes[1].Endpoints[0].Address = &name
	ctx, cancel := context.WithTimeout(context.Background(), refusedDials)
	defer cancel()
	// Go's resolver dials one query at a time, so the prepare runs on one goroutine at a time
	var readied []netip.AddrPort
	prepare := func(network string, to netip.AddrPort, _ syscall.RawConn) error {
		if !slices.Contains([]string{"udp4", "udp6", "tcp4", "tcp6"}, network) {
			t.Errorf("a query's first socket is %s, want a datagram or stream socket", network)
		}
		readied = append(readied, to)
		return errRefusedByTheTest
	}
	bus := events.New()
	c := &Client{ctx: ctx, cancel: cancel, prepare: prepare, privateKey: privateKey, sessions: newSessionSet(), events: bus}
	c.cfg.Store(cfg)
	c.storeIndex(trust(t, reg))
	for _, peer := range []identity.Identity{cfg.Dial.To[0], cfg.Dial.To[0].Node()} {
		before := len(readied)
		if err := c.connectPeer(ctx, dialTo(t, cfg, peer), slog.LevelInfo); err == nil {
			t.Fatalf("dialing %s resolved %s with every query refused", peer, name)
		}
		if len(readied) == before {
			t.Fatalf("dialing %s resolved %s without the node's prepare readying a query", peer, name)
		}
		for _, to := range readied[before:] {
			if to.Port() != 53 {
				t.Errorf("dialing %s readied a socket toward %s, want a nameserver's port 53", peer, to)
			}
		}
	}
	failed := recorded(bus, "dial.failed")
	if len(failed) != 2 {
		t.Fatalf("%d dial.failed events, want 2: %v", len(failed), failed)
	}
	reason := failed[0].Attrs["err"]
	toward := slices.ContainsFunc(readied, func(to netip.AddrPort) bool { return strings.Contains(reason, to.String()) })
	if !toward || !strings.Contains(reason, errRefusedByTheTest.Error()) {
		t.Errorf("dial.failed of the dial naming the endpoint carries %q, want the prepare's refusal toward one of %v", reason, readied)
	}
}
