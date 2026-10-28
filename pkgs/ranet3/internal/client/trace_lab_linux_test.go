// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package client

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/internal/netstack"
)

// labTrace reads a trace of query off socket into the channel it returns, until the cancel it returns or the test ends
func labTrace(t *testing.T, socket string, query control.TraceQuery) (<-chan control.TraceLine, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	lines, done := make(chan control.TraceLine, 1024), make(chan struct{})
	go func() {
		defer close(done)
		defer close(lines)
		for line, err := range control.Dial(socket).Trace(ctx, query) {
			if err != nil {
				return
			}
			select {
			case lines <- line:
			case <-ctx.Done():
				return
			}
		}
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return lines, cancel
}

// labRecord takes lines until a record match takes, failing the test where none comes within convergeBudget
func labRecord(t *testing.T, lines <-chan control.TraceLine, what string, match func(control.TracePacket) bool) control.TracePacket {
	t.Helper()
	deadline := time.After(convergeBudget)
	for {
		select {
		case line, open := <-lines:
			if !open {
				t.Fatalf("the trace ended before %s", what)
			}
			if line.Packet != nil && match(*line.Packet) {
				return *line.Packet
			}
		case <-deadline:
			t.Fatalf("no record of %s came within %s", what, convergeBudget)
		}
	}
}

// labPeerID is the ID of the peer node routes address to
func labPeerID(t *testing.T, node *labNode, address netip.Addr) string {
	t.Helper()
	peer, verdict, _ := node.client.Mesh.Routes.Resolve(netip.Addr{}, address)
	if verdict != netstack.RoutePeer {
		t.Fatalf("%s routes %s to no peer", node.name, address)
	}
	return peer.ID
}

// a, b and c in the line, b traced over its control socket by uid 0 for c's address and the half of c's network b holds
// a's datagrams of each family to c draw forward records at b naming a's session as the arrival and c's as the next peer
// a hop limit of 1 draws an answer expired and sent, and a datagram into b's hold an answer held
// a second trace whose filter matches nothing takes no record, both traces are recorded as uid 0's, and b's mesh holds no tracer once both close
func TestTUNTraceShowsTheMiddleNodesDecisions(t *testing.T) {
	nodes := startLab(t, lineSpecs(true), lineLinks)
	a, b, c := nodes[0], nodes[1], nodes[2]
	run(t, a.loopbackNode, b.loopbackNode, c.loopbackNode)
	for _, family := range labFamilies {
		v := family.version
		labRoutes(t, a, lineC[v], lineHeld[v].Addr().Next())
		labRoutes(t, c, lineA[v])
		labRoutes(t, b, lineA[v], lineC[v])
	}
	listener := labListen(t, c)
	socket := servedSocket(t, b.client)

	var watched []netip.Prefix
	for _, v := range []int{4, 6} {
		watched = append(watched, netip.PrefixFrom(lineC[v], lineC[v].BitLen()), lineHold[v])
	}
	lines, stop := labTrace(t, socket, control.TraceQuery{Destinations: watched, Rate: control.TraceRateDefault})
	nothing, stopNothing := labTrace(t, socket, control.TraceQuery{Destinations: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}, Rate: control.TraceRateDefault})
	waitFor(t, convergeBudget, "both traces to open at b", func() bool { return b.client.Mesh.TraceClients() == 2 })

	for _, family := range labFamilies {
		v := family.version
		t.Run(family.name, func(t *testing.T) {
			payload := []byte("traced through b over " + family.name)
			labReceive(t, listener, payload, labWrite(labDatagrams(t, a, family, lineC[v], 0), payload))
			from, next := labPeerID(t, b, lineA[v]), labPeerID(t, b, lineC[v])
			forward := labRecord(t, lines, "a forward to c", func(p control.TracePacket) bool {
				return p.Decision == "forward" && p.Destination == lineC[v] && p.Length == family.header+len(payload)
			})
			if forward.Arrival != "session" || forward.From != from || forward.Next != next || forward.Source != lineA[v] || forward.Protocol != 17 || forward.Payload != nil {
				t.Errorf("a's datagram to c was recorded as %+v, want a forward from %s to %s with no payload", forward, from, next)
			}

			labAwaitError(t, labDatagrams(t, a, family, lineC[v], 1), family, []byte("one hop"))
			expired := labRecord(t, lines, "an answer expired", func(p control.TracePacket) bool {
				return p.Decision == "answer" && p.Reason == "expired" && p.Destination == lineC[v]
			})
			if expired.HopLimit != 1 || expired.Answer != "expired" || expired.Outcome != "sent" || expired.From != from {
				t.Errorf("a datagram of hop limit 1 was recorded as %+v, want an answer expired sent", expired)
			}

			hold := lineHold[v]
			b.client.Mesh.Routes.Set(netip.Prefix{}, hold, netstack.Unreachable)
			defer b.client.Mesh.Routes.Remove(netip.Prefix{}, hold)
			labAwaitError(t, labDatagrams(t, a, family, hold.Addr().Next(), 0), family, []byte("into the hold"))
			held := labRecord(t, lines, "an answer held", func(p control.TracePacket) bool {
				return p.Decision == "answer" && p.Reason == "held" && p.Destination == hold.Addr().Next()
			})
			if held.Outcome != "sent" || held.From != from {
				t.Errorf("a datagram into b's hold was recorded as %+v, want an answer held sent", held)
			}
		})
	}

	stopNothing()
	for line := range nothing {
		if line.Packet != nil {
			t.Errorf("a trace whose filter matches nothing took %+v", *line.Packet)
		}
	}
	stop()
	waitFor(t, convergeBudget, "b's mesh to hold no tracer once both traces closed", func() bool { return b.client.Mesh.TraceClients() == 0 })
	started, ended := recorded(b.events, "control.trace.started"), recorded(b.events, "control.trace.ended")
	if len(started) != 2 || len(ended) != 2 {
		t.Fatalf("b recorded %d traces started and %d ended, want 2 of each", len(started), len(ended))
	}
	for _, event := range started {
		if event.Attrs["uid"] != "0" || event.Attrs["pid"] != fmt.Sprint(os.Getpid()) {
			t.Errorf("a trace was recorded as started by %+v, want this process as uid 0", event.Attrs)
		}
	}
}
