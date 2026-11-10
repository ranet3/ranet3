// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package client

import (
	"log/slog"
	"testing"
	"time"
)

const (
	// unroutedFourthWait is the least gap before the fifth of a dialer's dials no route takes, which a dialer that backs off waits out
	unroutedFourthWait = 6 * redialAfter
	// unroutedWoken bounds how soon a woken dialer whose dials no route takes dials again
	unroutedWoken = 16 * redialAfter
)

// a dial the host has no route for reads as one, and its dialer waits twice as long after each such dial in a row
// a wake ends the wait at once
// it runs as root under unshare -n, where nothing routes the documentation address the peer's endpoint holds
func TestDialerTheHostHasNoRouteForDialsAtOnceWhenWoken(t *testing.T) {
	kernelNamespace(t)
	cfg, privateKey, reg := runtimeFixture(t)
	unrouted := "192.0.2.1"
	reg[0].Nodes[1].Endpoints[0].Address = &unrouted
	c := testClientOf(t, cfg, privateKey, reg)
	c.dialRetry = redialAfter
	ctx, bus := c.ctx, c.events
	d := dialTo(t, cfg, cfg.Dial.To[0])
	if err := c.connectPeer(ctx, d, slog.LevelInfo); c.unroutedDelay(err, 0) == 0 {
		t.Fatalf("a dial to %s in a namespace that routes nothing ended with %v, which does not read as no route", unrouted, err)
	}

	// the dial above, then the dialer's own
	attempts := func() int { return len(recorded(bus, "dial.attempt")) - 1 }
	wake := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() { c.runPeer(ctx, d, wake); close(done) }()
	waitFor(t, convergeBudget, "the dialer's sixth dial to fail", func() bool { return len(recorded(bus, "dial.failed")) == 7 })
	dialed := recorded(bus, "dial.attempt")[1:]
	if gap := dialed[4].At.Sub(dialed[3].At); gap < unroutedFourthWait {
		t.Errorf("the dialer dialed a fifth time %s after the fourth, want at least %s", gap, unroutedFourthWait)
	}
	woken := time.Now()
	wake <- struct{}{}
	waitFor(t, convergeBudget, "the woken dialer to dial again", func() bool { return attempts() == 7 })
	if took := time.Since(woken); took > unroutedWoken {
		t.Errorf("the woken dialer dialed %s after the wake, want at once", took)
	}
	c.cancel()
	<-done
}
