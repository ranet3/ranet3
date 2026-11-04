// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/ike"
	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/logtest"
	"ranet3.com/pkgs/ranet3/internal/registry"
	"ranet3.com/pkgs/ranet3/transport"
)

// redialAfter is the reconnect delay of a test that waits for a node to dial again
const redialAfter = 200 * time.Millisecond

// recorded is every event bus holds of one kind, oldest first
func recorded(bus *events.Bus, kind string) []control.Event {
	return bus.Recorded(func(k, _ string, _ []slog.Attr) bool { return k == kind }, 0)
}

// a dialed peer's dial, its session and its babel neighbor are recorded in that order under one path
// the dial names no serial
// so the path is the session's from the endpoint it resolved
// each end's rekey is recorded under the path naming the other end
// the end that answered records its side of the session
// a reload is recorded with its file
// and the session's end is recorded when the node stops
func TestLoopbackRecordsDialSessionAndNeighborInOrder(t *testing.T) {
	alpha, bravo := newLoopbackMesh(t)
	// bravo answers and never dials
	// so every session is the one alpha dials
	quiet := *bravo.cfg
	quiet.Dial.To = nil
	bravo.client.cfg.Store(&quiet)
	unpinned := *alpha.cfg
	unpinned.Dial.To = slices.Clone(alpha.cfg.Dial.To)
	unpinned.Dial.To[0] = unpinned.Dial.To[0].Node()
	alpha.client.cfg.Store(&unpinned)
	if alpha.client.sessions.events != alpha.events || alpha.client.KernelRuntime().Events != alpha.events {
		t.Error("the session set or the reconciler records somewhere other than the node's bus")
	}
	_, stop := run(t, alpha, bravo)

	dialed := fmt.Sprintf("example/%s:0@0", bravo.name)
	waitFor(t, convergeBudget, "alpha's neighbor to come up", func() bool {
		return len(recorded(alpha.events, "babel.neighbor.up")) > 0
	})
	var order []string
	for _, event := range alpha.events.Recorded(func(_, peer string, _ []slog.Attr) bool { return peer == dialed }, 0) {
		if !slices.Contains(order, event.Kind) {
			order = append(order, event.Kind)
		}
	}
	at := func(kind string) int { return slices.Index(order, kind) }
	if at("dial.attempt") < 0 || at("dial.attempt") > at("ike.session.established") ||
		at("ike.session.established") > at("babel.neighbor.up") {
		t.Errorf("alpha recorded %q under %s", order, dialed)
	}
	// bravo records its session after the adopt that registered its Babel peer
	// so alpha's neighbor can come up first
	waitFor(t, convergeBudget, "bravo to record the session it answered", func() bool {
		return len(recorded(bravo.events, "ike.session.established")) > 0
	})
	answered := recorded(bravo.events, "ike.session.established")
	if len(answered) == 0 || answered[0].Peer != fmt.Sprintf("example/%s:0@0", alpha.name) || answered[0].Attrs["role"] != "responder" {
		t.Errorf("bravo recorded its session as %+v", answered)
	}
	// alpha dialed
	// it receives on the SPI its own SA holds as local
	// both ends write no cap.crypto list
	// so the session runs the first name of each
	dialing := recorded(alpha.events, "ike.session.established")
	if own := alpha.client.sessions.snapshot(); len(dialing) == 0 || len(own) != 1 || dialing[0].Peer != dialed || dialing[0].Attrs["role"] != "initiator" ||
		dialing[0].Attrs["spi_in"] != fmt.Sprintf("%08x", own[0].session.Child().LocalSPI) ||
		dialing[0].Attrs["spi_out"] != fmt.Sprintf("%08x", own[0].session.Child().RemoteSPI) ||
		dialing[0].Attrs["ike"] != "aes256gcm/sha384/x25519+mlkem768" || dialing[0].Attrs["esp"] != "aes256gcm" {
		t.Errorf("alpha recorded the session it dialed as %+v", dialing)
	}
	for _, end := range []struct{ node, other *loopbackNode }{{alpha, bravo}, {bravo, alpha}} {
		held := end.node.client.sessions.snapshot()
		if len(held) != 1 {
			t.Fatalf("%s holds %d sessions", end.node.name, len(held))
		}
		if err := held[0].session.RekeyChild(); err != nil {
			t.Fatalf("%s could not rekey its session: %v", end.node.name, err)
		}
		rekeyed := end.node.events.Recorded(func(kind, peer string, _ []slog.Attr) bool {
			return kind == "ike.rekey.completed" && identity.Names(peer, end.other.name)
		}, 0)
		if len(rekeyed) != 1 {
			t.Errorf("%s recorded %d rekeys under %s", end.node.name, len(rekeyed), end.other.name)
		}
	}

	if err := alpha.client.ReloadFrom(alpha.configPath); err != nil {
		t.Fatal(err)
	}
	if reloads := recorded(alpha.events, "daemon.reload"); len(reloads) != 1 || reloads[0].Attrs["path"] != alpha.configPath || reloads[0].Attrs["err"] != "" {
		t.Errorf("a reload was recorded as %+v", reloads)
	}

	stop()
	ended := alpha.events.Recorded(func(kind, peer string, _ []slog.Attr) bool { return kind == "ike.session.ended" && peer == dialed }, 0)
	started := alpha.events.Recorded(func(kind, peer string, _ []slog.Attr) bool {
		return kind == "ike.session.established" && peer == dialed
	}, 0)
	if len(ended) == 0 || ended[len(ended)-1].Attrs["err"] == "" || len(started) == 0 ||
		ended[len(ended)-1].Attrs["spi_in"] != started[len(started)-1].Attrs["spi_in"] {
		t.Errorf("alpha recorded the end of its session as %+v, its start as %+v", ended, started)
	}
}

// the resolution between two sessions for one path is recorded with the session it kept
func TestResolutionIsRecorded(t *testing.T) {
	set := newSessionSet()
	set.events = events.New()
	set.close = func(*ike.Session) {}
	const path = "example/gateway:1@0"
	set.adoptPreferred(path, &ike.Session{}, true, nil)
	if _, adopted := set.adoptPreferred(path, &ike.Session{}, false, nil); adopted {
		t.Fatal("a session neither end prefers took the path from one both prefer")
	}
	if _, adopted := set.adoptPreferred(path, &ike.Session{}, true, nil); !adopted {
		t.Fatal("an equally preferred session did not replace the one it reconnects")
	}
	var kept []string
	for _, event := range recorded(set.events, "ike.session.resolved") {
		if event.Peer != path {
			t.Errorf("a resolution was recorded under %q", event.Peer)
		}
		kept = append(kept, event.Attrs["kept"])
	}
	if want := []string{"the session already held", "the new session"}; !slices.Equal(kept, want) {
		t.Errorf("the resolutions kept %q, want %q", kept, want)
	}
}

// a session that loses its path to one the node already holds is recorded as resolved and never as established
func TestLosingSessionIsNeverRecordedEstablished(t *testing.T) {
	alpha, bravo := newLoopbackMesh(t)
	// alpha answers and never dials, and holds a session both ends prefer on bravo's path, so every session bravo dials loses
	quiet := *alpha.cfg
	quiet.Dial.To = nil
	alpha.client.cfg.Store(&quiet)
	held := &ike.Session{}
	closeSession := alpha.client.sessions.close
	alpha.client.sessions.close = func(sess *ike.Session) {
		if sess != held {
			closeSession(sess)
		}
	}
	path := fmt.Sprintf("example/%s:0@0", bravo.name)
	if _, adopted := alpha.client.sessions.adoptPreferred(path, held, true, nil); !adopted {
		t.Fatal("the held session was not adopted")
	}
	// crossed is after any handshake of bravo's starts, when a crossing dial's session is taken, so the INITIAL_CONTACT bravo's first handshake carries leaves the held one to the rule
	crossed := time.Now().Add(time.Hour)
	set := alpha.client.sessions
	set.mu.Lock()
	set.live[path].adopted = crossed
	set.mu.Unlock()
	run(t, alpha, bravo)
	waitFor(t, convergeBudget, "alpha to turn a session of bravo's away", func() bool {
		return len(recorded(alpha.events, "ike.session.resolved")) > 0
	})
	if established := recorded(alpha.events, "ike.session.established"); len(established) != 0 {
		t.Errorf("alpha recorded a session it turned away as established: %+v", established)
	}
}

// a dial the node cancels mid-handshake, as a stop or a reload dropping its peer does, is no failed dial
func TestCanceledDialIsNoFailure(t *testing.T) {
	cfg, privateKey, reg := runtimeFixture(t)
	silent, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	loopback := "127.0.0.1"
	reg[0].Nodes[1].Endpoints[0].Address = &loopback
	reg[0].Nodes[1].Endpoints[0].Port = uint16(silent.LocalAddr().(*net.UDPAddr).Port)
	hub, err := transport.NewHub("127.0.0.1:0", transport.Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bus := events.New()
	c := &Client{ctx: ctx, cancel: cancel, privateKey: privateKey, hub: hub, sessions: newSessionSet(), events: bus}
	c.cfg.Store(cfg)
	c.storeIndex(trust(t, reg))

	done := make(chan error, 1)
	d := dialTo(t, cfg, cfg.Dial.To[0])
	go func() { done <- c.connectPeer(ctx, d, slog.LevelInfo) }()
	waitFor(t, convergeBudget, "the handshake to start", func() bool { return len(recorded(bus, "dial.attempt")) == 1 })
	cancel()
	if err := <-done; err == nil {
		t.Fatal("a dial to a peer that never answered succeeded")
	}
	if failed := recorded(bus, "dial.failed"); len(failed) != 0 {
		t.Errorf("a canceled dial was recorded as failed: %+v", failed)
	}
}

// a session that ends after its dial succeeded is recorded as ended, and its dial as no failure
func TestEndedSessionIsNoFailedDial(t *testing.T) {
	alpha, bravo := newLoopbackMesh(t)
	// bravo answers and never dials, so the session alpha holds is one alpha dialed
	quiet := *bravo.cfg
	quiet.Dial.To = nil
	bravo.client.cfg.Store(&quiet)
	alpha.client.dialRetry = redialAfter
	run(t, alpha, bravo)
	waitFor(t, convergeBudget, "alpha's neighbor to come up", func() bool {
		return len(recorded(alpha.events, "babel.neighbor.up")) > 0
	})
	held := alpha.client.sessions.snapshot()
	if len(held) != 1 {
		t.Fatalf("alpha holds %d sessions", len(held))
	}
	held[0].session.Mux().Close()
	waitFor(t, convergeBudget, "the session to end and alpha to dial another", func() bool {
		return len(recorded(alpha.events, "ike.session.ended")) > 0 && len(recorded(alpha.events, "ike.session.established")) > 1
	})
	if failed := recorded(alpha.events, "dial.failed"); len(failed) != 0 {
		t.Errorf("the end of a session alpha dialed was recorded as a failed dial: %+v", failed)
	}
}

// a dial that fails after its endpoint resolved is recorded under the session's path, as its attempt is
func TestFailedDialIsRecordedUnderTheSessionPath(t *testing.T) {
	alpha, bravo := newLoopbackMesh(t)
	quiet := *bravo.cfg
	quiet.Dial.To = nil
	bravo.client.cfg.Store(&quiet)
	unpinned := *alpha.cfg
	unpinned.Dial.To = slices.Clone(alpha.cfg.Dial.To)
	unpinned.Dial.To[0] = unpinned.Dial.To[0].Node()
	alpha.client.cfg.Store(&unpinned)
	alpha.client.dialRetry = redialAfter
	// bravo no longer trusts alpha, so alpha's handshake fails after its endpoint resolved
	bravo.client.storeIndex(trust(t, registry.Registry{{Organization: "example", Nodes: []registry.Node{{CommonName: bravo.name,
		Endpoints: []registry.Endpoint{{SerialNumber: "0", AddressFamily: "ip4", Port: bravo.port}}}}}}))
	run(t, alpha, bravo)
	waitFor(t, convergeBudget, "alpha's dial to fail", func() bool { return len(recorded(alpha.events, "dial.failed")) > 0 })
	session := fmt.Sprintf("example/%s:0@0", bravo.name)
	for _, kind := range []string{"dial.attempt", "dial.failed"} {
		for _, event := range recorded(alpha.events, kind) {
			if event.Peer != session {
				t.Errorf("%s was recorded under %s, want the session's path %s", kind, event.Peer, session)
			}
		}
	}
	// the handshake bravo refused names no peer, since none authenticated
	waitFor(t, convergeBudget, "bravo's refusal", func() bool { return len(recorded(bravo.events, "ike.handshake.failed")) > 0 })
	for _, event := range recorded(bravo.events, "ike.handshake.failed") {
		if event.Peer != "" {
			t.Errorf("a refused handshake was recorded under %q", event.Peer)
		}
	}
}

// a dial that cannot reach its peer is recorded every time it fails, and a wake is recorded too
func TestDialerRecordsFailuresAndWakes(t *testing.T) {
	cfg, privateKey, reg := runtimeFixture(t)
	unresolvable := "gateway.invalid"
	reg[0].Nodes[1].Endpoints[0].Address = &unresolvable
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bus := events.New()
	c := &Client{ctx: ctx, cancel: cancel, privateKey: privateKey,
		dialers: make(map[string]*dialer), dialRetry: time.Hour, events: bus}
	c.cfg.Store(cfg)
	c.storeIndex(trust(t, reg))

	wake := make(chan struct{}, 1)
	done := make(chan struct{})
	d := dialTo(t, cfg, cfg.Dial.To[0])
	go func() { c.runPeer(ctx, d, wake); close(done) }()
	waitFor(t, convergeBudget, "the first dial to fail", func() bool { return len(recorded(bus, "dial.failed")) == 1 })
	wake <- struct{}{}
	waitFor(t, convergeBudget, "the woken dialer to fail again", func() bool { return len(recorded(bus, "dial.failed")) == 2 })
	cancel()
	<-done

	path := d.path
	woken := recorded(bus, "dial.woken")
	failed := recorded(bus, "dial.failed")
	if len(woken) != 1 || woken[0].Peer != path || failed[0].Peer != path || !strings.Contains(failed[0].Attrs["err"], "gateway.invalid") {
		t.Errorf("the dialer recorded wakes %+v and failures %+v", woken, failed)
	}
}

// a dialer says its first dial at info, and a dial after one that failed at debug as it says a failure repeated
// a session's end, the dial after it and the first failure after it are said at info, since the outcome changed
// the dial line names the address as the dial.attempt does
func TestDialerSaysAChangeOfOutcomeAtInfoAndARepeatAtDebug(t *testing.T) {
	written := &syncBuffer{}
	logtest.SetDefault(t, slog.New(slog.NewTextHandler(written, &slog.HandlerOptions{Level: slog.LevelDebug})))
	alpha, bravo := newLoopbackMesh(t)
	quiet := *bravo.cfg
	quiet.Dial.To = nil
	bravo.client.cfg.Store(&quiet)
	alpha.client.dialRetry = redialAfter
	trusting := bravo.client.index()
	// bravo no longer trusts alpha, so alpha's handshake fails after its endpoint resolved
	refusing := trust(t, registry.Registry{{Organization: "example", Nodes: []registry.Node{{CommonName: bravo.name,
		Endpoints: []registry.Endpoint{{SerialNumber: "0", AddressFamily: "ip4", Port: bravo.port}}}}}})
	bravo.client.storeIndex(refusing)
	run(t, alpha, bravo)
	waitFor(t, convergeBudget, "alpha's third dial to fail", func() bool { return len(recorded(alpha.events, "dial.failed")) >= 3 })
	bravo.client.storeIndex(trusting)
	waitFor(t, convergeBudget, "alpha's session to come up", func() bool { return len(alpha.client.sessions.snapshot()) == 1 })
	bravo.client.storeIndex(refusing)
	failed := len(recorded(alpha.events, "dial.failed"))
	// a dial's end is said after its dial.failed is recorded, at info or as a repeat at debug
	ends := func() int { return written.count("reconnecting in") + written.count("peer dial failed again") }
	said := ends()
	alpha.client.sessions.snapshot()[0].session.Mux().Close()
	waitFor(t, convergeBudget, "alpha's dial after the session to fail", func() bool { return len(recorded(alpha.events, "dial.failed")) > failed })
	waitFor(t, convergeBudget, "alpha to say the session's end and the failure after it", func() bool { return ends() >= said+2 })

	levels := func(phrase string) []string {
		var out []string
		for _, line := range written.lines(phrase) {
			level, _, _ := strings.Cut(strings.TrimPrefix(line[strings.Index(line, "level="):], "level="), " ")
			out = append(out, level)
		}
		return out
	}
	// the dials before the session's are 3 failures and the session's own
	dials := levels(": dialing ")
	after := slices.Index(dials[1:], "INFO") + 1
	if dials[0] != "INFO" || after < 4 || slices.Contains(dials[after+1:], "INFO") {
		t.Errorf("alpha said its dials at %v, want the first and the one after the session ended at info and the rest at debug", dials)
	}
	if said := strings.Count(strings.Join(levels("reconnecting in"), " "), "INFO"); said != 3 {
		t.Errorf("alpha said %d failures and ends at info, want the first failure, the session's end and the first failure after it:\n%s", said, strings.Join(written.lines("reconnecting in"), "\n"))
	}
	remote := recorded(alpha.events, "dial.attempt")[0].Attrs["remote"]
	if line := written.lines(": dialing ")[0]; !strings.Contains(line, "dialing "+remote) {
		t.Errorf("the dial line %q names another address than the dial.attempt's %s", line, remote)
	}
}

// a dialer that stood down behind a session the other end opened says its next dial and the first failure after it at info, since the outcome changed
func TestDialerSaysItsDialAfterAStandingSessionAtInfo(t *testing.T) {
	written := &syncBuffer{}
	logtest.SetDefault(t, slog.New(slog.NewTextHandler(written, &slog.HandlerOptions{Level: slog.LevelDebug})))
	alpha, bravo := newLoopbackMesh(t)
	quiet := *bravo.cfg
	quiet.Dial.To = nil
	bravo.client.cfg.Store(&quiet)
	// alpha dials only when woken
	alpha.client.dialRetry = time.Hour
	wake := func() {
		alpha.client.dialersMu.Lock()
		var paths []string
		for path := range alpha.client.dialers {
			paths = append(paths, path)
		}
		alpha.client.dialersMu.Unlock()
		alpha.client.wakeDialers(paths)
	}
	trusting := bravo.client.index()
	// bravo no longer trusts alpha, so alpha's handshake fails after its endpoint resolved
	refusing := trust(t, registry.Registry{{Organization: "example", Nodes: []registry.Node{{CommonName: bravo.name,
		Endpoints: []registry.Endpoint{{SerialNumber: "0", AddressFamily: "ip4", Port: bravo.port}}}}}})
	bravo.client.storeIndex(refusing)
	ctx, _ := run(t, alpha, bravo)
	waitFor(t, convergeBudget, "alpha's first dial to fail", func() bool { return len(recorded(alpha.events, "dial.failed")) == 1 })
	wake()
	waitFor(t, convergeBudget, "alpha's second dial to fail", func() bool { return len(recorded(alpha.events, "dial.failed")) == 2 })

	// bravo opens the session, and alpha's woken dialer stands down behind it
	bravo.client.storeIndex(trusting)
	go bravo.client.connectPeer(ctx, dialTo(t, bravo.cfg, bravo.cfg.Dial.To[0]), slog.LevelInfo)
	waitFor(t, convergeBudget, "bravo's session to come up", func() bool { return len(alpha.client.sessions.snapshot()) == 1 })
	woken := len(recorded(alpha.events, "dial.woken"))
	wake()
	waitFor(t, convergeBudget, "alpha's dialer to take the wake", func() bool { return len(recorded(alpha.events, "dial.woken")) > woken })
	// a second wake is taken only once the dial the first set going has stood down
	wake()
	waitFor(t, convergeBudget, "alpha's dialer to stand down", func() bool { return len(recorded(alpha.events, "dial.woken")) > woken+1 })

	bravo.client.storeIndex(refusing)
	alpha.client.sessions.snapshot()[0].session.Mux().Close()
	// the dialer stands down until the session has left the set, so it is woken until it dials
	waitFor(t, convergeBudget, "alpha's dial after the session to fail", func() bool {
		wake()
		return len(recorded(alpha.events, "dial.failed")) >= 3
	})

	levels := func(phrase string) []string {
		var out []string
		for _, line := range written.lines(phrase) {
			level, _, _ := strings.Cut(strings.TrimPrefix(line[strings.Index(line, "level="):], "level="), " ")
			out = append(out, level)
		}
		return out
	}
	// alpha's own dials end in bravo's port, where bravo's dial ends in alpha's
	// a wake left queued may dial once more, as a repeat
	if dials := levels(fmt.Sprintf(": dialing 127.0.0.1:%d\"", bravo.port)); len(dials) < 3 || !slices.Equal(dials[:3], []string{"INFO", "DEBUG", "INFO"}) {
		t.Errorf("alpha said its dials at %v, want the first and the one after the session at info", dials)
	}
	if said := levels("reconnecting in"); !slices.Equal(said, []string{"INFO", "INFO"}) {
		t.Errorf("alpha said failures at %v, want the first and the first after the session at info:\n%s", said, strings.Join(written.lines("reconnecting in"), "\n"))
	}
}

// the dial line names an IPv6 endpoint with its address in brackets, as the dial.attempt does
func TestDialLineBracketsAnIPv6Endpoint(t *testing.T) {
	written := &syncBuffer{}
	logtest.SetDefault(t, slog.New(slog.NewTextHandler(written, nil)))
	cfg, privateKey, reg := runtimeFixture(t)
	silent, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	loopback := "::1"
	for i := range reg[0].Nodes {
		reg[0].Nodes[i].Endpoints[0].AddressFamily = "ip6"
	}
	reg[0].Nodes[1].Endpoints[0].Address = &loopback
	reg[0].Nodes[1].Endpoints[0].Port = uint16(silent.LocalAddr().(*net.UDPAddr).Port)
	cfg.Link.Endpoints[0].Family = "ip6"
	hub, err := transport.NewHub("[::1]:0", transport.Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bus := events.New()
	c := &Client{ctx: ctx, cancel: cancel, privateKey: privateKey, hub: hub, sessions: newSessionSet(), events: bus}
	c.cfg.Store(cfg)
	c.storeIndex(trust(t, reg))
	done := make(chan error, 1)
	go func() { done <- c.connectPeer(ctx, dialTo(t, cfg, cfg.Dial.To[0]), slog.LevelInfo) }()
	waitFor(t, convergeBudget, "the handshake to start", func() bool { return len(recorded(bus, "dial.attempt")) == 1 })
	cancel()
	<-done
	want := fmt.Sprintf("dialing [::1]:%d", silent.LocalAddr().(*net.UDPAddr).Port)
	if lines := written.lines(": dialing "); len(lines) != 1 || !strings.Contains(lines[0], want) || recorded(bus, "dial.attempt")[0].Attrs["remote"] != want[len("dialing "):] {
		t.Errorf("the dial was said as %q and recorded with remote %s, want %q in both", lines, recorded(bus, "dial.attempt")[0].Attrs["remote"], want)
	}
}

// a dial the host has no route for waits 10 seconds, then twice the wait before it up to a minute, and any other end of a dial starts that over
func TestUnroutedDialsBackOffToAMinute(t *testing.T) {
	c := &Client{}
	unrouted := fmt.Errorf("handshake: %w", &net.OpError{Op: "write", Net: "udp", Err: os.NewSyscallError("sendto", syscall.ENETUNREACH)})
	var waits []time.Duration
	wait := time.Duration(0)
	for range 6 {
		wait = c.unroutedDelay(unrouted, wait)
		waits = append(waits, wait)
	}
	if want := []time.Duration{10 * time.Second, 20 * time.Second, 40 * time.Second, time.Minute, time.Minute, time.Minute}; !slices.Equal(waits, want) {
		t.Errorf("dials the host had no route for in a row waited %v, want %v", waits, want)
	}
	if got := c.unroutedDelay(errors.New("handshake: no response"), wait); got != 0 {
		t.Errorf("a dial that went unanswered after them waits %v of the backoff, want the reconnect delay", got)
	}
	// a host the host's route leads to but cannot reach is no missing route
	unreachable := fmt.Errorf("handshake: %w", &net.OpError{Op: "write", Net: "udp", Err: os.NewSyscallError("sendto", syscall.EHOSTUNREACH)})
	if got := c.unroutedDelay(unreachable, wait); got != 0 {
		t.Errorf("a dial that ended in EHOSTUNREACH after them waits %v of the backoff, want the reconnect delay", got)
	}
}

// servedSocket serves src on a control socket until the test ends, and returns the socket's path
// the socket sits in a directory of its own under the system's, whose short path a socket's address holds
func servedSocket(t *testing.T, src control.Source) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "rl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket := filepath.Join(dir, "control.sock")
	listener, err := control.Listen(socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go control.Serve(listener, src)
	return socket
}

// a verb asked over the socket is recorded with the uid the socket reported and what it came to
// a refused verb, which acted on nothing, is recorded once without a peer and with the peer as it was asked for
func TestVerbIsRecordedWithItsCaller(t *testing.T) {
	bus := events.New()
	socket := servedSocket(t, &Client{events: bus, dialers: make(map[string]*dialer)})

	if _, err := control.Dial(socket).Redial("nobody", false); err == nil {
		t.Fatal("a redial of a peer this node does not know succeeded")
	}
	if _, err := control.Dial(socket).Enable(control.SubsystemReconciler); err == nil {
		t.Fatal("a node that reconciles nothing started its reconciler")
	}
	if _, err := control.Dial(socket).Rekey("", false); err == nil {
		t.Fatal("a rekey naming neither a peer nor every session succeeded")
	}
	if _, err := control.Dial(socket).Reload(); err == nil {
		t.Fatal("a node never told its file reloaded")
	}
	verbs := recorded(bus, "control.verb")
	var asked []string
	for _, verb := range verbs {
		asked = append(asked, verb.Attrs["verb"])
		if verb.Attrs["uid"] != fmt.Sprint(os.Getuid()) || verb.Attrs["pid"] != fmt.Sprint(os.Getpid()) || verb.Attrs["err"] == "" {
			t.Errorf("a refused verb was recorded as %+v", verb)
		}
	}
	if want := []string{"redial", "enable", "rekey", "reload"}; !slices.Equal(asked, want) {
		t.Fatalf("the verbs %q were recorded, want %q", asked, want)
	}
	if verbs[0].Peer != "" || verbs[0].Attrs["peer"] != "nobody" || !strings.Contains(verbs[0].Attrs["err"], "nothing to redial") {
		t.Errorf("a redial over the socket was recorded as %+v", verbs[0])
	}
	if verbs[1].Attrs["subsystem"] != string(control.SubsystemReconciler) {
		t.Errorf("a start over the socket was recorded as %+v", verbs[1])
	}
	if verbs[2].Attrs["all"] != "false" {
		t.Errorf("a rekey over the socket was recorded as %+v", verbs[2])
	}
}

// a reload that fails is recorded with its file and what failed
func TestFailedReloadIsRecordedWithItsError(t *testing.T) {
	bus := events.New()
	missing := filepath.Join(t.TempDir(), "missing.toml")
	if err := (&Client{events: bus}).ReloadFrom(missing); err == nil {
		t.Fatal("a reload of a missing file succeeded")
	}
	if reloads := recorded(bus, "daemon.reload"); len(reloads) != 1 || reloads[0].Attrs["path"] != missing || reloads[0].Attrs["err"] == "" {
		t.Errorf("a failed reload was recorded as %+v", reloads)
	}
}
