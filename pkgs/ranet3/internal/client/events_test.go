// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/ike"
	"ranet3.com/pkgs/ranet3/internal/events"
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
// the dial names no serial, so the path is the session's from the endpoint it resolved
// each end's rekey is recorded under the path naming the other end
// the end that answered records its side of the session
// a reload is recorded with its file
// and the session's end is recorded when the node stops
func TestLoopbackRecordsDialSessionAndNeighborInOrder(t *testing.T) {
	alpha, bravo := newLoopbackMesh(t)
	// bravo answers and never dials, so every session is the one alpha dials
	quiet := *bravo.cfg
	quiet.Dial.To = nil
	bravo.client.cfg.Store(&quiet)
	unpinned := *alpha.cfg
	unpinned.Dial.To = slices.Clone(alpha.cfg.Dial.To)
	unpinned.Dial.To[0].Serial = ""
	alpha.client.cfg.Store(&unpinned)
	if alpha.client.sessions.events != alpha.events || alpha.client.KernelRuntime().Events != alpha.events {
		t.Error("the session set or the reconciler records somewhere other than the node's bus")
	}
	_, stop := run(t, alpha, bravo)

	dialed := fmt.Sprintf("example/%s/0@0", bravo.name)
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
	answered := recorded(bravo.events, "ike.session.established")
	if len(answered) == 0 || answered[0].Peer != fmt.Sprintf("example/%s/0@0", alpha.name) || answered[0].Attrs["role"] != "responder" {
		t.Errorf("bravo recorded its session as %+v", answered)
	}
	// alpha dialed, and receives on the SPI its own SA holds as local
	dialing := recorded(alpha.events, "ike.session.established")
	if own := alpha.client.sessions.snapshot(); len(dialing) == 0 || len(own) != 1 || dialing[0].Peer != dialed || dialing[0].Attrs["role"] != "initiator" ||
		dialing[0].Attrs["spi_in"] != fmt.Sprintf("%08x", own[0].session.Child.LocalSPI) ||
		dialing[0].Attrs["spi_out"] != fmt.Sprintf("%08x", own[0].session.Child.RemoteSPI) {
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
			return kind == "ike.rekey.completed" && matchesPeer(peer, end.other.name)
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
	const path = "example/gateway/1@0"
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
	if _, adopted := alpha.client.sessions.adoptPreferred(fmt.Sprintf("example/%s/0@0", bravo.name), held, true, nil); !adopted {
		t.Fatal("the held session was not adopted")
	}
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
	hub, err := transport.NewHub("127.0.0.1:0", transport.Underlay{}, transport.Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bus := events.New()
	c := &Client{ctx: ctx, cancel: cancel, privateKey: privateKey, hub: hub, sessions: newSessionSet(), events: bus}
	c.cfg.Store(cfg)
	c.storeRegistry(reg)

	done := make(chan error, 1)
	go func() { done <- c.connectPeer(ctx, cfg.Link.Endpoints[0], cfg.Dial.To[0], "example/gateway/1@0") }()
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
	unpinned.Dial.To[0].Serial = ""
	alpha.client.cfg.Store(&unpinned)
	alpha.client.dialRetry = redialAfter
	// bravo no longer trusts alpha, so alpha's handshake fails after its endpoint resolved
	trusted := bravo.client.registry()[0]
	trusted.Nodes = slices.DeleteFunc(slices.Clone(trusted.Nodes), func(node registry.Node) bool { return node.CommonName == alpha.name })
	bravo.client.storeRegistry(registry.Registry{trusted})
	run(t, alpha, bravo)
	waitFor(t, convergeBudget, "alpha's dial to fail", func() bool { return len(recorded(alpha.events, "dial.failed")) > 0 })
	session := fmt.Sprintf("example/%s/0@0", bravo.name)
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
	c.storeRegistry(reg)

	wake := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() { c.runPeer(ctx, cfg.Link.Endpoints[0], cfg.Dial.To[0], wake); close(done) }()
	waitFor(t, convergeBudget, "the first dial to fail", func() bool { return len(recorded(bus, "dial.failed")) == 1 })
	wake <- struct{}{}
	waitFor(t, convergeBudget, "the woken dialer to fail again", func() bool { return len(recorded(bus, "dial.failed")) == 2 })
	cancel()
	<-done

	path := peerPath(cfg.Dial.To[0], cfg.Link.Endpoints[0])
	woken := recorded(bus, "dial.woken")
	failed := recorded(bus, "dial.failed")
	if len(woken) != 1 || woken[0].Peer != path || failed[0].Peer != path || !strings.Contains(failed[0].Attrs["err"], "gateway.invalid") {
		t.Errorf("the dialer recorded wakes %+v and failures %+v", woken, failed)
	}
}

// a verb asked over the socket is recorded with the uid the socket reported and what it came to
// a refused verb, which acted on nothing, is recorded once without a peer and with the peer as it was asked for
func TestVerbIsRecordedWithItsCaller(t *testing.T) {
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
	defer listener.Close()
	bus := events.New()
	go control.Serve(listener, &Client{events: bus, dialers: make(map[string]*dialer)})

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
