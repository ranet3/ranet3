// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/ike"
	"ranet3.com/pkgs/ranet3/internal/babel"
	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/registry"
	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
)

// writable builds a node with all three subsystems configured, so a test below
// asks about the verb rather than about which blocks the file happens to
// carry.
func writable(t *testing.T) *Client {
	t.Helper()
	steering, err := srv6.NewSteerTable([]srv6.Steer{{
		To:  schema.MustPrefix("3fff:1::/48"),
		Via: []schema.Addr{schema.MustAddr("3fff:b:0:206::1")},
	}}, schema.MustAddr("3fff:b:0:100::1"))
	if err != nil {
		t.Fatal(err)
	}
	mesh := &netstack.Mesh{Routes: netstack.NewRouteTable()}
	mesh.SetSteering(steering)
	// A speaker and a registry, because a test below reads the whole status
	// rather than the stopped set alone: a subsystem stopped and not reported
	// is a node running less than its file says with nothing saying so.
	speaker, err := babel.New(babel.Config{}, babel.Routes{}, babel.Runtime{}, mesh)
	if err != nil {
		t.Fatal(err)
	}
	c := &Client{
		Mesh:     mesh,
		speaker:  speaker,
		sessions: newSessionSet(),
		dialers:  make(map[string]*dialer),
		running:  startedSubsystems(),
	}
	c.cfg.Store(&config.Config{Node: identity.MustParse("example/node"), Link: config.Link{Listen: true}})
	c.storeIndex(trust(t, registry.Registry{}))
	c.SetReconcilerEnable(func(bool) {})
	return c
}

// Each verb stops its own subsystem and starts it again, and a status reports
// what it leaves. Steering is read off the mesh rather than off the record:
// the record holds what a write remembered and the mesh holds what a packet
// meets.
func TestSubsystemStopsAndStartsWhatItNames(t *testing.T) {
	c := writable(t)
	var reconciler []bool
	c.SetReconcilerEnable(func(on bool) { reconciler = append(reconciler, on) })

	if _, err := c.SetSubsystem(context.Background(), control.SubsystemSteering, false); err != nil {
		t.Fatal(err)
	}
	if c.Mesh.SteeringEnabled() {
		t.Error("steering was stopped and the mesh is still acting on its policies")
	}
	if c.Mesh.Steering() == nil {
		t.Error("stopping steering unloaded the table, so a diagnostic can no longer report what was stopped")
	}
	if _, err := c.SetSubsystem(context.Background(), control.SubsystemReconciler, false); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SetSubsystem(context.Background(), control.SubsystemResponder, false); err != nil {
		t.Fatal(err)
	}
	if got := c.Status().Disabled; len(got) != 3 {
		t.Errorf("the status reports %v stopped, want all three", got)
	}
	if len(reconciler) != 1 || reconciler[0] {
		t.Errorf("the reconciler was told %v, want one stop", reconciler)
	}

	result, err := c.SetSubsystem(context.Background(), control.SubsystemSteering, true)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Mesh.SteeringEnabled() {
		t.Error("steering was started again and the mesh is not acting on its policies")
	}
	if !strings.Contains(result.Detail, "running") {
		t.Errorf("starting answered %q", result.Detail)
	}
	// A second ask is answered as the no-op it is rather than reported as a
	// change somebody then goes looking for in the logs.
	again, err := c.SetSubsystem(context.Background(), control.SubsystemSteering, true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(again.Detail, "already") {
		t.Errorf("a repeated start answered %q, want it to say nothing moved", again.Detail)
	}
}

// A subsystem outside the closed set, and one this node's file never turned
// on, are both refused by name. Reporting either as stopped tells an operator
// their node is in a state it was never in.
func TestSubsystemRefusesWhatThisNodeDoesNotRun(t *testing.T) {
	c := writable(t)
	if _, err := c.SetSubsystem(context.Background(), "dataplane", false); err == nil {
		t.Error("a subsystem outside the set was accepted")
	} else if !strings.Contains(err.Error(), "reconciler") {
		t.Errorf("the refusal reads %q, want it to name the set", err)
	}

	bare := &Client{Mesh: &netstack.Mesh{}, running: startedSubsystems()}
	bare.cfg.Store(&config.Config{})
	for name, want := range map[control.Subsystem]string{
		control.SubsystemReconciler: "cap.table",
		control.SubsystemSteering:   "cap.segment",
		control.SubsystemResponder:  "link.listen",
	} {
		if _, err := bare.SetSubsystem(context.Background(), name, false); err == nil {
			t.Errorf("%s was stopped on a node that does not run it", name)
		} else if !strings.Contains(err.Error(), want) {
			t.Errorf("the %s refusal reads %q, want it to name %s", name, err, want)
		}
	}
	if got := bare.disabledSubsystems(); got != nil {
		t.Errorf("a refused stop still recorded %v", got)
	}
}

// Stopping the responder leaves the sessions this node already holds alone,
// dialed and answered alike: it refuses the next handshake and is not a way to
// drop the mesh. TestStoppedResponderRefusesLiveHandshakes covers the refusal
// itself, against a peer actually dialing in.
func TestStoppedResponderKeepsTheSessionsItHolds(t *testing.T) {
	c := writable(t)
	if !c.subsystemRunning(control.SubsystemResponder) {
		t.Fatal("the fixture node does not answer dials, so this proves nothing")
	}
	c.sessions.close = func(*ike.Session) { t.Error("stopping the responder closed a live session") }
	c.sessions.active = func(*ike.Session) bool { return true }
	c.sessions.adoptPreferred("example/gateway:1@0", &ike.Session{}, true, nil)

	if _, err := c.SetSubsystem(context.Background(), control.SubsystemResponder, false); err != nil {
		t.Fatal(err)
	}
	if c.subsystemRunning(control.SubsystemResponder) {
		t.Error("a stopped responder still serves what it answers")
	}
	if !c.sessions.holds("example/gateway:1@0") {
		t.Error("stopping the responder dropped a session this node already held")
	}
}

// Redial drops what this node holds for the peer and cuts the reconnect delay
// short, the half of a stuck session this side can act on when the peer does
// not retry on its own. The session leaves the set before the dialer is woken,
// or the dialer stands down behind a session that is already going.
func TestRedialDropsSessionsAndWakesDialers(t *testing.T) {
	c := writable(t)
	var closedMu sync.Mutex
	var closed []*ike.Session
	c.sessions.close = func(sess *ike.Session) {
		closedMu.Lock()
		defer closedMu.Unlock()
		closed = append(closed, sess)
	}
	c.sessions.active = func(*ike.Session) bool { return true }
	held := &ike.Session{}
	if _, adopted := c.sessions.adoptPreferred("example/gateway:1@0", held, true, nil); !adopted {
		t.Fatal("the fixture session was not adopted")
	}
	woken := &dialer{cancel: func() {}, wake: make(chan struct{}, 1)}
	c.dialers["example/gateway:1@0"] = woken
	other := &dialer{cancel: func() {}, wake: make(chan struct{}, 1)}
	c.dialers["example/elsewhere:1@0"] = other

	result, err := c.Redial(context.Background(), "gateway", false)
	if err != nil {
		t.Fatal(err)
	}
	closedMu.Lock()
	if len(closed) != 1 || closed[0] != held {
		t.Errorf("redial closed %d sessions, want the one held for the peer", len(closed))
	}
	closedMu.Unlock()
	if c.sessions.holds("example/gateway:1@0") {
		t.Error("the session is still in the set, so the woken dialer stands down behind it")
	}
	select {
	case <-woken.wake:
	default:
		t.Error("the peer's dialer was not woken, so it waits out the whole reconnect delay")
	}
	select {
	case <-other.wake:
		t.Error("a dialer for another peer was woken")
	default:
	}
	if !strings.Contains(result.Detail, "1 session") {
		t.Errorf("redial answered %q", result.Detail)
	}

	if _, err := c.Redial(context.Background(), "nobody", false); err == nil {
		t.Error("redialing a peer this node neither dials nor holds was accepted")
	}
}

func TestRedialAtAnEndpointWakesTheDialersOfItsNode(t *testing.T) {
	dialers := []string{"example/gateway@0", "example/gateway@1", "example/gateway:2@0"}
	for _, tc := range []struct {
		name, peer string
		held       bool
		woken      []string
	}{
		{"endpoint", "example/gateway:1", true, []string{"example/gateway@0", "example/gateway@1"}},
		{"endpoint with nothing held", "example/gateway:1", false, []string{"example/gateway@0", "example/gateway@1"}},
		{"session path", "example/gateway:1@0", true, []string{"example/gateway@0"}},
		{"unknown local endpoint", "example/gateway:1@9", true, nil},
		{"malformed endpoint", "example/gateway:1:x", true, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := writable(t)
			c.sessions.close = func(*ike.Session) {}
			c.sessions.active = func(*ike.Session) bool { return true }
			if tc.held {
				c.sessions.adoptPreferred("example/gateway:1@0", &ike.Session{}, true, nil)
			}
			for _, path := range dialers {
				c.dialers[path] = &dialer{cancel: func() {}, wake: make(chan struct{}, 1)}
			}
			_, err := c.Redial(context.Background(), tc.peer, false)
			if tc.woken == nil {
				if err == nil {
					t.Errorf("redial %s was accepted", tc.peer)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			var woken []string
			for _, path := range dialers {
				select {
				case <-c.dialers[path].wake:
					woken = append(woken, path)
				default:
				}
			}
			if !slices.Equal(woken, tc.woken) {
				t.Errorf("redial %s woke %q, want %q", tc.peer, woken, tc.woken)
			}
		})
	}
}

// A peer this node only answers has no dialer, and dropping its session is
// still the useful half: the peer opens a new one.
func TestRedialDropsResponderOnlySession(t *testing.T) {
	c := writable(t)
	c.sessions.close = func(*ike.Session) {}
	c.sessions.active = func(*ike.Session) bool { return true }
	c.sessions.adoptPreferred("example/inbound:1@0", &ike.Session{}, true, nil)
	result, err := c.Redial(context.Background(), "example/inbound", false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result.Detail, "1 session") || !strings.Contains(result.Detail, "0 dialer") {
		t.Errorf("redial answered %q, want one session and no dialer", result.Detail)
	}
}

// every peer drops every session this node holds and wakes every dialer, as a peer does that one peer's
// a peer and every peer at once, or neither, is refused, and so is every peer on a node holding nothing
func TestRedialAllDropsEverySessionAndWakesEveryDialer(t *testing.T) {
	c := writable(t)
	var closedMu sync.Mutex
	closed := 0
	c.sessions.close = func(*ike.Session) {
		closedMu.Lock()
		defer closedMu.Unlock()
		closed++
	}
	c.sessions.active = func(*ike.Session) bool { return true }
	c.sessions.adoptPreferred("example/gateway:1@0", &ike.Session{}, true, nil)
	c.sessions.adoptPreferred("example/inbound:1@0", &ike.Session{}, true, nil)
	dialers := []*dialer{{cancel: func() {}, wake: make(chan struct{}, 1)}, {cancel: func() {}, wake: make(chan struct{}, 1)}}
	c.dialers["example/gateway:1@0"] = dialers[0]
	c.dialers["example/elsewhere:1@0"] = dialers[1]

	for _, refused := range []struct {
		peer string
		all  bool
	}{{"gateway", true}, {"", false}} {
		if _, err := c.Redial(context.Background(), refused.peer, refused.all); err == nil {
			t.Errorf("a redial of peer %q with every peer %v was accepted", refused.peer, refused.all)
		}
	}
	result, err := c.Redial(context.Background(), "", true)
	if err != nil {
		t.Fatal(err)
	}
	closedMu.Lock()
	if closed != 2 {
		t.Errorf("redial --all closed %d sessions, want both", closed)
	}
	closedMu.Unlock()
	for i, dialer := range dialers {
		select {
		case <-dialer.wake:
		default:
			t.Errorf("dialer %d was not woken", i)
		}
	}
	if want := []string{"example/elsewhere:1@0", "example/gateway:1@0", "example/inbound:1@0"}; !slices.Equal(result.Acted, want) {
		t.Errorf("redial --all acted on %v, want %v", result.Acted, want)
	}

	bare := writable(t)
	if _, err := bare.Redial(context.Background(), "", true); err == nil {
		t.Error("redial --all on a node that neither dials nor holds a session was accepted")
	}
}

// A dialer waiting out its reconnect delay comes round as soon as it is woken
// rather than at the end of it, which is the difference between a redial that
// acts now and one that acts in ten seconds. The loop under test is the real
// one, because a wake that never reaches its select is a redial that reports
// success and changes nothing.
func TestDialerWakesBeforeItsReconnectDelay(t *testing.T) {
	cfg, privateKey, reg := runtimeFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &Client{ctx: ctx, cancel: cancel, privateKey: privateKey,
		dialers: make(map[string]*dialer), dialRetry: time.Hour}
	c.cfg.Store(cfg)

	// A name the dialer takes and the resolver refuses, so each pass is one
	// attempt and then the wait this test is about. RFC 6761 reserves
	// .invalid for it.
	unresolvable := "gateway.invalid"
	reg[0].Nodes[1].Endpoints[0].Address = &unresolvable
	c.storeIndex(trust(t, reg))
	wake := make(chan struct{}, 1)
	done := make(chan struct{})
	d := dialTo(t, cfg, cfg.Dial.To[0])
	go func() {
		c.runPeer(ctx, d, wake)
		close(done)
	}()

	// Taking the node out of the registry ends the loop on its next pass, so
	// whether the loop came round is observable without a counter.
	time.Sleep(100 * time.Millisecond)
	c.storeIndex(trust(t, registry.Registry{}))
	select {
	case <-done:
		t.Fatal("the dialer came round with no wake, so this measures nothing about one")
	case <-time.After(200 * time.Millisecond):
	}

	wake <- struct{}{}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Error("a woken dialer waited out its reconnect delay")
	}
}

// rekey reaches one peer's sessions, --all reaches every one, and neither
// reaches a session it did not name.
func TestRekeyAsksTheSessionsItNames(t *testing.T) {
	c := writable(t)
	c.sessions.close = func(*ike.Session) {}
	c.sessions.active = func(*ike.Session) bool { return true }
	asked := make(chan *ike.Session, 4)
	c.sessions.rekey = func(sess *ike.Session) error {
		asked <- sess
		return nil
	}
	gateway, elsewhere := &ike.Session{}, &ike.Session{}
	c.sessions.adoptPreferred("example/gateway:1@0", gateway, true, nil)
	c.sessions.adoptPreferred("example/elsewhere:1@0", elsewhere, true, nil)

	result, err := c.Rekey(context.Background(), "gateway", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Acted) != 1 || result.Acted[0] != "example/gateway:1@0" {
		t.Errorf("rekey acted on %v, want the one peer", result.Acted)
	}
	select {
	case sess := <-asked:
		if sess != gateway {
			t.Error("rekey reached a session it did not name")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no session was asked to rekey")
	}

	if _, err := c.Rekey(context.Background(), "", true); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		select {
		case <-asked:
		case <-time.After(5 * time.Second):
			t.Fatal("--all left a session unasked")
		}
	}

	if _, err := c.Rekey(context.Background(), "gateway", true); err == nil {
		t.Error("a peer and --all together were accepted")
	}
	if _, err := c.Rekey(context.Background(), "", false); err == nil {
		t.Error("a rekey naming neither a peer nor --all was accepted")
	}
	if _, err := c.Rekey(context.Background(), "nobody", false); err == nil {
		t.Error("rekeying a peer this node holds no session with was accepted")
	}
}

const (
	// rekeyTestWait is the rekey verb's wait in the tests, long enough for a rekey that returns at once to be waited for on a loaded machine
	rekeyTestWait = 500 * time.Millisecond
	// rekeyAnswerBudget is how long past rekeyTestWait the verb's answer may take on a loaded machine, short of a wait that never ends
	rekeyAnswerBudget = 5 * time.Second
	// rekeyUnendingWait is a rekey wait no test outlasts
	rekeyUnendingWait = time.Hour
)

// rekeyAll asks c to rekey every session and returns the answer, failing where it takes longer than the verb's wait and rekeyAnswerBudget
func rekeyAll(t *testing.T, c *Client) control.Result {
	t.Helper()
	type answer struct {
		result control.Result
		err    error
	}
	answered := make(chan answer, 1)
	go func() {
		result, err := c.Rekey(context.Background(), "", true)
		answered <- answer{result, err}
	}()
	select {
	case got := <-answered:
		if got.err != nil {
			t.Fatal(got.err)
		}
		return got.result
	case <-time.After(c.sessions.rekeyWait + rekeyAnswerBudget):
		t.Fatalf("the rekey verb did not answer within %s", c.sessions.rekeyWait+rekeyAnswerBudget)
		return control.Result{}
	}
}

// a rekey answers with the sessions that rekeyed and each that did not with why, a rekey still running when the wait ran out among the ones that did not
// each that did not is logged and recorded as control.verb under its path with its reason, and each that rekeyed is recorded with none
// the answer renders as the golden files, and one where every session rekeyed lists them all
func TestRekeyAnswersWhichSessionsRekeyed(t *testing.T) {
	c := writable(t)
	c.events = events.New()
	written := capturedLog(t)
	c.sessions.close = func(*ike.Session) {}
	c.sessions.active = func(*ike.Session) bool { return true }
	c.sessions.rekeyWait = rekeyTestWait
	held := errors.New("ike: a Child SA rekey waits out the retry delay of the one that failed")
	bravo, charlie, delta := &ike.Session{}, &ike.Session{}, &ike.Session{}
	// the first ask finds charlie held and delta's exchange outlasting the wait, and the second finds every session free
	var failing atomic.Bool
	failing.Store(true)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	c.sessions.rekey = func(sess *ike.Session) error {
		switch {
		case sess == charlie && failing.Load():
			return held
		case sess == delta && failing.Load():
			<-release
		}
		return nil
	}
	for path, sess := range map[string]*ike.Session{"example/bravo:0@0": bravo, "example/charlie:0@0": charlie, "example/delta:0@0": delta} {
		c.sessions.adoptPreferred(path, sess, true, nil)
	}
	render := func(name string, result control.Result) {
		t.Helper()
		var out bytes.Buffer
		control.RenderResult(&out, result)
		verbGolden(t, name+".txt", out.Bytes())
		body, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		verbGolden(t, name+".json", append(body, '\n'))
	}

	result := rekeyAll(t, c)
	stillRunning := fmt.Sprintf("still rekeying after %s, and ike.rekey.completed or ike.rekey.failed tells how it ends", control.Spelled(rekeyTestWait))
	wantMissed := []control.Missed{{Entry: "example/charlie:0@0", Reason: held.Error()}, {Entry: "example/delta:0@0", Reason: stillRunning}}
	if !slices.Equal(result.Acted, []string{"example/bravo:0@0"}) || !slices.Equal(result.Missed, wantMissed) {
		t.Errorf("the rekey answered that %v rekeyed and %+v did not, want bravo alone rekeyed and %+v", result.Acted, result.Missed, wantMissed)
	}
	render("rekey-missed", result)
	if got := written.count("peer example/charlie:0@0: rekey asked for on the control socket: " + held.Error()); got != 1 {
		t.Errorf("the held rekey was logged %d times, want once", got)
	}
	reasons := map[string]string{}
	for _, event := range recorded(c.events, "control.verb") {
		reasons[event.Peer] = event.Attrs["err"]
	}
	if want := map[string]string{"example/bravo:0@0": "", "example/charlie:0@0": held.Error(), "example/delta:0@0": stillRunning}; !maps.Equal(reasons, want) {
		t.Errorf("the rekey was recorded with the reasons %q, want %q", reasons, want)
	}

	failing.Store(false)
	result = rekeyAll(t, c)
	if want := []string{"example/bravo:0@0", "example/charlie:0@0", "example/delta:0@0"}; !slices.Equal(result.Acted, want) || len(result.Missed) != 0 {
		t.Errorf("the second rekey answered that %v rekeyed and %+v did not, want %v and none", result.Acted, result.Missed, want)
	}
	render("rekey", result)
}

// a rekey that every session missed is recorded as control.verb under each with its reason, and not again without a peer
func TestRekeyEverySessionMissedIsRecordedUnderEachAlone(t *testing.T) {
	c := writable(t)
	c.events = events.New()
	capturedLog(t)
	c.sessions.close = func(*ike.Session) {}
	c.sessions.active = func(*ike.Session) bool { return true }
	c.sessions.rekeyWait = rekeyTestWait
	held := errors.New("ike: a Child SA rekey waits out the retry delay of the one that failed")
	c.sessions.rekey = func(*ike.Session) error { return held }
	for _, path := range []string{"example/bravo:0@0", "example/charlie:0@0"} {
		c.sessions.adoptPreferred(path, &ike.Session{}, true, nil)
	}
	if result := rekeyAll(t, c); len(result.Acted) != 0 || len(result.Missed) != 2 {
		t.Fatalf("the rekey answered %+v, want both sessions missed", result)
	}
	reasons := map[string]string{}
	for _, event := range recorded(c.events, "control.verb") {
		reasons[event.Peer] = event.Attrs["err"]
	}
	if want := map[string]string{"example/bravo:0@0": held.Error(), "example/charlie:0@0": held.Error()}; !maps.Equal(reasons, want) {
		t.Errorf("the rekey was recorded under the peers and with the reasons %q, want %q", reasons, want)
	}
}

// a rekey whose caller went away answers then, listing a rekey still running among those that did not, which goes on
// so the caller's place on the control socket is free again before the wait runs out
func TestRekeyWhoseCallerWentAwayAnswersThen(t *testing.T) {
	c := writable(t)
	capturedLog(t)
	c.sessions.close = func(*ike.Session) {}
	c.sessions.active = func(*ike.Session) bool { return true }
	c.sessions.rekeyWait = rekeyUnendingWait
	started := make(chan struct{})
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	c.sessions.rekey = func(*ike.Session) error {
		close(started)
		<-release
		return nil
	}
	c.sessions.adoptPreferred("example/bravo:0@0", &ike.Session{}, true, nil)
	ctx, hangUp := context.WithCancel(context.Background())
	answered := make(chan control.Result, 1)
	go func() {
		result, _ := c.Rekey(ctx, "", true)
		answered <- result
	}()
	select {
	case <-started:
	case <-time.After(rekeyAnswerBudget):
		t.Fatal("the rekey verb asked no session to rekey")
	}
	hangUp()
	select {
	case result := <-answered:
		want := []control.Missed{{Entry: "example/bravo:0@0", Reason: "still rekeying when the caller went away, and ike.rekey.completed or ike.rekey.failed tells how it ends"}}
		if len(result.Acted) != 0 || !slices.Equal(result.Missed, want) {
			t.Errorf("the rekey answered that %v rekeyed and %+v did not, want %+v", result.Acted, result.Missed, want)
		}
	case <-time.After(rekeyAnswerBudget):
		t.Fatal("the rekey verb still waited once its caller went away")
	}
}

// the rekey verb on a live session answers with what each ask came to
// the first rekeys, the peer's limit on rekeys refuses a second asked at once with TEMPORARY_FAILURE, and a third waits out the retry delay that refusal set, so it starts no exchange and says so
func TestRekeyVerbOnALiveSessionSaysWhatEachAskCameTo(t *testing.T) {
	alpha, bravo := newLoopbackMesh(t)
	// bravo answers and never dials, so alpha holds the one session it dials
	quiet := *bravo.cfg
	quiet.Dial.To = nil
	bravo.client.cfg.Store(&quiet)
	run(t, alpha, bravo)
	waitFor(t, convergeBudget, "the session alpha dials at both ends", func() bool {
		return len(alpha.client.Sessions()) == 1 && len(bravo.client.Sessions()) == 1
	})
	for i, missedFor := range []string{"", fmt.Sprintf("notify type %d", ike.N_TEMPORARY_FAILURE), "retry delay"} {
		result := rekeyAll(t, alpha.client)
		if missedFor == "" {
			if len(result.Acted) != 1 || len(result.Missed) != 0 {
				t.Errorf("ask %d answered %+v, want the session rekeyed", i+1, result)
			}
			continue
		}
		if len(result.Acted) != 0 || len(result.Missed) != 1 || !strings.Contains(result.Missed[0].Reason, missedFor) {
			t.Errorf("ask %d answered %+v, want the session missed for %q", i+1, result, missedFor)
		}
	}
}

// The reload verb re-reads the file the daemon was started with. A node that
// was never told says so, rather than guessing at the default path and
// re-reading a file this process is not running.
func TestReloadUsesThePathTheDaemonWasStartedWith(t *testing.T) {
	c := writable(t)
	if _, err := c.Reload(context.Background()); err == nil {
		t.Error("a node that was never told where its file is reloaded anyway")
	} else if !strings.Contains(err.Error(), "never told") {
		t.Errorf("the refusal reads %q", err)
	}
	c.SetConfigPath("/nonexistent/ranet3.toml")
	if _, err := c.Reload(context.Background()); err == nil {
		t.Error("a reload of a file that does not exist reported success")
	} else if !strings.Contains(err.Error(), "/nonexistent/ranet3.toml") {
		t.Errorf("the failure reads %q, want it to name the file it read", err)
	}
}

// A peer is named by the whole path, by organization and name, or by the name
// alone, and two nodes sharing a name across organizations stay apart.
func TestPeerMatchingTakesEveryShapeOfTheName(t *testing.T) {
	const path = "example/gateway:1@0"
	for name, want := range map[string]bool{
		"gateway":             true,
		"example/gateway":     true,
		"example/gateway:1@0": true,
		"other/gateway":       false,
		"gate":                false,
		"example":             false,
		"":                    false,
	} {
		if got := identity.Names(path, name); got != want {
			t.Errorf("identity.Names(%q, %q) = %v, want %v", path, name, got, want)
		}
	}
}
