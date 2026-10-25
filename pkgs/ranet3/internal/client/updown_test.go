// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/ike"
	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/goldentest"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/registry"
)

// a renamed method would drop the verbs and the view without a word, since the server finds both by assertion
var _ interface {
	control.Sink
	control.UpDownSource
} = (*Client)(nil)

// shortDialRetry brings a peer that lost its session back to dial within a test's wait
const shortDialRetry = 200 * time.Millisecond

// flaggedAt is when a flag a test writes says its node went down
var flaggedAt = time.Date(2026, 10, 12, 21, 4, 5, 0, time.UTC)

// verbGolden holds got to control's golden file name, or writes it there under -update
// the verbs' sentences are this package's, and their golden files sit beside the renders of control's own
func verbGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	goldentest.Check(t, "./internal/client", filepath.Join("..", "..", "control", "testdata", "debug", name), got)
}

// switchRecord is a reconciler or an exit as down and up drive one
// it records each stop and start with whether the flag was there at the moment
type switchRecord struct {
	mu      sync.Mutex
	flag    string
	on      []bool
	flagged []bool
}

func (s *switchRecord) set(on bool) {
	_, err := os.Stat(s.flag)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.on, s.flagged = append(s.on, on), append(s.flagged, err == nil)
}

func (s *switchRecord) calls() (on, flagged []bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.on), slices.Clone(s.flagged)
}

func flagOf(c *Client) string { return filepath.Join(c.stateDir, downFlag) }

// downable is writable with a context, a bus and the state directory dir, so down and up act on it
// it dials nothing and answers nothing, which leaves the speaker, the sessions and the two switches to show what moves
func downable(t *testing.T, dir string) (*Client, *switchRecord, *switchRecord) {
	t.Helper()
	c := writable(t)
	c.cfg.Store(&config.Config{Node: identity.MustParse("example/node")})
	ctx, cancel := context.WithCancel(context.Background())
	c.ctx, c.cancel, c.events = ctx, cancel, events.New()
	t.Cleanup(func() { cancel(); c.peers.Wait() })
	if err := c.SetStateDir(dir); err != nil {
		t.Fatal(err)
	}
	reconciler, translator := &switchRecord{flag: flagOf(c)}, &switchRecord{flag: flagOf(c)}
	c.SetReconcilerEnable(reconciler.set)
	c.SetExit(&fakeExit{enable: translator.set})
	return c, reconciler, translator
}

// heldSessions stands in for the sessions a node holds, each with its Babel neighbor
// closing one counts it and unwinds it as serveSession would, its neighbor going with it
type heldSessions struct {
	mu      sync.Mutex
	flag    string
	release map[*ike.Session]func()
	told    map[*ike.Session]int
	// flagged is whether the flag was there at each close
	flagged []bool
}

func holdSessions(c *Client) *heldSessions {
	h := &heldSessions{flag: flagOf(c), release: map[*ike.Session]func(){}, told: map[*ike.Session]int{}}
	c.sessions.close = func(sess *ike.Session) {
		_, err := os.Stat(h.flag)
		h.mu.Lock()
		h.told[sess]++
		h.flagged = append(h.flagged, err == nil)
		release := h.release[sess]
		h.mu.Unlock()
		if release != nil {
			release()
		}
	}
	return h
}

// adopt puts a session under path into c's set, with its neighbor in c's speaker
func (h *heldSessions) adopt(t testing.TB, c *Client, path string) *ike.Session {
	t.Helper()
	sess := &ike.Session{}
	release, adopted := c.sessions.adoptPreferred(path, sess, true, func() func() {
		return c.speaker.AddPeer(sinkPeer(t, path), identity.Identity{}).Close
	})
	if !adopted {
		t.Fatalf("%s was not adopted", path)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.release[sess] = release
	return sess
}

// down writes its flag before it stops anything, and up takes it away before it starts anything
// the flag holds the moment the status reports, and each session is told once with its Babel neighbor gone
func TestFlagIsWrittenBeforeDownActsAndRemovedBeforeUpActs(t *testing.T) {
	c, reconciler, translator := downable(t, t.TempDir())
	sessions := holdSessions(c)
	gateway := sessions.adopt(t, c, "example/gateway:1@0")
	c.syncSpeaker()

	result, err := c.Down(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(result.Acted, []string{"example/gateway:1@0"}) {
		t.Errorf("down reports %v, want the one session it closed", result.Acted)
	}
	for name, record := range map[string]*switchRecord{"reconciler": reconciler, "translator": translator} {
		if on, flagged := record.calls(); !slices.Equal(on, []bool{false}) || !slices.Equal(flagged, []bool{true}) {
			t.Errorf("down told the %s %v with the flag there %v, want one stop after the flag", name, on, flagged)
		}
	}
	if sessions.told[gateway] != 1 || !slices.Equal(sessions.flagged, []bool{true}) {
		t.Errorf("down told the session %d times with the flag there %v, want once after the flag", sessions.told[gateway], sessions.flagged)
	}
	c.dialersMu.Lock()
	speaking := c.speakerRun
	c.dialersMu.Unlock()
	if speaking != nil || len(c.speaker.Stats().Neighbors) != 0 || len(c.sessions.paths()) != 0 {
		t.Errorf("down left the speaker %v, %d neighbors and %d sessions", speaking, len(c.speaker.Stats().Neighbors), len(c.sessions.paths()))
	}
	body, err := os.ReadFile(flagOf(c))
	if err != nil {
		t.Fatal(err)
	}
	status := c.Status().Down
	if status == nil || strings.TrimSpace(string(body)) != status.Since.Format(time.RFC3339Nano) {
		t.Errorf("the flag holds %q and the status reports %+v", body, status)
	}

	if _, err := c.Up(context.Background()); err != nil {
		t.Fatal(err)
	}
	for name, record := range map[string]*switchRecord{"reconciler": reconciler, "translator": translator} {
		if on, flagged := record.calls(); !slices.Equal(on, []bool{false, true}) || !slices.Equal(flagged, []bool{true, false}) {
			t.Errorf("up told the %s %v with the flag there %v, want a start once the flag was gone", name, on, flagged)
		}
	}
	c.dialersMu.Lock()
	speaking = c.speakerRun
	c.dialersMu.Unlock()
	if speaking == nil || c.Status().Down != nil {
		t.Errorf("up left the speaker %v and the status %+v", speaking, c.Status().Down)
	}
	if _, err := os.Stat(flagOf(c)); err == nil {
		t.Error("up left the flag in place, so a restart would take the node down again")
	}
	// a session landing once the node is back is held, as the sweep's shut set would have refused it
	sessions.adopt(t, c, "example/gateway:1@0")
}

// a down while down and an up while up succeed and say so, moving nothing
func TestRepeatedDownAndUpSayNothingMoved(t *testing.T) {
	c, reconciler, _ := downable(t, t.TempDir())
	if _, err := c.Down(context.Background()); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(flagOf(c))
	if err != nil {
		t.Fatal(err)
	}
	again, err := c.Down(context.Background())
	if err != nil || !strings.Contains(again.Detail, "already down, since "+stamp(c.Status().Down.Since)) {
		t.Errorf("a second down answered %+v (err %v)", again, err)
	}
	if second, err := os.ReadFile(flagOf(c)); err != nil || !bytes.Equal(first, second) {
		t.Errorf("a second down rewrote the flag from %q to %q (err %v)", first, second, err)
	}
	if _, err := c.Up(context.Background()); err != nil {
		t.Fatal(err)
	}
	again, err = c.Up(context.Background())
	if err != nil || !strings.Contains(again.Detail, "already up") {
		t.Errorf("a second up answered %+v (err %v)", again, err)
	}
	if on, _ := reconciler.calls(); !slices.Equal(on, []bool{false, true}) {
		t.Errorf("the repeats told the reconciler %v, want one stop and one start", on)
	}
}

// redial, rekey, enable and the probe need the mesh, and while the node is off it each says why
// a disable is still taken, and up leaves the subsystem it stopped stopped
func TestVerbsNeedingTheMeshAreRefusedWhileDown(t *testing.T) {
	c, reconciler, _ := downable(t, t.TempDir())
	if _, err := c.Down(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for name, ask := range map[string]func() (control.Result, error){
		"redial a peer": func() (control.Result, error) { return c.Redial(ctx, "gateway", false) },
		"redial all":    func() (control.Result, error) { return c.Redial(ctx, "", true) },
		"rekey all":     func() (control.Result, error) { return c.Rekey(ctx, "", true) },
		"probe all":     func() (control.Result, error) { return c.DebugProbe(ctx, "", true) },
		"enable":        func() (control.Result, error) { return c.SetSubsystem(ctx, control.SubsystemSteering, true) },
	} {
		if _, err := ask(); err == nil || !strings.Contains(err.Error(), "this node is down since") {
			t.Errorf("%s while down answered %v, want a refusal saying the node is down", name, err)
		}
	}
	if _, err := c.SetSubsystem(context.Background(), control.SubsystemReconciler, false); err != nil {
		t.Fatalf("a disable while down was refused: %v", err)
	}
	if _, err := c.Up(context.Background()); err != nil {
		t.Fatal(err)
	}
	if on, _ := reconciler.calls(); slices.Contains(on, true) {
		t.Errorf("up started a reconciler somebody had stopped, telling it %v", on)
	}
	if got := c.Status().Disabled; !slices.Contains(got, control.SubsystemReconciler) {
		t.Errorf("after up the status reports %v stopped, want the reconciler", got)
	}
}

// a node whose flag is there starts down, since the flag says, and hands each switch its stop as it is handed over
// its start records the flag as the cause
func TestNodeStartingFromItsFlagStopsWhatItIsHanded(t *testing.T) {
	dir := t.TempDir()
	if err := writeDownFlag(dir, flaggedAt); err != nil {
		t.Fatal(err)
	}
	c, reconciler, translator := downable(t, dir)
	for name, record := range map[string]*switchRecord{"reconciler": reconciler, "translator": translator} {
		if on, _ := record.calls(); !slices.Equal(on, []bool{false}) {
			t.Errorf("the %s handed over on a node starting down was told %v, want a stop", name, on)
		}
	}
	if status := c.Status().Down; status == nil || !status.Since.Equal(flaggedAt) {
		t.Errorf("the status of a node starting from its flag reports %+v, want down since %s", status, flaggedAt)
	}
	got := recorded(c.events, "node.down")
	if len(got) != 1 || got[0].Attrs["cause"] != control.CauseFlag || got[0].Attrs["since"] != flaggedAt.Format(time.RFC3339Nano) {
		t.Errorf("the start recorded %+v, want one down caused by the flag", got)
	}
	if last := c.DebugUpDown().Last; last == nil || !last.Down || last.Cause != control.CauseFlag {
		t.Errorf("the debug view reports the last move as %+v", last)
	}
}

// a node built from its flag and put back up before Run, as the socket serving before Run can, records the flag's down and then the up
func TestUpBeforeRunIsRecordedAfterTheDownTheFlagMade(t *testing.T) {
	dir := t.TempDir()
	if err := writeDownFlag(dir, flaggedAt); err != nil {
		t.Fatal(err)
	}
	c, _, _ := downable(t, dir)
	if _, err := c.Up(context.Background()); err != nil {
		t.Fatal(err)
	}
	var got [][]string
	for _, event := range c.events.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "node.down" || kind == "node.up" }, 0) {
		got = append(got, []string{event.Kind, event.Attrs["cause"]})
	}
	if want := [][]string{{"node.down", control.CauseFlag}, {"node.up", control.CauseRequest}}; !slices.EqualFunc(got, want, slices.Equal) {
		t.Errorf("the node recorded the moves %q, want %q", got, want)
	}
}

// a flag holding no time is still a request to stay down, dated by its last write
func TestFlagHoldingNoTimeKeepsTheNodeDownSinceItsLastWrite(t *testing.T) {
	dir := t.TempDir()
	flagged := filepath.Join(dir, downFlag)
	if err := os.WriteFile(flagged, []byte("maintenance\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(flagged, flaggedAt, flaggedAt); err != nil {
		t.Fatal(err)
	}
	c, _, _ := downable(t, dir)
	if status := c.Status().Down; status == nil || !status.Since.Equal(flaggedAt) {
		t.Errorf("a flag holding no time reads as %+v, want down since its last write at %s", status, flaggedAt)
	}
}

// a missing state directory is made at its mode, and a path the flag cannot live under refuses the start
func TestStateDirectoryIsMadeAtItsModeAndAFileInItsPlaceRefusesTheStart(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "var", "lib", "ranet3")
	downable(t, dir)
	if info, err := os.Stat(dir); err != nil || !info.IsDir() || info.Mode().Perm() != stateDirMode {
		t.Errorf("the state directory was made as %v (err %v), want a directory at %o", info, err, stateDirMode)
	}
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	flagDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(flagDir, downFlag), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{"a file": file, "a flag that is a directory": flagDir} {
		if err := (&Client{}).SetStateDir(path); err == nil {
			t.Errorf("a state directory at %s was taken", name)
		}
	}
}

// a down that cannot write its flag refuses, and the node stays on the mesh with nothing stopped
// a directory where the flag goes refuses the rename onto it for root as for anyone, after the flag is written beside it
func TestDownThatCannotWriteItsFlagChangesNothing(t *testing.T) {
	c, reconciler, _ := downable(t, t.TempDir())
	if err := os.Mkdir(flagOf(c), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Down(context.Background()); err == nil || !strings.Contains(err.Error(), "stays on the mesh") {
		t.Fatalf("a down that could not write its flag answered %v", err)
	}
	if on, _ := reconciler.calls(); c.Status().Down != nil || len(on) != 0 {
		t.Errorf("a refused down left the status %+v and told the reconciler %v", c.Status().Down, on)
	}
	if entries, err := os.ReadDir(c.stateDir); err != nil || len(entries) != 2 || entries[0].Name() != babelStateFile || entries[1].Name() != downFlag || !entries[1].IsDir() {
		t.Errorf("a refused down left %v in the state directory (err %v), want the Babel state and the directory in the flag's place alone", entries, err)
	}
}

// a node nobody gave a state directory refuses both verbs rather than take a down that would not outlive it
func TestClientWithoutAStateDirectoryRefusesDownAndUp(t *testing.T) {
	c := writable(t)
	c.events = events.New()
	for name, verb := range map[string]func(context.Context) (control.Result, error){"down": c.Down, "up": c.Up} {
		if _, err := verb(context.Background()); err == nil || !strings.Contains(err.Error(), "no state directory") {
			t.Errorf("%s without a state directory answered %v", name, err)
		}
	}
}

// each verb's answer, and the second asking of each, renders as its golden file
func TestDownAndUpRenderAsTheGoldenFiles(t *testing.T) {
	c, _, _ := downable(t, t.TempDir())
	sessions := holdSessions(c)
	sessions.adopt(t, c, "example/bravo:0@0")
	sessions.adopt(t, c, "example/charlie:0@0")
	render := func(name string, verb func(context.Context) (control.Result, error)) {
		t.Helper()
		result, err := verb(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		control.RenderResult(&out, result)
		verbGolden(t, name, out.Bytes())
	}
	render("down.txt", c.Down)
	render("up.txt", c.Up)
	render("up-again.txt", c.Up)

	// the moment a second down names is the flag's, here one written before the start
	dir := t.TempDir()
	if err := writeDownFlag(dir, flaggedAt); err != nil {
		t.Fatal(err)
	}
	restarted, _, _ := downable(t, dir)
	render("down-again.txt", restarted.Down)
}

// restartNode builds node's client again from its file, its key and its trust document, as a restart reads them
// the port is the one it held, which the kernel can hand out between the two, so a bind is tried again for a while
func restartNode(t *testing.T, node *loopbackNode) *Client {
	t.Helper()
	cfg, err := config.Load(node.configPath)
	if err != nil {
		t.Fatal(err)
	}
	key, err := registry.LoadPrivateKey(cfg.Auth.Key)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := registry.Load(cfg.Auth.Trust)
	if err != nil {
		t.Fatal(err)
	}
	var restarted *Client
	retryPort(t, "bind again", func() (err error) {
		node.events = events.New()
		restarted, err = newClient(cfg, key, reg, netstack.NewRoutesOnly(), nil, node.events)
		return err
	})
	node.client = restarted
	t.Cleanup(restarted.Close)
	return restarted
}

// offTheMesh says what of the mesh c still runs, empty where it runs nothing
func offTheMesh(c *Client) string {
	c.dialersMu.Lock()
	dialers, responder, speaking := len(c.dialers), c.responder != nil, c.speakerRun != nil
	c.dialersMu.Unlock()
	sessions, neighbors := len(c.sessions.paths()), len(c.speaker.Stats().Neighbors)
	if dialers == 0 && !responder && !speaking && sessions == 0 && neighbors == 0 {
		return ""
	}
	return fmt.Sprintf("%d dialers, responder %v, speaker %v, %d sessions and %d neighbors", dialers, responder, speaking, sessions, neighbors)
}

// down tells the peer its session is gone, once, and leaves nothing of the mesh running or answering
// the peer stops reaching the node's prefix, and its dials meet a hub that answers nothing
// up brings the session and the routes back
func TestDownTellsThePeerOnceAndUpPutsTheNodeBack(t *testing.T) {
	alpha, bravo := newLoopbackMesh(t)
	if err := alpha.client.SetStateDir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	told := map[*ike.Session]int{}
	closeSession := alpha.client.sessions.close
	alpha.client.sessions.close = func(sess *ike.Session) {
		mu.Lock()
		told[sess]++
		mu.Unlock()
		closeSession(sess)
	}
	bravo.client.dialRetry = shortDialRetry
	run(t, alpha, bravo)
	waitFor(t, convergeBudget, "each node forwarding to the other's prefix", func() bool {
		return reaches(alpha, bravo) && reaches(bravo, alpha)
	})

	result, err := alpha.client.Down(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Acted) != 1 {
		t.Errorf("down reports %v, want the one session alpha held", result.Acted)
	}
	if what := offTheMesh(alpha.client); what != "" {
		t.Errorf("down returned with %s", what)
	}
	waitFor(t, convergeBudget, "bravo to be told its session is gone", func() bool { return len(bravo.client.sessions.paths()) == 0 })
	waitFor(t, convergeBudget, "bravo to stop reaching alpha's prefix", func() bool { return !reaches(bravo, alpha) })
	refused := alpha.client.hub.Refused()
	waitFor(t, convergeBudget, "alpha's hub to refuse bravo's dials", func() bool { return alpha.client.hub.Refused() > refused })
	if what := offTheMesh(alpha.client); what != "" {
		t.Errorf("bravo's dials found alpha with %s", what)
	}
	mu.Lock()
	for _, count := range told {
		if count != 1 {
			t.Errorf("a session alpha held was told %d times", count)
		}
	}
	mu.Unlock()
	if got := recorded(alpha.events, "node.down"); len(got) != 1 || got[0].Attrs["cause"] != control.CauseRequest || got[0].Attrs["closed"] != "1" {
		t.Errorf("down recorded %+v, want one move by a request closing one session", got)
	}

	if _, err := alpha.client.Up(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, convergeBudget, "each node forwarding to the other's prefix again", func() bool {
		return reaches(alpha, bravo) && reaches(bravo, alpha)
	})
	if got := recorded(alpha.events, "node.up"); len(got) != 1 || got[0].Attrs["cause"] != control.CauseRequest {
		t.Errorf("up recorded %+v, want one move by a request", got)
	}
}

// a down sweeps the sessions as the shutdown does, before it stops the dialers, and a dialer whose session the sweep ends reads it as the node leaving
// see Client.stopping
func TestDownSaysNothingAboutReconnecting(t *testing.T) {
	alpha, bravo := newLoopbackMesh(t)
	if err := alpha.client.SetStateDir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	// held open as TestShutdownSaysNothingAboutReconnecting holds it, so the dialer reaches its own check while the sweep still runs
	closeSession := alpha.client.sessions.close
	alpha.client.sessions.close = func(sess *ike.Session) {
		closeSession(sess)
		time.Sleep(200 * time.Millisecond)
	}
	run(t, alpha, bravo)
	waitFor(t, convergeBudget, "both ends established", func() bool {
		return len(alpha.client.sessions.paths()) == 1 && len(bravo.client.sessions.paths()) == 1
	})

	written := capturedLog(t)
	if _, err := alpha.client.Down(context.Background()); err != nil {
		t.Fatal(err)
	}
	// bravo loses its peer and says it will retry, as it should, so only the lines naming the peer of alpha count
	dialingBravo := "peer " + bravo.cfg.Node.String()
	for _, line := range written.lines("reconnecting in") {
		if strings.Contains(line, dialingBravo) {
			t.Errorf("the down wrote %q", line)
		}
	}
}

// a node restarted while down comes up down, since the moment it first went, and answers nothing
// up then puts it back on the mesh
func TestRestartWhileDownComesUpDownWithTheSameSince(t *testing.T) {
	alpha, bravo := newLoopbackMesh(t)
	dir := t.TempDir()
	if err := alpha.client.SetStateDir(dir); err != nil {
		t.Fatal(err)
	}
	bravo.client.dialRetry = shortDialRetry
	run(t, bravo)
	_, stopAlpha := run(t, alpha)
	waitFor(t, convergeBudget, "both ends established", func() bool {
		return len(alpha.client.sessions.paths()) == 1 && len(bravo.client.sessions.paths()) == 1
	})
	if _, err := alpha.client.Down(context.Background()); err != nil {
		t.Fatal(err)
	}
	since := alpha.client.Status().Down.Since
	stopAlpha()

	restarted := restartNode(t, alpha)
	if err := restarted.SetStateDir(dir); err != nil {
		t.Fatal(err)
	}
	run(t, alpha)
	if status := restarted.Status().Down; status == nil || !status.Since.Equal(since) {
		t.Fatalf("the restart reports %+v, want down since %s", status, since)
	}
	got := recorded(alpha.events, "node.down")
	if len(got) != 1 || got[0].Attrs["cause"] != control.CauseFlag || got[0].Attrs["since"] != since.Format(time.RFC3339Nano) {
		t.Errorf("the restart recorded %+v, want one down caused by the flag", got)
	}
	refused := restarted.hub.Refused()
	waitFor(t, convergeBudget, "the restarted hub to refuse bravo's dials", func() bool { return restarted.hub.Refused() > refused })
	if what := offTheMesh(restarted); what != "" {
		t.Errorf("the node restarted down runs %s", what)
	}

	if _, err := restarted.Up(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, convergeBudget, "both ends established again", func() bool {
		return len(restarted.sessions.paths()) == 1 && len(bravo.client.sessions.paths()) == 1
	})
}

// a reload while down takes the file and stays down, and the peer it adds is dialed once up puts the node back
func TestReloadWhileDownDialsANewPeerOnlyAfterUp(t *testing.T) {
	a, b, c := &listenNode{name: "a", listen: true}, &listenNode{name: "b", listen: true}, &listenNode{name: "c", listen: true}
	a.dials = []*listenNode{b}
	listenMesh(t, a, b, c)
	if err := a.client.SetStateDir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	runListen(t, a, b, c)
	waitFor(t, convergeBudget, "a's session with b", func() bool { return held(a, b) != nil })
	if _, err := a.client.Down(context.Background()); err != nil {
		t.Fatal(err)
	}

	a.dials = append(a.dials, c)
	writeListenConfig(t, a, true)
	if err := a.client.ReloadFrom(a.configPath); err != nil {
		t.Fatalf("a reload while down was refused: %v", err)
	}
	if a.client.Status().Down == nil || hasDialer(a.client, pathTo(c)) || dialerCount(a.client) != 0 {
		t.Errorf("the reload moved the node off down or dialed: down %+v, %d dialers", a.client.Status().Down, dialerCount(a.client))
	}

	if _, err := a.client.Up(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, convergeBudget, "a's session with the peer the reload added", func() bool { return held(a, c) != nil })
}
