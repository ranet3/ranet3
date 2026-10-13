// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/babel"
	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/events"
)

// stateNode is writable with a context, its speaker recording on a bus of its own, as the node example/name started on dir
// it dials nothing and answers nothing, which leaves the speaker to show what a start, a down and an up do to the Babel state
func stateNode(t *testing.T, name, dir string) (*Client, *events.Bus) {
	t.Helper()
	bus := events.New()
	c := writable(t)
	speaker, err := babel.New(babel.Config{}, babel.Routes{}, babel.Runtime{Events: bus}, c.Mesh)
	if err != nil {
		t.Fatal(err)
	}
	c.speaker, c.events = speaker, bus
	c.cfg.Store(&config.Config{Node: config.Node{Org: "example", Name: name}})
	ctx, cancel := context.WithCancel(context.Background())
	c.ctx, c.cancel = ctx, cancel
	t.Cleanup(func() { cancel(); c.peers.Wait() })
	if err := c.SetStateDir(dir); err != nil {
		t.Fatal(err)
	}
	return c, bus
}

// startRaise reads the attributes the raise of a node's start recorded
func startRaise(t *testing.T, bus *events.Bus) map[string]string {
	t.Helper()
	for _, event := range recorded(bus, "babel.seqno.raised") {
		if event.Attrs["cause"] == "start" {
			return event.Attrs
		}
	}
	t.Fatal("the start recorded no raise")
	return nil
}

// a node starting without a state file draws a router id, says why, starts at seqno 1 and saves both
// a restart keeps that router id and starts past the seqno limit the file holds
// a down and an up keep it as well and raise the seqno past the one in use before the down
// another state directory without a file draws another router id
func TestRouterIDOutlivesARestartAndADownAndUp(t *testing.T) {
	dir := t.TempDir()
	first, bus := stateNode(t, "alpha", dir)
	drawn, seqno := first.speaker.Origin()
	if got := startRaise(t, bus); got["drawn"] != "no state file" || got["router_id"] != hex.EncodeToString(drawn.RouterID[:]) || seqno != 1 {
		t.Errorf("the first start recorded %v at seqno %d, want router id %x drawn for want of a state file at seqno 1", got, seqno, drawn.RouterID)
	}

	restarted, bus := stateNode(t, "alpha", dir)
	kept, seqno := restarted.speaker.Origin()
	if kept.RouterID != drawn.RouterID || seqno != drawn.Limit+1 {
		t.Errorf("the restart advertises %x at seqno %d, want %x past the limit %d", kept.RouterID, seqno, drawn.RouterID, drawn.Limit)
	}
	if got := startRaise(t, bus); got["drawn"] != "" {
		t.Errorf("the restart recorded %v, want a router id it kept", got)
	}

	restarted.syncSpeaker()
	if _, err := restarted.Down(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Up(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, convergeBudget, "the run after the up to raise the seqno", func() bool {
		_, now := restarted.speaker.Origin()
		return now == seqno+1
	})
	if again, _ := restarted.speaker.Origin(); again.RouterID != drawn.RouterID {
		t.Errorf("the up advertises %x, want %x", again.RouterID, drawn.RouterID)
	}

	other, _ := stateNode(t, "alpha", t.TempDir())
	if elsewhere, _ := other.speaker.Origin(); elsewhere.RouterID == drawn.RouterID {
		t.Errorf("a node started on another empty state directory advertises %x as well", elsewhere.RouterID)
	}
}

// a state directory copied to another node, as a cloned image or a restored backup brings it, gives that node a router id of its own
// its start says the file named the node it came from, and its first save makes the file its own
func TestCopiedStateDirectoryGivesEachNodeItsOwnRouterID(t *testing.T) {
	alphaDir, bravoDir := t.TempDir(), t.TempDir()
	alpha, _ := stateNode(t, "alpha", alphaDir)
	body, err := os.ReadFile(filepath.Join(alphaDir, babelStateFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bravoDir, babelStateFile), body, 0o600); err != nil {
		t.Fatal(err)
	}
	bravo, bus := stateNode(t, "bravo", bravoDir)
	alphaOrigin, _ := alpha.speaker.Origin()
	bravoOrigin, seqno := bravo.speaker.Origin()
	if bravoOrigin.RouterID == alphaOrigin.RouterID || seqno != 1 {
		t.Errorf("bravo started from alpha's state directory advertises %x at seqno %d, and alpha %x", bravoOrigin.RouterID, seqno, alphaOrigin.RouterID)
	}
	if got := startRaise(t, bus)["drawn"]; got != "the state file names example/alpha" {
		t.Errorf("bravo's start says the router id was drawn because %q", got)
	}
	state, found, err := readBabelState(bravoDir)
	if err != nil || !found || state.node != (config.Node{Org: "example", Name: "bravo"}) || state.origin != bravoOrigin {
		t.Errorf("bravo's state file holds %+v (found %v, err %v), want bravo's own %+v", state, found, err, bravoOrigin)
	}
}

// the updown view shows the router id and seqno the speaker advertises, with the file and the limit it holds for them
// the limit is the file's as the view reads it, which a file changed since the last save shows
// a file holding another router id or another node's name holds no limit for them, and a node without a state directory names no file
func TestUpDownViewShowsTheLimitTheFileHoldsForThisRouterID(t *testing.T) {
	dir := t.TempDir()
	c, _ := stateNode(t, "alpha", dir)
	origin, seqno := c.speaker.Origin()
	view := c.DebugUpDown().Babel
	if view.RouterID != hex.EncodeToString(origin.RouterID[:]) || view.Seqno != seqno || view.File != filepath.Join(dir, babelStateFile) || view.Limit == nil || *view.Limit != origin.Limit {
		t.Errorf("the view shows %+v, want router id %x at seqno %d with the limit %d in the file", view, origin.RouterID, seqno, origin.Limit)
	}
	changed := babelState{node: config.Node{Org: "example", Name: "alpha"}, origin: babel.Origin{RouterID: origin.RouterID, Limit: origin.Limit + 1000}}
	if err := writeBabelState(dir, changed); err != nil {
		t.Fatal(err)
	}
	if view := c.DebugUpDown().Babel; view.Limit == nil || *view.Limit != changed.origin.Limit {
		t.Errorf("with the file changed to hold the limit %d the view shows %+v", changed.origin.Limit, view)
	}
	for name, state := range map[string]babelState{
		"another router id": {node: config.Node{Org: "example", Name: "alpha"}, origin: babel.Origin{RouterID: [8]byte{0x72, 1, 2, 3, 4, 5, 6, 7}, Limit: origin.Limit}},
		"another node":      {node: config.Node{Org: "example", Name: "bravo"}, origin: origin},
	} {
		if err := writeBabelState(dir, state); err != nil {
			t.Fatal(err)
		}
		if view := c.DebugUpDown().Babel; view.Limit != nil {
			t.Errorf("with a file holding %s the view shows the limit %d", name, *view.Limit)
		}
	}
	if view := writable(t).DebugUpDown().Babel; view.RouterID == "" || view.File != "" || view.Limit != nil {
		t.Errorf("a node without a state directory shows %+v, want its router id alone", view)
	}
}

// a save whose directory will not sync is a save that failed, since a crash could still lose the limit it wrote
// the speaker records it, keeps the limit it had and starts all the same
// a directory the daemon's user can write and not read refuses the sync, which root reads whatever its mode
func TestSaveFailsWhereTheStateDirectoryWillNotSync(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root opens a directory whatever its mode")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o300); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	c, bus := stateNode(t, "alpha", dir)
	origin, seqno := c.speaker.Origin()
	if got := recorded(bus, "babel.state.unsaved"); len(got) != 1 || got[0].Attrs["limit"] != "257" || origin.Limit != 0 || seqno != 1 {
		t.Errorf("a start whose directory would not sync recorded %+v and holds the limit %d at seqno %d, want one failed save of 257 and the limit 0 at seqno 1", got, origin.Limit, seqno)
	}
	if body, err := os.ReadFile(filepath.Join(dir, babelStateFile)); err != nil || len(body) == 0 {
		t.Errorf("the save before the sync left %q (err %v), want the file it wrote", body, err)
	}
}

// a state file that cannot be parsed costs the router id and nothing else, whichever part of it is wrong
// the node starts under a new one at seqno 1, records the file and why, and its first save replaces the file
// a file missing its limit is one of them, since reading it as 0 would start the kept router id at a seqno it has sent
// a directory where the file goes can be neither read nor replaced, and the node starts all the same, recording the save that failed
func TestUnreadableStateFileStartsUnderANewRouterID(t *testing.T) {
	const node, id = `"node":{"org":"example","name":"alpha"}`, `"router_id":"7201020304050607"`
	for name, malformed := range map[string]string{
		"a limit that is no number": `{` + node + `,` + id + `,"seqno_limit":"many"}`,
		"no limit":                  `{` + node + `,` + id + `}`,
		"no node":                   `{` + id + `,"seqno_limit":300}`,
		"a key of no state file":    `{` + node + `,` + id + `,"seqno_limit":300,"seqno":290}`,
		"a second object":           `{` + node + `,` + id + `,"seqno_limit":300}{}`,
		"a short router id":         `{` + node + `,"router_id":"72010203","seqno_limit":300}`,
		"a router id of all zeros":  `{` + node + `,"router_id":"0000000000000000","seqno_limit":300}`,
		"a router id of all ones":   `{` + node + `,"router_id":"ffffffffffffffff","seqno_limit":300}`,
		"half a file":               `{` + node + `,` + id + `,"seqno_li`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, babelStateFile)
			if err := os.WriteFile(path, []byte(malformed+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			c, bus := stateNode(t, "alpha", dir)
			origin, seqno := c.speaker.Origin()
			if hex.EncodeToString(origin.RouterID[:]) == "7201020304050607" || seqno != 1 {
				t.Errorf("a node whose state file is malformed advertises %x at seqno %d, want a new router id at seqno 1", origin.RouterID, seqno)
			}
			if got := recorded(bus, "babel.state.unreadable"); len(got) != 1 || got[0].Attrs["file"] != path || got[0].Attrs["err"] == "" {
				t.Errorf("the start recorded %+v, want the file it could not read and why", got)
			}
			if got := startRaise(t, bus)["drawn"]; got != "the state file is unreadable" {
				t.Errorf("the start says the router id was drawn because %q", got)
			}
			if state, found, err := readBabelState(dir); err != nil || !found || state.origin != origin {
				t.Errorf("after the start the file holds %+v (found %v, err %v), want %+v", state, found, err, origin)
			}
		})
	}

	blocked := t.TempDir()
	if err := os.Mkdir(filepath.Join(blocked, babelStateFile), 0o700); err != nil {
		t.Fatal(err)
	}
	c, bus := stateNode(t, "alpha", blocked)
	if _, seqno := c.speaker.Origin(); seqno != 1 {
		t.Errorf("a node whose state file is a directory starts at seqno %d, want 1", seqno)
	}
	if read, saved := recorded(bus, "babel.state.unreadable"), recorded(bus, "babel.state.unsaved"); len(read) != 1 || len(saved) != 1 {
		t.Errorf("a state file that is a directory recorded %+v and %+v, want one read and one save that failed", read, saved)
	}
}
