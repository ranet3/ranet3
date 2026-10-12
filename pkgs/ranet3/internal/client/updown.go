// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"ranet3.com/pkgs/ranet3/control"
)

// This file is down and up, the verbs that take the node off the mesh and put it back.
// down is the one verb whose state outlives the process, as a flag in the state directory holding when the node went down
// down writes the flag before it acts and up removes it before it acts
// a crash between the two halves leaves the flag saying what was last asked, and the next start acts on that
// the sweep is the shutdown's own leave, so taking a node down and stopping it cannot tear it down two ways

var errNoStateDir = errors.New("control: this daemon keeps no state directory, so a down could not outlive it")

// SetStateDir names the directory the down flag lives in and reads the flag, making the directory where it is missing
// a node whose flag is there comes up down, its tun, socket and metrics open and nothing else of the mesh started
// it runs before Run and before the socket serves a verb
// the move it records for a flag therefore comes before any verb's
func (c *Client) SetStateDir(dir string) error {
	if err := os.MkdirAll(dir, stateDirMode); err != nil {
		return fmt.Errorf("state: %w", err)
	}
	since, down, err := readDownFlag(dir)
	if err != nil {
		return fmt.Errorf("state: %w", err)
	}
	c.stateDir = dir
	if down {
		c.downSince.Store(&since)
		c.noteMove(true, control.CauseFlag, since, 0)
		log.Printf("this node is down since %s, as %s says, and ranet3 up puts it back on the mesh", stamp(since), filepath.Join(dir, downFlag))
	}
	return nil
}

// SetEgressEnable hands down and up the egress translator's own stop and start, as SetReconcilerEnable hands the reconciler's
// a node that starts down hands the translator its stop here, before its first pass
func (c *Client) SetEgressEnable(set func(bool)) {
	c.runningMu.Lock()
	defer c.runningMu.Unlock()
	c.egressEnable.Store(&set)
	if c.downSince.Load() != nil {
		set(false)
	}
}

// Down takes the node off the mesh until Up puts it back, through every restart and reboot between
func (c *Client) Down(ctx context.Context) (result control.Result, err error) {
	defer func() { c.noteVerb(ctx, "down", "", result.Acted, err) }()
	if c.stateDir == "" {
		return control.Result{}, errNoStateDir
	}
	c.reloadMu.Lock()
	defer c.reloadMu.Unlock()
	if since := c.downSince.Load(); since != nil {
		return control.Result{Detail: "This node was already down, since " + stamp(*since)}, nil
	}
	since := time.Now().UTC()
	if err := writeDownFlag(c.stateDir, since); err != nil {
		return control.Result{}, fmt.Errorf("control: the down flag could not be written, so this node stays on the mesh: %w", err)
	}
	c.syncStateDir()
	c.downSince.Store(&since)
	c.runningMu.Lock()
	c.applyInstalledLocked()
	c.runningMu.Unlock()
	closed := c.leave()
	c.noteMove(true, control.CauseRequest, since, len(closed))
	log.Printf("control: this node is down, %d session(s) closed", len(closed))
	return control.Result{Acted: closed,
		Detail: fmt.Sprintf("This node is off the mesh with %d session(s) closed, and it stays off through a restart until ranet3 up", len(closed))}, nil
}

// Up removes the flag and puts the node back on the mesh as a start would, a subsystem somebody disabled staying disabled
func (c *Client) Up(ctx context.Context) (result control.Result, err error) {
	defer func() { c.noteVerb(ctx, "up", "", nil, err) }()
	if c.stateDir == "" {
		return control.Result{}, errNoStateDir
	}
	c.reloadMu.Lock()
	defer c.reloadMu.Unlock()
	if c.downSince.Load() == nil {
		return control.Result{Detail: "This node was already up"}, nil
	}
	if err := os.Remove(filepath.Join(c.stateDir, downFlag)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return control.Result{}, fmt.Errorf("control: the down flag could not be removed, so this node stays down: %w", err)
	}
	c.syncStateDir()
	// nothing runs to adopt a session until the loops below start
	c.sessions.open()
	c.downSince.Store(nil)
	c.runningMu.Lock()
	c.applyInstalledLocked()
	c.runningMu.Unlock()
	c.syncMesh()
	c.noteMove(false, control.CauseRequest, time.Time{}, 0)
	log.Printf("control: this node is back on the mesh")
	return control.Result{Detail: "This node is back on the mesh"}, nil
}

// applyInstalledLocked hands the reconciler and the translator what the node's place on the mesh asks of them
// a down node holds nothing in the host, and an up one what its file and the stopped set say
// c.runningMu is held
func (c *Client) applyInstalledLocked() {
	up := c.downSince.Load() == nil
	if set := c.reconcilerEnable.Load(); set != nil {
		(*set)(up && c.running[control.SubsystemReconciler])
	}
	if set := c.egressEnable.Load(); set != nil {
		(*set)(up)
	}
}

// refuseWhileDown is the answer a verb that needs the mesh gets while the node is off it, and nil while it is on it
func (c *Client) refuseWhileDown(verb string) error {
	since := c.downSince.Load()
	if since == nil {
		return nil
	}
	return fmt.Errorf("control: this node is down since %s, so it cannot %s until ranet3 up puts it back on the mesh", stamp(*since), verb)
}

// noteMove records a move between up and down, for the debug view and as an event
// since is when the node went down, and closed how many sessions a down by request closed
func (c *Client) noteMove(down bool, cause string, since time.Time, closed int) {
	c.lastMove.Store(&control.UpDownChange{Down: down, Cause: cause, At: time.Now()})
	if !down {
		c.events.Emit("node.up", "", slog.String("cause", cause))
		return
	}
	attrs := []slog.Attr{slog.String("cause", cause), slog.String("since", since.Format(time.RFC3339Nano))}
	if cause == control.CauseRequest {
		attrs = append(attrs, slog.Int("closed", closed))
	}
	c.events.Emit("node.down", "", attrs...)
}

// syncStateDir makes the flag's last write or removal survive a crash, warning where the directory will not sync
// every later read already finds the flag as the verb left it, so the verb stands either way
func (c *Client) syncStateDir() {
	dir, err := os.Open(c.stateDir)
	if err == nil {
		err = errors.Join(dir.Sync(), dir.Close())
	}
	if err != nil {
		slog.Warn("the state directory did not sync, so a crash before its next write may undo the last down or up", "dir", c.stateDir, "err", err)
	}
}

// writeDownFlag puts the flag in dir holding since, whole or not at all
// it is written and synced beside the flag and renamed over it, so a crash leaves the flag as it was or as asked
func writeDownFlag(dir string, since time.Time) error {
	path := filepath.Join(dir, downFlag)
	temp := path + flagTemp
	file, err := os.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, flagMode)
	if err != nil {
		return err
	}
	_, err = file.WriteString(since.Format(time.RFC3339Nano) + "\n")
	if err == nil {
		err = file.Sync()
	}
	if err = errors.Join(err, file.Close()); err == nil {
		err = os.Rename(temp, path)
	}
	if err != nil {
		_ = os.Remove(temp)
	}
	return err
}

// readDownFlag reports whether the flag is in dir and when the node went down
// a flag holding no time still keeps the node down, since the file alone is the request, dated by its last write
func readDownFlag(dir string) (time.Time, bool, error) {
	path := filepath.Join(dir, downFlag)
	body, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, err
	}
	if since, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(string(body))); err == nil {
		return since.UTC(), true, nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return time.Time{}, false, err
	}
	slog.Warn("the down flag holds no time, so the node is down since the flag was last written", "path", path)
	return info.ModTime().UTC(), true, nil
}

// stamp writes a moment as the status and the debug views write one
func stamp(at time.Time) string { return at.UTC().Format(time.DateTime) + " UTC" }

// downStatus is the status's account of a node off the mesh, nil while it is on it
func (c *Client) downStatus() *control.Down {
	since := c.downSince.Load()
	if since == nil {
		return nil
	}
	return &control.Down{Since: *since, For: control.Duration(time.Since(*since))}
}
