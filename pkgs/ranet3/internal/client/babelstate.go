// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"

	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/internal/babel"
)

// This file is the Babel state kept beside the down flag, which spares the mesh a new speaker at every restart.
// it holds the node it belongs to, the router id and a seqno limit that no seqno the node has sent passes
// the speaker saves each new limit through it before it uses a seqno past the last one saved
// a file that is missing, names another node or cannot be read or parsed costs the router id and nothing else
// the node then starts as one that never had a file, under a new router id from seqno 1, and its first save replaces the file

// babelState holds the file's contents
type babelState struct {
	node   identity.Identity
	origin babel.Origin
}

// babelStateBody is the file's JSON, every field required
type babelStateBody struct {
	Node     *babelStateNode `json:"node"`
	RouterID string          `json:"router_id"`
	Limit    *uint16         `json:"seqno_limit"`
}

// babelStateNode is node as the file holds it, the raw organization and name, which every release reads
type babelStateNode struct {
	Org  string `json:"org"`
	Name string `json:"name"`
}

// startBabel hands the speaker the router id and seqno limit the file in dir holds, and the save of each new limit
// a file that is missing, names another node or cannot be read or parsed leaves the router id New drew, as the start's event says
func (c *Client) startBabel(dir string) {
	path, node := filepath.Join(dir, babelStateFile), c.config().Node
	save := func(origin babel.Origin) error { return writeBabelState(dir, babelState{node: node, origin: origin}) }
	state, found, err := readBabelState(dir)
	switch {
	case err != nil:
		slog.Warn("babel state file unreadable, so this node starts under a new router id and its first save replaces the file", "path", path, "err", err)
		c.events.Emit("babel.state.unreadable", "", slog.String("file", path), slog.String("err", err.Error()))
		c.speaker.SetOrigin(babel.Origin{}, save, "the state file is unreadable")
	case !found:
		c.speaker.SetOrigin(babel.Origin{}, save, "no state file")
	case state.node != node:
		names := state.node.String()
		slog.Warn("babel state file names another node, so this node starts under a new router id", "path", path, "names", names)
		c.speaker.SetOrigin(babel.Origin{}, save, "the state file names "+names)
	default:
		c.speaker.SetOrigin(state.origin, save, "")
	}
}

// readBabelState reads the file in dir, reporting false where there is none
func readBabelState(dir string) (babelState, bool, error) {
	body, err := os.ReadFile(filepath.Join(dir, babelStateFile))
	if errors.Is(err, fs.ErrNotExist) {
		return babelState{}, false, nil
	}
	if err != nil {
		return babelState{}, false, err
	}
	state, err := parseBabelState(body)
	if err != nil {
		return babelState{}, false, err
	}
	return state, true, nil
}

// parseBabelState takes the file's body, refusing what writeBabelState would not have written
func parseBabelState(body []byte) (babelState, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var file babelStateBody
	if err := decoder.Decode(&file); err != nil {
		return babelState{}, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return babelState{}, errors.New("more follows the JSON object")
	}
	if file.Node == nil || file.Limit == nil {
		return babelState{}, errors.New("node or seqno_limit is missing")
	}
	node, err := identity.From(file.Node.Org, file.Node.Name, "")
	if err != nil {
		return babelState{}, err
	}
	raw, err := hex.DecodeString(file.RouterID)
	if err != nil || len(raw) != 8 {
		return babelState{}, fmt.Errorf("router_id %q is not 16 hex digits", file.RouterID)
	}
	id := [8]byte(raw)
	if !babel.ValidRouterID(id) {
		return babelState{}, fmt.Errorf("router_id %s is all zeros or all ones", file.RouterID)
	}
	return babelState{node: node, origin: babel.Origin{RouterID: id, Limit: *file.Limit}}, nil
}

// writeBabelState puts state in dir whole and syncs the directory, and once it returns a crash finds the limit it holds
// a directory that will not sync fails the save, since the limit could still be lost
func writeBabelState(dir string, state babelState) error {
	organization, name := state.node.NodeParts()
	body, err := json.Marshal(babelStateBody{Node: &babelStateNode{organization, name}, RouterID: hex.EncodeToString(state.origin.RouterID[:]), Limit: &state.origin.Limit})
	if err != nil {
		return err
	}
	if err := replaceFile(dir, babelStateFile, append(body, '\n')); err != nil {
		return err
	}
	return syncDir(dir)
}
