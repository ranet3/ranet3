// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"time"

	"ranet3.com/pkgs/ranet3/control"
)

// DebugUpDown reads whether the node is on the mesh, its flag as the directory holds it now, and the last move between the two
// with the Babel router id and seqno, and the limit their file holds now
func (c *Client) DebugUpDown() control.UpDownInfo {
	info := control.UpDownInfo{Down: c.downStatus(), Babel: c.babelOrigin()}
	if c.stateDir != "" {
		info.Flag = filepath.Join(c.stateDir, downFlag)
		_, err := os.Stat(info.Flag)
		info.Flagged = err == nil
	}
	if last := c.lastMove.Load(); last != nil {
		move := *last
		move.At, move.Ago = last.At.UTC(), control.Duration(time.Since(last.At))
		info.Last = &move
	}
	return info
}

// babelOrigin is the router id and seqno of the node's own routes, with the limit the state file holds for them
// a file that is missing, cannot be read, or holds another node or router id holds no limit for them, and a restart would not keep the router id
func (c *Client) babelOrigin() control.BabelOrigin {
	origin, seqno := c.speaker.Origin()
	view := control.BabelOrigin{RouterID: hex.EncodeToString(origin.RouterID[:]), Seqno: seqno}
	if c.stateDir == "" {
		return view
	}
	view.File = filepath.Join(c.stateDir, babelStateFile)
	if state, found, err := readBabelState(c.stateDir); err == nil && found && state.node == c.config().Node && state.origin.RouterID == origin.RouterID {
		view.Limit = &state.origin.Limit
	}
	return view
}
