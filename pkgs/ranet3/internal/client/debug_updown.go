// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"os"
	"path/filepath"
	"time"

	"ranet3.com/pkgs/ranet3/control"
)

// DebugUpDown reads whether the node is on the mesh, its flag as the directory holds it now, and the last move between the two
func (c *Client) DebugUpDown() control.UpDownInfo {
	info := control.UpDownInfo{Down: c.downStatus()}
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
