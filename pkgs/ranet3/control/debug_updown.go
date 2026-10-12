// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package control

import (
	"io"
	"time"
)

// PathDebugUpDown is whether the node is on the mesh, the flag that keeps it off and its last move between the two
const PathDebugUpDown = PathDebug + "updown"

func init() {
	debugRead(PathDebugUpDown, classRead, "updown", UpDownSource.DebugUpDown)
}

// UpDownSource is a Source that can be taken off the mesh
type UpDownSource interface {
	DebugUpDown() UpDownInfo
}

// UpDownInfo is whether the node is on the mesh, where its flag lives and the last move between up and down
type UpDownInfo struct {
	// Down is present while the node is off the mesh, as the status carries it
	Down *Down `json:"down,omitempty"`
	// Flag is the file whose presence keeps the node down through a restart, absent where the daemon keeps no state directory
	Flag string `json:"flag,omitempty"`
	// Flagged is whether the flag is there, read when the view was asked for
	Flagged bool `json:"flagged"`
	// Last is absent before the first move
	Last *UpDownChange `json:"last,omitempty"`
}

// the causes of a move between up and down
const (
	// CauseRequest is the down or the up verb
	CauseRequest = "request"
	// CauseFlag is the flag a daemon found in its state directory at start
	CauseFlag = "flag"
)

// UpDownChange is one move between up and down
type UpDownChange struct {
	Down  bool      `json:"down"`
	Cause string    `json:"cause"`
	At    time.Time `json:"at"`
	// Ago is how long before the answer it happened
	Ago Duration `json:"ago"`
}

// UpDown reads whether the node is on the mesh and what last moved it
func (c *Client) UpDown() (UpDownInfo, error) { return read[UpDownInfo](c, PathDebugUpDown) }

// RenderUpDown writes the state, the flag and the last move
func RenderUpDown(w io.Writer, info UpDownInfo) {
	state := "up"
	if info.Down != nil {
		state = "down " + downLine(*info.Down)
	}
	changed := "not since the daemon started"
	if info.Last != nil {
		changed = changeLine(*info.Last)
	}
	pairs(w, [][]string{{"State", state}, {"Flag", flagLine(info)}, {"Changed", changed}})
}

// flagLine names the flag and whether it is there, and says what a restart does where the flag and the state disagree
func flagLine(info UpDownInfo) string {
	down := info.Down != nil
	switch {
	case info.Flag == "":
		return "none, this daemon keeps no state directory"
	case info.Flagged && !down:
		return info.Flag + ", present, and a restart would start this node down"
	case !info.Flagged && down:
		return info.Flag + ", absent, and a restart would put this node back on the mesh"
	case info.Flagged:
		return info.Flag + ", present"
	}
	return info.Flag + ", absent"
}

func changeLine(change UpDownChange) string {
	to, by := "up", "a request"
	if change.Down {
		to = "down"
	}
	if change.Cause == CauseFlag {
		by = "the flag at start"
	}
	return "to " + to + " by " + by + ", " + sinceText(time.Duration(change.Ago)) + " ago, at " + change.At.UTC().Format(time.DateTime) + " UTC"
}
