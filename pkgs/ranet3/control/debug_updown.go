// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package control

import (
	"io"
	"strconv"
	"time"
)

// PathDebugUpDown is whether the node is on the mesh, the flag that keeps it off and its last move between the two
// with the Babel router id and seqno kept beside the flag
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
	// Babel is the router id and seqno of the node's own routes, and what of them a restart keeps
	Babel BabelOrigin `json:"babel"`
}

// BabelOrigin is the router id and seqno the node's own routes carry, and the state file a restart starts them from
type BabelOrigin struct {
	// RouterID is 16 hex digits
	RouterID string `json:"router_id"`
	Seqno    uint16 `json:"seqno"`
	// File is absent where the daemon keeps no state directory
	File string `json:"file,omitempty"`
	// Limit is the seqno limit the file holds for this node and router id, read when the view was asked for
	// it is absent where the file holds none for them, and a restart then starts under another router id
	Limit *uint16 `json:"limit,omitempty"`
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

// RenderUpDown writes the state, the flag, the last move and the Babel router id and seqno
func RenderUpDown(w io.Writer, info UpDownInfo) {
	state := "up"
	if info.Down != nil {
		state = "down " + downLine(*info.Down)
	}
	changed := "not since the daemon started"
	if info.Last != nil {
		changed = changeLine(*info.Last)
	}
	pairs(w, [][]string{
		{"State", state}, {"Flag", flagLine(info)}, {"Changed", changed},
		{"Router ID", routerIDLine(info.Babel)}, {"Seqno", seqnoLine(info.Babel)},
	})
}

// routerIDLine names the router id and whether a restart keeps it
func routerIDLine(origin BabelOrigin) string {
	switch {
	case origin.File == "":
		return origin.RouterID + ", which a restart does not keep, as this daemon keeps no state directory"
	case origin.Limit == nil:
		return origin.RouterID + ", which a restart does not keep, as " + origin.File + " does not hold it"
	}
	return origin.RouterID + ", kept in " + origin.File
}

// seqnoLine names the seqno and the limit a restart starts past
// a seqno past that limit, in the order of RFC 8966 section 3.2.1, as a failed save leaves one, could be sent again after a restart
func seqnoLine(origin BabelOrigin) string {
	seqno := strconv.Itoa(int(origin.Seqno))
	if origin.Limit == nil {
		return seqno
	}
	limit := strconv.Itoa(int(*origin.Limit))
	if int16(origin.Seqno-*origin.Limit) > 0 {
		return seqno + ", past " + limit + ", the limit the file holds, and a restart could reuse a seqno this node has sent"
	}
	return seqno + ", and a restart starts past " + limit + ", the limit the file holds"
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
