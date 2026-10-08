// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package control

import (
	"context"
	"net/http"
	"reflect"
)

// PathDebugProbe asks sessions to prove their path now, the way a network change asks every one
const PathDebugProbe = PathDebug + "probe"

func init() { registerDebug(PathDebugProbe, classRoot, reflect.TypeFor[Result](), serveProbe) }

// ProbeSource is a Source whose sessions can be asked to prove their path
type ProbeSource interface {
	// DebugProbe asks the sessions of one peer, or every session, and reports which
	DebugProbe(ctx context.Context, peer string, all bool) (Result, error)
}

// serveProbe is an action, so it takes a POST and the body a write takes
func serveProbe(d *debugServer, w http.ResponseWriter, r *http.Request) {
	if !writing(w, r) {
		return
	}
	source, ok := implements[ProbeSource](d, w, "probe")
	if !ok {
		return
	}
	if request, ok := readRequest(w, r); ok {
		result, err := source.DebugProbe(r.Context(), request.Peer, request.All)
		answerResult(w, result, err)
	}
}

// Probe asks the sessions of one peer, or every session, to prove their path now
func (c *Client) Probe(peer string, all bool) (Result, error) {
	return c.call(PathDebugProbe, Request{Peer: peer, All: all})
}
