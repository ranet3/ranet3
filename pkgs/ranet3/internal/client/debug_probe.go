// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"context"
	"fmt"
	"log/slog"

	"ranet3.com/pkgs/ranet3/control"
)

// DebugProbe asks the sessions of one peer, or every session, to prove their path now, as a network change asks every one
func (c *Client) DebugProbe(ctx context.Context, peer string, all bool) (result control.Result, err error) {
	defer func() { c.noteVerb(ctx, "probe", peer, result.Acted, err, slog.Bool("all", all)) }()
	probed, err := c.askSessions("probe", peer, all, c.sessions.startProbe)
	if err != nil {
		return control.Result{}, err
	}
	return control.Result{Acted: probed, Detail: fmt.Sprintf("Asked %d session(s) to prove their path now", len(probed))}, nil
}
