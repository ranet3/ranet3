// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"ranet3.com/pkgs/ranet3/control"
)

func init() { debugCommands = append(debugCommands, (*reader).pmtuCommand) }

func (r *reader) pmtuCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "pmtu [peer]",
		Short: "Show each session's path MTU",
		Long: `The output covers link.mtu, the tun's MTU and the answers and MSS clamps
for packets past a session's budget, then each session's search of the path
to its endpoint: its state, its budget, the route's MTU, its probes and its
last budget change. Name a peer to show its sessions alone.`,
		Args:              cobra.MaximumNArgs(1),
		ValidArgsFunction: r.completeSessions,
		RunE: func(cmd *cobra.Command, args []string) error {
			peer := ""
			if len(args) == 1 {
				peer = args[0]
			}
			info, err := control.Dial(r.socket).PMTU(cmd.Context(), peer)
			if err != nil {
				return err
			}
			if peer != "" && len(info.Sessions) == 0 {
				return fmt.Errorf("no session of this node matches %s", peer)
			}
			w := cmd.OutOrStdout()
			return emit(w, r.asJSON, info, func() { control.RenderPMTU(w, info) })
		},
	}
}

// completeSessions offers the peers of the sessions the daemon searches the path of
// it asks for completionTimeout at most and offers nothing when the daemon does not answer
func (r *reader) completeSessions(_ *cobra.Command, args []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	ctx, cancel := context.WithTimeout(context.Background(), completionTimeout)
	defer cancel()
	info, err := control.Dial(r.socket).PMTU(ctx, "")
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	var out []cobra.Completion
	for _, session := range info.Sessions {
		if strings.HasPrefix(session.Peer, toComplete) {
			out = append(out, session.Peer)
		}
	}
	// a node is offered once, though it holds a session per pair of endpoints
	slices.Sort(out)
	return slices.Compact(out), cobra.ShellCompDirectiveNoFileComp
}
