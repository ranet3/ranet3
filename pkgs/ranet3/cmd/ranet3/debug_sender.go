// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"ranet3.com/pkgs/ranet3/control"
)

func init() { debugCommands = append(debugCommands, (*reader).senderCommand) }

func (r *reader) senderCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "sender [peer]",
		Short: "Show each session's sender",
		Long: `The output covers each session's ordered sender: what its batches hold of
the data and control budgets, how many packets it sends between two waits,
how long it waits for the first batch of its queue to be sealed and how long
a batch takes from its reservation to its seal. Name a peer to show its
sessions alone.`,
		Args:              cobra.MaximumNArgs(1),
		ValidArgsFunction: r.completeSessions,
		RunE: func(cmd *cobra.Command, args []string) error {
			peer := ""
			if len(args) == 1 {
				peer = args[0]
			}
			info, err := control.Dial(r.socket).Sender(cmd.Context(), peer)
			if err != nil {
				return err
			}
			if peer != "" && len(info.Sessions) == 0 {
				return fmt.Errorf("no session of this node matches %s", peer)
			}
			w := cmd.OutOrStdout()
			return emit(w, r.asJSON, info, func() { control.RenderSender(w, info) })
		},
	}
}
