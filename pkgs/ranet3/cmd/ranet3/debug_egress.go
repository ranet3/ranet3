// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"github.com/spf13/cobra"

	"ranet3.com/pkgs/ranet3/control"
)

func init() { debugCommands = append(debugCommands, (*reader).egressCommand) }

func (r *reader) egressCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "egress",
		Short: "Show the exit's state and readiness",
		Long: `The output opens with the exit's status line, which names the families
it is ready for. Under the kernel exit it then lists each rule of its chains in
the host's packet filter with its counter read now, and each family's
readiness condition by condition as the last pass judged it: the chains read
back, the host's forwarding, and each route lookup the pass read with its
answer. A rule of the translation's chain counts flows, since it meets a
flow's first packet alone. Under the userspace exit it lists the flows it
holds against its limits, its buffers, Go's memory limit beside the node's own
heap, each refusal and drop by its reason, and the sources holding the most
flows. A node with no cap.egress says so.`,
		Args:              noArguments,
		ValidArgsFunction: cobra.NoFileCompletions,
		RunE: func(cmd *cobra.Command, _ []string) error {
			info, err := control.Dial(r.socket).Egress()
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			return emit(w, r.asJSON, info, func() { control.RenderEgress(w, info) })
		},
	}
}
