// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"github.com/spf13/cobra"

	"ranet3.com/pkgs/ranet3/control"
)

func init() { debugCommands = append(debugCommands, (*reader).segmentsCommand) }

func (r *reader) segmentsCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "segments",
		Short: "Show local segments and steering",
		Long: `The output covers each segment this node answers for, an egress segment
with whether its SID is announced and the families the mesh hands to the exit
through it, the steering policies with their selectors, sources, paths and
overhead, stopped or not, and the node's segment counters as ranet3 status
reports them.`,
		Args:              noArguments,
		ValidArgsFunction: cobra.NoFileCompletions,
		RunE: func(cmd *cobra.Command, _ []string) error {
			info, err := control.Dial(r.socket).Segments()
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			return emit(w, r.asJSON, info, func() { control.RenderSegments(w, info) })
		},
	}
}
