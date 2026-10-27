// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"github.com/spf13/cobra"

	"ranet3.com/pkgs/ranet3/control"
)

func init() { debugCommands = append(debugCommands, (*reader).rulesCommand) }

func (r *reader) rulesCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "rules",
		Short: "Show the host's policy rules and the border filter's chain",
		Long: `The output covers every policy rule the kernel holds, whoever wrote it, the
rules the reconciler derives that the kernel does not hold, and, on a node with
cap.border, the border filter's chain with the packets each drop counted.`,
		Args:              noArguments,
		ValidArgsFunction: cobra.NoFileCompletions,
		RunE: func(cmd *cobra.Command, _ []string) error {
			info, err := control.Dial(r.socket).Rules()
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			return emit(w, r.asJSON, info, func() { control.RenderRules(w, info) })
		},
	}
}
