// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"github.com/spf13/cobra"

	"ranet3.com/pkgs/ranet3/control"
)

func init() { debugCommands = append(debugCommands, (*reader).upDownCommand) }

func (r *reader) upDownCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "updown",
		Short: "Show whether the node is on the mesh",
		Long: `The output covers whether the node is up or down and since when, the
flag in the state directory that keeps it down through a restart, and the
last move between up and down with its cause, a request or the flag at
start.`,
		Args:              noArguments,
		ValidArgsFunction: cobra.NoFileCompletions,
		RunE: func(cmd *cobra.Command, _ []string) error {
			info, err := control.Dial(r.socket).UpDown()
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			return emit(w, r.asJSON, info, func() { control.RenderUpDown(w, info) })
		},
	}
}
