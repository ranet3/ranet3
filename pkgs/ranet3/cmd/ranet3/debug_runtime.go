// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"github.com/spf13/cobra"

	"ranet3.com/pkgs/ranet3/control"
)

func init() { debugCommands = append(debugCommands, (*reader).runtimeCommand) }

func (r *reader) runtimeCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "runtime",
		Short: "Show daemon runtime state",
		Long: `The output covers the build, goroutines, threads, file descriptors, heap
and resolver of the running node.`,
		Args:              noArguments,
		ValidArgsFunction: cobra.NoFileCompletions,
		RunE: func(cmd *cobra.Command, _ []string) error {
			info, err := control.Dial(r.socket).Runtime()
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			return emit(w, r.asJSON, info, func() { control.RenderRuntime(w, info) })
		},
	}
}
