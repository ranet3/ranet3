// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

// completionCommand writes the shell's own completion script to stdout, which
// is how a package installs one: the build runs this and drops the output in
// the shell's completion directory, rather than a hand-written script drifting
// from the command tree it describes.
func completionCommand(root *cobra.Command) *cobra.Command {
	return &cobra.Command{
		Use:       "completion [bash|zsh|fish]",
		Short:     "Generate shell completion scripts",
		Long:      `The script for bash, zsh or fish goes to standard output.`,
		Args:      cobra.ExactArgs(1),
		ValidArgs: []string{"bash", "zsh", "fish"},
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			switch args[0] {
			case "bash":
				return root.GenBashCompletion(out)
			case "zsh":
				return root.GenZshCompletion(out)
			case "fish":
				return root.GenFishCompletion(out, true)
			default:
				return fmt.Errorf("unsupported shell: %s", args[0])
			}
		},
	}
}
