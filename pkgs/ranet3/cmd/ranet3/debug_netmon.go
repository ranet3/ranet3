// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"github.com/spf13/cobra"

	"ranet3.com/pkgs/ranet3/control"
)

func init() { debugCommands = append(debugCommands, (*reader).netmonCommand) }

func (r *reader) netmonCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "netmon",
		Short: "Show the host network the node watches",
		Long: `The output covers each family's default route, addresses and links outside
the mesh as the network watch last read them, and the last change it acted on.
A change of a default or an address probes every session, wakes every dialer
and wakes the route reconciler, and with cap.exit a change of links alone wakes
the reconciler too.`,
		Args:              noArguments,
		ValidArgsFunction: cobra.NoFileCompletions,
		RunE: func(cmd *cobra.Command, _ []string) error {
			info, err := control.Dial(r.socket).Netmon()
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			return emit(w, r.asJSON, info, func() { control.RenderNetmon(w, info) })
		},
	}
}
