// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"github.com/spf13/cobra"

	"ranet3.com/pkgs/ranet3/control"
)

func init() { debugCommands = append(debugCommands, (*reader).probeCommand) }

func (r *reader) probeCommand() *cobra.Command {
	var all bool
	cmd := &cobra.Command{
		Use:   "probe [peer]",
		Short: "Probe sessions now",
		Long: `Each matching session sends a liveness check at once, as every session
does after a network change. Name a peer to probe its sessions, or pass --all
to probe every session this node holds.`,
		Args:              peerOrAll(&all),
		ValidArgsFunction: r.completePeers,
		RunE: func(cmd *cobra.Command, args []string) error {
			peer := ""
			if !all {
				peer = args[0]
			}
			result, err := control.Dial(r.socket).Probe(peer, all)
			return r.report(cmd, result, err)
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "Probe every session")
	return cmd
}
