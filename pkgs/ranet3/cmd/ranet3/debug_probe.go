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
		Long: `Each matching session is asked to prove its path at once, as every session
is after a move of the host's default or one of its addresses. A change of
links alone probes no session. A session with a request outstanding resends that
request instead of a liveness check. One with none sends no liveness check
while its IKE SA is past its lifetime or a Delete of it has gone out, or while
a rekey of its own may run IKE_FOLLOWUP_KE exchanges or waits on the peer's.
Name a peer to probe its sessions, or pass --all to probe every session this
node holds.`,
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
