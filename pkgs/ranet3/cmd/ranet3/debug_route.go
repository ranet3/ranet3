// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/spf13/cobra"

	"ranet3.com/pkgs/ranet3/control"
)

func init() { debugCommands = append(debugCommands, (*reader).routeCommand) }

func (r *reader) routeCommand() *cobra.Command {
	var iif, peer string
	cmd := &cobra.Command{
		Use:   "route <src> <dst>",
		Short: "Show where a packet goes",
		Long: `The output follows a packet from src to dst to where this host sends it.
The packet is this host's own unless --iif names the link it arrives on or
--peer the node whose session it arrives through, and an unspecified src such
as 0.0.0.0 is this host's own packet sent with no source, whose source the
kernel picks. The mesh's tun is no arrival: a packet written into it is this
host's own. The packet is an ICMP echo request, unmarked and well formed, with
a hop limit of 64 and no options or extension headers.

The kernel's part is the policy rule it took, the route it matched with each
next hop, or the error it refused the packet with and the settings that
explain it. The kernel names no rule, so the rule shown is the one a walk of
the rules as the kernel walks them ends on for that answer, as far as the
answer tells. A route into the tun goes on through the mesh's checks of what
enters it for this host's own packet with a src, and for a packet arriving on
a link that the kernel forwards. It ends there for a packet of no src, whose
source the kernel picks, and for one the kernel does not forward.

A packet arriving through a session meets the segment of this node it is
addressed to first, which says whether it admits the source and stops, since
the packet carries no routing header or inner packet. Any other meets the
mesh's decision, in the words a trace of the decision uses, and the kernel's
part where the mesh delivers it to this host, whose route ends the walk.`,
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) != 2 {
				return errors.New("debug route takes a source and a destination address")
			}
			return nil
		},
		ValidArgsFunction: cobra.NoFileCompletions,
		RunE: func(cmd *cobra.Command, args []string) error {
			src, dst, err := control.ParseRoutePacket(args[0], args[1])
			if err != nil {
				return err
			}
			if iif != "" {
				if _, err := net.InterfaceByName(iif); err != nil {
					return fmt.Errorf("--iif %s names no link on this host", iif)
				}
			}
			info, err := control.Dial(r.socket).Route(cmd.Context(), src, dst, iif, peer)
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			return emit(w, r.asJSON, info, func() { control.RenderRoute(w, info) })
		},
	}
	cmd.Flags().StringVar(&iif, "iif", "", "Link the packet arrives on")
	cmd.Flags().StringVar(&peer, "peer", "", "Node whose session the packet arrives through")
	cmd.MarkFlagsMutuallyExclusive("iif", "peer")
	cmd.RegisterFlagCompletionFunc("iif", r.completeLinks)
	// the two addresses are arguments already, which completePeers reads as a peer named
	cmd.RegisterFlagCompletionFunc("peer", func(cmd *cobra.Command, _ []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
		return r.completePeers(cmd, nil, toComplete)
	})
	return cmd
}

// completeLinks offers the links of the host the command runs on but the
// mesh's tun, which a read of the status bounded by completionTimeout names,
// and nothing where the daemon does not answer.
func (r *reader) completeLinks(_ *cobra.Command, _ []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
	ctx, cancel := context.WithTimeout(context.Background(), completionTimeout)
	defer cancel()
	status, err := control.Dial(r.socket).StatusWithin(ctx)
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	links, err := net.Interfaces()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	var out []cobra.Completion
	for _, link := range links {
		if link.Name != status.TUN && strings.HasPrefix(link.Name, toComplete) {
			out = append(out, link.Name)
		}
	}
	return out, cobra.ShellCompDirectiveNoFileComp
}
