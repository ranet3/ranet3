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
	var iif string
	cmd := &cobra.Command{
		Use:   "route <src> <dst>",
		Short: "Show where a packet goes",
		Long: `The output follows a packet from src to dst to where the kernel sends it:
the policy rule the kernel took, the route it matched with each next hop, or
the error it refused the packet with and the settings that explain it. The
packet is this host's own unless --iif names the link it arrives on, and an
unspecified src such as 0.0.0.0 is this host's own packet sent with no source,
whose source the kernel picks. The mesh's tun is no arrival: a packet written
into it is this host's own. The packet is taken unmarked and well formed. The
kernel names no rule, so the rule shown is the one a walk of the rules as the
kernel walks them ends on for that answer, as far as the answer tells.`,
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
			info, err := control.Dial(r.socket).Route(cmd.Context(), src, dst, iif, "")
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			return emit(w, r.asJSON, info, func() { control.RenderRoute(w, info) })
		},
	}
	cmd.Flags().StringVar(&iif, "iif", "", "Link the packet arrives on")
	cmd.RegisterFlagCompletionFunc("iif", r.completeLinks)
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
