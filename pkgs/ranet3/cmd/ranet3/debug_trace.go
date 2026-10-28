// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"time"

	"github.com/spf13/cobra"

	"ranet3.com/pkgs/ranet3/control"
)

func init() {
	debugCommands = append(debugCommands, (*reader).traceCommand)
}

func (r *reader) traceCommand() *cobra.Command {
	query := control.TraceQuery{Rate: control.TraceRateDefault}
	var sources, destinations []string
	var protocol string
	var bound time.Duration
	cmd := &cobra.Command{
		Use:   "trace",
		Short: "Show each packet's forwarding decision",
		Long: `A record is one packet the node decided: how it arrived, what the node
did with it and why, and its headers as it arrived. Relayed packets are
other nodes' traffic, so a record carries none of a packet's bytes
unless --payload asks for them, and only uid 0 may trace, under every
--debug-access but off. It prints records until --for has passed. A
packet the forwarding decision does not see, such as Babel's own or IKE
and ESP on the underlay, never appears. A peer is named by its path, by
org/name:serial, by org/name or by name.`,
		Args:              noArguments,
		ValidArgsFunction: cobra.NoFileCompletions,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if bound <= 0 {
				return fmt.Errorf("--for takes a duration above zero, not %s", bound)
			}
			for _, list := range []struct {
				flag  string
				texts []string
				into  *[]netip.Prefix
			}{{"--src", sources, &query.Sources}, {"--dst", destinations, &query.Destinations}} {
				for _, text := range list.texts {
					prefix, err := control.ParseTracePrefix(text)
					if err != nil {
						return fmt.Errorf("%s: %w", list.flag, err)
					}
					*list.into = append(*list.into, prefix)
				}
			}
			if protocol != "" {
				number, err := control.ParseTraceProtocol(protocol)
				if err != nil {
					return fmt.Errorf("--proto: %w", err)
				}
				query.Protocol = number
			}
			if err := query.Check(); err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), bound)
			defer cancel()
			w := cmd.OutOrStdout()
			for line, err := range control.Dial(r.socket).Trace(ctx, query) {
				// a trace ends at --for, which is the command doing what it was asked
				if errors.Is(err, context.DeadlineExceeded) {
					return nil
				}
				if err != nil {
					return err
				}
				if r.asJSON {
					if err := json.NewEncoder(w).Encode(line); err != nil {
						return err
					}
					continue
				}
				control.RenderTraceLine(w, line)
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringArrayVar(&sources, "src", nil, "Only show packets from this prefix or address")
	f.StringArrayVar(&destinations, "dst", nil, "Only show packets to this prefix or address")
	f.StringVar(&protocol, "proto", "", "Only show packets of this protocol, by name or number")
	f.StringVar(&query.Decision, "decision", "", "Only show packets the node decided this way")
	f.StringVar(&query.Peer, "peer", "", "Only show packets from or to this peer")
	f.IntVar(&query.Rate, "rate", control.TraceRateDefault, "Most records a second")
	f.IntVar(&query.Payload, "payload", 0, "Bytes of each packet to show")
	f.DurationVar(&bound, "for", followFor, "How long to trace")
	cmd.RegisterFlagCompletionFunc("decision", cobra.FixedCompletions(control.TraceDecisions, cobra.ShellCompDirectiveNoFileComp))
	cmd.RegisterFlagCompletionFunc("proto", cobra.FixedCompletions(slices.Sorted(maps.Keys(control.TraceProtocols)), cobra.ShellCompDirectiveNoFileComp))
	cmd.RegisterFlagCompletionFunc("peer", r.completePeers)
	for _, name := range []string{"src", "dst", "rate", "payload", "for"} {
		cmd.RegisterFlagCompletionFunc(name, cobra.NoFileCompletions)
	}
	return cmd
}
