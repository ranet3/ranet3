// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"maps"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"ranet3.com/pkgs/ranet3/control"
)

// This file is the write half of the command tree: the verbs that act on a
// running node rather than reading one.
//
// None of them changes the node's configuration, which keeps its two entry
// points, the file and SIGHUP. What each acts on is operational state the file
// already decides, so the socket's mode stays the whole authorization story;
// the control package doc holds the argument and the line a fifth verb would
// have to stay inside.

// writeCommands is the four verbs, which the root adds after the reads so the
// usage lists what a node answers before what it does.
func (r *reader) writeCommands() []*cobra.Command {
	return []*cobra.Command{
		r.subsystemCommand("disable", "Disable a subsystem", `The subsystem stays stopped until it is enabled again or the node
restarts, and a reload does not start it. A node refuses the command for
a subsystem it does not run.`, false),
		r.subsystemCommand("enable", "Enable a subsystem", `This starts a subsystem that somebody disabled. A node refuses the
command for a subsystem it does not run.`, true),
		r.redialCommand(),
		r.rekeyCommand(),
		r.reloadCommand(),
	}
}

// subsystemCommand builds disable and enable, which differ only in the state
// they ask for. The argument is completed from the closed set rather than from
// the daemon, because the set is the same on every node and a completion that
// needed a running one would offer nothing where it is most wanted.
func (r *reader) subsystemCommand(use, short, long string, on bool) *cobra.Command {
	cmd := &cobra.Command{
		Use:       use + " <" + strings.Join(control.SubsystemNames(), "|") + ">",
		Short:     short,
		Long:      long,
		Args:      cobra.ExactArgs(1),
		ValidArgs: control.SubsystemNames(),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, subsystem := control.Dial(r.socket), control.Subsystem(args[0])
			ask := client.Disable
			if on {
				ask = client.Enable
			}
			result, err := ask(subsystem)
			return r.report(cmd, result, err)
		},
	}
	r.flags(cmd)
	return cmd
}

// redialCommand answers a peer holding a session this node no longer has. A
// peer in that state was seen to carry a dead session for sixteen minutes and
// came back only when its own daemon was reloaded by hand.
func (r *reader) redialCommand() *cobra.Command {
	var all bool
	cmd := &cobra.Command{
		Use:   "redial [peer]",
		Short: "Reconnect to a peer now",
		Long: `This drops the sessions held for the peer and sets its dialers going at
once, instead of after the reconnect delay. Pass --all to do this for every
peer, which helps after a network change the node did not see, such as a
captive portal that left every address and route in place.`,
		Args:              peerOrAll(&all),
		ValidArgsFunction: r.completePeers,
		RunE: func(cmd *cobra.Command, args []string) error {
			peer := ""
			if !all {
				peer = args[0]
			}
			result, err := control.Dial(r.socket).Redial(peer, all)
			return r.report(cmd, result, err)
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "Redial every peer")
	r.flags(cmd)
	return cmd
}

// rekeyCommand replaces a Child SA without waiting for its own schedule.
func (r *reader) rekeyCommand() *cobra.Command {
	var all bool
	cmd := &cobra.Command{
		Use:   "rekey [peer]",
		Short: "Rekey sessions now",
		Long: `Each session replaces its child SA without waiting for its own schedule.
Name a peer to rekey its sessions, or pass --all to rekey every session
this node holds.`,
		Args:              peerOrAll(&all),
		ValidArgsFunction: r.completePeers,
		RunE: func(cmd *cobra.Command, args []string) error {
			peer := ""
			if !all {
				peer = args[0]
			}
			result, err := control.Dial(r.socket).Rekey(peer, all)
			return r.report(cmd, result, err)
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "Rekey every session")
	r.flags(cmd)
	return cmd
}

// peerOrAll takes one peer, or none under --all.
// The peer and --all are exclusive, and the daemon says so as well:
// this is the local half, so a command line that names neither is
// answered without a round trip.
func peerOrAll(all *bool) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if *all {
			return noArguments(cmd, args)
		}
		return cobra.ExactArgs(1)(cmd, args)
	}
}

// reloadCommand is SIGHUP over the socket, so a supervisor is not the only way
// to ask and an operator on a node they did not start can ask at all.
func (r *reader) reloadCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "reload",
		Short: "Reload the config and trust document",
		Long: `This does what SIGHUP does. The node reads its config file and the trust
document again without restarting, and a subsystem that was disabled
stays disabled.`,
		Args: noArguments,
		RunE: func(cmd *cobra.Command, _ []string) error {
			result, err := control.Dial(r.socket).Reload()
			return r.report(cmd, result, err)
		},
	}
	r.flags(cmd)
	return cmd
}

// report prints one verb's answer, as the wire form under --json and as the
// sentence otherwise. The error goes back untouched, because the daemon's
// refusals already name what this node does not run.
func (r *reader) report(cmd *cobra.Command, result control.Result, err error) error {
	if err != nil {
		return err
	}
	w := cmd.OutOrStdout()
	return emit(w, r.asJSON, result, func() { control.RenderResult(w, result) })
}

// completePeers offers the peers this node dials and the peers it holds a
// session with, which between them cover everything redial and rekey act on.
// A daemon that cannot be reached offers nothing rather than an error: a
// completion that wrote one would put it in the middle of a command line.
func (r *reader) completePeers(_ *cobra.Command, args []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	client := control.Dial(r.socket)
	named := make(map[string]struct{})
	if peers, err := client.Peers(); err == nil {
		for _, peer := range peers {
			named[peer.Organization+"/"+peer.CommonName] = struct{}{}
		}
	}
	// The sessions as well, because a peer that only dials this node has no
	// entry in the peers list and is exactly the peer a redial is for.
	if sessions, err := client.Sessions(); err == nil {
		for _, session := range sessions {
			if session.Peer != "" {
				named[session.Peer] = struct{}{}
			}
		}
	}
	out := make([]cobra.Completion, 0, len(named))
	for _, name := range slices.Sorted(maps.Keys(named)) {
		if strings.HasPrefix(name, toComplete) {
			out = append(out, name)
		}
	}
	return out, cobra.ShellCompDirectiveNoFileComp
}
