// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/internal/notices"
	"ranet3.com/pkgs/ranet3/internal/version"
)

// This file is the command tree. `ranet3 daemon` is the node itself and
// every other command speaks to a running one's control socket. They are
// subcommands of one binary rather than two programs because a fleet deploys
// one file, and because the wire types and the renderer are then shared with
// the daemon by the compiler rather than by hand.
//
// The commands here read. The four that act on a node are in write.go, and
// none of them changes its configuration: the configuration's entry points
// stay its file and SIGHUP, so the socket needs no authorization story to
// replace the one the file's permissions already are.

// reader holds the two flags every read takes. One value is shared by all of
// them because cobra parses the flags of the one command that runs.
type reader struct {
	socket string
	asJSON bool
}

// newRoot builds the command tree. It takes no process state, so a test drives
// the same tree main does with its own arguments and its own output.
func newRoot() *cobra.Command {
	r := &reader{}
	root := &cobra.Command{
		Use:   "ranet3",
		Short: "Run and control a ranet3 mesh node",
		Long: `The daemon command runs the node. Most other commands ask a running
node a question or tell it to act, through its control socket.`,
		Version: version.String(),
		// main prints the one error and the usage is on --help, so neither is
		// written twice.
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(
		daemonCommand(runDaemon),
		r.command("status", "Show state of this node", `The output covers the identity and role of the node, the counts of its
sessions, neighbors and routes, and the last pass of the route
reconciler.`,
			func(c *control.Client, w io.Writer, asJSON bool) error {
				status, err := c.Status()
				if err != nil {
					return err
				}
				return emit(w, asJSON, status, func() { control.RenderStatus(w, status) })
			}),
		r.command("neighbors", "Show Babel neighbors and link costs", `Each row is a neighbor with the cost of its link, the cost it reports
back, its round trip time and the number of routes it offers. The
Dropped and Failed columns count the packets this node chose not to
send and the packets the transport lost.`,
			func(c *control.Client, w io.Writer, asJSON bool) error {
				neighbors, err := c.Neighbors()
				if err != nil {
					return err
				}
				return emit(w, asJSON, neighbors, func() { control.RenderNeighbors(w, neighbors) })
			}),
		r.command("routes", "Show the Babel route table", `Every prefix has a row, whether its route is selected or held
unreachable after a retraction. This is Babel's table and not the
routing table of the kernel.`,
			func(c *control.Client, w io.Writer, asJSON bool) error {
				routes, err := c.Routes()
				if err != nil {
					return err
				}
				return emit(w, asJSON, routes, func() { control.RenderRoutes(w, routes) })
			}),
		r.command("sessions", "Show IKE sessions", `Each row is a live IKE SA with its SPIs, its age and how long since the
peer last answered.`,
			func(c *control.Client, w io.Writer, asJSON bool) error {
				sessions, err := c.Sessions()
				if err != nil {
					return err
				}
				return emit(w, asJSON, sessions, func() { control.RenderSessions(w, sessions) })
			}),
		r.command("peers", "Show peers and their connection state", `The peers are the nodes this node dials, named in the config file or
taken from the registry. The State column says whether a session holds
the path.`,
			func(c *control.Client, w io.Writer, asJSON bool) error {
				peers, err := c.Peers()
				if err != nil {
					return err
				}
				return emit(w, asJSON, peers, func() { control.RenderPeers(w, peers) })
			}),
		metricsCommand(r),
		versionCommand(r),
		licensesCommand(),
		completionCommand(root),
		debugCommand(),
	)
	root.AddCommand(r.queryCommands()...)
	root.AddCommand(r.writeCommands()...)
	wordCobraDefaults(root)
	return root
}

// wordCobraDefaults makes the help command, every help flag and the root's version flag now and words them here
// cobra makes them at execution and words them in lowercase
// it also opens the description of every command with its summary, so each command writes its summary once
func wordCobraDefaults(root *cobra.Command) {
	// cobra lists how to run a command that runs, and a group runs only to print its help
	// so a command that holds others lists those and nothing above them, as a command that never runs does
	root.SetUsageTemplate(strings.Replace(root.UsageTemplate(),
		"Usage:{{if .Runnable}}", "Usage:{{if and .Runnable (not .HasAvailableSubCommands)}}", 1))
	root.InitDefaultHelpCmd()
	root.InitDefaultVersionFlag()
	root.Flags().Lookup("version").Usage = "Print ranet3 version"
	help, _, _ := root.Find([]string{"help"})
	help.Short = "Show help for any command"
	help.Long = "Type ranet3 help and the path to a command for full details."
	var walk func(*cobra.Command)
	walk = func(cmd *cobra.Command) {
		cmd.InitDefaultHelpFlag()
		cmd.Flags().Lookup("help").Usage = "Help for " + cmd.Name()
		cmd.Long = cmd.Short + "\n\n" + cmd.Long
		for _, child := range cmd.Commands() {
			walk(child)
		}
	}
	walk(root)
}

// command builds one read-only subcommand from what it asks the daemon for and
// how it prints the answer. The five are written out at the call sites rather
// than generated, so the type each one gets is the type the compiler checked.
func (r *reader) command(use, short, long string, run func(*control.Client, io.Writer, bool) error) *cobra.Command {
	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Long:  long,
		Args:  noArguments,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return run(control.Dial(r.socket), cmd.OutOrStdout(), r.asJSON)
		},
	}
	r.flags(cmd)
	return cmd
}

// flags is the pair every read shares. They are per command rather than
// persistent on the root, because --control means "bind here" to the daemon
// and "read here" to everything else, and --json is meaningless to the daemon.
func (r *reader) flags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVar(&r.socket, "control", control.DefaultSocket, "Path to the control socket")
	f.BoolVar(&r.asJSON, "json", false, "Print JSON output")
}

// metricsCommand prints the scrape this node would serve on a metrics
// listener, read over the control socket instead, so an operator reads a
// node's counters without it having to bind a port a fleet then has to
// firewall. It takes no --json, since a monitoring system already parses the
// exposition format.
func metricsCommand(r *reader) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "metrics",
		Short: "Print metrics in Prometheus format",
		Long: `The output is the scrape the node would serve on a metrics listener,
read over the control socket so the node needs no listener of its own.`,
		Args: noArguments,
		RunE: func(cmd *cobra.Command, _ []string) error {
			text, err := control.Dial(r.socket).Metrics()
			if err != nil {
				return err
			}
			_, err = io.WriteString(cmd.OutOrStdout(), text)
			return err
		},
	}
	cmd.Flags().StringVar(&r.socket, "control", control.DefaultSocket, "Path to the control socket")
	return cmd
}

// versionCommand prints the version this binary was built from, and with
// --daemon the one the node on the other end of the socket is running. The two
// differ for exactly as long as an upgraded file waits for a restart, which is
// the window a fleet conversion spends every node in.
func versionCommand(r *reader) *cobra.Command {
	var fromDaemon bool
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print ranet3 version",
		Long: `The version is the one this binary was built from. With --daemon it is
the one the running node reports, which differs from the binary's until
the node restarts on an upgraded file.`,
		Args: noArguments,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !fromDaemon {
				fmt.Fprintln(cmd.OutOrStdout(), version.String())
				return nil
			}
			status, err := control.Dial(r.socket).Status()
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), status.Version)
			return nil
		},
	}
	cmd.Flags().BoolVar(&fromDaemon, "daemon", false, "Ask the running daemon")
	cmd.Flags().StringVar(&r.socket, "control", control.DefaultSocket, "Path to the control socket")
	return cmd
}

// noArguments refuses a stray word. cobra.NoArgs reports it as an unknown
// command, which sends somebody who typed one argument too many looking for a
// subcommand that was never the problem.
func noArguments(cmd *cobra.Command, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("%s takes no arguments, got %q", cmd.CommandPath(), args[0])
	}
	return nil
}

// refuseUnknownCommands makes a command that only holds others refuse a word that names none of them
// cobra checks what follows a command only when the command runs, so the group runs to print its help
func refuseUnknownCommands(cmd *cobra.Command) {
	cmd.Args = unknownCommand
	cmd.RunE = func(cmd *cobra.Command, _ []string) error { return cmd.Help() }
	cmd.SuggestionsMinimumDistance = suggestionDistance
}

// unknownCommand is cobra's refusal of a word that names no command, with the suggestions cobra writes for the root alone
// the root's refusal comes from a check that only a command without a parent reaches
// the word help is taken, since the group answers it with its help as the root's help command answers the group's name
func unknownCommand(cmd *cobra.Command, args []string) error {
	if len(args) > 0 && args[0] == "help" {
		return nil
	}
	err := cobra.NoArgs(cmd, args)
	if err == nil {
		return nil
	}
	suggestions := cmd.SuggestionsFor(args[0])
	if len(suggestions) == 0 {
		return err
	}
	var lines strings.Builder
	lines.WriteString("\n\nDid you mean this?\n")
	for _, suggestion := range suggestions {
		fmt.Fprintf(&lines, "\t%s\n", suggestion)
	}
	return fmt.Errorf("%w%s", err, lines.String())
}

// emit writes one answer, as indented JSON or through its renderer. The JSON
// is re-encoded from the decoded value rather than passed through, so a client
// and a daemon that disagree about a field show that disagreement here rather
// than hiding it behind the daemon's own bytes.
func emit(w io.Writer, asJSON bool, value any, render func()) error {
	if !asJSON {
		render()
		return nil
	}
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "%s\n", body)
	return err
}

// licensesCommand prints the notice every module linked into this binary
// requires a distribution to carry. It is a subcommand rather than a file
// beside the binary, because a binary gets distributed on its own and the
// obligation has to travel with it.
func licensesCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "licenses",
		Short: "Print open source license information",
		Long:  `The output is the notice of every module linked into this binary.`,
		Args:  noArguments,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := io.WriteString(cmd.OutOrStdout(), notices.ThirdParty)
			return err
		},
	}
}
