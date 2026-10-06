// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"ranet3.com/pkgs/ranet3/control"
)

func init() {
	debugCommands = append(debugCommands, (*reader).eventsCommand, (*reader).waitCommand)
}

func (r *reader) eventsCommand() *cobra.Command {
	var query control.EventQuery
	var bound time.Duration
	cmd := &cobra.Command{
		Use:   "events",
		Short: "Show node events",
		Long: `The node records what it did, a state change and never a packet. This
prints the recorded events and exits. With --follow it goes on printing
new events until --for has passed. A kind also selects the events under
it, so babel selects every Babel event, and --kind may be repeated. A
peer is named by its path, by org/name or by name.`,
		Args:              noArguments,
		ValidArgsFunction: cobra.NoFileCompletions,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !query.Follow {
				bound = control.ReadTimeout
			}
			if bound <= 0 {
				return fmt.Errorf("--for takes a duration above zero, not %s", bound)
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), bound)
			defer cancel()
			w := cmd.OutOrStdout()
			for event, err := range control.Dial(r.socket).Events(ctx, query) {
				// a follow ends at --for, which is the command doing what it was asked
				// a daemon that never answered fails with an error of its own, which control.Stream keeps apart from this
				if query.Follow && errors.Is(err, context.DeadlineExceeded) {
					return nil
				}
				if err != nil {
					return err
				}
				if err := r.printEvent(w, event); err != nil {
					return err
				}
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.BoolVarP(&query.Follow, "follow", "f", false, "Follow new events")
	f.DurationVar(&bound, "for", followFor, "How long to follow")
	f.StringArrayVar(&query.Kinds, "kind", nil, "Only show events of this kind")
	f.DurationVar(&query.Since, "since", 0, "Only show events this recent")
	r.peerFlag(cmd, &query.Peer, "Only show events about this peer")
	cmd.RegisterFlagCompletionFunc("for", cobra.NoFileCompletions)
	cmd.RegisterFlagCompletionFunc("kind", r.recorded(func(e control.Event) string { return e.Kind }))
	cmd.RegisterFlagCompletionFunc("since", cobra.NoFileCompletions)
	return cmd
}

// peerFlag is the --peer both events and wait take, with its completion
func (r *reader) peerFlag(cmd *cobra.Command, peer *string, usage string) {
	cmd.Flags().StringVar(peer, "peer", "", usage)
	cmd.RegisterFlagCompletionFunc("peer", r.recorded(func(e control.Event) string { return e.Peer }))
}

// printEvent writes one event as its line, or under --json as one line of the wire form
func (r *reader) printEvent(w io.Writer, event control.Event) error {
	if r.asJSON {
		return json.NewEncoder(w).Encode(event)
	}
	control.RenderEvent(w, event)
	return nil
}

func (r *reader) waitCommand() *cobra.Command {
	var query control.EventQuery
	var attrs []string
	var past, timeout time.Duration
	cmd := &cobra.Command{
		Use:   "wait <kind>",
		Short: "Wait for a node event",
		Long: `This prints the first event of the kind and how long after the wait
began it happened, then exits 0. It exits 1 when none came within
--timeout and 2 when it could not watch for one. Repeat --attr to
require several attributes. A peer is named by its path, by org/name or
by name.`,
		Args: func(cmd *cobra.Command, args []string) error {
			if err := cobra.ExactArgs(1)(cmd, args); err != nil {
				return unwatched(cmd, err)
			}
			return nil
		},
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
			if len(args) > 0 {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			return r.recorded(func(e control.Event) string { return e.Kind })(cmd, args, toComplete)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if past < 0 {
				return unwatched(cmd, fmt.Errorf("--past takes a duration of zero or more, not %s", past))
			}
			if timeout <= 0 {
				return unwatched(cmd, fmt.Errorf("--timeout takes a duration above zero, not %s", timeout))
			}
			query.Attrs = make(map[string]string, len(attrs))
			for _, attr := range attrs {
				key, value, ok := strings.Cut(attr, "=")
				if !ok {
					return unwatched(cmd, fmt.Errorf("--attr takes key=value, not %q", attr))
				}
				query.Attrs[key] = value
			}
			// the whole recorder of the kind is read, so an event between this start and the subscription is not lost
			// the start is the boundary of the recorded events alone, on the clock the daemon shares with this host
			// an event after the stream.live note came after the subscription, so after the start, whatever its stamp says
			// the daemon queues only what the query takes, so the first such event after the subscription finds the queue empty
			started := time.Now()
			query.Kinds, query.Follow = args, true
			ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
			defer cancel()
			live := false
			for event, err := range control.Dial(r.socket).Events(ctx, query) {
				switch {
				case errors.Is(err, context.DeadlineExceeded):
					fmt.Fprintf(cmd.ErrOrStderr(), "No %s event arrived within %s\n", args[0], control.Spelled(timeout))
					return waitTimedOut
				case err != nil:
					return unwatched(cmd, err)
				case event.Kind == "stream.closed":
					return unwatched(cmd, fmt.Errorf("the daemon ended the stream before %s arrived: %s", args[0], event.Attrs["reason"]))
				case event.Kind == "stream.dropped":
					return unwatched(cmd, fmt.Errorf("the daemon dropped %s of the events this wait takes before it could read them", event.Attrs["count"]))
				case event.Kind == "stream.live":
					live = true
					continue
				case !live && event.At.Before(started.Add(-past)):
					continue
				}
				after := event.At.Sub(started)
				if live {
					after = max(after, 0)
				}
				answer, w := control.Waited{Event: event, After: control.Duration(after)}, cmd.OutOrStdout()
				return emit(w, r.asJSON, answer, func() { control.RenderWaited(w, answer) })
			}
			return unwatched(cmd, fmt.Errorf("the stream ended before %s arrived", args[0]))
		},
	}
	f := cmd.Flags()
	f.StringArrayVar(&attrs, "attr", nil, "Require this key=value attribute")
	f.DurationVar(&past, "past", 0, "Also match a recorded event this recent")
	f.DurationVar(&timeout, "timeout", waitTimeout, "How long to wait")
	r.peerFlag(cmd, &query.Peer, "Only match events about this peer")
	cmd.RegisterFlagCompletionFunc("attr", cobra.NoFileCompletions)
	cmd.RegisterFlagCompletionFunc("past", cobra.NoFileCompletions)
	cmd.RegisterFlagCompletionFunc("timeout", cobra.NoFileCompletions)
	cmd.SetFlagErrorFunc(unwatched)
	return cmd
}

// unwatched says why a wait could not watch for its event or lost it, and exits with a status a script tells from the timeout's
func unwatched(cmd *cobra.Command, err error) error {
	fmt.Fprintln(cmd.ErrOrStderr(), err)
	return waitUnwatched
}

// recorded completes from the distinct values pick takes from the daemon's recorder
// it asks for completionTimeout at most and offers nothing when the daemon does not answer
func (r *reader) recorded(pick func(control.Event) string) cobra.CompletionFunc {
	return func(_ *cobra.Command, _ []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
		ctx, cancel := context.WithTimeout(context.Background(), completionTimeout)
		defer cancel()
		seen := map[string]bool{}
		for event, err := range control.Dial(r.socket).Events(ctx, control.EventQuery{}) {
			if err != nil {
				break
			}
			if value := pick(event); value != "" && strings.HasPrefix(value, toComplete) {
				seen[value] = true
			}
		}
		return slices.Sorted(maps.Keys(seen)), cobra.ShellCompDirectiveNoFileComp
	}
}
