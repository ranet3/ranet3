// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"ranet3.com/pkgs/ranet3/control"
)

// debugCommands builds the command of every debug view
// each cmd/ranet3/debug_<view>.go appends its own from an init
var debugCommands []func(*reader) *cobra.Command

// debugCommand is the hidden tree, which promises nothing beyond the revision that built it
// its --control and --json are persistent here and nowhere else, since no command under debug binds a socket
func debugCommand() *cobra.Command {
	r := &reader{}
	cmd := &cobra.Command{
		Use:    "debug",
		Short:  "look inside a running node, through commands that are not a stable interface",
		Hidden: true,
	}
	flags := cmd.PersistentFlags()
	flags.StringVar(&r.socket, "control", control.DefaultSocket, "path to the daemon's control socket")
	flags.BoolVar(&r.asJSON, "json", false, "print the wire form instead of text")
	cmd.MarkPersistentFlagFilename("control", "sock")
	cmd.AddCommand(r.socketCommand(), r.buildInfoCommand())
	for _, build := range debugCommands {
		cmd.AddCommand(build(r))
	}
	return cmd
}

// socketCommand sends one request as written, for a path no command covers yet
// or a daemon of another revision
func (r *reader) socketCommand() *cobra.Command {
	var timeout time.Duration
	cmd := &cobra.Command{
		Use:               "socket [METHOD] PATH [BODY|-]",
		Short:             "send one raw request to the control socket and print the answer as it arrives",
		Args:              cobra.RangeArgs(1, 3),
		ValidArgsFunction: completeRaw,
		RunE: func(cmd *cobra.Command, args []string) error {
			method, path, body, err := rawRequest(args, cmd.InOrStdin())
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
			defer cancel()
			response, err := control.Dial(r.socket).Raw(ctx, method, path, body)
			if err != nil {
				return err
			}
			defer response.Body.Close()
			fmt.Fprintln(cmd.ErrOrStderr(), response.Proto, response.Status)
			// a stream ends at the timeout like any other answer, with what arrived printed
			if _, err := io.Copy(cmd.OutOrStdout(), response.Body); err != nil && !errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			if response.StatusCode/100 != 2 {
				return exitCode(1)
			}
			return nil
		},
	}
	cmd.Flags().DurationVar(&timeout, "timeout", readTimeout, "how long the request may take, the answer's body included")
	cmd.RegisterFlagCompletionFunc("timeout", cobra.NoFileCompletions)
	return cmd
}

// completeRaw offers a method or a path for the first word and a path after a method
// a body is free text, so nothing is offered for it
func completeRaw(_ *cobra.Command, args []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
	paths := append([]string{
		control.PathStatus, control.PathNeighbors, control.PathRoutes, control.PathSessions, control.PathPeers, control.PathMetrics,
		control.PathDisable, control.PathEnable, control.PathRedial, control.PathRekey, control.PathReload,
	}, slices.Sorted(control.DebugPaths())...)
	var offered []string
	switch {
	case len(args) == 0:
		offered = append([]string{http.MethodGet, http.MethodHead, http.MethodPost}, paths...)
	case len(args) == 1 && !strings.HasPrefix(args[0], "/"):
		offered = paths
	}
	var out []cobra.Completion
	for _, word := range offered {
		if strings.HasPrefix(word, toComplete) {
			out = append(out, word)
		}
	}
	return out, cobra.ShellCompDirectiveNoFileComp
}

// rawRequest reads METHOD PATH BODY
// the method is GET where it is left out, or POST where a body follows the path
func rawRequest(args []string, stdin io.Reader) (method, path string, body io.Reader, err error) {
	if !strings.HasPrefix(args[0], "/") {
		method, args = strings.ToUpper(args[0]), args[1:]
	}
	if len(args) == 0 || !strings.HasPrefix(args[0], "/") {
		return "", "", nil, errors.New("debug socket takes a path starting with a slash, such as /v0/status")
	}
	path = args[0]
	switch {
	case len(args) > 2:
		return "", "", nil, errors.New("debug socket takes a method, a path and a body, and nothing after them")
	case len(args) == 2 && args[1] == "-":
		body = stdin
	case len(args) == 2:
		body = strings.NewReader(args[1])
	}
	switch {
	case method != "":
	case body != nil:
		method = http.MethodPost
	default:
		method = http.MethodGet
	}
	return method, path, body, nil
}

// buildInfoCommand prints what the toolchain recorded about this binary
// the daemon's own build is under debug runtime
func (r *reader) buildInfoCommand() *cobra.Command {
	return &cobra.Command{
		Use:               "go-buildinfo",
		Short:             "print the go build information of this binary",
		Args:              noArguments,
		ValidArgsFunction: cobra.NoFileCompletions,
		RunE: func(cmd *cobra.Command, _ []string) error {
			info, ok := debug.ReadBuildInfo()
			if !ok {
				return errors.New("this binary carries no build information")
			}
			w := cmd.OutOrStdout()
			return emit(w, r.asJSON, info, func() { io.WriteString(w, info.String()) })
		},
	}
}
