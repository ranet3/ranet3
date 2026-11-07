// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net/netip"
	"os"
	"slices"
	"syscall"
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
	var protocol, pcap string
	var bound time.Duration
	cmd := &cobra.Command{
		Use:   "trace",
		Short: "Show each packet's forwarding decision",
		Long: `A record is one packet the node decided: how it arrived, what the node
did with it and why, and its headers as it arrived. Relayed packets are
other nodes' traffic, so a record carries none of a packet's bytes
unless --payload asks for them. It prints records until --for has passed. A
packet the forwarding decision does not see, such as Babel's own or IKE
and ESP on the underlay, never appears. A peer is named by its path, by
org/name:serial, by org/name or by name. --pcap writes the records to a
pcapng file instead, or to stdout for -, each packet's bytes as --payload
asks, which --pcap needs, with the rest of its line as the packet's
comment. The file is readable by its owner alone, and the stream's notes
go to stderr.`,
		Args:              noArguments,
		ValidArgsFunction: cobra.NoFileCompletions,
		RunE: func(cmd *cobra.Command, _ []string) (err error) {
			switch {
			case bound <= 0:
				return fmt.Errorf("--for takes a duration above zero, not %s", bound)
			case pcap != "" && r.asJSON:
				return errors.New("--pcap and --json each name the form the records take, so a trace takes one of them")
			case pcap != "" && query.Payload == 0:
				return errors.New("--pcap writes each packet's bytes, which a record carries only as --payload asks, so it takes --payload above 0")
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
			var capture *control.TracePcap
			if pcap != "" {
				file, done, openErr := openPcap(pcap, w)
				if openErr != nil {
					return openErr
				}
				defer func() { err = errors.Join(err, done()) }()
				if capture, err = control.NewTracePcap(file); err != nil {
					return err
				}
			}
			for line, err := range control.Dial(r.socket).Trace(ctx, query) {
				// a trace ends at --for, which is the command doing what it was asked
				if errors.Is(err, context.DeadlineExceeded) {
					return nil
				}
				if err != nil {
					return err
				}
				if capture != nil {
					if line.Packet == nil {
						control.RenderTraceLine(cmd.ErrOrStderr(), line)
					} else if err := capture.Write(*line.Packet); err != nil {
						return err
					}
					continue
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
	f.StringVar(&pcap, "pcap", "", "Write the records as pcapng to this file")
	cmd.MarkFlagFilename("pcap", "pcapng")
	cmd.RegisterFlagCompletionFunc("decision", cobra.FixedCompletions(control.TraceDecisions, cobra.ShellCompDirectiveNoFileComp))
	cmd.RegisterFlagCompletionFunc("proto", cobra.FixedCompletions(slices.Sorted(maps.Keys(control.TraceProtocols)), cobra.ShellCompDirectiveNoFileComp))
	cmd.RegisterFlagCompletionFunc("peer", r.completePeers)
	for _, name := range []string{"src", "dst", "rate", "payload", "for"} {
		cmd.RegisterFlagCompletionFunc(name, cobra.NoFileCompletions)
	}
	return cmd
}

// openPcap opens the file --pcap names, or stdout for -, and what closes it, so that the packets reach no one but the caller
// the file it writes is always one it created
func openPcap(name string, stdout io.Writer) (io.Writer, func() error, error) {
	if name == "-" {
		return stdout, func() error { return nil }, nil
	}
	info, err := os.Lstat(name)
	switch {
	case err == nil:
		if err := pcapRefusal(name, info); err != nil {
			return nil, nil, fmt.Errorf("--pcap: %w", err)
		}
		// syscall.Unlink removes only a name, where os.Remove would remove a directory swapped in after the lstat
		if err := syscall.Unlink(name); err != nil {
			return nil, nil, fmt.Errorf("--pcap: %w", &fs.PathError{Op: "unlink", Path: name, Err: err})
		}
	case !errors.Is(err, fs.ErrNotExist):
		return nil, nil, fmt.Errorf("--pcap: %w", err)
	}
	file, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("--pcap: %w", err)
	}
	return file, file.Close, nil
}

// pcapRefusal is why --pcap does not remove the name at which it found the file of the status info
// and nil for a regular file the caller owns
func pcapRefusal(name string, info fs.FileInfo) error {
	st := info.Sys().(*syscall.Stat_t)
	switch {
	case !info.Mode().IsRegular():
		return fmt.Errorf("%s is not a regular file", name)
	case int(st.Uid) != os.Geteuid():
		return fmt.Errorf("%s belongs to uid %d, not to the caller's uid %d", name, st.Uid, os.Geteuid())
	}
	return nil
}
