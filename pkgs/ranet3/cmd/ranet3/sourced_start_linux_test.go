// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package main

import (
	"errors"
	"net/netip"
	"os"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/client"
	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/egress"
	kernelexit "ranet3.com/pkgs/ranet3/internal/egress/kernel"
	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/kernel"
)

func TestSourcedStartRefusesForeignOccupancyBeforeConstructors(t *testing.T) {
	for _, tc := range []struct{ name, configured, expected string }{
		{name: "default tun", expected: "ranet3"},
		{name: "named tun", configured: "labtun0", expected: "labtun0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts, missing, s, _ := waitingStart(t, "auth.key")
			if err := os.WriteFile(missing, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if tc.configured != "" {
				rewrite(t, opts.configPath, "link:\n", "link:\n  tun: "+tc.configured+"\n")
			}
			rewrite(t, opts.configPath, "      family: ip4\n", "      family: ip4\ncap:\n  table:\n    sourced:\n      to: [2001:db8:80::/96]\n")
			checked, constructed := 0, 0
			s.preflight = func(table kernel.Table, _ []netip.Prefix, tun string) error {
				checked++
				if table.Sourced == nil || tun != tc.expected {
					t.Errorf("sourced preflight received key %v and tun %q, want %q", table.Sourced, tun, tc.expected)
				}
				return errors.New("kernel: foreign sourced occupant")
			}
			s.node = func(*config.Config, *events.Bus) (*client.Client, error) {
				constructed++
				return nil, errors.New("node constructed after refusal")
			}
			s.border = func(*egress.Border, egress.BorderRuntime) (*kernelexit.BorderFilter, error) {
				constructed++
				return nil, errors.New("border constructed after refusal")
			}
			if code := startDaemon(opts, s); code != 1 || checked != 1 || constructed != 0 {
				t.Fatalf("refused start: code %d, preflights %d, constructors %d", code, checked, constructed)
			}
		})
	}
}

func TestKeylessStartDoesNotPreflightSourcedOwnership(t *testing.T) {
	opts, missing, s, _ := waitingStart(t, "auth.key")
	if err := os.WriteFile(missing, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	constructed := 0
	s.preflight = func(kernel.Table, []netip.Prefix, string) error {
		t.Error("keyless start read sourced ownership")
		return errors.New("unexpected sourced preflight")
	}
	s.node = func(*config.Config, *events.Bus) (*client.Client, error) {
		constructed++
		return nil, errors.New("node constructed for the keyless start")
	}
	if code := startDaemon(opts, s); code != 1 || constructed != 1 {
		t.Fatalf("keyless start: code %d, constructors %d", code, constructed)
	}
}
