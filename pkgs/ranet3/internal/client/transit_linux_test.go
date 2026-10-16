// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux

package client

import (
	"bytes"
	"log/slog"
	"os"
	"strings"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/babel"
	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/logtest"
)

// the warning is for enable = true on a host that does not forward a family, and names the family
// a node that leaves cap.transit out or writes it off is quiet whatever the host forwards
// the forwarding is written into a network namespace of the test's own, which the reads on its locked thread see
func TestTransitWarnsOnlyWhereTheHostCannotForwardIt(t *testing.T) {
	enterEmptyNamespace(t)
	var lines bytes.Buffer
	logtest.SetDefault(t, slog.New(slog.NewTextHandler(&lines, nil)))
	on, off := true, false
	quiet := []*config.Config{{}, {Cap: config.Caps{Transit: &babel.Transit{Enable: &off}}}}
	enabled := &config.Config{Cap: config.Caps{Transit: &babel.Transit{Enable: &on}}}
	for _, host := range []struct{ ipv4, ipv6, warning string }{
		{"1", "0", "but IPv6 forwarding is off"},
		{"0", "1", "but IPv4 forwarding is off"},
		{"0", "0", "but IPv4 and IPv6 forwarding is off"},
		{"1", "1", ""},
	} {
		for path, value := range map[string]string{"/proc/sys/net/ipv4/ip_forward": host.ipv4, "/proc/sys/net/ipv6/conf/all/forwarding": host.ipv6} {
			if err := os.WriteFile(path, []byte(value), 0o644); err != nil {
				t.Fatalf("write %s: %v", path, err)
			}
		}
		lines.Reset()
		for _, cfg := range quiet {
			warnUnforwardableTransit(cfg)
		}
		if lines.Len() != 0 {
			t.Fatalf("a node with transit off on a host forwarding IPv4 %s and IPv6 %s warned:\n%s", host.ipv4, host.ipv6, lines.String())
		}
		warnUnforwardableTransit(enabled)
		switch got := lines.String(); {
		case host.warning == "" && got != "":
			t.Errorf("enable = true on a host forwarding both families warned:\n%s", got)
		case host.warning != "" && (!strings.Contains(got, host.warning) || !strings.Contains(got, "under cap.transit")):
			t.Errorf("enable = true on a host forwarding IPv4 %s and IPv6 %s warned %q, want it to say %q and name cap.transit", host.ipv4, host.ipv6, got, host.warning)
		}
	}
}
