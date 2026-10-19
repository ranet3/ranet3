// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/logtest"
)

// sysctlTree is a sysctl root for the egress device ranet3e holding the
// values given, a value of "" leaving that file out
func sysctlTree(t testing.TB, all, own, forwarding, disable string) string {
	t.Helper()
	root := t.TempDir()
	for path, value := range map[string]string{
		"net/ipv4/conf/all/rp_filter":        all,
		"net/ipv4/conf/ranet3e/rp_filter":    own,
		"net/ipv4/conf/ranet3e/forwarding":   forwarding,
		"net/ipv6/conf/ranet3e/disable_ipv6": disable,
	} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, path)), 0o755); err != nil {
			t.Fatal(err)
		}
		if value == "" {
			continue
		}
		if err := os.WriteFile(filepath.Join(root, path), []byte(value+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// slogged gathers what the default logger writes for the rest of the test
func slogged(t *testing.T) *bytes.Buffer {
	t.Helper()
	var lines bytes.Buffer
	logtest.SetDefault(t, slog.New(slog.NewTextHandler(&lines, nil)))
	return &lines
}

// the device's own rp_filter is put back to 0 with a line each time another
// writer set it, a nonzero conf.all.rp_filter holds IPv4 not ready with one
// warning per value, the device's forwarding off holds it too, a file that
// cannot be read counts as the good value, and IPv6 passes throughout
func TestEgressDeviceReaderPutsItsRPFilterBackAndHoldsIPv4ForTheHosts(t *testing.T) {
	lines := slogged(t)
	root := sysctlTree(t, "0", "2", "1", "0")
	reader := (&egressDeviceCheck{root: root, name: "ranet3e"}).check
	check := func() error {
		t.Helper()
		v4, v6 := reader()
		if v6 != nil {
			t.Errorf("IPv6 was refused beside IPv4's answer %v: %v", v4, v6)
		}
		return v4
	}
	own := filepath.Join(root, "net/ipv4/conf/ranet3e/rp_filter")
	if err := check(); err != nil {
		t.Errorf("a device whose own rp_filter could be put back was refused: %v", err)
	}
	if got := readSysctl(own); got != "0" {
		t.Errorf("the device's rp_filter reads %q, want it put back to 0", got)
	}
	if got := strings.Count(lines.String(), "egress device rp_filter put back to 0"); got != 1 || !strings.Contains(lines.String(), "was=2") {
		t.Errorf("the put back was logged %d times, want once naming was=2:\n%s", got, lines)
	}
	if err := check(); err != nil || strings.Count(lines.String(), "put back") != 1 {
		t.Errorf("a pass that reads 0 answered %v and logged:\n%s", err, lines)
	}

	all := filepath.Join(root, "net/ipv4/conf/all/rp_filter")
	for _, step := range []struct {
		all      string
		warnings int
	}{{"2", 1}, {"2", 1}, {"1", 2}, {"0", 2}, {"1", 3}} {
		if err := os.WriteFile(all, []byte(step.all+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		err := check()
		if (step.all != "0") != (err != nil) || err != nil && !strings.Contains(err.Error(), "net.ipv4.conf.all.rp_filter is "+step.all) {
			t.Errorf("conf.all.rp_filter %s answered %v", step.all, err)
		}
		if got := strings.Count(lines.String(), "from net.ipv4.conf.all.rp_filter"); got != step.warnings {
			t.Errorf("after conf.all.rp_filter %s the warning was logged %d times, want %d:\n%s", step.all, got, step.warnings, lines)
		}
	}
	if err := os.WriteFile(all, []byte("0\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(root, "net/ipv4/conf/ranet3e/forwarding"), []byte("0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := check(); err == nil || !strings.Contains(err.Error(), "net.ipv4.conf.ranet3e.forwarding is 0") {
		t.Errorf("the device's forwarding off answered %v", err)
	}
	if v4, v6 := (&egressDeviceCheck{root: sysctlTree(t, "", "", "", ""), name: "ranet3e"}).check(); v4 != nil || v6 != nil {
		t.Errorf("unreadable sysctls were refused: %v, %v", v4, v6)
	}
	if err := os.RemoveAll(filepath.Join(root, "net/ipv4/conf/ranet3e")); err != nil {
		t.Fatal(err)
	}
	v4, v6 := reader()
	for family, err := range map[string]error{"IPv4": v4, "IPv6": v6} {
		if !errors.Is(err, egress.ErrDeviceGone) || !strings.Contains(err.Error(), "no link named ranet3e") {
			t.Errorf("the device's link gone answered %s with %v, want it to wrap egress.ErrDeviceGone and name the link", family, err)
		}
	}
}

// the device's disable_ipv6 is put back to 0 with a line each time another
// writer set it, IPv6 is held not ready naming it while it cannot be put back
// and still reads 1, and IPv4 passes throughout
func TestEgressDeviceReaderPutsItsDisableIPv6BackAndHoldsIPv6WhileItCannot(t *testing.T) {
	lines := slogged(t)
	root := sysctlTree(t, "0", "0", "1", "1")
	reader := (&egressDeviceCheck{root: root, name: "ranet3e"}).check
	check := func() error {
		t.Helper()
		v4, v6 := reader()
		if v4 != nil {
			t.Errorf("IPv4 was refused beside IPv6's answer %v: %v", v6, v4)
		}
		return v6
	}
	disable := filepath.Join(root, "net/ipv6/conf/ranet3e/disable_ipv6")
	if err := check(); err != nil {
		t.Errorf("a device whose disable_ipv6 could be put back was refused: %v", err)
	}
	if got := readSysctl(disable); got != "0" {
		t.Errorf("the device's disable_ipv6 reads %q, want it put back to 0", got)
	}
	if err := check(); err != nil {
		t.Errorf("a pass that reads 0 answered %v", err)
	}
	if err := os.WriteFile(disable, []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := check(); err != nil || readSysctl(disable) != "0" {
		t.Errorf("another writer's 1 was answered with %v and left %q", err, readSysctl(disable))
	}
	if got := strings.Count(lines.String(), "egress device disable_ipv6 put back to 0"); got != 2 || strings.Count(lines.String(), "was=1") != 2 {
		t.Errorf("two put backs were logged %d times, want twice naming was=1:\n%s", got, lines)
	}

	if err := os.WriteFile(disable, []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(disable, 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(disable, []byte("1\n"), 0o444); err == nil {
		t.Skip("a file of mode 0444 takes this process's write, so the put back cannot be refused")
	}
	err := check()
	if err == nil || !strings.Contains(err.Error(), "net.ipv6.conf.ranet3e.disable_ipv6 is 1 and could not be put back to 0") {
		t.Errorf("a disable_ipv6 of 1 that could not be put back answered %v, want IPv6 refused naming it", err)
	}
}
