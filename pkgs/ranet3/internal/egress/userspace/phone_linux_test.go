// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package userspace

import (
	"bytes"
	"os"
	"os/exec"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/egress/egresstest"
)

const (
	// lowPortsFrom is ip_unprivileged_port_start as Android leaves it to an
	// app, the first port a process without CAP_NET_BIND_SERVICE may bind
	lowPortsFrom = 1024
	// phoneArmChild is the test the phone arm runs in a process of its own
	phoneArmChild = "TestUserspaceExitPassesTheSuiteUnderAndroidsProfile"
)

// androidLimits holds the limits the exit declares under Android's profile,
// linuxLimits' and two more: an app opens no raw socket and binds no port
// below 1024
func androidLimits() map[egresstest.Limit]egresstest.Declared {
	limits := linuxLimits()
	limits[egresstest.UnrelayedLeafErrors] = egresstest.Declared{
		Reason: "an app opens no raw socket, so the exit cannot send a leaf's error from the mapping's address",
		Row:    "RFC 5508 section 4.2.2 (REQ-5)",
	}
	limits[egresstest.NoLowPorts] = egresstest.Declared{
		Reason: "an app may bind no port below 1024, so a mapping takes one the host gives",
		Row:    "RFC 4787 section 4.2.1 (REQ-3)",
	}
	return limits
}

// the exit under Android's profile fails only the rows Android declares: run
// in a namespace of its own by a process whose bounding set holds no
// CAP_NET_BIND_SERVICE, so the kernel refuses its binds below 1024 with
// EACCES as an app's, and with no raw socket
func TestUserspaceExitUnderAndroidsProfileFailsOnlyItsLimits(t *testing.T) {
	claim(t)
	var tools [2]string
	for i, name := range []string{"unshare", "setpriv"} {
		path, err := exec.LookPath(name)
		if err != nil {
			t.Fatalf("find %s, which the phone arm drops its capability with: %v", name, err)
		}
		tools[i] = path
	}
	cmd := exec.Command(tools[0], "-rn", tools[1], "--bounding-set", "-net_bind_service", "--",
		os.Args[0], "-test.run", "^"+phoneArmChild+"$", "-test.count=1", "-test.v")
	out, err := cmd.CombinedOutput()
	t.Logf("the phone arm's process:\n%s", out)
	if err != nil {
		t.Fatalf("the phone arm's process ended with %v", err)
	}
	if !bytes.Contains(out, []byte("--- PASS: "+phoneArmChild+" ")) {
		t.Fatalf("the phone arm's process passed no %s", phoneArmChild)
	}
}

// TestUserspaceExitPassesTheSuiteUnderAndroidsProfile is the phone arm, which
// runs where this process may bind no port below 1024, as
// TestUserspaceExitUnderAndroidsProfileFailsOnlyItsLimits starts it
func TestUserspaceExitPassesTheSuiteUnderAndroidsProfile(t *testing.T) {
	bounded, err := unix.PrctlRetInt(unix.PR_CAPBSET_READ, unix.CAP_NET_BIND_SERVICE, 0, 0, 0)
	if err != nil {
		t.Fatalf("read the bounding set: %v", err)
	}
	if bounded == 1 {
		t.Skip("this process may bind below 1024, which an app may not, and the phone arm's own test runs this one without that capability")
	}
	claim(t)
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_unprivileged_port_start", []byte(strconv.Itoa(lowPortsFrom)+"\n"), 0o644); err != nil {
		t.Fatalf("keep the ports below %d to processes that may bind them: %v", lowPortsFrom, err)
	}
	egresstest.Run(t, func(t testing.TB) egresstest.Network {
		network := egresstest.Owned(t)
		// the suite's servers stand for hosts beyond the phone, which bind a
		// resolver's port as their own
		if err := network.Server(func() error {
			return os.WriteFile("/proc/sys/net/ipv4/ip_unprivileged_port_start", []byte("0\n"), 0o644)
		}); err != nil {
			t.Fatalf("let the servers bind any port: %v", err)
		}
		return network
	}, egresstest.Arm{
		Classes:    []egresstest.Class{egresstest.Auto, egresstest.Address},
		Limits:     androidLimits(),
		Terminates: true,
		New: func(t testing.TB, host egresstest.Host, cfg egress.Egress, hooks egress.Hooks) egress.Exit {
			// sized from the host's memory as the Linux arm, since the rows
			// open a host's flows, and a phone's totals are Within's to hold
			memory, err := HostMemory()
			if err != nil {
				t.Fatalf("read the host's memory: %v", err)
			}
			return newArmExit(t, host, cfg, hooks, memory, nil)
		},
		Holds: armHolds,
		Flows: armFlows,
	})
}
