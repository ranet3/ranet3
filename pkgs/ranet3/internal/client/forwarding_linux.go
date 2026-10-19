// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux

package client

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"ranet3.com/pkgs/ranet3/internal/egress"
)

// forwardingEnabled reports whether this host forwards, per family. Babel has
// no way to say "I carry my own prefixes but nothing else": a node that
// advertises a route is promising to forward it, so the only signal a peer
// ever gets is the advertisement itself. A node that redistributes with
// forwarding off therefore attracts traffic it drops, and nothing tells the
// sender.
//
// It is read here rather than in each package that needs it, so that transit
// and the egress capability answer the question the same way. Forwarding
// exports it, and internal/egress withholds an advertisement over the same fact
// this warns about.
func forwardingEnabled() (v4, v6 bool) {
	return sysctlIsOne("/proc/sys/net/ipv4/ip_forward"),
		sysctlIsOne("/proc/sys/net/ipv6/conf/all/forwarding")
}

func sysctlIsOne(path string) bool {
	// Unreadable is not "off": reporting a warning this node cannot
	// substantiate is worse than staying quiet.
	return readSysctl(path) != "0"
}

// l3mdevAccept reports whether a socket outside a VRF is matched by traffic
// that arrived through one. It is off by default, and with a VRF holding the
// mesh addresses that decides whether anything on this node can use them: a
// reply arriving through the master is looked up only against sockets bound to
// that master, so every TCP and UDP flow to and from a mesh address fails
// while ICMP, which is matched differently, answers. Measured on a fleet node
// on 2026-09-21, where it read as a routing problem for an afternoon.
//
// Both halves have to be on to say yes, since a node with one of them is half
// broken in a way that is harder to find than a node with neither.
func l3mdevAccept() bool {
	return sysctlIsOne("/proc/sys/net/ipv4/tcp_l3mdev_accept") &&
		sysctlIsOne("/proc/sys/net/ipv4/udp_l3mdev_accept")
}

func egressDeviceReader(name string) func() (v4, v6 error) {
	return (&egressDeviceCheck{root: sysctlRoot, name: name}).check
}

// the kernel takes the larger of conf.all.rp_filter and the device's own
type egressDeviceCheck struct {
	root, name string
	// warned is the nonzero conf.all.rp_filter last warned about, so the warning comes once per change
	warned string
}

func (e *egressDeviceCheck) check() (v4, v6 error) {
	// every link has a conf directory while it exists, so a missing one is the
	// link deleted under the mesh, which neither family survives
	if _, err := os.Stat(filepath.Join(e.root, "net/ipv4/conf", e.name)); errors.Is(err, fs.ErrNotExist) {
		gone := fmt.Errorf("%w, the kernel lists no link named %s", egress.ErrDeviceGone, e.name)
		return gone, gone
	}
	return e.checkIPv4(), e.putBack("ipv6", "disable_ipv6")
}

func (e *egressDeviceCheck) putBack(family, key string) error {
	path := filepath.Join(e.root, "net", family, "conf", e.name, key)
	was := readSysctl(path)
	if was == "" || was == "0" {
		return nil
	}
	if err := os.WriteFile(path, []byte("0\n"), 0o644); err != nil {
		return fmt.Errorf("net.%s.conf.%s.%s is %s and could not be put back to 0: %w", family, e.name, key, was, err)
	}
	slog.Info("egress device "+key+" put back to 0", "name", e.name, "was", was)
	return nil
}

func (e *egressDeviceCheck) checkIPv4() error {
	if err := e.putBack("ipv4", "rp_filter"); err != nil {
		return err
	}
	all := readSysctl(filepath.Join(e.root, "net/ipv4/conf/all/rp_filter"))
	if all == "" || all == "0" {
		e.warned = ""
	} else {
		if all != e.warned {
			slog.Warn("egress device takes rp_filter "+all+" from net.ipv4.conf.all.rp_filter", "name", e.name)
			e.warned = all
		}
		return fmt.Errorf("net.ipv4.conf.all.rp_filter is %s, and the kernel takes it over the device's 0", all)
	}
	if readSysctl(filepath.Join(e.root, "net/ipv4/conf", e.name, "forwarding")) == "0" {
		return fmt.Errorf("net.ipv4.conf.%s.forwarding is 0", e.name)
	}
	return nil
}

func readSysctl(path string) string {
	body, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(body))
}
