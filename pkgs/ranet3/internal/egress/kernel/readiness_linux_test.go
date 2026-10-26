// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel_test

import (
	"context"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/egress/egresstest"
	"ranet3.com/pkgs/ranet3/internal/netnstest"
	"ranet3.com/pkgs/ranet3/schema"
)

// heldSweep is the sweep of an exit whose host a test changes under it, so the
// pass that reads the change comes at once, heldWait how long the test waits
// for that pass, generous for a loaded machine, and heldPoll how often it looks
const (
	heldSweep = 100 * time.Millisecond
	heldWait  = 10 * time.Second
	heldPoll  = 10 * time.Millisecond
)

// An address a class translates to, taken off lo, holds its family not ready
// from the next pass with the address named, the other family ready
// throughout, and put back on lo the next pass reads both ready again
func TestClassAddressTakenOffLoopbackHoldsItsFamilyNotReady(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	host := netnstest.StartThread(t)
	classes := []netip.Prefix{netip.MustParsePrefix("198.51.100.7/32"), netip.MustParsePrefix("2001:db8::7/128")}
	loopback := func(what string, change func(netlink netnstest.Netlink, index int) error) {
		t.Helper()
		if err := host.Do(func() error {
			netlink, err := netnstest.OpenNetlink()
			if err != nil {
				return err
			}
			defer netlink.Close()
			lo, err := net.InterfaceByName("lo")
			if err != nil {
				return err
			}
			return change(netlink, lo.Index)
		}); err != nil {
			t.Fatalf("%s: %v", what, err)
		}
	}
	if err := host.Do(func() error {
		for _, path := range []string{"/proc/sys/net/ipv4/ip_forward", "/proc/sys/net/ipv6/conf/all/forwarding"} {
			if err := os.WriteFile(path, []byte("1\n"), 0o644); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("turn forwarding on: %v", err)
	}
	loopback("put the class addresses on lo", func(netlink netnstest.Netlink, index int) error {
		for _, class := range classes {
			if err := netlink.AddAddress(index, class); err != nil {
				return err
			}
		}
		return nil
	})
	cfg := egress.Egress{
		Advertise: []schema.Prefix{schema.MustPrefix("0.0.0.0/0"), schema.MustPrefix("::/0")},
		Translate: []egress.Class{
			{From: schema.MustPrefix("0.0.0.0/0"), To: egress.Translation{Addr: classes[0].Addr()}},
			{From: schema.MustPrefix("::/0"), To: egress.Translation{Addr: classes[1].Addr()}},
		},
		Sweep: schema.Duration(heldSweep),
	}
	exit := newKernelExit(t, egresstest.Host{Do: host.Do, TUN: "ranet0", Write: func([][]byte) {}}, cfg, egress.Hooks{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- exit.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("stop the exit: %v", err)
		}
	})
	await := func(what string, ok func(egress.Status) bool) {
		t.Helper()
		for deadline := time.Now().Add(heldWait); !ok(exit.Status()); time.Sleep(heldPoll) {
			if time.Now().After(deadline) {
				s := exit.Status()
				t.Fatalf("%s, within %s the exit read ready %v in IPv4 and %v in IPv6 with the reason %q", what, heldWait, s.Ready4, s.Ready6, s.Unready)
			}
		}
	}
	ready := func(s egress.Status) bool { return s.Ready4 && s.Ready6 && s.Unready == "" }
	await("with both addresses on lo", ready)
	for i, class := range classes {
		address := class.Addr().String()
		loopback("take "+address+" off lo", func(netlink netnstest.Netlink, index int) error { return netlink.DelAddress(index, class) })
		named := "the lookup of " + address + ", an address cap.egress translate names, "
		await("with "+address+" taken off lo", func(s egress.Status) bool {
			return s.Ready4 == (i == 1) && s.Ready6 == (i == 0) && strings.HasPrefix(s.Unready, named)
		})
		t.Logf("with %s taken off lo the exit reads %q", address, exit.Status().Unready)
		loopback("put "+address+" back on lo", func(netlink netnstest.Netlink, index int) error { return netlink.AddAddress(index, class) })
		await("with "+address+" put back on lo", ready)
	}
}
