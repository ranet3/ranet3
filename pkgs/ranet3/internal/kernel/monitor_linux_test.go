// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"context"
	"encoding/binary"
	"log/slog"
	"net/netip"
	"os"
	"slices"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/netlink"
	"ranet3.com/pkgs/ranet3/internal/netnstest"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/schema"
)

// ruleRestoreBudget is how soon a deleted rule of the reconciler's is back
// the periodic sweep alone takes DefaultReconcileInterval
const ruleRestoreBudget = time.Second

// the monitor wakes on a deleted rule carrying the reconciler's protocol and on nothing else about rules
// another writer's rule comes and goes without a pass, and a rule the reconciler adds itself is already in place
func TestRouteMonitorWakesOnlyOnADeletedRuleItOwns(t *testing.T) {
	plat, _ := writePlatform(t)
	wakesOn := reconcilerWakes(uint32(plat.table.ID), plat.table.Proto, plat.index)
	owned := plat.ruleMessage(Rule{Family: FamilyIPv4, FWMark: 0x72, Table: schema.TableMain, Priority: 40})
	for name, arm := range map[string]struct {
		kind uint16
		body []byte
		want bool
	}{
		"its own rule deleted":           {unix.RTM_DELRULE, owned, true},
		"its own rule added":             {unix.RTM_NEWRULE, owned, false},
		"another writer's rule deleted":  {unix.RTM_DELRULE, replaceProtocol(t, owned, unix.RTPROT_STATIC), false},
		"a rule without a protocol gone": {unix.RTM_DELRULE, stripProtocol(t, owned), false},
	} {
		if got := wakesOn(netlink.Message{Kind: arm.kind, Data: arm.body}); got != arm.want {
			t.Errorf("%s: the monitor woke %v, want %v", name, got, arm.want)
		}
	}
}

// the monitor wakes on an address added to the tun or taken off it, whoever wrote it, and on no other link's
func TestRouteMonitorWakesOnTheTunsAddresses(t *testing.T) {
	plat, _ := writePlatform(t)
	wakesOn := reconcilerWakes(uint32(plat.table.ID), plat.table.Proto, plat.index)
	tun := plat.addrMessage(netip.MustParsePrefix("192.0.2.1/32"))
	other := slices.Clone(tun)
	binary.NativeEndian.PutUint32(other[4:], plat.index+1)
	for name, arm := range map[string]struct {
		kind uint16
		body []byte
		want bool
	}{
		"an address added to the tun":       {unix.RTM_NEWADDR, tun, true},
		"an address taken off the tun":      {unix.RTM_DELADDR, tun, true},
		"an address added to another link":  {unix.RTM_NEWADDR, other, false},
		"an address taken off another link": {unix.RTM_DELADDR, other, false},
		"an address message cut short":      {unix.RTM_NEWADDR, tun[:4], false},
	} {
		if got := wakesOn(netlink.Message{Kind: arm.kind, Data: arm.body}); got != arm.want {
			t.Errorf("%s: the monitor woke %v, want %v", name, got, arm.want)
		}
	}
}

// notification is one datagram holding one netlink message of kind with body
func notification(kind uint16, body []byte) []byte {
	datagram := make([]byte, unix.SizeofNlMsghdr+len(body))
	binary.NativeEndian.PutUint32(datagram, uint32(len(datagram)))
	binary.NativeEndian.PutUint16(datagram[4:], kind)
	copy(datagram[unix.SizeofNlMsghdr:], body)
	return datagram
}

// the monitor reads its socket through readNotifications: an error wakes it, the notification after the error and a datagram that
// does not parse each wake it again, and Close ends the backoff two errors in a row leave it in, its goroutine with it
func TestRouteMonitorReadsOnAndClosesWhilePaused(t *testing.T) {
	source := newScriptedSource(nil)
	monitor := startMonitor("scripted", source, func(message netlink.Message) bool { return message.Kind == unix.RTM_NEWADDR })
	t.Cleanup(func() { _ = monitor.Close() })
	source.queue <- scriptedRead{err: unix.EMSGSIZE}
	awaitWake(t, monitor.signal, "EMSGSIZE")
	source.queue <- scriptedRead{datagram: notification(unix.RTM_NEWADDR, hostAddrMessage(2, prefix("192.0.2.10/24")))}
	awaitWake(t, monitor.signal, "an address after the error")
	runsPast := notification(unix.RTM_NEWADDR, nil)
	binary.NativeEndian.PutUint32(runsPast, uint32(2*len(runsPast)))
	source.queue <- scriptedRead{datagram: runsPast}
	awaitWake(t, monitor.signal, "a datagram whose length runs past its end")
	source.queue <- scriptedRead{err: unix.EMSGSIZE}
	source.queue <- scriptedRead{err: unix.EMSGSIZE}
	waitFor(t, func() bool { return source.reads.Load() == 5 })
	awaitClose(t, monitor.Close)
	select {
	case <-monitor.done:
	default:
		t.Error("the monitor's goroutine still runs after Close returned")
	}
}

// addressWakeBudget is how soon a pass follows another writer's address on the tun
// the periodic sweep alone takes DefaultReconcileInterval
const addressWakeBudget = time.Second

// in mode 2 another writer's overlay address of either family on the tun brings the family's catch-all for the host in, and taking it
// off takes it out, each on a pass the address's own notification wakes, long before the periodic sweep
func TestNetlinkFollowsAnotherWritersAddressOnTheTun(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("the real netlink path needs root on linux")
	}
	netnstest.EnterEmpty(t)
	conn, err := dialNetlink()
	if err != nil {
		t.Fatalf("dial rtnetlink: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	const device = "ranetaddr0"
	createTUN(t, device)

	bus := events.New()
	overlay := []schema.Prefix{schema.MustPrefix("192.0.2.0/24"), schema.MustPrefix("3fff::/20")}
	r, err := New(Table{}.WithMode(&ExitMode{}), Runtime{Interface: device, Overlay: overlay, Events: bus, Sessions: func() int { return 1 }}, netstack.NewRouteTable())
	if err != nil {
		t.Fatalf("start the reconciler: %v", err)
	}
	plat := r.plat.(*netlinkPlatform)
	// read through a socket of the test's own, since the loop owns the platform's
	catchAll := func() []string {
		replies, err := conn.execute(unix.RTM_GETRULE, unix.NLM_F_DUMP, make([]byte, sizeofFibRuleHdr))
		if err != nil {
			t.Fatalf("dump rules: %v", err)
		}
		var out []string
		for _, reply := range replies {
			if rule, ok := plat.decodeRule(reply); ok && rule.Priority == priorityCatchAll {
				out = append(out, string(rule.Family)+" iif "+rule.IIF)
			}
		}
		slices.Sort(out)
		return out
	}
	trigger := func() string {
		passes := bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "kernel.pass" }, 0)
		if len(passes) == 0 {
			return ""
		}
		return passes[len(passes)-1].Attrs["trigger"]
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("the reconciler stopped with %v", err)
		}
	})
	waitFor(t, func() bool { return trigger() == "start" })
	if got := catchAll(); len(got) != 0 {
		t.Fatalf("with no overlay address on the tun the catch-all reads %v, want none", got)
	}

	v4, v6 := netip.MustParsePrefix("192.0.2.1/32"), netip.MustParsePrefix("3fff::1/128")
	for _, step := range []struct {
		what    string
		kind    uint16
		address netip.Prefix
		want    []string
	}{
		{"another writer's IPv4 overlay address added", unix.RTM_NEWADDR, v4, []string{"ipv4 iif lo"}},
		{"the IPv4 address taken off", unix.RTM_DELADDR, v4, nil},
		{"another writer's IPv6 overlay address added", unix.RTM_NEWADDR, v6, []string{"ipv6 iif lo"}},
		{"the IPv6 address taken off", unix.RTM_DELADDR, v6, nil},
	} {
		flags := uint16(unix.NLM_F_ACK)
		if step.kind == unix.RTM_NEWADDR {
			flags |= unix.NLM_F_CREATE | unix.NLM_F_EXCL
		}
		if _, err := conn.execute(step.kind, flags, plat.addrMessage(step.address)); err != nil {
			t.Fatalf("%s: %v", step.what, err)
		}
		changed := time.Now()
		waitFor(t, func() bool { return slices.Equal(catchAll(), step.want) && trigger() == "kernel" })
		if took := time.Since(changed); took > addressWakeBudget {
			t.Errorf("%s: the catch-all followed in %s, want at most %s", step.what, took, addressWakeBudget)
		}
	}
}

// systemd-networkd deletes every rule it did not ask for whenever it configures a link
// the reconciler puts its own back within the settle window and one pass, long before the periodic sweep
func TestNetlinkRestoresADeletedRuleWithinASecond(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("the real netlink path needs root on linux")
	}
	netnstest.EnterEmpty(t)
	conn, err := dialNetlink()
	if err != nil {
		t.Fatalf("dial rtnetlink: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	const device = "ranetrule0"
	createTUN(t, device)

	// the rules derived from an overlay of each family
	overlay := []schema.Prefix{schema.MustPrefix("198.18.0.0/15"), schema.MustPrefix("3fff::/20")}
	installed := derivedRules(DefaultTable, overlay, nil, exitView{})
	r, err := New(Table{}, Runtime{Interface: device, Overlay: overlay}, netstack.NewRouteTable())
	if err != nil {
		t.Fatalf("start the reconciler: %v", err)
	}
	plat := r.plat.(*netlinkPlatform)
	// read through a socket of the test's own, since the loop owns the platform's
	holds := func(rule Rule) func() bool {
		return func() bool {
			replies, err := conn.execute(unix.RTM_GETRULE, unix.NLM_F_DUMP, make([]byte, sizeofFibRuleHdr))
			if err != nil {
				t.Fatalf("dump rules: %v", err)
			}
			return slices.ContainsFunc(replies, func(reply netlink.Message) bool {
				got, ok := plat.decodeRule(reply)
				return ok && got == rule
			})
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("the reconciler stopped with %v", err)
		}
	})
	for _, rule := range installed {
		waitFor(t, holds(rule))
	}

	for _, rule := range installed {
		if _, err := conn.execute(unix.RTM_DELRULE, unix.NLM_F_ACK, plat.ruleMessage(rule)); err != nil {
			t.Fatalf("delete %s as networkd would: %v", rule, err)
		}
		deleted := time.Now()
		waitFor(t, holds(rule))
		if took := time.Since(deleted); took > ruleRestoreBudget {
			t.Errorf("the deleted rule %s took %s to come back, want at most %s", rule, took, ruleRestoreBudget)
		}
	}
}
