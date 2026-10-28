// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package client

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/netnstest"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/nftables"
	"ranet3.com/pkgs/ranet3/internal/packet"
	"ranet3.com/pkgs/ranet3/schema"
)

const (
	// exitBridge is the container bridge's end on the leaf, and exitContainer its end in the container's namespace
	exitBridge    = "rulb"
	exitContainer = "rulc"
	// exitLAN is the end on the leaf of a LAN it routes untranslated, and exitLANHost the LAN host's end
	exitLAN     = "rull"
	exitLANHost = "rulh"
	// exitPings is how many echo requests a forwarded flow sends, each waiting exitPingWait for its reply
	exitPings    = 3
	exitPingWait = time.Second
	// exitService is the port of the services the lab runs, on the uplink's address and on the internet host, and exitClient
	// the port their clients send from, both below rulesPortBase so the captures never read either as a probe
	exitService = 7100
	exitClient  = 7200
	// exitPingBase is the first echo identifier a forwarded flow takes, above every probe number rulesSend takes
	exitPingBase = 30000
)

// exitLabHost is the lab's addresses beside rulesHost's in one family: the bridge's end on the leaf and the container behind it,
// the LAN's end on the leaf and its host, a host of the internet beyond the far host, and a subnet the mesh routes outside the overlay
var exitLabHost = map[int]struct{ bridge, container, lan, lanHost, internet, subnet netip.Prefix }{
	4: {
		netip.MustParsePrefix("203.0.113.129/26"), netip.MustParsePrefix("203.0.113.130/26"),
		netip.MustParsePrefix("203.0.113.65/26"), netip.MustParsePrefix("203.0.113.66/26"),
		netip.MustParsePrefix("203.0.113.9/32"), netip.MustParsePrefix("203.0.113.32/27"),
	},
	6: {
		netip.MustParsePrefix("2001:db8:17::1/64"), netip.MustParsePrefix("2001:db8:17::2/64"),
		netip.MustParsePrefix("2001:db8:50::1/64"), netip.MustParsePrefix("2001:db8:50::2/64"),
		netip.MustParsePrefix("2001:db8:c::9/128"), netip.MustParsePrefix("2001:db8:300::/64"),
	},
}

// exitLab is the leaf of the rules lab beside a container behind a bridge and a LAN host, each in a namespace of its own,
// with the far host holding an address of the internet and routing the LAN and the container's network back through the leaf
type exitLab struct {
	leaf, far, container, lan *netnstest.Thread
	// probe and ping are the last probe number and echo identifier the lab took, so no capture reads one twice
	probe, ping int
}

func newExitLab(t *testing.T) *exitLab {
	t.Helper()
	lab := &exitLab{leaf: netnstest.StartThread(t), far: netnstest.StartThread(t), container: netnstest.StartThread(t), lan: netnstest.StartThread(t), ping: exitPingBase}
	rulesUplinkPair(t, lab.leaf, lab.far)
	for _, side := range []struct {
		host       *netnstest.Thread
		near, peer string
		near4      netip.Prefix
		near6      netip.Prefix
		host4      netip.Prefix
		host6      netip.Prefix
	}{
		{lab.container, exitBridge, exitContainer, exitLabHost[4].bridge, exitLabHost[6].bridge, exitLabHost[4].container, exitLabHost[6].container},
		{lab.lan, exitLAN, exitLANHost, exitLabHost[4].lan, exitLabHost[6].lan, exitLabHost[4].lanHost, exitLabHost[6].lanHost},
	} {
		if err := lab.leaf.Do(func() error {
			netlink, err := netnstest.OpenNetlink()
			if err != nil {
				return err
			}
			defer netlink.Close()
			if err := netlink.AddVeth(side.near, side.peer, 0, side.host.Path); err != nil {
				return fmt.Errorf("make the veth pair %s: %w", side.near, err)
			}
			return netlink.AddAddresses(side.near, side.near4, side.near6)
		}); err != nil {
			t.Fatal(err)
		}
		if err := side.host.Do(func() error {
			netlink, err := netnstest.OpenNetlink()
			if err != nil {
				return err
			}
			defer netlink.Close()
			if err := netlink.AddAddresses(side.peer, side.host4, side.host6); err != nil {
				return err
			}
			link, err := net.InterfaceByName(side.peer)
			if err != nil {
				return err
			}
			return errors.Join(
				netlink.RouteVia(link.Index, netip.PrefixFrom(netip.IPv4Unspecified(), 0), side.near4.Addr()),
				netlink.RouteVia(link.Index, netip.PrefixFrom(netip.IPv6Unspecified(), 0), side.near6.Addr()))
		}); err != nil {
			t.Fatalf("address the host behind %s: %v", side.near, err)
		}
	}
	if err := lab.far.Do(func() error {
		netlink, err := netnstest.OpenNetlink()
		if err != nil {
			return err
		}
		defer netlink.Close()
		if err := netlink.AddAddresses("lo", exitLabHost[4].internet, exitLabHost[6].internet); err != nil {
			return err
		}
		far, err := net.InterfaceByName(rulesFar)
		if err != nil {
			return err
		}
		var errs []error
		for _, family := range []int{4, 6} {
			for _, back := range []netip.Prefix{exitLabHost[family].lan.Masked(), exitLabHost[family].container.Masked()} {
				errs = append(errs, netlink.RouteVia(far.Index, back, rulesHost[family].uplink.Addr()))
			}
		}
		return errors.Join(errs...)
	}); err != nil {
		t.Fatalf("give the far host the internet's address and its routes back: %v", err)
	}
	return lab
}

// exitDaemon is the leaf's node and its reconciler running over the mesh's table, with the peer every learned route goes to,
// and the table and the announcements it last handed the reconciler
type exitDaemon struct {
	node      *Client
	routes    *kernel.Reconciler
	learned   *netstack.Peer
	stop      func()
	table     kernel.Table
	announced []netip.Prefix
}

// startExitDaemon starts the rules lab's node in the leaf's namespace and its reconciler in mode off, a session counting as live throughout
func startExitDaemon(t *testing.T, leaf *netnstest.Thread) *exitDaemon {
	t.Helper()
	cfg := rulesConfig(t)
	d := &exitDaemon{}
	if err := leaf.Do(func() (err error) {
		d.node, err = New(cfg, events.New())
		return err
	}); err != nil {
		t.Fatalf("start the leaf: %v", err)
	}
	d.learned = netstack.NewPeer("example/peer", func(int) (netstack.BatchSealer, error) {
		return nil, errors.New("the peer is synthetic")
	}, func([][]byte) error { return nil }, nil)
	t.Cleanup(d.learned.Close)
	for _, family := range rulesHost {
		d.node.Mesh.Routes.Set(netip.Prefix{}, family.own, netstack.Assigned)
	}
	if err := leaf.Do(func() (err error) {
		rt := d.node.KernelRuntime()
		rt.Sessions = func() int { return 1 }
		d.routes, err = kernel.New(*cfg.ReconcilerTable(), rt, d.node.Mesh.Routes)
		return err
	}); err != nil {
		t.Fatalf("build the reconciler: %v", err)
	}
	d.node.SetReconcilerNetwork(d.routes.NetworkChanged)
	ctx, cancel := context.WithCancel(context.Background())
	var runs sync.WaitGroup
	d.stop = sync.OnceFunc(func() {
		cancel()
		runs.Wait()
		d.node.Close()
	})
	t.Cleanup(d.stop)
	runs.Go(func() {
		if err := d.routes.Run(ctx); err != nil {
			t.Errorf("the reconciler: %v", err)
		}
	})
	return d
}

// mode hands the reconciler the leaf's table running cap.exit with forward, mode off where on is false, and the announcements,
// and waits for a pass that took them, since the state a wait looks for may be the one the last table left
func (d *exitDaemon) mode(t *testing.T, forward []string, on bool, announced []netip.Prefix) {
	t.Helper()
	var mode *kernel.ExitMode
	if on {
		mode = &kernel.ExitMode{Forward: forward}
	}
	d.hand(t, d.node.config().Cap.Table.WithMode(mode), announced)
}

// withoutOverlayAddress hands the reconciler the table it runs less its addresses of each of families, 4 or 6, which the reconciler
// then takes off the tun, and waits for a pass that took it
func (d *exitDaemon) withoutOverlayAddress(t *testing.T, families ...int) {
	t.Helper()
	table := d.table
	table.Addresses = slices.DeleteFunc(slices.Clone(table.Addresses), func(address schema.Prefix) bool {
		family := 6
		if address.Addr().Is4() {
			family = 4
		}
		return slices.Contains(families, family)
	})
	d.hand(t, table, d.announced)
}

// hand hands the reconciler table with the announcements and waits for a pass that took them
func (d *exitDaemon) hand(t *testing.T, table kernel.Table, announced []netip.Prefix) {
	t.Helper()
	before := d.reloaded()
	if err := d.routes.SetTable(table, d.node.config().Overlay(), announced); err != nil {
		t.Fatalf("hand the reconciler cap.table with cap.exit %+v: %v", table.Mode(), err)
	}
	d.table, d.announced = table, announced
	waitFor(t, rulesSettle, "a pass under the table the reconciler was handed", func() bool { return d.reloaded() > before })
}

// reloaded numbers the last pass the reconciler ran after taking a table it was handed, 0 before the first
func (d *exitDaemon) reloaded() uint64 { return d.lastPass("reload") }

// lastPass numbers the last pass that changed anything, woken by trigger where it is set, 0 before the first
func (d *exitDaemon) lastPass(trigger string) uint64 {
	passes := d.node.events.Recorded(func(kind, _ string, attrs []slog.Attr) bool {
		return kind == "kernel.pass" && (trigger == "" || slices.ContainsFunc(attrs, func(attr slog.Attr) bool {
			return attr.Key == "trigger" && attr.Value.String() == trigger
		}))
	}, 0)
	if len(passes) == 0 {
		return 0
	}
	return passes[len(passes)-1].Seq
}

// settled waits for the rules at 5440 to read want after the last pass woken by trigger, and fails where a later pass moved anything,
// so the rules are that pass's own
func (d *exitDaemon) settled(t *testing.T, leaf *netnstest.Thread, trigger string, want []string) {
	t.Helper()
	waitFor(t, rulesSettle, "the catch-all of the pass woken by "+trigger, func() bool {
		woken := d.lastPass(trigger)
		return woken != 0 && woken == d.lastPass("") && slices.Equal(exitRules(t, leaf, 5440), want)
	})
}

// exitRules is the rules of the reconciler's protocol the leaf holds at priority, each as its family, its source and its input link
func exitRules(t *testing.T, leaf *netnstest.Thread, priorities ...uint32) []string {
	t.Helper()
	var rules []kernelRule
	if err := leaf.Do(func() (err error) { rules, err = dumpRules(); return err }); err != nil {
		t.Fatalf("read the leaf's rules: %v", err)
	}
	var out []string
	for _, rule := range rules {
		if rule.protocol != kernel.DefaultProtocol || !slices.Contains(priorities, rule.priority) {
			continue
		}
		words := []string{fmt.Sprint(rule.priority), map[uint8]string{unix.AF_INET: "ipv4", unix.AF_INET6: "ipv6"}[rule.family]}
		if rule.source.IsValid() {
			words = append(words, "from", rule.source.String())
		}
		if rule.iif != "" {
			words = append(words, "iif", rule.iif)
		}
		out = append(out, strings.Join(words, " "))
	}
	slices.Sort(out)
	return out
}

// exitAllRules is every rule the leaf holds, as `ip rule` would list it in priority order, for the log
func exitAllRules(t *testing.T, leaf *netnstest.Thread) string {
	t.Helper()
	var rules []kernelRule
	if err := leaf.Do(func() (err error) { rules, err = dumpRules(); return err }); err != nil {
		t.Fatalf("read the leaf's rules: %v", err)
	}
	slices.SortStableFunc(rules, func(a, b kernelRule) int { return int(a.priority) - int(b.priority) })
	var lines []string
	for _, rule := range rules {
		lines = append(lines, rule.String())
	}
	return strings.Join(lines, "\n")
}

// exitPing sends exitPings echo requests from the calling thread's namespace to destination, numbered id, and counts the replies
func exitPing(destination netip.Addr, id int) (int, error) {
	family, protocol, reply := unix.AF_INET6, unix.IPPROTO_ICMPV6, byte(129)
	if destination.Is4() {
		family, protocol, reply = unix.AF_INET, unix.IPPROTO_ICMP, 0
	}
	fd, err := unix.Socket(family, unix.SOCK_RAW|unix.SOCK_CLOEXEC, protocol)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)
	timeout := unix.NsecToTimeval(exitPingWait.Nanoseconds())
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout); err != nil {
		return 0, err
	}
	received := 0
	buf := make([]byte, 1<<16)
	for sequence := range exitPings {
		message := rulesEcho(destination.Is4(), id, []byte(fmt.Sprintf("forwarded %d", sequence)))
		binary.BigEndian.PutUint16(message[6:], uint16(sequence+1))
		if destination.Is4() {
			message[2], message[3] = 0, 0
			binary.BigEndian.PutUint16(message[2:], ^uint16(packet.Sum(0, message)))
		}
		if err := unix.Sendto(fd, message, 0, rulesSockaddr(destination, 0)); err != nil {
			continue
		}
		deadline := time.Now().Add(exitPingWait)
		for time.Now().Before(deadline) {
			n, _, err := unix.Recvfrom(fd, buf, 0)
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if err != nil {
				break
			}
			body := buf[:n]
			if destination.Is4() && n >= 20 {
				body = body[int(body[0]&0x0f)*4:]
			}
			if len(body) >= 8 && body[0] == reply && int(binary.BigEndian.Uint16(body[4:])) == id {
				received++
				break
			}
		}
	}
	return received, nil
}

// exitFlow is a flow a host behind the leaf sends through it, and where its first packet has to go with how many replies come back
type exitFlow struct {
	from        string
	destination netip.Addr
	want        rulesVerdict
	replies     int
}

// exitReplies is how many replies a flow whose first packet went where want says gets: all of them out of the uplink, none elsewhere
func exitReplies(want rulesVerdict) int {
	if want == rulesOutUplink {
		return exitPings
	}
	return 0
}

// exitReply is a reply that has to come back: from the leaf's service on the uplink's address to the internet host,
// or from the internet host to the underlay's socket on the leaf, which carries the underlay's mark and the uplink's address
type exitReply struct {
	underlay    bool
	destination netip.Addr
	answered    bool
}

// exitCapture is a link the lab captures, and where a packet it sees went
type exitCapture struct {
	verdict rulesVerdict
	fd      int
}

// exitProbe sends each probe from the leaf in each of protocols, pings each flow from its host and asks each reply, then reads every
// capture: each probe and flow went where it says, a flow with the replies it says, and a container's IPv4 flow into the tun carries the
// tun's own address, which the bridge's masquerade gives it
func exitProbe(t *testing.T, lab *exitLab, captures []exitCapture, protocols []string, probes []rulesProbe, flows []exitFlow, replies []exitReply) {
	t.Helper()
	type sent struct {
		probe    rulesProbe
		protocol string
		number   int
		refused  bool
	}
	var all []sent
	var fds []int
	if err := lab.leaf.Do(func() error {
		for _, p := range probes {
			for _, protocol := range protocols {
				lab.probe++
				fd, refused, err := rulesSend(p, protocol, lab.probe)
				if err != nil {
					return fmt.Errorf("%s %s to %s: %w", p.socket, protocol, p.destination, err)
				}
				if fd >= 0 {
					fds = append(fds, fd)
				}
				all = append(all, sent{p, protocol, lab.probe, refused})
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("send the probes: %v", err)
	}
	type pinged struct {
		flow     exitFlow
		id       int
		received int
	}
	var pings []pinged
	for _, flow := range flows {
		lab.ping++
		from := map[string]*netnstest.Thread{"container": lab.container, "lan": lab.lan}[flow.from]
		var received int
		if err := from.Do(func() (err error) { received, err = exitPing(flow.destination, lab.ping); return err }); err != nil {
			t.Fatalf("ping %s from the %s: %v", flow.destination, flow.from, err)
		}
		pings = append(pings, pinged{flow, lab.ping, received})
	}
	for _, reply := range replies {
		if got := exitAnswered(t, lab, reply); got != reply.answered {
			what := "the leaf's service on the uplink's address answered the internet host"
			if reply.underlay {
				what = "the internet host answered the leaf's underlay socket"
			}
			t.Errorf("over %s, %s %v, want %v", familyName(reply.destination), what, got, reply.answered)
		}
	}
	read := make([]map[rulesKey]netip.Addr, len(captures))
	for i, capture := range captures {
		read[i] = rulesDrain(capture.fd)
	}
	for _, fd := range fds {
		_ = unix.Close(fd)
	}
	where := func(key rulesKey) (rulesVerdict, netip.Addr) {
		got, source := rulesNowhere, netip.Addr{}
		for i, capture := range captures {
			if from, ok := read[i][key]; ok {
				if got != rulesNowhere {
					return rulesSeveral, source
				}
				got, source = capture.verdict, from
			}
		}
		return got, source
	}
	for _, s := range all {
		got, source := where(rulesKey{s.protocol, s.number})
		if s.refused {
			got = rulesRefused
		}
		if got != s.probe.want {
			t.Errorf("%s from a socket %s under mark %#x to %s went %s from %s, want %s", s.protocol, s.probe.socket, s.probe.mark, s.probe.destination, got, source, s.probe.want)
		}
	}
	for _, p := range pings {
		got, source := where(rulesKey{"echo", p.id})
		if got != p.flow.want || p.received != p.flow.replies {
			t.Errorf("the %s's ping of %s went %s from %s with %d replies, want %s with %d", p.flow.from, p.flow.destination, got, source, p.received, p.flow.want, p.flow.replies)
		}
		if got == rulesIntoTun && p.flow.from == "container" && p.flow.destination.Is4() && source != rulesHost[4].own.Addr() {
			t.Errorf("the container's ping entered the tun from %s, want the tun's own address %s", source, rulesHost[4].own.Addr())
		}
	}
}

// exitLabArm is one state of the mode 2 lab
type exitLabArm struct {
	name string
	// on runs cap.exit, forwarding the links forward names
	on      bool
	forward []string
	// retracted holds the mesh's defaults unreachable, and exit makes this node an exit with another exit's halves learned
	retracted, exit bool
	// strict sets rp_filter 1 on the uplink, and fib writes NixOS's reverse path chain, "strict" or "loose"
	strict bool
	fib    string
	// unaddressed is the family, 4 or 6, whose overlay address the arm takes out of cap.table and so off the tun, none where it is 0
	unaddressed int
	// byHand takes both overlay addresses out of cap.table and puts them on the tun as another writer would
	byHand bool
	// catchAlls is the input links of the rules at 5440 the arm converges on in a family the tun holds an overlay address of
	catchAlls []string
	probes    []rulesProbe
	flows     []exitFlow
	replies   []exitReply
}

// exitLabArms are the lab's arms
func exitLabArms() []exitLabArm {
	tun, up, refused := rulesIntoTun, rulesOutUplink, rulesRefused
	internet4, internet6 := exitLabHost[4].internet.Addr().String(), exitLabHost[6].internet.Addr().String()
	modeTwo := slices.Concat(
		rulesRow(internet4, tun, tun, up, up, up), rulesRow(internet6, tun, tun, up, up, up),
		[]rulesProbe{{exitLabHost[4].internet.Addr(), rulesOnUplink, up, 0}, {exitLabHost[6].internet.Addr(), rulesOnUplink, up, 0}},
		rulesRow("192.0.2.5", tun, tun, tun, up, up), rulesRow("3fff::5", tun, tun, tun, up, up),
		rulesRow("192.0.2.77", refused, refused, refused, up, up), rulesRow("3fff::77", refused, refused, refused, up, up),
		rulesRow("203.0.113.40", tun, tun, up, up, up), rulesRow("2001:db8:300::4", tun, tun, up, up, up),
		rulesOut(rulesHost[4].lan.Addr().String()), rulesOut(rulesHost[6].lan.Addr().String()),
	)
	flows := func(container, lan rulesVerdict) []exitFlow {
		var out []exitFlow
		for _, family := range []int{4, 6} {
			out = append(out,
				exitFlow{"container", exitLabHost[family].internet.Addr(), container, exitReplies(container)},
				exitFlow{"lan", exitLabHost[family].internet.Addr(), lan, exitReplies(lan)})
		}
		return out
	}
	answered := func(services, underlay bool) []exitReply {
		var out []exitReply
		for _, family := range []int{4, 6} {
			out = append(out, exitReply{false, exitLabHost[family].internet.Addr(), services}, exitReply{true, exitLabHost[family].internet.Addr(), underlay})
		}
		return out
	}
	// the internet host from an unbound socket, connected and not, and the container's and the LAN host's pings of it, the host's own and
	// the container's into the tun in a family the tun holds an overlay address of and out of the uplink in the one it holds none of
	unbound := func(unaddressed int) ([]rulesProbe, []exitFlow) {
		var probes []rulesProbe
		var flows []exitFlow
		for _, family := range []int{4, 6} {
			want := tun
			if family == unaddressed {
				want = up
			}
			internet := exitLabHost[family].internet.Addr()
			probes = append(probes, rulesProbe{internet, rulesUnbound, want, 0}, rulesProbe{internet, rulesUnconnected, want, 0})
			flows = append(flows, exitFlow{"container", internet, want, exitReplies(want)}, exitFlow{"lan", internet, up, exitReplies(up)})
		}
		return probes, flows
	}
	lo := []string{"lo"}
	var unaddressed []exitLabArm
	for _, family := range []int{4, 6} {
		probes, flows := unbound(family)
		// with no overlay address of the family on the tun the family runs mode off's rules, so the host's own traffic to the internet
		// and the bridge's leave by the uplink, and the host's own to the mesh's subnet enters the tun in both families, connected or not,
		// with no rule at 5405 to send a connected socket's second lookup from the uplink's address by main
		for _, subnet := range []netip.Addr{netip.MustParseAddr("203.0.113.40"), netip.MustParseAddr("2001:db8:300::4")} {
			probes = append(probes, rulesProbe{subnet, rulesUnbound, tun, 0}, rulesProbe{subnet, rulesUnconnected, tun, 0})
		}
		unaddressed = append(unaddressed, exitLabArm{
			name: fmt.Sprintf("the tun holding no IPv%d overlay address", family), on: true, forward: []string{exitBridge}, unaddressed: family,
			catchAlls: []string{"lo", exitBridge}, probes: probes, flows: flows,
		})
	}
	byHand, _ := unbound(0)
	return slices.Concat([]exitLabArm{{
		// the host's own traffic follows the mesh's default from every source but the uplink's and the underlay's,
		// while a forwarded flow from a link forward leaves out keeps main's default
		name: "the mesh's defaults with nothing forwarded", on: true, catchAlls: lo,
		probes: modeTwo, flows: flows(up, up), replies: answered(true, true),
	}, {
		// forward names the bridge, whose masqueraded flow follows the mode into the tun, while the LAN's stays on main
		name: "forward naming the bridge", on: true, forward: []string{exitBridge}, catchAlls: []string{"lo", exitBridge},
		flows: flows(tun, up), replies: answered(true, true),
	}, {
		// the kernel's strict check passes the replies of both forwarded flows, the underlay's and the service's
		name: "strict rp_filter on the uplink", on: true, strict: true, catchAlls: lo,
		flows: flows(up, up), replies: answered(true, true),
	}, {
		// NixOS's strict fib chain passes them too, with 5435 for the bridge's and the LAN's networks and 5405 for the uplink's address
		name: "NixOS's strict fib chain", on: true, fib: "strict", catchAlls: lo,
		flows: flows(up, up), replies: answered(true, true),
	}, {
		name: "NixOS's loose fib chain", on: true, fib: "loose", catchAlls: lo,
		flows: flows(up, up), replies: answered(true, true),
	}, {
		// with the mesh's defaults retracted the host's own traffic leaves by main from every source, as "uplink" says
		name: "the mesh's defaults retracted", on: true, retracted: true, strict: true, fib: "strict", catchAlls: lo,
		probes: slices.Concat(rulesOut(internet4), rulesOut(internet6),
			rulesRow("192.0.2.5", tun, tun, tun, up, up), rulesRow("3fff::5", tun, tun, tun, up, up)),
		flows: flows(up, up), replies: answered(true, true),
	}, {
		// an exit withholds every route that counts as a default, so mode 2's catch-all finds none and its own traffic leaves by its uplink
		name: "an exit with another exit's halves", on: true, exit: true, catchAlls: lo,
		probes: slices.Concat(rulesOut(internet4), rulesOut(internet6),
			rulesRow("192.0.2.5", tun, tun, tun, up, up), rulesRow("3fff::5", tun, tun, tun, up, up)),
		flows: flows(up, up), replies: answered(true, true),
	}}, unaddressed, []exitLabArm{{
		// another writer's overlay addresses on the tun, cap.table writing none, address both families, so the host's own traffic,
		// connected or not, follows the mode into the tun from them
		name: "another writer's overlay addresses on the tun", on: true, byHand: true, catchAlls: lo,
		probes: byHand,
	}})
}

// each arm probes after a pass under its own table, and a clean stop leaves no rule or route of the reconciler's protocol
func TestTUNExitModeSendsEachSocketWhereModeTwoSays(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("creating a tun needs root on linux")
	}
	lab := newExitLab(t)
	d := startExitDaemon(t, lab.leaf)
	masqueradeBridge(t, lab.leaf)
	var tunCapture, farCapture int
	if err := errors.Join(
		lab.leaf.Do(func() (err error) { tunCapture, err = openCapture(rulesTUN, labRetry); return err }),
		lab.far.Do(func() (err error) { farCapture, err = openCapture(rulesFar, labRetry); return err }),
	); err != nil {
		t.Fatalf("capture the tun and the far end of the uplink: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(tunCapture); _ = unix.Close(farCapture) })

	for _, arm := range exitLabArms() {
		t.Run(arm.name, func(t *testing.T) {
			entries := map[string]*netstack.Peer{
				"192.0.2.5/32": d.learned, "3fff::5/128": d.learned,
				exitLabHost[4].subnet.String(): d.learned, exitLabHost[6].subnet.String(): d.learned,
				"0.0.0.0/0": d.learned, "::/0": d.learned,
			}
			var announced []netip.Prefix
			switch {
			case arm.retracted:
				entries["0.0.0.0/0"], entries["::/0"] = netstack.Unreachable, netstack.Unreachable
			case arm.exit:
				entries["0.0.0.0/0"], entries["::/0"] = netstack.Local, netstack.Local
				for _, half := range []string{"0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"} {
					entries[half] = d.learned
				}
				announced = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}
			}
			for prefix, value := range entries {
				d.node.Mesh.Routes.Set(netip.Prefix{}, netip.MustParsePrefix(prefix), value)
			}
			t.Cleanup(func() {
				for prefix := range entries {
					d.node.Mesh.Routes.Remove(netip.Prefix{}, netip.MustParsePrefix(prefix))
				}
			})
			if arm.strict {
				exitStrict(t, lab.leaf, "1")
				t.Cleanup(func() { exitStrict(t, lab.leaf, "0") })
			}
			if arm.fib != "" {
				reverseFib(t, lab.leaf, arm.fib == "strict")
				t.Cleanup(func() { reverseFibRemove(t, lab.leaf) })
			}
			d.mode(t, arm.forward, arm.on, announced)
			// catchAll is the arm's rules at 5440 with none in each family of unaddressed
			catchAll := func(unaddressed ...int) []string {
				var want []string
				for _, family := range []int{4, 6} {
					for _, link := range arm.catchAlls {
						if !slices.Contains(unaddressed, family) {
							want = append(want, fmt.Sprintf("5440 ipv%d iif %s", family, link))
						}
					}
				}
				slices.Sort(want)
				return want
			}
			waitFor(t, rulesSettle, "the reconciler to install the arm's catch-all and its routes", func() bool {
				return slices.Equal(exitRules(t, lab.leaf, 5440), catchAll()) && exitDefaults(t, lab.leaf, !arm.retracted && !arm.exit)
			})
			switch {
			case arm.unaddressed != 0:
				d.withoutOverlayAddress(t, arm.unaddressed)
				d.settled(t, lab.leaf, "reload", catchAll(arm.unaddressed))
			case arm.byHand:
				d.withoutOverlayAddress(t, 4, 6)
				d.settled(t, lab.leaf, "reload", catchAll(4, 6))
				exitByHand(t, lab.leaf)
				d.settled(t, lab.leaf, "kernel", catchAll())
			}
			waitFor(t, rulesSettle, "the mesh's defaults", func() bool { return exitDefaults(t, lab.leaf, !arm.retracted && !arm.exit) })
			t.Logf("the leaf holds the rules\n%s", exitAllRules(t, lab.leaf))
			if status := d.routes.Stats().Exit; status != nil {
				t.Logf("the exit status reads %+v", *status)
			}

			exitProbe(t, lab, []exitCapture{{rulesIntoTun, tunCapture}, {rulesOutUplink, farCapture}}, []string{"udp", "tcp", "echo"}, arm.probes, arm.flows, arm.replies)
		})
	}

	t.Run("a clean stop", func(t *testing.T) {
		d.stop()
		var rules []kernelRule
		var left []kernelRoute
		if err := lab.leaf.Do(func() (err error) {
			if rules, err = dumpRules(); err != nil {
				return err
			}
			left, err = dumpRoutes()
			return err
		}); err != nil {
			t.Fatalf("read the leaf back: %v", err)
		}
		for _, rule := range rules {
			if rule.protocol == kernel.DefaultProtocol {
				t.Errorf("the stop left the rule %s", rule)
			}
		}
		for _, route := range left {
			if route.protocol == kernel.DefaultProtocol {
				t.Errorf("the stop left the route %s", route)
			}
		}
	})
}

func familyName(address netip.Addr) string {
	if address.Is4() {
		return "IPv4"
	}
	return "IPv6"
}

// exitDefaults reports whether the mesh's table holds a default of each family where live says, and of neither where it does
// not, so a wait for the defaults retracted ends only once both families are
func exitDefaults(t *testing.T, leaf *netnstest.Thread, live bool) bool {
	t.Helper()
	var routes []kernelRoute
	if err := leaf.Do(func() (err error) { routes, err = dumpRoutes(); return err }); err != nil {
		t.Fatalf("read the leaf's routes: %v", err)
	}
	held := 0
	for _, route := range routes {
		if route.table == kernel.DefaultTable && route.protocol == kernel.DefaultProtocol && route.kind == unix.RTN_UNICAST && route.destination.Bits() == 0 {
			held++
		}
	}
	if live {
		return held == 2
	}
	return held == 0
}

// exitByHand puts the leaf's overlay address of each family on the tun as another writer would, and takes them off when t ends
func exitByHand(t *testing.T, leaf *netnstest.Thread) {
	t.Helper()
	addresses := []netip.Prefix{rulesHost[4].own, rulesHost[6].own}
	edit := func(add bool) error {
		netlink, err := netnstest.OpenNetlink()
		if err != nil {
			return err
		}
		defer netlink.Close()
		if add {
			return netlink.AddAddresses(rulesTUN, addresses...)
		}
		link, err := net.InterfaceByName(rulesTUN)
		if err != nil {
			return err
		}
		var errs []error
		for _, address := range addresses {
			errs = append(errs, netlink.DelAddress(link.Index, address))
		}
		return errors.Join(errs...)
	}
	if err := leaf.Do(func() error { return edit(true) }); err != nil {
		t.Fatalf("put the overlay addresses on the tun by hand: %v", err)
	}
	t.Cleanup(func() {
		if err := leaf.Do(func() error { return edit(false) }); err != nil {
			t.Errorf("take the overlay addresses put on by hand off the tun: %v", err)
		}
	})
}

// exitStrict sets rp_filter on every link and on the uplink, the kernel taking the larger of the two
func exitStrict(t *testing.T, leaf *netnstest.Thread, value string) {
	t.Helper()
	if err := leaf.Do(func() error {
		return errors.Join(
			os.WriteFile("/proc/sys/net/ipv4/conf/all/rp_filter", []byte(value+"\n"), 0o644),
			os.WriteFile("/proc/sys/net/ipv4/conf/"+rulesUplink+"/rp_filter", []byte(value+"\n"), 0o644))
	}); err != nil {
		t.Fatalf("set rp_filter %s: %v", value, err)
	}
}

// bridgeMasquerade is Docker's masquerade of the bridge's network leaving by any other link, in both families
var bridgeMasquerade = nftables.Chain{Table: "exitlab", Name: "post", Type: "nat", Hook: unix.NF_INET_POST_ROUTING, Priority: 100}

func masqueradeBridge(t *testing.T, leaf *netnstest.Thread) {
	t.Helper()
	if err := leaf.Do(func() error {
		conn, err := nftables.Dial()
		if err != nil {
			return err
		}
		defer conn.Close()
		requests := []nftables.Request{nftables.NewTable(unix.NFPROTO_INET, bridgeMasquerade.Table), bridgeMasquerade.Create(unix.NFPROTO_INET)}
		for _, family := range []int{4, 6} {
			network := exitLabHost[family].container.Masked()
			proto := uint8(unix.NFPROTO_IPV6)
			if family == 4 {
				proto = unix.NFPROTO_IPV4
			}
			rule, err := bridgeMasquerade.Rule(unix.NFPROTO_INET, fmt.Sprintf("saddr %s oifname != %s masquerade", network, exitBridge), slices.Concat(
				nftables.MetaCompareValue(unix.NFT_META_NFPROTO, unix.NFT_CMP_EQ, []byte{proto}),
				nftables.SourcePrefix(network),
				nftables.MetaCompare(unix.NFT_META_OIFNAME, unix.NFT_CMP_NEQ, exitBridge),
				[][]byte{nftables.Expression("masq", nil)}))
			if err != nil {
				return err
			}
			requests = append(requests, rule)
		}
		return conn.Batch(requests)
	}); err != nil {
		t.Fatalf("write the bridge's masquerade: %v", err)
	}
}

// reverseFibChain is NixOS's reverse path chain at prerouting, as its firewall writes it with networking.firewall.checkReversePath
var reverseFibChain = nftables.Chain{Table: "exitfib", Name: "rpfilter", Type: "filter", Hook: unix.NF_INET_PRE_ROUTING, Priority: -150 + 10}

// reverseFib writes reverseFibChain, `fib saddr . mark . iif oif exists accept` when strict and `fib saddr . mark oif exists accept` when loose,
// then a counted drop of each family, which stands for the chain's policy drop
func reverseFib(t *testing.T, leaf *netnstest.Thread, strict bool) {
	t.Helper()
	flags := uint32(unix.NFTA_FIB_F_SADDR | unix.NFTA_FIB_F_MARK | unix.NFTA_FIB_F_PRESENT)
	spec := "fib saddr . mark oif exists accept"
	if strict {
		flags |= unix.NFTA_FIB_F_IIF
		spec = "fib saddr . mark . iif oif exists accept"
	}
	fib := nftables.PutAttrBE32(nil, unix.NFTA_FIB_DREG, unix.NFT_REG_1)
	fib = nftables.PutAttrBE32(fib, unix.NFTA_FIB_RESULT, unix.NFT_FIB_RESULT_OIF)
	fib = nftables.PutAttrBE32(fib, unix.NFTA_FIB_FLAGS, flags)
	if err := leaf.Do(func() error {
		conn, err := nftables.Dial()
		if err != nil {
			return err
		}
		defer conn.Close()
		accept, err := reverseFibChain.Rule(unix.NFPROTO_INET, spec, [][]byte{
			nftables.Expression("fib", fib), nftables.Expression("cmp", nftables.Compare(unix.NFT_CMP_EQ, []byte{1})), labVerdict(nftables.Accept),
		})
		if err != nil {
			return err
		}
		requests := []nftables.Request{nftables.NewTable(unix.NFPROTO_INET, reverseFibChain.Table), reverseFibChain.Create(unix.NFPROTO_INET), accept}
		for _, proto := range []uint8{unix.NFPROTO_IPV4, unix.NFPROTO_IPV6} {
			drop, err := reverseFibChain.Rule(unix.NFPROTO_INET, fmt.Sprintf("meta nfproto %d counter drop", proto), slices.Concat(
				nftables.MetaCompareValue(unix.NFT_META_NFPROTO, unix.NFT_CMP_EQ, []byte{proto}),
				[][]byte{nftables.Expression("counter", nil), labVerdict(labDrop)}))
			if err != nil {
				return err
			}
			requests = append(requests, drop)
		}
		return conn.Batch(requests)
	}); err != nil {
		t.Fatalf("write NixOS's reverse path chain: %v", err)
	}
}

func reverseFibRemove(t *testing.T, leaf *netnstest.Thread) {
	t.Helper()
	if err := leaf.Do(func() error {
		conn, err := nftables.Dial()
		if err != nil {
			return err
		}
		defer conn.Close()
		return conn.Batch([]nftables.Request{nftables.DeleteTable(unix.NFPROTO_INET, reverseFibChain.Table)})
	}); err != nil {
		t.Fatalf("remove NixOS's reverse path chain: %v", err)
	}
}

// labDrop is NF_DROP of linux/netfilter.h, which x/sys does not carry
const labDrop = 0

// labVerdict ends a lab chain for a packet with code, nftables.Accept or labDrop
func labVerdict(code uint32) []byte {
	data := nftables.PutAttr(nil, unix.NFTA_DATA_VERDICT|unix.NLA_F_NESTED, nftables.PutAttrBE32(nil, unix.NFTA_VERDICT_CODE, code))
	immediate := nftables.PutAttrBE32(nil, unix.NFTA_IMMEDIATE_DREG, unix.NFT_REG_VERDICT)
	immediate = nftables.PutAttr(immediate, unix.NFTA_IMMEDIATE_DATA|unix.NLA_F_NESTED, data)
	return nftables.Expression("immediate", immediate)
}

// exitAnswered reports whether a datagram is answered: the internet host's to the leaf's service on the uplink's address,
// or the leaf's underlay socket's, carrying the underlay's mark from the uplink's address, to the internet host's service
func exitAnswered(t *testing.T, lab *exitLab, reply exitReply) bool {
	t.Helper()
	family := 6
	if reply.destination.Is4() {
		family = 4
	}
	uplink := rulesHost[family].uplink.Addr()
	server, client := lab.leaf, lab.far
	serverAt, clientAt, mark := uplink, reply.destination, 0
	if reply.underlay {
		server, client = lab.far, lab.leaf
		serverAt, clientAt, mark = reply.destination, uplink, int(schema.UnderlayMark)
	}
	var listen, send int
	if err := errors.Join(
		server.Do(func() (err error) { listen, err = exitSocket(serverAt, exitService, 0); return err }),
		client.Do(func() (err error) { send, err = exitSocket(clientAt, exitClient, mark); return err }),
	); err != nil {
		t.Fatalf("open the service and its client over %s: %v", familyName(reply.destination), err)
	}
	defer unix.Close(listen)
	defer unix.Close(send)
	served := make(chan error, 1)
	go func() {
		buf := make([]byte, 1500)
		n, from, err := unix.Recvfrom(listen, buf, 0)
		if err == nil {
			err = unix.Sendto(listen, buf[:n], 0, from)
		}
		served <- err
	}()
	if err := unix.Sendto(send, []byte("asked"), 0, rulesSockaddr(serverAt, exitService)); err != nil {
		t.Fatalf("ask the service at %s: %v", serverAt, err)
	}
	buf := make([]byte, 1500)
	_, _, err := unix.Recvfrom(send, buf, 0)
	<-served
	return err == nil
}

// exitSocket opens a UDP socket of address's family in the calling thread's namespace, bound to address and port, carrying mark where it is not zero,
// each read waiting exitPingWait
func exitSocket(address netip.Addr, port, mark int) (int, error) {
	family := unix.AF_INET6
	if address.Is4() {
		family = unix.AF_INET
	}
	fd, err := unix.Socket(family, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	timeout := unix.NsecToTimeval(exitPingWait.Nanoseconds())
	err = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout)
	if mark != 0 && err == nil {
		err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, mark)
	}
	if err == nil {
		err = unix.Bind(fd, rulesSockaddr(address, port))
	}
	if err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}
