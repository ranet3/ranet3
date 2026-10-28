// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package client

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/netnstest"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/nftables"
	"ranet3.com/pkgs/ranet3/schema"
)

const (
	// switchUnlisted is a port of a service on the uplink's address that inbound leaves out, and switchSilent a listed port
	// no service listens on, beside exitService, which the arms list
	switchUnlisted = exitService + 1
	switchSilent   = exitService + 2
	// switchOtherMark is the mark other programs' chains set and route by main, as the probe's arms set 0x10
	switchOtherMark = 0x10
	// switchOtherPriority is the priority of the other program's rule looking up main for switchOtherMark
	switchOtherPriority = 100
)

// switchOwn is the prefix of each family this node announces outside the overlay, which the mesh's table throws and 5445 sends to main
var switchOwn = map[int]netip.Prefix{4: netip.MustParsePrefix("203.0.113.240/28"), 6: netip.MustParsePrefix("2001:db8:f0::/48")}

// switchState is the state of the mesh an arm runs the switch in
type switchState string

const (
	switchPresent   switchState = "the mesh's defaults present"
	switchRetracted switchState = "the mesh's defaults retracted"
	// switchCrashed is the switch a helper process wrote with the defaults present, after kill -9 of the helper took the tun with it
	switchCrashed switchState = "after kill -9"
)

// switchStates is each state in the order a lab runs them, the crash last, since it stops the lab's own node
var switchStates = []switchState{switchPresent, switchRetracted, switchCrashed}

// switchWant is where a probe's first packet has to go
type switchWant string

const (
	switchOut  switchWant = "out of the uplink"
	switchTun  switchWant = "into the tun and not out of the uplink"
	switchHeld switchWant = "neither out of the uplink nor into the tun"
	switchKept switchWant = "not out of the uplink"
	// switchRefused is switchHeld by a send its route refused, 5450's ENETUNREACH, where the filter's drop meets EPERM or none
	switchRefused switchWant = "refused by its route, neither out of the uplink nor into the tun"
)

// switchProbe is the first packet of each of protocols that the socket rulesProbe opens sends to its destination, and where it has
// to go, its rulesProbe's own verdict unused
type switchProbe struct {
	rulesProbe
	want      switchWant
	protocols []string
}

// switchFrom is a probe of destination from socket carrying mark, none for 0, wanting want, of protocols or of UDP, TCP and echo
func switchFrom(destination netip.Addr, socket rulesSocket, mark uint32, want switchWant, protocols ...string) switchProbe {
	return switchProbe{rulesProbe{destination: destination, socket: socket, mark: mark}, want, protocols}
}

// switchRow is a probe of destination from the six sockets, unbound, from the overlay address, from the uplink's address,
// on the uplink's device, marked, and marked from the overlay address, wanting in turn
func switchRow(destination netip.Addr, wants ...switchWant) []switchProbe {
	sockets := []struct {
		socket rulesSocket
		mark   uint32
	}{{rulesUnbound, 0}, {rulesFromOverlay, 0}, {rulesFromUplink, 0}, {rulesOnUplink, 0}, {rulesUnbound, schema.UnderlayMark}, {rulesFromOverlay, schema.UnderlayMark}}
	var out []switchProbe
	for i, want := range wants {
		out = append(out, switchFrom(destination, sockets[i].socket, sockets[i].mark, want))
	}
	return out
}

// switchAddresses is the destinations of one family the probes go to: the internet host, a peer and an address the overlay holds unreachable,
// a subnet the mesh routes outside the overlay, the LAN beside the uplink, and an address in this node's own prefix beyond the gateway
type switchAddresses struct{ internet, peer, held, subnet, lan, own netip.Addr }

func switchAt(family int) switchAddresses {
	if family == 4 {
		return switchAddresses{exitLabHost[4].internet.Addr(), netip.MustParseAddr("192.0.2.5"), netip.MustParseAddr("192.0.2.77"),
			netip.MustParseAddr("203.0.113.40"), rulesHost[4].lan.Addr(), switchOwn[4].Addr().Next()}
	}
	return switchAddresses{exitLabHost[6].internet.Addr(), netip.MustParseAddr("3fff::5"), netip.MustParseAddr("3fff::77"),
		netip.MustParseAddr("2001:db8:300::4"), rulesHost[6].lan.Addr(), switchOwn[6].Addr().Next()}
}

// switchSocketProbes is every socket's probe of every destination in state: what the mode sends into the tun goes there while the
// defaults are present and while they are retracted but for the internet, and nowhere once the tun is gone, the LAN and the own
// prefix leave by the uplink from every socket, the underlay's mark leaves by it to every destination, and nothing else leaves by it
func switchSocketProbes(state switchState) []switchProbe {
	out, tun, held := switchOut, switchTun, switchHeld
	if state == switchCrashed {
		tun = held
	}
	internet := tun
	if state != switchPresent {
		internet = held
	}
	var probes []switchProbe
	for _, family := range []int{4, 6} {
		at := switchAt(family)
		probes = slices.Concat(probes,
			switchRow(at.internet, internet, internet, held, held, out, out),
			switchRow(at.peer, tun, tun, tun, held, out, out),
			switchRow(at.held, held, held, held, held, out, out),
			switchRow(at.subnet, tun, tun, held, held, out, out),
			switchRow(at.lan, out, out, out, out, out, out),
			switchRow(at.own, out, out, out, out, out, out))
	}
	return probes
}

// switchUnaddressedProbes is switchSocketProbes with the tun holding no IPv4 overlay address, so IPv4 runs mode off's rules with
// 5445 and 5450: 5450 refuses the internet to an unbound socket and one bound to the uplink's address in every state, the mesh's
// subnet enters the tun from both while the tun lives with no 5405 to send the second by main, the LAN and the own prefix leave by
// the uplink, and IPv6 goes as switchSocketProbes says
func switchUnaddressedProbes(state switchState) []switchProbe {
	out, tun, held, refused := switchOut, switchTun, switchHeld, switchRefused
	if state == switchCrashed {
		tun = held
	}
	at := switchAt(4)
	return slices.Concat(
		switchRow(at.internet, refused, held, refused, held, out, out),
		switchRow(at.peer, tun, tun, tun, held, out, out),
		switchRow(at.held, held, held, held, held, out, out),
		switchRow(at.subnet, tun, tun, tun, held, out, out),
		switchRow(at.lan, out, out, out, out, out, out),
		switchRow(at.own, out, out, out, out, out, out),
		slices.DeleteFunc(switchSocketProbes(state), func(p switchProbe) bool { return p.destination.Is4() }))
}

// switchTableOwner is NFT_TABLE_F_OWNER of linux/netfilter/nf_tables.h, which x/sys does not carry
const switchTableOwner = 0x2

// notHolding takes the table under a socket of the test's own, owned, so the reconciler can neither write nor read it back, and
// while the switch reads not holding sends the internet host the host's own unbound and uplink-bound probes and the forwarded
// pings of an arm forwarding the bridge in state, the tun holding no IPv4 overlay address: 5450 refuses each in IPv4, and in
// IPv6 5440 takes it into the tun while the defaults are present and 5450 refuses it once they are retracted. Then it lets the
// table go and waits for the switch to read want again.
func (lab *switchLab) notHolding(t *testing.T, state switchState, want kernel.FallbackState) {
	t.Helper()
	var holder *nftables.Conn
	if err := lab.leaf.Do(func() (err error) {
		if holder, err = nftables.Dial(); err != nil {
			return err
		}
		owned := nftables.Request{Kind: nftables.Command(unix.NFT_MSG_NEWTABLE), Flags: unix.NLM_F_CREATE,
			Body: nftables.PutAttrBE32(nftables.PutAttrString(nftables.PutNfgenmsg(nil, unix.NFPROTO_INET), unix.NFTA_TABLE_NAME, kernel.FallbackTable), unix.NFTA_TABLE_FLAGS, switchTableOwner)}
		return holder.Batch([]nftables.Request{nftables.DeleteTable(unix.NFPROTO_INET, kernel.FallbackTable), owned})
	}); err != nil {
		t.Fatalf("take the table under another writer's socket: %v", err)
	}
	released := false
	release := func() {
		if !released {
			released = true
			_ = holder.Close()
		}
	}
	t.Cleanup(release)
	waitFor(t, rulesSettle, "the switch to read not holding", func() bool { return lab.switchStatus() == string(kernel.FallbackNotHolding) })
	t.Logf("with the table held by another writer the leaf holds the rules\n%s", exitAllRules(t, lab.leaf))
	internet6 := switchTun
	if state != switchPresent {
		internet6 = switchRefused
	}
	var probes []switchProbe
	for family, want := range map[int]switchWant{4: switchRefused, 6: internet6} {
		internet := switchAt(family).internet
		probes = append(probes, switchFrom(internet, rulesUnbound, 0, want), switchFrom(internet, rulesFromUplink, 0, want))
	}
	container6 := switchFlow{"container", exitLabHost[6].internet.Addr(), switchTun, 0}
	if state != switchPresent {
		container6.want = switchHeld
	}
	lab.exercise(t, switchArm{state: state, forward: []string{exitBridge}, unaddressed: 4, probes: probes, flows: []switchFlow{
		{"container", exitLabHost[4].internet.Addr(), switchHeld, 0}, container6,
		{"lan", exitLabHost[4].internet.Addr(), switchOut, exitPings}, {"lan", exitLabHost[6].internet.Addr(), switchOut, exitPings},
	}})
	release()
	waitFor(t, rulesSettle, "the switch to read "+string(want)+" again", func() bool { return lab.switchStatus() == string(want) })
}

// switchFlow is a ping a host behind the leaf sends to the internet host, where it has to go and how many replies come back
type switchFlow struct {
	from        string
	destination netip.Addr
	want        switchWant
	replies     int
}

// switchArm is one arm of a kill switch lab: the state, cap.exit's forward and inbound, another program's chains and rules
// written before the switch, and what the arm sends
type switchArm struct {
	name    string
	state   switchState
	forward []string
	inbound []string
	// unaddressed is the family, 4 or 6, whose overlay address the arm takes out of cap.table and so off the tun, none where it is 0
	unaddressed int
	// other writes another program's chains and rules in the leaf's namespace and answers how to remove them
	other func(t *testing.T, leaf *netnstest.Thread) func()
	// underlayCut is an arm whose chains take the underlay's mark off ranet3's own packets, so its probes carrying it go nowhere by the uplink
	underlayCut bool
	probes      []switchProbe
	flows       []switchFlow
	replies     []exitReply
	// usability sends the neighbor and router solicitations, DHCP and multicast, which leave by the uplink in every state
	usability bool
	// services is the far host's asks of the leaf's services on the uplink's address
	services []switchService
	// pinned sends each probe from the CPU cpu
	pinned bool
	cpu    int
}

// switchLab is the exit lab's leaf in mode 2 with its captures of the tun and of the far end of the uplink
type switchLab struct {
	*exitLab
	d                      *exitDaemon
	tunCapture, farCapture int
	probe, ping            int
}

func newSwitchLab(t *testing.T) *switchLab {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("creating a tun needs root on linux")
	}
	lab := &switchLab{exitLab: newExitLab(t), ping: exitPingBase}
	lab.d = startExitDaemon(t, lab.leaf)
	masqueradeBridge(t, lab.leaf)
	if err := errors.Join(
		lab.leaf.Do(func() (err error) { lab.tunCapture, err = openCapture(rulesTUN, labRetry); return err }),
		lab.far.Do(func() (err error) { lab.farCapture, err = openCapture(rulesFar, labRetry); return err }),
	); err != nil {
		t.Fatalf("capture the tun and the far end of the uplink: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(lab.tunCapture); _ = unix.Close(lab.farCapture) })
	// an arm sends its every probe before a capture is read, and the far end's default receive buffer drops some of them on an
	// arm with many, so each capture holds an arm's worth
	for _, capture := range []int{lab.tunCapture, lab.farCapture} {
		if err := unix.SetsockoptInt(capture, unix.SOL_SOCKET, unix.SO_RCVBUF, 8<<20); err != nil {
			t.Fatalf("size the capture's receive buffer: %v", err)
		}
	}
	return lab
}

// switchStatus is the switch's state as the reconciler's status names it, "off" where it names none
func (lab *switchLab) switchStatus() string {
	exit := lab.d.routes.Stats().Exit
	if exit == nil || exit.Fallback == nil {
		return "off"
	}
	return string(exit.Fallback.State)
}

// switchEntries gives d's mesh a peer inside the overlay, a subnet outside it, the defaults learned or, retracted, held unreachable,
// and this node's own prefix, and answers the prefixes it set
func switchEntries(d *exitDaemon, state switchState) []netip.Prefix {
	entries := map[string]*netstack.Peer{
		"192.0.2.5/32": d.learned, "3fff::5/128": d.learned,
		exitLabHost[4].subnet.String(): d.learned, exitLabHost[6].subnet.String(): d.learned,
		"0.0.0.0/0": d.learned, "::/0": d.learned,
		switchOwn[4].String(): netstack.Local, switchOwn[6].String(): netstack.Local,
	}
	if state == switchRetracted {
		entries["0.0.0.0/0"], entries["::/0"] = netstack.Unreachable, netstack.Unreachable
	}
	var out []netip.Prefix
	for prefix, value := range entries {
		d.node.Mesh.Routes.Set(netip.Prefix{}, netip.MustParsePrefix(prefix), value)
		out = append(out, netip.MustParsePrefix(prefix))
	}
	return out
}

// switchMode hands d's reconciler cap.exit with fallback = "none", forward and inbound, and cap.table less its addresses of the
// family unaddressed, 4 or 6, where it is not 0
func switchMode(t *testing.T, d *exitDaemon, forward, inbound []string, unaddressed int) {
	t.Helper()
	cfg := d.node.config()
	table := cfg.Cap.Table.WithMode(&kernel.ExitMode{Forward: forward, Fallback: kernel.FallbackNone, Inbound: inbound})
	table.Addresses = slices.DeleteFunc(slices.Clone(table.Addresses), func(address schema.Prefix) bool {
		return address.Addr().Is4() && unaddressed == 4 || address.Addr().Is6() && unaddressed == 6
	})
	if err := d.routes.SetTable(table, cfg.Overlay(), nil); err != nil {
		t.Fatalf("hand the reconciler cap.exit with fallback none: %v", err)
	}
}

// switchCatchAlls is the rules at 5440 for the host's own traffic and each link forward names, sorted, of both families but the
// one unaddressed names
func switchCatchAlls(forward []string, unaddressed int) []string {
	var want []string
	for family, name := range map[int]string{4: "ipv4", 6: "ipv6"} {
		if family == unaddressed {
			continue
		}
		for _, link := range append([]string{"lo"}, forward...) {
			want = append(want, "5440 "+name+" iif "+link)
		}
	}
	slices.Sort(want)
	return want
}

// settle installs the arm's routes and mode and waits until the leaf holds the catch-alls, the defaults the state says, and the switch
// passing while they are present and holding while they are retracted. After kill -9 the crash helper installs them instead.
func (lab *switchLab) settle(t *testing.T, arm switchArm) {
	t.Helper()
	if arm.state == switchCrashed {
		lab.crash(t, arm)
		return
	}
	d := lab.d
	entries := switchEntries(d, arm.state)
	t.Cleanup(func() {
		for _, prefix := range entries {
			d.node.Mesh.Routes.Remove(netip.Prefix{}, prefix)
		}
	})
	switchMode(t, d, arm.forward, arm.inbound, arm.unaddressed)
	state := string(kernel.FallbackPassing)
	if arm.state == switchRetracted {
		state = string(kernel.FallbackHolding)
	}
	waitFor(t, rulesSettle, "the reconciler to install the arm's rules, its routes and the switch "+state, func() bool {
		return slices.Equal(exitRules(t, lab.leaf, 5440), switchCatchAlls(arm.forward, arm.unaddressed)) && exitDefaults(t, lab.leaf, arm.state == switchPresent) && lab.switchStatus() == state
	})
	t.Logf("the leaf holds the rules\n%s", exitAllRules(t, lab.leaf))
}

// switchHelperArm names, in the crash helper's environment, the arm it runs as JSON
const switchHelperArm = "RANET3_SWITCH_LAB_ARM"

// switchHelped holds the kill switch crash helper's cap.exit forward and inbound, the family it takes the tun's overlay address of,
// and the file it writes once its switch passes
type switchHelped struct {
	Forward, Inbound []string
	Unaddressed      int
	Ready            string
}

// crash stops the lab's own node, runs the arm's node and reconciler in a helper process with the defaults present until the switch
// passes, kills the helper with SIGKILL and waits for the tun to go with it, leaving what the helper wrote
func (lab *switchLab) crash(t *testing.T, arm switchArm) {
	t.Helper()
	lab.d.stop()
	helped := switchHelped{Forward: arm.forward, Inbound: arm.inbound, Unaddressed: arm.unaddressed, Ready: filepath.Join(t.TempDir(), "ready")}
	encoded, err := json.Marshal(helped)
	if err != nil {
		t.Fatal(err)
	}
	kill := startExitHelper(t, lab.leaf, "TestKillSwitchLabCrashHelper", switchHelperArm+"="+string(encoded))
	waitFor(t, rulesSettle, "the crash helper's switch to pass", func() bool {
		_, err := os.Stat(helped.Ready)
		return err == nil && slices.Equal(exitRules(t, lab.leaf, 5440), switchCatchAlls(arm.forward, arm.unaddressed)) && exitDefaults(t, lab.leaf, true)
	})
	t.Logf("the leaf holds the rules\n%s", exitAllRules(t, lab.leaf))
	kill()
	waitFor(t, rulesSettle, "the tun to go with the helper", func() bool { return !besideHasTun(t, lab.leaf) })
	var held kernel.FallbackDebug
	if err := lab.leaf.Do(func() (err error) { held, err = kernel.ReadFallback(); return err }); err != nil {
		t.Fatalf("read the table back: %v", err)
	}
	if !held.Held {
		t.Errorf("the table %s went with the helper", kernel.FallbackTable)
	}
}

// the kill switch's crash helper, which runs the leaf's node and its reconciler in mode 2 with fallback = "none" and the mesh's defaults
// learned, in the namespace exitHelperNamespace names and as switchHelperArm says, until it is killed
func TestKillSwitchLabCrashHelper(t *testing.T) {
	path, arm := os.Getenv(exitHelperNamespace), os.Getenv(switchHelperArm)
	if path == "" || arm == "" {
		t.Skip("the kill switch's labs run the crash helper in a process of its own")
	}
	var helped switchHelped
	if err := json.Unmarshal([]byte(arm), &helped); err != nil {
		t.Fatal(err)
	}
	d := startExitDaemon(t, netnstest.JoinThread(t, path))
	switchEntries(d, switchPresent)
	switchMode(t, d, helped.Forward, helped.Inbound, helped.Unaddressed)
	waitFor(t, rulesSettle, "the switch to pass", func() bool {
		exit := d.routes.Stats().Exit
		return exit != nil && exit.Fallback != nil && exit.Fallback.State == kernel.FallbackPassing
	})
	if err := os.WriteFile(helped.Ready, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, os.Stdin)
}

// run runs one arm: its state, its other program, then its probes, flows, replies and asks, and checks where each went
func (lab *switchLab) run(t *testing.T, arm switchArm) {
	t.Helper()
	lab.settle(t, arm)
	if arm.other != nil {
		t.Cleanup(arm.other(t, lab.leaf))
	}
	lab.exercise(t, arm)
}

// exercise sends the arm's probes, flows, replies and asks over the leaf as it stands, and checks where each went. After kill -9, and
// in the family the arm takes the tun's overlay address of, it leaves out the probes from a socket bound to that address, which the
// tun no longer holds.
func (lab *switchLab) exercise(t *testing.T, arm switchArm) {
	t.Helper()
	rulesDrain(lab.tunCapture)
	rulesDrain(lab.farCapture)
	probes := slices.DeleteFunc(slices.Clone(arm.probes), func(p switchProbe) bool {
		return p.socket == rulesFromOverlay && (arm.state == switchCrashed || arm.unaddressed == 4 && p.destination.Is4() || arm.unaddressed == 6 && p.destination.Is6())
	})

	type sent struct {
		probe    switchProbe
		protocol string
		number   int
		outcome  rulesOutcome
	}
	var all []sent
	var fds []int
	if err := lab.leaf.Do(func() error {
		if arm.pinned {
			var allowed, one unix.CPUSet
			if err := unix.SchedGetaffinity(0, &allowed); err != nil {
				return err
			}
			defer unix.SchedSetaffinity(0, &allowed)
			one.Set(arm.cpu)
			if err := unix.SchedSetaffinity(0, &one); err != nil {
				return fmt.Errorf("pin to CPU %d: %w", arm.cpu, err)
			}
		}
		for _, p := range probes {
			for _, protocol := range cmpProtocols(p.protocols) {
				lab.probe++
				fd, outcome, err := rulesSend(p.rulesProbe, protocol, lab.probe)
				if err != nil {
					return fmt.Errorf("%s %s to %s: %w", p.socket, protocol, p.destination, err)
				}
				if fd >= 0 {
					fds = append(fds, fd)
				}
				all = append(all, sent{p, protocol, lab.probe, outcome})
			}
		}
		if arm.usability {
			solicited, err := switchSolicit()
			fds = append(fds, solicited...)
			return err
		}
		return nil
	}); err != nil {
		t.Fatalf("send the probes: %v", err)
	}
	type pinged struct {
		flow     switchFlow
		id       int
		received int
	}
	var flows []pinged
	for _, flow := range arm.flows {
		lab.ping++
		from := map[string]*netnstest.Thread{"container": lab.container, "lan": lab.lan}[flow.from]
		var received int
		if err := from.Do(func() (err error) { received, err = exitPing(flow.destination, lab.ping); return err }); err != nil {
			t.Fatalf("ping %s from the %s: %v", flow.destination, flow.from, err)
		}
		flows = append(flows, pinged{flow, lab.ping, received})
	}
	for _, reply := range arm.replies {
		if got := exitAnswered(t, lab.exitLab, reply); got != reply.answered {
			what := "the leaf's service on the uplink's address answered the internet host"
			if reply.underlay {
				what = "the internet host answered the leaf's underlay socket"
			}
			t.Errorf("over %s, %s %v, want %v", familyName(reply.destination), what, got, reply.answered)
		}
	}
	for _, s := range arm.services {
		if got := switchAsk(t, lab.exitLab, s); got != s.want {
			t.Errorf("the internet host's %s ask of port %d over %s was %s, want %s", s.protocol, s.port, familyName(s.destination), got, s.want)
		}
	}
	intoTun, tunOther := switchDrain(lab.tunCapture)
	outUplink, uplinkOther := switchDrain(lab.farCapture)
	for _, fd := range fds {
		_ = unix.Close(fd)
	}
	where := func(key rulesKey) (bool, bool, netip.Addr) {
		tunSource, inTun := intoTun[key]
		upSource, onUplink := outUplink[key]
		if onUplink {
			return inTun, true, upSource
		}
		return inTun, false, tunSource
	}
	for _, s := range all {
		inTun, onUplink, source := where(rulesKey{s.protocol, s.number})
		if !switchMet(s.probe.want, s.outcome, inTun, onUplink) {
			pinned := ""
			if arm.pinned {
				pinned = fmt.Sprintf(" on CPU %d", arm.cpu)
			}
			t.Errorf("%s from a socket %s under mark %#x to %s%s was %s, into the tun %v, out of the uplink %v from %s, want %s",
				s.protocol, s.probe.socket, s.probe.mark, s.probe.destination, pinned, s.outcome, inTun, onUplink, source, s.probe.want)
		}
	}
	for _, f := range flows {
		inTun, onUplink, source := where(rulesKey{"echo", f.id})
		if !switchMet(f.flow.want, "", inTun, onUplink) || f.received != f.flow.replies {
			t.Errorf("the %s's ping of %s went into the tun %v, out of the uplink %v from %s with %d replies, want %s with %d",
				f.flow.from, f.flow.destination, inTun, onUplink, source, f.received, f.flow.want, f.flow.replies)
		}
	}
	if arm.usability {
		if !uplinkOther.solicited[switchNeighbor] || uplinkOther.routerSolicits == 0 {
			t.Errorf("the uplink carried the neighbor solicitations %v and %d router solicitations, want one for %s and one",
				uplinkOther.solicited, uplinkOther.routerSolicits, switchNeighbor)
		}
	}
	if len(tunOther.solicited) > 0 {
		t.Logf("the tun carried neighbor solicitations %v", tunOther.solicited)
	}
	if arm.state != switchCrashed {
		t.Logf("the switch's state reads %s", lab.switchStatus())
	}
}

func cmpProtocols(protocols []string) []string {
	if protocols == nil {
		return []string{"udp", "tcp", "echo"}
	}
	return protocols
}

// switchMet reports whether a packet seen into the tun and out of the uplink as given, its send meeting outcome, went where want says
func switchMet(want switchWant, outcome rulesOutcome, inTun, onUplink bool) bool {
	switch want {
	case switchOut:
		return onUplink && !inTun
	case switchTun:
		return inTun && !onUplink
	case switchHeld:
		return !inTun && !onUplink
	case switchRefused:
		return !inTun && !onUplink && outcome == rulesUnreachable
	}
	return !onUplink
}

// switchNeighbor is an address on the uplink's IPv6 network no host holds, whose neighbor solicitation the kernel sends
var switchNeighbor = netip.MustParseAddr("2001:db8:a::99")

// switchSolicit sends a datagram to switchNeighbor, which makes the kernel solicit it, and a router solicitation to ff02::2 from a socket bound
// to the uplink's device, in the calling thread's namespace, and answers the sockets, still open
func switchSolicit() ([]int, error) {
	datagram, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	fds := []int{datagram}
	if err := unix.Sendto(datagram, []byte("neighbor"), 0, rulesSockaddr(switchNeighbor, rulesDiscard)); err != nil {
		return fds, fmt.Errorf("send to %s: %w", switchNeighbor, err)
	}
	raw, err := unix.Socket(unix.AF_INET6, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_ICMPV6)
	if err != nil {
		return fds, err
	}
	fds = append(fds, raw)
	if err := errors.Join(unix.BindToDevice(raw, rulesUplink), unix.SetsockoptInt(raw, unix.IPPROTO_IPV6, unix.IPV6_MULTICAST_HOPS, 255)); err != nil {
		return fds, err
	}
	// a router solicitation of RFC 4861 section 4.1, its checksum written by the kernel
	solicitation := []byte{133, 0, 0, 0, 0, 0, 0, 0}
	if err := unix.Sendto(raw, solicitation, 0, rulesSockaddr(netip.MustParseAddr("ff02::2"), 0)); err != nil {
		return fds, fmt.Errorf("send a router solicitation: %w", err)
	}
	return fds, nil
}

// switchSeen holds the targets of the neighbor solicitations a capture read and the count of its router solicitations
type switchSeen struct {
	solicited      map[netip.Addr]bool
	routerSolicits int
}

// switchDrain reads the capture until a read waits out its timeout, and answers the source of each probe's packet it read and the solicitations
func switchDrain(capture int) (map[rulesKey]netip.Addr, switchSeen) {
	out := make(map[rulesKey]netip.Addr)
	seen := switchSeen{solicited: map[netip.Addr]bool{}}
	buf := make([]byte, 1<<16)
	for {
		n, _, err := unix.Recvfrom(capture, buf, 0)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return out, seen
		}
		raw := buf[:n]
		if key, source, ok := rulesKeyOf(raw); ok {
			out[key] = source
			continue
		}
		if len(raw) < 48 || raw[0]>>4 != 6 || raw[6] != unix.IPPROTO_ICMPV6 {
			continue
		}
		switch icmp := raw[40:]; {
		case icmp[0] == 135 && len(icmp) >= 24:
			seen.solicited[netip.AddrFrom16([16]byte(icmp[8:24]))] = true
		case icmp[0] == 133:
			seen.routerSolicits++
		}
	}
}

// switchUsability is the probes every state lets out of the uplink: a DHCPv4 broadcast and an mDNS datagram from a socket bound to the
// uplink's device, a DHCPv6 solicit to ff02::1:2 and an echo to ff02::1 from one, and a datagram and an echo to the far end's link-local address
func switchUsability(farLinkLocal netip.Addr) []switchProbe {
	on := func(destination string, protocol string) switchProbe {
		return switchFrom(netip.MustParseAddr(destination), rulesOnUplink, 0, switchOut, protocol)
	}
	return []switchProbe{
		on("255.255.255.255", "udp"), on("224.0.0.251", "udp"), on("ff02::1:2", "udp"), on("ff02::1", "echo"),
		switchFrom(farLinkLocal, rulesOnUplink, 0, switchOut, "udp", "echo"),
	}
}

// switchFarLinkLocal is the link-local address the far end of the uplink is given
var switchFarLinkLocal = netip.MustParsePrefix("fe80::1/64")

// farLinkLocal gives the far end of the uplink switchFarLinkLocal and answers its address
func farLinkLocal(t *testing.T, lab *exitLab) netip.Addr {
	t.Helper()
	if err := lab.far.Do(func() error {
		netlink, err := netnstest.OpenNetlink()
		if err != nil {
			return err
		}
		defer netlink.Close()
		return netlink.AddAddresses(rulesFar, switchFarLinkLocal)
	}); err != nil {
		t.Fatalf("give the far end a link-local address: %v", err)
	}
	return switchFarLinkLocal.Addr()
}

// switchForwardedFlows is the container's and the LAN host's pings of the internet host: from a link forward leaves out
// they leave by the uplink and are answered in every state, and from the bridge forward names they go into the tun while the
// defaults are present and nowhere once they are retracted or the tun is gone
func switchForwardedFlows(state switchState, forwardBridge bool) []switchFlow {
	var out []switchFlow
	for _, family := range []int{4, 6} {
		internet := exitLabHost[family].internet.Addr()
		container := switchFlow{"container", internet, switchOut, exitPings}
		if forwardBridge {
			container = switchFlow{"container", internet, switchTun, 0}
			if state != switchPresent {
				container.want = switchHeld
			}
		}
		out = append(out, container, switchFlow{"lan", internet, switchOut, exitPings})
	}
	return out
}

// switchReplies is the leaf's service on the uplink's address answering the internet host as listed says, and the underlay's
// socket answered as underlay says
func switchReplies(listed, underlay bool) []exitReply {
	var out []exitReply
	for _, family := range []int{4, 6} {
		internet := exitLabHost[family].internet.Addr()
		out = append(out, exitReply{false, internet, listed}, exitReply{true, internet, underlay})
	}
	return out
}

// a leaf in mode 2 with fallback = "none" beside a container behind a bridge, masqueraded as Docker does, and a LAN host, each in
// a namespace of its own, in each state of the mesh's defaults: every socket of the host's own, unbound, bound to the overlay
// address, to the uplink's address or device, carrying the underlay's mark, sends UDP, TCP and echo, and only the LAN, this node's
// own prefix beyond the gateway and the underlay's mark leave by the uplink, what mode 2 sends into the tun going there while
// the defaults are present. Neighbor and router solicitation, DHCP, multicast and link-local pass, a forwarded link forward leaves
// out keeps its routes and one it names follows the switch, a listed service answers and an unlisted one does not, a clean stop
// leaves no table or rule, and the table a node killed with SIGKILL leaves holds as it did. With the tun holding no IPv4 overlay
// address 5450 refuses IPv4 beyond the LAN, and while another writer holds the table it still refuses what the switch would drop.
func TestTUNKillSwitchKeepsEachSocketOffTheUplink(t *testing.T) {
	lab := newSwitchLab(t)
	linkLocal := farLinkLocal(t, lab.exitLab)
	listed := []string{fmt.Sprintf("%d/udp", exitService)}
	for _, state := range switchStates {
		if state == switchCrashed {
			lab.cleanStop(t)
		}
		t.Run(string(state)+", nothing forwarded, the service listed", func(t *testing.T) {
			lab.run(t, switchArm{
				state: state, inbound: listed, probes: slices.Concat(switchSocketProbes(state), switchUsability(linkLocal)), usability: true,
				flows: switchForwardedFlows(state, false), replies: switchReplies(true, true),
			})
		})
		t.Run(string(state)+", forward naming the bridge, nothing listed", func(t *testing.T) {
			lab.run(t, switchArm{
				state: state, forward: []string{exitBridge},
				flows: switchForwardedFlows(state, true), replies: switchReplies(false, true),
			})
		})
		t.Run(string(state)+", the tun holding no IPv4 overlay address, forward naming the bridge", func(t *testing.T) {
			flows := switchForwardedFlows(state, true)
			// the bridge's IPv4 ping meets 5450 in every state, since IPv4 holds no 5440 for it to follow
			flows[0] = switchFlow{"container", exitLabHost[4].internet.Addr(), switchHeld, 0}
			lab.run(t, switchArm{
				state: state, forward: []string{exitBridge}, unaddressed: 4, probes: switchUnaddressedProbes(state),
				flows: flows, replies: switchReplies(false, true),
			})
			if state != switchCrashed {
				lab.notHolding(t, state, map[switchState]kernel.FallbackState{switchPresent: kernel.FallbackPassing, switchRetracted: kernel.FallbackHolding}[state])
			}
		})
	}
}

// cleanStop stops the lab's own node and checks it left no table or rule
func (lab *switchLab) cleanStop(t *testing.T) {
	t.Run("a clean stop", func(t *testing.T) {
		lab.d.stop()
		var tables map[uint8]uint32
		var rules []kernelRule
		if err := lab.leaf.Do(func() error {
			conn, err := nftables.Dial()
			if err != nil {
				return err
			}
			defer conn.Close()
			if tables, err = nftables.Tables(conn, kernel.FallbackTable); err != nil {
				return err
			}
			rules, err = dumpRules()
			return err
		}); err != nil {
			t.Fatalf("read the leaf back: %v", err)
		}
		if len(tables) > 0 {
			t.Errorf("the stop left the table %s in the families %v", kernel.FallbackTable, tables)
		}
		for _, rule := range rules {
			if rule.protocol == kernel.DefaultProtocol {
				t.Errorf("the stop left the rule %s", rule)
			}
		}
	})
}

// switchService is one ask of the leaf's services on the uplink's address from the internet host, and how it is met
type switchService struct {
	protocol    string
	destination netip.Addr
	port        int
	// listen runs a service on the port
	listen bool
	want   string
}

// switchAsk sends s from the internet host to the leaf's uplink address and answers how it was met: "answered", "refused" by an
// ICMP port unreachable, or "unanswered"
func switchAsk(t *testing.T, lab *exitLab, s switchService) string {
	t.Helper()
	family, kind := 6, unix.SOCK_DGRAM
	if s.destination.Is4() {
		family = 4
	}
	if s.protocol == "tcp" {
		kind = unix.SOCK_STREAM
	}
	uplink := rulesHost[family].uplink.Addr()
	if s.listen {
		var listen int
		if err := lab.leaf.Do(func() (err error) {
			listen, err = switchListen(uplink, s.port, kind, true)
			return err
		}); err != nil {
			t.Fatalf("listen on %s port %d: %v", uplink, s.port, err)
		}
		served := make(chan struct{})
		if kind == unix.SOCK_DGRAM {
			go func() {
				defer close(served)
				buf := make([]byte, 1500)
				if n, from, err := unix.Recvfrom(listen, buf, 0); err == nil {
					_ = unix.Sendto(listen, buf[:n], 0, from)
				}
			}()
		} else {
			close(served)
		}
		defer func() { <-served; _ = unix.Close(listen) }()
	}
	var answer string
	if err := lab.far.Do(func() error {
		fd, err := switchListen(s.destination, 0, kind|unix.SOCK_NONBLOCK, false)
		if err != nil {
			return err
		}
		defer unix.Close(fd)
		answer, err = switchAskFrom(fd, kind, rulesSockaddr(uplink, s.port))
		return err
	}); err != nil {
		t.Fatalf("ask port %d from the internet host: %v", s.port, err)
	}
	return answer
}

// switchListen opens a socket of kind bound to address and port, listening where listen says, in the calling thread's namespace
func switchListen(address netip.Addr, port, kind int, listen bool) (int, error) {
	family := unix.AF_INET6
	if address.Is4() {
		family = unix.AF_INET
	}
	fd, err := unix.Socket(family, kind|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	timeout := unix.NsecToTimeval(exitPingWait.Nanoseconds())
	err = errors.Join(unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1), unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout))
	if err == nil {
		err = unix.Bind(fd, rulesSockaddr(address, port))
	}
	if err == nil && listen && kind&unix.SOCK_STREAM == unix.SOCK_STREAM {
		err = unix.Listen(fd, 4)
	}
	if err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

// switchAskFrom sends from the non-blocking fd to the service at to and waits exitPingWait for its answer
func switchAskFrom(fd, kind int, to unix.Sockaddr) (string, error) {
	err := unix.Connect(fd, to)
	if kind == unix.SOCK_DGRAM {
		if err != nil {
			return "", err
		}
		if _, err := unix.Write(fd, []byte("asked")); err != nil {
			return "", err
		}
	} else if err != nil && !errors.Is(err, unix.EINPROGRESS) {
		return "", err
	}
	events := int16(unix.POLLIN)
	if kind != unix.SOCK_DGRAM {
		events = unix.POLLOUT
	}
	fds := []unix.PollFd{{Fd: int32(fd), Events: events}}
	deadline := time.Now().Add(exitPingWait)
	for {
		n, err := unix.Poll(fds, int(time.Until(deadline).Milliseconds()))
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return "", err
		}
		if n == 0 {
			return "unanswered", nil
		}
		break
	}
	failure, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
	if err != nil {
		return "", err
	}
	if failure == int(unix.ECONNREFUSED) {
		return "refused", nil
	}
	if failure != 0 {
		return unix.Errno(failure).Error(), nil
	}
	if kind == unix.SOCK_DGRAM {
		buf := make([]byte, 1500)
		if _, err := unix.Read(fd, buf); errors.Is(err, unix.ECONNREFUSED) {
			return "refused", nil
		} else if err != nil {
			return err.Error(), nil
		}
	}
	return "answered", nil
}

// a leaf in mode 2 with fallback = "none" listing 7100 over UDP and TCP, in each state: the internet host's ask of a listed service
// on the uplink's address is answered, a listed port with no service answers with its port unreachable, and an unlisted service,
// running, is not answered, over both protocols and both families
func TestTUNKillSwitchAnswersOnlyTheListedServices(t *testing.T) {
	lab := newSwitchLab(t)
	listed := []string{fmt.Sprintf("%d/udp", exitService), fmt.Sprintf("%d/udp", switchSilent), fmt.Sprintf("%d/tcp", exitService), fmt.Sprintf("%d/tcp", switchSilent)}
	var services []switchService
	for _, family := range []int{4, 6} {
		internet := exitLabHost[family].internet.Addr()
		for _, protocol := range []string{"udp", "tcp"} {
			services = append(services,
				switchService{protocol, internet, exitService, true, "answered"},
				switchService{protocol, internet, switchSilent, false, "refused"},
				switchService{protocol, internet, switchUnlisted, true, "unanswered"})
		}
	}
	for _, state := range switchStates {
		t.Run(string(state), func(t *testing.T) {
			lab.run(t, switchArm{state: state, inbound: listed, services: services})
		})
	}
}

// otherChain is another program's table and chain in the leaf's namespace
func otherChain(kind string, hook uint32, priority int32) nftables.Chain {
	return nftables.Chain{Table: "otherprogram", Name: "out", Type: kind, Hook: hook, Priority: priority}
}

// setMark loads value into register 1 and sets the packet's mark from it
func setMark(value uint32) [][]byte {
	load := nftables.PutAttrBE32(nil, unix.NFTA_IMMEDIATE_DREG, unix.NFT_REG_1)
	load = nftables.PutAttr(load, unix.NFTA_IMMEDIATE_DATA|unix.NLA_F_NESTED, nftables.PutAttr(nil, unix.NFTA_DATA_VALUE, binary.NativeEndian.AppendUint32(nil, value)))
	return [][]byte{nftables.Expression("immediate", load), markFromRegister()}
}

// markFromRegister sets the packet's mark from register 1
func markFromRegister() []byte {
	set := nftables.PutAttrBE32(nil, unix.NFTA_META_KEY, unix.NFT_META_MARK)
	set = nftables.PutAttrBE32(set, unix.NFTA_META_SREG, unix.NFT_REG_1)
	return nftables.Expression("meta", set)
}

// unmarked goes on only for a packet carrying no mark
func unmarked() [][]byte {
	return nftables.MetaCompareValue(unix.NFT_META_MARK, unix.NFT_CMP_EQ, make([]byte, 4))
}

// destinationTranslation translates the destination of a packet of proto bound to from to to, as `dnat to` does
func destinationTranslation(from, to netip.Addr) [][]byte {
	proto := uint8(unix.NFPROTO_IPV6)
	if from.Is4() {
		proto = unix.NFPROTO_IPV4
	}
	load := nftables.PutAttrBE32(nil, unix.NFTA_IMMEDIATE_DREG, unix.NFT_REG_1)
	load = nftables.PutAttr(load, unix.NFTA_IMMEDIATE_DATA|unix.NLA_F_NESTED, nftables.PutAttr(nil, unix.NFTA_DATA_VALUE, nftables.AddressBytes(to)))
	nat := nftables.PutAttrBE32(nil, unix.NFTA_NAT_TYPE, unix.NFT_NAT_DNAT)
	nat = nftables.PutAttrBE32(nat, unix.NFTA_NAT_FAMILY, uint32(proto))
	nat = nftables.PutAttrBE32(nat, unix.NFTA_NAT_REG_ADDR_MIN, unix.NFT_REG_1)
	return slices.Concat(nftables.NFProto(proto),
		[][]byte{nftables.DestinationLoad(proto), nftables.Expression("cmp", nftables.Compare(unix.NFT_CMP_EQ, nftables.AddressBytes(from)))},
		[][]byte{nftables.Expression("immediate", load), nftables.Expression("nat", nat)})
}

// redirection is a rule redirecting at output a packet to from to the host itself, 127.0.0.1 or ::1, keeping its port, as
// nft's redirect writes one
func redirection(from netip.Addr) [][]byte {
	proto := uint8(unix.NFPROTO_IPV6)
	if from.Is4() {
		proto = unix.NFPROTO_IPV4
	}
	return slices.Concat(nftables.NFProto(proto),
		[][]byte{nftables.DestinationLoad(proto), nftables.Expression("cmp", nftables.Compare(unix.NFT_CMP_EQ, nftables.AddressBytes(from)))},
		[][]byte{nftables.Expression("redir", nil)})
}

// otherProgram writes chain with each rule's expressions, and where route is set the program's rule looking up main for switchOtherMark
// at switchOtherPriority in both families, and answers how to remove them
func otherProgram(chain nftables.Chain, route bool, rules ...[][]byte) func(t *testing.T, leaf *netnstest.Thread) func() {
	return func(t *testing.T, leaf *netnstest.Thread) func() {
		t.Helper()
		if err := leaf.Do(func() error {
			conn, err := nftables.Dial()
			if err != nil {
				return err
			}
			defer conn.Close()
			requests := []nftables.Request{nftables.NewTable(unix.NFPROTO_INET, chain.Table), chain.Create(unix.NFPROTO_INET)}
			for i, expressions := range rules {
				rule, err := chain.Rule(unix.NFPROTO_INET, fmt.Sprintf("rule %d", i), expressions)
				if err != nil {
					return err
				}
				requests = append(requests, rule)
			}
			if err := conn.Batch(requests); err != nil {
				return fmt.Errorf("write the chain: %w", err)
			}
			if route {
				return otherMarkRule(unix.RTM_NEWRULE)
			}
			return nil
		}); err != nil {
			t.Fatalf("write the other program's %s chain at %d: %v", chain.Type, chain.Priority, err)
		}
		return func() {
			if err := leaf.Do(func() error {
				conn, err := nftables.Dial()
				if err != nil {
					return err
				}
				defer conn.Close()
				err = conn.Batch([]nftables.Request{nftables.DeleteTable(unix.NFPROTO_INET, chain.Table)})
				if route {
					err = errors.Join(err, otherMarkRule(unix.RTM_DELRULE))
				}
				return err
			}); err != nil {
				t.Errorf("remove the other program's chain: %v", err)
			}
		}
	}
}

// otherMarkRule adds or deletes the other program's rule looking up main for switchOtherMark, in both families, with protocol boot
func otherMarkRule(kind uint16) error {
	netlink, err := netnstest.OpenNetlink()
	if err != nil {
		return err
	}
	defer netlink.Close()
	var flags uint16
	if kind == unix.RTM_NEWRULE {
		flags = unix.NLM_F_CREATE | unix.NLM_F_EXCL
	}
	for _, family := range []byte{unix.AF_INET, unix.AF_INET6} {
		header := []byte{family, 0, 0, 0, unix.RT_TABLE_MAIN, 0, 0, unix.FR_ACT_TO_TBL, 0, 0, 0, 0}
		if err := netlink.Request(kind, flags, slices.Concat(header, netnstest.Attr(unix.FRA_PRIORITY, netnstest.U32(switchOtherPriority)),
			netnstest.Attr(unix.FRA_FWMARK, netnstest.U32(switchOtherMark)), netnstest.Attr(unix.FRA_PROTOCOL, []byte{unix.RTPROT_BOOT}))); err != nil {
			return fmt.Errorf("the rule at %d: %w", switchOtherPriority, err)
		}
	}
	return nil
}

// switchChainProbes is the internet host's and the LAN's probes under another program's chains: from every socket the internet host is
// reached by no unmarked packet out of the uplink, the underlay's mark leaves by it where the chains leave the mark alone, and the
// LAN is reached by the uplink
func switchChainProbes(underlayCut bool) []switchProbe {
	marked := switchOut
	if underlayCut {
		marked = switchKept
	}
	kept := switchKept
	var probes []switchProbe
	for _, family := range []int{4, 6} {
		at := switchAt(family)
		probes = slices.Concat(probes,
			switchRow(at.internet, kept, kept, kept, kept, marked, marked),
			[]switchProbe{switchFrom(at.internet, rulesUnbound, 0x1, kept), switchFrom(at.lan, rulesUnbound, 0, switchOut), switchFrom(at.lan, rulesUnbound, 0x1, switchOut)})
	}
	return probes
}

// a leaf in mode 2 with fallback = "none" under each other program's chains below, in each state: a socket's own mark 0x1 (M1), a
// route chain marking every unmarked packet at mangle - 5 with its rule sending the mark to main (M2), one overwriting every mark at
// mangle + 5 (M3), one clearing every mark at mangle (M5), the same at 400 (M5x) and at 2147483647 (M5z), filter chains marking
// unmarked packets at filter (M6), at mangle (M6m) and at raw (M6r), and a restore of the connection's mark at mangle guarded on an
// unmarked packet (R1), the same unguarded at mangle (CR) and at 400 (R2): no unmarked packet reaches the internet host by the uplink,
// the LAN is reached, and the underlay's mark leaves by it wherever the chains leave the mark alone
func TestTUNKillSwitchHoldsUnderOtherProgramsChains(t *testing.T) {
	lab := newSwitchLab(t)
	const mangle, raw, filter = -150, -300, 0
	route, output := "route", uint32(unix.NF_INET_LOCAL_OUT)
	ctMark := [][]byte{nftables.CTLoad(unix.NFT_CT_MARK), markFromRegister()}
	arms := []switchArm{
		{name: "M5x, a route chain clearing every mark at 400", underlayCut: true, other: otherProgram(otherChain(route, output, 400), false, setMark(0))},
		{name: "M6m, a filter chain marking unmarked packets at mangle", other: otherProgram(otherChain("filter", output, mangle), true, slices.Concat(unmarked(), setMark(switchOtherMark)))},
		{name: "R1, a restore of the connection's mark at mangle guarded on an unmarked packet", other: otherProgram(otherChain(route, output, mangle), false, slices.Concat(unmarked(), ctMark))},
		{name: "R2, a full restore of the connection's mark at 400", underlayCut: true, other: otherProgram(otherChain(route, output, 400), false, ctMark)},
		{name: "M1, a socket's own mark 0x1"},
		{name: "M2, a route chain marking unmarked packets at mangle - 5", other: otherProgram(otherChain(route, output, mangle-5), true, slices.Concat(unmarked(), setMark(switchOtherMark)))},
		{name: "M3, a route chain overwriting every mark at mangle + 5", underlayCut: true, other: otherProgram(otherChain(route, output, mangle+5), true, setMark(switchOtherMark))},
		{name: "M5, a route chain clearing every mark at mangle", underlayCut: true, other: otherProgram(otherChain(route, output, mangle), false, setMark(0))},
		{name: "M5z, a route chain marking unmarked packets at 2147483647", other: otherProgram(otherChain(route, output, 2147483647), true, slices.Concat(unmarked(), setMark(switchOtherMark)))},
		{name: "M6, a filter chain marking unmarked packets at filter", other: otherProgram(otherChain("filter", output, filter), true, slices.Concat(unmarked(), setMark(switchOtherMark)))},
		{name: "M6r, a filter chain marking unmarked packets at raw", other: otherProgram(otherChain("filter", output, raw), true, slices.Concat(unmarked(), setMark(switchOtherMark)))},
		{name: "CR, a full restore of the connection's mark at mangle", underlayCut: true, other: otherProgram(otherChain(route, output, mangle), false, ctMark)},
	}
	for _, state := range switchStates {
		for _, arm := range arms {
			t.Run(arm.name+", "+string(state), func(t *testing.T) {
				arm.state, arm.probes = state, switchChainProbes(arm.underlayCut)
				lab.run(t, arm)
			})
		}
	}
}

// a leaf in mode 2 with fallback = "none" under NAT at output, in each state: a packet the host addressed to its own uplink address, translated
// to the internet host (N), from an unbound socket and one bound to the uplink's device (Nb), reaches it by no path out of the uplink
func TestTUNKillSwitchHoldsUnderNATAtOutput(t *testing.T) {
	lab := newSwitchLab(t)
	var rules [][][]byte
	var probes []switchProbe
	for _, family := range []int{4, 6} {
		uplink := rulesHost[family].uplink.Addr()
		rules = append(rules, destinationTranslation(uplink, exitLabHost[family].internet.Addr()))
		probes = append(probes, switchFrom(uplink, rulesUnbound, 0, switchKept, "udp", "tcp"), switchFrom(uplink, rulesOnUplink, 0, switchKept, "udp", "tcp"))
	}
	for _, state := range switchStates {
		t.Run(string(state), func(t *testing.T) {
			lab.run(t, switchArm{state: state, probes: probes, other: otherProgram(otherChain("nat", unix.NF_INET_LOCAL_OUT, -100), false, rules...)})
		})
	}
}

// a leaf in mode 2 with fallback = "none", in each state, where a packet first routed into the tun has its destination changed after it: NAT
// at output translating a peer's address to the internet host's (NM), and a route chain marking a packet routed into the tun so that its
// rule routes it again by main (NMm, RD-1's way): neither reaches the internet host out of the uplink from any socket
func TestTUNKillSwitchHoldsWhenADestinationChangesAfterTheTun(t *testing.T) {
	lab := newSwitchLab(t)
	var translations, marks [][][]byte
	var probes []switchProbe
	for _, family := range []int{4, 6} {
		at := switchAt(family)
		translations = append(translations, destinationTranslation(at.peer, at.internet))
		proto := uint8(unix.NFPROTO_IPV6)
		if family == 4 {
			proto = unix.NFPROTO_IPV4
		}
		marks = append(marks, slices.Concat(
			nftables.MetaCompare(unix.NFT_META_OIFNAME, unix.NFT_CMP_EQ, rulesTUN), nftables.NFProto(proto),
			[][]byte{nftables.DestinationLoad(proto), nftables.Expression("cmp", nftables.Compare(unix.NFT_CMP_EQ, nftables.AddressBytes(at.peer)))},
			setMark(switchOtherMark)))
		for _, socket := range []rulesSocket{rulesUnbound, rulesFromOverlay, rulesFromUplink, rulesOnUplink} {
			probes = append(probes, switchFrom(at.peer, socket, 0, switchKept, "udp", "tcp"))
		}
	}
	arms := []switchArm{
		{name: "NM, NAT at output after the tun", other: otherProgram(otherChain("nat", unix.NF_INET_LOCAL_OUT, -100), false, translations...)},
		{name: "NMm, a route chain marking a packet routed into the tun", other: otherProgram(otherChain("route", unix.NF_INET_LOCAL_OUT, -150), true, marks...)},
	}
	for _, state := range switchStates {
		for _, arm := range arms {
			t.Run(arm.name+", "+string(state), func(t *testing.T) {
				arm.state, arm.probes = state, probes
				lab.run(t, arm)
			})
		}
	}
}

// a leaf in mode 2 with fallback = "none", in each state: the host's own datagrams to 127.0.0.1, ::1, its uplink's addresses and, while
// the tun holds them, its overlay addresses, one to its uplink's address and one to a LAN host, first routed out of the uplink,
// redirected at output to 127.0.0.1 or ::1, and one to its uplink's address translated to its overlay address at output, are delivered
// on the host
func TestTUNKillSwitchKeepsTheHostsOwnTrafficOnLoopback(t *testing.T) {
	lab := newSwitchLab(t)
	for _, state := range switchStates {
		t.Run(string(state), func(t *testing.T) {
			lab.settle(t, switchArm{state: state})
			check := func(arm string) {
				t.Helper()
				for _, family := range []int{4, 6} {
					loopback := netip.IPv6Loopback()
					if family == 4 {
						loopback = netip.AddrFrom4([4]byte{127, 0, 0, 1})
					}
					addresses := []netip.Addr{loopback, rulesHost[family].uplink.Addr()}
					if state != switchCrashed {
						addresses = append(addresses, rulesHost[family].own.Addr())
					}
					for _, to := range addresses {
						if err := lab.leaf.Do(func() error { return switchLoopback(to, to) }); err != nil {
							t.Errorf("%s: a datagram to %s was not delivered on the host: %v", arm, to, err)
						}
					}
				}
			}
			check("P, no translation")
			var redirects [][][]byte
			for _, family := range []int{4, 6} {
				redirects = append(redirects, redirection(rulesHost[family].uplink.Addr()), redirection(rulesHost[family].lan.Addr()))
			}
			removeRedirects := otherProgram(otherChain("nat", unix.NF_INET_LOCAL_OUT, -100), false, redirects...)(t, lab.leaf)
			for _, family := range []int{4, 6} {
				loopback := netip.IPv6Loopback()
				if family == 4 {
					loopback = netip.AddrFrom4([4]byte{127, 0, 0, 1})
				}
				// the uplink's address is first routed into lo, and a LAN host's out of the uplink
				for _, to := range []netip.Addr{rulesHost[family].uplink.Addr(), rulesHost[family].lan.Addr()} {
					if err := lab.leaf.Do(func() error { return switchLoopback(loopback, to) }); err != nil {
						t.Errorf("PR: a datagram to %s redirected to %s was not delivered on the host: %v", to, loopback, err)
					}
				}
			}
			removeRedirects()
			if state == switchCrashed {
				// the overlay addresses went with the tun
				return
			}
			var rules [][][]byte
			for _, family := range []int{4, 6} {
				rules = append(rules, destinationTranslation(rulesHost[family].uplink.Addr(), rulesHost[family].own.Addr()))
			}
			t.Cleanup(otherProgram(otherChain("nat", unix.NF_INET_LOCAL_OUT, -100), false, rules...)(t, lab.leaf))
			for _, family := range []int{4, 6} {
				uplink, own := rulesHost[family].uplink.Addr(), rulesHost[family].own.Addr()
				if err := lab.leaf.Do(func() error { return switchLoopback(own, uplink) }); err != nil {
					t.Errorf("PD: a datagram to %s translated to %s was not delivered on the host: %v", uplink, own, err)
				}
			}
		})
	}
}

// switchLoopback sends a datagram to to and reads it on a socket bound to at, in the calling thread's namespace
func switchLoopback(at, to netip.Addr) error {
	listen, err := exitSocket(at, exitService, 0)
	if err != nil {
		return err
	}
	defer unix.Close(listen)
	unbound := netip.IPv6Unspecified()
	if to.Is4() {
		unbound = netip.IPv4Unspecified()
	}
	send, err := exitSocket(unbound, 0, 0)
	if err != nil {
		return err
	}
	defer unix.Close(send)
	if err := unix.Sendto(send, []byte("delivered"), 0, rulesSockaddr(to, exitService)); err != nil {
		return err
	}
	buf := make([]byte, 64)
	n, _, err := unix.Recvfrom(listen, buf, 0)
	if err != nil {
		return err
	}
	if string(buf[:n]) != "delivered" {
		return fmt.Errorf("read %q", buf[:n])
	}
	return nil
}

// a leaf in mode 2 with fallback = "none", in each state: each CPU in turn sends the host's probes to the internet host from every socket and
// to the LAN and the own prefix unbound, and every CPU sends each where the others do, out of the uplink only for the LAN, the own prefix and
// the underlay's mark
func TestTUNKillSwitchIsTheSameOnEveryCPU(t *testing.T) {
	lab := newSwitchLab(t)
	for _, state := range switchStates {
		t.Run(string(state), func(t *testing.T) {
			internet := switchTun
			if state != switchPresent {
				internet = switchHeld
			}
			var probes []switchProbe
			for _, family := range []int{4, 6} {
				at := switchAt(family)
				probes = slices.Concat(probes,
					switchRow(at.internet, internet, internet, switchHeld, switchHeld, switchOut, switchOut),
					[]switchProbe{switchFrom(at.lan, rulesUnbound, 0, switchOut), switchFrom(at.own, rulesUnbound, 0, switchOut)})
			}
			for i := range probes {
				probes[i].protocols = []string{"udp", "echo"}
			}
			var allowed unix.CPUSet
			if err := unix.SchedGetaffinity(0, &allowed); err != nil {
				t.Fatal(err)
			}
			lab.settle(t, switchArm{state: state})
			// CPU_SETSIZE of sched.h, the CPUs a set names
			for cpu := range 1024 {
				if allowed.IsSet(cpu) {
					lab.exercise(t, switchArm{state: state, probes: probes, pinned: true, cpu: cpu})
				}
			}
		})
	}
}

// a leaf in mode 2 with fallback = "none", in each state, under the kernel's strict reverse path check on the uplink and NixOS's strict
// and loose fib chains: the container's and the LAN host's pings from links forward leaves out are answered by the uplink, the listed
// service and the underlay are answered, as they are with no switch (S2, K1, F2 of rpf-routed-v4.sh and catchall-v4.sh)
func TestTUNKillSwitchKeepsReversePathChecksPassing(t *testing.T) {
	lab := newSwitchLab(t)
	listed := []string{fmt.Sprintf("%d/udp", exitService)}
	checks := []struct {
		name   string
		strict bool
		fib    string
	}{{"S2 and K1, strict rp_filter on the uplink", true, ""}, {"F2, NixOS's strict fib chain", false, "strict"}, {"NixOS's loose fib chain", false, "loose"}}
	for _, state := range switchStates {
		for _, check := range checks {
			t.Run(check.name+", "+string(state), func(t *testing.T) {
				if check.strict {
					exitStrict(t, lab.leaf, "1")
					t.Cleanup(func() { exitStrict(t, lab.leaf, "0") })
				}
				if check.fib != "" {
					reverseFib(t, lab.leaf, check.fib == "strict")
					t.Cleanup(func() { reverseFibRemove(t, lab.leaf) })
				}
				lab.run(t, switchArm{state: state, inbound: listed, flows: switchForwardedFlows(state, false), replies: switchReplies(true, true)})
			})
		}
	}
}
