// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel_test

import (
	"bytes"
	"cmp"
	"context"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/egress/egresstest"
	kernelexit "ranet3.com/pkgs/ranet3/internal/egress/kernel"
	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/logtest"
	"ranet3.com/pkgs/ranet3/internal/netlink"
	"ranet3.com/pkgs/ranet3/internal/netnstest"
	"ranet3.com/pkgs/ranet3/internal/nftables"
	"ranet3.com/pkgs/ranet3/schema"
)

const (
	// downQuiet is how long a down's test watches for what must not come
	downQuiet = 2 * time.Second
	// downPort is the server's port of a down's flows and leafDownPort the
	// leaf's
	downPort     = 10403
	leafDownPort = 40804
	// downReplies is how many datagrams and writes the server sends each flow
	// while down
	downReplies = 3
	// raceRefusals is how many of the exit's writes the racer of its table
	// has the kernel refuse before it stops
	raceRefusals = 5
	// raceMade and raceDeleted bound the racer's random pause after it makes
	// the table and after it deletes it again
	raceMade    = 1500 * time.Microsecond
	raceDeleted = 3000 * time.Microsecond
	// stoppedPoll is how often the test of a down over a held set reads Status
	// for the translator stopped, which it must never read
	stoppedPoll = 10 * time.Millisecond
	// waitPoll is how often waitRead and waitFor look again within PassWait
	waitPoll = time.Millisecond
)

// exitModules are the modules the kernel exit's rules use, which a root test
// that runs it finds held or skips, and tunModules those of a root test
// whose mesh is a tun and whose uplink a veth
var (
	exitModules = []string{"nf_tables", "nf_conntrack", "nf_nat", "nft_ct", "nft_nat", "nft_masq", "nft_chain_nat", "nft_connlimit", "nf_conncount", "nft_reject_inet"}
	tunModules  = append([]string{"tun", "veth"}, exitModules...)
)

// counterPackets reads the packets of each rule of a counting table by its
// comment
var counterPackets = regexp.MustCompile(`counter packets (\d+) bytes \d+ comment "(\w+)"`)

// needModules skips t unless the kernel holds each of names (kernelHolds), so
// the test loads no module of its own
func needModules(t *testing.T, names ...string) {
	t.Helper()
	for _, name := range names {
		held, err := kernelHolds(name)
		if err != nil {
			t.Skipf("the modules the kernel holds cannot be read: %v", err)
		}
		if !held {
			t.Skipf("the kernel neither loaded the module %s nor built it in, and the test loads none", name)
		}
	}
}

// kernelHolds is whether the running kernel holds the module name, as
// moduleSources.holds reads it from the running kernel's sources
func kernelHolds(name string) (bool, error) {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return false, err
	}
	release := unix.ByteSliceToString(uts.Release[:])
	return moduleSources{
		loaded: "/proc/modules",
		sys:    "/sys/module",
		// where a distribution keeps the running kernel's list, then where
		// NixOS keeps the booted kernel's
		builtin: []string{"/lib/modules/" + release + "/modules.builtin", "/run/booted-system/kernel-modules/lib/modules/" + release + "/modules.builtin"},
	}.holds(name)
}

// moduleSources are where a kernel's modules are read: loaded the list of
// those loaded, as /proc/modules, sys the directory of those that show
// themselves, as /sys/module, and builtin the places of a list of those built
// in, as modules.builtin, the first readable taken
type moduleSources struct {
	loaded  string
	sys     string
	builtin []string
}

// holds is whether the kernel holds the module name: loaded, as the list of
// those loaded names it, or built in, which that list leaves out, as sys names
// one with parameters and the list of those built in names every one. Where
// no list of those built in can be read, one with no parameters reads as not
// held.
func (s moduleSources) holds(name string) (bool, error) {
	raw, err := os.ReadFile(s.loaded)
	if err != nil {
		return false, err
	}
	for line := range strings.Lines(string(raw)) {
		if loaded, _, _ := strings.Cut(line, " "); loaded == name {
			return true, nil
		}
	}
	if _, err := os.Stat(filepath.Join(s.sys, name)); err == nil {
		return true, nil
	}
	for _, list := range s.builtin {
		raw, err := os.ReadFile(list)
		if err != nil {
			continue
		}
		for line := range strings.Lines(string(raw)) {
			// a path such as kernel/drivers/net/tun.ko, the module's name its
			// file's with underscores for dashes, as the kernel spells it
			module := strings.ReplaceAll(strings.TrimSuffix(path.Base(strings.TrimSpace(line)), ".ko"), "-", "_")
			if module == name {
				return true, nil
			}
		}
		return false, nil
	}
	return false, nil
}

// A module the kernel holds reads held whether it is loaded, shows itself
// under sys or is listed built in, under its name with underscores where its
// file has dashes, the first readable list of those built in taken, and one
// it holds nowhere reads as not held
func TestModuleSourcesHoldWhatIsLoadedOrBuiltIn(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		t.Helper()
		at := filepath.Join(dir, name)
		if err := os.WriteFile(at, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return at
	}
	sys := filepath.Join(dir, "module")
	if err := os.MkdirAll(filepath.Join(sys, "nf_conntrack"), 0o700); err != nil {
		t.Fatal(err)
	}
	s := moduleSources{
		loaded:  write("modules", "nf_tables 380928 0 - Live 0x0000000000000000\n"),
		sys:     sys,
		builtin: []string{filepath.Join(dir, "absent"), write("builtin", "kernel/drivers/net/tun.ko\nkernel/net/netfilter/nf-conntrack-netlink.ko\n"), write("second", "kernel/drivers/net/veth.ko\n")},
	}
	for name, want := range map[string]bool{"nf_tables": true, "nf_conntrack": true, "tun": true, "nf_conntrack_netlink": true, "veth": false, "nft_ct": false} {
		if held, err := s.holds(name); err != nil || held != want {
			t.Errorf("the module %s read held %t (%v), want %t", name, held, err, want)
		}
	}
}

// asRootWithNft skips t unless it runs as root with nft on the path and each
// module of tunModules held (needModules), and answers nft's path
func asRootWithNft(t *testing.T) string {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("a tun and a network namespace need root on linux")
	}
	nft, err := exec.LookPath("nft")
	if err != nil {
		t.Skipf("what leaves the exit is counted through nft, which is not on the path: %v", err)
	}
	needModules(t, tunModules...)
	return nft
}

// downCounting adds a table to host's namespace counting the packets to each
// family's overlay that leave by a link other than the tun, under the
// comments out4 and out6, and answers a read of the counts
func downCounting(t *testing.T, host egresstest.Host, nft string, families []egresstest.Family) func() map[string]int {
	t.Helper()
	return nftCounters(t, host, nft, "downcount", fmt.Sprintf(`table inet downcount {
	chain post {
		type filter hook postrouting priority 200; policy accept;
		oifname != %q ip daddr %s counter comment "out4"
		oifname != %q ip6 daddr %s counter comment "out6"
	}
}
`, host.TUN, families[0].Overlay, host.TUN, families[1].Overlay))
}

// nftCounters adds the table inet table script makes to host's namespace and
// answers a read of its counters by their comments
func nftCounters(t *testing.T, host egresstest.Host, nft, table, script string) func() map[string]int {
	t.Helper()
	if _, err := nftIn(host, nft, script, "-f", "-"); err != nil {
		t.Fatalf("add the counting table %s: %v", table, err)
	}
	return func() map[string]int {
		t.Helper()
		listing, err := nftIn(host, nft, "", "list", "table", "inet", table)
		if err != nil {
			t.Fatalf("list the counting table %s: %v", table, err)
		}
		read := map[string]int{}
		for _, match := range counterPackets.FindAllStringSubmatch(listing, -1) {
			read[match[2]], _ = strconv.Atoi(match[1])
		}
		return read
	}
}

// downCarry hands each batch of frames the leaf sends out of the mesh to the
// exit to answers then, from the call until the test ends, and drops a batch
// sent while it answers none
func downCarry(network egresstest.Network, to func() *kernelexit.Translator) {
	network.Carry(func(packets [][]byte) {
		exit := to()
		if exit == nil {
			return
		}
		frames := make([][]byte, 0, len(packets))
		for _, packet := range packets {
			frames = append(frames, egresstest.Headroomed(packet))
		}
		exit.Egress(frames, nil)
	})
}

// runExit builds the kernel exit for cfg on host as the daemon builds it, its
// readiness moving the mesh's, and runs it until its end, at the latest the
// end of t, which waits for Run and holds it to no error. Where host has a
// done channel the end closes the mesh, and the tun with it, as the daemon's
// stop does.
func runExit(t *testing.T, host egresstest.Host, cfg egress.Egress) (*kernelexit.Translator, func()) {
	t.Helper()
	mesh := host.Lanes
	hooks := egress.Hooks{Ready: func(v4, v6, _ bool) { mesh.SetEgressReady(v4, v6); mesh.SetAdvertisedReady(v4, v6) }, Republish: func() {}}
	exit := newKernelExit(t, host, cfg, hooks).(*kernelexit.Translator)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- exit.Run(ctx) }()
	end := sync.OnceFunc(func() {
		cancel()
		if host.Done != nil {
			mesh.Close()
		}
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("the exit's Run returned %v", err)
			}
		case <-time.After(kernelexit.PassWait):
			t.Errorf("the exit's Run had not returned %s after its context ended", kernelexit.PassWait)
		}
	})
	t.Cleanup(end)
	return exit, end
}

// takeDown takes exit on host down as `ranet3 down` does with cap.table: the
// stop, the leaf's routes gone from the mesh as its sessions close, and the
// tun's addresses of each family, and with them its routes, withdrawn as the
// reconciler withdraws them. It waits for the stop in effect, and answers the
// time from its start, and up, which puts the addresses and the routes back
// and starts exit again.
func takeDown(t *testing.T, host egresstest.Host, exit *kernelexit.Translator, families []egresstest.Family) (time.Duration, func()) {
	t.Helper()
	mesh := host.Lanes
	members := host.Members()
	peer, _, _ := mesh.Routes.Resolve(families[0].Server, families[0].Leaf)
	started := time.Now()
	exit.SetEnabled(false)
	for _, prefix := range members {
		mesh.Routes.Remove(netip.Prefix{}, prefix)
	}
	addresses := make([]netip.Prefix, 0, len(families))
	for _, family := range families {
		addresses = append(addresses, netip.PrefixFrom(family.Exit[0], family.Overlay.Bits()))
	}
	if err := downAddresses(host, addresses, netnstest.Netlink.DelAddress); err != nil {
		t.Fatalf("withdraw the tun's addresses: %v", err)
	}
	waitFor(t, "the stop in effect", func() bool { return exit.Status().Unready == "the translator is stopped" })
	took := time.Since(started)
	return took, func() {
		t.Helper()
		if err := downAddresses(host, addresses, netnstest.Netlink.AddAddress); err != nil {
			t.Fatalf("put the tun's addresses back: %v", err)
		}
		if peer != nil {
			for _, prefix := range members {
				mesh.Routes.Set(netip.Prefix{}, prefix, peer)
			}
		}
		exit.SetEnabled(true)
	}
}

// exitThread is a thread of its own in host's namespace, for what dials there
// while the exit's reads of the host run on the exit's thread
func exitThread(t *testing.T, host egresstest.Host) *netnstest.Thread {
	t.Helper()
	var path string
	_ = host.Do(func() error { path = fmt.Sprintf("/proc/%d/task/%d/ns/net", os.Getpid(), unix.Gettid()); return nil })
	return netnstest.JoinThread(t, path)
}

// debugRead is exit's debug read on an exitThread
func debugRead(t *testing.T, host egresstest.Host, exit *kernelexit.Translator) egress.ExitDebug {
	t.Helper()
	var debug egress.ExitDebug
	_ = exitThread(t, host).Do(func() error { debug = exit.Debug(); return nil })
	return debug
}

// labelledDrops is how many packets the drops of a labelled flow's packet
// leaving by another link counted in debug's rules, the one ending each
// family's chain and the one ahead of its pass of untranslated sources, of the
// family named family, every family where it is empty
func labelledDrops(debug egress.ExitDebug, family string) int {
	dropped := 0
	for _, rule := range debug.Rules {
		if strings.HasSuffix(rule.Spec, " leaving by another link dropped while stopped") && (family == "" || strings.Contains(rule.Spec, " "+family+" ")) {
			dropped += int(rule.Packets)
		}
	}
	return dropped
}

// TestKernelExitDownLeavesNoReplyAWayOutButTheMesh takes an exit down as
// takeDown does. Replies the server sends while down to a UDP flow and a TCP
// connection the exit translated while up, in each family, reach the leaf not
// at all and leave by no link: the kept bindings translate each back to the
// leaf's address, which the host then routes by its uplink, and the stopped
// rules drop it as a packet of a flow the exit labelled. So do its replies to
// a UDP flow the exit's host sent from its own mesh address, whose socket has
// closed, translated back to that address, which is no longer the host's once
// the tun's addresses are gone. Once up again the leaf's flows resume under
// the bindings they had. The time from the stop's start to its rules reading
// back bounds how long a reconciler's withdrawal that commits first leaves
// such a reply its way out in this run.
func TestKernelExitDownLeavesNoReplyAWayOutButTheMesh(t *testing.T) {
	nft := asRootWithNft(t)
	network := egresstest.Namespaces(t)
	host := network.Exit()
	families := []egresstest.Family{network.Family(false), network.Family(true)}
	filter := besideFilter(t, network)
	waitFor(t, "the antispoof filter ready", filter.Ready)
	counters := downCounting(t, host, nft, families)
	// the antispoof filter's chains share the table and stop after the exit
	t.Cleanup(func() {
		held, err := kernelExitTables(host)
		exits := slices.DeleteFunc(held, func(item string) bool {
			return !slices.ContainsFunc([]string{kernelexit.ChainName, kernelexit.LimitChain, kernelexit.NoneChain}, func(name string) bool {
				return strings.HasPrefix(item, "chain "+name)
			})
		})
		if err != nil || len(exits) != 0 {
			t.Errorf("the exit's shutdown left %q (%v), want none of its chains", exits, err)
		}
	})
	host.Done = host.Lanes.Done()
	cfg := egress.Egress{Advertise: []schema.Prefix{schema.MustPrefix("0.0.0.0/0"), schema.MustPrefix("::/0")}, Sweep: schema.Duration(time.Hour)}
	exit, _ := runExit(t, host, cfg)
	downCarry(network, func() *kernelexit.Translator { return exit })
	ready := func() bool { v4, v6 := host.Lanes.EgressReady(); return v4 && v6 }
	waitFor(t, "both families ready", ready)
	var flows, own []*downFlow
	for _, family := range families {
		flows = append(flows, openDownFlow(t, network, family, downPort))
		f := openDownUDP(t, network, host.Do, family.Exit[0], family, downPort+2)
		if f.mapped.Addr() == family.Exit[0] {
			t.Fatalf("the server read the exit's own %s flow from its mesh address %s, want it translated", family.Name, f.mapped)
		}
		own = append(own, f)
	}

	took, up := takeDown(t, host, exit, families)
	t.Logf("the stop read in effect %s after it began", took.Round(time.Microsecond))
	// a reply whose socket is still open is matched to it ahead of its route,
	// and the kernel forwards no packet so matched, so the host's sockets
	// close first, as a program's end leaves its flows' bindings
	for _, flow := range own {
		_ = flow.leafUDP.Close()
	}
	before := counters()
	for i := range downReplies {
		for _, flow := range slices.Concat(flows, own) {
			flow.reply(t, fmt.Sprintf("down %d", i))
		}
	}
	time.Sleep(downQuiet)
	after := counters()
	for i, family := range families {
		key := "out" + strconv.Itoa(4+2*i)
		if out := after[key] - before[key]; out != 0 {
			t.Errorf("%d packets to the %s overlay left by a link other than the tun while down, want none", out, family.Name)
		}
	}
	for _, flow := range flows {
		if udp, tcp := flow.heard(downQuiet); udp != "" || tcp != "" {
			t.Errorf("while down the leaf read %q on its %s UDP flow and %q on its connection, want nothing with its session closed", udp, flow.family.Name, tcp)
		}
	}
	labelled := labelledDrops(debugRead(t, host, exit), "")
	if labelled == 0 {
		t.Error("the drop of a labelled flow's packet leaving by another link counted none of the replies, want it to have met them")
	}
	t.Logf("the drop of a labelled flow's packet leaving by another link counted %d", labelled)

	up()
	waitFor(t, "both families ready again", ready)
	for _, flow := range flows {
		flow.resumed(t)
	}
}

// TestKernelExitDownDropsTheLabelledFlowsOfAFamilyItNoLongerTranslates
// translates a flow in IPv6, ends that run over the tun, which stays, and
// starts again translating IPv4 alone, as a restart over a file that no
// longer advertises IPv6 does, then takes the exit down as takeDown does. The
// replies the server sends while down to the IPv6 flow, under the binding the
// first run made and labelled, leave by no link, the stopped rules' drop of a
// labelled flow's IPv6 packet counting them. A new IPv6 flow of the leaf's,
// which no run labelled and none translates, still reaches the server while
// down, from the leaf's own address.
func TestKernelExitDownDropsTheLabelledFlowsOfAFamilyItNoLongerTranslates(t *testing.T) {
	nft := asRootWithNft(t)
	network := egresstest.Namespaces(t)
	host := network.Exit()
	families := []egresstest.Family{network.Family(false), network.Family(true)}
	counters := downCounting(t, host, nft, families)
	var current atomic.Pointer[kernelexit.Translator]
	downCarry(network, current.Load)
	advertise := []schema.Prefix{schema.MustPrefix("0.0.0.0/0"), schema.MustPrefix("::/0")}
	first, end := runExit(t, host, egress.Egress{Advertise: advertise, Sweep: schema.Duration(time.Hour)})
	current.Store(first)
	waitFor(t, "both families ready in the first run", func() bool { v4, v6 := host.Lanes.EgressReady(); return v4 && v6 })
	flow := openDownFlow(t, network, families[1], downPort)
	// the first run waits for no mesh, so its end leaves the tun and what Run
	// leaves over it
	end()
	host.Done = host.Lanes.Done()
	second, _ := runExit(t, host, egress.Egress{Advertise: advertise[:1], Sweep: schema.Duration(time.Hour)})
	current.Store(second)
	waitFor(t, "IPv4 alone ready in the second run", func() bool {
		s := second.Status()
		return s.Ready4 && !s.Ready6 && s.Err == ""
	})

	takeDown(t, host, second, families)
	before := counters()
	for i := range downReplies {
		flow.reply(t, fmt.Sprintf("down %d", i))
	}
	time.Sleep(downQuiet)
	if out := counters()["out6"] - before["out6"]; out != 0 {
		t.Errorf("%d replies to the IPv6 flow the first run translated left by a link other than the tun while down, want none", out)
	}
	if dropped := labelledDrops(debugRead(t, host, second), "ipv6"); dropped == 0 {
		t.Error("the drop of a labelled flow's IPv6 packet leaving by another link counted none of the replies, want it to have met them")
	}
	// its datagram alone, since whatever answers it leaves by the uplink with
	// the tun's addresses gone
	if from := openDownUDP(t, network, network.Leaf, families[1].Leaf, families[1], downPort+1).mapped; from.Addr() != families[1].Leaf {
		t.Errorf("while down the server read a new IPv6 flow of the leaf's from %s, want the leaf's own address %s", from, families[1].Leaf)
	}
}

// TestKernelExitDownDropsTheLabelledFlowsOfASourceItPutsUnderNone translates a
// UDP flow of the leaf's in each family, ends that run over the tun, which
// stays, and starts again with the leaf's addresses under a class of none, as
// a restart over a file that no longer translates them does, then takes the
// exit down. A datagram the leaf sends on each flow while down, under the
// binding the first run made and labelled, reaches the server not at all, the
// stopped rules' drop of a labelled flow's packet in its family counting it,
// while a new flow of the leaf's in each family, which no run labelled, still
// reaches the server from the leaf's own address.
func TestKernelExitDownDropsTheLabelledFlowsOfASourceItPutsUnderNone(t *testing.T) {
	asRootWithNft(t)
	network := egresstest.Namespaces(t)
	host := network.Exit()
	families := []egresstest.Family{network.Family(false), network.Family(true)}
	var current atomic.Pointer[kernelexit.Translator]
	downCarry(network, current.Load)
	advertise := []schema.Prefix{schema.MustPrefix("0.0.0.0/0"), schema.MustPrefix("::/0")}
	first, end := runExit(t, host, egress.Egress{Advertise: advertise, Sweep: schema.Duration(time.Hour)})
	current.Store(first)
	ready := func() bool { v4, v6 := host.Lanes.EgressReady(); return v4 && v6 }
	waitFor(t, "both families ready in the first run", ready)
	var flows []*downFlow
	var none []egress.Class
	for _, family := range families {
		flows = append(flows, openDownUDP(t, network, network.Leaf, family.Leaf, family, downPort))
		none = append(none, egress.Class{From: schema.MustPrefix(netip.PrefixFrom(family.Leaf, family.Leaf.BitLen()).String()), To: egress.Translation{None: true}})
	}
	// the first run waits for no mesh, so its end leaves the tun and what Run
	// leaves over it
	end()
	host.Done = host.Lanes.Done()
	second, _ := runExit(t, host, egress.Egress{Advertise: advertise, Translate: none, Sweep: schema.Duration(time.Hour)})
	current.Store(second)
	waitFor(t, "both families ready in the second run", ready)

	second.SetEnabled(false)
	waitFor(t, "the stop in effect", func() bool { return second.Status().Unready == "the translator is stopped" })
	for _, flow := range flows {
		if _, err := flow.leafUDP.Write([]byte("down")); err != nil {
			t.Fatal(err)
		}
	}
	for _, flow := range flows {
		if from, read := flow.arrived("down", downQuiet); read {
			t.Errorf("while down the server read the leaf's datagram on the %s flow the first run labelled from %s, want it dropped", flow.family.Name, from)
		}
	}
	debug := debugRead(t, host, second)
	for i, family := range families {
		if labelledDrops(debug, family.Name) == 0 {
			t.Errorf("the drop of a labelled flow's %s packet leaving by another link counted none of the leaf's datagrams, want it to have met them", family.Name)
		}
		if from := openDownUDP(t, network, network.Leaf, family.Leaf, family, downPort+1+uint16(i)).mapped; from.Addr() != family.Leaf {
			t.Errorf("while down the server read a new %s flow of the leaf's from %s, want the leaf's own address %s", family.Name, from, family.Leaf)
		}
	}
}

// TestKernelExitDownSendsByTheUplinkWhatTheHostItselfSendsALeaf takes an exit
// down as takeDown does under cap.table, then writes from the tun, in each
// family, the frames of each case below one at a time, each of which draws a
// packet the host itself sends to the leaf's mesh address, and waits for that
// packet to leave by the uplink before it writes the next. With the tun's
// routes gone, the host's other routes send each by the uplink, the leaf's
// address its destination, as exit-nodes.md states under "What the host itself
// sends to a leaf", so a change that keeps one off that link meets the page
// here. The host filters no reverse path but in the case that says so, holds
// an unreachable and a prohibit route for one address of each family, holds
// another program's reject at the forward hook ahead of the exit's chain, and
// limits none of the errors it sends.
func TestKernelExitDownSendsByTheUplinkWhatTheHostItselfSendsALeaf(t *testing.T) {
	// sentWait is how long the test waits for what one frame draws to leave,
	// and sentPoll how often it reads the counters meanwhile
	const (
		sentWait = 10 * time.Second
		sentPoll = 10 * time.Millisecond
	)
	nft := asRootWithNft(t)
	network := egresstest.Namespaces(t)
	host := network.Exit()
	families := []egresstest.Family{network.Family(false), network.Family(true)}
	// each family's address under an unreachable route and under a prohibit one
	unreachable := []netip.Addr{netip.MustParseAddr("203.0.113.200"), netip.MustParseAddr("2001:db8:6::1")}
	prohibit := []netip.Addr{netip.MustParseAddr("203.0.113.201"), netip.MustParseAddr("2001:db8:6::2")}
	// rejected is the server's port another program rejects a frame from the tun to
	const rejected = downPort + 30
	sysctl := func(name, value string) {
		t.Helper()
		var read []byte
		if err := host.Do(func() (err error) {
			if err = os.WriteFile("/proc/sys/net/"+name, []byte(value), 0o644); err == nil {
				read, err = os.ReadFile("/proc/sys/net/" + name)
			}
			return err
		}); err != nil {
			t.Fatalf("set %s to %q: %v", name, value, err)
		}
		if got := strings.TrimSpace(string(read)); got != strings.TrimSpace(value) {
			t.Fatalf("set %s to %q and read back %q", name, value, got)
		}
	}
	// a packet IPv6's reassembly never completes is given up within the wait
	// for what each case's frames draw
	sysctl("netfilter/nf_conntrack_frag6_timeout", "1")
	// the kernel limits the errors it sends, to one peer and from the
	// namespace, of the types each family's ratemask names alone
	// (net/ipv4/icmp.c:277 and net/ipv6/icmp.c:166 at 940de590b), so with both
	// empty no frame's packet meets a limit
	sysctl("ipv4/icmp_ratemask", "0")
	sysctl("ipv6/icmp/ratemask", "\n")
	// uplink is the link holding the host's uplink address of each family
	uplink := make([]string, len(families))
	if err := host.Do(func() error {
		links, err := net.Interfaces()
		if err != nil {
			return err
		}
		for _, link := range links {
			addresses, err := link.Addrs()
			if err != nil {
				return err
			}
			for _, address := range addresses {
				prefix, err := netip.ParsePrefix(address.String())
				for i, f := range families {
					if err == nil && prefix.Addr() == f.Uplink {
						uplink[i] = link.Name
					}
				}
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("read the host's links: %v", err)
	}
	for i, f := range families {
		if uplink[i] == "" {
			t.Fatalf("no link of the host holds its %s uplink address %s", f.Name, f.Uplink)
		}
	}
	if err := host.Do(func() error {
		conn, err := netnstest.OpenNetlink()
		if err != nil {
			return err
		}
		defer conn.Close()
		for i := range families {
			for kind, to := range map[byte]netip.Addr{unix.RTN_UNREACHABLE: unreachable[i], unix.RTN_PROHIBIT: prohibit[i]} {
				if err := conn.Request(unix.RTM_NEWROUTE, unix.NLM_F_CREATE|unix.NLM_F_EXCL, typedRoute(to, kind)); err != nil {
					return fmt.Errorf("%s: %w", to, err)
				}
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("route the refused addresses: %v", err)
	}
	if _, err := nftIn(host, nft, fmt.Sprintf(`table inet another {
	chain forward {
		type filter hook forward priority -10; policy accept;
		iifname %q udp dport %d reject
	}
}
`, host.TUN, rejected), "-f", "-"); err != nil {
		t.Fatalf("add another program's reject: %v", err)
	}
	host.Done = host.Lanes.Done()
	cfg := egress.Egress{Advertise: []schema.Prefix{schema.MustPrefix("0.0.0.0/0"), schema.MustPrefix("::/0")}, Sweep: schema.Duration(time.Hour)}
	exit, _ := runExit(t, host, cfg)
	downCarry(network, func() *kernelexit.Translator { return exit })
	waitFor(t, "both families ready", func() bool { v4, v6 := host.Lanes.EgressReady(); return v4 && v6 })
	var leaf []*downFlow
	for i, family := range families {
		leaf = append(leaf, openDownUDP(t, network, network.Leaf, family.Leaf, family, downPort+uint16(10*i)))
	}
	// labelled is the ends of family i's flow the exit translated and labelled
	labelled := func(i int) (netip.AddrPort, netip.AddrPort) {
		local, remote := leaf[i].leafUDP.LocalAddr().(*net.UDPAddr).AddrPort(), leaf[i].leafUDP.RemoteAddr().(*net.UDPAddr).AddrPort()
		return netip.AddrPortFrom(local.Addr().Unmap(), local.Port()), netip.AddrPortFrom(remote.Addr().Unmap(), remote.Port())
	}
	cases := []struct {
		name string
		// strict has the host's IPv4 reverse path filter strict, which is off for
		// the other cases
		strict bool
		// match4 and match6 match, as nft reads it, the packet the host sends the
		// leaf for the case's frames in each family, empty where it sends none
		match4, match6 string
		// frames are the case's frames in family i, from, where the case takes
		// it, a port of the leaf's no flow has used
		frames func(i int, f egresstest.Family, from netip.AddrPort) [][]byte
	}{
		{"the time exceeded at one hop", false, "icmp type time-exceeded icmp code 0", "icmpv6 type time-exceeded icmpv6 code 0",
			func(i int, f egresstest.Family, from netip.AddrPort) [][]byte {
				source, to := labelled(i)
				return [][]byte{egresstest.DatagramFrameHops(source, to, 1, []byte("at one hop")), egresstest.DatagramFrameHops(from, to, 1, []byte("a new flow at one hop"))}
			}},
		{"the fragmentation needed or packet too big", false, "icmp type destination-unreachable icmp code frag-needed", "icmpv6 type packet-too-big",
			func(i int, f egresstest.Family, _ netip.AddrPort) [][]byte {
				// past the uplink's MTU, its IPv4 header forbidding fragments, as
				// each of egresstest's does
				source, to := labelled(i)
				return [][]byte{egresstest.DatagramFrame(source, to, make([]byte, f.UplinkMTU))}
			}},
		{"the destination unreachable of an unreachable and a prohibit route", true,
			"icmp type destination-unreachable icmp code { host-unreachable, admin-prohibited }", "icmpv6 type destination-unreachable icmpv6 code { no-route, admin-prohibited }",
			func(i int, f egresstest.Family, from netip.AddrPort) [][]byte {
				return [][]byte{egresstest.DatagramFrame(from, netip.AddrPortFrom(unreachable[i], 9), []byte("to an unreachable route")),
					egresstest.DatagramFrame(from, netip.AddrPortFrom(prohibit[i], 9), []byte("to a prohibit route"))}
			}},
		{"the parameter problem", false, "icmp type parameter-problem", "icmpv6 type parameter-problem",
			func(i int, f egresstest.Family, from netip.AddrPort) [][]byte {
				return [][]byte{refusedOption(from, netip.AddrPortFrom(f.Server, downPort))}
			}},
		{"the reassembly time exceeded", false, "", "icmpv6 type time-exceeded icmpv6 code 1",
			func(i int, f egresstest.Family, from netip.AddrPort) [][]byte {
				if f.Leaf.Is4() {
					return nil
				}
				return [][]byte{firstFragment(from, netip.AddrPortFrom(f.Server, downPort))}
			}},
		{"another program's reject", false, "icmp type destination-unreachable icmp code port-unreachable", "icmpv6 type destination-unreachable icmpv6 code port-unreachable",
			func(i int, f egresstest.Family, from netip.AddrPort) [][]byte {
				return [][]byte{egresstest.DatagramFrame(from, netip.AddrPortFrom(f.Server, rejected), []byte("rejected"))}
			}},
		{"the host's own answers", false, "icmp type { destination-unreachable, echo-reply }", "icmpv6 type { destination-unreachable, echo-reply }",
			func(i int, f egresstest.Family, from netip.AddrPort) [][]byte {
				// a datagram to a port of the host's no socket holds, and an echo request
				return [][]byte{egresstest.DatagramFrame(from, netip.AddrPortFrom(f.Uplink, 9), []byte("to the host")), egresstest.EchoFrame(f.Leaf, f.Uplink, 1, nil)}
			}},
	}
	// made counts at the output hook what the host sends the leaf for each case
	// in each family and marks it, and left what of it leaves by the uplink with
	// that mark, so a packet that comes back from beyond the uplink, which the
	// link from another namespace hands over unmarked, and leaves again is not
	// counted twice
	const mark = 0x5e1
	var made, left strings.Builder
	for k, c := range cases {
		for i, match := range []string{c.match4, c.match6} {
			if match != "" {
				ip := []string{"ip", "ip6"}[i]
				fmt.Fprintf(&made, "\t\t%s daddr %s %s meta mark set %#x counter comment \"made%d_%d\"\n", ip, families[i].Leaf, match, mark, k, i)
				fmt.Fprintf(&left, "\t\toifname %q meta mark %#x %s daddr %s %s counter comment \"left%d_%d\"\n", uplink[i], mark, ip, families[i].Leaf, match, k, i)
			}
		}
	}
	counters := nftCounters(t, host, nft, "sentcount", fmt.Sprintf(`table inet sentcount {
	chain made {
		type filter hook output priority -300; policy accept;
%s	}
	chain left {
		type filter hook postrouting priority 300; policy accept;
%s	}
}
`, made.String(), left.String()))

	takeDown(t, host, exit, families)
	for k, c := range cases {
		// the kernel filters by the larger of all's value and the tun's, and loose
		// filtering refuses a frame from a link with no IPv4 address, as strict
		// filtering does, which the tun is once its addresses are withdrawn
		filter := "0"
		if c.strict {
			filter = "1"
		}
		for _, conf := range []string{"all", host.TUN} {
			sysctl("ipv4/conf/"+conf+"/rp_filter", filter)
		}
		for i, f := range families {
			key := fmt.Sprintf("%d_%d", k, i)
			for j, frame := range c.frames(i, f, netip.AddrPortFrom(f.Leaf, leafDownPort+100+uint16(10*k+i))) {
				before := counters()
				host.Write([][]byte{frame}, nil)
				made, left := 0, 0
				for deadline := time.Now().Add(sentWait); ; time.Sleep(sentPoll) {
					after := counters()
					made, left = after["made"+key]-before["made"+key], after["left"+key]-before["left"+key]
					if made > 0 && left >= made || time.Now().After(deadline) {
						break
					}
				}
				if made == 0 || left < made {
					t.Errorf("%s: the host made %d toward the leaf for its %s frame %d and %d left by the uplink, want it made and leaving", c.name, made, f.Name, j+1, left)
				}
			}
		}
	}
}

// TestKernelExitKeepsItsLabelWhileAnotherWriterRacesItsTable has another
// writer make table inet ranet3 a table nf_tables refuses the exit's write
// over with EOPNOTSUPP, an orphaned persistent one, and delete it again a
// moment later, over and over, until the kernel has refused raceRefusals of
// the exit's writes. On a kernel that has connection labels the label stays
// on: once ready again the exit's translations set it as before, it warns of
// no label refused, its debug view reads it on, and a down's rules drop a
// labelled flow's packet in each family.
func TestKernelExitKeepsItsLabelWhileAnotherWriterRacesItsTable(t *testing.T) {
	nft := asRootWithNft(t)
	lines := &syncedLines{}
	logtest.SetDefault(t, slog.New(slog.NewTextHandler(lines, nil)))
	network := egresstest.Namespaces(t)
	host := network.Exit()
	host.Done = host.Lanes.Done()
	cfg := egress.Egress{Advertise: []schema.Prefix{schema.MustPrefix("0.0.0.0/0"), schema.MustPrefix("::/0")}, Sweep: schema.Duration(time.Hour)}
	exit, _ := runExit(t, host, cfg)
	ready := func() bool { v4, v6 := host.Lanes.EgressReady(); return v4 && v6 }
	waitFor(t, "both families ready", ready)
	labelling := func() int {
		t.Helper()
		listing, err := nftIn(host, nft, "", "list", "chain", "inet", nftables.Table, kernelexit.ChainName)
		if err != nil {
			t.Fatalf("list the translation's chain: %v", err)
		}
		return strings.Count(listing, "ct label set 127")
	}
	labelled := labelling()
	if labelled == 0 {
		t.Fatal("before the race no translation sets the label")
	}

	// NFT_TABLE_F_OWNER and NFT_TABLE_F_PERSIST: the table outlives the socket
	// that made it, owned by none
	const owner, persist = 0x2, 0x4
	made := nftables.Request{Kind: nftables.Command(unix.NFT_MSG_NEWTABLE), Flags: unix.NLM_F_CREATE,
		Body: nftables.PutAttrBE32(netlink.PutAttrString(nftables.PutNfgenmsg(nil, unix.NFPROTO_INET), unix.NFTA_TABLE_NAME, nftables.Table), unix.NFTA_TABLE_FLAGS, owner|persist)}
	refused := func() int {
		n := 0
		for line := range strings.Lines(lines.String()) {
			if strings.Contains(line, "egress pass failed") && strings.Contains(line, unix.EOPNOTSUPP.Error()) {
				n++
			}
		}
		return n
	}
	cycles, persisted, started := 0, 0, time.Now()
	if err := exitThread(t, host).Do(func() error {
		conn, err := nftables.Dial()
		if err != nil {
			return err
		}
		defer conn.Close()
		for refused() < raceRefusals && time.Since(started) < 4*kernelexit.PassWait && (persisted != 0 || cycles < 200) {
			cycles++
			_ = conn.Batch([]nftables.Request{nftables.DeleteTable(unix.NFPROTO_INET, nftables.Table)})
			setter, err := nftables.Dial()
			if err != nil {
				return err
			}
			if setter.Batch([]nftables.Request{made}) == nil {
				persisted++
			}
			_ = setter.Close()
			time.Sleep(rand.N(raceMade))
			_ = conn.Batch([]nftables.Request{nftables.DeleteTable(unix.NFPROTO_INET, nftables.Table)})
			time.Sleep(rand.N(raceDeleted))
		}
		return nil
	}); err != nil {
		t.Fatalf("race the exit's table: %v", err)
	}
	if persisted == 0 {
		t.Skip("the kernel made no persistent table, so no write of the exit's meets one")
	}
	t.Logf("%d cycles in %s, %d persistent tables made, %d of the exit's writes refused", cycles, time.Since(started).Round(time.Millisecond), persisted, refused())
	if refused() < raceRefusals {
		t.Errorf("the kernel refused %d of the exit's writes in %d cycles, want %d, so the race tried the label too few times", refused(), cycles, raceRefusals)
	}
	waitFor(t, "both families ready after the race", ready)
	if got := labelling(); got != labelled {
		t.Errorf("after the race %d translations set the label, want the %d of before", got, labelled)
	}
	if strings.Contains(lines.String(), "egress cannot label the flows it translates") {
		t.Errorf("the exit warned that it cannot label:\n%s", lines.String())
	}
	if why := debugRead(t, host, exit).Unlabelled; why != "" {
		t.Errorf("the debug view reads the label off for %q", why)
	}
	exit.SetEnabled(false)
	waitFor(t, "the stop in effect", func() bool { return exit.Status().Unready == "the translator is stopped" })
	listing, err := nftIn(host, nft, "", "list", "table", "inet", nftables.Table)
	if err != nil {
		t.Fatalf("list the table: %v", err)
	}
	if got := strings.Count(listing, "ct label 127 counter"); got != 2 {
		t.Errorf("the stop's rules read the label in %d lines, want the drop of a labelled flow's packet in each family:\n%s", got, listing)
	}
}

// TestKernelExitDownNamesTheFlagOfItsTableMadeAgain takes an exit down, then
// has another program delete table inet ranet3, the stopped rules with it, and
// make it again in the same transaction with the owner and persist flags, and
// close its socket, so the table outlives it under persist and the kernel
// refuses the exit's writes into it with EOPNOTSUPP. Another writer then makes
// untranslated4 in the table without the interval flag and holds it from a
// chain of its own, and each stop's fault names the flag ahead of that set.
// The stop the change wakes and each retry after it are refused, and the stop
// goes on retrying: each warning and egress.pass event names in its err the
// refusal beside the fault the readback found, and the events count a retry
// among their triggers. A stop whose write came before the socket closed is
// refused with the kernel's EPERM, its readback finding the owner's flag among
// the flags where it came before the close too, and the table orphaned where
// it came after it. A stop whose write came after the close is refused with
// EOPNOTSUPP and finds the table orphaned. Of an orphaned table the test reads
// the whole fault, which names the delete that clears the flag, and of a table
// read before the close the flags alone, leaving what clears them to the
// nftables package's tests. Once a stop after the close has run, Status names
// its refusal, its fault and the empty chain forward in the reason, which
// still says the translator is stopping, and the refusal and the same faults
// in the error, with no rule counted. A shutdown over the tun, which outlives
// the mesh, returns that refusal and the orphaned table's fault.
func TestKernelExitDownNamesTheFlagOfItsTableMadeAgain(t *testing.T) {
	nft := asRootWithNft(t)
	lines := &syncedLines{}
	logtest.SetDefault(t, slog.New(slog.NewTextHandler(lines, nil)))
	network := egresstest.Namespaces(t)
	host := network.Exit()
	// ahead of the exit's end, so it runs after it: a shutdown over the tun
	// leaves what the table holds
	t.Cleanup(func() { _, _ = nftIn(host, nft, "", "delete", "table", "inet", nftables.Table) })
	// the mesh is the network's to close, so the tun outlives the exit's
	// shutdown, which closed starts
	closed := make(chan struct{})
	host.Done = closed
	mesh, bus := host.Lanes, events.New()
	hooks := egress.Hooks{Ready: func(v4, v6, _ bool) { mesh.SetEgressReady(v4, v6); mesh.SetAdvertisedReady(v4, v6) }, Republish: func() {}, Events: bus}
	cfg := egress.Egress{Advertise: []schema.Prefix{schema.MustPrefix("0.0.0.0/0"), schema.MustPrefix("::/0")}, Sweep: schema.Duration(time.Hour)}
	exit := newKernelExit(t, host, cfg, hooks).(*kernelexit.Translator)
	// the table made again holds no chain, so the readback finds forward empty
	emptied := "its chain forward holds [], where [" + exit.ChainSpecs(kernelexit.LimitChain, true) + "] was written"
	ctx, cancel := context.WithCancel(context.Background())
	ran := make(chan error, 1)
	go func() { ran <- exit.Run(ctx) }()
	shutdown := sync.OnceValue(func() error {
		cancel()
		close(closed)
		select {
		case err := <-ran:
			return err
		case <-time.After(kernelexit.PassWait):
			t.Errorf("the exit's Run had not returned %s after its context ended", kernelexit.PassWait)
			return nil
		}
	})
	t.Cleanup(func() { _ = shutdown() })
	waitFor(t, "both families ready", func() bool { v4, v6 := mesh.EgressReady(); return v4 && v6 })
	exit.SetEnabled(false)
	waitFor(t, "the stop in effect", func() bool { return exit.Status().Unready == "the translator is stopped" })
	passes := func() []control.Event {
		return bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "egress.pass" }, 0)
	}
	// mark is the number of the last egress.pass event before the change
	var mark uint64
	for _, event := range passes() {
		mark = max(mark, event.Seq)
	}

	// NFT_TABLE_F_OWNER and NFT_TABLE_F_PERSIST, the table made again in the
	// transaction that deletes it, so no write of the exit's comes between
	const owner, persist = 0x2, 0x4
	made := nftables.Request{Kind: nftables.Command(unix.NFT_MSG_NEWTABLE), Flags: unix.NLM_F_CREATE,
		Body: nftables.PutAttrBE32(netlink.PutAttrString(nftables.PutNfgenmsg(nil, unix.NFPROTO_INET), unix.NFTA_TABLE_NAME, nftables.Table), unix.NFTA_TABLE_FLAGS, owner|persist)}
	if err := exitThread(t, host).Do(func() error {
		setter, err := nftables.Dial()
		if err != nil {
			return err
		}
		defer setter.Close()
		return setter.Batch([]nftables.Request{nftables.DeleteTable(unix.NFPROTO_INET, nftables.Table), made})
	}); err != nil {
		t.Fatalf("make the table again with the flags %#x: %v", owner|persist, err)
	}
	// a set the write would be refused on too, the flag named ahead of it
	held := fmt.Sprintf("add set inet %[1]s untranslated4 { type ipv4_addr; }\nadd chain inet %[1]s other\nadd rule inet %[1]s other ip saddr @untranslated4 counter\n", nftables.Table)
	if _, err := nftIn(host, nft, held, "-f", "-"); err != nil {
		t.Fatalf("make untranslated4 in the table without the interval flag and hold it from the chain other: %v", err)
	}
	// The owner flag goes with the socket, which the Do closed, and persist
	// keeps the table. The change wakes the stop, which can read the table
	// before that close: then it finds the owner's socket open and the kernel
	// refuses its write with EPERM, and the readback after the refusal finds
	// either. Every stop that reads after the close finds the table orphaned,
	// refused with EOPNOTSUPP. The readback's fault is the nftables package's
	// text: a record names it whole, and of a fault read before the close the
	// test holds the flags the stop read, and leaves the owner's remedy after
	// them to that package's tests.
	const (
		ownedFlags = "its table carries flags 0x6, "
		orphaned   = "its table carries flags 0x4, where none are written and 0x1 is dormant, and only nft delete table inet " + nftables.Table + " clears another"
		readBack   = ", then the stopped rules read back other than written: "
	)
	stopping := "the translator is stopping: the host refused the stopped rules, which are not in place: " + orphaned + ", and " + emptied
	isOwned := func(fault string) bool { return strings.HasPrefix(fault, ownedFlags) }
	isOrphaned := func(fault string) bool { return fault == orphaned+", and "+emptied }
	// refusedAs is whether err is a stop's refused with errno, its rules then
	// read back with a fault that fault takes
	refusedAs := func(err string, errno error, fault func(string) bool) bool {
		refusal, found, ok := strings.Cut(err, readBack)
		return ok && strings.HasPrefix(refusal, "install rules: ") && strings.Contains(refusal, errno.Error()) && fault(found)
	}
	// refused is whether err is a stop's refused over what the table held as
	// it read it, before the close or after
	refused := func(err string) bool {
		return refusedAs(err, unix.EPERM, isOwned) || refusedAs(err, unix.EPERM, isOrphaned) || refusedAs(err, unix.EOPNOTSUPP, isOrphaned)
	}
	// named is whether Status reads a stop after the close, which every later
	// stop is
	named := func() bool {
		s := exit.Status()
		return s.Unready == stopping && refusedAs(s.Err, unix.EOPNOTSUPP, isOrphaned) && s.Rules.Installed == 0
	}
	waitFor(t, "a refused stop after the close naming the flag", named)
	// warned is the err of each warning of a stop not taken, and recorded the
	// trigger and the err of each egress.pass event from the change on
	warned := func() []string {
		var out []string
		for line := range strings.Lines(lines.String()) {
			if _, attrs, ok := strings.Cut(line, `level=WARN msg="egress could not stop its chains, retrying" err="`); ok {
				err, _, _ := strings.Cut(attrs, `" retry_in=`)
				out = append(out, err)
			}
		}
		return out
	}
	recorded := func() (triggers, errs []string) {
		for _, event := range passes() {
			if event.Seq > mark {
				triggers, errs = append(triggers, event.Attrs["trigger"]), append(errs, event.Attrs["err"])
			}
		}
		return triggers, errs
	}
	// the change's wake, then 2 retries the refusal takes
	waitFor(t, "the stop retried twice", func() bool { return len(warned()) >= 3 })
	if errs := warned(); slices.ContainsFunc(errs, func(err string) bool { return !refused(err) }) {
		t.Errorf("the retries warned with the errors %q, want each the refusal beside the flags read and what clears them", errs)
	}
	// the first event after the change among them
	triggers, errs := recorded()
	if !slices.Contains(triggers, "retry") || slices.ContainsFunc(errs, func(err string) bool { return !refused(err) }) {
		t.Errorf("the stops from the change on recorded egress.pass with the triggers %q and the errors %q, want retries among them and each the refusal beside the flags read and what clears them", triggers, errs)
	}
	if !named() {
		s := exit.Status()
		t.Errorf("after the retries Status reads %q, the error %q and %d installed, want %q, the refusal beside the flag and none", s.Unready, s.Err, s.Rules.Installed, stopping)
	}
	err := shutdown()
	if err == nil || !strings.HasPrefix(err.Error(), "the shutdown saw no write of the stopped rules taken: ") ||
		!refusedAs(strings.TrimPrefix(err.Error(), "the shutdown saw no write of the stopped rules taken: "), unix.EOPNOTSUPP, isOrphaned) {
		t.Errorf("the shutdown over the tun returned %v, want no write taken, the refusal beside the flag and its delete", err)
	}
	if s := exit.Status(); s.Unready != stopping || !refusedAs(s.Err, unix.EOPNOTSUPP, isOrphaned) {
		t.Errorf("after the shutdown Status reads %q and the error %q, want %q and the refusal beside the flag", s.Unready, s.Err, stopping)
	}
}

// TestKernelExitDownOverAHeldSetItMustDeleteKeepsTheRunningRules runs an exit
// that translates both families and puts no source under none. No rule of the
// exit's reads untranslated4 or untranslated6 then. Another writer deletes one
// of them, makes it again without the interval flag and holds it from a chain
// of its own, in one transaction. It takes untranslated4 in one case and
// untranslated6 in a second. In a third case it holds untranslated6 and makes
// untranslated4 again beside it, held by nothing. In a fourth it holds
// untranslated4 under 600 classes that translate, whose refusal's
// acknowledgments can overflow the socket. In a fifth, and in a sixth under
// 600 classes, it holds untranslated4 and adds to forward and forward6 decoys,
// rules that only count under the comments of the stopped rules a running exit
// lacks. In a seventh it holds untranslated6 beside a chain it makes under the
// name of an earlier version's chain, and in an eighth beside a ct timeout it
// makes under the name of an earlier version's timeout, neither held by
// anything. In a ninth it holds untranslated4 and makes the table dormant, a
// flag the write would clear. The stop's write must delete a set another
// writer holds. The host refuses the whole write. A down leaves the table with
// the running rules, the decoys where there are any, and none of the stopped
// rules. A shutdown over the tun, which outlives the exit, leaves it the same.
// Each error names the write's answer, the held set and its holder. Status's
// reason says the stopped rules are not in place and names the held set and
// its holder, then the dormant flag where the table carries it, then chain
// forward holding the running rules. It names the host's refusal where the
// answer read as one, which an overflow under 600 classes can hide. Status
// never reads the translator stopped.
func TestKernelExitDownOverAHeldSetItMustDeleteKeepsTheRunningRules(t *testing.T) {
	nft := asRootWithNft(t)
	// sets is the key and the source match of each set another writer makes
	// again
	sets := map[string]struct{ key, source string }{
		"untranslated4": {"ipv4_addr", "ip saddr"},
		"untranslated6": {"ipv6_addr", "ip6 saddr"},
	}
	for _, c := range []struct {
		name    string
		remade  []string
		set     string
		classes int
		// decoys is whether another writer adds to forward and forward6 the
		// rules that only count under the comments of the stopped rules a
		// running exit lacks, extra what else it makes, and named what a
		// pass's reason names from then on
		decoys       bool
		extra, named string
	}{
		{"untranslated4", []string{"untranslated4"}, "untranslated4", 0, false, "", ""},
		{"untranslated6", []string{"untranslated6"}, "untranslated6", 0, false, "", ""},
		{"untranslated4 stale beside untranslated6 held", []string{"untranslated4", "untranslated6"}, "untranslated6", 0, false, "", ""},
		{"untranslated4 under 600 classes", []string{"untranslated4"}, "untranslated4", 600, false, "", ""},
		{"untranslated4 beside decoys", []string{"untranslated4"}, "untranslated4", 0, true, "", ""},
		{"untranslated4 beside decoys under 600 classes", []string{"untranslated4"}, "untranslated4", 600, true, "", ""},
		{"a stray chain beside untranslated6 held", []string{"untranslated6"}, "untranslated6", 0, false,
			fmt.Sprintf("add chain inet %s %s4\n", nftables.Table, kernelexit.LimitChain), "chain " + kernelexit.LimitChain + "4"},
		{"an earlier version's timeout beside untranslated6 held", []string{"untranslated6"}, "untranslated6", 0, false,
			fmt.Sprintf("add ct timeout inet %s translated-udp4 { protocol udp; l3proto ip; policy = { unreplied : 30, replied : 60 }; }\n", nftables.Table), "ct timeout translated-udp4"},
		{"untranslated4 held in a dormant table", []string{"untranslated4"}, "untranslated4", 0, false,
			fmt.Sprintf("add table inet %s { flags dormant; }\n", nftables.Table), "flags 0x1"},
	} {
		t.Run(c.name, func(t *testing.T) {
			lines := &syncedLines{}
			logtest.SetDefault(t, slog.New(slog.NewTextHandler(lines, nil)))
			network := egresstest.Namespaces(t)
			host := network.Exit()
			// The mesh is the network's to close, and the tun outlives the exit's
			// shutdown, whose wait for the mesh ends once closed is closed.
			closed := make(chan struct{})
			host.Done = closed
			mesh := host.Lanes
			hooks := egress.Hooks{Ready: func(v4, v6, _ bool) { mesh.SetEgressReady(v4, v6); mesh.SetAdvertisedReady(v4, v6) }, Republish: func() {}}
			cfg := egress.Egress{Advertise: []schema.Prefix{schema.MustPrefix("0.0.0.0/0"), schema.MustPrefix("::/0")}, Sweep: schema.Duration(time.Hour)}
			// a class that translates for each of as many /32 sources, whose
			// lines make the stop's write large enough that its acknowledgments
			// can overflow the socket
			from := netip.MustParseAddr("10.0.0.0")
			for range c.classes {
				from = from.Next()
				cfg.Translate = append(cfg.Translate, egress.Class{From: schema.MustPrefix(netip.PrefixFrom(from, 32).String()), To: egress.Translation{Auto: true}})
			}
			exit := newKernelExit(t, host, cfg, hooks).(*kernelexit.Translator)
			ctx, cancel := context.WithCancel(context.Background())
			ran := make(chan error, 1)
			go func() { ran <- exit.Run(ctx) }()
			shutdown := sync.OnceValue(func() error {
				cancel()
				close(closed)
				select {
				case err := <-ran:
					return err
				case <-time.After(kernelexit.PassWait):
					t.Errorf("the exit's Run had not returned %s after its context ended", kernelexit.PassWait)
					return nil
				}
			})
			t.Cleanup(func() { _ = shutdown() })
			waitFor(t, "both families ready", func() bool { v4, v6 := mesh.EgressReady(); return v4 && v6 })

			list := func() string {
				t.Helper()
				listing, err := nftIn(host, nft, "", "list", "table", "inet", nftables.Table)
				if err != nil {
					t.Fatalf("list the table: %v", err)
				}
				return listing
			}
			commented := regexp.MustCompile(`(?m)^\s+\S.* comment "([^"]*)"$`)
			// ruleComments is the comment of each rule of listing, sorted
			ruleComments := func(listing string) []string {
				var out []string
				for _, m := range commented.FindAllStringSubmatch(listing, -1) {
					out = append(out, m[1])
				}
				slices.Sort(out)
				return out
			}
			listing := list()
			for _, set := range c.remade {
				if strings.Contains(listing, "@"+set) {
					t.Fatalf("a rule of the running exit's reads %s, which the test needs unread:\n%s", set, listing)
				}
			}
			running := ruleComments(listing)
			if !slices.ContainsFunc(running, func(rule string) bool { return strings.Contains(rule, " limit ") }) {
				t.Fatalf("the running exit's table holds the rules %q, want each family's limit among them", running)
			}

			const holder = "other"
			var remade strings.Builder
			for _, set := range c.remade {
				fmt.Fprintf(&remade, "delete set inet %[1]s %[2]s\nadd set inet %[1]s %[2]s { type %[3]s; }\n", nftables.Table, set, sets[set].key)
			}
			fmt.Fprintf(&remade, "add chain inet %[1]s %[2]s\nadd rule inet %[1]s %[2]s %[3]s @%[4]s counter\n", nftables.Table, holder, sets[c.set].source, c.set)
			remade.WriteString(c.extra)
			if c.decoys {
				// the comment of each stopped rule a running exit lacks, over a counter alone
				for _, in := range []struct{ chain, family string }{{kernelexit.LimitChain, "ipv4"}, {"forward6", "ipv6"}} {
					for _, comment := range []string{"out via %s %s dropped while stopped", "translated via %s %s leaving by another link dropped while stopped"} {
						comment = fmt.Sprintf(comment, host.TUN, in.family)
						fmt.Fprintf(&remade, "add rule inet %s %s counter comment %q\n", nftables.Table, in.chain, comment)
						running = append(running, comment)
					}
				}
				slices.Sort(running)
			}
			if _, err := nftIn(host, nft, remade.String(), "-f", "-"); err != nil {
				t.Fatalf("make %q again and hold %s from the chain %s: %v", c.remade, c.set, holder, err)
			}
			named := cmp.Or(c.named, c.set)
			waitFor(t, "a pass naming "+named, func() bool { return strings.Contains(exit.Status().Unready, named) })
			if c.decoys {
				// the refused pass leaves them as they were
				if got := ruleComments(list()); !slices.Equal(got, running) {
					t.Fatalf("after the refused pass the table holds the rules %q, want the running exit's and the decoys %q", got, running)
				}
			}

			// answers is the errors a refused write can answer with: EBUSY, and
			// under many classes ENOBUFS, where its acknowledgments overflow
			answers := []string{unix.EBUSY.Error()}
			// reasons is the starts a refused stop's reason can read
			reasons := []string{"the translator is stopping: the host refused the stopped rules, which are not in place: its set " + c.set + " "}
			if c.classes > 0 {
				answers = append(answers, unix.ENOBUFS.Error())
				reasons = append(reasons, "the translator is stopping: the stopped rules are not in place: its set "+c.set+" ")
			}
			// refusedOver is whether err is a stop's refused, its rules then
			// read back with the held set and its holder named
			refusedOver := func(err string) bool {
				refusal, fault, ok := strings.Cut(err, ", then the stopped rules read back other than written: ")
				return ok && strings.HasPrefix(refusal, "install rules: ") && slices.ContainsFunc(answers, func(answer string) bool { return strings.Contains(refusal, answer) }) &&
					strings.HasPrefix(fault, "its set "+c.set+" ") && strings.Contains(fault, "chain "+holder+" holds a rule using it")
			}
			// after follows the set and its holder in the reason: the dormant
			// flag where the table carries it, then chain forward
			after := ", so it stays until that rule goes, and its chain " + kernelexit.LimitChain + " holds ["
			if c.named == "flags 0x1" {
				after = ", so it stays until that rule goes, and its table carries flags 0x1, where none are written and 0x1 is dormant, and its chain " + kernelexit.LimitChain + " holds ["
			}
			// refusalRead is whether Status reads a refused stop, with the
			// stopped rules not in place, the set and its holder in the reason,
			// then after, and the write's answer, the set and its holder in the
			// error
			refusalRead := func(s egress.Status) bool {
				return slices.ContainsFunc(reasons, func(reason string) bool { return strings.HasPrefix(s.Unready, reason) }) &&
					strings.Contains(s.Unready, "chain "+holder+" holds a rule using it"+after) && refusedOver(s.Err)
			}
			// stoppedRead holds whether any read of Status from the down on read the
			// translator stopped
			var stoppedRead atomic.Bool
			watching, watched := make(chan struct{}), make(chan struct{})
			go func() {
				defer close(watched)
				tick := time.NewTicker(stoppedPoll)
				defer tick.Stop()
				for {
					if exit.Status().Unready == "the translator is stopped" {
						stoppedRead.Store(true)
					}
					select {
					case <-watching:
						return
					case <-tick.C:
					}
				}
			}()
			// warned is the err of each warning of a stop that returned an error
			warned := func() []string {
				var out []string
				for line := range strings.Lines(lines.String()) {
					if _, attrs, ok := strings.Cut(line, `level=WARN msg="egress could not stop its chains, retrying" err="`); ok {
						err, _, _ := strings.Cut(attrs, `" retry_in=`)
						out = append(out, err)
					}
				}
				return out
			}

			exit.SetEnabled(false)
			waitFor(t, "the down's stop recorded", func() bool {
				u := exit.Status().Unready
				return u == "the translator is stopped" || strings.HasPrefix(u, "the translator is stopping: ")
			})
			s := exit.Status()
			if !refusalRead(s) {
				t.Errorf("after the refused down Status reads %q and the error %q, want the reason to start with one of %q and name the chain %s and then %q, and the refusal beside the set and its holder", s.Unready, s.Err, reasons, holder, after)
			} else if c.classes == 0 {
				// the down's stop, then 2 retries the refusal takes
				waitFor(t, "the stop tried 3 times", func() bool { return len(warned()) >= 3 })
				if errs := warned(); slices.ContainsFunc(errs, func(err string) bool { return !refusedOver(err) }) {
					t.Errorf("the down's stops warned with the errors %q, want each the refusal beside the set and its holder", errs)
				}
				if s = exit.Status(); !refusalRead(s) {
					t.Errorf("after the retries Status reads %q and the error %q, want the reason to start with one of %q and name the chain %s and then %q, and the refusal beside the set and its holder", s.Unready, s.Err, reasons, holder, after)
				}
			}
			t.Logf("after the down Status reads %q and the error %q", s.Unready, s.Err)
			if got := ruleComments(list()); !slices.Equal(got, running) {
				t.Errorf("after the refused down the table holds the rules %q, want the running exit's rules and any decoys %q, and none of the stopped ones", got, running)
			}

			err := shutdown()
			const unTaken = "the shutdown saw no write of the stopped rules taken: "
			if err == nil || !strings.HasPrefix(err.Error(), unTaken) || !refusedOver(strings.TrimPrefix(err.Error(), unTaken)) {
				t.Errorf("the shutdown over the tun returned %v, want no write taken and the refusal beside the set and its holder", err)
			}
			if s := exit.Status(); !refusalRead(s) {
				t.Errorf("after the shutdown Status reads %q and the error %q, want the reason to start with one of %q and name the chain %s and then %q, and the refusal beside the set and its holder", s.Unready, s.Err, reasons, holder, after)
			}
			if got := ruleComments(list()); !slices.Equal(got, running) {
				t.Errorf("after the shutdown the table holds the rules %q, want the running exit's rules and any decoys %q, and none of the stopped ones", got, running)
			}
			close(watching)
			<-watched
			if stoppedRead.Load() {
				t.Errorf("Status read the translator stopped while the host refused each stop")
			}
		})
	}
}

// The faults a stop names of another writer's change: held4 and held6 of
// untranslated4 and untranslated6 as heldSet makes them, dormantFault of the
// table's dormant flag, strayFault of an earlier version's chain forward4
// that a rule of the chain other goes to, and the reason's and the error's
// heads
const (
	held4Fault   = `its set untranslated4 reads back with key type 7 of 4 bytes, flags 0x0, size 0 and comment "", where key type 7 of 4 bytes, flags 0x4, size 0 and comment "" were written, and chain other holds a rule using it, so it stays until that rule goes`
	held6Fault   = `its set untranslated6 reads back with key type 8 of 16 bytes, flags 0x0, size 0 and comment "", where key type 8 of 16 bytes, flags 0x4, size 0 and comment "" were written, and chain other holds a rule using it, so it stays until that rule goes`
	dormantFault = "its table carries flags 0x1, where none are written and 0x1 is dormant"
	strayFault   = "its chain forward4 is not one the translator writes, and chain other holds a rule going to it, so it stays until that rule goes"
	refusedOut   = "the host refused the stopped rules, which are not in place: "
	outOfPlace   = "the stopped rules are not in place: "
	readBackAs   = ", then the stopped rules read back other than written: "
	faultedAs    = "the stopped rules read back other than written: "
)

// labelOf reads the label of a labelled flow in a listing of the table
var labelOf = regexp.MustCompile(`ct label (?:set )?(\d+)`)

// handled is a line of what nft -a lists of a chain, its text and its handle
var handled = regexp.MustCompile(`(?m)^\s+(\S.*) # handle (\d+)$`)

// heldSet is another writer's change that deletes the set named set, makes it
// again without the interval flag, holding elements, and holds it from the
// chain other, a set the stop's write must delete
func heldSet(set string, elements ...string) string {
	key, source := "ipv4_addr", "ip saddr"
	if strings.HasSuffix(set, "6") {
		key, source = "ipv6_addr", "ip6 saddr"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "delete set inet %[1]s %[2]s\nadd set inet %[1]s %[2]s { type %[3]s; }\n", nftables.Table, set, key)
	if len(elements) > 0 {
		fmt.Fprintf(&b, "add element inet %s %s { %s }\n", nftables.Table, set, strings.Join(elements, ", "))
	}
	fmt.Fprintf(&b, "add chain inet %[1]s other\nadd rule inet %[1]s other %[2]s @%[3]s counter\n", nftables.Table, source, set)
	return b.String()
}

// stopCopies is the stopped rules a running exit lacks, with their
// expressions and comments as the exit writes them, appended to chain for each
// family, each family's own chain at the forward hook where chain is empty,
// each family's after the line ahead where it is not empty
func stopCopies(tun, label, chain, ahead string) string {
	var b strings.Builder
	for _, c := range []struct{ chain, family string }{{kernelexit.LimitChain, "ipv4"}, {"forward6", "ipv6"}} {
		in := cmp.Or(chain, c.chain)
		if ahead != "" {
			fmt.Fprintf(&b, "add rule inet %s %s %s\n", nftables.Table, in, ahead)
		}
		fmt.Fprintf(&b, "add rule inet %s %s iifname %q oifname != %q counter drop comment \"out via %s %s dropped while stopped\"\n", nftables.Table, in, tun, tun, tun, c.family)
		fmt.Fprintf(&b, "add rule inet %s %s oifname != %q ct label %s counter drop comment \"translated via %s %s leaving by another link dropped while stopped\"\n", nftables.Table, in, tun, label, tun, c.family)
	}
	return b.String()
}

// putBack is another writer's change that takes out the lines of chain, as
// listing lists it with handles, that look up set, makes set again without
// the interval flag holding element, holds it from the chain other, and puts
// the lines back where they were, each as nft lists it, ahead of the line
// after the last of them
func putBack(t *testing.T, listing, chain, set, element string) string {
	t.Helper()
	lines := handled.FindAllStringSubmatch(listing, -1)
	lines = slices.DeleteFunc(lines, func(line []string) bool { return strings.HasSuffix(line[1], "{") })
	var using [][]string
	after := ""
	for i, line := range lines {
		if strings.Contains(line[1], "@"+set) {
			using = append(using, line)
			after = ""
			if i+1 < len(lines) {
				after = lines[i+1][2]
			}
		}
	}
	if len(using) == 0 || after == "" {
		t.Fatalf("the chain %s holds no line looking up %s with a line after it:\n%s", chain, set, listing)
	}
	var b strings.Builder
	for _, line := range using {
		fmt.Fprintf(&b, "delete rule inet %s %s handle %s\n", nftables.Table, chain, line[2])
	}
	b.WriteString(heldSet(set, element))
	for _, line := range using {
		fmt.Fprintf(&b, "insert rule inet %s %s position %s %s\n", nftables.Table, chain, after, line[1])
	}
	return b.String()
}

// retimed is another writer's change that gives the timeout object udp4 other
// seconds and holds it from the chain other: each line of postrouting, as
// listing lists it with handles, that attaches udp4 attaches an object of the
// writer's in its place, and udp4 is deleted and made again
func retimed(t *testing.T, listing string) string {
	t.Helper()
	const object = `{ protocol udp; l3proto ip; policy = { unreplied : 7, replied : 11 }; }`
	var b strings.Builder
	fmt.Fprintf(&b, "add ct timeout inet %s stopheld %s\n", nftables.Table, object)
	replaced := 0
	for _, line := range handled.FindAllStringSubmatch(listing, -1) {
		if strings.Contains(line[1], `ct timeout set "udp4"`) {
			fmt.Fprintf(&b, "replace rule inet %s %s handle %s %s\n", nftables.Table, kernelexit.ChainName, line[2], strings.Replace(line[1], `"udp4"`, `"stopheld"`, 1))
			replaced++
		}
	}
	if replaced == 0 {
		t.Fatalf("no line of the chain %s attaches udp4:\n%s", kernelexit.ChainName, listing)
	}
	fmt.Fprintf(&b, "delete ct timeout inet %[1]s udp4\nadd ct timeout inet %[1]s udp4 %[2]s\n", nftables.Table, object)
	fmt.Fprintf(&b, "add chain inet %[1]s other\nadd rule inet %[1]s other meta l4proto udp ct timeout set \"udp4\"\n", nftables.Table)
	return b.String()
}

// refilled is the fault of the set named set, written holding the prefix
// none alone, that reads back holding the address leaf beside it
func refilled(set string, leaf netip.Addr, none netip.Prefix) string {
	held := []string{leaf.String(), none.String()}
	if none.Addr().Less(leaf) {
		held[0], held[1] = held[1], held[0]
	}
	return fmt.Sprintf("its set %s holds { %s }, where { %s } was written", set, strings.Join(held, ", "), none)
}

// newFlowFrom is where the server read a new UDP datagram of the leaf's in
// family from, sent from the port as far past leafDownPort as port is past
// downPort, the zero value where it read nothing within downQuiet
func newFlowFrom(t *testing.T, network egresstest.Network, family egresstest.Family, port uint16) netip.AddrPort {
	t.Helper()
	f := &downFlow{family: family}
	to := netip.AddrPortFrom(family.Server, port)
	if err := network.Server(func() (err error) {
		f.server, err = net.ListenUDP("udp", net.UDPAddrFromAddrPort(to))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.server.Close() })
	if err := network.Leaf(func() (err error) {
		f.leafUDP, err = net.DialUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(family.Leaf, leafDownPort+port-downPort)), net.UDPAddrFromAddrPort(to))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.leafUDP.Close() })
	if _, err := f.leafUDP.Write([]byte("fresh")); err != nil {
		t.Fatal(err)
	}
	from, _ := f.arrived("fresh", downQuiet)
	return from
}

// waitRead waits PassWait for exit's Status to hold ok, failing t with the
// last read where it never does
func waitRead(t *testing.T, exit *kernelexit.Translator, what string, ok func(egress.Status) bool) {
	t.Helper()
	for deadline := time.Now().Add(kernelexit.PassWait); ; time.Sleep(waitPoll) {
		s := exit.Status()
		if ok(s) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("waited %s for %s, and Status reads %q and the error %q", kernelexit.PassWait, what, s.Unready, s.Err)
		}
	}
}

// stopWriter holds the parts of another writer's change: the tun, the label
// the exit's rules read, the leaf's address in IPv4 and in IPv6, and a read of
// nft -a's listing of a chain of the table
type stopWriter struct {
	tun, label string
	leaf       [2]netip.Addr
	chain      func(name string) string
}

// TestKernelExitDownSaysWhetherAPacketMeetsItsStoppedRules runs an exit that
// translates both families, puts the sources of the prefix none under none
// where it names one, and has another writer change its table, before the
// down or after a stop the host took. The stopped rules are in place only
// where the table is not dormant and each of the translator's chains reads
// back with its type, hook, priority and policy and the stopped rules alone,
// line for line, and each set and object a stopped line uses reads back as
// written, a set with its elements. Where they are not, a leaf's new flow
// leaves the exit in a family the change opens, and Status's reason says they
// are not in place, after the refusal where the host refused the stop: it
// names what the write is refused on, then the dormant flag, then the first
// chain, set or object read back otherwise than written, each once. The
// error, each retry's warning and the shutdown over the tun, which outlives
// the exit, name the same faults, after the write's answer where it was not
// taken. Where the stop's write is taken over a change that keeps them in
// place, as a held stray chain does, the reason names the fault without
// those words, and no flow leaves.
func TestKernelExitDownSaysWhetherAPacketMeetsItsStoppedRules(t *testing.T) {
	nft := asRootWithNft(t)
	none4, none6 := netip.MustParsePrefix("198.18.0.0/24"), netip.MustParsePrefix("100::/64")
	// holds is the fault of chain holding the lines held where written was
	// written, each list a chain's fault's
	holds := func(chain, held, written string) string {
		return "its chain " + chain + " holds [" + held + "], where [" + written + "] was written"
	}
	// copied is the comments of stopCopies's lines in IPv4's chain
	copied := func(tun string) string {
		return "out via " + tun + " ipv4 dropped while stopped; translated via " + tun + " ipv4 leaving by another link dropped while stopped"
	}
	// specs reads a chain's comments as ChainSpecs gives them, stopped or
	// running, and leaf the leaf's addresses
	type read struct {
		specs func(chain string, stopped bool) string
		tun   string
		leaf  [2]netip.Addr
	}
	for i, c := range []struct {
		name string
		// none is the class of none of each family, none where it is invalid
		none    [2]netip.Prefix
		classes int
		// stopFirst takes a stop before the change, which script makes
		stopFirst bool
		script    func(t *testing.T, w stopWriter) string
		// pass, where it is not empty, is a text the running pass's reason
		// holds after the change, and that reason never names the dormant flag
		pass string
		// stopped is whether the down reads the translator stopped. Otherwise
		// head follows "the translator is stopping: ", and then parts, joined
		// by ", and ", and what rest holds where it is not nil
		stopped bool
		head    string
		parts   func(r read) []string
		rest    func(r read, after string) bool
		// leaves is whether a leaf's new flow of IPv4 and of IPv6 leaves the
		// exit while down
		leaves [2]bool
	}{
		{name: "copies after an accept", script: func(_ *testing.T, w stopWriter) string {
			return heldSet("untranslated4") + stopCopies(w.tun, w.label, "", "counter accept")
		}, head: refusedOut, parts: func(r read) []string {
			return []string{held4Fault, holds(kernelexit.LimitChain, r.specs(kernelexit.LimitChain, false)+"; ; "+copied(r.tun), r.specs(kernelexit.LimitChain, true))}
		}, leaves: [2]bool{true, true}},
		{name: "copies after an accept under 600 classes", classes: 600, script: func(_ *testing.T, w stopWriter) string {
			return heldSet("untranslated4") + stopCopies(w.tun, w.label, "", "counter accept")
		}, head: refusedOut, parts: func(r read) []string {
			return []string{held4Fault, holds(kernelexit.LimitChain, r.specs(kernelexit.LimitChain, false)+"; ; "+copied(r.tun), r.specs(kernelexit.LimitChain, true))}
		}, leaves: [2]bool{true, true}},
		{name: "copies after a goto", script: func(_ *testing.T, w stopWriter) string {
			return heldSet("untranslated4") + fmt.Sprintf("add chain inet %s stopempty\n", nftables.Table) + stopCopies(w.tun, w.label, "", "counter goto stopempty")
		}, head: refusedOut, parts: func(r read) []string {
			return []string{held4Fault, holds(kernelexit.LimitChain, r.specs(kernelexit.LimitChain, false)+"; ; "+copied(r.tun), r.specs(kernelexit.LimitChain, true))}
		}, leaves: [2]bool{true, true}},
		{name: "copies in a chain no hook reaches", script: func(_ *testing.T, w stopWriter) string {
			return heldSet("untranslated4") + fmt.Sprintf("add chain inet %s stopcopies\n", nftables.Table) + stopCopies(w.tun, w.label, "stopcopies", "")
		}, head: refusedOut, parts: func(r read) []string {
			return []string{held4Fault, holds(kernelexit.LimitChain, r.specs(kernelexit.LimitChain, false), r.specs(kernelexit.LimitChain, true))}
		}, leaves: [2]bool{true, true}},
		{name: "an accept ahead of the stopped rules after a taken stop", stopFirst: true, script: func(*testing.T, stopWriter) string {
			return heldSet("untranslated4") + fmt.Sprintf("insert rule inet %s %s counter accept\n", nftables.Table, kernelexit.LimitChain)
		}, head: refusedOut, parts: func(r read) []string {
			return []string{held4Fault, holds(kernelexit.LimitChain, "; "+r.specs(kernelexit.LimitChain, true), r.specs(kernelexit.LimitChain, true))}
		}, leaves: [2]bool{true, true}},
		{name: "a dormant table, first stop", script: func(*testing.T, stopWriter) string {
			return heldSet("untranslated4") + fmt.Sprintf("add table inet %s { flags dormant; }\n", nftables.Table)
		}, head: refusedOut, parts: func(r read) []string {
			return []string{held4Fault, dormantFault, holds(kernelexit.LimitChain, r.specs(kernelexit.LimitChain, false), r.specs(kernelexit.LimitChain, true))}
		}, leaves: [2]bool{true, true}},
		{name: "a dormant table after a taken stop", stopFirst: true, script: func(*testing.T, stopWriter) string {
			return heldSet("untranslated4") + fmt.Sprintf("add table inet %s { flags dormant; }\n", nftables.Table)
		}, head: refusedOut, parts: func(read) []string { return []string{held4Fault, dormantFault} }, leaves: [2]bool{true, true}},
		{name: "a dormant table alone after a taken stop", stopFirst: true, script: func(*testing.T, stopWriter) string {
			return fmt.Sprintf("add table inet %s { flags dormant; }\n", nftables.Table)
		}, stopped: true},
		{name: "a held stray chain beside a held set in a dormant table", script: func(*testing.T, stopWriter) string {
			return heldSet("untranslated4") + fmt.Sprintf("add table inet %[1]s { flags dormant; }\nadd chain inet %[1]s forward4\nadd rule inet %[1]s other jump forward4\n", nftables.Table)
		}, pass: strayFault, head: refusedOut, parts: func(r read) []string {
			return []string{held4Fault, dormantFault, holds(kernelexit.LimitChain, r.specs(kernelexit.LimitChain, false), r.specs(kernelexit.LimitChain, true))}
		}, leaves: [2]bool{true, true}},
		{name: "a held stray chain alone in a dormant table", script: func(*testing.T, stopWriter) string {
			return fmt.Sprintf("add table inet %[1]s { flags dormant; }\nadd chain inet %[1]s forward4\nadd chain inet %[1]s other\nadd rule inet %[1]s other jump forward4\n", nftables.Table)
		}, pass: strayFault, parts: func(read) []string { return []string{strayFault} }},
		{name: "a stopped rule rewritten under its comment after a taken stop", stopFirst: true, script: func(t *testing.T, w stopWriter) string {
			comment := fmt.Sprintf(`comment "out via %s ipv4 dropped while stopped"`, w.tun)
			for _, line := range handled.FindAllStringSubmatch(w.chain(kernelexit.LimitChain), -1) {
				if strings.HasSuffix(line[1], comment) {
					return heldSet("untranslated4") + fmt.Sprintf("replace rule inet %s %s handle %s iifname %q oifname != %q counter accept %s\n", nftables.Table, kernelexit.LimitChain, line[2], w.tun, w.tun, comment)
				}
			}
			t.Fatalf("no line of the chain %s carries the %s", kernelexit.LimitChain, comment)
			return ""
		}, head: refusedOut, parts: func(read) []string { return []string{held4Fault} }, rest: func(r read, after string) bool {
			return strings.HasPrefix(after, ", and its chain "+kernelexit.LimitChain+"'s line out via "+r.tun+" ipv4 dropped while stopped: ")
		}, leaves: [2]bool{true, false}},
		{name: "an accept at the head of forward6 alone after a taken stop", stopFirst: true, script: func(*testing.T, stopWriter) string {
			return heldSet("untranslated4") + fmt.Sprintf("insert rule inet %s forward6 counter accept\n", nftables.Table)
		}, head: refusedOut, parts: func(r read) []string {
			return []string{held4Fault, holds("forward6", "; "+r.specs("forward6", true), r.specs("forward6", true))}
		}, leaves: [2]bool{false, true}},
		{name: "a line in postrouting after a taken stop", stopFirst: true, script: func(*testing.T, stopWriter) string {
			return heldSet("untranslated4") + fmt.Sprintf("add rule inet %s %s counter\n", nftables.Table, kernelexit.ChainName)
		}, head: refusedOut, parts: func(r read) []string {
			return []string{held4Fault, holds(kernelexit.ChainName, r.specs(kernelexit.ChainName, true)+"; ", r.specs(kernelexit.ChainName, true))}
		}},
		{name: "forward's policy changed after a taken stop", stopFirst: true, script: func(*testing.T, stopWriter) string {
			return heldSet("untranslated4") + fmt.Sprintf("add chain inet %s %s { type filter hook forward priority 0; policy drop; }\n", nftables.Table, kernelexit.LimitChain)
		}, head: refusedOut, parts: func(read) []string {
			return []string{held4Fault, `its chain forward reads back as type "filter" at hook 2, priority 0, policy 0, where a filter chain at hook 2, priority 0, policy accept was written`}
		}},
		{name: "untranslated4 refilled with the leaf beside untranslated6 held after a taken stop", none: [2]netip.Prefix{none4}, stopFirst: true, script: func(_ *testing.T, w stopWriter) string {
			return heldSet("untranslated6") + fmt.Sprintf("add element inet %s untranslated4 { %s }\n", nftables.Table, w.leaf[0])
		}, head: refusedOut, parts: func(r read) []string { return []string{held6Fault, refilled("untranslated4", r.leaf[0], none4)} }, leaves: [2]bool{true, false}},
		{name: "untranslated4 refilled with the leaf alone after a taken stop", none: [2]netip.Prefix{none4}, stopFirst: true, script: func(_ *testing.T, w stopWriter) string {
			return fmt.Sprintf("add element inet %s untranslated4 { %s }\n", nftables.Table, w.leaf[0])
		}, stopped: true},
		{name: "untranslated6 refilled with the leaf beside untranslated4 held after a taken stop", none: [2]netip.Prefix{{}, none6}, stopFirst: true, script: func(_ *testing.T, w stopWriter) string {
			return heldSet("untranslated4") + fmt.Sprintf("add element inet %s untranslated6 { %s }\n", nftables.Table, w.leaf[1])
		}, head: refusedOut, parts: func(r read) []string { return []string{held4Fault, refilled("untranslated6", r.leaf[1], none6)} }, leaves: [2]bool{false, true}},
		{name: "untranslated4 made again with the leaf and held, its lines put back, after a taken stop", none: [2]netip.Prefix{none4}, stopFirst: true, script: func(t *testing.T, w stopWriter) string {
			return putBack(t, w.chain(kernelexit.LimitChain), kernelexit.LimitChain, "untranslated4", w.leaf[0].String())
		}, head: refusedOut, parts: func(read) []string { return []string{held4Fault} }, leaves: [2]bool{true, false}},
		{name: "untranslated6 made again with the leaf and held, its lines put back, after a taken stop", none: [2]netip.Prefix{{}, none6}, stopFirst: true, script: func(t *testing.T, w stopWriter) string {
			return putBack(t, w.chain("forward6"), "forward6", "untranslated6", w.leaf[1].String())
		}, head: refusedOut, parts: func(read) []string { return []string{held6Fault} }, leaves: [2]bool{false, true}},
		{name: "a held timeout object with other seconds after a taken stop", stopFirst: true, script: func(t *testing.T, w stopWriter) string {
			return retimed(t, w.chain(kernelexit.ChainName))
		}, head: outOfPlace, parts: func(read) []string { return nil }, rest: func(_ read, after string) bool {
			return strings.HasPrefix(after, "its ct timeout udp4 reads back as ") && strings.HasSuffix(after, ", and chain other holds a rule using it, so it stays until that rule goes")
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			lines := &syncedLines{}
			logtest.SetDefault(t, slog.New(slog.NewTextHandler(lines, nil)))
			network := egresstest.Namespaces(t)
			host := network.Exit()
			families := []egresstest.Family{network.Family(false), network.Family(true)}
			var current atomic.Pointer[kernelexit.Translator]
			downCarry(network, current.Load)
			// the mesh is the network's to close, so the tun outlives the exit's
			// shutdown, which closed starts
			closed := make(chan struct{})
			host.Done = closed
			mesh := host.Lanes
			hooks := egress.Hooks{Ready: func(v4, v6, _ bool) { mesh.SetEgressReady(v4, v6); mesh.SetAdvertisedReady(v4, v6) }, Republish: func() {}}
			cfg := egress.Egress{Advertise: []schema.Prefix{schema.MustPrefix("0.0.0.0/0"), schema.MustPrefix("::/0")}, Sweep: schema.Duration(time.Hour)}
			for _, prefix := range c.none {
				if prefix.IsValid() {
					cfg.Translate = append(cfg.Translate, egress.Class{From: schema.MustPrefix(prefix.String()), To: egress.Translation{None: true}})
				}
			}
			from := netip.MustParseAddr("10.0.0.0")
			for range c.classes {
				from = from.Next()
				cfg.Translate = append(cfg.Translate, egress.Class{From: schema.MustPrefix(netip.PrefixFrom(from, 32).String()), To: egress.Translation{Auto: true}})
			}
			exit := newKernelExit(t, host, cfg, hooks).(*kernelexit.Translator)
			current.Store(exit)
			r := read{tun: host.TUN, leaf: [2]netip.Addr{families[0].Leaf, families[1].Leaf}}
			specs := map[bool]map[string]string{}
			for _, stopped := range []bool{false, true} {
				specs[stopped] = map[string]string{}
				for _, chain := range []string{kernelexit.LimitChain, "forward6", kernelexit.ChainName} {
					specs[stopped][chain] = exit.ChainSpecs(chain, stopped)
				}
			}
			r.specs = func(chain string, stopped bool) string { return specs[stopped][chain] }
			ctx, cancel := context.WithCancel(context.Background())
			ran := make(chan error, 1)
			go func() { ran <- exit.Run(ctx) }()
			shutdown := sync.OnceValue(func() error {
				cancel()
				close(closed)
				select {
				case err := <-ran:
					return err
				case <-time.After(kernelexit.PassWait):
					t.Errorf("the exit's Run had not returned %s after its context ended", kernelexit.PassWait)
					return nil
				}
			})
			t.Cleanup(func() { _ = shutdown() })
			waitFor(t, "both families ready", func() bool { v4, v6 := mesh.EgressReady(); return v4 && v6 })
			listing, err := nftIn(host, nft, "", "list", "table", "inet", nftables.Table)
			if err != nil {
				t.Fatalf("list the table: %v", err)
			}
			label := labelOf.FindStringSubmatch(listing)
			if label == nil {
				t.Fatalf("no line of the table reads a label:\n%s", listing)
			}
			w := stopWriter{tun: host.TUN, label: label[1], leaf: r.leaf, chain: func(name string) string {
				t.Helper()
				out, err := nftIn(host, nft, "", "-a", "list", "chain", "inet", nftables.Table, name)
				if err != nil {
					t.Fatalf("list the chain %s: %v", name, err)
				}
				return out
			}}
			// stopsLogged is how many stops logged their rules written
			stopsLogged := func() int { return strings.Count(lines.String(), `msg="egress translator stopped"`) }
			if c.stopFirst {
				exit.SetEnabled(false)
				waitFor(t, "the first stop in effect", func() bool { return exit.Status().Unready == "the translator is stopped" })
			}
			script := c.script(t, w)
			if _, err := nftIn(host, nft, script, "-f", "-"); err != nil {
				t.Fatalf("another writer's change: %v\n%s", err, script)
			}
			if !c.stopFirst {
				waitRead(t, exit, "the running pass to read the change", func(s egress.Status) bool {
					v4, _ := mesh.EgressReady()
					return !v4 && (c.pass == "" || strings.Contains(s.Unready, c.pass) || strings.Contains(s.Unready, "flags 0x1"))
				})
				if s := exit.Status(); c.pass != "" && (!strings.Contains(s.Unready, c.pass) || strings.Contains(s.Unready, "flags 0x1")) {
					t.Errorf("the running pass reads %q, want it to name %q and not the dormant flag", s.Unready, c.pass)
				}
				exit.SetEnabled(false)
			}

			// answers is the starts of the error of a write that was not taken,
			// heads the starts of the reason's text past its stopping
			refused := c.head == refusedOut || c.classes > 0
			answers := []string{"install rules: " + unix.EBUSY.Error()}
			heads := []string{c.head}
			if c.classes > 0 {
				answers = append(answers, "install rules: "+unix.ENOBUFS.Error())
				heads = append(heads, outOfPlace)
			}
			var parts []string
			if c.parts != nil {
				parts = c.parts(r)
			}
			// named reports whether text is the reason past its head
			named := func(text string) bool {
				joined := strings.Join(parts, ", and ")
				if c.rest == nil {
					return text == joined
				}
				after, ok := strings.CutPrefix(text, joined)
				return ok && c.rest(r, after)
			}
			// errs is whether err is the down's error
			errs := func(err string) bool {
				if !refused {
					text, ok := strings.CutPrefix(err, faultedAs)
					return ok && named(text)
				}
				answer, text, ok := strings.Cut(err, readBackAs)
				return ok && slices.Contains(answers, answer) && named(text)
			}
			// reads is whether s reads the down
			reads := func(s egress.Status) bool {
				if c.stopped {
					return s.Unready == "the translator is stopped" && s.Err == ""
				}
				return slices.ContainsFunc(heads, func(head string) bool {
					text, ok := strings.CutPrefix(s.Unready, "the translator is stopping: "+head)
					return ok && named(text)
				}) && errs(s.Err)
			}
			if c.stopped {
				// the stop the change wakes logs its write
				waitFor(t, "the stop the change wakes", func() bool { return stopsLogged() >= 2 })
			}
			waitRead(t, exit, "the down's reason and error", reads)
			s := exit.Status()
			t.Logf("the down reads %q and the error %q", s.Unready, s.Err)
			for j, family := range families {
				port := downPort + uint16(10*i+j)
				if got := newFlowFrom(t, network, family, port); got.IsValid() != c.leaves[j] {
					t.Errorf("a new %s flow of the leaf's read at the server from %s, want it to leave %v", family.Name, got, c.leaves[j])
				}
			}
			// warned is the err of each warning of a stop that returned an error
			warned := func() []string {
				var out []string
				for line := range strings.Lines(lines.String()) {
					if _, attrs, ok := strings.Cut(line, `level=WARN msg="egress could not stop its chains, retrying" err=`); ok {
						quoted, err := strconv.QuotedPrefix(attrs)
						if err != nil {
							out = append(out, attrs)
							continue
						}
						text, _ := strconv.Unquote(quoted)
						out = append(out, text)
					}
				}
				return out
			}
			if !c.stopped && c.classes == 0 {
				// the down's stop, then 2 retries
				waitFor(t, "the stop tried 3 times", func() bool { return len(warned()) >= 3 })
				if got := warned(); slices.ContainsFunc(got, func(err string) bool { return !errs(err) }) {
					t.Errorf("the stops warned with the errors %q, want each the down's", got)
				}
				if s := exit.Status(); !reads(s) {
					t.Errorf("after the retries Status reads %q and the error %q", s.Unready, s.Err)
				}
			}

			err = shutdown()
			const unTaken = "the shutdown saw no write of the stopped rules taken: "
			logged := lines.String()
			inPlace := strings.Count(logged, `level=WARN msg="egress left its stopped rules at shutdown"`) == 1 && strings.Contains(logged, "they hold the exit as ranet3 down does")
			outOf := strings.Count(logged, `level=WARN msg="egress left its stopped rules at shutdown, which did not read back in place"`) == 1
			switch {
			case c.stopped:
				if err != nil || !inPlace || outOf {
					t.Errorf("the shutdown over the tun returned %v, warned that it left the stopped rules in place %v and out of place %v, want no error and in place", err, inPlace, outOf)
				}
			case refused:
				if text, ok := strings.CutPrefix(fmt.Sprint(err), unTaken); !ok || !errs(text) || inPlace || outOf {
					t.Errorf("the shutdown over the tun returned %v, want no write taken and the down's error, and no warning of the rules left", err)
				}
			default:
				// a write taken over a fault, out of place where the reason says so
				placed := c.head == ""
				if err == nil || !errs(err.Error()) || inPlace != placed || outOf == placed {
					t.Errorf("the shutdown over the tun returned %v, warned that it left the stopped rules in place %v and out of place %v, want the down's error and in place %v", err, inPlace, outOf, placed)
				}
			}
		})
	}
}

// syncedLines is a log a handler writes while the test reads it
type syncedLines struct {
	mu    sync.Mutex
	lines strings.Builder
}

func (l *syncedLines) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lines.Write(p)
}

func (l *syncedLines) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lines.String()
}

// waitFor waits PassWait for ok, failing t where it never holds
func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(kernelexit.PassWait); !ok(); time.Sleep(waitPoll) {
		if time.Now().After(deadline) {
			t.Fatalf("waited %s for %s", kernelexit.PassWait, what)
		}
	}
}

// nftIn runs nft in the exit's namespace with stdin, answering what it
// printed
func nftIn(host egresstest.Host, nft, stdin string, args ...string) (string, error) {
	var out []byte
	err := host.Do(func() error {
		cmd := exec.Command(nft, args...)
		cmd.Stdin = strings.NewReader(stdin)
		var err error
		if out, err = cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("nft %s: %w: %s", strings.Join(args, " "), err, out)
		}
		return nil
	})
	return string(out), err
}

// downAddresses adds or deletes each of addresses on the exit's tun
func downAddresses(host egresstest.Host, addresses []netip.Prefix, change func(netnstest.Netlink, int, netip.Prefix) error) error {
	return host.Do(func() error {
		link, err := net.InterfaceByName(host.TUN)
		if err != nil {
			return err
		}
		conn, err := netnstest.OpenNetlink()
		if err != nil {
			return err
		}
		defer conn.Close()
		for _, address := range addresses {
			if err := change(conn, link.Index, address); err != nil {
				return fmt.Errorf("%s: %w", address, err)
			}
		}
		return nil
	})
}

// typedRoute is the body of a request for a route of kind, such as
// unix.RTN_UNREACHABLE, to the address to alone in the main table
func typedRoute(to netip.Addr, kind byte) []byte {
	family := byte(unix.AF_INET6)
	if to.Is4() {
		family = unix.AF_INET
	}
	header := []byte{family, byte(to.BitLen()), 0, 0, unix.RT_TABLE_MAIN, unix.RTPROT_BOOT, unix.RT_SCOPE_UNIVERSE, kind, 0, 0, 0, 0}
	return slices.Concat(header, netnstest.Attr(unix.RTA_DST, to.AsSlice()))
}

// refusedOption is the frame of the leaf's datagram from from to to carrying an
// option the host answers with a parameter problem: over IPv4 a record route
// whose length, 2, leaves no room for its pointer, padded by a no-operation and
// the end of the options, and over IPv6 a hop-by-hop option of type 0x9e, which
// RFC 4727 keeps for experiments and whose two high bits ask a host that does
// not know it for that error
func refusedOption(from, to netip.AddrPort) []byte {
	udp := egresstest.UDPMessage(from, to, []byte("an option"))
	if from.Addr().Is4() {
		return egresstest.PacketFrame(from.Addr(), to.Addr(), unix.IPPROTO_UDP, []byte{7, 2, 1, 0}, udp)
	}
	return egresstest.PacketFrame(from.Addr(), to.Addr(), unix.IPPROTO_HOPOPTS, nil, slices.Concat([]byte{unix.IPPROTO_UDP, 0, 0x9e, 4, 0, 0, 0, 0}, udp))
}

// firstFragment is the frame of the first fragment of the leaf's IPv6 datagram
// from from to to, whose other fragments never come: offset 0 with more to
// follow, carrying the datagram's first 24 octets, a multiple of 8 as every
// fragment but the last is
func firstFragment(from, to netip.AddrPort) []byte {
	udp := egresstest.UDPMessage(from, to, make([]byte, 32))
	return egresstest.PacketFrame(from.Addr(), to.Addr(), unix.IPPROTO_FRAGMENT, nil, slices.Concat([]byte{unix.IPPROTO_UDP, 0, 0, 1, 0, 0, 0, 1}, udp[:24]))
}

// downFlow is a UDP flow toward the server in one family, of the leaf's or
// the exit's host's, with a TCP connection of the leaf's beside it where there
// is one, and where the server read the UDP flow from
type downFlow struct {
	family            egresstest.Family
	leafUDP, server   *net.UDPConn
	mapped            netip.AddrPort
	leafTCP, accepted net.Conn
}

// openDownUDP opens a UDP flow from source in family to the server's port,
// made where in runs, the leaf's namespace or the exit's, from the port as far
// past leafDownPort as port is past downPort, with its first datagram, closed
// at the end of t
func openDownUDP(t *testing.T, network egresstest.Network, in func(func() error) error, source netip.Addr, family egresstest.Family, port uint16) *downFlow {
	t.Helper()
	f := &downFlow{family: family}
	to := netip.AddrPortFrom(family.Server, port)
	if err := network.Server(func() (err error) {
		f.server, err = net.ListenUDP("udp", net.UDPAddrFromAddrPort(to))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.server.Close() })
	if err := in(func() (err error) {
		f.leafUDP, err = net.DialUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(source, leafDownPort+port-downPort)), net.UDPAddrFromAddrPort(to))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.leafUDP.Close() })
	f.mapped = f.sent(t, "opened")
	return f
}

// openDownFlow opens family's UDP flow of the leaf's as openDownUDP does and a
// TCP connection beside it, to the same port, closed at the end of t
func openDownFlow(t *testing.T, network egresstest.Network, family egresstest.Family, port uint16) *downFlow {
	t.Helper()
	f := openDownUDP(t, network, network.Leaf, family.Leaf, family, port)
	to := netip.AddrPortFrom(family.Server, port)
	var listener net.Listener
	if err := network.Server(func() (err error) {
		listener, err = net.Listen("tcp", to.String())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan net.Conn, 1)
	go func() {
		if conn, err := listener.Accept(); err == nil {
			accepted <- conn
		}
	}()
	if err := network.Leaf(func() (err error) {
		f.leafTCP, err = net.DialTimeout("tcp", to.String(), kernelexit.PassWait)
		return err
	}); err != nil {
		t.Fatalf("the leaf's %s connection: %v", family.Name, err)
	}
	t.Cleanup(func() { _ = f.leafTCP.Close() })
	select {
	case f.accepted = <-accepted:
	case <-time.After(kernelexit.PassWait):
		t.Fatalf("the server accepted no %s connection", family.Name)
	}
	t.Cleanup(func() { _ = f.accepted.Close() })
	return f
}

// sent has the leaf send data on its UDP flow and answers where the server
// read it from
func (f *downFlow) sent(t *testing.T, data string) netip.AddrPort {
	t.Helper()
	if _, err := f.leafUDP.Write([]byte(data)); err != nil {
		t.Fatal(err)
	}
	from, read := f.arrived(data, kernelexit.PassWait)
	if !read {
		t.Fatalf("the server read nothing of the leaf's %s datagram %q within %s", f.family.Name, data, kernelexit.PassWait)
	}
	return from
}

// reply has the server send data on the UDP flow and on the connection where
// there is one
func (f *downFlow) reply(t *testing.T, data string) {
	t.Helper()
	if _, err := f.server.WriteToUDPAddrPort([]byte(data), f.mapped); err != nil {
		t.Fatalf("the server's %s datagram: %v", f.family.Name, err)
	}
	if f.accepted == nil {
		return
	}
	if _, err := f.accepted.Write([]byte(data)); err != nil {
		t.Fatalf("the server's %s write: %v", f.family.Name, err)
	}
}

// heard answers the data the leaf reads on each of its flows within wait,
// empty where it reads nothing
func (f *downFlow) heard(wait time.Duration) (udp, tcp string) {
	buf := make([]byte, 256)
	_ = f.leafUDP.SetReadDeadline(time.Now().Add(wait))
	if n, err := f.leafUDP.Read(buf); err == nil {
		udp = string(buf[:n])
	}
	_ = f.leafTCP.SetReadDeadline(time.Now().Add(wait))
	if n, err := f.leafTCP.Read(buf); err == nil {
		tcp = string(buf[:n])
	}
	return udp, tcp
}

// arrived answers where the server read data on the UDP flow from within
// wait, and whether it read it
func (f *downFlow) arrived(data string, wait time.Duration) (netip.AddrPort, bool) {
	buf := make([]byte, 64)
	_ = f.server.SetReadDeadline(time.Now().Add(wait))
	for {
		n, from, err := f.server.ReadFromUDPAddrPort(buf)
		if err != nil {
			return netip.AddrPort{}, false
		}
		if string(buf[:n]) == data {
			return netip.AddrPortFrom(from.Addr().Unmap(), from.Port()), true
		}
	}
}

// resumed fails t unless both flows carry each way once the exit is up again:
// the leaf's datagram reaches the server from the address it was read from
// before the down, the server's datagram after up reaches the leaf, and the
// connection carries the leaf's write and the server's writes, those of the
// down retransmitted ahead of the one after up
func (f *downFlow) resumed(t *testing.T) {
	t.Helper()
	if from := f.sent(t, "after up"); from != f.mapped {
		t.Errorf("after up the server read the leaf's %s datagram from %s, want %s as before the down", f.family.Name, from, f.mapped)
	}
	f.reply(t, "after up")
	buf := make([]byte, 256)
	_ = f.leafUDP.SetReadDeadline(time.Now().Add(kernelexit.PassWait))
	if n, err := f.leafUDP.Read(buf); err != nil || string(buf[:n]) != "after up" {
		t.Errorf("after up the leaf read %q (%v) on its %s UDP flow, want the server's datagram after up", buf[:n], err, f.family.Name)
	}
	var stream []byte
	_ = f.leafTCP.SetReadDeadline(time.Now().Add(kernelexit.PassWait))
	for !bytes.HasSuffix(stream, []byte("after up")) {
		n, err := f.leafTCP.Read(buf)
		if err != nil {
			t.Errorf("after up the leaf's %s connection read %q, then %v, want the server's writes through the one after up", f.family.Name, stream, err)
			break
		}
		stream = append(stream, buf[:n]...)
	}
	if _, err := f.leafTCP.Write([]byte("leaf after up")); err != nil {
		t.Errorf("the leaf's %s write after up: %v", f.family.Name, err)
	}
	read := make([]byte, len("leaf after up"))
	_ = f.accepted.SetReadDeadline(time.Now().Add(kernelexit.PassWait))
	if _, err := io.ReadFull(f.accepted, read); err != nil || string(read) != "leaf after up" {
		t.Errorf("after up the server's %s connection read %q (%v), want the leaf's write", f.family.Name, read, err)
	}
}
