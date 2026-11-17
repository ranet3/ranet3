// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/egress/egresstest"
	kernelexit "ranet3.com/pkgs/ranet3/internal/egress/kernel"
	"ranet3.com/pkgs/ranet3/internal/logtest"
	"ranet3.com/pkgs/ranet3/internal/netlink"
	"ranet3.com/pkgs/ranet3/internal/netnstest"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/nftables"
	"ranet3.com/pkgs/ranet3/schema"
)

const (
	// downWait is how long a down's test waits for what it expects, generous
	// for a loaded machine
	downWait = 30 * time.Second
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
)

// exitModules are the modules the kernel exit's rules use, which a root test
// that runs it finds loaded or skips, and downModules those of a down's test,
// whose mesh is a tun and whose uplink a veth
var (
	exitModules = []string{"nf_tables", "nf_conntrack", "nf_nat", "nft_ct", "nft_nat", "nft_masq", "nft_chain_nat", "nft_connlimit", "nf_conncount", "nft_reject_inet"}
	downModules = append([]string{"tun", "veth"}, exitModules...)
)

// downCounters reads the packets of each rule of a counting table by its
// comment
var downCounters = regexp.MustCompile(`counter packets (\d+) bytes \d+ comment "(\w+)"`)

// needModules skips t unless /proc/modules lists each of names, so the test
// loads no module of its own
func needModules(t *testing.T, names ...string) {
	t.Helper()
	raw, err := os.ReadFile("/proc/modules")
	if err != nil {
		t.Skipf("the modules loaded cannot be read: %v", err)
	}
	loaded := map[string]bool{}
	for line := range strings.Lines(string(raw)) {
		name, _, _ := strings.Cut(line, " ")
		loaded[name] = true
	}
	for _, name := range names {
		if !loaded[name] {
			t.Skipf("the module %s is not loaded, and the test loads none", name)
		}
	}
}

// downTools skips t unless it runs as root with nft on the path and each
// module of downModules loaded, and answers nft's path
func downTools(t *testing.T) string {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("a tun and a network namespace need root on linux")
	}
	nft, err := exec.LookPath("nft")
	if err != nil {
		t.Skipf("what leaves the exit is counted through nft, which is not on the path: %v", err)
	}
	needModules(t, downModules...)
	return nft
}

// downCounting adds a table to host's namespace counting the packets to each
// family's overlay that leave by a link other than the tun, under the
// comments out4 and out6, and answers a read of the counts
func downCounting(t *testing.T, host egresstest.Host, nft string, families []egresstest.Family) func() map[string]int {
	t.Helper()
	count := fmt.Sprintf(`table inet downcount {
	chain post {
		type filter hook postrouting priority 200; policy accept;
		oifname != %q ip daddr %s counter comment "out4"
		oifname != %q ip6 daddr %s counter comment "out6"
	}
}
`, host.TUN, families[0].Overlay, host.TUN, families[1].Overlay)
	if _, err := downNft(host, nft, count, "-f", "-"); err != nil {
		t.Fatalf("add the counting table: %v", err)
	}
	return func() map[string]int {
		t.Helper()
		listing, err := downNft(host, nft, "", "list", "table", "inet", "downcount")
		if err != nil {
			t.Fatalf("list the counting table: %v", err)
		}
		read := map[string]int{}
		for _, match := range downCounters.FindAllStringSubmatch(listing, -1) {
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
			frames = append(frames, slices.Concat(make([]byte, netstack.TUNHeadroom), packet))
		}
		exit.Egress(frames, nil)
	})
}

// downExit builds the kernel exit for cfg on host as the daemon builds it, its
// readiness moving the mesh's, and runs it until its end, at the latest the
// end of t, which waits for Run and holds it to no error
func downExit(t *testing.T, host egresstest.Host, cfg egress.Egress) (*kernelexit.Translator, func()) {
	t.Helper()
	mesh := host.Lanes
	hooks := egress.Hooks{Ready: func(v4, v6, _ bool) { mesh.SetEgressReady(v4, v6); mesh.SetAdvertisedReady(v4, v6) }, Republish: func() {}}
	exit := newKernelExit(t, host, cfg, hooks).(*kernelexit.Translator)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- exit.Run(ctx) }()
	end := sync.OnceFunc(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("the exit's Run returned %v", err)
			}
		case <-time.After(downWait):
			t.Errorf("the exit's Run had not returned %s after its context ended", downWait)
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
	downAwait(t, "the stop in effect", func() bool { return exit.Status().Unready == "the translator is stopped" })
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
	nft := downTools(t)
	network := egresstest.Namespaces(t)
	host := network.Exit()
	families := []egresstest.Family{network.Family(false), network.Family(true)}
	filter := besideFilter(t, network)
	downAwait(t, "the antispoof filter ready", filter.Ready)
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
	cfg := egress.Egress{Advertise: []schema.Prefix{schema.MustPrefix("0.0.0.0/0"), schema.MustPrefix("::/0")}, Sweep: schema.Duration(time.Hour)}
	exit, _ := downExit(t, host, cfg)
	downCarry(network, func() *kernelexit.Translator { return exit })
	ready := func() bool { v4, v6 := host.Lanes.EgressReady(); return v4 && v6 }
	downAwait(t, "both families ready", ready)
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
	downAwait(t, "both families ready again", ready)
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
	nft := downTools(t)
	network := egresstest.Namespaces(t)
	host := network.Exit()
	families := []egresstest.Family{network.Family(false), network.Family(true)}
	counters := downCounting(t, host, nft, families)
	var current atomic.Pointer[kernelexit.Translator]
	downCarry(network, current.Load)
	advertise := []schema.Prefix{schema.MustPrefix("0.0.0.0/0"), schema.MustPrefix("::/0")}
	first, end := downExit(t, host, egress.Egress{Advertise: advertise, Sweep: schema.Duration(time.Hour)})
	current.Store(first)
	downAwait(t, "both families ready in the first run", func() bool { v4, v6 := host.Lanes.EgressReady(); return v4 && v6 })
	flow := openDownFlow(t, network, families[1], downPort)
	// the first run's end withdraws its chains, and leaves the tun and the
	// flow's binding with its label
	end()
	second, _ := downExit(t, host, egress.Egress{Advertise: advertise[:1], Sweep: schema.Duration(time.Hour)})
	current.Store(second)
	downAwait(t, "IPv4 alone ready in the second run", func() bool {
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
	downTools(t)
	network := egresstest.Namespaces(t)
	host := network.Exit()
	families := []egresstest.Family{network.Family(false), network.Family(true)}
	var current atomic.Pointer[kernelexit.Translator]
	downCarry(network, current.Load)
	advertise := []schema.Prefix{schema.MustPrefix("0.0.0.0/0"), schema.MustPrefix("::/0")}
	first, end := downExit(t, host, egress.Egress{Advertise: advertise, Sweep: schema.Duration(time.Hour)})
	current.Store(first)
	ready := func() bool { v4, v6 := host.Lanes.EgressReady(); return v4 && v6 }
	downAwait(t, "both families ready in the first run", ready)
	var flows []*downFlow
	var none []egress.Class
	for _, family := range families {
		flows = append(flows, openDownUDP(t, network, network.Leaf, family.Leaf, family, downPort))
		none = append(none, egress.Class{From: schema.MustPrefix(netip.PrefixFrom(family.Leaf, family.Leaf.BitLen()).String()), To: egress.Translation{None: true}})
	}
	// the first run's end withdraws its chains, and leaves the tun and the
	// flows' bindings with their labels
	end()
	second, _ := downExit(t, host, egress.Egress{Advertise: advertise, Translate: none, Sweep: schema.Duration(time.Hour)})
	current.Store(second)
	downAwait(t, "both families ready in the second run", ready)

	second.SetEnabled(false)
	downAwait(t, "the stop in effect", func() bool { return second.Status().Unready == "the translator is stopped" })
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

// TestKernelExitKeepsItsLabelWhileAnotherWriterRacesItsTable has another
// writer make table inet ranet3 a table nf_tables refuses the exit's write
// over with EOPNOTSUPP, an orphaned persistent one, and delete it again a
// moment later, over and over, until the kernel has refused raceRefusals of
// the exit's writes. On a kernel that has connection labels the label stays
// on: once ready again the exit's translations set it as before, it warns of
// no label refused, its debug view reads it on, and a down's rules drop a
// labelled flow's packet in each family.
func TestKernelExitKeepsItsLabelWhileAnotherWriterRacesItsTable(t *testing.T) {
	nft := downTools(t)
	lines := &syncedLines{}
	logtest.SetDefault(t, slog.New(slog.NewTextHandler(lines, nil)))
	network := egresstest.Namespaces(t)
	host := network.Exit()
	cfg := egress.Egress{Advertise: []schema.Prefix{schema.MustPrefix("0.0.0.0/0"), schema.MustPrefix("::/0")}, Sweep: schema.Duration(time.Hour)}
	exit, _ := downExit(t, host, cfg)
	ready := func() bool { v4, v6 := host.Lanes.EgressReady(); return v4 && v6 }
	downAwait(t, "both families ready", ready)
	labelling := func() int {
		t.Helper()
		listing, err := downNft(host, nft, "", "list", "chain", "inet", nftables.Table, kernelexit.ChainName)
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
		for refused() < raceRefusals && time.Since(started) < 4*downWait && (persisted != 0 || cycles < 200) {
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
	downAwait(t, "both families ready after the race", ready)
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
	downAwait(t, "the stop in effect", func() bool { return exit.Status().Unready == "the translator is stopped" })
	listing, err := downNft(host, nft, "", "list", "table", "inet", nftables.Table)
	if err != nil {
		t.Fatalf("list the table: %v", err)
	}
	if got := strings.Count(listing, "ct label 127 counter"); got != 2 {
		t.Errorf("the stop's rules read the label in %d lines, want the drop of a labelled flow's packet in each family:\n%s", got, listing)
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

// downAwait waits PassWait for ok, failing t where it never holds
func downAwait(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(downWait); !ok(); time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("waited %s for %s", downWait, what)
		}
	}
}

// downNft runs nft in the exit's namespace with stdin, answering what it
// printed
func downNft(host egresstest.Host, nft, stdin string, args ...string) (string, error) {
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
		f.leafTCP, err = net.DialTimeout("tcp", to.String(), downWait)
		return err
	}); err != nil {
		t.Fatalf("the leaf's %s connection: %v", family.Name, err)
	}
	t.Cleanup(func() { _ = f.leafTCP.Close() })
	select {
	case f.accepted = <-accepted:
	case <-time.After(downWait):
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
	buf := make([]byte, 64)
	_ = f.server.SetReadDeadline(time.Now().Add(downWait))
	for {
		n, from, err := f.server.ReadFromUDPAddrPort(buf)
		if err != nil {
			t.Fatalf("the server read nothing of the leaf's %s datagram %q: %v", f.family.Name, data, err)
		}
		if string(buf[:n]) == data {
			return netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		}
	}
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
	_ = f.leafUDP.SetReadDeadline(time.Now().Add(downWait))
	if n, err := f.leafUDP.Read(buf); err != nil || string(buf[:n]) != "after up" {
		t.Errorf("after up the leaf read %q (%v) on its %s UDP flow, want the server's datagram after up", buf[:n], err, f.family.Name)
	}
	var stream []byte
	_ = f.leafTCP.SetReadDeadline(time.Now().Add(downWait))
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
	_ = f.accepted.SetReadDeadline(time.Now().Add(downWait))
	if _, err := io.ReadFull(f.accepted, read); err != nil || string(read) != "leaf after up" {
		t.Errorf("after up the server's %s connection read %q (%v), want the leaf's write", f.family.Name, read, err)
	}
}
