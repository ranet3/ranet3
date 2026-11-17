// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel_test

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/client"
	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/egress/egresstest"
	kernelexit "ranet3.com/pkgs/ranet3/internal/egress/kernel"
	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/logtest"
	"ranet3.com/pkgs/ranet3/internal/netlink"
	"ranet3.com/pkgs/ranet3/internal/netnstest"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/nftables"
	"ranet3.com/pkgs/ranet3/schema"
)

// noTranslationPerEndpoint is why the kernel exit neither filters by address
// alone nor hairpins
const noTranslationPerEndpoint = "an external endpoint can name several leaves at once, and a map entry keeps the value it was made with, so no destination translation per endpoint holds"

// the kernel exit meets rows 1 to 6 of the exit behavior suite in both
// families, translating to its uplink's address under auto and to an address
// of its own under the address class, and leaving the leaf's own address under
// none, carries every protocol it can translate and refuses DCCP and UDP-Lite
// under a class that translates, holding each source to the share of flows
// its capability names, the default or another, but for the flows its count
// misses, with no total of its own beside conntrack's table
// its stop leaves no table of its name once the mesh's done channel closes, and every chain before, and its disabling
// every chain it held, its status reading the stop in effect
// it crosses stopCrossings stops and starts alone and beside another writer's empty nat chain at srcnat, and a
// source's flows end with their conntrack entries, deleted over ctnetlink, where the kernel holds forgetModule, and
// the step skips where it does not
// another writer's deletion of its table is the change it is held to notice
// the second owner of its table is the antispoof filter, and the reload a host firewall's flush of the ruleset
// another writer's masquerade is a nat chain at srcnat made after the exit's, or one below the exit's
// the idle timers are each flow's conntrack entry as the namespace lists it
func TestKernelExitPassesTheExitBehaviorSuite(t *testing.T) {
	// the frames across a stop fill the leaf's share, which forgetConntrack
	// frees after them, so where the kernel lacks its module the step skips
	skipped := ""
	if held, err := kernelHolds(forgetModule); !held {
		skipped = fmt.Sprintf("the step ends the leaf's flows over ctnetlink, whose module %s the kernel neither loaded nor built in (%v), and the test loads none", forgetModule, err)
	}
	egresstest.Run(t, egresstest.Namespaces, egresstest.Arm{
		Classes: []egresstest.Class{egresstest.Auto, egresstest.Address, egresstest.None},
		Limits: udpLiteBefore71(t, map[egresstest.Limit]egresstest.Declared{
			egresstest.PortDependentFiltering: {
				Reason: noTranslationPerEndpoint,
				Row:    "RFC 4787 section 5, RFC 5382 section 4.3, RFC 6888 section 3 (REQ-7)",
			},
			egresstest.NoHairpinning: {
				Reason: noTranslationPerEndpoint,
				Row:    "RFC 4787 section 6, RFC 5382 section 7.2, RFC 5508 section 5",
			},
			egresstest.ResetsUnsolicitedSYN: {
				Reason: "the exit leaves the host's answer to a SYN as the host gives it, since a rule dropping a SYN no socket takes would silence the host's own closed ports too",
				Row:    "RFC 5382 section 4.3 (REQ-4), RFC 5382 section 4.2 (REQ-2a)",
			},
			egresstest.UnansweredIPv4DCCP: {
				Reason: "the kernel's reject answers a DCCP packet only where it verifies its checksum, and it verifies an IPv4 one without the pseudo-header the checksum covers",
				Row:    "RFC 6888 section 3 (REQ-1), RFC 5508 section 6 (REQ-8), RFC 4443 section 3.1",
			},
			egresstest.OverloadsPorts: {
				Reason: "conntrack keeps a translated connection unique with its destination, and no nf_tables statement keeps an external port for 1 inside endpoint",
				Row:    "RFC 4787 section 4.2.1 (REQ-3), RFC 5382 section 7.1 (REQ-7)",
			},
			egresstest.RemapsOnClash: {
				Reason: "conntrack maps per connection, and no nf_tables statement pins 1 external port per inside endpoint",
				Row:    "RFC 4787 sections 4.1 and 8, RFC 5382 section 4.1",
			},
			egresstest.OverloadsTCPPorts: {
				Reason: "conntrack keeps a translated connection unique with its destination, and no nf_tables statement keeps an external port for 1 inside endpoint",
				Row:    "RFC 4787 section 4.2.1 (REQ-3), RFC 5382 section 7.1 (REQ-7)",
			},
			egresstest.RemapsTCPOnClash: {
				Reason: "conntrack maps per connection, and no nf_tables statement pins 1 external port per inside endpoint",
				Row:    "RFC 4787 sections 4.1 and 8, RFC 5382 section 4.1",
			},
		}),
		MissesFlows: &egresstest.Missed{
			Reason:    "the kernel's count of a source's flows can leave a flow open and uncounted",
			LimitsRow: "Flows of 1 mesh source the kernel exit's count misses",
		},
		New:              newKernelExit,
		Waits:            true,
		Holds:            kernelExitTables,
		Stopped:          func(s egress.Status) bool { return s.Unready == "the translator is stopped" },
		Crossings:        stopCrossings,
		Untranslating:    untranslatingAsAnotherWriter,
		Forget:           forgetConntrack,
		CrossingsSkipped: skipped,
		Remove:           deleteKernelExitTables,
		Beside:           besideFilter,
		Reload:           reloadFirewall,
		Masquerade:       masqueradeAsAnotherWriter,
		Flows:            conntrackFlows,
	})
}

// stopCrossings is how many stops and starts each class that translates
// crosses alone and again beside another writer's nat chain: a stop whose
// commit lets a frame out untranslated in a ninth of the stops leaks in one of
// them with a miss below 1 percent
const stopCrossings = 40

// udpLiteBefore71 is limits with UDP-Lite declared unanswered on a kernel
// before 7.1
func udpLiteBefore71(t *testing.T, limits map[egresstest.Limit]egresstest.Declared) map[egresstest.Limit]egresstest.Declared {
	t.Helper()
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		t.Fatalf("read the kernel's release: %v", err)
	}
	release := unix.ByteSliceToString(uts.Release[:])
	var major, minor int
	if _, err := fmt.Sscanf(release, "%d.%d", &major, &minor); err != nil {
		t.Fatalf("read the kernel's release %q: %v", release, err)
	}
	if major < 7 || major == 7 && minor < 1 {
		limits[egresstest.UnansweredUDPLite] = egresstest.Declared{
			Reason: "on a kernel before 7.1 connection tracking checks a UDP-Lite checksum against UDP's protocol number while nf_conntrack_checksum is on, its default, so it takes a valid packet for one no flow is tracked for, which the exit drops with no answer, and drops the reply into the mesh to one it carries under none",
			Row:    "RFC 6888 section 3 (REQ-1), RFC 5508 section 6 (REQ-8), RFC 4443 section 3.1",
		}
	}
	return limits
}

// phases is RFC 5382 section 5's phase of each TCP state conntrack lists:
// opening until each end's SYN is acknowledged, established until a FIN has
// gone each way, so in FIN_WAIT and CLOSE_WAIT with one, and closing in
// LAST_ACK, with TIME_WAIT and CLOSE outside REQ-5
var phases = map[string]egresstest.Phase{
	"SYN_SENT": egresstest.Opening, "SYN_RECV": egresstest.Opening, "SYN_SENT2": egresstest.Opening,
	"ESTABLISHED": egresstest.Established, "FIN_WAIT": egresstest.Established, "CLOSE_WAIT": egresstest.Established,
	"LAST_ACK": egresstest.Closing,
}

// conntrackFlows reads the exit's conntrack table from the listing /proc keeps
// of it, which holds each entry's state and seconds left as a ctnetlink dump
// does, with no module to load for it
func conntrackFlows(host egresstest.Host) ([]egresstest.Flow, error) {
	var listing []byte
	if err := host.Do(func() (err error) {
		listing, err = os.ReadFile("/proc/thread-self/net/nf_conntrack")
		return err
	}); err != nil {
		return nil, err
	}
	var flows []egresstest.Flow
	for line := range strings.Lines(string(listing)) {
		flow, err := conntrackFlow(strings.Fields(line))
		if err != nil {
			return nil, fmt.Errorf("conntrack lists %q: %w", line, err)
		}
		flows = append(flows, flow)
	}
	return flows, nil
}

// ctnetlink's request that deletes entries and the attributes forgetConntrack
// writes, as include/uapi/linux/netfilter/nfnetlink_conntrack.h numbers them,
// and the filter's flag for the original source, as net/netfilter's
// nf_internals.h does, which golang.org/x/sys/unix names none of
const (
	ctDelete           = 2
	ctaTupleOrig       = 1
	ctaFilter          = 25
	ctaTupleIP         = 1
	ctaIPv4Source      = 1
	ctaIPv6Source      = 3
	ctaFilterOrigFlags = 1
	ctaFilterIPSource  = 1 << 0
)

// forgetModule serves forgetConntrack's requests, and a request to it where it
// is not loaded would load it
const forgetModule = "nf_conntrack_netlink"

// forgetConntrack deletes every conntrack entry of host's namespace whose
// original source is source, in one ctnetlink delete filtered on that source
func forgetConntrack(host egresstest.Host, source netip.Addr) error {
	family, kind := uint8(unix.AF_INET), uint16(ctaIPv4Source)
	if source.Is6() {
		family, kind = unix.AF_INET6, ctaIPv6Source
	}
	tuple := netlink.PutAttr(nil, ctaTupleIP|unix.NLA_F_NESTED, netlink.PutAttr(nil, kind, source.AsSlice()))
	request := netlink.PutAttr(nftables.PutNfgenmsg(nil, family), ctaTupleOrig|unix.NLA_F_NESTED, tuple)
	request = netlink.PutAttr(request, ctaFilter|unix.NLA_F_NESTED, netlink.PutAttr(nil, ctaFilterOrigFlags, binary.NativeEndian.AppendUint32(nil, ctaFilterIPSource)))
	return host.Do(func() error {
		conn, err := netlink.Dial(unix.NETLINK_NETFILTER, netlink.Options{Timeout: time.Second})
		if err != nil {
			return err
		}
		defer conn.Close()
		_, err = conn.Execute(uint16(unix.NFNL_SUBSYS_CTNETLINK)<<8|ctDelete, unix.NLM_F_ACK, request)
		return err
	})
}

// conntrackFlow reads one entry of the listing: its family's name and number,
// its protocol's name and number, the seconds left, a TCP entry's state, then
// the original direction's addresses and ports ahead of the reply's, an echo's
// identifier in place of the ports, and no port for a protocol without them
func conntrackFlow(fields []string) (egresstest.Flow, error) {
	if len(fields) < 6 {
		return egresstest.Flow{}, errors.New("too few fields")
	}
	original := map[string]string{}
	for _, field := range fields[5:] {
		if key, value, ok := strings.Cut(field, "="); ok {
			if _, seen := original[key]; !seen {
				original[key] = value
			}
		}
	}
	port := func(key string) (uint64, error) {
		if value, ok := original[key]; ok {
			return strconv.ParseUint(value, 10, 16)
		}
		return 0, nil
	}
	sport, dport := "sport", "dport"
	if _, ok := original["id"]; ok {
		sport, dport = "id", "id"
	}
	protocol, errProtocol := strconv.ParseUint(fields[3], 10, 8)
	seconds, errSeconds := strconv.ParseUint(fields[4], 10, 32)
	from, errFrom := netip.ParseAddr(original["src"])
	to, errTo := netip.ParseAddr(original["dst"])
	fromPort, errFromPort := port(sport)
	toPort, errToPort := port(dport)
	if err := errors.Join(errProtocol, errSeconds, errFrom, errTo, errFromPort, errToPort); err != nil {
		return egresstest.Flow{}, err
	}
	return egresstest.Flow{
		Protocol: byte(protocol),
		From:     netip.AddrPortFrom(from, uint16(fromPort)),
		To:       netip.AddrPortFrom(to, uint16(toPort)),
		Phase:    phases[fields[5]],
		Left:     time.Duration(seconds) * time.Second,
	}, nil
}

// srcnat is NF_IP_PRI_NAT_SRC, the priority a host's source translation runs
// at, where the kernel runs a chain made later ahead of those made before it,
// and the kernel exit's chain is one below it
const srcnat = 100

// masqueradeAsAnotherWriter adds another writer's table in each family whose
// nat chain masquerades every packet at postrouting, at srcnat, made after the
// exit's chain, or ahead of it below the exit's chain, where an operator who
// translates a mesh flow itself puts one, and returns what deletes the tables
func masqueradeAsAnotherWriter(host egresstest.Host, ahead bool) (func() error, error) {
	if ahead {
		return masqueradeAt(host, srcnat-2)
	}
	return masqueradeAt(host, srcnat)
}

// untranslatingAsAnotherWriter adds another writer's table in each family
// whose nat chain at postrouting, at srcnat, holds no rule, which keeps the
// host's source translation hooked whatever the exit holds, and returns what
// deletes the tables
func untranslatingAsAnotherWriter(host egresstest.Host) (func() error, error) {
	return natChainAt(host, srcnat, false)
}

func masqueradeAt(host egresstest.Host, priority int32) (func() error, error) {
	return natChainAt(host, priority, true)
}

// natChainAt adds another writer's table in each family with a nat chain at
// postrouting at priority, masquerading every packet where masquerades is set
// and holding no rule where it is not, and returns what deletes the tables
func natChainAt(host egresstest.Host, priority int32, masquerades bool) (func() error, error) {
	const table = "another"
	chain := nftables.Chain{Table: table, Name: "postrouting", Type: "nat", Hook: unix.NF_INET_POST_ROUTING, Priority: priority}
	var requests []nftables.Request
	for _, proto := range []uint8{unix.NFPROTO_IPV4, unix.NFPROTO_IPV6} {
		requests = append(requests, nftables.NewTable(proto, table), chain.Create(proto))
		if masquerades {
			rule, err := chain.Rule(proto, "masquerade", [][]byte{nftables.Expression("masq", nil)})
			if err != nil {
				return nil, err
			}
			requests = append(requests, rule)
		}
	}
	batch := func(requests []nftables.Request) error {
		return host.Do(func() error {
			conn, err := nftables.Dial()
			if err != nil {
				return err
			}
			defer conn.Close()
			return conn.Batch(requests)
		})
	}
	undo := func() error {
		return batch([]nftables.Request{nftables.DeleteTable(unix.NFPROTO_IPV4, table), nftables.DeleteTable(unix.NFPROTO_IPV6, table)})
	}
	return undo, batch(requests)
}

// newKernelExit builds the kernel exit as the daemon does, its reads of the
// host made in the exit's namespace, which Run's goroutine is not in. A host
// with no done channel has no mesh writing to its tun, so Run waits for none.
func newKernelExit(t testing.TB, host egresstest.Host, cfg egress.Egress, hooks egress.Hooks) egress.Exit {
	t.Helper()
	inExit := func(f func()) { _ = host.Do(func() error { f(); return nil }) }
	done := host.Done
	if done == nil {
		done = egresstest.Closed
	}
	var exit *kernelexit.Translator
	if err := host.Do(func() (err error) {
		present := kernelexit.DevicePresence(host.TUN)
		exit, err = kernelexit.New(cfg, kernelexit.Runtime{
			Interface:     host.TUN,
			Write:         host.Write,
			Done:          done,
			MeshAddresses: host.Mesh,
			Forwarding:    func() (v4, v6 bool) { inExit(func() { v4, v6 = client.Forwarding() }); return v4, v6 },
			Lookup: func(lookups []kernelexit.Lookup) (answers []kernelexit.Answer, err error) {
				inExit(func() { answers, err = client.RouteLookups(lookups) })
				return answers, err
			},
			Sysctl: func(path string) (value string) { inExit(func() { value = client.Sysctl(path) }); return value },
			Present: func() (there bool, err error) {
				inExit(func() { there, err = present() })
				return there, err
			},
			Members: host.Members,
			Hooks:   hooks,
		})
		return err
	}); err != nil {
		t.Fatalf("build the kernel exit: %v", err)
	}
	return exit
}

// unheard is the hooks of a test that reads no report through them
var unheard = egress.Hooks{Ready: func(bool, bool, bool) {}, Republish: func() {}}

// kernelExitTables names the table the kernel exit writes in the exit's
// namespace and each chain in it, which no other writer there adds to
func kernelExitTables(host egresstest.Host) ([]string, error) {
	var held []string
	err := host.Do(func() error {
		conn, err := nftables.Dial()
		if err != nil {
			return err
		}
		defer conn.Close()
		tables, err := nftables.Tables(conn, nftables.Table)
		if err != nil {
			return err
		}
		if _, ok := tables[unix.NFPROTO_INET]; !ok {
			return nil
		}
		held = append(held, "table inet "+nftables.Table)
		chains, err := nftables.TableChains(conn, unix.NFPROTO_INET, nftables.Table)
		for _, chain := range chains {
			held = append(held, "chain "+chain)
		}
		return err
	})
	slices.Sort(held)
	return held, err
}

// besideFilter starts the antispoof filter over the network's overlay in the
// exit's namespace, as a node that carries cap.egress runs it beside the
// kernel exit, and stops it at the end of t, which withdraws its chains
func besideFilter(t *testing.T, network egresstest.Network) egresstest.Owner {
	t.Helper()
	host := network.Exit()
	bus := events.New()
	cfg := &egress.Border{Overlay: []schema.Prefix{schema.PrefixFrom(network.Family(false).Overlay), schema.PrefixFrom(network.Family(true).Overlay)}}
	var f *kernelexit.BorderFilter
	if err := host.Do(func() (err error) {
		f, err = kernelexit.NewBorderFilter(cfg, egress.BorderRuntime{Tun: host.TUN, Inside: []string{host.TUN, "lo"}, Events: bus})
		return err
	}); err != nil {
		t.Fatalf("start the antispoof filter: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- f.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("the antispoof filter's Run returned %v", err)
			}
		case <-time.After(kernelexit.PassWait):
			t.Errorf("the antispoof filter's Run had not returned %s after its context ended", kernelexit.PassWait)
		}
	})
	unready := func() int {
		return len(bus.Recorded(func(kind, _ string, attrs []slog.Attr) bool {
			return kind == "antispoof.ready" && slices.ContainsFunc(attrs, func(a slog.Attr) bool { return a.Key == "ready" && !a.Value.Bool() })
		}, 0))
	}
	return egresstest.Owner{Ready: func() bool { return f.Stats().Ready }, Unready: unready}
}

// hostFirewall is a host firewall's ruleset as its restart writes it, in one
// transaction that flushes every table first
const hostFirewall = `flush ruleset
table inet host-firewall {
	chain input-allow {
		tcp dport 22 accept
		icmp type echo-request accept
		icmpv6 type { nd-neighbor-solicit, nd-router-advert, nd-neighbor-advert } accept
	}
	chain input {
		type filter hook input priority filter; policy drop;
		iifname "lo" accept
		ct state vmap { invalid : drop, established : accept, related : accept, new : jump input-allow, untracked : jump input-allow }
	}
	chain forward {
		type filter hook forward priority filter; policy accept;
	}
}
`

// reloadFirewall writes hostFirewall with nft in the exit's namespace, as
// another writer
func reloadFirewall(host egresstest.Host) error {
	nft, err := exec.LookPath("nft")
	if err != nil {
		return fmt.Errorf("another writer's reload is made through nft, which is not on the path: %w", err)
	}
	_, err = nftIn(host, nft, hostFirewall, "-f", "/dev/stdin")
	return err
}

// the socket is not the exit's, so the exit reads the deletion as another
// writer's
func deleteKernelExitTables(host egresstest.Host) error {
	return host.Do(func() error {
		conn, err := nftables.Dial()
		if err != nil {
			return err
		}
		defer conn.Close()
		return conn.Batch([]nftables.Request{nftables.DeleteTable(unix.NFPROTO_INET, nftables.Table)})
	})
}

const (
	// shutdownCycles is how many shutdowns each case of the shutdown's test
	// crosses, as many as the frames across a stop cross stops
	shutdownCycles = stopCrossings
	// shutdownWriters hand frames of new flows from the leaf's address at once,
	// each at most shutdownPerWriter in a shutdown, which begins once
	// shutdownLead are handed
	shutdownWriters   = 4
	shutdownPerWriter = 1000
	shutdownLead      = 1000
	// shutdownLeadPoll is how often the run looks whether shutdownLead are
	// handed
	shutdownLeadPoll = 50 * time.Microsecond
	// shutdownPort is the first of the server's ports the frames go to, each
	// flow a pair of one of them and a leaf port from leafShutdownPort, so
	// every frame of every shutdown is a new flow's
	shutdownPort      = 10410
	leafShutdownPort  = 1024
	shutdownLeafPorts = 65536 - leafShutdownPort
	// shutdownTUN is the tun of each mesh, shutdownUplink the exit's link to
	// the server and shutdownFar the server's end of it
	shutdownTUN    = "shut0"
	shutdownUplink = "shutup0"
	shutdownFar    = "shutfar0"
	// shutdownLeft is the warning of a shutdown that leaves the stopped rules
	shutdownLeft = `level=WARN msg="egress left its stopped rules at shutdown"`
	// rpsDefaultMask is the receive steering a namespace gives each device made
	// in it, a setting a kernel built without receive packet steering lacks
	rpsDefaultMask = "/proc/sys/net/core/rps_default_mask"
)

var (
	shutdownLeaf     = netip.MustParseAddr("192.0.2.2")
	shutdownMesh     = netip.MustParsePrefix("192.0.2.1/24")
	shutdownUplinkAt = netip.MustParsePrefix("198.51.100.1/24")
	shutdownFarAt    = netip.MustParsePrefix("198.51.100.2/24")
	shutdownServer   = netip.MustParseAddr("203.0.113.17")
)

// TestKernelExitShutdownLeavesItsStoppedRulesWhereTheTunOutlivesTheMesh shuts
// the exit down with frames of new flows from the leaf's address handed up to
// the mesh's close, as the daemon's stop closes it. Over a multiqueue tun that
// outlives each mesh attached to it, as link.tun names one made persistent,
// whether the namespace's rps_default_mask, set before the tun is made, has
// the kernel steer its receive to other CPUs' backlogs or not, and where the
// exit thread's /sys is another namespace's, holding a device of the tun's
// name and index, every shutdown leaves the stopped rules, listed beside the
// translation's chain, and warns naming the tun, and the next start takes them
// over. Over a tun each mesh makes, which goes with it, every shutdown
// withdraws, leaving nothing of the exit's. In no case does a frame leave
// under the leaf's address. On a kernel without rps_default_mask the case of
// a steered receive skips, saying so, and the others run with none steered.
func TestKernelExitShutdownLeavesItsStoppedRulesWhereTheTunOutlivesTheMesh(t *testing.T) {
	nft := asRootWithNft(t)
	every := strconv.FormatUint(1<<min(runtime.NumCPU(), 32)-1, 16)
	for _, c := range []struct {
		name   string
		layout shutdownLayout
		// steered is whether the case shows a steered receive, which a kernel
		// without the setting cannot give
		steered bool
	}{
		{"persistent, its receive steered", shutdownLayout{mask: every, persistent: true}, true},
		{"persistent, its receive not steered", shutdownLayout{mask: "0", persistent: true}, false},
		{"persistent, beside another namespace's sysfs naming it", shutdownLayout{mask: every, persistent: true, namesake: true}, false},
		{"made by each mesh", shutdownLayout{mask: every}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := os.Stat(rpsDefaultMask); err != nil && c.layout.mask != "0" {
				if c.steered {
					t.Skipf("the kernel has no %s, as one built without receive packet steering has none, so it steers no tun's receive: %v", rpsDefaultMask, err)
				}
				c.layout.mask = "0"
			}
			var lines strings.Builder
			logtest.SetDefault(t, slog.New(slog.NewTextHandler(&lines, nil)))
			exit, server := shutdownNetwork(t, c.layout)
			count := fmt.Sprintf(`table ip shutdowncount {
	chain post {
		type filter hook postrouting priority 200; policy accept;
		oifname %q ip saddr %s counter comment "leaf"
	}
}
`, shutdownUplink, shutdownMesh.Masked())
			host := egresstest.Host{Do: exit.Do}
			if _, err := nftIn(host, nft, count, "-f", "-"); err != nil {
				t.Fatalf("add the counting table: %v", err)
			}
			arrivals := shutdownArrivals(t, server, shutdownCycles)
			cfg := egress.Egress{Advertise: []schema.Prefix{schema.MustPrefix("0.0.0.0/0")}, Sweep: schema.Duration(time.Hour), FlowsPerSource: 1 << 20}
			handed := 0
			for cycle := range shutdownCycles {
				handed += shutdown(t, exit, cfg, cycle, !c.layout.persistent)
				if c.layout.persistent {
					listing, err := nftIn(host, nft, "", "list", "table", "inet", nftables.Table)
					for _, want := range []string{"chain " + kernelexit.ChainName + " {", `comment "out via ` + shutdownTUN + ` ipv4 dropped while stopped"`,
						`comment "translated via ` + shutdownTUN + ` ipv4 leaving by another link dropped while stopped"`} {
						if !strings.Contains(listing, want) {
							t.Fatalf("shutdown %d left (%v)\n%s\nwant the stopped rules beside the translation's chain, %q among them", cycle, err, listing, want)
						}
					}
					continue
				}
				if held, err := kernelExitTables(host); err != nil || len(held) != 0 {
					t.Fatalf("shutdown %d left %q (%v), want nothing of the exit's, having logged\n%s", cycle, held, err, lines.String())
				}
			}
			logged := lines.String()
			left, named := strings.Count(logged, shutdownLeft), strings.Count(logged, "the mesh device "+shutdownTUN+" outlives the mesh")
			if c.layout.persistent && (left != shutdownCycles || named != shutdownCycles) || !c.layout.persistent && left != 0 {
				t.Errorf("%d shutdowns warned %d times that they left the stopped rules, %d naming the tun outliving the mesh:\n%s", shutdownCycles, left, named, logged)
			}
			listing, err := nftIn(host, nft, "", "list", "table", "ip", "shutdowncount")
			if err != nil {
				t.Fatalf("list the counting table: %v", err)
			}
			uplink := -1
			if match := counterPackets.FindStringSubmatch(listing); match != nil {
				uplink, _ = strconv.Atoi(match[1])
			}
			read, leaf := arrivals()
			t.Logf("%d shutdowns on %s, mask %s: %d frames handed, %d read at the server, %d under the leaf's address, %d left the uplink under it",
				shutdownCycles, shutdownTUN, c.layout.mask, handed, read, leaf, uplink)
			if leaf != 0 || uplink != 0 {
				t.Errorf("%d frames reached the server under the leaf's address and the uplink counted %d leaving under it, want none", leaf, uplink)
			}
		})
	}
}

// shutdownLayout is the exit's namespace of a shutdown's test: its
// rps_default_mask, whether its tun is made persistent ahead of every mesh or
// by each mesh, and whether the exit's thread reads the sysfs of another
// namespace that holds a persistent device of the tun's name, made first there
// as the tun is made first in the exit's, so of the same index
type shutdownLayout struct {
	mask                 string
	persistent, namesake bool
}

// shutdownNetwork makes the exit's namespace as layout says, with forwarding
// on and a link to the server's, whose loopback holds the server's address,
// the persistent tun, where there is one, holding its address. A kernel with
// no rps_default_mask steers nothing, so layout's mask of none sets nothing
// there.
func shutdownNetwork(t *testing.T, layout shutdownLayout) (exit, server *netnstest.Thread) {
	t.Helper()
	exit, server = netnstest.StartThread(t), netnstest.StartThread(t)
	settings := map[string]string{"/proc/sys/net/ipv4/ip_forward": "1"}
	if _, err := os.Stat(rpsDefaultMask); err == nil || layout.mask != "0" {
		settings[rpsDefaultMask] = layout.mask
	}
	if err := exit.Do(func() error {
		for path, value := range settings {
			if err := os.WriteFile(path, []byte(value+"\n"), 0o644); err != nil {
				return err
			}
		}
		if layout.persistent {
			if err := shutdownPersist(shutdownTUN); err != nil {
				return err
			}
		}
		conn, err := netnstest.OpenNetlink()
		if err != nil {
			return err
		}
		defer conn.Close()
		if err := conn.AddVeth(shutdownUplink, shutdownFar, 0, server.Path); err != nil {
			return err
		}
		if err := conn.AddAddresses(shutdownUplink, shutdownUplinkAt); err != nil {
			return err
		}
		if layout.persistent {
			if err := conn.AddAddresses(shutdownTUN, shutdownMesh); err != nil {
				return err
			}
		}
		up, err := net.InterfaceByName(shutdownUplink)
		if err != nil {
			return err
		}
		return conn.RouteVia(up.Index, netip.MustParsePrefix("0.0.0.0/0"), shutdownFarAt.Addr())
	}); err != nil {
		t.Fatalf("make the exit's namespace: %v", err)
	}
	if layout.namesake {
		shutdownNamesake(t, exit)
	}
	if err := server.Do(func() error {
		conn, err := netnstest.OpenNetlink()
		if err != nil {
			return err
		}
		defer conn.Close()
		if err := conn.AddAddresses(shutdownFar, shutdownFarAt); err != nil {
			return err
		}
		return conn.AddAddresses("lo", netip.PrefixFrom(shutdownServer, 32))
	}); err != nil {
		t.Fatalf("make the server's namespace: %v", err)
	}
	return exit, server
}

// shutdownNamesake gives the exit's thread a mount namespace of its own, kept
// for the thread's life, which ends with the test, whose /sys is the sysfs of
// another network namespace, kept until the test ends, where a persistent
// device of the tun's name holds the tun's index
func shutdownNamesake(t *testing.T, exit *netnstest.Thread) {
	t.Helper()
	var own, other int
	var indices [2]string
	if err := exit.Do(func() (err error) {
		if own, err = unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0); err != nil {
			return err
		}
		defer unix.Close(own)
		link, err := net.InterfaceByName(shutdownTUN)
		if err != nil {
			return err
		}
		indices[0] = strconv.Itoa(link.Index)
		if err := unix.Unshare(unix.CLONE_NEWNS); err != nil {
			return err
		}
		if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
			return err
		}
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			return err
		}
		if other, err = unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0); err != nil {
			return err
		}
		if err := shutdownPersist(shutdownTUN); err != nil {
			return err
		}
		if err := unix.Mount("sysfs", "/sys", "sysfs", 0, ""); err != nil {
			return err
		}
		if err := unix.Setns(own, unix.CLONE_NEWNET); err != nil {
			return err
		}
		raw, err := os.ReadFile("/sys/class/net/" + shutdownTUN + "/ifindex")
		indices[1] = strings.TrimSpace(string(raw))
		return err
	}); err != nil {
		t.Fatalf("give the exit's thread another namespace's sysfs: %v", err)
	}
	t.Cleanup(func() {
		if other != 0 {
			_ = unix.Close(other)
		}
	})
	if indices[0] != indices[1] {
		t.Fatalf("the exit's %s holds the index %s and the sysfs its thread reads lists one of index %s, want the same", shutdownTUN, indices[0], indices[1])
	}
}

// shutdownPersist makes the multiqueue tun name, which outlives the
// descriptor that made it, with the flags the mesh attaches with
func shutdownPersist(name string) error {
	fd, err := shutdownOpen(name)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	return unix.IoctlSetInt(fd, unix.TUNSETPERSIST, 1)
}

// shutdownOpen makes the multiqueue tun name with the flags the mesh attaches
// with, held by the descriptor it answers, whose close takes it away
func shutdownOpen(name string) (int, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	ifr, err := unix.NewIfreq(name)
	if err == nil {
		ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_VNET_HDR | unix.IFF_MULTI_QUEUE)
		err = unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr)
	}
	if err != nil {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("make %s: %w", name, err)
	}
	return fd, nil
}

// TestDevicePresenceTakesNoOtherNamespacesDeviceForTheTun reads, on the exit's
// thread, whether a tun its namespace made is there, while the thread's /sys
// is another namespace's, listing a device of the tun's name and index
// (shutdownNamesake). The tun reads there while its descriptor is open and
// gone once that closes, as a tun each mesh makes goes with the mesh's close,
// the other namespace's device not taken for it.
func TestDevicePresenceTakesNoOtherNamespacesDeviceForTheTun(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("a tun and a network namespace need root on linux")
	}
	needModules(t, "tun")
	exit := netnstest.StartThread(t)
	fd := -1
	if err := exit.Do(func() (err error) { fd, err = shutdownOpen(shutdownTUN); return err }); err != nil {
		t.Fatalf("make the tun: %v", err)
	}
	t.Cleanup(func() {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
	})
	shutdownNamesake(t, exit)
	var present func() (bool, error)
	read := func() (there bool, err error) {
		err = exit.Do(func() (err error) {
			if present == nil {
				present = kernelexit.DevicePresence(shutdownTUN)
			}
			there, err = present()
			return err
		})
		return there, err
	}
	if there, err := read(); err != nil || !there {
		t.Fatalf("with the tun open the read said there %t (%v), want there", there, err)
	}
	err := unix.Close(fd)
	fd = -1
	if err != nil {
		t.Fatalf("close the tun: %v", err)
	}
	if there, err := read(); err != nil || there {
		t.Errorf("with the tun closed the read said there %t (%v), want gone, the device of its name and index the thread's /sys lists not taken for it", there, err)
	}
}

// TestDevicePresenceFollowsTheIndexTheTunHeldAtTheBuild reads, on the exit's
// thread, whether a tun its namespace made is there, by the index the tun held
// when the reader was built: renamed, it reads there, and once it is gone a new
// tun of its old name, which the kernel gives another index, reads gone.
func TestDevicePresenceFollowsTheIndexTheTunHeldAtTheBuild(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("a tun and a network namespace need root on linux")
	}
	needModules(t, "tun")
	exit := netnstest.StartThread(t)
	fds := []int{-1, -1}
	t.Cleanup(func() {
		for _, fd := range fds {
			if fd >= 0 {
				_ = unix.Close(fd)
			}
		}
	})
	if err := exit.Do(func() (err error) { fds[0], err = shutdownOpen(shutdownTUN); return err }); err != nil {
		t.Fatalf("make the tun: %v", err)
	}
	var present func() (bool, error)
	_ = exit.Do(func() error { present = kernelexit.DevicePresence(shutdownTUN); return nil })
	read := func() (there bool, err error) {
		err = exit.Do(func() (err error) { there, err = present(); return err })
		return there, err
	}
	var before, renamed *net.Interface
	if err := exit.Do(func() (err error) {
		if before, err = net.InterfaceByName(shutdownTUN); err != nil {
			return err
		}
		if err = renameLink(shutdownTUN, "shutold0"); err != nil {
			return err
		}
		renamed, err = net.InterfaceByName("shutold0")
		return err
	}); err != nil || renamed.Index != before.Index {
		t.Fatalf("rename the tun: %v, the new name on %+v, want it on the tun's index %+v", err, renamed, before)
	}
	if there, err := read(); err != nil || !there {
		t.Errorf("with the tun renamed the read said there %t (%v), want there, the tun holding the index it held", there, err)
	}
	err := unix.Close(fds[0])
	fds[0] = -1
	if err != nil {
		t.Fatalf("close the tun: %v", err)
	}
	if err := exit.Do(func() (err error) { fds[1], err = shutdownOpen(shutdownTUN); return err }); err != nil {
		t.Fatalf("make a new tun of the old name: %v", err)
	}
	if there, err := read(); err != nil || there {
		t.Errorf("with the tun gone and a new one of its old name made the read said there %t (%v), want gone, the new tun holding another index", there, err)
	}
}

// renameLink renames the link name of the calling thread's namespace to, as
// `ip link set dev name` does
func renameLink(name, to string) error {
	link, err := net.InterfaceByName(name)
	if err != nil {
		return err
	}
	conn, err := netnstest.OpenNetlink()
	if err != nil {
		return err
	}
	defer conn.Close()
	return conn.Request(unix.RTM_NEWLINK, 0, slices.Concat(netnstest.IfInfo(link.Index, 0), netnstest.Attr(unix.IFLA_IFNAME, netnstest.CString(to))))
}

// shutdownArrivals reads, on every server port the frames of cycles
// shutdowns go to, the datagrams that reach the server until the test ends,
// and answers how many it read and how many from the leaf's address
func shutdownArrivals(t *testing.T, server *netnstest.Thread, cycles int) func() (read, leaf int) {
	t.Helper()
	var mu sync.Mutex
	var all, fromLeaf int
	for port := range (cycles*shutdownWriters*shutdownPerWriter)/shutdownLeafPorts + 1 {
		var conn *net.UDPConn
		if err := server.Do(func() (err error) {
			conn, err = net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(shutdownServer, uint16(shutdownPort+port))))
			return err
		}); err != nil {
			t.Fatal(err)
		}
		_ = conn.SetReadBuffer(8 << 20)
		t.Cleanup(func() { _ = conn.Close() })
		go func() {
			buf := make([]byte, 2048)
			for {
				_, from, err := conn.ReadFromUDPAddrPort(buf)
				if err != nil {
					return
				}
				mu.Lock()
				all++
				if from.Addr().Unmap() == shutdownLeaf {
					fromLeaf++
				}
				mu.Unlock()
			}
		}()
	}
	return func() (int, int) {
		time.Sleep(downQuiet)
		mu.Lock()
		defer mu.Unlock()
		return all, fromLeaf
	}
}

// shutdown attaches a mesh to the tun, which it makes where none is there and
// then gives its address where address is set, runs the exit on it until IPv4
// is ready (runExit), hands frames of new flows from the leaf's address from
// shutdownWriters goroutines, and once shutdownLead are handed ends the run,
// closing the mesh as the daemon's stop does, and answers how many frames it
// had handed
func shutdown(t *testing.T, exit *netnstest.Thread, cfg egress.Egress, cycle int, address bool) int {
	t.Helper()
	var mesh *netstack.Mesh
	if err := exit.Do(func() (err error) {
		if mesh, err = netstack.NewNamed(netstack.DefaultMTU, shutdownTUN, false, nil); err != nil || !address {
			return err
		}
		conn, err := netnstest.OpenNetlink()
		if err != nil {
			return err
		}
		defer conn.Close()
		return conn.AddAddresses(shutdownTUN, shutdownMesh)
	}); err != nil {
		t.Fatalf("shutdown %d: attach the mesh: %v", cycle, err)
	}
	host := egresstest.Host{
		Do: exit.Do, TUN: mesh.Name, Write: mesh.WriteHost, Done: mesh.Done(), Mesh: []netip.Addr{shutdownMesh.Addr()}, Lanes: mesh,
		Members: func() []netip.Prefix { return []netip.Prefix{netip.PrefixFrom(shutdownLeaf, 32)} },
	}
	_, end := runExit(t, host, cfg)
	waitFor(t, fmt.Sprintf("IPv4 ready in shutdown %d", cycle), func() bool { v4, _ := mesh.EgressReady(); return v4 })
	var stop atomic.Bool
	var count atomic.Int64
	var writers sync.WaitGroup
	for writer := range shutdownWriters {
		writers.Go(func() {
			for n := 0; n < shutdownPerWriter && !stop.Load(); n++ {
				flow := (cycle*shutdownWriters+writer)*shutdownPerWriter + n
				from := netip.AddrPortFrom(shutdownLeaf, uint16(leafShutdownPort+flow%shutdownLeafPorts))
				to := netip.AddrPortFrom(shutdownServer, uint16(shutdownPort+flow/shutdownLeafPorts))
				mesh.WriteHost([][]byte{egresstest.DatagramFrame(from, to, fmt.Appendf(nil, "from %s", from))}, nil)
				count.Add(1)
			}
		})
	}
	for count.Load() < shutdownLead {
		time.Sleep(shutdownLeadPoll)
	}
	handed := int(count.Load())
	end()
	stop.Store(true)
	writers.Wait()
	return handed
}
