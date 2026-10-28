// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package client

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sync"
	"testing"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/netnstest"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/nftables"
	"ranet3.com/pkgs/ranet3/schema"
)

// the states each program beside ranet3 is checked in, mode 2 forwarding the bridge throughout
const (
	besideLive      = "the mesh's defaults live"
	besideRetracted = "the mesh's defaults retracted"
	besideCrashed   = "after kill -9"
)

// exitHelperNamespace names, in the crash helper's environment, the namespace it runs the leaf's node in
const exitHelperNamespace = "RANET3_EXIT_LAB_NAMESPACE"

// exitBeside is a program beside ranet3 in mode 2: what it writes into the leaf, the bridge's masquerade among it, and where each
// state sends the leaf's traffic
type exitBeside struct {
	write func(t *testing.T, lab *exitLab)
	// probes is where each state sends the host's own traffic and the underlay's, from an unbound socket sending a datagram and an
	// echo request, the underlay's datagram as IKE's goes and its echo request standing for ESP, an IP protocol with no port, and
	// flows where it sends a family's ping from the container behind the bridge forward names and from the LAN host, whose link
	// forward leaves out
	probes func(state string) []rulesProbe
	flows  func(state string, family int) (bridge, lan rulesVerdict)
	// after checks what the program holds once a state's traffic has passed, where it counts any
	after func(t *testing.T, lab *exitLab, state string)
}

// besideRow is the host's own probes and the underlay's to the internet host in both families, and the host's to a peer in the overlay,
// which the overlay's hold refuses once the tun is gone
func besideRow(state string, host, underlay rulesVerdict) []rulesProbe {
	peer := rulesIntoTun
	if state == besideCrashed {
		peer = rulesRefused
	}
	var out []rulesProbe
	for _, family := range []int{4, 6} {
		internet := exitLabHost[family].internet.Addr()
		out = append(out,
			rulesProbe{internet, rulesUnbound, host, 0},
			rulesProbe{internet, rulesUnbound, underlay, schema.UnderlayMark},
			rulesProbe{netip.MustParseAddr(map[int]string{4: "192.0.2.5", 6: "3fff::5"}[family]), rulesUnbound, peer, 0})
	}
	return out
}

// besideUnless is want in the live state and out of the uplink once the mesh's defaults are retracted or the tun is gone
func besideUnless(state string, want rulesVerdict) rulesVerdict {
	if state == besideLive {
		return want
	}
	return rulesOutUplink
}

// besideModeTwo is where mode 2 forwarding the bridge sends the forwarded flows: the bridge's into the tun while the mesh's defaults
// are live, and by main otherwise, and the LAN's by main
func besideModeTwo(state string, _ int) (bridge, lan rulesVerdict) {
	return besideUnless(state, rulesIntoTun), rulesOutUplink
}

// runBeside runs mode 2 forwarding the bridge beside c's program: in-process with the mesh's defaults live and then retracted,
// and then in a helper process holding the tun and the reconciler, killed with SIGKILL once its rules and defaults are in place
func runBeside(t *testing.T, c exitBeside) {
	if os.Getuid() != 0 {
		t.Skip("creating a tun needs root on linux")
	}
	lab := newExitLab(t)
	c.write(t, lab)
	var farCapture, otherCapture int
	if err := errors.Join(
		lab.far.Do(func() (err error) { farCapture, err = openCapture(rulesFar, labRetry); return err }),
		lab.leaf.Do(func() (err error) { otherCapture, err = openCapture(rulesOther, labRetry); return err }),
	); err != nil {
		t.Fatalf("capture the far end of the uplink and the other program's link: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(farCapture); _ = unix.Close(otherCapture) })
	d := startExitDaemon(t, lab.leaf)
	for _, state := range []string{besideLive, besideRetracted, besideCrashed} {
		t.Run(state, func(t *testing.T) {
			if state == besideCrashed {
				d.stop()
				kill := startExitHelper(t, lab.leaf)
				besideConverged(t, lab, true)
				kill()
				waitFor(t, rulesSettle, "the tun to go with the helper", func() bool { return !besideHasTun(t, lab.leaf) })
				// the rules are the kernel's, so they outlive the process that wrote them
				if got, want := exitRules(t, lab.leaf, 5440), besideRules(); !slices.Equal(got, want) {
					t.Fatalf("after kill -9 the leaf holds %v at 5440, want the helper's rules %v", got, want)
				}
			} else {
				besideEntries(d, state == besideRetracted)
				d.mode(t, []string{exitBridge}, true, nil, 0)
				besideConverged(t, lab, state == besideLive)
			}
			t.Logf("the leaf holds the rules\n%s", exitAllRules(t, lab.leaf))
			captures := []exitCapture{{rulesOutUplink, farCapture}, {rulesIntoOther, otherCapture}}
			if besideHasTun(t, lab.leaf) {
				var tunCapture int
				if err := lab.leaf.Do(func() (err error) { tunCapture, err = openCapture(rulesTUN, labRetry); return err }); err != nil {
					t.Fatalf("capture the tun: %v", err)
				}
				defer unix.Close(tunCapture)
				captures = append(captures, exitCapture{rulesIntoTun, tunCapture})
			}
			probes := c.probes(state)
			var flows []exitFlow
			var replies []exitReply
			for _, family := range []int{4, 6} {
				internet := exitLabHost[family].internet.Addr()
				bridge, lan := c.flows(state, family)
				flows = append(flows, exitFlow{"container", internet, bridge, exitReplies(bridge)}, exitFlow{"lan", internet, lan, exitReplies(lan)})
				for _, p := range probes {
					if p.mark == schema.UnderlayMark && p.destination == internet {
						replies = append(replies, exitReply{true, internet, p.want == rulesOutUplink})
					}
				}
			}
			exitProbe(t, lab, captures, []string{"udp", "echo"}, probes, flows, replies)
			if c.after != nil {
				c.after(t, lab, state)
			}
		})
	}
}

// besideEntries gives the leaf's mesh a peer inside the overlay and the defaults, learned or held unreachable
func besideEntries(d *exitDaemon, retracted bool) {
	defaults := d.learned
	if retracted {
		defaults = netstack.Unreachable
	}
	for prefix, value := range map[string]*netstack.Peer{"192.0.2.5/32": d.learned, "3fff::5/128": d.learned, "0.0.0.0/0": defaults, "::/0": defaults} {
		d.node.Mesh.Routes.Set(netip.Prefix{}, netip.MustParsePrefix(prefix), value)
	}
}

// besideRules is mode 2's rules at 5440 for the host's own traffic and the bridge's, sorted
func besideRules() []string {
	rules := []string{"5440 ipv4 iif lo", "5440 ipv4 iif " + exitBridge, "5440 ipv6 iif lo", "5440 ipv6 iif " + exitBridge}
	slices.Sort(rules)
	return rules
}

// besideConverged waits for mode 2's rules at 5440 for the host's own traffic and the bridge's, and for the mesh's defaults where live says
func besideConverged(t *testing.T, lab *exitLab, live bool) {
	t.Helper()
	want := besideRules()
	waitFor(t, rulesSettle, "the reconciler to install mode 2's rules and the mesh's defaults", func() bool {
		return slices.Equal(exitRules(t, lab.leaf, 5440), want) && exitDefaults(t, lab.leaf) == live
	})
}

func besideHasTun(t *testing.T, leaf *netnstest.Thread) bool {
	t.Helper()
	var held bool
	if err := leaf.Do(func() error {
		_, err := net.InterfaceByName(rulesTUN)
		held = err == nil
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return held
}

// startExitHelper runs TestExitLabCrashHelper in a process of its own in the leaf's namespace, and answers what kills it with SIGKILL
func startExitHelper(t *testing.T, leaf *netnstest.Thread) func() {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	log, err := os.Create(filepath.Join(t.TempDir(), "helper.log"))
	if err != nil {
		t.Fatal(err)
	}
	helper := exec.Command(executable, "-test.run=^TestExitLabCrashHelper$", "-test.v")
	helper.Env = append(os.Environ(), exitHelperNamespace+"="+leaf.Path)
	helper.Stdout, helper.Stderr = log, log
	// the helper runs until its stdin closes, which a test that fails before the kill leaves to the cleanup
	stdin, err := helper.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := helper.Start(); err != nil {
		t.Fatalf("start the crash helper: %v", err)
	}
	kill := sync.OnceFunc(func() {
		_ = helper.Process.Signal(unix.SIGKILL)
		_ = helper.Wait()
		_ = stdin.Close()
		_ = log.Close()
		written, _ := os.ReadFile(log.Name())
		t.Logf("the crash helper wrote\n%s", written)
	})
	t.Cleanup(kill)
	return kill
}

// the crash helper of the tests beside other programs, which runs the leaf's node and its reconciler in mode 2 forwarding the bridge with the mesh's defaults
// learned, in the namespace exitHelperNamespace names, until it is killed
func TestExitLabCrashHelper(t *testing.T) {
	path := os.Getenv(exitHelperNamespace)
	if path == "" {
		t.Skip("the tests beside other programs run the crash helper in a process of its own")
	}
	leaf := netnstest.JoinThread(t, path)
	d := startExitDaemon(t, leaf)
	besideEntries(d, false)
	d.mode(t, []string{exitBridge}, true, nil, 0)
	_, _ = io.Copy(io.Discard, os.Stdin)
}

// Tailscale's mark of its own sockets, under its mask, as baseIPRules reads it
const (
	tailscaleMark = 0x80000
	tailscaleMask = 0xff0000
)

// writeTailscale writes Tailscale's rules as baseIPRules does (tailscale e8ebe6aba, router_linux.go:1593-1625) in both families:
// its own sockets' mark to main at 5210, then to the default table at 5230, then unreachable at 5250, and every lookup to table 52 at 5270.
// Table 52 holds what a client using an exit node holds, as 1.104.2 writes it in the coexistence VM: a default over its tun, here the other
// program's link, and throws for the loopback, the uplink's network and IPv6's link-local network.
func writeTailscale(t *testing.T, lab *exitLab) {
	t.Helper()
	masqueradeBridge(t, lab.leaf)
	if err := lab.leaf.Do(func() error {
		if err := rulesOtherProgram(unix.RTM_NEWRULE, unix.RTM_NEWROUTE, []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}); err != nil {
			return err
		}
		netlink, err := netnstest.OpenNetlink()
		if err != nil {
			return err
		}
		defer netlink.Close()
		create := uint16(unix.NLM_F_CREATE | unix.NLM_F_EXCL)
		for _, family := range []byte{unix.AF_INET, unix.AF_INET6} {
			for _, rule := range []struct {
				priority      uint32
				table, action byte
			}{{5210, unix.RT_TABLE_MAIN, unix.FR_ACT_TO_TBL}, {5230, unix.RT_TABLE_DEFAULT, unix.FR_ACT_TO_TBL}, {5250, 0, unix.FR_ACT_UNREACHABLE}} {
				// struct fib_rule_hdr of include/uapi/linux/fib_rules.h
				body := slices.Concat([]byte{family, 0, 0, 0, rule.table, 0, 0, rule.action, 0, 0, 0, 0}, netnstest.Attr(unix.FRA_PRIORITY, netnstest.U32(rule.priority)),
					netnstest.Attr(unix.FRA_FWMARK, netnstest.U32(tailscaleMark)), netnstest.Attr(unix.FRA_FWMASK, netnstest.U32(tailscaleMask)))
				if err := netlink.Request(unix.RTM_NEWRULE, create, body); err != nil {
					return fmt.Errorf("Tailscale's rule at %d: %w", rule.priority, err)
				}
			}
			throws := []netip.Prefix{rulesHost[6].uplink.Masked(), netip.MustParsePrefix("fe80::/64")}
			if family == unix.AF_INET {
				throws = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), rulesHost[4].uplink.Masked()}
			}
			for _, prefix := range throws {
				if err := netlink.Request(unix.RTM_NEWROUTE, create, slices.Concat(
					[]byte{family, byte(prefix.Bits()), 0, 0, rulesOtherTable, unix.RTPROT_BOOT, unix.RT_SCOPE_UNIVERSE, unix.RTN_THROW, 0, 0, 0, 0},
					netnstest.Attr(unix.RTA_DST, prefix.Addr().AsSlice()))); err != nil {
					return fmt.Errorf("table %d's throw of %s: %w", rulesOtherTable, prefix, err)
				}
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("write Tailscale's rules and table: %v", err)
	}
}

// a leaf in mode 2 forwarding the bridge beside Tailscale's rules and an exit node's table 52, live, retracted and after kill -9:
// 5270 sits ahead of 5440, so table 52's default takes the host's own traffic and the bridge's into Tailscale's link in every state,
// while the overlay reaches the mesh at 5110 ahead of it. The underlay's mark skips 5110 to 5190 and then meets 5270, so ranet3's
// underlay leaves by Tailscale's link but to the uplink's network, which table 52 throws, and Tailscale's own sockets leave by
// main at 5210.
func TestTUNExitModeBesideTailscale(t *testing.T) {
	other, up := rulesIntoOther, rulesOutUplink
	runBeside(t, exitBeside{
		write: writeTailscale,
		probes: func(state string) []rulesProbe {
			out := besideRow(state, other, other)
			for _, family := range []int{4, 6} {
				out = append(out,
					rulesProbe{rulesHost[family].lan.Addr(), rulesUnbound, up, schema.UnderlayMark},
					rulesProbe{exitLabHost[family].internet.Addr(), rulesUnbound, up, tailscaleMark})
			}
			return out
		},
		flows: func(string, int) (rulesVerdict, rulesVerdict) { return other, other },
	})
}

// conntrackRestore is a firewall's route chain at output restoring the conntrack mark with the full mask and saving none, so every
// packet of the host's own leaves it with mark 0, and one whose mark that changes is routed again with iif lo
var conntrackRestore = nftables.Chain{Table: "exitct", Name: "restore", Type: "route", Hook: unix.NF_INET_LOCAL_OUT, Priority: -150}

func writeConntrackRestore(t *testing.T, lab *exitLab) {
	t.Helper()
	masqueradeBridge(t, lab.leaf)
	if err := lab.leaf.Do(func() error {
		conn, err := nftables.Dial()
		if err != nil {
			return err
		}
		defer conn.Close()
		ct := nftables.PutAttrBE32(nil, unix.NFTA_CT_KEY, unix.NFT_CT_MARK)
		ct = nftables.PutAttrBE32(ct, unix.NFTA_CT_DREG, unix.NFT_REG_1)
		set := nftables.PutAttrBE32(nil, unix.NFTA_META_KEY, unix.NFT_META_MARK)
		set = nftables.PutAttrBE32(set, unix.NFTA_META_SREG, unix.NFT_REG_1)
		rule, err := conntrackRestore.Rule(unix.NFPROTO_INET, "meta mark set ct mark", [][]byte{nftables.Expression("ct", ct), nftables.Expression("meta", set)})
		if err != nil {
			return err
		}
		return conn.Batch([]nftables.Request{nftables.NewTable(unix.NFPROTO_INET, conntrackRestore.Table), conntrackRestore.Create(unix.NFPROTO_INET), rule})
	}); err != nil {
		t.Fatalf("write the conntrack mark's restore: %v", err)
	}
}

// a leaf in mode 2 forwarding the bridge beside a firewall restoring the conntrack mark with the full mask at output, live, retracted
// and after kill -9: the underlay's datagram has its mark cleared and is routed again from the uplink's address with iif lo, which 5405
// sends by main, so the underlay reaches the far side in every state rather than entering its own tun
func TestTUNExitModeBesideAConntrackMarkRestore(t *testing.T) {
	tun, up := rulesIntoTun, rulesOutUplink
	runBeside(t, exitBeside{
		write: writeConntrackRestore,
		probes: func(state string) []rulesProbe {
			out := besideRow(state, besideUnless(state, tun), up)
			for _, family := range []int{4, 6} {
				out = append(out, rulesProbe{rulesHost[family].lan.Addr(), rulesUnbound, up, schema.UnderlayMark})
			}
			return out
		},
		flows: besideModeTwo,
	})
}

// writeKubernetes writes Cilium's rule and table in both families, and kube-proxy's masquerade
func writeKubernetes(t *testing.T, lab *exitLab) {
	t.Helper()
	masqueradeBridge(t, lab.leaf)
	if err := lab.leaf.Do(func() error {
		netlink, err := netnstest.OpenNetlink()
		if err != nil {
			return err
		}
		defer netlink.Close()
		create := uint16(unix.NLM_F_CREATE | unix.NLM_F_EXCL)
		for _, family := range []byte{unix.AF_INET, unix.AF_INET6} {
			if err := netlink.Request(unix.RTM_NEWRULE, create, netnstest.CiliumRule(family)); err != nil {
				return fmt.Errorf("Cilium's rule: %w", err)
			}
			if err := netlink.Request(unix.RTM_NEWROUTE, create, netnstest.CiliumLocal(family)); err != nil {
				return fmt.Errorf("Cilium's local default: %w", err)
			}
		}
		conn, err := nftables.Dial()
		if err != nil {
			return err
		}
		defer conn.Close()
		requests, err := netnstest.KubeProxyMasquerade()
		if err != nil {
			return err
		}
		return conn.Batch(requests)
	}); err != nil {
		t.Fatalf("write Cilium's rule and kube-proxy's masquerade: %v", err)
	}
}

// a leaf in mode 2 forwarding the bridge beside Cilium's rule at 9 and kube-proxy's masquerade, live, retracted and after kill -9:
// neither reads a bit of the underlay's mark, so the underlay skips ranet3's blocks and leaves by the uplink in every state while the host's
// own traffic and the bridge's follow the mode, and the masquerade counts nothing
func TestTUNExitModeBesideKubeProxyAndCilium(t *testing.T) {
	runBeside(t, exitBeside{
		write: writeKubernetes,
		probes: func(state string) []rulesProbe {
			return besideRow(state, besideUnless(state, rulesIntoTun), rulesOutUplink)
		},
		flows: besideModeTwo,
		after: func(t *testing.T, lab *exitLab, state string) {
			var read nftables.Readback
			if err := lab.leaf.Do(func() error {
				conn, err := nftables.Dial()
				if err != nil {
					return err
				}
				defer conn.Close()
				read, err = nftables.Contents{Chains: []nftables.Chain{netnstest.KubeProxyNAT}}.Read(conn, map[uint8]uint32{unix.NFPROTO_INET: 0}, unix.NFPROTO_INET)
				return err
			}); err != nil {
				t.Fatalf("read kube-proxy's masquerade: %v", err)
			}
			if len(read.Rules) != 1 || read.Rules[0].Packets != 0 {
				t.Errorf("%s, kube-proxy's masquerade reads back as %+v, want one that counted no packet", state, read.Rules)
			}
		},
	})
}

// nftJump is NFT_JUMP of linux/netfilter/nf_tables.h, -3 as the kernel reads a verdict code
const nftJump = 0xfffffffd

// labJump jumps to chain
func labJump(chain string) []byte {
	verdict := nftables.PutAttrBE32(nil, unix.NFTA_VERDICT_CODE, nftJump)
	verdict = nftables.PutAttrString(verdict, unix.NFTA_VERDICT_CHAIN, chain)
	data := nftables.PutAttr(nil, unix.NFTA_DATA_VERDICT|unix.NLA_F_NESTED, verdict)
	immediate := nftables.PutAttrBE32(nil, unix.NFTA_IMMEDIATE_DREG, unix.NFT_REG_VERDICT)
	immediate = nftables.PutAttr(immediate, unix.NFTA_IMMEDIATE_DATA|unix.NLA_F_NESTED, data)
	return nftables.Expression("immediate", immediate)
}

// dockerChain is a chain of Docker's in an iptables-nft table, a base chain where kind is set, with its rules as nft lists them
type dockerChain struct {
	table, name, kind string
	hook              uint32
	priority          int32
	policy            uint32
	specs             []string
	rules             [][][]byte
}

// dockerTables is the tables Docker 29.9.1 writes through iptables-nft with no container running, as `nft list ruleset` prints them on a
// NixOS VM whose forwarding was off before Docker started, with the lab's bridge for docker0 and the container's network for 172.17.0.0/16. ipv4 is ip filter's FORWARD policy, which that VM's Docker set to drop, and which a host forwarding before Docker
// starts keeps at accept. ip6 filter's stays accept. The nat table's DOCKER chains, empty with no published port, are left out.
func dockerTables(ipv4 uint32) map[uint8][]dockerChain {
	counter := nftables.Expression("counter", nil)
	jump := func(chain string) [][]byte { return [][]byte{counter, labJump(chain)} }
	in := nftables.MetaCompare(unix.NFT_META_IIFNAME, unix.NFT_CMP_EQ, exitBridge)
	out := nftables.MetaCompare(unix.NFT_META_OIFNAME, unix.NFT_CMP_EQ, exitBridge)
	// ct state's bits are NF_CT_STATE_BIT of ESTABLISHED and RELATED, 1 << 1 and 1 << 2
	established := nftables.CTMatch(unix.NFT_CT_STATE, 1<<1|1<<2, unix.NFT_CMP_NEQ)
	bridge := "oifname \"" + exitBridge + "\""
	forward := func(policy uint32) dockerChain {
		return dockerChain{name: "FORWARD", kind: "filter", hook: unix.NF_INET_FORWARD, policy: policy,
			specs: []string{"counter jump DOCKER-USER", "counter jump DOCKER-FORWARD"},
			rules: [][][]byte{jump("DOCKER-USER"), jump("DOCKER-FORWARD")}}
	}
	jumps := [][][]byte{jump("DOCKER-CT"), jump("DOCKER-INTERNAL"), jump("DOCKER-BRIDGE")}
	jumpSpecs := []string{"counter jump DOCKER-CT", "counter jump DOCKER-INTERNAL", "counter jump DOCKER-BRIDGE"}
	network := exitLabHost[4].container.Masked()
	return map[uint8][]dockerChain{
		unix.NFPROTO_IPV4: {
			{table: "filter", name: "DOCKER",
				specs: []string{"iifname != \"" + exitBridge + "\" " + bridge + " counter drop"},
				rules: [][][]byte{slices.Concat(nftables.MetaCompare(unix.NFT_META_IIFNAME, unix.NFT_CMP_NEQ, exitBridge), out, [][]byte{counter, labVerdict(labDrop)})}},
			{table: "filter", name: "DOCKER-CT",
				specs: []string{bridge + " ct state related,established counter accept"},
				rules: [][][]byte{slices.Concat(out, established, [][]byte{counter, labVerdict(nftables.Accept)})}},
			{table: "filter", name: "DOCKER-INTERNAL"},
			{table: "filter", name: "DOCKER-BRIDGE", specs: []string{bridge + " counter jump DOCKER"}, rules: [][][]byte{slices.Concat(out, jump("DOCKER"))}},
			{table: "filter", name: "DOCKER-USER"},
			{table: "filter", name: "DOCKER-FORWARD",
				specs: append(slices.Clone(jumpSpecs), "iifname \""+exitBridge+"\" counter accept"),
				rules: append(slices.Clone(jumps), slices.Concat(in, [][]byte{counter, labVerdict(nftables.Accept)}))},
			withTable(forward(ipv4), "filter"),
			{table: "nat", name: "POSTROUTING", kind: "nat", hook: unix.NF_INET_POST_ROUTING, priority: 100, policy: nftables.Accept,
				specs: []string{fmt.Sprintf("ip saddr %s oifname != \"%s\" counter masquerade", network, exitBridge)},
				rules: [][][]byte{slices.Concat(nftables.SourcePrefix(network), nftables.MetaCompare(unix.NFT_META_OIFNAME, unix.NFT_CMP_NEQ, exitBridge),
					[][]byte{counter, nftables.Expression("masq", nil)})}},
		},
		unix.NFPROTO_IPV6: {
			{table: "filter", name: "DOCKER"},
			{table: "filter", name: "DOCKER-CT"},
			{table: "filter", name: "DOCKER-INTERNAL"},
			{table: "filter", name: "DOCKER-BRIDGE"},
			{table: "filter", name: "DOCKER-USER"},
			{table: "filter", name: "DOCKER-FORWARD", specs: jumpSpecs, rules: jumps},
			withTable(forward(nftables.Accept), "filter"),
		},
	}
}

func withTable(c dockerChain, table string) dockerChain {
	c.table = table
	return c
}

// writeDocker writes dockerTables for ip filter's FORWARD policy ipv4, each table's regular chains ahead of its base chains and every chain ahead of the rules
func writeDocker(ipv4 uint32) func(t *testing.T, lab *exitLab) {
	return func(t *testing.T, lab *exitLab) {
		t.Helper()
		if err := lab.leaf.Do(func() error {
			conn, err := nftables.Dial()
			if err != nil {
				return err
			}
			defer conn.Close()
			var chains, rules []nftables.Request
			made := map[string]bool{}
			for _, proto := range []uint8{unix.NFPROTO_IPV4, unix.NFPROTO_IPV6} {
				for _, chain := range dockerTables(ipv4)[proto] {
					if key := fmt.Sprint(proto, chain.table); !made[key] {
						made[key] = true
						chains = append(chains, nftables.NewTable(proto, chain.table))
					}
					body := nftables.PutNfgenmsg(nil, proto)
					body = nftables.PutAttrString(body, unix.NFTA_CHAIN_TABLE, chain.table)
					body = nftables.PutAttrString(body, unix.NFTA_CHAIN_NAME, chain.name)
					if chain.kind != "" {
						hooked := nftables.PutAttrBE32(nil, unix.NFTA_HOOK_HOOKNUM, chain.hook)
						hooked = nftables.PutAttrBE32(hooked, unix.NFTA_HOOK_PRIORITY, uint32(chain.priority))
						body = nftables.PutAttr(body, unix.NFTA_CHAIN_HOOK|unix.NLA_F_NESTED, hooked)
						body = nftables.PutAttrBE32(body, unix.NFTA_CHAIN_POLICY, chain.policy)
						body = nftables.PutAttrString(body, unix.NFTA_CHAIN_TYPE, chain.kind)
					}
					chains = append(chains, nftables.Request{Kind: nftables.Command(unix.NFT_MSG_NEWCHAIN), Flags: unix.NLM_F_CREATE, Body: body})
					for i, spec := range chain.specs {
						rule, err := nftables.Chain{Table: chain.table, Name: chain.name}.Rule(proto, spec, chain.rules[i])
						if err != nil {
							return err
						}
						rules = append(rules, rule)
					}
				}
			}
			return conn.Batch(slices.Concat(chains, rules))
		}); err != nil {
			t.Fatalf("write Docker's tables: %v", err)
		}
	}
}

// a leaf in mode 2 forwarding Docker's bridge beside Docker 29.9.1's tables, live, retracted and after kill -9, under ip filter's
// FORWARD policy accept, as a host forwarding before Docker starts keeps it, and drop, as Docker sets it on a host that was not:
// DOCKER-FORWARD accepts whatever enters by the bridge, so the bridge's flow follows the mode under either policy, masqueraded to the
// tun's address while the mesh's defaults are live, while the policy alone decides the LAN's IPv4 flow, which drop stops before it
// leaves. ip6 filter's policy stays accept.
func TestTUNExitModeBesideDocker(t *testing.T) {
	for name, policy := range map[string]uint32{"forward policy accept": nftables.Accept, "forward policy drop": labDrop} {
		t.Run(name, func(t *testing.T) {
			runBeside(t, exitBeside{
				write: writeDocker(policy),
				probes: func(state string) []rulesProbe {
					return besideRow(state, besideUnless(state, rulesIntoTun), rulesOutUplink)
				},
				flows: func(state string, family int) (rulesVerdict, rulesVerdict) {
					bridge, lan := besideModeTwo(state, family)
					if policy == labDrop && family == 4 {
						lan = rulesNowhere
					}
					return bridge, lan
				},
			})
		})
	}
}
