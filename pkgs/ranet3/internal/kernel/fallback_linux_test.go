// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/netlink"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/nftables"
	"ranet3.com/pkgs/ranet3/schema"
)

const (
	// fallbackRestoreBudget is how soon a pass answers another writer's change
	// to the switch, the settle window and one pass, where the periodic pass the
	// test sets takes an hour
	fallbackRestoreBudget = time.Second
)

// fallbackLines is the lines of the chain at postrouting in fallbackSample's
// switch as nft spells them, and output's with fib daddr type local accept
// ahead of the drop
const fallbackLines = `		oifname { "lo", "ranetsw0" } accept
		meta mark 0x00000072 accept
		meta iif != 0 iifname != @forwarded fib daddr type != local accept
		ip daddr @lan4 accept
		ip6 daddr @lan6 accept
		ip daddr { 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255 } accept
		ip6 daddr { fe80::/10, ff00::/8 } accept
		icmpv6 type { nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } ip6 hoplimit 255 accept
		meta iif 0 icmpv6 type packet-too-big accept
		meta iif 0 icmp type destination-unreachable icmp code 4 accept
		ip daddr @self4 accept
		ip6 daddr @self6 accept
		ct direction reply ct protocol tcp ct original proto-dst @tcpports accept
		ct direction reply ct protocol udp ct original proto-dst @udpports accept
		counter drop
`

// fallbackText is fallbackSample's switch as nft spells it, each line under the
// comment the platform writes for it
func fallbackText(t *testing.T) string {
	t.Helper()
	text := `table inet ranet3 {
	set forwarded { type ifname; elements = { "lo", "ranetfw0" } }
	set lan4 { type ipv4_addr; flags interval; elements = { 198.51.100.0/25 } }
	set lan6 { type ipv6_addr; flags interval; elements = { 2001:db8:a::/64 } }
	set self4 { type ipv4_addr; flags interval; elements = { 203.0.113.0/24 } }
	set self6 { type ipv6_addr; flags interval; }
	set tcpports { type inet_service; flags interval; elements = { 22, 2222 } }
	set udpports { type inet_service; flags interval; elements = { 53, 60000-61000 } }
`
	postrouting := strings.Split(strings.TrimSuffix(fallbackLines, "\n"), "\n")
	output := slices.Insert(slices.Clone(postrouting), len(postrouting)-1, "\t\tfib daddr type local accept")
	for i, chain := range []struct {
		header string
		lines  []string
	}{
		{"\tchain fallback {\n\t\ttype filter hook postrouting priority 2147483646; policy accept;\n", postrouting},
		{"\tchain output {\n\t\ttype filter hook output priority 2147483646; policy accept;\n", output},
	} {
		rules, err := fallbackSample.rules(i)
		if err != nil || len(rules) != len(chain.lines) {
			t.Fatalf("the sample's chain %s has %d lines (err %v), where the text spells %d", fallbackChains[i].Name, len(rules), err, len(chain.lines))
		}
		text += chain.header
		for j, rule := range rules {
			text += fmt.Sprintf("%s comment %q\n", chain.lines[j], rule.spec)
		}
		text += "\t}\n"
	}
	return text + "}\n"
}

// The switch's rewrite of a set nf_tables will not change in place, and its
// withdrawal, leave the antispoof filter's and the translator's chains, rules,
// sets and objects in the same table as they were, each by its handle, as
// another writer's socket wrote them under the names those owners write, and
// the switch's withdrawal leaves the table to them
func TestNetlinkFallbackKeepsTheOtherOwnersObjects(t *testing.T) {
	plat := rootRulePlatform(t, "ranetsw0")
	nft, err := exec.LookPath("nft")
	if err != nil {
		t.Fatal("the other owners' chains are written through nft, which is not on the path")
	}
	run := func(script string) {
		t.Helper()
		cmd := exec.Command(nft, "-f", "-")
		cmd.Stdin = strings.NewReader(script)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("nft -f %q: %v\n%s", script, err, out)
		}
	}
	if err := plat.writeFallback(fallbackSample, false); err != nil {
		t.Fatal(err)
	}
	run(fmt.Sprintf(`add chain inet %[1]s antispoof { type filter hook prerouting priority -300; policy accept; }
add rule inet %[1]s antispoof iifname "lo" accept comment "accept via lo"
add set inet %[1]s owned4 { type ipv4_addr; flags interval; elements = { 192.0.2.7 } }
add chain inet %[1]s postrouting { type nat hook postrouting priority 99; policy accept; }
add rule inet %[1]s postrouting oifname != "ranet0" counter masquerade comment "ipv4 out via ranet0 masquerade"
add set inet %[1]s flows4 { type ipv4_addr; size 65535; flags dynamic; }
add ct timeout inet %[1]s udp4 { protocol udp; l3proto ip; policy = { unreplied: 120s, replied: 120s }; }
`, nftables.Table))
	// every line of the listing outside the switch's chains and sets, which carries its handle
	others := func() []string {
		listing, err := exec.Command(nft, "-a", "list", "table", "inet", nftables.Table).CombinedOutput()
		if err != nil {
			t.Fatalf("nft list: %v\n%s", err, listing)
		}
		var out []string
		inSwitch := false
		for _, line := range strings.Split(string(listing), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "chain ") || strings.HasPrefix(trimmed, "set ") || strings.HasPrefix(trimmed, "ct timeout ") {
				name := strings.Fields(trimmed)[1]
				if strings.HasPrefix(trimmed, "ct timeout ") {
					name = strings.Fields(trimmed)[2]
				}
				inSwitch = slices.ContainsFunc(fallbackNamed, func(s nftables.Set) bool { return s.Name == name }) || slices.ContainsFunc(fallbackChains, func(c nftables.Chain) bool { return c.Name == name })
			}
			if !inSwitch && strings.Contains(line, "# handle") {
				out = append(out, trimmed)
			}
		}
		return out
	}
	before := others()
	if len(before) < 7 {
		t.Fatalf("the other owners' listing holds %d lines with handles, want every chain, rule, set and object of theirs:\n%s", len(before), strings.Join(before, "\n"))
	}
	// lan4 made again without its interval flag, which only a delete mends
	run(fmt.Sprintf("flush chain inet %[1]s fallback; flush chain inet %[1]s output; delete set inet %[1]s lan4; add set inet %[1]s lan4 { type ipv4_addr; }", nftables.Table))
	read, err := plat.readFallback(fallbackSample)
	if err != nil || read.fault == "" || !read.remake {
		t.Fatalf("with lan4 made again the switch reads back as %+v (%v), want a fault that remakes it", read, err)
	}
	if err := plat.writeFallback(fallbackSample, read.remake); err != nil {
		t.Fatal(err)
	}
	if read, err := plat.readFallback(fallbackSample); read.fault != "" || err != nil {
		t.Errorf("after the remake the switch reads back with %q (%v)", read.fault, err)
	}
	if after := others(); !slices.Equal(after, before) {
		t.Errorf("the switch's remake changed the other owners' listing from\n%s\nto\n%s", strings.Join(before, "\n"), strings.Join(after, "\n"))
	}
	if err := plat.deleteFallback(); err != nil {
		t.Fatal(err)
	}
	if after := others(); !slices.Equal(after, before) {
		t.Errorf("the switch's withdrawal changed the other owners' listing from\n%s\nto\n%s", strings.Join(before, "\n"), strings.Join(after, "\n"))
	}
	if read, err := plat.readFallback(fallbackSample); read.fault != "its chains are missing" || err != nil {
		t.Errorf("after the withdrawal the switch reads back with %q (%v)", read.fault, err)
	}
}

// oneField is set's Create with a description of one concatenated field as
// long as its key, NFTA_SET_DESC_CONCAT holding one NFTA_SET_FIELD_LEN, after
// Create's own description, which nf_tables takes the last of. A dump shows
// the set as Create makes it, and nf_tables refuses Create over it.
func oneField(t *testing.T, set nftables.Set) nftables.Request {
	t.Helper()
	made, err := set.Create(unix.NFPROTO_INET)
	if err != nil {
		t.Fatal(err)
	}
	field := netlink.PutAttr(nil, unix.NFTA_LIST_ELEM|unix.NLA_F_NESTED, nftables.PutAttrBE32(nil, 1, set.KeyLen))
	desc := netlink.PutAttr(nftables.PutAttrBE32(nil, unix.NFTA_SET_DESC_SIZE, set.Size), 2|unix.NLA_F_NESTED, field)
	made.Body = netlink.PutAttr(made.Body, unix.NFTA_SET_DESC|unix.NLA_F_NESTED, desc)
	return made
}

// The switch's set forwarded made again by another writer with one
// concatenated field, which nf_tables refuses the switch's create for, and
// the switch's chains flushed, which its read finds as a fault that remakes
// nothing, is made again by the switch's pass once nothing else uses it,
// after which the switch holds and reads back as written. While another
// writer's rule looks the set up the pass is refused with EBUSY, and the
// switch is not holding with a fault that says so.
func TestNetlinkFallbackMakesAgainASetItsCreateIsRefusedFor(t *testing.T) {
	const device, uplink = "ranetsw0", "ranetup0"
	plat := rootRulePlatform(t, device)
	tbl, rt := fallbackNoneOverUplink(t, device, uplink)
	plat.retable(tbl)
	reconciler := newReconciler(tbl, rt, tbl.Assigned(nil), netstack.NewRouteTable(), plat)
	exit, _ := reconciler.exitPass(reconciler.addresses, nil, reconciler.readNetwork())
	sets, asked := reconciler.fallbackFor(exit)
	if !asked {
		t.Fatal("the mode does not ask for the switch")
	}
	if status, err := reconciler.applyFallback(sets, true); err != nil || status == nil || status.State != FallbackHolding {
		t.Fatalf("the switch's first pass reports %+v (%v), want holding", status, err)
	}
	another, err := nftables.Dial()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = another.Close() })
	forwarded := fallbackNamed[slices.IndexFunc(fallbackNamed, func(set nftables.Set) bool { return set.Name == "forwarded" })]
	requests := []nftables.Request{fallbackChain.Flush(unix.NFPROTO_INET), fallbackOutput.Flush(unix.NFPROTO_INET), forwarded.Delete(unix.NFPROTO_INET), oneField(t, forwarded)}
	if err := another.Batch(requests); err != nil {
		t.Fatalf("another writer makes forwarded again: %v", err)
	}
	made, err := forwarded.Create(unix.NFPROTO_INET)
	if err != nil {
		t.Fatal(err)
	}
	if err := another.Batch([]nftables.Request{made}); !errors.Is(err, unix.EEXIST) {
		t.Fatalf("the switch's create of forwarded made again: %v, want %v", err, unix.EEXIST)
	}
	if read, err := plat.readFallback(sets); err != nil || read.fault == "" || read.remake {
		t.Fatalf("with forwarded made again the switch reads back as %+v (%v), want a fault that remakes nothing", read, err)
	}
	other := nftables.Chain{Table: nftables.Table, Name: "other", Hook: nftables.NoHook}
	rule, err := other.Rule(unix.NFPROTO_INET, "other", [][]byte{nftables.MetaLoad(unix.NFT_META_IIFNAME), nftables.Lookup(forwarded, false)})
	if err != nil {
		t.Fatal(err)
	}
	if err := another.Batch([]nftables.Request{other.Create(unix.NFPROTO_INET), rule}); err != nil {
		t.Fatalf("another writer's rule that looks forwarded up: %v", err)
	}
	status, err := reconciler.applyFallback(sets, true)
	if !errors.Is(err, unix.EBUSY) {
		t.Errorf("the switch's pass while another writer's rule looks forwarded up: %v, want %v", err, unix.EBUSY)
	}
	if status == nil || status.State != FallbackNotHolding || !strings.Contains(status.Fault, unix.EBUSY.Error()) {
		t.Errorf("the refused pass reports %+v, want not holding with %q", status, unix.EBUSY.Error())
	}
	if err := another.Batch([]nftables.Request{other.Flush(unix.NFPROTO_INET), other.Delete(unix.NFPROTO_INET)}); err != nil {
		t.Fatalf("another writer deletes its rule: %v", err)
	}
	if status, err := reconciler.applyFallback(sets, true); err != nil || status == nil || status.State != FallbackHolding {
		t.Errorf("the switch's pass reports %+v (%v), want holding", status, err)
	}
	if read, err := plat.readFallback(sets); read.fault != "" || err != nil {
		t.Errorf("after the switch's pass it reads back with %q (%v)", read.fault, err)
	}
}

// The switch's set lan4 made again by another writer as an anonymous set
// holding every IPv4 address, held by a line of that writer's in the switch's
// output chain, with the switch's own lines gone, passes a datagram beyond the
// LAN. The switch's pass, which flushes that line, makes the set again, after
// which the switch holds, reads back as written and refuses that datagram
// while it passes one to the LAN.
func TestNetlinkFallbackMakesAgainASetAnotherWriterMadeAnonymous(t *testing.T) {
	const device, uplink = "ranetsw0", "ranetup0"
	plat := rootRulePlatform(t, device)
	tbl, rt := fallbackNoneOverUplink(t, device, uplink)
	plat.retable(tbl)
	reconciler := newReconciler(tbl, rt, tbl.Assigned(nil), netstack.NewRouteTable(), plat)
	exit, _ := reconciler.exitPass(reconciler.addresses, nil, reconciler.readNetwork())
	sets, asked := reconciler.fallbackFor(exit)
	if !asked {
		t.Fatal("the mode does not ask for the switch")
	}
	if status, err := reconciler.applyFallback(sets, true); err != nil || status == nil || status.State != FallbackHolding {
		t.Fatalf("the switch's first pass reports %+v (%v), want holding", status, err)
	}
	beyond, lan := netip.MustParseAddr("192.0.2.200"), netip.MustParseAddr("198.51.100.5")
	if err := sendFrom(t, beyond, 9, ""); !errors.Is(err, unix.EPERM) {
		t.Fatalf("with the switch holding a datagram beyond the LAN left with %v, want EPERM", err)
	}
	another, err := nftables.Dial()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = another.Close() })
	lan4 := fallbackNamed[slices.IndexFunc(fallbackNamed, func(set nftables.Set) bool { return set.Name == "lan4" })]
	made := lan4
	made.Flags |= unix.NFT_SET_ANONYMOUS | unix.NFT_SET_CONSTANT
	create, err := made.Create(unix.NFPROTO_INET)
	if err != nil {
		t.Fatal(err)
	}
	filled, err := made.Fill(unix.NFPROTO_INET, nftables.Prefixes([]netip.Prefix{prefix("0.0.0.0/0")}))
	if err != nil {
		t.Fatal(err)
	}
	line, err := fallbackOutput.Rule(unix.NFPROTO_INET, "theirs", [][]byte{nftables.DestinationLoad(unix.NFPROTO_IPV4), nftables.Lookup(made, false)})
	if err != nil {
		t.Fatal(err)
	}
	requests := slices.Concat([]nftables.Request{fallbackChain.Flush(unix.NFPROTO_INET), fallbackOutput.Flush(unix.NFPROTO_INET), lan4.Delete(unix.NFPROTO_INET), create}, filled, []nftables.Request{line})
	if err := another.Batch(requests); err != nil {
		t.Fatalf("another writer makes lan4 again anonymous: %v", err)
	}
	if err := sendFrom(t, beyond, 9, ""); err != nil {
		t.Fatalf("with lan4 made again a datagram beyond the LAN left with %v, want sent", err)
	}
	if read, err := plat.readFallback(sets); err != nil || read.fault == "" || read.remake {
		t.Errorf("with lan4 made again the switch reads back as %+v (%v), want a fault that remakes nothing", read, err)
	}
	if status, err := reconciler.applyFallback(sets, true); err != nil || status == nil || status.State != FallbackHolding {
		t.Errorf("the switch's pass reports %+v (%v), want holding", status, err)
	}
	if read, err := plat.readFallback(sets); read.fault != "" || err != nil {
		t.Errorf("after the switch's pass it reads back with %q (%v)", read.fault, err)
	}
	if err := sendFrom(t, beyond, 9, ""); !errors.Is(err, unix.EPERM) {
		t.Errorf("after the switch's pass a datagram beyond the LAN left with %v, want EPERM", err)
	}
	if err := sendFrom(t, lan, 9, ""); err != nil {
		t.Errorf("after the switch's pass a datagram to the LAN was refused: %v", err)
	}
}

// Anonymous sets another writer makes under own4 and udp_ports, the names an
// earlier switch gave self4 and udpports, holding every IPv4 address and port
// 9, each read by a line of that writer's that accepts at the head of one of
// the switch's chains, pass a datagram beyond the LAN. The switch's pass,
// whose flush of those lines takes the sets out with them, holds and reads
// back as written, and refuses that datagram while it passes one to the LAN.
func TestNetlinkFallbackLeavesAnonymousSetsUnderEarlierNamesToItsFlush(t *testing.T) {
	const device, uplink = "ranetsw0", "ranetup0"
	plat := rootRulePlatform(t, device)
	tbl, rt := fallbackNoneOverUplink(t, device, uplink)
	plat.retable(tbl)
	reconciler := newReconciler(tbl, rt, tbl.Assigned(nil), netstack.NewRouteTable(), plat)
	exit, _ := reconciler.exitPass(reconciler.addresses, nil, reconciler.readNetwork())
	sets, asked := reconciler.fallbackFor(exit)
	if !asked {
		t.Fatal("the mode does not ask for the switch")
	}
	if status, err := reconciler.applyFallback(sets, true); err != nil || status == nil || status.State != FallbackHolding {
		t.Fatalf("the switch's first pass reports %+v (%v), want holding", status, err)
	}
	beyond, lan := netip.MustParseAddr("192.0.2.200"), netip.MustParseAddr("198.51.100.5")
	if err := sendFrom(t, beyond, 9, ""); !errors.Is(err, unix.EPERM) {
		t.Fatalf("with the switch holding a datagram beyond the LAN left with %v, want EPERM", err)
	}
	another, err := nftables.Dial()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = another.Close() })
	var requests []nftables.Request
	for _, c := range []struct {
		chain nftables.Chain
		set   nftables.Set
		held  []nftables.Interval
		load  [][]byte
	}{
		{
			fallbackChain, nftables.Set{Table: nftables.Table, Name: earlierSets["self4"], ID: 1, KeyType: nftables.TypeIPv4Addr, KeyLen: 4},
			nftables.Prefixes([]netip.Prefix{prefix("0.0.0.0/0")}), slices.Concat(nftables.NFProto(unix.NFPROTO_IPV4), [][]byte{nftables.DestinationLoad(unix.NFPROTO_IPV4)}),
		},
		{
			fallbackOutput, nftables.Set{Table: nftables.Table, Name: earlierSets["udpports"], ID: 2, KeyType: nftables.TypeInetService, KeyLen: 2},
			[]nftables.Interval{{First: []byte{0, 9}, Last: []byte{0, 9}}}, append(nftables.MetaCompareValue(unix.NFT_META_L4PROTO, unix.NFT_CMP_EQ, []byte{unix.IPPROTO_UDP}), nftables.TransportLoad(2, 2)),
		},
	} {
		c.set.Flags = unix.NFT_SET_INTERVAL | unix.NFT_SET_ANONYMOUS | unix.NFT_SET_CONSTANT
		create, err := c.set.Create(unix.NFPROTO_INET)
		if err != nil {
			t.Fatal(err)
		}
		filled, err := c.set.Fill(unix.NFPROTO_INET, c.held)
		if err != nil {
			t.Fatal(err)
		}
		line, err := c.chain.Rule(unix.NFPROTO_INET, "theirs", append(c.load, nftables.Lookup(c.set, false), nftables.Verdict(nftables.Accept)))
		if err != nil {
			t.Fatal(err)
		}
		// with no NLM_F_APPEND nf_tables puts the line at the head of the chain
		line.Flags = unix.NLM_F_CREATE
		requests = slices.Concat(requests, []nftables.Request{create}, filled, []nftables.Request{line})
	}
	if err := another.Batch(requests); err != nil {
		t.Fatalf("another writer makes the anonymous sets and the lines at the head of the switch's chains that read them: %v", err)
	}
	if err := sendFrom(t, beyond, 9, ""); err != nil {
		t.Fatalf("with those lines a datagram beyond the LAN left with %v, want sent", err)
	}
	read, err := plat.readFallback(sets)
	if err != nil || read.fault == "" {
		t.Errorf("with those lines the switch reads back with %q (%v), want a fault", read.fault, err)
	}
	t.Logf("with those lines the switch reads back with %q", read.fault)
	status, err := reconciler.applyFallback(sets, true)
	if err != nil || status == nil || status.State != FallbackHolding {
		t.Errorf("the switch's pass reports %+v (%v), want holding", status, err)
	}
	if read, err := plat.readFallback(sets); read.fault != "" || err != nil {
		t.Errorf("after the switch's pass it reads back with %q (%v)", read.fault, err)
	}
	if err := sendFrom(t, beyond, 9, ""); !errors.Is(err, unix.EPERM) {
		t.Errorf("after the switch's pass a datagram beyond the LAN left with %v, want EPERM", err)
	}
	if err := sendFrom(t, lan, 9, ""); err != nil {
		t.Errorf("after the switch's pass a datagram to the LAN was refused: %v", err)
	}
	// the same set read by a line of a chain of that writer's own, which no flush of the switch's takes out
	other := nftables.Chain{Table: nftables.Table, Name: "other", Type: "filter", Hook: unix.NF_INET_LOCAL_OUT, Priority: 0}
	held := nftables.Set{Table: nftables.Table, Name: earlierSets["self4"], ID: 1, KeyType: nftables.TypeIPv4Addr, KeyLen: 4, Flags: unix.NFT_SET_INTERVAL | unix.NFT_SET_ANONYMOUS | unix.NFT_SET_CONSTANT}
	create, err := held.Create(unix.NFPROTO_INET)
	if err != nil {
		t.Fatal(err)
	}
	filled, err := held.Fill(unix.NFPROTO_INET, nftables.Prefixes([]netip.Prefix{prefix("0.0.0.0/0")}))
	if err != nil {
		t.Fatal(err)
	}
	line, err := other.Rule(unix.NFPROTO_INET, "theirs", slices.Concat(nftables.NFProto(unix.NFPROTO_IPV4), [][]byte{nftables.DestinationLoad(unix.NFPROTO_IPV4), nftables.Lookup(held, false), nftables.Verdict(nftables.Accept)}))
	if err != nil {
		t.Fatal(err)
	}
	if err := another.Batch(slices.Concat([]nftables.Request{other.Create(unix.NFPROTO_INET), create}, filled, []nftables.Request{line})); err != nil {
		t.Fatalf("another writer makes %s again read by a line of its own chain: %v", held.Name, err)
	}
	want := "its set " + held.Name + " is not one the kill switch writes, and chain other holds a rule using it, so it stays until that rule goes"
	if status, err := reconciler.applyFallback(sets, true); err != nil || status == nil || status.State != FallbackNotHolding || status.Fault != want {
		t.Errorf("the switch's pass beside the set another writer's chain holds reports %+v (%v), want not holding with %q", status, err, want)
	}
	if err := sendFrom(t, beyond, 9, ""); !errors.Is(err, unix.EPERM) {
		t.Errorf("beside the set another writer's chain holds a datagram beyond the LAN left with %v, want EPERM", err)
	}
	if err := sendFrom(t, lan, 9, ""); err != nil {
		t.Errorf("beside the set another writer's chain holds a datagram to the LAN was refused: %v", err)
	}
}

// nftChainFlags and nftChainBinding are NFTA_CHAIN_FLAGS and
// NFT_CHAIN_BINDING, which x/sys does not carry
const (
	nftChainFlags   = 10
	nftChainBinding = 0x4
)

// acceptingBinding is another writer's transaction that makes a binding chain
// named name, holding a line that accepts, and puts a goto to it at the head
// of from, which binds it
func acceptingBinding(t *testing.T, from nftables.Chain, name string) []nftables.Request {
	t.Helper()
	bound := nftables.Chain{Table: nftables.Table, Name: name, Hook: nftables.NoHook}
	made := bound.Create(unix.NFPROTO_INET)
	made.Body = nftables.PutAttrBE32(made.Body, nftChainFlags, nftChainBinding)
	accept, err := bound.Rule(unix.NFPROTO_INET, "theirs", [][]byte{nftables.Verdict(nftables.Accept)})
	if err != nil {
		t.Fatal(err)
	}
	goes, err := from.Rule(unix.NFPROTO_INET, "theirs", [][]byte{nftables.Goto(name)})
	if err != nil {
		t.Fatal(err)
	}
	// with no NLM_F_APPEND nf_tables puts the line at the head of the chain
	goes.Flags = unix.NLM_F_CREATE
	return []nftables.Request{made, accept, goes}
}

// holdingSwitch is the platform, the reconciler and the sets of the switch
// over an uplink after a first pass that holds, which refuses a datagram
// beyond the LAN
func holdingSwitch(t *testing.T) (*netlinkPlatform, *Reconciler, fallbackSets) {
	t.Helper()
	const device, uplink = "ranetsw0", "ranetup0"
	plat := rootRulePlatform(t, device)
	tbl, rt := fallbackNoneOverUplink(t, device, uplink)
	plat.retable(tbl)
	reconciler := newReconciler(tbl, rt, tbl.Assigned(nil), netstack.NewRouteTable(), plat)
	exit, _ := reconciler.exitPass(reconciler.addresses, nil, reconciler.readNetwork())
	sets, asked := reconciler.fallbackFor(exit)
	if !asked {
		t.Fatal("the mode does not ask for the switch")
	}
	if status, err := reconciler.applyFallback(sets, true); err != nil || status == nil || status.State != FallbackHolding {
		t.Fatalf("the switch's first pass reports %+v (%v), want holding", status, err)
	}
	if err := sendFrom(t, netip.MustParseAddr("192.0.2.200"), 9, ""); !errors.Is(err, unix.EPERM) {
		t.Fatalf("with the switch holding a datagram beyond the LAN left with %v, want EPERM", err)
	}
	return plat, reconciler, sets
}

// An anonymous set another writer makes under own4, the name an earlier switch
// gave self4, holding every IPv4 address and read by an accepting line of a
// binding chain bound from the head of the switch's chain at postrouting,
// beside one accepting from the head of output, passes a datagram beyond the
// LAN. The switch's flush of the chain at postrouting takes the set out with
// the binding chain, so the read before the pass names the foreign line and
// not the set, and the pass holds and refuses that datagram.
func TestNetlinkFallbackReadsNoSetHeldByABindingChainItsFlushTakesOut(t *testing.T) {
	plat, reconciler, sets := holdingSwitch(t)
	beyond := netip.MustParseAddr("192.0.2.200")
	another, err := nftables.Dial()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = another.Close() })
	set := nftables.Set{Table: nftables.Table, Name: earlierSets["self4"], ID: 1, KeyType: nftables.TypeIPv4Addr, KeyLen: 4, Flags: unix.NFT_SET_INTERVAL | unix.NFT_SET_ANONYMOUS | unix.NFT_SET_CONSTANT}
	create, err := set.Create(unix.NFPROTO_INET)
	if err != nil {
		t.Fatal(err)
	}
	filled, err := set.Fill(unix.NFPROTO_INET, nftables.Prefixes([]netip.Prefix{prefix("0.0.0.0/0")}))
	if err != nil {
		t.Fatal(err)
	}
	bound := nftables.Chain{Table: nftables.Table, Name: "theirs4", Hook: nftables.NoHook}
	made := bound.Create(unix.NFPROTO_INET)
	made.Body = nftables.PutAttrBE32(made.Body, nftChainFlags, nftChainBinding)
	accept, err := bound.Rule(unix.NFPROTO_INET, "theirs", slices.Concat(nftables.NFProto(unix.NFPROTO_IPV4), [][]byte{nftables.DestinationLoad(unix.NFPROTO_IPV4), nftables.Lookup(set, false), nftables.Verdict(nftables.Accept)}))
	if err != nil {
		t.Fatal(err)
	}
	goes, err := fallbackChain.Rule(unix.NFPROTO_INET, "theirs", [][]byte{nftables.Goto(bound.Name)})
	if err != nil {
		t.Fatal(err)
	}
	// with no NLM_F_APPEND nf_tables puts the line at the head of the chain
	goes.Flags = unix.NLM_F_CREATE
	if err := another.Batch(slices.Concat([]nftables.Request{create}, filled, []nftables.Request{made, accept, goes}, acceptingBinding(t, fallbackOutput, "theirsout"))); err != nil {
		t.Fatalf("another writer makes %s, the binding chain that reads it and one that accepts at output: %v", set.Name, err)
	}
	if err := sendFrom(t, beyond, 9, ""); err != nil {
		t.Fatalf("with the binding chain a datagram beyond the LAN left with %v, want sent", err)
	}
	if read, err := plat.readFallback(sets); err != nil || !strings.HasPrefix(read.fault, "its chain fallback holds [theirs;") {
		t.Errorf("with the binding chain the switch reads back with %q (%v), want its chain fallback's foreign line", read.fault, err)
	}
	if status, err := reconciler.applyFallback(sets, true); err != nil || status == nil || status.State != FallbackHolding {
		t.Errorf("the switch's pass reports %+v (%v), want holding", status, err)
	}
	if err := sendFrom(t, beyond, 9, ""); !errors.Is(err, unix.EPERM) {
		t.Errorf("after the switch's pass a datagram beyond the LAN left with %v, want EPERM", err)
	}
}

// A binding chain another writer makes under the name of the switch's output
// chain, in the transaction that deletes that chain, accepting and bound from
// the head of the switch's chain at postrouting, passes a datagram beyond the
// LAN. The switch's pass, which flushes the chain at postrouting before it
// makes output, takes the binding chain out with the goto and makes output
// again, holds, reads back as written, and refuses that datagram while it
// passes one to the LAN. So does the pass where that writer makes the chain at
// postrouting again at another priority, which the pass deletes first, and the
// binding chain with it.
func TestNetlinkFallbackMakesAgainAChainUnderItsNameItsFlushTakesOut(t *testing.T) {
	plat, reconciler, sets := holdingSwitch(t)
	beyond, lan := netip.MustParseAddr("192.0.2.200"), netip.MustParseAddr("198.51.100.5")
	another, err := nftables.Dial()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = another.Close() })
	moved := fallbackChain
	moved.Priority = 0
	for _, c := range []struct {
		name string
		head []nftables.Request
		from nftables.Chain
	}{
		{"output deleted", []nftables.Request{fallbackOutput.Delete(unix.NFPROTO_INET)}, fallbackChain},
		{"postrouting made again at priority 0", []nftables.Request{fallbackChain.Delete(unix.NFPROTO_INET), fallbackOutput.Delete(unix.NFPROTO_INET), moved.Create(unix.NFPROTO_INET)}, moved},
	} {
		if err := another.Batch(append(c.head, acceptingBinding(t, c.from, fallbackOutput.Name)...)); err != nil {
			t.Fatalf("%s: another writer makes the binding chain %s: %v", c.name, fallbackOutput.Name, err)
		}
		if err := sendFrom(t, beyond, 9, ""); err != nil {
			t.Fatalf("%s: with the binding chain a datagram beyond the LAN left with %v, want sent", c.name, err)
		}
		read, err := plat.readFallback(sets)
		if err != nil || read.fault == "" {
			t.Errorf("%s: with the binding chain the switch reads back with %q (%v), want a fault", c.name, read.fault, err)
		}
		t.Logf("%s: with the binding chain the switch reads back with %q, remake %v", c.name, read.fault, read.remake)
		if status, err := reconciler.applyFallback(sets, true); err != nil || status == nil || status.State != FallbackHolding {
			t.Errorf("%s: the switch's pass reports %+v (%v), want holding", c.name, status, err)
		}
		if read, err := plat.readFallback(sets); read.fault != "" || err != nil {
			t.Errorf("%s: after the switch's pass it reads back with %q (%v)", c.name, read.fault, err)
		}
		if err := sendFrom(t, beyond, 9, ""); !errors.Is(err, unix.EPERM) {
			t.Errorf("%s: after the switch's pass a datagram beyond the LAN left with %v, want EPERM", c.name, err)
		}
		if err := sendFrom(t, lan, 9, ""); err != nil {
			t.Errorf("%s: after the switch's pass a datagram to the LAN was refused: %v", c.name, err)
		}
	}
}

// A binding chain another writer makes under the name of the switch's chain at
// postrouting, in the transaction that deletes that chain, accepting and bound
// from the head of the switch's output chain, passes a datagram beyond the
// LAN. The switch makes its chain at postrouting before it flushes output, and
// nf_tables refuses a policy for a chain that is no base chain, so every pass
// is refused: the switch does not hold, with a reason that says how the chain
// reads back and gives the refusal, and the datagram still passes.
func TestNetlinkFallbackReportsAChainUnderItsNameBoundFromALaterChain(t *testing.T) {
	_, reconciler, sets := holdingSwitch(t)
	beyond := netip.MustParseAddr("192.0.2.200")
	another, err := nftables.Dial()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = another.Close() })
	if err := another.Batch(append([]nftables.Request{fallbackChain.Delete(unix.NFPROTO_INET)}, acceptingBinding(t, fallbackOutput, fallbackChain.Name)...)); err != nil {
		t.Fatalf("another writer makes the binding chain %s: %v", fallbackChain.Name, err)
	}
	if err := sendFrom(t, beyond, 9, ""); err != nil {
		t.Fatalf("with the binding chain a datagram beyond the LAN left with %v, want sent", err)
	}
	want := `its chain fallback reads back as type "" at hook -1, priority 0, policy -1, where a filter chain at hook 4, priority 2147483646, policy accept was written, and the write failed: operation not supported`
	for i := range 2 {
		status, err := reconciler.applyFallback(sets, true)
		if !errors.Is(err, unix.EOPNOTSUPP) || status == nil || status.State != FallbackNotHolding || status.Fault != want {
			t.Errorf("the switch's pass %d reports %+v (%v), want not holding with %q", i+1, status, err, want)
		}
		if err := sendFrom(t, beyond, 9, ""); err != nil {
			t.Errorf("after the switch's pass %d a datagram beyond the LAN left with %v, want sent", i+1, err)
		}
	}
}

// otherChain is another writer's regular chain, which no packet enters
var otherChain = nftables.Chain{Table: nftables.Table, Name: "other", Hook: nftables.NoHook}

// holdingForwarded is another writer's transaction that makes otherChain with
// line, which uses the switch's set forwarded, after head
func holdingForwarded(t *testing.T, head []nftables.Request, line ...[]byte) []nftables.Request {
	t.Helper()
	rule, err := otherChain.Rule(unix.NFPROTO_INET, "theirs", line)
	if err != nil {
		t.Fatal(err)
	}
	return append(head, otherChain.Create(unix.NFPROTO_INET), rule)
}

// A rule of another writer's own chain that adds each packet's input link to
// the switch's set forwarded gives the set a size the switch does not write
// (nft_dynset.c, nft_dynset_init). The switch, passing with 192.0.2.0/24 among
// the LAN and told to hold without it, leaves the set to its pass while that
// rule stays: each pass commits beside it, the chains hold the switch's lines
// alone and refuse a datagram to 192.0.2.200, and the switch is not holding
// with a reason that names the chain holding the set. Once the rule goes the
// pass makes the set again and the switch holds.
func TestNetlinkFallbackLeavesASetAnotherWritersRuleSizedToItsPass(t *testing.T) {
	plat, reconciler, sets := holdingSwitch(t)
	beyond := netip.MustParseAddr("192.0.2.200")
	wide := sets
	wide.lan4 = slices.Concat([]netip.Prefix{prefix("192.0.2.0/24")}, sets.lan4)
	reconciler.capturing = true
	if status, err := reconciler.applyFallback(wide, true); err != nil || status == nil || status.State != FallbackPassing {
		t.Fatalf("the pass with 192.0.2.0/24 among the LAN reports %+v (%v), want passing", status, err)
	}
	if err := sendFrom(t, beyond, 9, ""); err != nil {
		t.Fatalf("with 192.0.2.0/24 among the LAN a datagram to it left with %v, want sent", err)
	}
	another, err := nftables.Dial()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = another.Close() })
	adds := nftables.PutAttrBE32(nil, unix.NFTA_DYNSET_SREG_KEY, unix.NFT_REG_1)
	adds = nftables.PutAttrBE32(adds, unix.NFTA_DYNSET_OP, unix.NFT_DYNSET_OP_ADD)
	adds = netlink.PutAttrString(adds, unix.NFTA_DYNSET_SET_NAME, "forwarded")
	if err := another.Batch(holdingForwarded(t, nil, nftables.MetaLoad(unix.NFT_META_IIFNAME), nftables.Expression("dynset", adds))); err != nil {
		t.Fatalf("another writer's rule that adds to forwarded: %v", err)
	}
	read, err := plat.readFallback(sets)
	t.Logf("with the rule the switch reads back with %q, remake %v (%v)", read.fault, read.remake, err)
	reconciler.capturing = false
	held := `size 0 and comment "" were written, and chain other holds a rule using it, so it stays until that rule goes`
	for i := range 2 {
		status, err := reconciler.applyFallback(sets, true)
		sent := sendFrom(t, beyond, 9, "")
		t.Logf("the switch's pass %d told to hold reports %+v (%v), and a datagram to 192.0.2.200 left with %v", i+1, status, err, sent)
		if err != nil || status == nil || status.State != FallbackNotHolding || !strings.Contains(status.Fault, "size 65535") || !strings.HasSuffix(status.Fault, held) {
			t.Errorf("the switch's pass %d reports %+v (%v), want not holding with %q", i+1, status, err, held)
		}
		if !errors.Is(sent, unix.EPERM) {
			t.Errorf("after the switch's pass %d a datagram to 192.0.2.200 left with %v, want EPERM", i+1, sent)
		}
	}
	rules, err := nftables.TableRules(another, unix.NFPROTO_INET, nftables.Table)
	if err != nil {
		t.Fatal(err)
	}
	for i, chain := range fallbackChains {
		if fault, err := chainFault(another, sets, i, rules); fault != "" || err != nil {
			t.Errorf("beside the rule the switch's chain %s reads back with %q (%v)", chain.Name, fault, err)
		}
	}
	if err := another.Batch([]nftables.Request{otherChain.Flush(unix.NFPROTO_INET), otherChain.Delete(unix.NFPROTO_INET)}); err != nil {
		t.Fatalf("another writer deletes its rule: %v", err)
	}
	if status, err := reconciler.applyFallback(sets, true); err != nil || status == nil || status.State != FallbackHolding {
		t.Errorf("once the rule is gone the switch's pass reports %+v (%v), want holding", status, err)
	}
	if read, err := plat.readFallback(sets); read.fault != "" || err != nil {
		t.Errorf("once the rule is gone the switch reads back with %q (%v)", read.fault, err)
	}
	if err := sendFrom(t, beyond, 9, ""); !errors.Is(err, unix.EPERM) {
		t.Errorf("once the rule is gone a datagram to 192.0.2.200 left with %v, want EPERM", err)
	}
}

// The switch's set forwarded made again by another writer flagged dynamic,
// over which nf_tables takes no create of the switch's, looked up by a rule of
// that writer's own chain, with the switch's chains flushed, passes a datagram
// beyond the LAN. Every pass is refused while that rule stays: the switch is
// not holding with a reason that names the chain holding the set and gives the
// refusal, and the datagram still passes. Once the rule goes the pass makes
// the set again and the switch holds.
func TestNetlinkFallbackReportsTheHolderOfASetItCannotMakeAgain(t *testing.T) {
	plat, reconciler, sets := holdingSwitch(t)
	beyond := netip.MustParseAddr("192.0.2.200")
	another, err := nftables.Dial()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = another.Close() })
	forwarded := fallbackNamed[slices.IndexFunc(fallbackNamed, func(set nftables.Set) bool { return set.Name == "forwarded" })]
	dynamic := forwarded
	dynamic.Flags |= unix.NFT_SET_EVAL
	made, err := dynamic.Create(unix.NFPROTO_INET)
	if err != nil {
		t.Fatal(err)
	}
	head := []nftables.Request{fallbackChain.Flush(unix.NFPROTO_INET), fallbackOutput.Flush(unix.NFPROTO_INET), forwarded.Delete(unix.NFPROTO_INET), made}
	if err := another.Batch(holdingForwarded(t, head, nftables.MetaLoad(unix.NFT_META_IIFNAME), nftables.Lookup(dynamic, false))); err != nil {
		t.Fatalf("another writer makes forwarded again flagged dynamic and looks it up: %v", err)
	}
	if err := sendFrom(t, beyond, 9, ""); err != nil {
		t.Fatalf("with the switch's chains flushed a datagram beyond the LAN left with %v, want sent", err)
	}
	held := "and chain other holds a rule using it, so it stays until that rule goes, and the write failed: " + unix.EBUSY.Error()
	for i := range 2 {
		status, err := reconciler.applyFallback(sets, true)
		if !errors.Is(err, unix.EBUSY) || status == nil || status.State != FallbackNotHolding || !strings.HasSuffix(status.Fault, held) {
			t.Errorf("the switch's pass %d reports %+v (%v), want not holding with %q", i+1, status, err, held)
		}
		if err := sendFrom(t, beyond, 9, ""); err != nil {
			t.Errorf("after the switch's pass %d a datagram beyond the LAN left with %v, want sent", i+1, err)
		}
	}
	if err := another.Batch([]nftables.Request{otherChain.Flush(unix.NFPROTO_INET), otherChain.Delete(unix.NFPROTO_INET)}); err != nil {
		t.Fatalf("another writer deletes its rule: %v", err)
	}
	if status, err := reconciler.applyFallback(sets, true); err != nil || status == nil || status.State != FallbackHolding {
		t.Errorf("once the rule is gone the switch's pass reports %+v (%v), want holding", status, err)
	}
	if read, err := plat.readFallback(sets); read.fault != "" || err != nil {
		t.Errorf("once the rule is gone the switch reads back with %q (%v)", read.fault, err)
	}
	if err := sendFrom(t, beyond, 9, ""); !errors.Is(err, unix.EPERM) {
		t.Errorf("once the rule is gone a datagram beyond the LAN left with %v, want EPERM", err)
	}
}

// The switch's set lan4 made again by another writer as a set of single keys,
// over which nf_tables takes no create of the switch's, looked up by a rule of
// that writer's own chain, with the switch's chains flushed and a link of its
// own added to forwarded, which the switch reads first: every pass is refused
// while that rule stays, and the switch is not holding with a reason that
// names lan4 and the chain holding it, not forwarded's other element. Once
// the rule goes the pass makes the set again and the switch holds.
func TestNetlinkFallbackNamesTheHolderOfASetItCannotMakeAgainAheadOfAnEarlierSet(t *testing.T) {
	_, reconciler, sets := holdingSwitch(t)
	another, err := nftables.Dial()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = another.Close() })
	named := func(name string) nftables.Set {
		return fallbackNamed[slices.IndexFunc(fallbackNamed, func(set nftables.Set) bool { return set.Name == name })]
	}
	lan4, forwarded := named("lan4"), named("forwarded")
	single := lan4
	single.Flags = 0
	made, err := single.Create(unix.NFPROTO_INET)
	if err != nil {
		t.Fatal(err)
	}
	added, err := forwarded.Fill(unix.NFPROTO_INET, []nftables.Interval{nftables.Key(nftables.InterfaceName("eth9"))})
	if err != nil {
		t.Fatal(err)
	}
	head := slices.Concat([]nftables.Request{fallbackChain.Flush(unix.NFPROTO_INET), fallbackOutput.Flush(unix.NFPROTO_INET), lan4.Delete(unix.NFPROTO_INET), made}, added)
	if err := another.Batch(holdingForwarded(t, head, nftables.DestinationLoad(unix.NFPROTO_IPV4), nftables.Lookup(single, false))); err != nil {
		t.Fatalf("another writer makes lan4 again of single keys, looks it up and adds to forwarded: %v", err)
	}
	held := "and chain other holds a rule using it, so it stays until that rule goes, and the write failed: " + unix.EBUSY.Error()
	for i := range 2 {
		status, err := reconciler.applyFallback(sets, true)
		if !errors.Is(err, unix.EBUSY) || status == nil || status.State != FallbackNotHolding || !strings.Contains(status.Fault, "its set lan4 reads back") || !strings.HasSuffix(status.Fault, held) {
			t.Errorf("the switch's pass %d reports %+v (%v), want not holding with lan4's fault and %q", i+1, status, err, held)
		}
	}
	if err := another.Batch([]nftables.Request{otherChain.Flush(unix.NFPROTO_INET), otherChain.Delete(unix.NFPROTO_INET)}); err != nil {
		t.Fatalf("another writer deletes its rule: %v", err)
	}
	if status, err := reconciler.applyFallback(sets, true); err != nil || status == nil || status.State != FallbackHolding {
		t.Errorf("once the rule is gone the switch's pass reports %+v (%v), want holding", status, err)
	}
}

// fallbackSample is a switch of every line, on the tun ranetsw0, each port set
// holding a port beside another port or a range
var fallbackSample = fallbackSets{
	tun: "ranetsw0", forwarded: []string{"ranetfw0"},
	lan4: []netip.Prefix{prefix("198.51.100.0/25")}, lan6: []netip.Prefix{prefix("2001:db8:a::/64")},
	self4: []netip.Prefix{prefix("203.0.113.0/24")},
	tcp:   []Service{{Protocol: "tcp", First: 22, Last: 22}, {Protocol: "tcp", First: 2222, Last: 2222}},
	udp:   []Service{{Protocol: "udp", First: 53, Last: 53}, {Protocol: "udp", First: 60000, Last: 61000}},
}

// nft 1.1.7's own table of the same text reads back as the platform writes
// it, and the platform's lists as nft's does and outlives the socket that
// wrote it. A datagram bound to the uplink toward an address another link
// holds, translated so by NAT at output or not, passes output's fib line and
// meets postrouting's drop, and the read sums both chains' drops. Another
// writer's change reads back as a fault until the next write.
func TestNetlinkFallbackTableListsAsNftsOwnAndOutlivesItsWriter(t *testing.T) {
	plat := rootRulePlatform(t, "ranetsw0")
	nft, err := exec.LookPath("nft")
	if err != nil {
		t.Fatal("the table to compare with is written through nft, which is not on the path")
	}
	run := func(args ...string) string {
		t.Helper()
		cmd := exec.Command(nft, args...)
		if args[0] == "-f" {
			cmd.Stdin = strings.NewReader(fallbackText(t))
		}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("nft %s: %v\n%s", strings.Join(args, " "), err, out)
		}
		return string(out)
	}
	runScript := func(script string) {
		t.Helper()
		cmd := exec.Command(nft, "-f", "-")
		cmd.Stdin = strings.NewReader(script)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("nft -f %q: %v\n%s", script, err, out)
		}
	}
	list := func() string {
		return regexp.MustCompile(` comment "[^"]*"`).ReplaceAllString(run("list", "table", "inet", nftables.Table), "")
	}
	run("-f", "-")
	theirs := list()
	if read, err := plat.readFallback(fallbackSample); read.fault != "" || err != nil {
		t.Errorf("nft's table reads back with %q (err %v), want it as the platform writes it", read.fault, err)
	}
	if err := plat.deleteFallback(); err != nil {
		t.Fatal(err)
	}

	// closing the platform's socket for the table deletes a table carrying the
	// owner flag
	if err := plat.writeFallback(fallbackSample, false); err != nil {
		t.Fatalf("write the table: %v", err)
	}
	if err := plat.unwatchFallback(); err != nil {
		t.Fatal(err)
	}
	if mine := list(); mine != theirs {
		t.Errorf("the platform's table lists as\n%s\nwhere nft's lists as\n%s", mine, theirs)
	}
	if read, err := plat.readFallback(fallbackSample); read.fault != "" || err != nil {
		t.Errorf("the table reads back with %q (err %v)", read.fault, err)
	}

	conn, err := dialNetlink()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	const uplink = "ranetup0"
	createTUN(t, uplink)
	createTUN(t, "ranetd1")
	link, err := conn.link(0, uplink)
	if err != nil {
		t.Fatal(err)
	}
	other, err := conn.link(0, "ranetd1")
	if err != nil {
		t.Fatal(err)
	}
	setLinkFlags(t, conn, link.index, unix.IFF_UP)
	setLinkFlags(t, conn, other.index, unix.IFF_UP)
	writeBatchAddress(t, conn, link.index, prefix("198.51.100.10/25"))
	writeBatchAddress(t, conn, link.index, prefix("2001:db8:a::10/64"))
	writeBatchRoute(t, conn, unix.RT_TABLE_MAIN, prefix("0.0.0.0/0"), batchHop{index: link.index})
	writeBatchRoute(t, conn, unix.RT_TABLE_MAIN, prefix("::/0"), batchHop{index: link.index})
	// addresses of the host's own on another link, outside the sample's LAN and own prefixes
	held := []netip.Addr{netip.MustParseAddr("192.0.2.77"), netip.MustParseAddr("2001:db8:f::77")}
	for _, address := range held {
		writeBatchAddress(t, conn, other.index, netip.PrefixFrom(address, address.BitLen()))
	}
	// sourced is the source a datagram to the IPv6 address to takes, from a socket bound to the uplink's device where bound is
	// set, invalid where none can be had
	sourced := func(to netip.Addr, bound bool) netip.Addr {
		fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fd)
		if bound {
			if err := unix.BindToDevice(fd, uplink); err != nil {
				t.Fatal(err)
			}
		}
		if unix.Connect(fd, &unix.SockaddrInet6{Port: 9, Addr: to.As16()}) != nil {
			return netip.Addr{}
		}
		name, err := unix.Getsockname(fd)
		if err != nil {
			t.Fatal(err)
		}
		return netip.AddrFrom16(name.(*unix.SockaddrInet6).Addr)
	}
	// an IPv6 address stays tentative until the work of its duplicate address detection runs, even on a tun, where it detects
	// nothing, so the sends wait until the uplink's address sources a datagram bound to it and the other link's address is the
	// host's own
	waitFor(t, func() bool { return sourced(held[1], true).IsValid() && sourced(held[1], false) == held[1] })
	beyond := []netip.Addr{netip.MustParseAddr("192.0.2.200"), netip.MustParseAddr("2001:db8:e::9")}
	if err := sendFrom(t, beyond[0], 9, ""); !errors.Is(err, unix.EPERM) {
		t.Errorf("a datagram beyond the LAN left with %v, want EPERM", err)
	}
	if err := sendFrom(t, netip.MustParseAddr("198.51.100.5"), 9, ""); err != nil {
		t.Errorf("a datagram to the LAN was refused: %v", err)
	}
	// a lookup bound to the uplink passes over the local route of an address another link holds and sends the datagram out of the
	// uplink toward a destination of the host's own
	for _, to := range held {
		if err := sendFrom(t, to, 9, uplink); !errors.Is(err, unix.EPERM) {
			t.Errorf("a datagram bound to the uplink to %s, which the host holds on another link, left with %v, want EPERM", to, err)
		}
	}
	runScript("table inet othernat {\n\tchain output {\n\t\ttype nat hook output priority -100; policy accept;\n" +
		"\t\tmeta nfproto ipv4 udp dport 7 dnat ip to " + held[0].String() + "\n\t\tmeta nfproto ipv6 udp dport 7 dnat ip6 to " + held[1].String() + "\n\t}\n}\n")
	for _, to := range beyond {
		if err := sendFrom(t, to, 7, uplink); !errors.Is(err, unix.EPERM) {
			t.Errorf("a datagram bound to the uplink to %s that NAT at output translated to an address of the host's own left with %v, want EPERM", to, err)
		}
	}
	run("delete", "table", "inet", "othernat")
	// a datagram of one byte is 29 bytes in IPv4 and 49 in IPv6: output dropped the one beyond the LAN, and postrouting both bound
	// to an address of the host's own and both NAT translated
	if read, err := plat.readFallback(fallbackSample); read.dropped != 5 || read.bytes != 185 || err != nil {
		t.Errorf("the drops counted %d packets and %d bytes (err %v), want the five refused datagrams", read.dropped, read.bytes, err)
	}
	debug, err := ReadFallback()
	if err != nil {
		t.Fatal(err)
	}
	sets := map[string][]string{}
	for _, set := range debug.Sets {
		sets[set.Name] = set.Elements
	}
	// fifteen lines at postrouting and sixteen at output, each datagram output dropped kept from postrouting
	if !debug.Held || len(debug.Rules) != 31 {
		t.Fatalf("the debug read finds %+v, want the table's thirty-one lines", debug)
	}
	if routed, output := debug.Rules[14], debug.Rules[30]; routed.Spec != fallbackDrop || routed.Chain != "fallback" || routed.Packets != 4 ||
		output.Spec != fallbackDrop || output.Chain != "output" || output.Packets != 1 ||
		!reflect.DeepEqual(sets, map[string][]string{"forwarded": {"lo", "ranetfw0"}, "lan4": {"198.51.100.0/25"}, "lan6": {"2001:db8:a::/64"}, "self4": {"203.0.113.0/24"}, "self6": {},
			"tcpports": {"22", "2222"}, "udpports": {"53", "60000-61000"}}) {
		t.Errorf("the debug read finds %+v", debug)
	}

	mark := regexp.MustCompile(`meta mark 0x00000072 accept (comment "[^"]*") # handle (\d+)`)
	oifname := regexp.MustCompile(`oifname \{[^}]*\} accept (comment "[^"]*") # handle (\d+)`)
	for _, change := range []func() string{
		func() string { run("flush", "set", "inet", nftables.Table, "lan4"); return "a flushed set" },
		func() string { run("flush", "chain", "inet", nftables.Table, "fallback"); return "a flushed chain" },
		func() string {
			found := mark.FindStringSubmatch(run("-a", "list", "chain", "inet", nftables.Table, "output"))
			if found == nil {
				t.Fatal("the output chain lists no mark line")
			}
			run("replace", "rule", "inet", nftables.Table, "output", "handle", found[2], "meta", "mark", "0x72", "drop", found[1])
			return "a verdict edited under its comment"
		},
		func() string {
			found := oifname.FindStringSubmatch(run("-a", "list", "chain", "inet", nftables.Table, "output"))
			if found == nil {
				t.Fatal("the output chain lists no oifname line")
			}
			run("replace", "rule", "inet", nftables.Table, "output", "handle", found[2], `oifname { "lo", "ranetup0" } accept`, found[1])
			return "a line's own set naming the uplink under its comment"
		},
		func() string {
			// in one transaction, the chains' lines in the order the two chains list them, all in output
			rules, err := fallbackSample.rules(0)
			if err != nil {
				t.Fatal(err)
			}
			lines := strings.Split(strings.TrimSuffix(fallbackLines, "\n"), "\n")
			script := "flush chain inet " + nftables.Table + " fallback\n"
			for j, rule := range slices.Backward(rules) {
				script += fmt.Sprintf("insert rule inet %s output %s comment %q\n", nftables.Table, strings.TrimSpace(lines[j]), rule.spec)
			}
			runScript(script)
			return "the postrouting chain's lines moved ahead of output's"
		},
	} {
		what := change()
		read, err := plat.readFallback(fallbackSample)
		if read.fault == "" || err != nil {
			t.Errorf("after %s the table reads back with %q (err %v), want a fault", what, read.fault, err)
		}
		if err := plat.writeFallback(fallbackSample, read.remake); err != nil {
			t.Fatal(err)
		}
		if read, err := plat.readFallback(fallbackSample); read.fault != "" || err != nil {
			t.Errorf("after %s and a write the table reads back with %q (err %v)", what, read.fault, err)
		}
	}

	if err := plat.deleteFallback(); err != nil {
		t.Fatal(err)
	}
	if read, err := plat.readFallback(fallbackSample); read.fault != "its chains are missing" || err != nil {
		t.Errorf("after the delete the switch reads back with %q (err %v)", read.fault, err)
	}
	if err := sendFrom(t, beyond[0], 9, ""); err != nil {
		t.Errorf("with the table gone a datagram beyond the LAN was refused: %v", err)
	}
	if err := plat.deleteFallback(); err != nil {
		t.Errorf("a delete with no table failed: %v", err)
	}

	// a start with no reconciler deletes the switch an earlier instance left
	if err := plat.writeFallback(fallbackSample, false); err != nil {
		t.Fatal(err)
	}
	DeleteFallback(nil)
	if read, err := plat.readFallback(fallbackSample); read.fault != "its chains are missing" || err != nil {
		t.Errorf("after a start with no reconciler the switch reads back with %q (err %v)", read.fault, err)
	}
}

// A notification the watch may have missed wakes a pass, which finds the switch
// not reading back and takes 5405 and 5435 out within it, where the periodic
// pass is the default's 30 seconds away
func TestFallbackMissedNotificationWakesAPass(t *testing.T) {
	network := &hostNetwork{state: exitPassHost("docker0")}
	tbl := Table{Addresses: prefixes(prefix("192.0.2.1/32"), prefix("3fff::1/128"))}.WithMode(&ExitMode{Fallback: FallbackNone, LAN: exitPassLAN})
	reconciler, routes, fake := harness(t, tbl, Runtime{Interface: "ranet3", Overlay: exitPassOverlay, Network: network.read})
	// the reconciler's reader of the switch starts with Run, so this change wakes nothing after the first pass
	routes.Set(netip.Prefix{}, prefix("203.0.113.0/24"), netstack.Local)
	held := func() bool {
		fake.mu.Lock()
		defer fake.mu.Unlock()
		return uplinkSources(fake)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- reconciler.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	<-reconciler.FirstPass()
	if !held() {
		t.Fatal("the first pass left 5405 and 5435 out")
	}

	changed, missed := make(chan struct{}), make(chan struct{}, 1)
	w := &fallbackWatch{stop: make(chan struct{}), done: make(chan struct{})}
	go w.forward(changed, missed, func() {
		select {
		case fake.signal <- struct{}{}:
		default:
		}
	})
	t.Cleanup(func() {
		close(w.stop)
		<-w.done
	})
	fake.mu.Lock()
	fake.spoiled = "its set lan4 holds { }"
	fake.mu.Unlock()
	sent := time.Now()
	missed <- struct{}{}
	for held() {
		if time.Since(sent) > fallbackRestoreBudget {
			t.Fatalf("5405 and 5435 held %s after a missed notification, want them out within %s", time.Since(sent), fallbackRestoreBudget)
		}
		time.Sleep(waitPoll)
	}
}

// Another writer's flushed set, deleted rule and set remade otherwise are
// written back within a pass of the change, where the periodic pass is an hour
// away, the last by a table deleted and made again. A table another
// writer holds under its own socket, which the reconciler cannot write, takes
// 5405 and 5435 out within a pass, and once that socket closes the
// reconciler's next try writes the switch back and puts them in again.
func TestNetlinkFallbackTableAnswersAnotherWritersChangeWithinAPass(t *testing.T) {
	const device, uplink = "ranetsw0", "ranetup0"
	plat := rootRulePlatform(t, device)
	nft, err := exec.LookPath("nft")
	if err != nil {
		t.Fatal("another writer's changes are made through nft, which is not on the path")
	}
	conn, err := dialNetlink()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	createTUN(t, uplink)
	link, err := conn.link(0, uplink)
	if err != nil {
		t.Fatal(err)
	}
	setLinkFlags(t, conn, link.index, unix.IFF_UP)
	lan4, lan6 := prefix("198.51.100.10/25"), prefix("2001:db8:a::10/64")
	for address, unspecified := range map[netip.Prefix]netip.Addr{lan4: netip.IPv4Unspecified(), lan6: netip.IPv6Unspecified()} {
		writeBatchAddress(t, conn, link.index, address)
		writeBatchRoute(t, conn, unix.RT_TABLE_MAIN, netip.PrefixFrom(unspecified, 0), batchHop{index: link.index})
	}

	tbl, rt := platformFor(device)
	tbl.Reconcile = schema.Duration(time.Hour)
	// an overlay address of each family on the tun, without which mode 2 adds no 5405 or 5435
	tbl.Addresses = prefixes(prefix("192.0.2.1/32"), prefix("3fff::1/128"))
	rt.Overlay = exitPassOverlay
	network := NetworkState{
		IPv4: NetworkFamily{Default: DefaultRoute{Interface: uplink}, Links: []Link{{Name: uplink, Prefixes: []netip.Prefix{lan4}}}},
		IPv6: NetworkFamily{Default: DefaultRoute{Interface: uplink}, Links: []Link{{Name: uplink, Prefixes: []netip.Prefix{lan6}}}},
	}
	rt.Network = func() NetworkState { return network }
	// lan lists the uplink's public networks, so lan4 holds one for the flush to take
	mode := &ExitMode{Fallback: FallbackNone, LAN: []schema.Prefix{schema.PrefixFrom(lan4.Masked()), schema.PrefixFrom(lan6.Masked())}}
	tbl = tbl.WithMode(mode).Normalized()
	// as newPlatform would for the mode, on the test's thread, whose namespace the rules go in, where Run's is another
	plat.retable(tbl)
	if _, err := plat.watchFallback(); err != nil {
		t.Fatal(err)
	}
	reconciler := newReconciler(tbl, rt, tbl.Assigned(nil), netstack.NewRouteTable(), plat)
	exit, _ := reconciler.exitPass(reconciler.addresses, nil, reconciler.readNetwork())
	sets, asked := reconciler.fallbackFor(exit)
	if !asked {
		t.Fatal("the mode does not ask for the table")
	}

	// read through sockets of the test's own, since the loop owns the platform's
	reader, err := nftables.Dial()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close() })
	fault := func() string {
		read, _, err := fallbackFault(reader, sets)
		if err != nil {
			t.Fatalf("read the table back: %v", err)
		}
		return read.fault
	}
	uplinkSources := func() int {
		replies, err := conn.execute(unix.RTM_GETRULE, unix.NLM_F_DUMP, make([]byte, sizeofFibRuleHdr))
		if err != nil {
			t.Fatalf("dump rules: %v", err)
		}
		held := 0
		for _, reply := range replies {
			if rule, ok := plat.decodeRule(reply); ok && (rule.Priority == priorityUplinkSource || rule.Priority == priorityLinkSource) {
				held++
			}
		}
		return held
	}
	// one address and one network of each family
	const sources = 4
	// settle waits for the switch to read back as written, or not, and for
	// held of 5405 and 5435, naming what it last read when it gives up
	settle := func(written bool, held int) {
		t.Helper()
		var last string
		var count int
		for deadline := time.Now().Add(waitBudget); time.Now().Before(deadline); time.Sleep(waitPoll) {
			last, count = fault(), uplinkSources()
			if (last == "") == written && count == held {
				return
			}
		}
		t.Fatalf("the table reads back with %q and the kernel holds %d of 5405 and 5435, want written %v and %d", last, count, written, held)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- reconciler.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("the reconciler stopped with %v", err)
		}
	})
	settle(true, sources)

	run := func(args ...string) string {
		t.Helper()
		out, err := exec.Command(nft, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("nft %s: %v\n%s", strings.Join(args, " "), err, out)
		}
		return string(out)
	}
	handle := regexp.MustCompile(`comment "counter drop" # handle (\d+)`)
	for _, change := range []func() string{
		func() string {
			run("flush", "set", "inet", nftables.Table, "lan4")
			return "a flushed set"
		},
		func() string {
			found := handle.FindStringSubmatch(run("-a", "list", "chain", "inet", nftables.Table, "fallback"))
			if found == nil {
				t.Fatal("the chain lists no drop")
			}
			run("delete", "rule", "inet", nftables.Table, "fallback", "handle", found[1])
			return "a deleted drop"
		},
		func() string {
			// in one transaction, so no pass writes the table between them, and nf_tables changes no set's flags in place
			run("delete table inet " + nftables.Table + "; add table inet " + nftables.Table + "; add set inet " + nftables.Table + " lan4 { type ipv4_addr; }")
			return "a set remade without its interval flag"
		},
	} {
		what := change()
		changed := time.Now()
		settle(true, sources)
		if took := time.Since(changed); took > fallbackRestoreBudget {
			t.Errorf("after %s the table took %s to read back as written, want at most %s", what, took, fallbackRestoreBudget)
		}
	}

	// the switch's chains flushed and lan4 made again without its interval
	// flag, which only a delete mends, under a rule of another writer's chain
	// that looks it up, so the switch's delete of it fails until that chain goes
	run(fmt.Sprintf("flush chain inet %[1]s fallback; flush chain inet %[1]s output; delete set inet %[1]s lan4; add set inet %[1]s lan4 { type ipv4_addr; }; "+
		"add chain inet %[1]s other; add rule inet %[1]s other ip daddr @lan4 accept", nftables.Table))
	changed := time.Now()
	settle(false, 0)
	if took := time.Since(changed); took > fallbackRestoreBudget {
		t.Errorf("with its set held by another writer's rule 5405 and 5435 took %s to go, want at most %s", took, fallbackRestoreBudget)
	}
	run(fmt.Sprintf("delete chain inet %[1]s other; add element inet %[1]s lan4 { 192.0.2.1 }", nftables.Table))
	settle(true, sources)
}

// fallbackNoneOverUplink makes uplink a tun that is up and holds
// 198.51.100.10/25, with main's IPv4 default through it, and answers mode 2
// under fallback = "none" on device with that network as its LAN, and its
// runtime
func fallbackNoneOverUplink(t *testing.T, device, uplink string) (Table, Runtime) {
	t.Helper()
	conn, err := dialNetlink()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	createTUN(t, uplink)
	link, err := conn.link(0, uplink)
	if err != nil {
		t.Fatal(err)
	}
	setLinkFlags(t, conn, link.index, unix.IFF_UP)
	lan := prefix("198.51.100.10/25")
	writeBatchAddress(t, conn, link.index, lan)
	writeBatchRoute(t, conn, unix.RT_TABLE_MAIN, prefix("0.0.0.0/0"), batchHop{index: link.index})

	tbl, rt := platformFor(device)
	tbl.Addresses = prefixes(prefix("192.0.2.1/32"), prefix("3fff::1/128"))
	tbl = tbl.WithMode(&ExitMode{Fallback: FallbackNone, LAN: []schema.Prefix{schema.PrefixFrom(lan.Masked())}}).Normalized()
	rt.Overlay = exitPassOverlay
	rt.Network = func() NetworkState {
		return NetworkState{IPv4: NetworkFamily{Default: DefaultRoute{Interface: uplink}, Links: []Link{{Name: uplink, Prefixes: []netip.Prefix{lan}}}}}
	}
	return tbl, rt
}

// A Run the failed mesh's stop ends leaves the kill switch's chains, which a
// listing finds, and no rule, route or address of its own, so the switch's drop
// alone refuses the host's datagram beyond the LAN. The next Run puts the rules
// back and takes the chains over as it finds them, its drop's count kept, and a
// Run stopped plainly leaves nothing for a listing to find, the table with it,
// since the switch it took over holds the table as a write would, and leaves
// no switch even with the antispoof filter's entry chain in the table.
func TestNetlinkFallbackTableOutlivesTheStopOfAFailedMesh(t *testing.T) {
	const device, uplink = "ranetsw0", "ranetup0"
	plat := rootRulePlatform(t, device)
	tbl, rt := fallbackNoneOverUplink(t, device, uplink)
	open := func() *Reconciler {
		opened, err := newPlatform(tbl, rt)
		if err != nil {
			t.Fatal(err)
		}
		return newReconciler(tbl, rt, tbl.Assigned(nil), netstack.NewRouteTable(), opened)
	}
	first := open()
	exit, _ := first.exitPass(first.addresses, nil, first.readNetwork())
	sets, asked := first.fallbackFor(exit)
	if !asked {
		t.Fatal("the mode does not ask for the table")
	}
	type leftover struct {
		read                     fallbackRead
		listed                   bool
		rules, routes, addresses int
	}
	reader, err := nftables.Dial()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close() })
	// held reads the switch back through a socket of the test's own, so the read holds no table, lists it through the
	// test's own platform, and counts the reconciler's rules, routes and addresses
	held := func() (out leftover) {
		read, _, err := fallbackFault(reader, sets)
		listed, listErr := plat.holdsFallback()
		rules, ruleErr := plat.Rules()
		routes, routeErr := plat.Routes()
		addresses, addressErr := plat.Addrs()
		if err := errors.Join(err, listErr, ruleErr, routeErr, addressErr); err != nil {
			t.Fatalf("read the namespace back: %v", err)
		}
		out = leftover{read: read, listed: listed, rules: len(rules), routes: len(routes)}
		for _, address := range addresses {
			if slices.Contains(first.addresses, address) {
				out.addresses++
			}
		}
		return out
	}

	stop := runThroughFirstPass(t, first)
	written := held().rules
	stop(ErrMeshFailed)
	if left := held(); left.read.fault != "" || !left.listed || left.rules+left.routes+left.addresses > 0 {
		t.Fatalf("the failed mesh's stop left %+v, want the table as written alone", left)
	}
	if err := sendFrom(t, netip.MustParseAddr("203.0.113.9"), 9, ""); !errors.Is(err, unix.EPERM) {
		t.Errorf("with the table alone a datagram beyond the LAN left with %v, want EPERM", err)
	}
	stop = runThroughFirstPass(t, open())
	if left := held(); left.read.fault != "" || left.read.dropped != 1 || left.rules != written {
		t.Errorf("the next start holds %+v, want the table as written with the one drop and %d rules", left, written)
	}
	stop(nil)
	if left := held(); left.read.fault != "its chains are missing" || left.listed || left.rules+left.routes+left.addresses > 0 {
		t.Errorf("a plain stop left %+v, want nothing", left)
	}
	if tables, err := nftables.Tables(reader, nftables.Table); err != nil || len(tables) != 0 {
		t.Errorf("after the plain stop of the start that took the switch over, the table %s is in the families %v (%v), want none", nftables.Table, tables, err)
	}
	filter, err := nftables.Dial()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = filter.Close() })
	entry := nftables.Chain{Table: nftables.Table, Name: "entry", Hook: nftables.NoHook}
	if err := filter.Batch([]nftables.Request{nftables.NewTable(unix.NFPROTO_INET, nftables.Table), entry.Create(unix.NFPROTO_INET)}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = filter.Batch([]nftables.Request{nftables.DeleteTable(unix.NFPROTO_INET, nftables.Table)}) })
	if left := held(); left.read.fault != "its chains are missing" || left.listed {
		t.Errorf("with the antispoof filter's entry chain alone in the table the switch reads %+v, want no switch listed", left)
	}
}

// The socket for the kill switch, its monitor and their goroutine are open
// only while the switch is written: a platform built for mode off opens none,
// one built for fallback = "none" opens them, a reload into it opens them at
// its pass, a refused reload out of it leaves them and the switch, a reload out
// of it deletes the switch and closes them, a stop deletes the switch and
// closes them, a reload taken while stopped opens nothing, and the first pass
// of a start under the mode opens them again. Nothing else writes in the
// table here, so the switch's withdrawal takes the table with it.
func TestNetlinkFallbackWatchIsOpenOnlyWhileTheModeWritesTheTable(t *testing.T) {
	const device, uplink = "ranetsw0", "ranetup0"
	plat := rootRulePlatform(t, device)
	if plat.fallback != nil {
		t.Fatal("a platform built for mode off opened the table's socket")
	}
	conn, err := dialNetlink()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	createTUN(t, uplink)
	link, err := conn.link(0, uplink)
	if err != nil {
		t.Fatal(err)
	}
	setLinkFlags(t, conn, link.index, unix.IFF_UP)
	lan := prefix("198.51.100.10/25")
	writeBatchAddress(t, conn, link.index, lan)
	writeBatchRoute(t, conn, unix.RT_TABLE_MAIN, prefix("0.0.0.0/0"), batchHop{index: link.index})

	off, rt := platformFor(device)
	off.Addresses = prefixes(prefix("192.0.2.1/32"), prefix("3fff::1/128"))
	off = off.Normalized()
	none := off.WithMode(&ExitMode{Fallback: FallbackNone, LAN: []schema.Prefix{schema.PrefixFrom(lan.Masked())}}).Normalized()
	rt.Overlay = exitPassOverlay
	rt.Sessions = func() int { return 1 }
	rt.Network = func() NetworkState {
		return NetworkState{IPv4: NetworkFamily{Default: DefaultRoute{Interface: uplink}, Links: []Link{{Name: uplink, Prefixes: []netip.Prefix{lan}}}}}
	}
	built, err := newPlatform(none, rt)
	if err != nil {
		t.Fatal(err)
	}
	if built.(*netlinkPlatform).fallback == nil {
		t.Error("a platform built for fallback = \"none\" left the table's socket closed")
	}
	if err := built.Close(); err != nil {
		t.Fatal(err)
	}

	reader, err := nftables.Dial()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close() })
	held := func() bool {
		tables, err := nftables.Tables(reader, nftables.Table)
		if err != nil {
			t.Fatalf("list the table: %v", err)
		}
		_, held := tables[unix.NFPROTO_INET]
		return held
	}
	moved := off
	moved.ID++
	r := newReconciler(off, rt, off.Assigned(nil), netstack.NewRouteTable(), plat)
	for _, step := range []struct {
		name          string
		table         Table
		stopped, stop bool
		open, held    bool
	}{
		{name: "mode off", table: off},
		{name: "a reload into fallback none", table: none, open: true, held: true},
		{name: "a refused reload out of it", table: moved, open: true, held: true},
		{name: "a reload out of it", table: off},
		{name: "a reload into it again", table: none, open: true, held: true},
		{name: "a stop under it", table: none, stop: true},
		{name: "a reload out of it while stopped", table: off, stopped: true},
		{name: "a reload into it while stopped", table: none, stopped: true},
		{name: "a start under it", table: none, open: true, held: true},
		{name: "a stop under it again", table: none, stop: true},
		{name: "a start after a reload out of it", table: off},
	} {
		err := r.SetTable(step.table, rt.Overlay, nil)
		if refused := step.table.ID != off.ID; (err != nil) != refused {
			t.Fatalf("%s: SetTable returned %v, want refused %v", step.name, err, refused)
		}
		// a stopped Run takes the reload and runs no pass
		r.adopt()
		if !step.stopped {
			if err := r.reconcile(); err != nil {
				t.Fatalf("%s: %v", step.name, err)
			}
		}
		if step.stop {
			if err := r.withdraw(nil); err != nil {
				t.Fatalf("%s: %v", step.name, err)
			}
		}
		if open, held := plat.fallback != nil, held(); open != step.open || held != step.held {
			t.Errorf("%s leaves the socket open %v and the table held %v, want %v and %v", step.name, open, held, step.open, step.held)
		}
	}
}

// A left switch of reject routes whose delete the kernel refuses with EINVAL,
// wrapped or joined, is deleted by the next pass that does not ask for it and
// by the withdrawal, since a routing socket's EINVAL says nothing of the
// rejects, where for linux's chains EINVAL and EPROTONOSUPPORT read as a
// kernel without nf_tables, which neither asks again, and any other refusal is
// tried again
func TestFallbackDeleteRefusedWithEINVALIsTriedAgainOutsideATable(t *testing.T) {
	for name, c := range map[string]struct {
		form fallbackForm
		err  error
		left bool
	}{
		"rejects, EINVAL wrapped": {fakeRejectsForm, fmt.Errorf("delete the reject at 0.0.0.0/1: %w", unix.EINVAL), false},
		"rejects, EINVAL joined":  {fakeRejectsForm, errors.Join(unix.EBUSY, fmt.Errorf("delete the reject at ::/1: %w", unix.EINVAL)), false},
		"table, EINVAL":           {tableForm, fmt.Errorf("netlink receive: %w", unix.EINVAL), true},
		"table, EPROTONOSUPPORT":  {tableForm, fmt.Errorf("netlink dial: %w", unix.EPROTONOSUPPORT), true},
		"table, ENOBUFS":          {tableForm, fmt.Errorf("netlink receive: %w", unix.ENOBUFS), false},
	} {
		t.Run(name, func(t *testing.T) { deleteRefusedOnce(t, c.form, c.err, c.left) })
	}
}

// liveOwner and livePersistentOwner end the read's fault for table inet ranet3
// where a socket still open owns it, without the persist flag and with it
const (
	liveOwner           = "another program's open socket owns it until that program closes the socket or stops, which deletes the table"
	livePersistentOwner = "another program's open socket owns it until that program closes the socket or stops, after which its persist flag keeps it until nft delete table inet " + nftables.Table
)

// flaggedTable makes table inet ranet3 with flags through a socket of its own,
// holding the switch's chains and sets of held where it is not nil, and closes
// that socket at once or, where live, at the test's end
func flaggedTable(t *testing.T, flags uint32, live bool, held *fallbackSets) {
	t.Helper()
	setter, err := nftables.Dial()
	if err != nil {
		t.Fatal(err)
	}
	requests := []nftables.Request{{Kind: nftables.Command(unix.NFT_MSG_NEWTABLE), Flags: unix.NLM_F_CREATE,
		Body: nftables.PutAttrBE32(netlink.PutAttrString(nftables.PutNfgenmsg(nil, unix.NFPROTO_INET), unix.NFTA_TABLE_NAME, nftables.Table), unix.NFTA_TABLE_FLAGS, flags)}}
	if held != nil {
		batch, err := fallbackBatch(*held, nftables.Contents{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		requests = append(requests, slices.DeleteFunc(batch, func(r nftables.Request) bool { return r.Kind == requests[0].Kind })...)
	}
	if err := setter.Batch(requests); err != nil {
		_ = setter.Close()
		t.Fatalf("make the table with flags %#x: %v", flags, err)
	}
	if live {
		t.Cleanup(func() { _ = setter.Close() })
	} else if err := setter.Close(); err != nil {
		t.Fatal(err)
	}
}

// The switch over table inet ranet3 another socket flagged keeps the read's
// diagnosis beside the rewrite's refusal in the error it returns and in its
// fault, and deletes nothing of the table: one that outlived its owner under
// the persist flag, empty or holding the switch, refuses the rewrite with
// EOPNOTSUPP and names the delete that clears it, and one a socket still open
// owns refuses it with EPERM and says what that socket's close leaves of it
func TestNetlinkFallbackKeepsTheFlaggedTablesDiagnosisBesideTheRewritesError(t *testing.T) {
	const owner, persist = 0x2, 0x4
	for _, c := range []struct {
		name      string
		flags     uint32
		live      bool
		held      bool
		errno     error
		diagnosis string
	}{
		{"an empty orphaned persistent table", owner | persist, false, false, unix.EOPNOTSUPP, orphanedFix},
		{"an orphaned persistent table holding the switch", owner | persist, false, true, unix.EOPNOTSUPP, orphanedFix},
		{"a table a live socket owns", owner, true, false, unix.EPERM, liveOwner},
		{"a persistent table a live socket owns", owner | persist, true, false, unix.EPERM, livePersistentOwner},
	} {
		t.Run(c.name, func(t *testing.T) {
			const device, uplink = "ranetsw0", "ranetup0"
			plat := rootRulePlatform(t, device)
			tbl, rt := fallbackNoneOverUplink(t, device, uplink)
			plat.retable(tbl)
			reconciler := newReconciler(tbl, rt, tbl.Assigned(nil), netstack.NewRouteTable(), plat)
			exit, _ := reconciler.exitPass(reconciler.addresses, nil, reconciler.readNetwork())
			sets, asked := reconciler.fallbackFor(exit)
			if !asked {
				t.Fatal("the mode does not ask for the switch")
			}
			var held *fallbackSets
			if c.held {
				held = &sets
			}
			flaggedTable(t, c.flags, c.live, held)

			status, err := reconciler.applyFallback(sets, true)
			if !errors.Is(err, c.errno) || !strings.Contains(err.Error(), c.diagnosis) {
				t.Errorf("the pass returned %v, want %v beside %q", err, c.errno, c.diagnosis)
			}
			if status == nil || status.State != FallbackNotHolding || !strings.Contains(status.Fault, c.diagnosis) || !strings.Contains(status.Fault, c.errno.Error()) {
				t.Errorf("the pass reports %+v, want not holding with %q beside %q", status, c.diagnosis, c.errno.Error())
			}
			reader, err := nftables.Dial()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = reader.Close() })
			// the owner flag goes with its socket where the persist flag keeps the table
			want := c.flags
			if !c.live {
				want &^= owner
			}
			if tables, err := nftables.Tables(reader, nftables.Table); err != nil || len(tables) != 1 || tables[unix.NFPROTO_INET] != want {
				t.Errorf("after the pass the table is held with %v (%v), want it kept with the flags %#x", tables, err, want)
			}
		})
	}
}

// sendFrom sends a datagram of one byte to port at to, from a socket bound to device where it is not empty
func sendFrom(t *testing.T, to netip.Addr, port int, device string) error {
	t.Helper()
	family, address := unix.AF_INET6, unix.Sockaddr(&unix.SockaddrInet6{Port: port, Addr: to.As16()})
	if to.Is4() {
		family, address = unix.AF_INET, &unix.SockaddrInet4{Port: port, Addr: to.As4()}
	}
	fd, err := unix.Socket(family, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if device != "" {
		if err := unix.BindToDevice(fd, device); err != nil {
			t.Fatal(err)
		}
	}
	return unix.Sendto(fd, []byte("x"), 0, address)
}
