// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"os/exec"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/netlink"
	"ranet3.com/pkgs/ranet3/internal/nftables"
)

// earlierSets is the name an earlier switch gave each of its sets, by the name
// this build gives it, written apart from the switch's own list
var earlierSets = map[string]string{"self4": "own4", "self6": "own6", "tcpports": "tcp_ports", "udpports": "udp_ports"}

// An earlier switch had only the first two chains and seven named sets, under
// the four older names. It did not write routed, from4, or from6.
func earlierFallbackText(t *testing.T) string {
	t.Helper()
	full := fallbackText(t)
	sets, _, foundSets := strings.Cut(full, "\tset from4 {")
	_, tail, foundChain := strings.Cut(full, "\tchain fallback {")
	chains, _, foundRouted := strings.Cut(tail, "\tchain routed {")
	if !foundSets || !foundChain || !foundRouted {
		t.Fatal("the earlier switch has no two-chain layout in the current fixture")
	}
	var pairs []string
	for name, earlier := range earlierSets {
		pairs = append(pairs, "@"+name+" ", "@"+earlier+" ", "set "+name+" {", "set "+earlier+" {")
	}
	return strings.NewReplacer(pairs...).Replace(sets + "\tchain fallback {" + chains + "}\n")
}

// loadEarlierFallback loads earlierFallbackText with nft, as the table an
// earlier switch that ended without its withdrawal left, and returns nft's
// runner
func loadEarlierFallback(t *testing.T) func(args ...string) string {
	t.Helper()
	nft, err := exec.LookPath("nft")
	if err != nil {
		t.Fatal("the earlier switch's table is written through nft, which is not on the path")
	}
	load := exec.Command(nft, "-f", "-")
	load.Stdin = strings.NewReader(earlierFallbackText(t))
	if out, err := load.CombinedOutput(); err != nil {
		t.Fatalf("nft -f of the earlier switch: %v\n%s", err, out)
	}
	run := func(args ...string) string {
		t.Helper()
		out, err := exec.Command(nft, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("nft %s: %v\n%s", strings.Join(args, " "), err, out)
		}
		return string(out)
	}
	listing := run("list", "table", "inet", nftables.Table)
	for name, earlier := range earlierSets {
		if strings.Contains(listing, "set "+name+" {") || !strings.Contains(listing, "set "+earlier+" {") || !strings.Contains(listing, "@"+earlier+" ") {
			t.Fatalf("the earlier switch lists, want the set %s its lines read and no set %s:\n%s", earlier, name, listing)
		}
	}
	return run
}

// A table an earlier switch left, its sets under the names it gave them and
// read by its lines, reads back with a fault, and the next write deletes every
// set under an earlier name in the transaction that writes the lines again, so
// the table lists as a fresh one the same write made and reads back as written
func TestNetlinkFallbackRetiresTheEarlierSets(t *testing.T) {
	plat := rootRulePlatform(t, "ranetsw0")
	nft, err := exec.LookPath("nft")
	if err != nil {
		t.Fatal(err)
	}
	if err := plat.writeFallback(fallbackSample, false); err != nil {
		t.Fatal(err)
	}
	listed, err := exec.Command(nft, "list", "table", "inet", nftables.Table).CombinedOutput()
	if err != nil {
		t.Fatalf("nft list: %v\n%s", err, listed)
	}
	fresh := string(listed)
	if err := plat.deleteFallback(); err != nil {
		t.Fatal(err)
	}
	run := loadEarlierFallback(t)
	read, err := plat.readFallback(fallbackSample)
	if err != nil || read.fault == "" {
		t.Fatalf("the earlier switch reads back with %q (%v), want a fault", read.fault, err)
	}
	if err := plat.writeFallback(fallbackSample, read.remake); err != nil {
		t.Fatalf("the write over the earlier switch: %v", err)
	}
	if read, err := plat.readFallback(fallbackSample); read.fault != "" || err != nil {
		t.Errorf("after the write the switch reads back with %q (%v)", read.fault, err)
	}
	listing := run("list", "table", "inet", nftables.Table)
	for _, earlier := range earlierSets {
		if strings.Contains(listing, "set "+earlier+" {") {
			t.Errorf("after the write nft lists the set %s:\n%s", earlier, listing)
		}
	}
	if listing != fresh {
		t.Errorf("after the write the table lists\n%s\nwhere the write over no table made\n%s", listing, fresh)
	}
}

// A set under an earlier name beside the switch as written, that another
// writer's rule reads, is a fault naming that rule's chain, which a write
// leaves the set to, and the write after the rule goes deletes it and reads
// back as written
func TestNetlinkFallbackKeepsAnEarlierSetAnotherWritersRuleReads(t *testing.T) {
	plat := rootRulePlatform(t, "ranetsw0")
	nft, err := exec.LookPath("nft")
	if err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) string {
		t.Helper()
		out, err := exec.Command(nft, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("nft %s: %v\n%s", strings.Join(args, " "), err, out)
		}
		return string(out)
	}
	if err := plat.writeFallback(fallbackSample, false); err != nil {
		t.Fatal(err)
	}
	earlier := earlierSets["self4"]
	run("add", "set", "inet", nftables.Table, earlier, "{ type ipv4_addr; flags interval; }")
	run("add", "chain", "inet", nftables.Table, "other")
	run("add", "rule", "inet", nftables.Table, "other", "ip", "daddr", "@"+earlier, "accept")
	const fault = "its set own4 is not one the kill switch writes, and chain other holds a rule using it, so it stays until that rule goes"
	for _, when := range []string{"beside the set", "after the write beside the set"} {
		read, err := plat.readFallback(fallbackSample)
		if err != nil || read.fault != fault {
			t.Errorf("%s the switch reads back with %q (%v), want %q", when, read.fault, err, fault)
		}
		if err := plat.writeFallback(fallbackSample, read.remake); err != nil {
			t.Fatalf("the write %s: %v", when, err)
		}
	}
	run("flush", "chain", "inet", nftables.Table, "other")
	if err := plat.writeFallback(fallbackSample, false); err != nil {
		t.Fatalf("the write after the rule went: %v", err)
	}
	if read, err := plat.readFallback(fallbackSample); read.fault != "" || err != nil {
		t.Errorf("after the rule went the switch reads back with %q (%v)", read.fault, err)
	}
	if listing := run("list", "table", "inet", nftables.Table); strings.Contains(listing, "set "+earlier+" {") || !strings.Contains(listing, "chain other {") {
		t.Errorf("after the rule went nft lists, want no set %s and the chain other:\n%s", earlier, listing)
	}
}

// The switch's withdrawal over the table an earlier switch left takes the
// sets under their earlier names with the rest, and the table with them, and
// a start that runs no reconciler takes them too
func TestNetlinkFallbackWithdrawsTheEarlierSets(t *testing.T) {
	plat := rootRulePlatform(t, "ranetsw0")
	run := loadEarlierFallback(t)
	if _, err := plat.readFallback(fallbackSample); err != nil {
		t.Fatal(err)
	}
	if err := plat.deleteFallback(); err != nil {
		t.Fatalf("the withdrawal over the earlier switch: %v", err)
	}
	if listing := run("list", "ruleset"); listing != "" {
		t.Errorf("after the withdrawal over the earlier switch nft lists:\n%s", listing)
	}
	run = loadEarlierFallback(t)
	DeleteFallback(nil)
	if listing := run("list", "table", "inet", nftables.Table); strings.Contains(listing, "set ") || strings.Contains(listing, "chain ") {
		t.Errorf("after a start with no reconciler over the earlier switch nft lists:\n%s", listing)
	}
}

// The switch's monitor wakes for another writer's change to a set under an
// earlier name as for one under its own
func TestFallbackMonitorWakesForTheEarlierSets(t *testing.T) {
	const own, other = 7, 9
	for name, earlier := range earlierSets {
		for _, set := range []string{name, earlier} {
			for _, command := range []int{unix.NFT_MSG_NEWSET, unix.NFT_MSG_DELSET, unix.NFT_MSG_NEWSETELEM, unix.NFT_MSG_DELSETELEM} {
				tableAttr, nameAttr := uint16(unix.NFTA_SET_TABLE), uint16(unix.NFTA_SET_NAME)
				if command == unix.NFT_MSG_NEWSETELEM || command == unix.NFT_MSG_DELSETELEM {
					tableAttr, nameAttr = unix.NFTA_SET_ELEM_LIST_TABLE, unix.NFTA_SET_ELEM_LIST_SET
				}
				body := netlink.PutAttrString(netlink.PutAttrString(nftables.PutNfgenmsg(nil, unix.NFPROTO_INET), tableAttr, nftables.Table), nameAttr, set)
				if !fallbackScope.ChangedByAnother(netlink.Message{Kind: nftables.Command(command), Pid: other, Data: body}, own) {
					t.Errorf("another writer's message %d naming the set %s does not wake the switch", command, set)
				}
			}
		}
	}
}
