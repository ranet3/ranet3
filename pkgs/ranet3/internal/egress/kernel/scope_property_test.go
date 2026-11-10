// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/netlink"
	"ranet3.com/pkgs/ranet3/internal/nftables"
	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// chainOwner and setOwner are which writer of the table a chain or a set of
// the name belongs to, from the owners' constants, the kill switch's by its
// names in internal/kernel: 0 for the translator, 1 for the antispoof filter,
// 2 for the kill switch and -1 for another writer
func chainOwner(name string) int {
	switch {
	case name == ChainName || name == LimitChain || name == retiredChain || name == forward6.Name || strings.HasPrefix(name, NoneChain) && name != NoneChain:
		return 0
	case name == BorderChain || name == EntryChain:
		return 1
	case name == "fallback" || name == "output":
		return 2
	}
	return -1
}

func setOwner(name string) int {
	sets := func(stem string) []string { return []string{stem + "4", stem + "6"} }
	switch {
	case slices.Contains(sets(flowsSet), name):
		return 0
	case slices.Contains(slices.Concat(sets(carvedSet), sets(ownedSet), sets(noneSet)), name):
		return 1
	case slices.Contains([]string{"forwarded", "lan4", "lan6", "own4", "own6", "tcp_ports", "udp_ports"}, name):
		return 2
	}
	return -1
}

// Each owner's monitor wakes on a message exactly where another socket sent
// it, in the inet table of this tool's name, and it deletes the table, makes
// it or changes it with a flag set or no flags attribute, or names one of that
// owner's chains or sets, over the nine kinds of message it reads and the
// rest and the names of the three owners, IPv6's chain, the chain an earlier
// translator held IPv4's lines in, a class of none's chain, an anonymous set
// and map and a stranger's, each in every family, the table's name and
// others, from either port and with a table message's flags absent, 0,
// dormant, owner and persist. A NEWTABLE whose flags are 0 makes the table or
// clears its flags, and takes no owner's chain.
func TestEachOwnersMonitorWakesForItsOwnNamesAlone(t *testing.T) {
	kinds := []struct {
		command     int
		table, name uint16
	}{
		{unix.NFT_MSG_NEWTABLE, unix.NFTA_TABLE_NAME, 0}, {unix.NFT_MSG_DELTABLE, unix.NFTA_TABLE_NAME, 0},
		{unix.NFT_MSG_NEWCHAIN, unix.NFTA_CHAIN_TABLE, unix.NFTA_CHAIN_NAME}, {unix.NFT_MSG_DELCHAIN, unix.NFTA_CHAIN_TABLE, unix.NFTA_CHAIN_NAME},
		{unix.NFT_MSG_NEWRULE, unix.NFTA_RULE_TABLE, unix.NFTA_RULE_CHAIN}, {unix.NFT_MSG_DELRULE, unix.NFTA_RULE_TABLE, unix.NFTA_RULE_CHAIN},
		{unix.NFT_MSG_NEWSET, unix.NFTA_SET_TABLE, unix.NFTA_SET_NAME}, {unix.NFT_MSG_DELSET, unix.NFTA_SET_TABLE, unix.NFTA_SET_NAME},
		{unix.NFT_MSG_NEWSETELEM, unix.NFTA_SET_ELEM_LIST_TABLE, unix.NFTA_SET_ELEM_LIST_SET}, {unix.NFT_MSG_DELSETELEM, unix.NFTA_SET_ELEM_LIST_TABLE, unix.NFTA_SET_ELEM_LIST_SET},
		{unix.NFT_MSG_NEWOBJ, unix.NFTA_OBJ_TABLE, unix.NFTA_OBJ_NAME},
	}
	names := []string{ChainName, LimitChain, retiredChain, forward6.Name, NoneChain + "192_0_2_0_24", NoneChain, flowsSet + "4", flowsSet + "6", BorderChain, EntryChain,
		carvedSet + "4", noneSet + "6", "fallback", "output", "lan4", "udp_ports", "__set0", "__map0", "other", timeoutObject + "udp4"}
	scopes := map[int]nftables.Scope{0: translatorScope, 1: borderScope}
	const own, other = 7, 9
	// flags are a table message's NFTA_TABLE_FLAGS, absent where negative
	flags := []int64{-1, 0, unix.NFT_TABLE_F_DORMANT, 0x2, 0x4}
	pbt.Check(t, func(ht *hegel.T) {
		kind := kinds[hegel.Draw(ht, pbt.Spanning(0, len(kinds)-1))]
		name := hegel.Draw(ht, hegel.SampledFrom(names))
		// the family, the table and the port each message is checked under are swept, since a message wakes
		// in one of each alone, and the flags are swept beside them
		for _, family := range []uint8{unix.NFPROTO_INET, unix.NFPROTO_IPV4, unix.NFPROTO_IPV6, unix.NFPROTO_BRIDGE} {
			for _, table := range []string{nftables.Table, "nat", nftables.Table + "x"} {
				for _, pid := range []uint32{own, other} {
					for _, flag := range flags {
						body := netlink.PutAttrString(nftables.PutNfgenmsg(nil, family), kind.table, table)
						if kind.name != 0 {
							body = netlink.PutAttrString(body, kind.name, name)
						}
						if kind.name == 0 && flag >= 0 {
							body = nftables.PutAttrBE32(body, unix.NFTA_TABLE_FLAGS, uint32(flag))
						}
						message := netlink.Message{Kind: nftables.Command(kind.command), Pid: pid, Data: body}
						for owner, scope := range scopes {
							var named bool
							switch kind.command {
							case unix.NFT_MSG_NEWTABLE:
								named = flag != 0
							case unix.NFT_MSG_DELTABLE:
								named = true
							case unix.NFT_MSG_NEWCHAIN, unix.NFT_MSG_DELCHAIN, unix.NFT_MSG_NEWRULE, unix.NFT_MSG_DELRULE:
								named = chainOwner(name) == owner
							case unix.NFT_MSG_NEWSET, unix.NFT_MSG_DELSET, unix.NFT_MSG_NEWSETELEM, unix.NFT_MSG_DELSETELEM:
								named = setOwner(name) == owner
							}
							want := pid == other && family == unix.NFPROTO_INET && table == nftables.Table && named
							if got := scope.ChangedByAnother(message, own); got != want {
								ht.Fatalf("owner %d woke %v for kind %d in family %d of table %s naming %q from port %d with flags %d, want %v", owner, got, kind.command, family, table, name, pid, flag, want)
							}
						}
					}
				}
			}
		}
	})
}
