// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package nftables

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/netlink"
	"ranet3.com/pkgs/ranet3/internal/netnstest"
)

// x/sys omits NFTA_FLOWTABLE_NAME, NFTA_FLOWTABLE_HOOK, NFTA_FLOWTABLE_HOOK_NUM,
// NFTA_FLOWTABLE_HOOK_PRIORITY, NFTA_FLOWTABLE_HOOK_DEVS and NFTA_DEVICE_NAME
const (
	flowtableName = 2
	flowtableHook = 3
	hookNum       = 1
	hookPriority  = 2
	hookDevs      = 3
	deviceName    = 1
)

// requireModule skips t where the netfilter module is neither loaded nor
// built in. A request naming a flowtable, expression or set type the kernel
// lacks has it load the module, so absence is decided from the module lists
// without asking the kernel.
func requireModule(t *testing.T, module string) {
	t.Helper()
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		t.Skipf("cannot identify the running kernel: %v", err)
	}
	loaded, loadedErr := os.ReadFile("/proc/modules")
	var builtin []byte
	var builtinErr error
	for _, root := range []string{"/lib/modules", "/run/booted-system/kernel-modules/lib/modules"} {
		builtin, builtinErr = os.ReadFile(filepath.Join(root, unix.ByteSliceToString(uts.Release[:]), "modules.builtin"))
		if builtinErr == nil {
			break
		}
	}
	if !modulePresent(loaded, builtin, module) {
		t.Skipf("%s is neither loaded nor known built in (loaded list: %v, built-in list: %v)", module, loadedErr, builtinErr)
	}
}

// modulePresent is whether the netfilter module is live in loaded, as
// /proc/modules lists modules, or in builtin, as modules.builtin does
func modulePresent(loaded, builtin []byte, module string) bool {
	for line := range bytes.Lines(loaded) {
		fields := bytes.Fields(line)
		if len(fields) >= 5 && string(fields[0]) == module && bytes.Equal(fields[4], []byte("Live")) {
			return true
		}
	}
	for line := range bytes.Lines(builtin) {
		if string(bytes.TrimSpace(line)) == "kernel/net/netfilter/"+module+".ko" {
			return true
		}
	}
	return false
}

// An absent or unready module must not permit a request that names what it
// registers, while loaded and built-in support both permit the namespace test.
// nf_flow_table_inet registers the inet flowtable type and depends on
// nf_flow_table.
func TestModulePresentWhereLoadedLiveOrBuiltIn(t *testing.T) {
	for _, tt := range []struct {
		name, loaded, builtin string
		want                  bool
	}{
		{name: "absent"},
		{name: "core_only", loaded: "nf_flow_table 73728 0 - Live 0\n", builtin: "kernel/net/netfilter/nf_flow_table.ko\n"},
		{name: "loaded", loaded: "nf_flow_table_inet 12288 0 - Live 0\n", want: true},
		{name: "built_in", builtin: "kernel/net/netfilter/nf_flow_table_inet.ko\n", want: true},
		{name: "loading", loaded: "nf_flow_table_inet 12288 0 - Loading 0\n"},
		{name: "unloading", loaded: "nf_flow_table_inet 12288 0 - Unloading 0\n"},
		{name: "dependency_name", loaded: "other 12288 1 nf_flow_table_inet Live 0\n"},
		{name: "similar_names", loaded: "nf_flow_table_inet_extra 12288 0 - Live 0\n", builtin: "kernel/net/netfilter/nf_flow_table_inet_extra.ko\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := modulePresent([]byte(tt.loaded), []byte(tt.builtin), "nf_flow_table_inet"); got != tt.want {
				t.Fatalf("nf_flow_table_inet present: %v, want %v", got, tt.want)
			}
		})
	}
}

// A successful withdrawal removes the owned chain but keeps the foreign
// flowtable and its table, while a failed dump keeps the chain and the hold too
func TestNftablesWithdrawalKeepsTheTableOfAForeignFlowtable(t *testing.T) {
	for _, dumpFails := range []bool{false, true} {
		name := "owned_chain_removed"
		if dumpFails {
			name = "failed_dump_keeps_hold_and_content"
		}
		t.Run(name, func(t *testing.T) {
			netnstest.EnterEmptyLoopbackDown(t)
			requireModule(t, "nf_flow_table_inet")
			conn, other := dial(t), dial(t)
			var h Hold
			t.Cleanup(h.Release)
			chain := Chain{Table: Table, Name: "owned", Hook: NoHook}
			if err := h.Write(conn, []Request{NewTable(unix.NFPROTO_INET, Table), chain.Create(unix.NFPROTO_INET)}); err != nil {
				t.Fatal(err)
			}
			body := netlink.PutAttrString(PutNfgenmsg(nil, unix.NFPROTO_INET), flowtableTable, Table)
			body = netlink.PutAttrString(body, flowtableName, "foreign")
			hook := PutAttrBE32(nil, hookNum, unix.NF_NETDEV_INGRESS)
			hook = PutAttrBE32(hook, hookPriority, 0)
			hook = netlink.PutAttr(hook, hookDevs|unix.NLA_F_NESTED, netlink.PutAttrString(nil, deviceName, "lo"))
			body = netlink.PutAttr(body, flowtableHook|unix.NLA_F_NESTED, hook)
			if err := other.Batch([]Request{{Kind: Command(unix.NFT_MSG_NEWFLOWTABLE), Flags: unix.NLM_F_CREATE | unix.NLM_F_EXCL, Body: body}}); err != nil {
				t.Fatalf("create foreign flowtable: %v", err)
			}
			if dumpFails {
				// a reply shorter than its advertised length must fail decoding
				kind := binary.BigEndian.Uint16(binary.NativeEndian.AppendUint16(nil, Command(unix.NFT_MSG_NEWFLOWTABLE)))
				filter := []unix.SockFilter{
					{Code: unix.BPF_LD | unix.BPF_H | unix.BPF_ABS, K: 4},
					{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: uint32(kind), Jf: 1},
					{Code: unix.BPF_RET | unix.BPF_K, K: unix.SizeofNlMsghdr},
					{Code: unix.BPF_RET | unix.BPF_K, K: ^uint32(0)},
				}
				if err := unix.SetsockoptSockFprog(conn.link.Fd(), unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}); err != nil {
					t.Fatal(err)
				}
			}
			removed, err := h.Withdraw(conn, Scope{Chains: []string{chain.Name}})
			var left []string
			if dumpFails {
				if err == nil || !strings.Contains(err.Error(), "dump flowtables") || removed {
					t.Fatalf("withdrawal over a failed dump: removed=%v, err=%v", removed, err)
				}
				if counted(t, other) != 1 {
					t.Fatal("the failed withdrawal released its hold")
				}
				left = []string{chain.Name}
			} else if err != nil || !removed {
				t.Fatalf("withdrawal: removed=%v, err=%v", removed, err)
			}
			if tableGone(t, other) {
				t.Fatal("the withdrawal deleted the table of the foreign flowtable")
			}
			if got := held(t, other); !slices.Equal(got, left) {
				t.Fatalf("the table holds %q, want %q", got, left)
			}
			flowtables, err := other.Dump(Command(unix.NFT_MSG_GETFLOWTABLE), netlink.PutAttrString(PutNfgenmsg(nil, unix.NFPROTO_INET), flowtableTable, Table))
			if err != nil || len(flowtables) != 1 {
				t.Fatalf("flowtables left: %d, err=%v", len(flowtables), err)
			}
		})
	}
}

// A flowtable in another table or family does not keep the last holder's
// table, and deleting that table leaves the other flowtable in place
func TestNftablesLastWithdrawalDeletesTheTableBesideAFlowtableElsewhere(t *testing.T) {
	for _, place := range []struct {
		name   string
		family uint8
		table  string
	}{
		{"inet_other", unix.NFPROTO_INET, "other"},
		{"ip_same_name", unix.NFPROTO_IPV4, Table},
	} {
		t.Run(place.name, func(t *testing.T) {
			netnstest.EnterEmptyLoopbackDown(t)
			requireModule(t, "nf_flow_table_inet")
			conn, other := dial(t), dial(t)
			var h Hold
			t.Cleanup(h.Release)
			chain := Chain{Table: Table, Name: "owned", Hook: NoHook}
			if err := h.Write(conn, []Request{NewTable(unix.NFPROTO_INET, Table), chain.Create(unix.NFPROTO_INET)}); err != nil {
				t.Fatal(err)
			}
			body := netlink.PutAttrString(PutNfgenmsg(nil, place.family), flowtableTable, place.table)
			body = netlink.PutAttrString(body, flowtableName, "foreign")
			hook := PutAttrBE32(nil, hookNum, unix.NF_NETDEV_INGRESS)
			hook = PutAttrBE32(hook, hookPriority, 0)
			hook = netlink.PutAttr(hook, hookDevs|unix.NLA_F_NESTED, netlink.PutAttrString(nil, deviceName, "lo"))
			body = netlink.PutAttr(body, flowtableHook|unix.NLA_F_NESTED, hook)
			if err := other.Batch([]Request{NewTable(place.family, place.table), {Kind: Command(unix.NFT_MSG_NEWFLOWTABLE), Flags: unix.NLM_F_CREATE | unix.NLM_F_EXCL, Body: body}}); err != nil {
				t.Fatalf("create foreign table and flowtable: %v", err)
			}
			removed, err := h.Withdraw(conn, Scope{Chains: []string{chain.Name}})
			if err != nil || !removed {
				t.Fatalf("withdrawal: removed=%v, err=%v", removed, err)
			}
			tables, err := Tables(other, Table)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := tables[unix.NFPROTO_INET]; ok {
				t.Fatal("the last withdrawal kept its inet table beside a flowtable elsewhere")
			}
			flowtables, err := other.Dump(Command(unix.NFT_MSG_GETFLOWTABLE), netlink.PutAttrString(PutNfgenmsg(nil, place.family), flowtableTable, place.table))
			if err != nil || len(flowtables) != 1 {
				t.Fatalf("flowtables of %d %s left: %d, err=%v", place.family, place.table, len(flowtables), err)
			}
		})
	}
}
