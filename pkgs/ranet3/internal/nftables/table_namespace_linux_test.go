// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package nftables

import (
	"errors"
	"os"
	"runtime"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// writeOwners writes a chain of each owner's at forward and a named set of
// each owner's, as the model's names give them, beside regular chains of
// another writer's named others, in one transaction, which makes the table
// where table holds
func writeOwners(t *testing.T, conn *Conn, table bool, others ...string) {
	t.Helper()
	var requests []Request
	if table {
		requests = append(requests, NewTable(unix.NFPROTO_INET, Table))
	}
	for i, o := range owners {
		chain := Chain{Table: Table, Name: o.chains[0], Type: "filter", Hook: unix.NF_INET_FORWARD}
		set := Set{Table: Table, Name: o.sets[0], ID: uint32(i + 1), KeyType: TypeIPv4Addr, KeyLen: 4}
		made, err := set.Create(unix.NFPROTO_INET)
		if err != nil {
			t.Fatal(err)
		}
		requests = append(requests, chain.Create(unix.NFPROTO_INET), made)
	}
	for _, name := range others {
		requests = append(requests, Chain{Table: Table, Name: name, Hook: NoHook}.Create(unix.NFPROTO_INET))
	}
	if err := conn.Batch(requests); err != nil {
		t.Fatalf("write the owners' chains and sets: %v", err)
	}
}

// held is the chains and named sets the table holds, nil where it is gone
func held(t *testing.T, conn *Conn) []string {
	t.Helper()
	tables, err := Tables(conn, Table)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := tables[unix.NFPROTO_INET]; !ok {
		return nil
	}
	l, err := list(conn, 0)
	if err != nil {
		t.Fatal(err)
	}
	out := slices.Concat(l.chains, l.sets)
	slices.Sort(out)
	return out
}

// The kill switch's and the translator's withdrawals beside the antispoof
// filter's chain take their own chain and set and leave the table, the
// filter's, last, deletes it, and a filter's withdrawal beside another
// writer's chain takes its own and leaves the table to that chain
func TestNftablesWithdrawalDeletesTheTableForItsLastOwner(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	enterThrowawayNamespace(t)
	conn := dial(t)
	writeOwners(t, conn, true)
	for _, step := range []struct {
		owner int
		left  []string
	}{
		{2, []string{"antispoof", "carved4", "flows4", "forward"}},
		{0, []string{"antispoof", "carved4"}},
		{1, nil},
	} {
		if removed, err := Withdraw(conn, ownerScope(step.owner)); err != nil || !removed {
			t.Fatalf("the %s's withdrawal answered %v, %v", owners[step.owner].name, removed, err)
		}
		if got := held(t, conn); !slices.Equal(got, step.left) {
			t.Errorf("after the %s's withdrawal the table holds %q, want %q", owners[step.owner].name, got, step.left)
		}
	}
	// held reads an empty table as one that is not there
	if tables, err := Tables(conn, Table); err != nil || len(tables) != 0 {
		t.Fatalf("after the last owner's withdrawal the tables named %s are %v, %v, want none", Table, tables, err)
	}
	if removed, err := Withdraw(conn, ownerScope(1)); err != nil || removed {
		t.Errorf("a withdrawal with no table answered %v, %v, want nothing removed", removed, err)
	}

	writeOwners(t, conn, true, "other")
	for _, owner := range []int{0, 2, 1} {
		if _, err := Withdraw(conn, ownerScope(owner)); err != nil {
			t.Fatalf("the %s's withdrawal beside another writer's chain: %v", owners[owner].name, err)
		}
	}
	if got := held(t, conn); !slices.Equal(got, []string{"other"}) {
		t.Errorf("after every owner's withdrawal beside another writer's chain the table holds %q, want that chain alone", got)
	}
}

// A named set of an owner's that another writer's rule looks up fails that
// owner's withdrawal with EBUSY and changes nothing, the table and every
// owner's chain and set left as they were
func TestNftablesWithdrawalOfASetAnotherWriterUsesFails(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	enterThrowawayNamespace(t)
	conn := dial(t)
	writeOwners(t, conn, true, "other")
	lan4 := Set{Table: Table, Name: "lan4"}
	rule, err := Chain{Table: Table, Name: "other"}.Rule(unix.NFPROTO_INET, "another writer's",
		slices.Concat(NFProto(unix.NFPROTO_IPV4), [][]byte{DestinationLoad(unix.NFPROTO_IPV4), Lookup(lan4, false), Verdict(Accept)}))
	if err != nil {
		t.Fatal(err)
	}
	if err := dial(t).Batch([]Request{rule}); err != nil {
		t.Fatalf("another writer's rule looking lan4 up: %v", err)
	}
	before := held(t, conn)
	if removed, err := Withdraw(conn, ownerScope(2)); !errors.Is(err, unix.EBUSY) || removed {
		t.Errorf("the kill switch's withdrawal under another writer's lookup answered %v, %v, want EBUSY", removed, err)
	}
	if got := held(t, conn); !slices.Equal(got, before) {
		t.Errorf("after the failed withdrawal the table holds %q, want %q", got, before)
	}
}

// A table carrying the persist flag past the socket that set it with the
// owner flag reads back as a fault naming the operator's delete for every
// owner, which no rewrite mends, since nf_tables refuses any owner's NewTable
// of flags 0 over it, and no owner's withdrawal deletes it
func TestNftablesPersistentTableIsNeverDeleted(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	enterThrowawayNamespace(t)
	const owner, persist = 0x2, 0x4
	setter, err := Dial()
	if err != nil {
		t.Fatal(err)
	}
	made := Request{Kind: Command(unix.NFT_MSG_NEWTABLE), Flags: unix.NLM_F_CREATE,
		Body: PutAttrBE32(PutAttrString(PutNfgenmsg(nil, unix.NFPROTO_INET), unix.NFTA_TABLE_NAME, Table), unix.NFTA_TABLE_FLAGS, owner|persist)}
	if err := setter.Batch([]Request{made}); err != nil {
		_ = setter.Close()
		if errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.EINVAL) {
			t.Skipf("this kernel takes no persist flag: %v", err)
		}
		t.Fatal(err)
	}
	if err := setter.Close(); err != nil {
		t.Fatal(err)
	}
	conn := dial(t)
	writeOwners(t, conn, false)
	if err := conn.Batch([]Request{NewTable(unix.NFPROTO_INET, Table)}); err == nil {
		t.Error("an owner's NewTable of flags 0 over the persistent table went through")
	}
	tables, err := Tables(conn, Table)
	if err != nil || tables[unix.NFPROTO_INET]&persist == 0 {
		t.Fatalf("the table outlived its owner with the flags %#x (%v), want persist", tables[unix.NFPROTO_INET], err)
	}
	for i, o := range owners {
		chain := Chain{Table: Table, Name: o.chains[0], Type: "filter", Hook: unix.NF_INET_FORWARD}
		read, err := Contents{Chains: []Chain{chain}}.Read(conn, tables, unix.NFPROTO_INET)
		if err != nil || !strings.Contains(read.Fault, "nft delete table inet "+Table) || read.Remake() {
			t.Errorf("the %s reads the persistent table back as %+v (%v), want a fault naming the delete and nothing to remake", owners[i].name, read, err)
		}
	}
	for _, owner := range []int{2, 0, 1} {
		if _, err := Withdraw(conn, ownerScope(owner)); err != nil {
			t.Fatalf("the %s's withdrawal from the persistent table: %v", owners[owner].name, err)
		}
	}
	if tables, err := Tables(conn, Table); err != nil || tables[unix.NFPROTO_INET]&persist == 0 {
		t.Errorf("after every owner's withdrawal the table is held with %v (%v), want it with its persist flag", tables, err)
	}
}
