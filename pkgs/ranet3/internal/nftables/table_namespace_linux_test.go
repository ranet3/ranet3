// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package nftables

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/netlink"
	"ranet3.com/pkgs/ranet3/internal/netnstest"
)

// ownerRequests is a chain of the owner's at index owner at forward and a
// named set of its own, as the model's names give them, in one transaction
// that makes the table where table holds
func ownerRequests(t *testing.T, owner int, table bool) []Request {
	t.Helper()
	var requests []Request
	if table {
		requests = append(requests, NewTable(unix.NFPROTO_INET, Table))
	}
	o := owners[owner]
	set := Set{Table: Table, Name: o.sets[0], ID: 1, KeyType: TypeIPv4Addr, KeyLen: 4}
	made, err := set.Create(unix.NFPROTO_INET)
	if err != nil {
		t.Fatal(err)
	}
	return append(requests, Chain{Table: Table, Name: o.chains[0], Type: "filter", Hook: unix.NF_INET_FORWARD}.Create(unix.NFPROTO_INET), made)
}

// writeOwners writes each owner's chain and set through a holder of its own,
// which makes the table where table holds, beside regular chains of another
// writer's named others, and answers the holders, which hold nothing past the
// test
func writeOwners(t *testing.T, conn *Conn, table bool, others ...string) []Hold {
	t.Helper()
	hs := make([]Hold, len(owners))
	t.Cleanup(func() { release(hs) })
	for i := range owners {
		if err := hs[i].Write(conn, ownerRequests(t, i, table)); err != nil {
			t.Fatalf("write the %s's chain and set: %v", owners[i].name, err)
		}
	}
	var requests []Request
	for _, name := range others {
		requests = append(requests, Chain{Table: Table, Name: name, Hook: NoHook}.Create(unix.NFPROTO_INET))
	}
	if err := conn.Batch(requests); err != nil {
		t.Fatalf("write another writer's chains: %v", err)
	}
	return hs
}

// release ends each of hs's hold, as its owner's end does
func release(hs []Hold) {
	for i := range hs {
		hs[i].Release()
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

// counted is how many Holds hold the table in the namespace of conn's socket
func counted(t *testing.T, conn *Conn) int {
	t.Helper()
	ns, pin, err := conn.namespace()
	if err != nil {
		t.Fatal(err)
	}
	_ = pin.Close()
	holders.Lock()
	defer holders.Unlock()
	if s, ok := holders.held[ns]; ok {
		return s.count
	}
	return 0
}

// tableGone is whether no table named Table is there in any family
func tableGone(t *testing.T, conn *Conn) bool {
	t.Helper()
	tables, err := Tables(conn, Table)
	if err != nil {
		t.Fatal(err)
	}
	return len(tables) == 0
}

// The kill switch's and the translator's withdrawals beside the antispoof
// filter's hold take their own chain and set and leave the table, the
// filter's, last, deletes it, a holder that never wrote removes nothing from
// no table, and the last holder's withdrawal beside another writer's chain
// takes its own and leaves the table to that chain
func TestNftablesWithdrawalDeletesTheTableForItsLastOwner(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmptyLoopbackDown(t)
	conn := dial(t)
	hs := writeOwners(t, conn, true)
	for _, step := range []struct {
		owner int
		left  []string
	}{
		{2, []string{"antispoof", "carved4", "flows4", "forward"}},
		{0, []string{"antispoof", "carved4"}},
		{1, nil},
	} {
		if removed, err := hs[step.owner].Withdraw(conn, ownerScope(step.owner)); err != nil || !removed {
			t.Fatalf("the %s's withdrawal answered %v, %v", owners[step.owner].name, removed, err)
		}
		if got := held(t, conn); !slices.Equal(got, step.left) {
			t.Errorf("after the %s's withdrawal the table holds %q, want %q", owners[step.owner].name, got, step.left)
		}
	}
	// held reads an empty table as one that is not there
	if !tableGone(t, conn) {
		t.Fatalf("after the last owner's withdrawal a table named %s is there", Table)
	}
	var never Hold
	if removed, err := never.Withdraw(conn, ownerScope(1)); err != nil || removed {
		t.Errorf("a withdrawal with no table answered %v, %v, want nothing removed", removed, err)
	}

	hs = writeOwners(t, conn, true, "other")
	for _, owner := range []int{0, 2, 1} {
		if _, err := hs[owner].Withdraw(conn, ownerScope(owner)); err != nil {
			t.Fatalf("the %s's withdrawal beside another writer's chain: %v", owners[owner].name, err)
		}
	}
	if got := held(t, conn); !slices.Equal(got, []string{"other"}) {
		t.Errorf("after every owner's withdrawal beside another writer's chain the table holds %q, want that chain alone", got)
	}
}

// A named set of an owner's that another writer's rule looks up fails that
// owner's withdrawal with EBUSY and changes nothing, the table and every
// owner's chain and set left as they were, and the owner holds the table as
// before: once the other writer's chain goes, the withdrawals of the other two
// leave the table and the owner's chain and set, and the owner's own, the
// last, deletes the table
func TestNftablesWithdrawalOfASetAnotherWriterUsesFails(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmptyLoopbackDown(t)
	conn := dial(t)
	hs := writeOwners(t, conn, true, "other")
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
	if removed, err := hs[2].Withdraw(conn, ownerScope(2)); !errors.Is(err, unix.EBUSY) || removed {
		t.Errorf("the kill switch's withdrawal under another writer's lookup answered %v, %v, want EBUSY", removed, err)
	}
	if got := held(t, conn); !slices.Equal(got, before) {
		t.Errorf("after the failed withdrawal the table holds %q, want %q", got, before)
	}
	other := Chain{Table: Table, Name: "other"}
	if err := dial(t).Batch([]Request{other.Flush(unix.NFPROTO_INET), other.Delete(unix.NFPROTO_INET)}); err != nil {
		t.Fatalf("delete another writer's chain: %v", err)
	}
	for _, owner := range []int{0, 1} {
		if _, err := hs[owner].Withdraw(conn, ownerScope(owner)); err != nil {
			t.Fatalf("the %s's withdrawal: %v", owners[owner].name, err)
		}
	}
	if got := held(t, conn); !slices.Equal(got, []string{"fallback", "lan4"}) {
		t.Errorf("after the other two withdrew beside the kill switch's failed withdrawal the table holds %q, want the switch's chain and set", got)
	}
	if removed, err := hs[2].Withdraw(conn, ownerScope(2)); err != nil || !removed {
		t.Errorf("the kill switch's second withdrawal answered %v, %v", removed, err)
	}
	if !tableGone(t, conn) {
		t.Error("after the kill switch's second withdrawal, the last, the table is there")
	}
}

// A table carrying the persist flag past the socket that set it with the
// owner flag reads back as a fault naming the operator's delete for every
// owner, which no rewrite mends, since nf_tables refuses any owner's NewTable
// of flags 0 over it, and no owner's withdrawal deletes it, the last holder's
// included
func TestNftablesPersistentTableIsNeverDeleted(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmptyLoopbackDown(t)
	const owner, persist = 0x2, 0x4
	setter, err := Dial()
	if err != nil {
		t.Fatal(err)
	}
	made := Request{Kind: Command(unix.NFT_MSG_NEWTABLE), Flags: unix.NLM_F_CREATE,
		Body: PutAttrBE32(netlink.PutAttrString(PutNfgenmsg(nil, unix.NFPROTO_INET), unix.NFTA_TABLE_NAME, Table), unix.NFTA_TABLE_FLAGS, owner|persist)}
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
	hs := writeOwners(t, conn, false)
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
		if _, err := hs[owner].Withdraw(conn, ownerScope(owner)); err != nil {
			t.Fatalf("the %s's withdrawal from the persistent table: %v", owners[owner].name, err)
		}
	}
	if tables, err := Tables(conn, Table); err != nil || tables[unix.NFPROTO_INET]&persist == 0 {
		t.Errorf("after every owner's withdrawal the table is held with %v (%v), want it with its persist flag", tables, err)
	}
}

// concurrentTurns is how many times a test sends two holders' writes or
// withdrawals at once
const concurrentTurns = 20

// The last two holders withdrawing at once, each through a socket of its own,
// both succeed and leave no table, so exactly one of them deleted it: a
// second deletion would have failed on the table gone, and none would leave
// it there
func TestNftablesLastTwoWithdrawalsAtOnceDeleteTheTableOnce(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmptyLoopbackDown(t)
	conn := dial(t)
	sockets := []*Conn{dial(t), dial(t)}
	for turn := range concurrentTurns {
		hs := writeOwners(t, conn, true)
		if _, err := hs[2].Withdraw(conn, ownerScope(2)); err != nil {
			t.Fatalf("turn %d: the kill switch's withdrawal: %v", turn, err)
		}
		start := make(chan struct{})
		removed, errs := make([]bool, 2), make([]error, 2)
		var wg sync.WaitGroup
		for i, owner := range []int{0, 1} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				removed[i], errs[i] = hs[owner].Withdraw(sockets[i], ownerScope(owner))
			}()
		}
		close(start)
		wg.Wait()
		for i, owner := range []int{0, 1} {
			if errs[i] != nil || !removed[i] {
				t.Errorf("turn %d: the %s's withdrawal answered %v, %v", turn, owners[owner].name, removed[i], errs[i])
			}
		}
		if got := held(t, conn); got != nil || !tableGone(t, conn) {
			t.Fatalf("turn %d: after both withdrawals the table holds %q, want it gone", turn, got)
		}
	}
}

// The kill switch's first write at once with the withdrawal of the filter,
// the one holder, keeps the switch's chain and set in the table whichever
// takes the table first: a withdrawal that finds itself the last deletes the
// table before the write commits or not at all
func TestNftablesFirstWriteBesideTheLastWithdrawalKeepsItsChain(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmptyLoopbackDown(t)
	conn := dial(t)
	sockets := []*Conn{dial(t), dial(t)}
	for turn := range concurrentTurns {
		hs := make([]Hold, len(owners))
		t.Cleanup(func() { release(hs) })
		if err := hs[1].Write(conn, ownerRequests(t, 1, true)); err != nil {
			t.Fatalf("turn %d: write the filter's chain and set: %v", turn, err)
		}
		written := ownerRequests(t, 2, true)
		start := make(chan struct{})
		var writeErr, withdrawErr error
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			writeErr = hs[2].Write(sockets[0], written)
		}()
		go func() {
			defer wg.Done()
			<-start
			_, withdrawErr = hs[1].Withdraw(sockets[1], ownerScope(1))
		}()
		close(start)
		wg.Wait()
		if writeErr != nil || withdrawErr != nil {
			t.Fatalf("turn %d: the switch's write answered %v and the filter's withdrawal %v", turn, writeErr, withdrawErr)
		}
		if got := held(t, conn); !slices.Equal(got, []string{"fallback", "lan4"}) {
			t.Fatalf("turn %d: after the switch's first write beside the filter's withdrawal the table holds %q, want the switch's chain and set", turn, got)
		}
		if _, err := hs[2].Withdraw(conn, ownerScope(2)); err != nil || !tableGone(t, conn) {
			t.Fatalf("turn %d: the switch's withdrawal, the last, answered %v or left the table", turn, err)
		}
	}
}

// A holder that never wrote withdraws what it finds of its own and leaves the
// table to the filter, which holds it, and once the filter withdraws, neither
// that holder nor one whose write the kernel refused, and which has not
// withdrawn, keeps the table. A holder that never held, withdrawing what an
// earlier instance left alone in the table, as a start without the kill
// switch's capability does, takes its chain and set and leaves the table.
func TestNftablesHolderThatNeverWroteOrFailedNeitherKeepsNorDeletesTheTable(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmptyLoopbackDown(t)
	conn := dial(t)
	hs := make([]Hold, len(owners))
	t.Cleanup(func() { release(hs) })
	if err := hs[1].Write(conn, ownerRequests(t, 1, true)); err != nil {
		t.Fatalf("write the filter's chain and set: %v", err)
	}
	// a rule in a chain that is not there, which nf_tables refuses with the whole transaction
	refused, err := Chain{Table: Table, Name: owners[2].chains[0]}.Rule(unix.NFPROTO_INET, "drop", [][]byte{Verdict(Drop)})
	if err != nil {
		t.Fatal(err)
	}
	if err := hs[2].Write(conn, []Request{refused}); !errors.Is(err, unix.ENOENT) {
		t.Fatalf("the kill switch's write into a chain that is not there answered %v, want ENOENT", err)
	}
	// the translator's chain and set as an earlier instance left them, written through no holder
	if err := dial(t).Batch(ownerRequests(t, 0, false)); err != nil {
		t.Fatalf("write the translator's leftover chain and set: %v", err)
	}
	if removed, err := hs[0].Withdraw(conn, ownerScope(0)); err != nil || !removed {
		t.Errorf("the translator's withdrawal of its leftovers answered %v, %v", removed, err)
	}
	if got := held(t, conn); !slices.Equal(got, []string{"antispoof", "carved4"}) {
		t.Errorf("beside the filter's hold the table holds %q, want the filter's chain and set", got)
	}
	// the switch has not withdrawn, so its refused write alone could keep the table
	if removed, err := hs[1].Withdraw(conn, ownerScope(1)); err != nil || !removed {
		t.Errorf("the filter's withdrawal answered %v, %v", removed, err)
	}
	if !tableGone(t, conn) {
		t.Error("after the filter, the one holder, withdrew, the table is there")
	}
	if removed, err := hs[2].Withdraw(conn, ownerScope(2)); err != nil || removed {
		t.Errorf("the kill switch's withdrawal after its refused write answered %v, %v, want nothing removed", removed, err)
	}

	if err := dial(t).Batch(ownerRequests(t, 2, true)); err != nil {
		t.Fatalf("write the kill switch's leftover chain and set: %v", err)
	}
	var never Hold
	if removed, err := never.Withdraw(conn, ownerScope(2)); err != nil || !removed {
		t.Errorf("the withdrawal of the switch's leftovers through a holder that never held answered %v, %v", removed, err)
	}
	if got := held(t, conn); len(got) != 0 || tableGone(t, conn) {
		t.Errorf("after the withdrawal of the switch's leftovers alone in the table, through a holder that never held, the table holds %q or is gone, want it there and empty", got)
	}
}

// Holders that found the chains and sets an earlier instance left, and keep
// them without a write, hold the table, each once however often it finds
// them: the kill switch's withdrawal leaves the table and the filter's chain
// and set, and the filter's, the last, deletes the table
func TestNftablesHoldersThatFoundTheirObjectsHoldTheTable(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmptyLoopbackDown(t)
	conn := dial(t)
	// written through no holder
	earlier := dial(t)
	for _, owner := range []int{1, 2} {
		if err := earlier.Batch(ownerRequests(t, owner, true)); err != nil {
			t.Fatalf("write the %s's chain and set as an earlier instance left them: %v", owners[owner].name, err)
		}
	}
	hs := make([]Hold, len(owners))
	t.Cleanup(func() { release(hs) })
	for _, owner := range []int{1, 2, 1} {
		if err := hs[owner].Found(conn); err != nil {
			t.Fatalf("the %s's find: %v", owners[owner].name, err)
		}
	}
	if _, err := hs[2].Withdraw(conn, ownerScope(2)); err != nil {
		t.Fatalf("the kill switch's withdrawal: %v", err)
	}
	if got := held(t, conn); !slices.Equal(got, []string{"antispoof", "carved4"}) {
		t.Errorf("after the kill switch's withdrawal the table holds %q, want the filter's chain and set", got)
	}
	if removed, err := hs[1].Withdraw(conn, ownerScope(1)); err != nil || !removed {
		t.Errorf("the filter's withdrawal answered %v, %v", removed, err)
	}
	if !tableGone(t, conn) {
		t.Error("after the filter, the last holder, withdrew what it found, the table is there")
	}
}

// A holder that withdraws and then writes again holds the table again: the
// other holder's withdrawal after that write leaves the table and the
// written chain, and the holder's own next withdrawal deletes the table
func TestNftablesHolderWritingAgainAfterItsWithdrawalHoldsTheTable(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmptyLoopbackDown(t)
	conn := dial(t)
	hs := writeOwners(t, conn, true)
	for _, owner := range []int{2, 0} {
		if _, err := hs[owner].Withdraw(conn, ownerScope(owner)); err != nil {
			t.Fatalf("the %s's withdrawal: %v", owners[owner].name, err)
		}
	}
	if err := hs[0].Write(conn, ownerRequests(t, 0, true)); err != nil {
		t.Fatalf("the translator's second write: %v", err)
	}
	if n := counted(t, conn); n != 2 {
		t.Fatalf("after the translator's second write %d holders hold the table, want the translator and the filter", n)
	}
	if _, err := hs[1].Withdraw(conn, ownerScope(1)); err != nil {
		t.Fatalf("the filter's withdrawal: %v", err)
	}
	if got := held(t, conn); !slices.Equal(got, []string{"flows4", "forward"}) {
		t.Errorf("after the filter's withdrawal beside the translator's second write the table holds %q, want the translator's chain and set", got)
	}
	if removed, err := hs[0].Withdraw(conn, ownerScope(0)); err != nil || !removed {
		t.Errorf("the translator's second withdrawal answered %v, %v", removed, err)
	}
	if !tableGone(t, conn) {
		t.Error("after the translator's second withdrawal, the last, the table is there")
	}
}

// A holder whose chain and set another writer deleted ends its hold at a
// withdrawal that finds nothing of its own and removes nothing, so the
// filter's withdrawal after it, the last, deletes the table
func TestNftablesHolderWhoseObjectsAreGoneEndsItsHoldAtItsWithdrawal(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmptyLoopbackDown(t)
	conn := dial(t)
	hs := make([]Hold, len(owners))
	t.Cleanup(func() { release(hs) })
	for _, owner := range []int{1, 2} {
		if err := hs[owner].Write(conn, ownerRequests(t, owner, true)); err != nil {
			t.Fatalf("write the %s's chain and set: %v", owners[owner].name, err)
		}
	}
	chain, set := Chain{Table: Table, Name: owners[2].chains[0]}, Set{Table: Table, Name: owners[2].sets[0]}
	if err := dial(t).Batch([]Request{chain.Flush(unix.NFPROTO_INET), chain.Delete(unix.NFPROTO_INET), set.Delete(unix.NFPROTO_INET)}); err != nil {
		t.Fatalf("delete the kill switch's chain and set through another socket: %v", err)
	}
	if removed, err := hs[2].Withdraw(conn, ownerScope(2)); err != nil || removed {
		t.Errorf("the kill switch's withdrawal with its chain and set gone answered %v, %v, want nothing removed", removed, err)
	}
	if n := counted(t, conn); n != 1 {
		t.Errorf("after the kill switch's withdrawal %d holders hold the table, want the filter alone", n)
	}
	if removed, err := hs[1].Withdraw(conn, ownerScope(1)); err != nil || !removed {
		t.Errorf("the filter's withdrawal answered %v, %v", removed, err)
	}
	if !tableGone(t, conn) {
		t.Error("after the filter's withdrawal, the last, the table is there")
	}
}

const (
	// procCover names, in the environment of a process that
	// TestNftablesProcIsReadForTheKeyOnceAtTheFirstAsk runs itself in, when
	// that process covers /proc: "after" its first ask or "before" it
	procCover = "RANET3_NFTABLES_PROC_COVER"
	// procCoverParent names, in the same environment, the mount namespace of
	// the process that started it, as its /proc/self/ns/mnt link reads
	procCoverParent = "RANET3_NFTABLES_PROC_COVER_PARENT"
	// procCoverRefusal begins the failure of a process that refuses to cover
	// /proc
	procCoverRefusal = "refusing to cover /proc: "
)

// A process reads /proc for its key once, at its first ask: one whose /proc is
// covered after that ask keys its next ask as its first, and one whose /proc is
// covered before it keys soleNamespace with nothing opened, its socket not
// asked. Each runs in a process of its own, as root in a user, mount and
// network namespace of its own, since the answer is taken once a process.
// Before any mount it proves its mount namespace is not its parent's, by the
// link /proc/self/ns/mnt, which asks nothing and leaves the read of
// /proc/self/ns/net to the first ask. A third process, started in its
// parent's mount namespace, refuses, and could not mount there anyway: a
// mount needs CAP_SYS_ADMIN in the user namespace that owns the mount
// namespace, and its own user namespace, a descendant of that one, gives none
// there.
func TestNftablesProcIsReadForTheKeyOnceAtTheFirstAsk(t *testing.T) {
	if cover := os.Getenv(procCover); cover != "" {
		if err := ownMountNamespace(cover, os.Getenv(procCoverParent)); err != nil {
			t.Fatal(procCoverRefusal + err.Error())
		}
		askAcrossACoveredProc(t, cover)
		return
	}
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	parent, err := os.Readlink("/proc/self/ns/mnt")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		cover string
		flags uintptr
		// refused is whether the process runs in its parent's mount namespace
		// and so refuses to cover /proc
		refused bool
	}{
		{"after", syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWNET, false},
		{"before", syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWNET, false},
		{"after", syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET, true},
	} {
		helper := exec.Command(executable, "-test.run=^"+t.Name()+"$", "-test.count=1", "-test.v")
		helper.Env = append(os.Environ(), procCover+"="+c.cover, procCoverParent+"="+parent)
		helper.SysProcAttr = &syscall.SysProcAttr{
			Cloneflags:  c.flags,
			UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
			GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		}
		out, err := helper.CombinedOutput()
		if c.refused {
			if err == nil || !strings.Contains(string(out), procCoverRefusal+"this process runs in its parent's mount namespace") {
				t.Errorf("the process in its parent's mount namespace ended with %v, want its refusal:\n%s", err, out)
			}
			if _, err := os.Stat("/proc/self/ns/net"); err != nil {
				t.Errorf("after the refusal this process's /proc/self/ns/net does not stat: %v", err)
			}
			continue
		}
		if err != nil || !strings.Contains(string(out), "--- PASS: "+t.Name()+" ") {
			t.Errorf("the process whose /proc is covered %s its first ask ended with %v:\n%s", c.cover, err, out)
		}
	}
}

// ownMountNamespace refuses, with the reason, unless cover is "before" or
// "after", parent reads as a mount namespace's link, and this process's mount
// namespace is another
func ownMountNamespace(cover, parent string) error {
	if cover != "before" && cover != "after" {
		return fmt.Errorf("the case %q is neither before nor after", cover)
	}
	inode, prefixed := strings.CutPrefix(parent, "mnt:[")
	inode, closed := strings.CutSuffix(inode, "]")
	if _, err := strconv.ParseUint(inode, 10, 64); !prefixed || !closed || err != nil {
		return fmt.Errorf("the parent's mount namespace %q reads as no mnt:[inode]", parent)
	}
	own, err := os.Readlink("/proc/self/ns/mnt")
	if err != nil {
		return fmt.Errorf("read this process's mount namespace: %w", err)
	}
	if own == parent {
		return fmt.Errorf("this process runs in its parent's mount namespace %s", own)
	}
	return nil
}

// askAcrossACoveredProc asks for the key of a socket of its own on each side of
// a tmpfs it mounts over /proc in this process's mount namespace alone, the
// cover after the first ask or before it
func askAcrossACoveredProc(t *testing.T, cover string) {
	conn := dial(t)
	coverProc := func() {
		if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
			t.Fatalf("keep this mount namespace's mounts to itself: %v", err)
		}
		if err := unix.Mount("ranet3", "/proc", "tmpfs", 0, ""); err != nil {
			t.Fatalf("cover /proc: %v", err)
		}
		if _, err := os.Stat("/proc/self/ns/net"); err == nil {
			t.Fatal("under the cover /proc/self/ns/net still stats")
		}
	}
	ask := func() namespace {
		ns, pin, err := conn.namespace()
		if err != nil {
			t.Fatal(err)
		}
		if (pin == nil) != (ns == soleNamespace) {
			t.Errorf("the key %+v comes with the descriptor %v", ns, pin)
		}
		_ = pin.Close()
		return ns
	}
	if cover == "before" {
		coverProc()
		if ns := ask(); ns != soleNamespace {
			t.Errorf("with /proc covered before the first ask the key is %+v, want soleNamespace with the socket not asked", ns)
		}
		return
	}
	first := ask()
	if first == soleNamespace {
		t.Fatal("with /proc there the first ask keys soleNamespace, want the namespace's own key")
	}
	coverProc()
	if second := ask(); second != first {
		t.Errorf("after /proc was covered the second ask keys %+v, the first %+v: one namespace under two keys", second, first)
	}
}

// notificationQuiet is how long a read of the notification group waits for
// another datagram once the withdrawal it watches has been answered
const notificationQuiet = 200 * time.Millisecond

// The last holder's withdrawal reaches the kernel as one transaction: the
// notification group sees the deletions of its chain, its set and the table
// before the one generation that transaction ends with, and no other
func TestNftablesLastHoldersWithdrawalDeletesTheTableInItsOwnTransaction(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmptyLoopbackDown(t)
	conn := dial(t)
	hs := make([]Hold, len(owners))
	t.Cleanup(func() { release(hs) })
	if err := hs[1].Write(conn, ownerRequests(t, 1, true)); err != nil {
		t.Fatalf("write the filter's chain and set: %v", err)
	}
	group, err := netlink.Subscribe("nftables-test", unix.NETLINK_NETFILTER, 1<<(unix.NFNLGRP_NFTABLES-1), receiveBuffer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = group.Close() })
	if removed, err := hs[1].Withdraw(conn, ownerScope(1)); err != nil || !removed {
		t.Fatalf("the filter's withdrawal, the last, answered %v, %v", removed, err)
	}
	var kinds []uint16
	buf := make([]byte, notificationReadSize)
	for {
		if err := group.SetReadDeadline(time.Now().Add(notificationQuiet)); err != nil {
			t.Fatal(err)
		}
		n, err := group.Read(buf)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			break
		}
		if err != nil {
			t.Fatalf("read the notification group: %v", err)
		}
		messages, err := netlink.ParseMessages(buf[:n])
		if err != nil {
			t.Fatal(err)
		}
		for _, message := range messages {
			kinds = append(kinds, message.Kind)
		}
	}
	kind := func(command int) int { return slices.Index(kinds, Command(command)) }
	generations := 0
	for _, k := range kinds {
		if k == Command(unix.NFT_MSG_NEWGEN) {
			generations++
		}
	}
	end := kind(unix.NFT_MSG_NEWGEN)
	for _, command := range []int{unix.NFT_MSG_DELCHAIN, unix.NFT_MSG_DELSET, unix.NFT_MSG_DELTABLE} {
		if at := kind(command); at < 0 || at > end {
			t.Errorf("the withdrawal's notifications %v carry the deletion %d at %d, want it before the generation at %d", kinds, command, at, end)
		}
	}
	if generations != 1 {
		t.Errorf("the withdrawal's notifications %v end %d generations, want 1", kinds, generations)
	}
}
