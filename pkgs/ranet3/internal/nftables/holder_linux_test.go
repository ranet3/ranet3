// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package nftables

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
)

// holding makes each of hs hold the table in ns, as its first write does,
// and forgets ns at the test's end. A namespace of device 0 is none a kernel
// names.
func holding(t *testing.T, ns namespace, hs ...*Hold) {
	t.Helper()
	holders.Lock()
	defer holders.Unlock()
	if _, taken := holders.held[ns]; taken {
		t.Fatalf("the namespace %+v is held already", ns)
	}
	s := &share{}
	for _, h := range hs {
		h.ns = ns
		s.count++
	}
	holders.held[ns] = s
	t.Cleanup(func() {
		holders.Lock()
		delete(holders.held, ns)
		holders.Unlock()
	})
}

// sentKind is the index of the first of requests of the nf_tables message
// kind, -1 for none
func sentKind(requests []Request, kind int) int {
	return slices.IndexFunc(requests, func(r Request) bool { return r.Kind == Command(kind) })
}

// The filter's withdrawal over a listing that misses the kill switch's chain,
// as a dump that meets another transaction's commit can come back short with
// no flag, deletes the filter's own chain and set and leaves the table while
// the switch holds it, where the listing alone shows the table holding
// nothing but the filter's
func TestWithdrawalOverAListingMissingAnotherHoldersChainKeepsTheTable(t *testing.T) {
	var filter, killSwitch Hold
	holding(t, namespace{ino: 1}, &filter, &killSwitch)
	missed := listing{chains: []string{"antispoof"}, sets: []string{"carved4"}}
	holders.Lock()
	requests := filter.withdrawal(missed, ownerScope(1))
	holders.Unlock()
	if i := sentKind(requests, unix.NFT_MSG_DELTABLE); i >= 0 {
		t.Errorf("the filter's withdrawal beside the switch's hold deletes the table at %d of %d requests", i, len(requests))
	}
	if sentKind(requests, unix.NFT_MSG_DELCHAIN) < 0 || sentKind(requests, unix.NFT_MSG_DELSET) < 0 {
		t.Errorf("the filter's withdrawal sends %d requests, want its chain and set deleted", len(requests))
	}
}

// A hold the switch's owner released as it ended, its chain left in the
// table, keeps the table whatever the listing shows: the filter's withdrawal,
// the one holder's now, deletes its own chain and set and not the table over a
// listing that misses the switch's chain, and with it the namespace's last
// hold goes
func TestWithdrawalAfterAReleaseKeepsTheTableOverAListingMissingTheReleasedChain(t *testing.T) {
	var filter, killSwitch Hold
	ns := namespace{ino: 2}
	holding(t, ns, &filter, &killSwitch)
	killSwitch.Release()
	holders.Lock()
	requests := filter.withdrawal(listing{chains: []string{"antispoof"}, sets: []string{"carved4"}}, ownerScope(1))
	filter.release()
	_, left := holders.held[ns]
	holders.Unlock()
	if i := sentKind(requests, unix.NFT_MSG_DELTABLE); i >= 0 {
		t.Errorf("after the switch's release the filter's withdrawal over a listing of its own alone deletes the table at %d of %d requests", i, len(requests))
	}
	if sentKind(requests, unix.NFT_MSG_DELCHAIN) < 0 || sentKind(requests, unix.NFT_MSG_DELSET) < 0 {
		t.Errorf("the filter's withdrawal sends %d requests, want its chain and set deleted", len(requests))
	}
	if left {
		t.Error("after the switch's release and the filter's withdrawal the namespace is still held")
	}
}

// netNamespaceShown takes a stat of /proc/self/ns/net that succeeds as showing
// a network namespace of the process's own, and shows none where the link is
// not there, where /proc is missing, where the stat is denied or where it
// fails for anything else
func TestNetNamespaceIsShownOnlyByAStatThatSucceeds(t *testing.T) {
	dir := t.TempDir()
	net := filepath.Join(dir, "net")
	if err := os.WriteFile(net, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	stat := func(path string) error {
		_, err := os.Stat(path)
		return err
	}
	for _, c := range []struct {
		name  string
		err   error
		shown bool
	}{
		{"a link that stats", stat(net), true},
		{"no link", stat(filepath.Join(dir, "absent")), false},
		{"no /proc", stat(filepath.Join(dir, "proc", "self", "ns", "net")), false},
		{"a denied stat", &fs.PathError{Op: "stat", Path: "/proc/self/ns/net", Err: unix.EACCES}, false},
		{"a path through a file", stat(filepath.Join(net, "net")), false},
	} {
		if got := netNamespaceShown(c.err); got != c.shown {
			t.Errorf("with %s, a stat answering %v, a network namespace is shown %v, want %v", c.name, c.err, got, c.shown)
		}
	}
}

// A release in one namespace keeps the table in that namespace alone, and a
// release by a Hold that never held keeps it nowhere: the one holder of a
// second namespace, withdrawing over a listing of its own alone, deletes the
// table there
func TestLastWithdrawalInOneNamespaceDeletesTheTableBesideAReleaseInAnother(t *testing.T) {
	var filter, killSwitch, translator, never Hold
	released, other := namespace{ino: 3}, namespace{ino: 4}
	holding(t, released, &filter, &killSwitch)
	holding(t, other, &translator)
	killSwitch.Release()
	never.Release()
	holders.Lock()
	requests := translator.withdrawal(listing{chains: []string{"forward"}, sets: []string{"flows4"}}, ownerScope(0))
	holders.Unlock()
	if i := sentKind(requests, unix.NFT_MSG_DELTABLE); i != len(requests)-1 {
		t.Errorf("beside a release in another namespace the translator's withdrawal, the last in its own, deletes the table at %d of %d requests, want last", i, len(requests))
	}
}

// The last of three holders to withdraw deletes the table at the end of the
// transaction that deletes its own chain and set, and neither of the two
// before it deletes the table, in each order the three can withdraw in
func TestLastOfThreeHoldersDeletesTheTableInEachOrder(t *testing.T) {
	orders := [][]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}}
	for i, order := range orders {
		hs := make([]Hold, len(owners))
		ns := namespace{ino: uint64(10 + i)}
		holding(t, ns, &hs[0], &hs[1], &hs[2])
		left := []int{0, 1, 2}
		for step, owner := range order {
			var l listing
			for _, o := range left {
				l.chains = append(l.chains, owners[o].chains[0])
				l.sets = append(l.sets, owners[o].sets[0])
			}
			holders.Lock()
			requests := hs[owner].withdrawal(l, ownerScope(owner))
			hs[owner].release()
			holders.Unlock()
			deletes, last := sentKind(requests, unix.NFT_MSG_DELTABLE), step == len(order)-1
			if (deletes >= 0) != last {
				t.Errorf("in the order %v the %s's withdrawal, at step %d, deletes the table %v, want %v", order, owners[owner].name, step, deletes >= 0, last)
			}
			if last && deletes != len(requests)-1 {
				t.Errorf("in the order %v the last withdrawal deletes the table at %d of %d requests, want last", order, deletes, len(requests))
			}
			deleted := func(kind int, name string) bool {
				return slices.ContainsFunc(requests, func(r Request) bool { return r.Kind == Command(kind) && requestName(r) == name })
			}
			if !deleted(unix.NFT_MSG_DELCHAIN, owners[owner].chains[0]) || !deleted(unix.NFT_MSG_DELSET, owners[owner].sets[0]) {
				t.Errorf("in the order %v the %s's withdrawal leaves its chain or set", order, owners[owner].name)
			}
			left = slices.DeleteFunc(left, func(o int) bool { return o == owner })
		}
		holders.Lock()
		s, held := holders.held[ns]
		holders.Unlock()
		if held {
			t.Errorf("in the order %v the namespace keeps %d holders after every withdrawal", order, s.count)
		}
	}
}
