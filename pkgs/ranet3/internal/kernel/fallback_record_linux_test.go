// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/netlink"
	"ranet3.com/pkgs/ranet3/internal/netnstest"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/nftables"
	"ranet3.com/pkgs/ranet3/schema"
)

// The watch marks its record moved on each change and each loss its monitor
// reports, before the wake that starts the pass reading the record
func TestFallbackWatchMarksItsRecordMovedBeforeItWakes(t *testing.T) {
	for _, report := range []string{"a change", "a loss"} {
		changed, missed := make(chan struct{}, 1), make(chan struct{}, 1)
		moved := make(chan bool, 1)
		w := &fallbackWatch{stop: make(chan struct{}), done: make(chan struct{})}
		go w.forward(changed, missed, func() { moved <- w.rec.moved.Swap(false) })
		if report == "a change" {
			changed <- struct{}{}
		} else {
			missed <- struct{}{}
		}
		select {
		case got := <-moved:
			if !got {
				t.Errorf("%s the monitor reported woke the reconciler with the record unmoved", report)
			}
		case <-time.After(monitorWakeBudget):
			t.Errorf("%s the monitor reported woke nothing", report)
		}
		close(w.stop)
		<-w.done
	}
}

// An overflow the switch's monitor reports, each datagram it reads before its
// queue is empty, while the kernel may still be dropping, and the read that
// finds it empty each have the next pass a route change alone wakes read the
// switch through the watch's record, and the pass after the last skips
func TestFallbackOverrunHasThePassesReadUntilTheDrainAndOneAfter(t *testing.T) {
	reconciler, watched, _ := watchedHarness(t)
	missed, marked := make(chan struct{}, 1), make(chan struct{})
	w := &fallbackWatch{stop: make(chan struct{}), done: make(chan struct{})}
	watched.rec = &w.rec
	go w.forward(make(chan struct{}), missed, func() { marked <- struct{}{} })
	t.Cleanup(func() {
		close(w.stop)
		<-w.done
	})
	// the watch's record holds no read yet, so the first pass reads
	if reads, err := watched.pass(reconciler, "mesh"); reads != 1 || err != nil {
		t.Fatalf("the first route change on the watch read the switch %d times with %v, want 1", reads, err)
	}
	for _, report := range []string{"the overflow", "a datagram read before the drain", "the drain"} {
		missed <- struct{}{}
		select {
		case <-marked:
		case <-time.After(monitorWakeBudget):
			t.Fatalf("the loss the monitor reported at %s woke nothing", report)
		}
		if reads, err := watched.pass(reconciler, "mesh"); reads != 1 || err != nil {
			t.Fatalf("the route change after %s read the switch %d times with %v, want 1", report, reads, err)
		}
	}
	if reads, err := watched.pass(reconciler, "mesh"); reads != 0 || err != nil {
		t.Fatalf("the route change after the drain's pass read the switch %d times with %v, want none", reads, err)
	}
}

// watchedSwitch is a reconciler under fallback none on its own platform
// whose switch a monitor watches, running past its first pass, where the
// periodic pass takes an hour, with the mesh's routes it reads, a socket of
// the test's own to write the table through and whether the switch reads
// back as written through that socket
func watchedSwitch(t *testing.T, device, uplink string) (*netlinkPlatform, *netstack.RouteTable, *nftables.Conn, func() bool) {
	t.Helper()
	plat := rootRulePlatform(t, device)
	if err := netnstest.BringUp(device); err != nil {
		t.Fatal(err)
	}
	tbl, rt := fallbackNoneOverUplink(t, device, uplink)
	tbl.Reconcile = schema.Duration(time.Hour)
	// as newPlatform would for the mode, on the test's thread, whose namespace the rules go in, where Run's is another
	plat.retable(tbl)
	if _, err := plat.watchFallback(); err != nil {
		t.Fatal(err)
	}
	routes := netstack.NewRouteTable()
	reconciler := newReconciler(tbl, rt, tbl.Assigned(nil), routes, plat)
	exit, _ := reconciler.exitPass(reconciler.addresses, nil, reconciler.readNetwork())
	sets, asked := reconciler.fallbackFor(exit)
	if !asked {
		t.Fatal("the mode does not ask for the table")
	}
	// read and written through a socket of the test's own, since the loop owns the platform's
	other, err := nftables.Dial()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = other.Close() })
	written := func() bool {
		read, _, err := fallbackFault(other, sets)
		if err != nil {
			t.Fatalf("read the table back: %v", err)
		}
		return read.fault == ""
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- reconciler.Run(ctx) }()
	// the monitor closed by hand fails the platform's own close, which Run returns
	t.Cleanup(func() {
		cancel()
		<-done
	})
	<-reconciler.FirstPass()
	waitFor(t, written)
	// the pass the start's own address writes wake has run by then
	time.Sleep(secondPassWindow)
	return plat, routes, other, written
}

// With the switch's monitor stopped, as a read error other than an overflow
// stops it, another writer's flush of the switch's chain wakes no pass, and the
// next pass a route change alone wakes reads the switch and writes it back
func TestNetlinkFallbackStoppedMonitorLeavesEveryPassReading(t *testing.T) {
	plat, routes, other, written := watchedSwitch(t, "ranetrec0", "ranetrup0")
	if err := plat.fallback.monitor.Close(); err != nil {
		t.Fatal(err)
	}
	if err := other.Batch([]nftables.Request{nftables.Chain{Table: nftables.Table, Name: fallbackChain.Name}.Flush(unix.NFPROTO_INET)}); err != nil {
		t.Fatalf("flush the switch's chain as another writer: %v", err)
	}
	time.Sleep(secondPassWindow)
	if written() {
		t.Fatal("a pass wrote the flushed chain back with the switch's monitor stopped, so something else woke it")
	}
	routes.Set(netip.Prefix{}, prefix("2001:db8:1::/48"), nil)
	changed := time.Now()
	waitFor(t, written)
	if took := time.Since(changed); took > fallbackRestoreBudget {
		t.Errorf("the flushed chain took %s to be written back after the route change, want at most %s", took, fallbackRestoreBudget)
	}
}

// Another writer's rename of the switch's chain to a name outside the switch's
// and its deletion under that name each start a pass, which writes the chain
// back with no route change, where the periodic pass takes an hour
func TestNetlinkFallbackChainRenamedAwayAndDeletedIsWrittenBack(t *testing.T) {
	_, _, other, written := watchedSwitch(t, "ranetren0", "ranetrenup0")
	replies, err := other.Dump(nftables.Command(unix.NFT_MSG_GETCHAIN), netlink.PutAttrString(nftables.PutNfgenmsg(nil, unix.NFPROTO_INET), unix.NFTA_CHAIN_TABLE, nftables.Table))
	if err != nil {
		t.Fatalf("dump the table's chains: %v", err)
	}
	var handle []byte
	for _, reply := range replies {
		var name string
		var held []byte
		for kind, value := range reply.Attributes(nftables.SizeofNfgenmsg) {
			switch kind {
			case unix.NFTA_CHAIN_NAME:
				name = unix.ByteSliceToString(value)
			case unix.NFTA_CHAIN_HANDLE:
				held = value
			}
		}
		if name == fallbackChain.Name {
			handle = held
		}
	}
	if handle == nil {
		t.Fatalf("the table holds no chain %s", fallbackChain.Name)
	}
	const elsewhere = "elsewhere"
	renamed := netlink.PutAttrString(nftables.PutNfgenmsg(nil, unix.NFPROTO_INET), unix.NFTA_CHAIN_TABLE, nftables.Table)
	renamed = netlink.PutAttr(renamed, unix.NFTA_CHAIN_HANDLE, handle)
	renamed = netlink.PutAttrString(renamed, unix.NFTA_CHAIN_NAME, elsewhere)
	if err := other.Batch([]nftables.Request{{Kind: nftables.Command(unix.NFT_MSG_NEWCHAIN), Body: renamed}}); err != nil {
		t.Fatalf("rename the switch's chain as another writer: %v", err)
	}
	if err := other.Batch([]nftables.Request{nftables.Chain{Table: nftables.Table, Name: elsewhere}.Delete(unix.NFPROTO_INET)}); err != nil {
		t.Fatalf("delete the renamed chain as another writer: %v", err)
	}
	deleted := time.Now()
	waitFor(t, written)
	if took := time.Since(deleted); took > fallbackRestoreBudget {
		t.Errorf("the chain renamed away and deleted took %s to be written back, want at most %s", took, fallbackRestoreBudget)
	}
}
