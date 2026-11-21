// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/egress"
	meshkernel "ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/netnstest"
	"ranet3.com/pkgs/ranet3/internal/nftables"
)

// readCountedTable is the filter's nftables backend with its reads and fills
// counted, a step another writer takes before or after the next fill, and
// short, which makes the next fill send one range less of each set it
// changes. Its monitor's wakes never reach Run, as a monitor stopped on a read
// error leaves them.
type readCountedTable struct {
	*borderTable
	reads, fills  atomic.Int32
	before, after func()
	short         bool
}

func (b *readCountedTable) Rules(rules []BorderRule, sets borderSets) (chainReadback, error) {
	b.reads.Add(1)
	return b.borderTable.Rules(rules, sets)
}

func (b *readCountedTable) Fill(rules []BorderRule, was, sets borderSets) error {
	b.fills.Add(1)
	if b.before != nil {
		b.before()
		b.before = nil
	}
	if b.short {
		b.short = false
		sets = shortened(sets)
	}
	err := b.borderTable.Fill(rules, was, sets)
	if b.after != nil {
		b.after()
		b.after = nil
	}
	return err
}

func (b *readCountedTable) Changed() <-chan struct{} { return nil }

func (b *readCountedTable) Missed() <-chan struct{} { return nil }

// generationLab is a filter on nf_tables in an empty namespace at 8 learned
// IPv6 LANs, its counted backend, the step that adds or takes a ninth, which
// stands apart from the others so that a fill adds or deletes its one range
// alone, and another writer's flush of none6
func generationLab(t *testing.T) (*BorderFilter, *readCountedTable, func(), func()) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmpty(t)
	var lans []netip.Prefix
	for i := range 8 {
		lans = append(lans, deltaLAN(4*i))
	}
	moving := deltaLAN(18)
	rt := egress.BorderRuntime{Tun: "ranet3", Inside: []string{"ranet3", "lo"}, Sets: func(*egress.Border) egress.BorderSets {
		return egress.BorderSets{None: meshkernel.Ranges(lans)}
	}}
	opened, err := newBorderBackend(nil, egress.BorderRuntime{})
	if err != nil {
		t.Fatal(err)
	}
	be := &readCountedTable{borderTable: opened.(*borderTable)}
	f, err := startBorderFilter(nil, rt, be)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.finish() })
	other, err := nftables.Dial()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = other.Close() })
	in := false
	step := func() {
		if in = !in; in {
			lans = append(slices.Clone(lans), moving)
		} else {
			lans = slices.DeleteFunc(slices.Clone(lans), func(lan netip.Prefix) bool { return lan == moving })
		}
	}
	flush := func() {
		if err := other.Batch([]nftables.Request{nftables.Set{Table: nftables.Table, Name: noneSet + "6"}.Flush(unix.NFPROTO_INET)}); err != nil {
			t.Errorf("another writer's flush of none6: %v", err)
		}
	}
	return f, be, step, flush
}

// The filter on nf_tables at 8 learned IPv6 LANs, each pass changing none6
// by one LAN. A pass reads once, after its fill, where no transaction has
// committed since the last read. Another writer's flush of none6 before the
// fill lets the fill's add commit, and the read after finds the set short,
// and so does a flush after the fill and a fill one range short, each pass
// arming the retry, whose read rewrites the filter. A flush between two passes
// moves the generation, so the next pass reads before it fills, and so does
// a sweep where nothing moved it. A flush before a fill that deletes makes
// nf_tables refuse the fill, and the retry rewrites the filter.
func TestBorderFillsOnAnUnmovedGenerationAndTheReadAfterFindsEachFault(t *testing.T) {
	f, be, step, flush := generationLab(t)
	pass := func(trigger string, change bool) (reads, fills int, err error) {
		if change {
			step()
		}
		be.reads.Store(0)
		be.fills.Store(0)
		f.trigger = trigger
		err = f.reconcile()
		return int(be.reads.Load()), int(be.fills.Load()), err
	}
	for i := range 2 {
		if reads, fills, err := pass("routes", true); err != nil || reads != 1 || fills != 1 || !f.ready {
			t.Errorf("plain change %d: %d reads, %d fills, %v, ready %v (%s), want one read after one fill", i, reads, fills, err, f.ready, f.unready)
		}
	}
	retried := func(what string, fault bool) {
		t.Helper()
		if fault && !f.retryOnFault {
			t.Errorf("the pass after %s armed no retry", what)
		}
		if reads, _, err := pass("retry", false); err != nil || reads != 2 || !f.ready {
			t.Errorf("the retry after %s: %d reads, %v, ready %v (%s), want the read, a rewrite and the read after", what, reads, err, f.ready, f.unready)
		}
	}

	be.before = flush
	if reads, fills, err := pass("routes", true); err != nil || reads != 1 || fills != 1 || f.ready {
		t.Errorf("a flush before the fill: %d reads, %d fills, %v, ready %v, want the fill's add committed and the read after it to find the set short", reads, fills, err, f.ready)
	}
	retried("a flush before the fill", true)

	be.after = flush
	if reads, fills, err := pass("routes", true); err != nil || reads != 1 || fills != 1 || f.ready {
		t.Errorf("a flush after the fill: %d reads, %d fills, %v, ready %v, want the read after it to find the set empty", reads, fills, err, f.ready)
	}
	retried("a flush after the fill", true)

	be.short = true
	if reads, fills, err := pass("routes", true); err != nil || reads != 1 || fills != 1 || f.ready {
		t.Errorf("a fill one range short: %d reads, %d fills, %v, ready %v, want the read after it to find it", reads, fills, err, f.ready)
	}
	retried("a fill one range short", true)

	flush()
	if reads, fills, err := pass("routes", true); err != nil || reads != 2 || fills != 0 || !f.ready {
		t.Errorf("a change after a flush between passes: %d reads, %d fills, %v, ready %v (%s), want the read before it to find the flush and a rewrite", reads, fills, err, f.ready, f.unready)
	}
	if reads, fills, err := pass("sweep", true); err != nil || reads != 2 || fills != 1 || !f.ready {
		t.Errorf("a sweep that changes a set where nothing moved the generation: %d reads, %d fills, %v, ready %v, want a read on each side of the fill", reads, fills, err, f.ready)
	}

	be.before = flush
	if reads, fills, err := pass("routes", true); err == nil || reads != 0 || fills != 1 || f.ready {
		t.Errorf("a flush before a fill that deletes: %d reads, %d fills, %v, ready %v, want the fill refused", reads, fills, err, f.ready)
	}
	retried("a flush before a fill that deletes", false)
}

// Under Run on nf_tables, with the monitor's wakes stopped and the sweep 30
// seconds off, another writer's flush of none6 before a fill with no read
// before it leaves the set short after the fill, and the retry rewrites the
// filter within its delay
func TestBorderRunRetriesAFaultTheReadAfterAFillFoundOnNftables(t *testing.T) {
	f, be, step, flush := generationLab(t)
	runBorder(t, f)
	woken := func(what string) egress.BorderStats {
		t.Helper()
		at := f.Stats().At
		f.kernel <- struct{}{}
		for deadline := time.Now().Add(PassWait); ; time.Sleep(passPoll) {
			if stats := f.Stats(); !stats.At.Equal(at) {
				return stats
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s drew no pass within %v", what, PassWait)
			}
		}
	}
	for i := range 2 {
		step()
		be.reads.Store(0)
		be.fills.Store(0)
		if stats := woken("a plain change"); !stats.Ready || be.reads.Load() != 1 || be.fills.Load() != 1 {
			t.Fatalf("plain change %d: %d reads, %d fills, ready %v (%s, %s), want one read after one fill", i, be.reads.Load(), be.fills.Load(), stats.Ready, stats.Unready, stats.Err)
		}
	}
	be.before = flush
	step()
	be.reads.Store(0)
	be.fills.Store(0)
	stats := woken("a change with a flush before its fill")
	faulted := time.Now()
	if stats.Ready || stats.Err != "" || be.reads.Load() != 1 || be.fills.Load() != 1 {
		t.Fatalf("a flush before the fill: %d reads, %d fills, ready %v, error %q, want the fill's add committed and the read after it to find the set short", be.reads.Load(), be.fills.Load(), stats.Ready, stats.Err)
	}
	for !f.Stats().Ready {
		if time.Since(faulted) > retryWait {
			t.Fatalf("no pass repaired the set within %v of the fault, %d reads since the change", retryWait, be.reads.Load())
		}
		time.Sleep(passPoll)
	}
	if reads := be.reads.Load(); reads != 3 {
		t.Errorf("the repair took %d reads since the change, want the read after the fill, the retry's read and the read after its rewrite", reads)
	}
}

// A fill the kernel acknowledged with an errno reads as refused, and one
// whose acknowledgment did not come does not
func TestBorderTableFillTakesOnlyAnAcknowledgedErrnoAsRefused(t *testing.T) {
	if !errors.As(refusal(fmt.Errorf("write: %w", &nftables.Refused{Err: unix.ENOENT})), new(refused)) {
		t.Error("an errno the kernel acknowledged read as a commit left unknown")
	}
	if errors.As(refusal(errors.New("netlink: the kernel did not answer in time")), new(refused)) {
		t.Error("an answer that did not come read as refused")
	}
}

// The filter's generation is 0 where the read fails
func TestBorderTableGenerationIsZeroWhereTheReadFails(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmpty(t)
	opened, err := newBorderBackend(nil, egress.BorderRuntime{})
	if err != nil {
		t.Fatal(err)
	}
	be := opened.(*borderTable)
	t.Cleanup(func() { _ = be.Close() })
	if g := be.generation(); g == 0 {
		t.Fatal("a read on an open socket answered 0")
	}
	_ = be.conn.Close()
	if g := be.generation(); g != 0 {
		t.Errorf("a read on a closed socket answered %d, want 0", g)
	}
}
