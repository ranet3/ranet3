// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"maps"
	"net/netip"
	"os"
	"slices"
	"testing"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/egress"
	meshkernel "ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/netnstest"
	"ranet3.com/pkgs/ranet3/internal/nftables"
)

// readCountedTable is the filter's nftables backend with its reads and fills
// counted, a step another writer takes before or after the next fill, and
// short, which makes the next fill send one range less of each set it moves
type readCountedTable struct {
	*borderTable
	reads, fills  int
	before, after func()
	short         bool
}

func (b *readCountedTable) Rules(rules []BorderRule, sets borderSets) (chainReadback, error) {
	b.reads++
	return b.borderTable.Rules(rules, sets)
}

func (b *readCountedTable) Fill(rules []BorderRule, was, sets borderSets) error {
	b.fills++
	if b.before != nil {
		b.before()
		b.before = nil
	}
	if b.short {
		b.short = false
		sets = maps.Clone(sets)
		for name, ranges := range sets {
			if len(ranges) > 1 {
				sets[name] = slices.Clone(ranges[:len(ranges)-1])
			}
		}
	}
	err := b.borderTable.Fill(rules, was, sets)
	if b.after != nil {
		b.after()
		b.after = nil
	}
	return err
}

// The report's four runs of the filter on nf_tables, at 8 learned IPv6 LANs.
// A pass that moves none6 reads once, after the fill, where nothing moved the
// generation. Another writer's flush of none6 before the fill fails or faults
// that pass, and its retry rewrites the filter. A flush after the fill is found
// by the read after it, and so is a fill one range short. A flush between two
// passes moves the generation, so the next pass reads before it fills, and so
// does a sweep where nothing moved it.
func TestBorderFillsOnAnUnmovedGenerationAndTheReadAfterFindsEachFault(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmpty(t)
	var lans []netip.Prefix
	for i := range 8 {
		lans = append(lans, deltaLAN(4*i))
	}
	moving := deltaLAN(17)
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
	flush := func() {
		if err := other.Batch([]nftables.Request{nftables.Set{Table: nftables.Table, Name: noneSet + "6"}.Flush(unix.NFPROTO_INET)}); err != nil {
			t.Fatalf("another writer's flush of none6: %v", err)
		}
	}
	in := false
	pass := func(trigger string, move bool) (reads, fills int, err error) {
		if move {
			if in = !in; in {
				lans = append(slices.Clone(lans), moving)
			} else {
				lans = slices.DeleteFunc(slices.Clone(lans), func(lan netip.Prefix) bool { return lan == moving })
			}
		}
		be.reads, be.fills = 0, 0
		f.trigger = trigger
		err = f.reconcile()
		return be.reads, be.fills, err
	}
	for i := range 2 {
		if reads, fills, err := pass("routes", true); err != nil || reads != 1 || fills != 1 || !f.ready {
			t.Fatalf("plain move %d: %d reads, %d fills, %v, ready %v (%s), want one read after one fill", i, reads, fills, err, f.ready, f.unready)
		}
	}
	retried := func(what string) {
		t.Helper()
		if reads, _, err := pass("retry", false); err != nil || reads != 2 || !f.ready {
			t.Errorf("the retry after %s: %d reads, %v, ready %v (%s), want the read, a rewrite and the read after", what, reads, err, f.ready, f.unready)
		}
	}

	be.before = flush
	if reads, fills, err := pass("routes", true); fills != 1 || reads > 1 || err == nil && f.ready {
		t.Errorf("a flush before the fill: %d reads, %d fills, %v, ready %v, want the pass failed or not ready", reads, fills, err, f.ready)
	}
	retried("a flush before the fill")

	be.after = flush
	if reads, fills, err := pass("routes", true); err != nil || reads != 1 || fills != 1 || f.ready {
		t.Errorf("a flush after the fill: %d reads, %d fills, %v, ready %v, want the read after it to find the set empty", reads, fills, err, f.ready)
	}
	retried("a flush after the fill")

	be.short = true
	if reads, fills, err := pass("routes", true); err != nil || reads != 1 || fills != 1 || f.ready {
		t.Errorf("a fill one range short: %d reads, %d fills, %v, ready %v, want the read after it to find it", reads, fills, err, f.ready)
	}
	retried("a fill one range short")

	flush()
	if reads, fills, err := pass("routes", true); err != nil || reads != 2 || fills != 0 || !f.ready {
		t.Errorf("a move after a flush between passes: %d reads, %d fills, %v, ready %v (%s), want the read before it to find the flush and a rewrite", reads, fills, err, f.ready, f.unready)
	}
	if reads, fills, err := pass("sweep", true); err != nil || reads != 2 || fills != 1 || !f.ready {
		t.Errorf("a sweep that moves a set at an unmoved generation: %d reads, %d fills, %v, ready %v, want a read on each side of the fill", reads, fills, err, f.ready)
	}
}
