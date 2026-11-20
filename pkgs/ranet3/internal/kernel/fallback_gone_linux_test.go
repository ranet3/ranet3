// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/logtest"
	"ranet3.com/pkgs/ranet3/internal/netlink"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/nftables"
)

// fallbackFault reads the switch through conn, a socket of a test's own, over
// one dump of the tables
func fallbackFault(conn *nftables.Conn, s fallbackSets) (fallbackRead, bool, error) {
	tables, err := nftables.Tables(conn, nftables.Table)
	if err != nil {
		return fallbackRead{}, false, err
	}
	return faultOver(connReads(conn, s), tables)
}

// goneSwitch fails its first read from from with first and answers later
// dumps with confirm, as a table that goes or stays does
type goneSwitch struct {
	// firstDump fails the first dump of the tables
	firstDump error
	// first fails the read from names, contents where empty, over a dump
	// naming the table before it went
	first error
	from  string
	// confirm answers every dump of the tables after the first
	confirm func() (map[uint8]uint32, error)
	// readback makes the first read a write's readback
	readback bool
	// absent is whether the last dump found the table gone
	absent        bool
	dumps, writes int
}

func (g *goneSwitch) dump() (map[uint8]uint32, error) {
	if g.dumps++; g.dumps == 1 {
		return map[uint8]uint32{unix.NFPROTO_INET: 0}, g.firstDump
	}
	now, err := g.confirm()
	_, held := now[unix.NFPROTO_INET]
	g.absent = err == nil && !held
	return now, err
}

func (g *goneSwitch) readFallback(fallbackSets) (fallbackRead, error) {
	// before is whether the read is over a dump naming the table before it went
	before := false
	failing := func(from string) error {
		if before && cmp.Or(g.from, "contents") == from {
			return g.first
		}
		return nil
	}
	reads := fallbackReads{
		contents: func(tables map[uint8]uint32) (nftables.Readback, error) {
			_, held := tables[unix.NFPROTO_INET]
			before = g.dumps == 1 || held && g.absent
			if err := failing("contents"); err != nil {
				return nftables.Readback{}, err
			}
			if g.writes > 0 || before {
				return nftables.Readback{Held: true}, nil
			}
			return nftables.Readback{Fault: "its chains are missing"}, nil
		},
		leftovers:  func(map[uint8]uint32) ([]nftables.Retired, error) { return nil, failing("leftovers") },
		chainFault: func(int, []nftables.Installed) (string, error) { return "", failing("lines") },
	}
	read, _, err := readOrGone(g.dump, func(tables map[uint8]uint32) (fallbackRead, bool, error) { return faultOver(reads, tables) }, !g.readback)
	return read, err
}

func (g *goneSwitch) writeFallback(fallbackSets, bool) error {
	g.writes++
	return nil
}

func (g *goneSwitch) deleteFallback() error        { return nil }
func (g *goneSwitch) holdsFallback() (bool, error) { return g.writes > 0, nil }
func (g *goneSwitch) form() fallbackForm           { return tableForm }

// goneLine is the line a pass logs where it finds the switch's table gone
const goneLine = "kernel's kill switch table was deleted during its read"

// A read that fails ENOENT, from any of its dumps, where a fresh dump of the
// tables holds no inet table is a table gone during the read: the pass says so
// once and writes the switch in it.
func TestFallbackReadsTheTableGoneOnlyWhereAFreshDumpConfirmsIt(t *testing.T) {
	vanish := fmt.Errorf("kernel: read table inet %s: dump sets: %w", nftables.Table, unix.ENOENT)
	absent := func() (map[uint8]uint32, error) { return map[uint8]uint32{}, nil }
	present := func() (map[uint8]uint32, error) { return map[uint8]uint32{unix.NFPROTO_INET: 0}, nil }
	failing := func() (map[uint8]uint32, error) { return nil, fmt.Errorf("nftables: dump tables: %w", unix.ENOBUFS) }
	for name, row := range map[string]struct {
		goneSwitch
		gone  bool
		dumps int
	}{
		"ENOENT from the switch's chains and sets and the table absent from the fresh dump": {goneSwitch: goneSwitch{first: vanish, confirm: absent}, gone: true},
		"ENOENT from the leftovers and the table absent from the fresh dump":                {goneSwitch: goneSwitch{first: fmt.Errorf("nftables: dump sets: %w", unix.ENOENT), from: "leftovers", confirm: absent}, gone: true},
		"ENOENT from a line's anonymous set and the table absent from the fresh dump":       {goneSwitch: goneSwitch{first: fmt.Errorf("nftables: dump the elements of set __set0: %w", unix.ENOENT), from: "lines", confirm: absent}, gone: true},
		"ENOENT and the table in the fresh dump":                                            {goneSwitch: goneSwitch{first: vanish, confirm: present}, dumps: 2},
		"ENOENT and the fresh dump failing":                                                 {goneSwitch: goneSwitch{first: vanish, confirm: failing}, dumps: 2},
		"ENOENT on a readback and the table absent":                                         {goneSwitch: goneSwitch{first: vanish, confirm: absent, readback: true}, dumps: 1},
		"the first dump of the tables failing":                                              {goneSwitch: goneSwitch{firstDump: fmt.Errorf("nftables: dump tables: %w", unix.ENOBUFS), confirm: absent}, dumps: 1},
		"EPERM and the table absent":                                                        {goneSwitch: goneSwitch{first: fmt.Errorf("nftables: dump sets: %w", unix.EPERM), confirm: absent}, dumps: 1},
		"ENOBUFS and the table absent":                                                      {goneSwitch: goneSwitch{first: fmt.Errorf("dump rules: %w", unix.ENOBUFS), confirm: absent}, dumps: 1},
		"dump given up as interrupted and the table absent":                                 {goneSwitch: goneSwitch{first: fmt.Errorf("dump chains: %w", netlink.ErrDumpInterrupted), confirm: absent}, dumps: 1},
		"reply that does not decode and the table absent":                                   {goneSwitch: goneSwitch{first: errors.New("netlink: truncated errno"), confirm: absent}, dumps: 1},
	} {
		t.Run(name, func(t *testing.T) {
			var logs bytes.Buffer
			logtest.SetDefault(t, slog.New(slog.NewJSONHandler(&logs, nil)))
			reconciler, _, _ := harness(t, Table{})
			sw := &row.goneSwitch
			reconciler.sw = sw
			status, err := reconciler.applyFallback(fallbackSets{}, true)
			said := strings.Count(logs.String(), goneLine)
			if row.gone {
				if err != nil || status == nil || status.State != FallbackHolding || sw.writes != 1 || said != 1 {
					t.Errorf("the pass reports %+v (%v) after %d writes and %d lines of the table gone, want holding after one of each", status, err, sw.writes, said)
				}
				return
			}
			want := cmp.Or(row.firstDump, row.first)
			if !errors.Is(err, want) || sw.writes != 0 || sw.dumps != row.dumps || said != 0 {
				t.Errorf("the pass failed with %v after %d writes, %d dumps of the tables and %d lines of the table gone, want the read's %v, none, %d and none", err, sw.writes, sw.dumps, said, want, row.dumps)
			}
			if status == nil || status.State != FallbackNotHolding {
				t.Errorf("the pass reports %+v, want not holding", status)
			}
		})
	}
}

// tablesSwitch is the platform's switch whose reads dump the tables through
// dump, so another writer's change lands between a read's dump of the tables
// and its later dumps
type tablesSwitch struct {
	*netlinkPlatform
	dump func(conn *nftables.Conn) (map[uint8]uint32, error)
}

func (s tablesSwitch) readFallback(sets fallbackSets) (fallbackRead, error) {
	return s.readFallbackThrough(sets, s.dump)
}

// anotherWriter is a socket of another writer's to the table, whose batch
// fails the test where nf_tables refuses it
func anotherWriter(t *testing.T) func(requests ...nftables.Request) {
	t.Helper()
	conn, err := nftables.Dial()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return func(requests ...nftables.Request) {
		t.Helper()
		if err := conn.Batch(requests); err != nil {
			t.Fatalf("another writer's batch: %v", err)
		}
	}
}

// switchUnderAnotherWriter is a reconciler asking for the switch over an
// uplink, on the platform, with the table holding another writer's chain alone
func switchUnderAnotherWriter(t *testing.T) (*netlinkPlatform, *Reconciler, fallbackSets, func(requests ...nftables.Request)) {
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
	write := anotherWriter(t)
	write(nftables.NewTable(unix.NFPROTO_INET, nftables.Table), nftables.Chain{Table: nftables.Table, Name: "entry", Hook: nftables.NoHook}.Create(unix.NFPROTO_INET))
	return plat, reconciler, sets, write
}

// The switch asked for over a table holding another writer's chain alone, the
// table deleted between the read's dump of the tables and its later dumps, is
// written in that pass, which reports it holding, and it then reads back as
// written and refuses a datagram beyond the LAN
func TestNetlinkFallbackIsWrittenInThePassItsTableGoesIn(t *testing.T) {
	plat, reconciler, sets, write := switchUnderAnotherWriter(t)
	deleted := false
	reconciler.sw = tablesSwitch{netlinkPlatform: plat, dump: func(conn *nftables.Conn) (map[uint8]uint32, error) {
		tables, err := nftables.Tables(conn, nftables.Table)
		if !deleted {
			write(nftables.DeleteTable(unix.NFPROTO_INET, nftables.Table))
			deleted = true
		}
		return tables, err
	}}
	if status, err := reconciler.applyFallback(sets, true); err != nil || status == nil || status.State != FallbackHolding {
		t.Fatalf("the pass the table went in reports %+v (%v), want holding", status, err)
	}
	if read, err := plat.readFallback(sets); read.fault != "" || err != nil {
		t.Errorf("after the pass the switch reads back with %q (%v)", read.fault, err)
	}
	if err := sendFrom(t, netip.MustParseAddr("192.0.2.200"), 9, ""); !errors.Is(err, unix.EPERM) {
		t.Errorf("after the pass a datagram beyond the LAN left with %v, want EPERM", err)
	}
}

// The table deleted between the read's dump of the tables and its later
// dumps, and made again by another writer before the read's fresh dump of the
// tables, is not gone: the pass writes nothing and fails with ENOENT, and the
// next pass writes the switch
func TestNetlinkFallbackLeavesATableMadeAgainBeforeTheFreshDumpToTheNextPass(t *testing.T) {
	plat, reconciler, sets, write := switchUnderAnotherWriter(t)
	dumps := 0
	reconciler.sw = tablesSwitch{netlinkPlatform: plat, dump: func(conn *nftables.Conn) (map[uint8]uint32, error) {
		if dumps++; dumps == 2 {
			write(nftables.NewTable(unix.NFPROTO_INET, nftables.Table))
		}
		tables, err := nftables.Tables(conn, nftables.Table)
		if dumps == 1 {
			write(nftables.DeleteTable(unix.NFPROTO_INET, nftables.Table))
		}
		return tables, err
	}}
	status, err := reconciler.applyFallback(sets, true)
	if !errors.Is(err, unix.ENOENT) || status == nil || status.State != FallbackNotHolding {
		t.Fatalf("the pass reports %+v (%v), want not holding with %v", status, err, unix.ENOENT)
	}
	reader, err := nftables.Dial()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close() })
	chains, err := nftables.TableChains(reader, unix.NFPROTO_INET, nftables.Table)
	if err != nil || len(chains) != 0 {
		t.Fatalf("after the failed pass the table holds chains %v (%v), want none", chains, err)
	}
	if status, err := reconciler.applyFallback(sets, true); err != nil || status == nil || status.State != FallbackHolding {
		t.Errorf("the next pass reports %+v (%v), want holding", status, err)
	}
}

// The table deleted again under the readback of the write that made it again
// fails the pass with ENOENT, so the retry follows it, and the next pass
// writes the switch
func TestNetlinkFallbackFailsThePassWhoseReadbackFindsItsTableGoneAgain(t *testing.T) {
	plat, reconciler, sets, write := switchUnderAnotherWriter(t)
	dumps := 0
	reconciler.sw = tablesSwitch{netlinkPlatform: plat, dump: func(conn *nftables.Conn) (map[uint8]uint32, error) {
		tables, err := nftables.Tables(conn, nftables.Table)
		// the read's first dump and the readback's
		if dumps++; dumps == 1 || dumps == 3 {
			write(nftables.DeleteTable(unix.NFPROTO_INET, nftables.Table))
		}
		return tables, err
	}}
	status, err := reconciler.applyFallback(sets, true)
	if dumps != 3 || !errors.Is(err, unix.ENOENT) || status == nil || status.State != FallbackNotHolding {
		t.Fatalf("the pass reports %+v (%v) after %d dumps of the tables, want not holding with %v after 3", status, err, dumps, unix.ENOENT)
	}
	if status, err := reconciler.applyFallback(sets, true); err != nil || status == nil || status.State != FallbackHolding {
		t.Errorf("the next pass reports %+v (%v), want holding", status, err)
	}
}

// The table deleted after the write and before the readback's dump of the
// tables fails the pass with ENOENT, so the retry follows it, and the next
// pass writes the switch
func TestNetlinkFallbackFailsThePassWhoseReadbackDumpsNoTable(t *testing.T) {
	plat, reconciler, sets, write := switchUnderAnotherWriter(t)
	dumps := 0
	reconciler.sw = tablesSwitch{netlinkPlatform: plat, dump: func(conn *nftables.Conn) (map[uint8]uint32, error) {
		// the readback's dump
		if dumps++; dumps == 2 {
			write(nftables.DeleteTable(unix.NFPROTO_INET, nftables.Table))
		}
		return nftables.Tables(conn, nftables.Table)
	}}
	status, err := reconciler.applyFallback(sets, true)
	if dumps != 2 || !errors.Is(err, unix.ENOENT) || status == nil || status.State != FallbackNotHolding {
		t.Fatalf("the pass reports %+v (%v) after %d dumps of the tables, want not holding with %v after 2", status, err, dumps, unix.ENOENT)
	}
	if status, err := reconciler.applyFallback(sets, true); err != nil || status == nil || status.State != FallbackHolding {
		t.Errorf("the next pass reports %+v (%v), want holding", status, err)
	}
}

// Each dump of the switch's read past its dump of the tables fails on a table
// deleted after that dump in a way the read takes for the table gone: the
// switch's chains and sets, the leftovers and a line's anonymous set
func TestNetlinkFallbackReadsEachDumpOfADeletedTableAsGone(t *testing.T) {
	plat, _, sets := holdingSwitch(t)
	conn, err := plat.watchFallback()
	if err != nil {
		t.Fatal(err)
	}
	for name, dump := range map[string]func(tables map[uint8]uint32, held []nftables.Installed) error{
		"the switch's chains and sets": func(tables map[uint8]uint32, _ []nftables.Installed) error {
			_, err := readFallback(conn, sets, tables)
			return err
		},
		"the leftovers": func(tables map[uint8]uint32, _ []nftables.Installed) error {
			_, err := nftables.Leftovers(conn, tables, fallbackRetired, fallbackScope)
			return err
		},
		"a line's anonymous set": func(_ map[uint8]uint32, held []nftables.Installed) error {
			_, err := chainFault(conn, sets, 0, held)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := plat.writeFallback(sets, false); err != nil {
				t.Fatal(err)
			}
			tables, err := nftables.Tables(conn, nftables.Table)
			if err != nil {
				t.Fatal(err)
			}
			read, err := readFallback(conn, sets, tables)
			if err != nil || !slices.ContainsFunc(read.Rules, func(rule nftables.Installed) bool { return rule.Chain == fallbackChain.Name }) {
				t.Fatalf("the written switch reads back as %+v (%v)", read, err)
			}
			if err := conn.Batch([]nftables.Request{nftables.DeleteTable(unix.NFPROTO_INET, nftables.Table)}); err != nil {
				t.Fatal(err)
			}
			first := true
			out, _, err := readOrGone(func() (map[uint8]uint32, error) {
				if first {
					return tables, nil
				}
				return nftables.Tables(conn, nftables.Table)
			}, func(now map[uint8]uint32) (fallbackRead, bool, error) {
				if first {
					first = false
					err := dump(now, read.Rules)
					if !errors.Is(err, unix.ENOENT) {
						t.Errorf("the dump over the deleted table failed with %v, want %v", err, unix.ENOENT)
					}
					return fallbackRead{}, false, err
				}
				return faultOver(connReads(conn, sets), now)
			}, true)
			if out.fault != "its chains are missing" || err != nil {
				t.Errorf("the read reports %q (%v), want the fault of a table never there", out.fault, err)
			}
		})
	}
}
