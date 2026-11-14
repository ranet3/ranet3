// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package pf

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// a table load sends every table it names, an empty one as an empty
// definition, so none keeps entries a set no longer holds, and refuses a
// table pf would not hold as written before pfctl runs
func TestTableLoadWritesEveryTableItNames(t *testing.T) {
	var stdin string
	var args []string
	c := Ctl{run: func(in string, a ...string) (string, error) {
		stdin, args = in, a
		return "", nil
	}}
	err := c.LoadTables("com.apple/ranet3", []Table{
		{Name: "ranet3_carved", Const: true},
		{Name: "ranet3_overlay", Const: true, Prefixes: []netip.Prefix{netip.MustParsePrefix("3fff:10::/32"), netip.MustParsePrefix("192.0.2.0/24")}},
	})
	if want := "table <ranet3_carved> const { }\ntable <ranet3_overlay> const { 192.0.2.0/24, 3fff:10::/32 }\n"; err != nil || stdin != want {
		t.Errorf("the load sent %q (%v), want %q", stdin, err, want)
	}
	if want := []string{"-a", "com.apple/ranet3", "-T", "load", "-f", "-"}; !slices.Equal(args, want) {
		t.Errorf("the load ran pfctl %q, want %q", args, want)
	}
	args = nil
	if err := c.LoadTables("com.apple/ranet3", []Table{{Name: "ranet3_carved", Prefixes: []netip.Prefix{netip.MustParsePrefix("fe80:1:2::/48")}}}); err == nil || args != nil {
		t.Errorf("a table pf would hold otherwise loaded: %v, ran %q", err, args)
	}
}

// tableListing is tables as pfctl -s Tables -vv prints them under -a anchor, as
// the goldens under testdata show: 6 flags, a tab, the name as it is, a tab
// and the anchor, then counter lines opening with a tab, Addresses and
// Cleared first
func tableListing(anchor string, tables ...Table) string {
	var b strings.Builder
	for _, table := range tables {
		flags := "-pa---"
		if table.Const {
			flags = "c-a-r-"
		}
		fmt.Fprintf(&b, "%s\t%s\t%s\n\tAddresses:   %d\n\tCleared:     Wed Oct 28 15:51:10 2026\n", flags, table.Name, anchor, len(table.Prefixes))
		b.WriteString("\tReferences:  [ Anchors: 0                  Rules: 1                  ]\n")
	}
	return b.String()
}

// overlayOnly is an anchor of one table, ranet3_overlay, and the rule that
// reads it
func overlayOnly() Ruleset {
	return Ruleset{
		Tables: []Table{{Name: "ranet3_overlay", Const: true, Prefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}}},
		Rules:  []Rule{{Action: Pass, Quick: true, Interface: "lo0", From: Address{Table: "ranet3_overlay"}, Label: "accept via lo0"}},
	}
}

// a load, once pfctl took the text, removes by its whole name under -a each
// table of the anchor it does not define, which the load's transaction
// leaves, one whose name a defined table's opens among them, and no table it
// defines
func TestLoadRemovesEachTableItDoesNotDefine(t *testing.T) {
	var calls []string
	c := Ctl{run: func(_ string, args ...string) (string, error) {
		calls = append(calls, strings.Join(args, " "))
		if slices.Equal(args, []string{"-a", "com.apple/ranet3", "-s", "Tables", "-vv"}) {
			return tableListing("com.apple/ranet3", Table{Name: "ranet3_overlay", Const: true}, Table{Name: "stray"}, Table{Name: "ranet3_overlay2"}), nil
		}
		return "", nil
	}}
	if err := c.Load("com.apple/ranet3", overlayOnly()); err != nil {
		t.Fatal(err)
	}
	want := []string{"-a com.apple/ranet3 -f -", "-a com.apple/ranet3 -s Tables -vv", "-a com.apple/ranet3 -t stray -T kill", "-a com.apple/ranet3 -t ranet3_overlay2 -T kill"}
	if !slices.Equal(calls, want) {
		t.Errorf("the load ran pfctl %q, want %q", calls, want)
	}
}

// a load pfctl refuses lists no table and removes none, so the anchor stays
// as it was
func TestRefusedLoadRemovesNoTable(t *testing.T) {
	var calls []string
	c := Ctl{run: func(_ string, args ...string) (string, error) {
		calls = append(calls, strings.Join(args, " "))
		if slices.Contains(args, "-f") {
			return "", errors.New("pf: pfctl -a com.apple/ranet3 -f -: exit status 1: pfctl: Syntax error in config file")
		}
		return tableListing("com.apple/ranet3", Table{Name: "stray"}), nil
	}}
	if err := c.Load("com.apple/ranet3", overlayOnly()); err == nil || !slices.Equal(calls, []string{"-a com.apple/ranet3 -f -"}) {
		t.Errorf("a refused load returned %v and ran pfctl %q", err, calls)
	}
}

// heldTables answers pfctl for one anchor as pf_table.c and pfctl's
// print_table do: -s Tables -vv lists each table under its name as pf holds
// it, -T show of a name pf does not hold fails, and -T kill removes the table
// of exactly the name given, where pf holds one
type heldTables struct {
	anchor string
	held   []Table
	kills  []string
}

func (h *heldTables) run(_ string, args ...string) (string, error) {
	if slices.Equal(args, []string{"-a", h.anchor, "-s", "Tables", "-vv"}) {
		return tableListing(h.anchor, h.held...), nil
	}
	if len(args) != 6 || args[0] != "-a" || args[1] != h.anchor || args[2] != "-t" || args[4] != "-T" {
		return "", nil
	}
	i := slices.IndexFunc(h.held, func(t Table) bool { return t.Name == args[3] })
	switch args[5] {
	case "show":
		if i < 0 {
			return "", errors.New("pf: pfctl -T show: exit status 1: pfctl: Table does not exist.")
		}
		return "   192.0.2.1\n", nil
	case "kill":
		h.kills = append(h.kills, args[3])
		if i >= 0 {
			h.held = slices.Delete(h.held, i, i+1)
		}
	}
	return "", nil
}

// a table of any name pf takes, 1 to 31 bytes but NUL, reads back under its
// whole name and a load removes it under that name alone, in the daemon's
// anchor and in one of the shortest name: a name opening with a dash, one
// holding a space, a tab or a newline anywhere, one that holds a line like a
// table's, and those holding the anchor and as much of the Addresses line
// that follow every name as 31 bytes leave room for
func TestTableOfAnyNameReadsBackWholeAndALoadRemovesIt(t *testing.T) {
	for _, anchor := range []string{"com.apple/ranet3", "com.apple/r"} {
		for _, name := range []string{
			"stray", "-F", "a b", "x\ty", "\tx", "x\t", "x\ny", "x\n", "\nx", "x\n-pa---\ty", "a\t" + anchor + "\n-pa---\tb",
			"\t" + anchor + "\n\tAddresses:  ", "x\t" + anchor + "\n\tAddresses:   1", "\t" + anchor + "\n\tAddresses:   1\n\t",
		} {
			if len(name) > 31 {
				continue
			}
			tableOfAnyName(t, anchor, name)
		}
	}
}

// tableOfAnyName reads back an anchor holding the table name beside
// ranet3_overlay, loads it with ranet3_overlay alone and reads it back again
func tableOfAnyName(t *testing.T, anchor, name string) {
	t.Helper()
	h := &heldTables{anchor: anchor, held: []Table{{Name: "ranet3_overlay", Const: true}, {Name: name}}}
	c := Ctl{run: h.run}
	read, err := c.Read(anchor)
	if err != nil || len(read.Tables) != 2 || read.Tables[1].Name != name {
		t.Errorf("in %s a table named %q reads back as %+v (%v)", anchor, name, read.Tables, err)
	}
	if err := c.Load(anchor, overlayOnly()); err != nil || !slices.Equal(h.kills, []string{name}) {
		t.Errorf("in %s the load over a table named %q returned %v and removed %q", anchor, name, err, h.kills)
	}
	if read, err := c.Read(anchor); err != nil || len(read.Tables) != 1 || read.Tables[0].Name != "ranet3_overlay" {
		t.Errorf("in %s after the load over a table named %q the anchor reads %+v (%v)", anchor, name, read.Tables, err)
	}
}

// a listing pfctl -s Tables -vv never prints under -a anchor is
// ErrUnreadable: a table line with no counters after it, counters with no
// Cleared line or no count of addresses, flags that are not 6 and a line
// holding no tab
func TestTableListingNotAsPfctlPrintsItIsUnreadable(t *testing.T) {
	const anchor = "com.apple/ranet3"
	good := tableListing(anchor, Table{Name: "stray"})
	for _, printed := range []string{
		"c-a-r-\tranet3_overlay\t" + anchor + "\n" + good,
		"c-a-r-\tranet3_overlay\t" + anchor + "\n\tAddresses:   1\n" + good,
		"c-a-r-\tranet3_overlay\t" + anchor + "\n\tAddresses:   \n\tCleared:     Wed Oct 28 15:51:10 2026\n",
		"c-a-r\tranet3_overlay\t" + anchor + "\n\tAddresses:   1\n\tCleared:     Wed Oct 28 15:51:10 2026\n",
		"ranet3_overlay\n",
	} {
		c := Ctl{run: func(_ string, args ...string) (string, error) {
			if slices.Equal(args, []string{"-a", anchor, "-s", "Tables", "-vv"}) {
				return printed, nil
			}
			return "", nil
		}}
		if read, err := c.Read(anchor); !errors.Is(err, ErrUnreadable) {
			t.Errorf("the listing %q reads back as %+v (%v), want ErrUnreadable", printed, read.Tables, err)
		}
	}
}

// a readback holding a rule the parser cannot read, a stateful pass as pfctl
// prints one, is ErrUnreadable, while a pfctl run that fails is not
func TestReadbackTheParserCannotReadIsUnreadable(t *testing.T) {
	printed := "@0 pass in quick on en0 all flags S/SA keep state\n"
	failing := false
	c := Ctl{run: func(_ string, args ...string) (string, error) {
		switch {
		case failing:
			return "", errors.New("pf: pfctl -sr -vv: exit status 1")
		case slices.Contains(args, "-sr"):
			return printed, nil
		}
		return "", nil
	}}
	if _, err := c.Read("com.apple/ranet3"); !errors.Is(err, ErrUnreadable) || !strings.Contains(err.Error(), "pass in quick on en0 all flags S/SA keep state") {
		t.Errorf("a stateful pass reads back as %v, want ErrUnreadable naming it", err)
	}
	failing = true
	if _, err := c.Read("com.apple/ranet3"); err == nil || errors.Is(err, ErrUnreadable) {
		t.Errorf("a failed pfctl run reads back as %v, want an error of its own", err)
	}
}

// a rule of a ruleset the filter never writes, which pfctl -sr leaves out, is
// ErrUnreadable naming it: a nat, a binat and an rdr rule as pfctl -s nat
// prints them and a dummynet rule as pfctl -s dummynet does
func TestRuleOfARulesetTheFilterNeverWritesIsUnreadable(t *testing.T) {
	for _, printed := range []struct{ kind, line string }{
		{"nat", "nat on utun250 inet from 192.0.2.0/24 to any -> 198.51.100.1"},
		{"nat", "binat on utun250 inet from 192.0.2.1 to any -> 198.51.100.1"},
		{"nat", "rdr pass on utun250 inet from 192.0.2.0/24 to any -> 192.0.2.1"},
		{"dummynet", "dummynet in on utun250 inet from 192.0.2.0/24 to any pipe 1"},
	} {
		c := Ctl{run: func(_ string, args ...string) (string, error) {
			if slices.Equal(args, []string{"-a", "com.apple/ranet3", "-s", printed.kind}) {
				return "\n" + printed.line + "\n", nil
			}
			return "", nil
		}}
		if _, err := c.Read("com.apple/ranet3"); !errors.Is(err, ErrUnreadable) || !strings.Contains(err.Error(), printed.line) {
			t.Errorf("%q printed by pfctl -s %s reads back as %v, want ErrUnreadable naming it", printed.line, printed.kind, err)
		}
	}
}

// an anchor whose translation or dummynet ruleset prints nothing, a blank
// line or a line of whitespace reads back with no fault, each ruleset alone
func TestEmptyRulesetTheFilterNeverWritesIsNoFault(t *testing.T) {
	for _, kind := range unwritten {
		for _, printed := range []string{"", "\n", " \t \n"} {
			c := Ctl{run: func(_ string, args ...string) (string, error) {
				if slices.Equal(args, []string{"-a", "com.apple/ranet3", "-s", kind}) {
					return printed, nil
				}
				return "", nil
			}}
			if got, err := c.Read("com.apple/ranet3"); err != nil || len(got.Rules) != 0 || len(got.Tables) != 0 {
				t.Errorf("pfctl -s %s printing %q reads back as %+v (%v), want an empty anchor", kind, printed, got, err)
			}
		}
	}
}

// a withdrawal flushes the anchor's filter, translation and dummynet rules and
// its tables, each under -a, tries every flush whatever the others returned,
// and returns every failure
func TestWithdrawalFlushesEveryRulesetAndGoesOnPastAFailure(t *testing.T) {
	var flushed []string
	c := Ctl{run: func(_ string, args ...string) (string, error) {
		if len(args) != 4 || args[0] != "-a" || args[1] != "com.apple/ranet3" || args[2] != "-F" {
			t.Errorf("the withdrawal ran pfctl %q", args)
			return "", nil
		}
		flushed = append(flushed, args[3])
		if args[3] == "rules" || args[3] == "dummynet" {
			return "", errors.New("pf: pfctl -F " + args[3] + ": exit status 1")
		}
		return "", nil
	}}
	err := c.Withdraw("com.apple/ranet3")
	if want := []string{"Tables", "dummynet", "nat", "rules"}; !slices.Equal(slices.Sorted(slices.Values(flushed)), want) {
		t.Errorf("the withdrawal flushed %q, want %q", flushed, want)
	}
	if err == nil || !strings.Contains(err.Error(), "-F rules") || !strings.Contains(err.Error(), "-F dummynet") {
		t.Errorf("the withdrawal returned %v, want both failures", err)
	}
}

// the reads of a steady pass start 1 pfctl process each for the references,
// the main ruleset's call and the skipped interfaces, and 4 for the anchor's
// readback and 1 more for each of its tables
func TestReadsOfASteadyPassStartSevenPfctlAndOnePerTable(t *testing.T) {
	overlay, carved := Table{Name: "ranet3_overlay", Const: true}, Table{Name: "ranet3_carved", Const: true}
	listings := []string{"", tableListing("com.apple/ranet3", overlay), tableListing("com.apple/ranet3", overlay, carved)}
	for tables, listing := range listings {
		started := 0
		c := Ctl{run: func(_ string, args ...string) (string, error) {
			started++
			if slices.Equal(args, []string{"-a", "com.apple/ranet3", "-s", "Tables", "-vv"}) {
				return listing, nil
			}
			return "", nil
		}}
		for _, read := range []func() error{
			func() error { _, err := c.References(); return err },
			func() error { _, err := c.Calls(); return err },
			func() error { _, err := c.Skipped(); return err },
		} {
			if err := read(); err != nil {
				t.Fatal(err)
			}
		}
		if started != 3 {
			t.Errorf("the references, the call and the skipped interfaces started %d pfctl processes, want 3", started)
		}
		if _, err := c.Read("com.apple/ranet3"); err != nil {
			t.Fatal(err)
		}
		if want := 7 + tables; started != want {
			t.Errorf("a steady pass's reads over %d tables started %d pfctl processes, want %d", tables, started, want)
		}
	}
}

// beside a steady pass's reads, the read of whether pf runs and a table load
// start 1 pfctl process each, and a load 2, the load and the listing of the
// anchor's tables, and 1 more for each table it does not define
func TestOtherCallsOfAPassStartTheirPfctlProcesses(t *testing.T) {
	for strays := range 3 {
		held := []Table{{Name: "ranet3_overlay", Const: true}}
		for i := range strays {
			held = append(held, Table{Name: fmt.Sprintf("stray%d", i)})
		}
		started := 0
		c := Ctl{run: func(_ string, args ...string) (string, error) {
			started++
			switch {
			case slices.Equal(args, []string{"-s", "info"}):
				return golden(t, "info-disabled.txt"), nil
			case slices.Equal(args, []string{"-a", "com.apple/ranet3", "-s", "Tables", "-vv"}):
				return tableListing("com.apple/ranet3", held...), nil
			}
			return "", nil
		}}
		for _, call := range []struct {
			name string
			do   func() error
			want int
		}{
			{"the read of whether pf runs", func() error { _, err := c.Running(); return err }, 1},
			{"the table load", func() error { return c.LoadTables("com.apple/ranet3", overlayOnly().Tables) }, 1},
			{"the load", func() error { return c.Load("com.apple/ranet3", overlayOnly()) }, 2 + strays},
		} {
			started = 0
			if err := call.do(); err != nil || started != call.want {
				t.Errorf("over %d tables the load does not define, %s started %d pfctl processes (%v), want %d", strays, call.name, started, err, call.want)
			}
		}
	}
}

// the skipped interfaces are read from pfctl's listing of every interface
func TestSkipIsReadFromTheInterfacesListing(t *testing.T) {
	var args []string
	c := Ctl{run: func(_ string, a ...string) (string, error) {
		args = a
		return "lo0 (skip)\nen0\nutun7 (skip)\n", nil
	}}
	if skipped, err := c.Skipped(); err != nil || !slices.Equal(skipped, []string{"lo0", "utun7"}) {
		t.Errorf("the listing reads skipped %q (%v)", skipped, err)
	}
	if want := []string{"-s", "Interfaces", "-v"}; !slices.Equal(args, want) {
		t.Errorf("the read ran pfctl %q, want %q", args, want)
	}
}

// whether pf runs is read from pfctl's status alone, and a status pfctl
// printed otherwise is an error
func TestRunningIsReadFromPfctlsStatus(t *testing.T) {
	var args []string
	printed := golden(t, "info-disabled.txt")
	c := Ctl{run: func(_ string, a ...string) (string, error) {
		args = a
		return printed, nil
	}}
	if running, err := c.Running(); err != nil || running {
		t.Errorf("a disabled pf reads running %v (%v)", running, err)
	}
	if want := []string{"-s", "info"}; !slices.Equal(args, want) {
		t.Errorf("the read ran pfctl %q, want %q", args, want)
	}
	printed = "Status: Stopping\n"
	if _, err := c.Running(); err == nil {
		t.Error("a status neither enabled nor disabled reads as one")
	}
}

// a pfctl call that fails reports what pfctl wrote to stderr, less the notice
// it writes on every call, and a call reads its stdin
func TestRunnerErrorCarriesPfctlsOutput(t *testing.T) {
	run := command("/bin/sh")
	_, err := run("", "-c", `printf 'No ALTQ support in kernel\nALTQ related functions disabled\npfctl: pf: token invalid\n' >&2; exit 1`)
	if err == nil || !strings.HasSuffix(err.Error(), "exit status 1: pfctl: pf: token invalid") {
		t.Errorf("a failed call reports %v", err)
	}
	if out, err := run("printf loaded", "-s"); err != nil || out != "loaded" {
		t.Errorf("a call fed its stdin wrote %q (%v)", out, err)
	}
}

// a pfctl call that succeeds returns what it wrote to stdout alone, so the
// notice pfctl writes to stderr on every call reaches no readback
func TestRunnerReturnsStdoutAloneOnSuccess(t *testing.T) {
	out, err := command("/bin/sh")("", "-c", `printf 'No ALTQ support in kernel\nALTQ related functions disabled\n' >&2; printf 'rules'`)
	if err != nil || out != "rules" {
		t.Errorf("a call that succeeded returned %q (%v), want its stdout alone", out, err)
	}
}
