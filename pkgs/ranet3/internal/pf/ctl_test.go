// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package pf

import (
	"errors"
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
