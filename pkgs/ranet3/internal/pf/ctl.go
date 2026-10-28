// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package pf

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// Runner runs pfctl with args and stdin and returns what it wrote to stdout
type Runner func(stdin string, args ...string) (string, error)

// Ctl issues every pfctl command this tree runs. Its only writes are a load
// and a withdrawal of one child anchor of com.apple, and the release of a
// reference by its token: never a flush without -a, never -F all, whose
// states, info, Sources and osfp parts are global, and never -d, -e or -E,
// which stop or start pf for every holder.
type Ctl struct{ run Runner }

// NewCtl runs /sbin/pfctl
func NewCtl() Ctl {
	return Ctl{run: command(pfctlPath)}
}

// command runs the program at path, its error carrying what it wrote to
// stderr less the notice pfctl writes on every call
func command(path string) Runner {
	return func(stdin string, args ...string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), pfctlTimeout)
		defer cancel()
		cmd := exec.CommandContext(ctx, path, args...)
		cmd.Stdin = strings.NewReader(stdin)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		if err := cmd.Run(); err != nil {
			var said []string
			for line := range strings.SplitSeq(stderr.String(), "\n") {
				line = strings.TrimSpace(line)
				if line != "" && line != "No ALTQ support in kernel" && line != "ALTQ related functions disabled" {
					said = append(said, line)
				}
			}
			return stdout.String(), fmt.Errorf("pf: pfctl %s: %w: %s", strings.Join(args, " "), err, strings.Join(said, " "))
		}
		return stdout.String(), nil
	}
}

// checkAnchor holds a write to one child of com.apple, which the stock main
// ruleset calls, never com.apple itself, a wildcard or the main ruleset
func checkAnchor(anchor string) error {
	name, ok := strings.CutPrefix(anchor, "com.apple/")
	// PF_ANCHOR_NAME_SIZE less its terminator, bsd/net/pfvar.h
	if !ok || name == "" || len(name) > 63 {
		return fmt.Errorf("pf: anchor %q is not one child of com.apple", anchor)
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return fmt.Errorf("pf: anchor %q holds %q", anchor, c)
		}
	}
	return nil
}

// Load replaces everything anchor holds with rs in one transaction, which
// leaves the anchor as it was when pfctl refuses the text. Each rule's label is
// unique within the anchor, and pf.conf(5) names a label an optimization
// barrier, so the optimizer pfctl runs by default leaves the rules as rendered.
func (c Ctl) Load(anchor string, rs Ruleset) error {
	if err := checkAnchor(anchor); err != nil {
		return err
	}
	text, err := rs.Render()
	if err != nil {
		return err
	}
	_, err = c.run(text, "-a", anchor, "-f", "-")
	return err
}

// LoadTables replaces the contents of anchor's tables that tables names in one
// transaction and leaves its rules and their counters. A table of anchor that
// tables leaves out keeps what it held.
func (c Ctl) LoadTables(anchor string, tables []Table) error {
	if err := checkAnchor(anchor); err != nil {
		return err
	}
	var b strings.Builder
	named := make(map[string]bool, len(tables))
	for _, t := range tables {
		if err := t.check(); err != nil {
			return err
		}
		if named[t.Name] {
			return fmt.Errorf("pf: table <%s> is defined twice", t.Name)
		}
		named[t.Name] = true
		b.WriteString(t.String() + "\n")
	}
	_, err := c.run(b.String(), "-a", anchor, "-T", "load", "-f", "-")
	return err
}

// Withdraw flushes anchor's rules and then its tables, and nothing outside it
func (c Ctl) Withdraw(anchor string) error {
	if err := checkAnchor(anchor); err != nil {
		return err
	}
	_, rules := c.run("", "-a", anchor, "-F", "rules")
	_, tables := c.run("", "-a", anchor, "-F", "Tables")
	return errors.Join(rules, tables)
}

// Release gives back the reference token names, which stops pf only when it
// was the last
func (c Ctl) Release(token uint64) error {
	_, err := c.run("", "-X", strconv.FormatUint(token, 10))
	return err
}

// ErrUnreadable marks a readback that pfctl printed and the parsers cannot
// read, a rule or table entry of a form this tree never writes, which another
// program loaded into the anchor
var ErrUnreadable = errors.New("pf: a readback the parsers cannot read")

// Read reads anchor's rules with their counters and its tables with their
// prefixes. A readback the parsers cannot read is ErrUnreadable, apart from a
// pfctl run that failed.
func (c Ctl) Read(anchor string) (Readback, error) {
	if err := checkAnchor(anchor); err != nil {
		return Readback{}, err
	}
	out, err := c.run("", "-a", anchor, "-sr", "-vv")
	if err != nil {
		return Readback{}, err
	}
	rules, err := ParseRules(out)
	if err != nil {
		return Readback{}, fmt.Errorf("%w: %w", ErrUnreadable, err)
	}
	if out, err = c.run("", "-a", anchor, "-s", "Tables", "-vv"); err != nil {
		return Readback{}, err
	}
	tables, err := ParseTables(out)
	if err != nil {
		return Readback{}, fmt.Errorf("%w: %w", ErrUnreadable, err)
	}
	for i := range tables {
		if out, err = c.run("", "-a", anchor, "-t", tables[i].Name, "-T", "show"); err != nil {
			return Readback{}, err
		}
		if tables[i].Prefixes, err = ParseTableShow(out); err != nil {
			return Readback{}, fmt.Errorf("%w: %w", ErrUnreadable, err)
		}
	}
	return Readback{Rules: rules, Tables: tables}, nil
}

// Calls reports whether the main ruleset calls com.apple's children for
// filtering every packet in, without which pf evaluates no rule of theirs for
// some
func (c Ctl) Calls() (bool, error) {
	out, err := c.run("", "-sr")
	if err != nil {
		return false, err
	}
	return ParseCalls(out, "com.apple/*"), nil
}

// Skipped lists the interfaces pf skips, as a set skip loaded with the main
// ruleset asks, so that pf evaluates no rule for a packet on them
func (c Ctl) Skipped() ([]string, error) {
	out, err := c.run("", "-s", "Interfaces", "-v")
	if err != nil {
		return nil, err
	}
	return ParseSkipped(out), nil
}

// Running reports whether pf is enabled, as pfctl -s info's status says
func (c Ctl) Running() (bool, error) {
	out, err := c.run("", "-s", "info")
	if err != nil {
		return false, err
	}
	return ParseRunning(out)
}

// References lists every reference held on pf, by the process that took it
func (c Ctl) References() ([]Enabler, error) {
	out, err := c.run("", "-s", "References")
	if err != nil {
		return nil, err
	}
	return ParseReferences(out)
}
