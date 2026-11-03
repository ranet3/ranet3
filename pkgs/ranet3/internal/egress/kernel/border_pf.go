// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/events"
	meshkernel "ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/pf"
)

// pfControl is the part of pf.Ctl the backend drives
type pfControl interface {
	Load(anchor string, rs pf.Ruleset) error
	LoadTables(anchor string, tables []pf.Table) error
	Withdraw(anchor string) error
	Read(anchor string) (pf.Readback, error)
	Calls() (bool, error)
	Skipped() ([]string, error)
	References() ([]pf.Enabler, error)
	Running() (bool, error)
}

// pfReference is the part of *pf.Reference the backend drives
type pfReference interface {
	Token() uint64
	PID() int
	Inherited() bool
	Renew() error
	Release() error
	Close() error
}

// borderPF is the antispoof filter's backend on pf: one anchor under
// com.apple that the stock main ruleset calls, the filter's rules and tables in
// it, and a reference on pf that keeps pf enabled while the filter runs. pf
// posts no event of another writer's change, so Changed and Missed never fire
// and the pass reads the anchor back on every sweep. inside is the devices
// inside the mesh, the tun and the loopback link.
type borderPF struct {
	ctl    pfControl
	ref    pfReference
	anchor string
	tun    string
	inside []string
	events *events.Bus
	// every is the sweep, zero for the default
	every time.Duration
}

func (b *borderPF) Changed() <-chan struct{} { return nil }

func (b *borderPF) Missed() <-chan struct{} { return nil }

// Close leaves the anchor and gives the reference back, so a start refused
// after it took one leaves pf as it found it, unless the take found an
// earlier run's reference that pf still listed: the new one then keeps pf
// enabled in its place, recorded for the next start. After Withdraw it has
// nothing left to give back.
func (b *borderPF) Close() error {
	if b.ref.Inherited() {
		return b.ref.Close()
	}
	return b.ref.Release()
}

// Leave keeps the anchor and the reference in place, so pf keeps evaluating
// the anchor until the next start takes both over
func (b *borderPF) Leave() error { return b.ref.Close() }

func (b *borderPF) where(*egress.Border) string { return "pf anchor " + b.anchor }

// writes the antispoof chain's rules, each a rule of the anchor, but the tun's
// inside rule, which each drop folds in as on ! <tun>, since pf filters every
// packet in at the one point and a drop that names every interface but the
// tun leaves the tun's packets to whatever follows, as the accept does on
// Linux. It writes no rule of the entry chain: darwin runs no exit, and the
// tun read drops a packet from a source this node does not own.
func (b *borderPF) writes(rule BorderRule) bool {
	return rule.Chain() == BorderChain && (rule.Class != BorderInside || rule.Device != b.tun)
}

// holds the carved sets alone, in one table, since only the carved drops read
// a set
func (b *borderPF) holds(set string) bool { return set == carvedSet }

func (b *borderPF) sweep() time.Duration { return b.every }

// wildcards is false, since pf matches an interface by its exact name, with no
// wildcard (pfi_kif_match, bsd_net_pf_if.c:224-231)
func (b *borderPF) wildcards() bool { return false }

// chain heads the antispoof chain by the direction its rules match, since
// every rule of an anchor runs at the one point pf filters, in the order the
// anchor holds
func (b *borderPF) chain(name string) egress.BorderChainReading {
	return egress.BorderChainReading{Name: name, Hook: "in"}
}

// readings is the carved sets as the one table holding both families
func (b *borderPF) readings(sets borderSets) []egress.BorderSetReading {
	return []egress.BorderSetReading{{Kind: "table", Name: pfCarvedTable, Elements: carvedRanges(sets)}}
}

// Rules reads what pf holds for the filter beside the anchor, taking this
// daemon's reference again where pf no longer lists it, then reads the anchor
// back against rules and sets. The renewal comes first, so a pass that fails
// on the anchor still turns pf back on. An anchor holding what the parsers
// cannot read is a fault, which the pass rewrites whole like any other.
func (b *borderPF) Rules(rules []BorderRule, sets borderSets) (chainReadback, error) {
	state, unready, err := b.hold()
	if err != nil {
		return chainReadback{}, err
	}
	want, err := pfRuleset(b.tun, rules, sets)
	if err != nil {
		return chainReadback{}, err
	}
	var out chainReadback
	switch read, err := b.ctl.Read(b.anchor); {
	case errors.Is(err, pf.ErrUnreadable):
		out = chainReadback{held: true, fault: "its anchor holds what the filter does not write: " + err.Error()}
	case err != nil:
		return chainReadback{}, err
	default:
		out = pfReadback(read, rules)
		out.fault = anchorFault(read.Ruleset(), want)
	}
	out.pf, out.unready = state, unready
	return out, nil
}

// Read reads the anchor and the references pf lists, and renews nothing,
// since a renewal is a write the run goroutine's pass alone makes
func (b *borderPF) Read(rules []BorderRule) (chainReadback, error) {
	read, err := b.ctl.Read(b.anchor)
	if err != nil {
		return chainReadback{}, err
	}
	out := pfReadback(read, rules)
	enablers, err := b.ctl.References()
	if err != nil {
		return out, err
	}
	out.pf = &egress.BorderPF{Anchor: b.anchor, Enablers: enablers}
	return out, nil
}

// Apply loads the anchor whole in one transaction, which leaves it as it was
// where pfctl refuses the text
func (b *borderPF) Apply(rules []BorderRule, sets borderSets) error {
	rs, err := pfRuleset(b.tun, rules, sets)
	if err != nil {
		return err
	}
	return b.ctl.Load(b.anchor, rs)
}

// Fill loads the tables rules read alone in one transaction, which leaves the
// anchor's rules and their counters. A set sets does not name keeps what was
// gives it.
func (b *borderPF) Fill(rules []BorderRule, was, sets borderSets) error {
	moved := maps.Clone(was)
	maps.Copy(moved, sets)
	return b.ctl.LoadTables(b.anchor, pfTables(rules, moved))
}

// Withdraw empties the anchor, then gives the reference back, which stops pf
// where no other holder keeps it. An anchor holding what the parsers cannot
// read holds something, which the flush removes as any other.
func (b *borderPF) Withdraw() (bool, error) {
	read, err := b.ctl.Read(b.anchor)
	unreadable := errors.Is(err, pf.ErrUnreadable)
	if err != nil && !unreadable {
		return false, err
	}
	if err := b.ctl.Withdraw(b.anchor); err != nil {
		return false, err
	}
	return unreadable || len(read.Rules) != 0 || len(read.Tables) != 0, b.ref.Release()
}

// hold reads what pf holds for the filter beside the anchor, in order:
//  1. Whether pf lists this daemon's reference under its pid. Where it does
//     not, whether pf runs, then a new reference, taken whatever that read
//     gave.
//  2. Whether the main ruleset calls com.apple's children for every packet
//     in.
//  3. Whether pf skips an interface outside the mesh.
//
// Any one of them failing leaves the anchor unevaluated for some packets in,
// its rules read back as written.
func (b *borderPF) hold() (*egress.BorderPF, string, error) {
	enablers, err := b.ctl.References()
	if err != nil {
		return nil, "", err
	}
	var unready []string
	listed := slices.ContainsFunc(enablers, func(e pf.Enabler) bool { return e.Token == b.ref.Token() && e.PID == b.ref.PID() })
	if !listed {
		// pfctl -d ends every reference and stops pf, and another program's
		// pfctl -X ends this one, which stops pf where no other holder keeps
		// it, so whether pf ran is read before the renewal turns it back on.
		// That read shapes the log alone, so the renewal does not wait on it.
		running, readErr := b.ctl.Running()
		if err := b.ref.Renew(); err != nil {
			unready = append(unready, "pf no longer lists this daemon's reference, so pf may not run, and taking one again failed: "+err.Error())
		} else {
			listed = true
			b.renewed(running, readErr)
		}
	}
	called, err := b.ctl.Calls()
	if err != nil {
		return nil, "", err
	}
	if !called {
		unready = append(unready, `pf's main ruleset calls neither anchor "com.apple/*" all nor anchor "com.apple/*" in all at its own depth, so pf may evaluate no rule of `+b.anchor+
			` for a packet in: a call that names out, an interface, a family, a protocol or an address leaves packets out of it, one inside an inline anchor's braces resolves relative to that anchor, `+
			`pfctl -f /etc/pf.conf loads the stock ruleset again, and a ruleset loaded in its place needs that line`)
	}
	skipped, err := b.ctl.Skipped()
	if err != nil {
		return nil, "", err
	}
	if outside := slices.DeleteFunc(skipped, func(name string) bool { return slices.Contains(b.inside, name) }); len(outside) != 0 {
		unready = append(unready, "pf skips "+strings.Join(outside, ", ")+", as a set skip loaded with the main ruleset asks, so pf evaluates no rule for a packet arriving there "+
			"and a forged overlay source passes: pfctl -f /etc/pf.conf loads the stock ruleset again, which skips no interface")
	}
	state := &egress.BorderPF{Anchor: b.anchor, Token: b.ref.Token(), PID: b.ref.PID(), Listed: listed, Called: called}
	return state, strings.Join(unready, ", and "), nil
}

// renewed logs and records a renewal, whose event leaves pf_off out where the
// read of whether pf ran failed
func (b *borderPF) renewed(running bool, readErr error) {
	attrs := []slog.Attr{slog.Uint64("token", b.ref.Token()), slog.Int("pid", b.ref.PID())}
	var state string
	switch {
	case readErr != nil:
		state = "whether pf was off could not be read"
	case running:
		state = "pf was not off, as another holder kept it running"
		attrs = append(attrs, slog.Bool("pf_off", false))
	default:
		state = "pf was off, and this daemon turned it back on, so the host's protection was off until now"
		attrs = append(attrs, slog.Bool("pf_off", true))
	}
	b.events.Emit("antispoof.pf", "", attrs...)
	if readErr != nil {
		attrs = append(attrs, slog.String("err", readErr.Error()))
	}
	slog.LogAttrs(context.Background(), slog.LevelWarn, "this daemon took its reference on pf again, since pf no longer listed it, which pfctl -d or another program's pfctl -X ends: "+
		state+", and removing overlay turns the antispoof filter off", attrs...)
}

// pfReadback is the anchor's rules as the filter reads them, each with its
// counters, and whether the anchor holds anything. A rule carrying the label
// rules give its place reads as that rule's String, which a shortened label
// does not spell out, and any other as its label.
func pfReadback(read pf.Readback, rules []BorderRule) chainReadback {
	labels := pfLabels(rules)
	out := chainReadback{held: len(read.Rules) != 0 || len(read.Tables) != 0}
	for i, rule := range read.Rules {
		spec := rule.Rule.Label
		if i < len(labels) && spec == labels[i] {
			spec = rules[i].String()
		}
		out.rules = append(out.rules, Installed{Spec: spec, Counted: rule.Rule.Action == pf.Block, Packets: rule.Packets, Bytes: rule.Bytes})
	}
	return out
}

// anchorFault names how the anchor differs from want, empty where it holds
// want's rules in order and its tables as sets. A carve-out's pass and an
// interface exemption's render the same text, so a rule's label tells which
// it is, and one under another class's label at a place is a fault.
func anchorFault(held, want pf.Ruleset) string {
	if held.Equal(want) {
		return ""
	}
	for i, rule := range held.Rules {
		switch {
		case i >= len(want.Rules):
			return fmt.Sprintf("its anchor holds %q, which the filter does not write", rule.String())
		case rule.Interface != want.Rules[i].Interface || rule.NotInterface != want.Rules[i].NotInterface:
			return fmt.Sprintf("its rule %q reads %q where the filter writes %q", rule.Label, rule.String(), want.Rules[i].String())
		case rule.Label != want.Rules[i].Label:
			return fmt.Sprintf("its rule %d carries the label %q where the filter writes %q", i+1, rule.Label, want.Rules[i].Label)
		case rule != want.Rules[i]:
			return fmt.Sprintf("its anchor reads %q where the filter writes %q", rule.String(), want.Rules[i].String())
		}
	}
	if len(held.Rules) < len(want.Rules) {
		return fmt.Sprintf("its anchor lacks %q", want.Rules[len(held.Rules)].String())
	}
	named := func(tables []pf.Table, name string) bool {
		return slices.ContainsFunc(tables, func(t pf.Table) bool { return t.Name == name })
	}
	for _, table := range want.Tables {
		if !named(held.Tables, table.Name) {
			return fmt.Sprintf("its anchor lacks the table <%s>", table.Name)
		}
	}
	for _, table := range held.Tables {
		if !named(want.Tables, table.Name) {
			return fmt.Sprintf("its anchor holds the table <%s>, which the filter does not write", table.Name)
		}
	}
	return "its tables hold other entries than the filter writes"
}

// pfRuleset is the anchor that rules and sets ask for over the mesh's tun.
// Every rule is quick, which ends pf's evaluation for the whole host where
// Linux's accept ends the antispoof chain alone, and every pass keeps no
// state, so no packet passes on a state ahead of the drops.
func pfRuleset(tun string, rules []BorderRule, sets borderSets) (pf.Ruleset, error) {
	rs := pf.Ruleset{Tables: pfTables(rules, sets)}
	labels := pfLabels(rules)
	for i, rule := range rules {
		r := pf.Rule{Quick: true, Label: labels[i]}
		switch rule.Family() {
		case "ipv4":
			r.Family = pf.Inet
		case "ipv6":
			r.Family = pf.Inet6
		}
		switch rule.Class {
		case BorderInside:
			// pf cannot negate two interfaces in one rule, so the loopback link's accept is a pass of the overlay alone
			r.Action, r.Interface, r.From = pf.Pass, rule.Device, pf.Address{Table: pfOverlayTable}
		case BorderCarved:
			r.Action, r.Interface, r.NotInterface, r.From = pf.Block, tun, true, pf.Address{Table: pfCarvedTable}
		case BorderCarveOut, BorderExempt:
			r.Action, r.Interface, r.From = pf.Pass, rule.Device, pf.Address{Prefix: rule.Source}
			// the shared exemption names no device
			if rule.Device == "" {
				r.Interface, r.NotInterface = tun, true
			}
		case BorderSource:
			r.Action, r.Interface, r.NotInterface, r.From = pf.Block, tun, true, pf.Address{Prefix: rule.Source}
		default:
			return pf.Ruleset{}, fmt.Errorf("egress: pf holds no rule of its own for %q", rule)
		}
		rs.Rules = append(rs.Rules, r)
	}
	return rs, nil
}

// pfLabels is each rule's label: its String, which every class's fits in
// pf.LabelMax but a carve-out's and an exemption's, which each take a shorter
// form past it numbered by the rule's place among its class's rules from 1, so
// every label stays unique while the rule's text keeps the prefix
func pfLabels(rules []BorderRule) []string {
	labels := make([]string, len(rules))
	places := make(map[BorderClass]int)
	for i, rule := range rules {
		places[rule.Class]++
		label := rule.String()
		if len(label) > pf.LabelMax {
			place := strconv.Itoa(places[rule.Class])
			switch {
			case rule.Class == BorderCarveOut:
				label = "accept via " + rule.Device + " carve-out " + place
			case rule.Class == BorderExempt && rule.Device == "":
				label = "accept exempt " + place
			case rule.Class == BorderExempt:
				label = "accept exempt via " + rule.Device + " " + place
			}
		}
		labels[i] = label
	}
	return labels
}

// pfTables is the tables rules read, each holding both families, which a rule
// of one family reads its family of: the overlay, from the overlay's drops,
// for the loopback link's pass, and the carved sets for the carved drops
func pfTables(rules []BorderRule, sets borderSets) []pf.Table {
	var overlay []netip.Prefix
	for _, rule := range rules {
		if rule.Class == BorderSource {
			overlay = append(overlay, rule.Source)
		}
	}
	var tables []pf.Table
	if slices.ContainsFunc(rules, func(rule BorderRule) bool { return rule.Class == BorderInside }) {
		tables = append(tables, pf.Table{Name: pfOverlayTable, Const: true, Prefixes: overlay})
	}
	if slices.ContainsFunc(rules, func(rule BorderRule) bool { return rule.Class == BorderCarved }) {
		tables = append(tables, pf.Table{Name: pfCarvedTable, Const: true, Prefixes: meshkernel.RangePrefixes(carvedRanges(sets)...)})
	}
	return tables
}

// carvedRanges is both families of the carved sets, as the one table holds them
func carvedRanges(sets borderSets) []egress.Range {
	return slices.Concat(sets[carvedSet+"4"], sets[carvedSet+"6"])
}

// refuseUnwritable refuses an exemption's exact interface name that no pf rule
// can carry
func refuseUnwritable(cfg *egress.Border) error {
	var refused []error
	for _, name := range slices.Sorted(maps.Keys(cfg.Antispoof.Interface)) {
		if _, wildcard := egress.InterfacePattern(name); wildcard {
			continue
		}
		if err := pf.CheckInterface(name); err != nil {
			refused = append(refused, fmt.Errorf("egress: an exemption names the interface %q, which the antispoof filter's pf anchor cannot write: %w", name, err))
		}
	}
	return errors.Join(refused...)
}
