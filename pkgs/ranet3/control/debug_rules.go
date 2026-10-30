// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package control

import (
	"cmp"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"

	"ranet3.com/pkgs/ranet3/schema"
)

// PathDebugRules is the host's policy rules beside the ones the reconciler
// derives, and the border filter's chain with its counters
const PathDebugRules = PathDebug + "rules"

func init() {
	debugRead(PathDebugRules, classRead, "rules", RulesSource.DebugRules)
}

// RulesSource is a Source that reads the host's policy rules and the border filter
type RulesSource interface {
	DebugRules() RulesInfo
}

// RulesInfo is every policy rule the kernel holds, the rules the reconciler
// derives that it does not, and the border filter's chain
type RulesInfo struct {
	Policy []PolicyRule `json:"policy"`
	// PolicyErr says why Policy is empty: a platform with no policy rules, or
	// a dump that failed
	PolicyErr string       `json:"policy_err,omitempty"`
	Missing   []PolicyRule `json:"missing"`
	// Lookups is every lookup the reconciler's last pass whose batch answered
	// asked to find another program's rule ahead of the mesh's, and on darwin
	// the route the underlay's selection takes toward each live endpoint
	Lookups []RuleLookup `json:"lookups,omitempty"`
	// Border is absent on a node that writes no cap.border
	Border *BorderChain `json:"border,omitempty"`
}

// RuleLookup is one lookup of the reconciler: unmarked, of Address inside the
// overlay hold Prefix, or of the underlay, under its mark toward the peer
// endpoint Address from Source out of Interface, each absent where a live
// session's send carries none. Taken is an overlay lookup answered outside the
// tun and its hold, or the underlay's answered through the tun. Source and
// Interface are linux's lookups'. On darwin an underlay row is the interface a
// live session's datagrams to Address name, or the interface of the pin they
// carry, in Answer, its Source and Interface empty, Prefix the route the
// selection matched, absent for a pin, and never taken
type RuleLookup struct {
	Lookup    string       `json:"lookup"`
	Family    string       `json:"family"`
	Prefix    netip.Prefix `json:"prefix,omitzero"`
	Address   netip.Addr   `json:"address"`
	Source    netip.Addr   `json:"source,omitzero"`
	Interface string       `json:"interface,omitempty"`
	Answer    string       `json:"answer"`
	Taken     bool         `json:"taken"`
}

// PolicyRule is one policy rule, as the kernel holds it or as the reconciler
// derives it
type PolicyRule struct {
	Family   string       `json:"family"`
	Priority uint32       `json:"priority"`
	To       netip.Prefix `json:"to,omitzero"`
	From     netip.Prefix `json:"from,omitzero"`
	IIF      string       `json:"iif,omitempty"`
	OIF      string       `json:"oif,omitempty"`
	FWMark   uint32       `json:"fwmark,omitempty"`
	FWMask   uint32       `json:"fwmask,omitempty"`
	L3mdev   bool         `json:"l3mdev,omitempty"`
	// Unread names each selector the rule carries whose value the dump's
	// reading keeps no record of, as `ip rule` spells it
	Unread []string `json:"unread,omitempty"`
	// Invert is a rule taking every packet its selectors do not
	Invert bool   `json:"invert,omitempty"`
	Action string `json:"action"`
	// Table is the table a lookup reads, as the kernel holds it whatever the
	// action, absent where it holds none
	Table uint32 `json:"table,omitempty"`
	// Goto is the priority a goto jumps to, absent for any other action
	Goto uint32 `json:"goto,omitempty"`
	// Suppress is the suppress length the kernel stores with the rule, which only a lookup reads, absent where it stores none
	Suppress *int  `json:"suppress_prefixlength,omitempty"`
	Protocol uint8 `json:"protocol"`
	// Owned is a rule carrying the reconciler's protocol, the default one on a
	// node with no cap.table, and Wanted one the reconciler derives
	Owned  bool `json:"owned"`
	Wanted bool `json:"wanted"`
}

// BorderChain is the border filter's chain as a debug read finds it
type BorderChain struct {
	Where    string `json:"where"`
	Hook     string `json:"hook"`
	Priority int    `json:"priority"`
	// ReadAt is the last pass, whose readback Ready and Unready report, and
	// ReadAgo how long before the answer it ran
	ReadAt  time.Time         `json:"read_at,omitzero"`
	ReadAgo Duration          `json:"read_ago"`
	Ready   bool              `json:"ready"`
	Unready string            `json:"unready,omitempty"`
	Rules   []BorderChainRule `json:"rules"`
	Err     string            `json:"err,omitempty"`
}

// BorderChainRule is one rule of the chain: the ones the configuration asks
// for in order, with their counters read now, then any the chain holds that
// it does not ask for
type BorderChainRule struct {
	Spec    string `json:"spec"`
	Verdict string `json:"verdict"`
	Reason  string `json:"reason,omitempty"`
	Family  string `json:"family,omitempty"`
	// Held is whether the chain holds the rule
	Held    bool   `json:"held"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

// Rules reads the policy rules and the border filter's chain
func (c *Client) Rules() (RulesInfo, error) { return read[RulesInfo](c, PathDebugRules) }

// RenderRules writes the policy rules of each family as a table, the wanted
// rules the kernel does not hold, then the border filter's chain with the
// packets each drop counted
func RenderRules(w io.Writer, info RulesInfo) {
	if info.PolicyErr != "" {
		fmt.Fprintf(w, "Policy rules: %s\n", info.PolicyErr)
	}
	for _, family := range []string{"ipv4", "ipv6"} {
		var rows [][]string
		for _, rule := range info.Policy {
			if rule.Family == family {
				rows = append(rows, []string{fmt.Sprint(rule.Priority), rule.selects(), rule.target(), rule.owner()})
			}
		}
		if len(rows) == 0 {
			continue
		}
		fmt.Fprintf(w, "Policy rules, %s\n", family)
		indented(w, func(w io.Writer) { table(w, []string{"Priority", "Selects", "Table", "Owner"}, rows) })
	}
	if info.PolicyErr == "" {
		missing := "none"
		if len(info.Missing) > 0 {
			specs := make([]string, 0, len(info.Missing))
			for _, rule := range info.Missing {
				specs = append(specs, fmt.Sprintf("%s priority %d %s %s", rule.Family, rule.Priority, rule.selects(), rule.target()))
			}
			missing = strings.Join(specs, ", ")
		}
		fmt.Fprintf(w, "Wanted and missing: %s\n", missing)
	}
	if len(info.Lookups) > 0 {
		rows := make([][]string, 0, len(info.Lookups))
		for _, lookup := range info.Lookups {
			prefix, source, iface, taken := "-", "-", cmp.Or(lookup.Interface, "-"), "no"
			if lookup.Prefix.IsValid() {
				prefix = lookup.Prefix.String()
			}
			if lookup.Source.IsValid() {
				source = lookup.Source.String()
			}
			if lookup.Taken {
				taken = "yes"
			}
			rows = append(rows, []string{lookup.Lookup, lookup.Family, prefix, lookup.Address.String(), source, iface, taken, lookup.Answer})
		}
		fmt.Fprint(w, "Lookups\n")
		indented(w, func(w io.Writer) {
			table(w, []string{"Lookup", "Family", "Prefix", "Address", "Source", "Interface", "Taken", "Answer"}, rows)
		})
	} else if info.PolicyErr == "" {
		fmt.Fprint(w, "Lookups: none\n")
	}
	if info.Border == nil {
		return
	}
	border := info.Border
	state := "ready"
	if !border.Ready {
		state = "not ready, " + border.Unready
	}
	read := "no pass yet"
	if !border.ReadAt.IsZero() {
		read = "read " + sinceText(time.Duration(border.ReadAgo)) + " ago"
	}
	fmt.Fprintf(w, "\nBorder filter, %s, %s at priority %d, %s, %s\n", border.Where, border.Hook, border.Priority, read, state)
	if border.Err != "" {
		fmt.Fprintf(w, "  read now: %s\n", border.Err)
	}
	rows := make([][]string, 0, len(border.Rules))
	for _, rule := range border.Rules {
		row := []string{rule.Verdict, strings.TrimPrefix(rule.Spec, rule.Verdict+" ")}
		switch {
		case !rule.Held:
			row = append(row, "not held")
		case rule.Verdict == "drop":
			row = append(row, fmt.Sprintf("%d packets, %d B", rule.Packets, rule.Bytes))
		}
		rows = append(rows, row)
	}
	indented(w, func(w io.Writer) { pairs(w, rows) })
}

// indented writes what write writes with every line two spaces in
func indented(w io.Writer, write func(io.Writer)) {
	var out strings.Builder
	write(&out)
	for line := range strings.Lines(out.String()) {
		fmt.Fprint(w, "  "+line)
	}
}

// selects is the rule's selectors as `ip rule` spells them, all where it
// names none
func (r PolicyRule) selects() string {
	var parts []string
	if r.Invert {
		parts = append(parts, "not")
	}
	if r.From.IsValid() {
		parts = append(parts, "from "+r.From.String())
	}
	if r.To.IsValid() {
		parts = append(parts, "to "+r.To.String())
	}
	if r.IIF != "" {
		parts = append(parts, "iif "+r.IIF)
	}
	if r.OIF != "" {
		parts = append(parts, "oif "+r.OIF)
	}
	if r.FWMark != 0 || r.FWMask != 0 {
		mark := fmt.Sprintf("fwmark %#x", r.FWMark)
		if r.FWMask != 0 && r.FWMask != ^uint32(0) {
			mark += fmt.Sprintf("/%#x", r.FWMask)
		}
		parts = append(parts, mark)
	}
	if r.L3mdev {
		parts = append(parts, "l3mdev")
	}
	parts = append(parts, r.Unread...)
	if len(parts) == 0 || len(parts) == 1 && r.Invert {
		parts = append(parts, "all")
	}
	return strings.Join(parts, " ")
}

// target is the table a lookup reads, by name where it has one, with the
// suppress length the kernel stores with the rule, the priority a goto jumps
// to, or the action where the rule reads no table
func (r PolicyRule) target() string {
	switch {
	case r.Action == "goto":
		return fmt.Sprintf("goto %d", r.Goto)
	case r.Action != "lookup":
		return r.Action
	case r.Suppress != nil:
		return fmt.Sprintf("%s suppress_prefixlength %d", schema.TableID(r.Table), *r.Suppress)
	}
	return schema.TableID(r.Table).String()
}

// owner names who wrote the rule: ranet3 for the reconciler's protocol, the
// kernel for RTPROT_KERNEL, and the protocol number for anybody else
func (r PolicyRule) owner() string {
	switch {
	case r.Owned:
		return "ranet3"
	case r.Protocol == 2:
		return "kernel"
	}
	return fmt.Sprintf("protocol %d", r.Protocol)
}
