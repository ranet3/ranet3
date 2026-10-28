// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package control

import (
	"fmt"
	"io"
	"net/netip"
	"strings"
)

// PathDebugEgress is cap.egress: each rule of the exit with its counter read
// now, and each family's readiness condition by condition as the last pass
// judged it
const PathDebugEgress = PathDebug + "egress"

func init() {
	debugRead(PathDebugEgress, classRead, "egress", EgressSource.DebugEgress)
}

// EgressSource is a Source that reads its cap.egress
type EgressSource interface {
	DebugEgress() EgressInfo
}

// EgressInfo is cap.egress as a debug read finds it, Enabled false and every
// other part absent on a node that holds none, and the parts past Status
// absent for an exit whose backend holds no rules in the host's packet filter
type EgressInfo struct {
	Enabled bool `json:"enabled"`
	// Status is the exit's own report, as ranet3 status gives it but for the
	// border filter's hold on the egress segments, which this view leaves out
	Status EgressStatus `json:"status,omitzero"`
	// Rules is each rule the exit asks for in order, then each its chains hold
	// that it does not ask for, and ReadErr why they could not be read now
	Rules    []EgressRule   `json:"rules,omitempty"`
	ReadErr  string         `json:"read_err,omitempty"`
	Families []EgressFamily `json:"families,omitempty"`
	// RPFilter is IPv4's rp_filter on all and on each device a route of the
	// last pass's lookups leaves by, read now
	RPFilter []RouteSetting `json:"rp_filter,omitempty"`
}

// EgressRule is one rule of the exit's chains: Wanted where the exit asks for
// it and Held where the chains hold it, with its counter read now. Counter is
// flows for a rule of the translation's chain, which meets a flow's first
// packet alone and so counts flows and the bytes of their first packets,
// packets for any other, and absent for a rule that keeps none.
type EgressRule struct {
	Spec    string `json:"spec"`
	Wanted  bool   `json:"wanted"`
	Held    bool   `json:"held"`
	Counter string `json:"counter,omitempty"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

// EgressFamily is one family the exit translates, as the last pass judged it:
// whether it is ready and why not, its chains' readback, the host's
// forwarding, and each route lookup the pass read for it
type EgressFamily struct {
	Family string `json:"family"`
	Ready  bool   `json:"ready"`
	Why    string `json:"why,omitempty"`
	// Unwritten is why the family's chains do not read back as written,
	// absent where they do
	Unwritten  string         `json:"unwritten,omitempty"`
	Forwarding bool           `json:"forwarding"`
	Lookups    []EgressLookup `json:"lookups,omitempty"`
}

// EgressLookup is one route lookup of the last pass, for a packet from Source
// to Destination arriving on IIF, and for this host's own route from no source
// on no device, with its answer: Route or Err, and where Reply asked for it,
// the reply's lookup arriving on ReplyIIF with ReplyRoute or ReplyErr.
// Answered is false where the pass's batch failed or answered short.
type EgressLookup struct {
	Source      netip.Addr   `json:"source,omitzero"`
	Destination netip.Addr   `json:"destination"`
	IIF         string       `json:"iif,omitempty"`
	Reply       bool         `json:"reply,omitempty"`
	Answered    bool         `json:"answered"`
	Route       *EgressRoute `json:"route,omitempty"`
	Err         string       `json:"err,omitempty"`
	ReplyIIF    string       `json:"reply_iif,omitempty"`
	ReplyRoute  *EgressRoute `json:"reply_route,omitempty"`
	ReplyErr    string       `json:"reply_err,omitempty"`
}

// EgressRoute is a route a lookup found, its type as ip-route(8) names it and
// its next hops with the kernel's marks
type EgressRoute struct {
	Type     string         `json:"type"`
	NextHops []RouteNextHop `json:"nexthops,omitempty"`
}

// Egress reads cap.egress with its rules and readiness
func (c *Client) Egress() (EgressInfo, error) { return read[EgressInfo](c, PathDebugEgress) }

// RenderEgress writes the exit's status line, each rule with its counter, each
// family's readiness with its lookups, then the rp_filter settings read
func RenderEgress(w io.Writer, info EgressInfo) {
	if !info.Enabled {
		fmt.Fprintln(w, "This node holds no cap.egress")
		return
	}
	pairs(w, [][]string{{"Exit", egressLine(info.Status)}})
	if info.Rules == nil && info.Families == nil && info.ReadErr == "" {
		return
	}
	fmt.Fprintln(w, "Rules")
	if info.ReadErr != "" {
		fmt.Fprintf(w, "  read now: %s\n", info.ReadErr)
	}
	rows := make([][]string, 0, len(info.Rules))
	for _, rule := range info.Rules {
		spec := rule.Spec
		if spec == "" {
			spec = "a rule with no comment"
		}
		rows = append(rows, []string{spec, ruleState(rule)})
	}
	indented(w, func(w io.Writer) { pairs(w, rows) })
	for _, family := range info.Families {
		state := "ready"
		if !family.Ready {
			state = "not ready, " + family.Why
		}
		fmt.Fprintf(w, "Family %s, %s\n", family.Family, state)
		chains := "read back as written"
		if family.Unwritten != "" {
			chains = family.Unwritten
		}
		rows := [][]string{{"Chains", chains}, {"Forwarding", onOff(family.Forwarding)}}
		for _, lookup := range family.Lookups {
			rows = append(rows, []string{"Lookup", lookupLine(lookup)})
			if lookup.Reply && lookup.Answered {
				rows = append(rows, []string{"Reply", replyLine(lookup)})
			}
		}
		indented(w, func(w io.Writer) { pairs(w, rows) })
	}
	if len(info.RPFilter) > 0 {
		settings := make([]string, 0, len(info.RPFilter))
		for _, setting := range info.RPFilter {
			value := setting.Value
			if setting.Err != "" {
				value = setting.Err
			}
			settings = append(settings, setting.Name+" "+value)
		}
		pairs(w, [][]string{{"Settings", strings.Join(settings, ", ")}})
	}
}

// ruleState is a rule's counter, or why it has none to read
func ruleState(rule EgressRule) string {
	var state string
	switch {
	case !rule.Held:
		return "not held"
	case rule.Counter == "flows":
		state = fmt.Sprintf("%s, %d B of their first packets", countOf(int(rule.Packets), "flow"), rule.Bytes)
	case rule.Counter != "":
		state = fmt.Sprintf("%s, %d B", countOf(int(rule.Packets), "packet"), rule.Bytes)
	default:
		state = "uncounted"
	}
	if !rule.Wanted {
		state += ", not asked for"
	}
	return state
}

// lookupLine is a lookup and its forward answer
func lookupLine(lookup EgressLookup) string {
	line := lookup.Destination.String()
	if lookup.Source.IsValid() {
		line += " from " + lookup.Source.String()
	} else {
		line += ", this host's own"
	}
	if lookup.IIF != "" {
		line += " arriving on " + lookup.IIF
	}
	return line + ": " + answerText(lookup.Answered, lookup.Route, lookup.Err)
}

// replyLine is the reply's lookup of a lookup that asked for it
func replyLine(lookup EgressLookup) string {
	line := lookup.Source.String() + " from " + lookup.Destination.String()
	if lookup.ReplyIIF != "" {
		line += " arriving on " + lookup.ReplyIIF
	}
	return line + ": " + answerText(true, lookup.ReplyRoute, lookup.ReplyErr)
}

func answerText(answered bool, route *EgressRoute, err string) string {
	switch {
	case !answered:
		return "not answered"
	case err != "":
		return err
	case route == nil:
		return "no route"
	}
	parts := []string{route.Type}
	for _, hop := range route.NextHops {
		text := "dev " + hop.Dev
		if hop.Dead {
			text += " dead"
		}
		if hop.LinkDown {
			text += " linkdown"
		}
		parts = append(parts, text)
	}
	return strings.Join(parts, ", ")
}
