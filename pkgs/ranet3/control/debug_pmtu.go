// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package control

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"reflect"
	"strconv"
	"time"
)

// PathDebugPMTU is link.mtu, the tun's MTU and each session's search of its path MTU
const PathDebugPMTU = PathDebug + "pmtu"

func init() { registerDebug(PathDebugPMTU, classRead, reflect.TypeFor[PMTUInfo](), servePMTU) }

// PMTUSource is a Source whose sessions search their path MTU
type PMTUSource interface {
	// DebugPMTU is the node's part and the sessions of one peer, or of every peer where peer is empty
	DebugPMTU(peer string) PMTUInfo
}

// PMTUInfo is the node's link.mtu and tun, what it did to packets past a session's budget, its router-ids and answer SID, and each session's search
// End's answers to a packet past its session and transit's errors come from the router-ids and the answer SID as netstack's AnswerSources says
type PMTUInfo struct {
	// LinkMTU is link.mtu, the largest inner packet a session carries
	LinkMTU int `json:"link_mtu"`
	// Steering is the longest segment list's header, which the tun's MTU leaves room for
	Steering int `json:"steering"`
	// DeviceMTU is the tun's MTU as the kernel reported it for this answer, zero where the device could not answer
	DeviceMTU int `json:"device_mtu"`
	// TooBigSent counts the packet too big and fragmentation needed answers to packets past their session's budget
	TooBigSent uint64 `json:"packet_too_big_sent"`
	// MSSClamped counts the SYNs whose MSS the node lowered to a session's budget
	MSSClamped uint64 `json:"mss_clamped"`
	// RouterIDv4 and RouterIDv6 are the router-id of each family, RFC 1812 section 2.2.7, absent where the node holds none
	RouterIDv4 netip.Addr `json:"router_id_ipv4,omitzero"`
	RouterIDv6 netip.Addr `json:"router_id_ipv6,omitzero"`
	// AnswerSID is the End SID an IPv6 error about a packet in transit comes from where the node holds no IPv6 router-id
	// absent where the node holds none
	AnswerSID netip.Addr    `json:"answer_sid,omitzero"`
	Sessions  []PMTUSession `json:"sessions"`
}

// the states of a session's search, RFC 8899's phases as ranet3 runs them
const (
	PMTUConfirming    = "confirming"
	PMTUSearchingUp   = "searching up"
	PMTUSearchingDown = "searching down"
	PMTUConfirmed     = "confirmed"
	PMTUUnderFloor    = "under the floor"
	// PMTUNotSearched is a session whose platform sends without DF, which carries link.mtu
	PMTUNotSearched = "not searched"
)

// PMTUSession is one session's search of the path to its endpoint
type PMTUSession struct {
	// Path is the session's path, which its pmtu events name as their peer
	Path string `json:"path"`
	// Peer is the canonical form of the node the session is with
	Peer     string `json:"peer"`
	Endpoint string `json:"endpoint"`
	State    string `json:"state"`
	// DontFragment says the session's sends leave with DF, false while its family fragments them
	DontFragment bool `json:"dont_fragment"`
	// Budget is the largest inner packet the session carries now
	Budget int `json:"budget"`
	// MSSv4 and MSSv6 are the MSS a SYN through the session leaves with at most
	MSSv4 int `json:"mss_ipv4"`
	MSSv6 int `json:"mss_ipv6"`
	// Route is the largest inner packet the route to the endpoint let through when last read, zero where the read failed
	// Target is the least of it and link.mtu, which the search climbs no further than
	Route  int `json:"route,omitempty"`
	Target int `json:"target,omitempty"`
	// Probe is the size of the probe out, absent while none is
	Probe *PMTUProbe `json:"probe,omitempty"`
	// Last is the last attempt an Ack answered or whose wait ran out, absent before the first
	Last *PMTUOutcome `json:"last,omitempty"`
	// Sent counts the attempts the speaker queued, Acked those an Ack answered and Lost those queued whose wait ran out
	// an attempt whose target the search moves while it is out counts neither acked nor lost
	// whether a refusal, a route read lower, a change of link.mtu or an endpoint change moves it
	// and one answered after its wait ran out counts both, so the three need not add up
	Sent  uint64 `json:"sent"`
	Acked uint64 `json:"acked"`
	Lost  uint64 `json:"lost"`
	// Refusals counts the sends to the endpoint the host refused as past the path's MTU
	Refusals uint64 `json:"refusals"`
	// Changed is the session's last budget change, absent before the first
	Changed *PMTUChange `json:"changed,omitempty"`
}

// PMTUProbe is a probe out and how many times it has gone
type PMTUProbe struct {
	Size     int `json:"size"`
	Attempts int `json:"attempts"`
	// MaxAttempts is how many attempts of a size go unanswered before the path counts as losing it
	MaxAttempts int `json:"max_attempts"`
}

// PMTUOutcome is how one attempt ended
type PMTUOutcome struct {
	Size  int  `json:"size"`
	Acked bool `json:"acked"`
	// Ago is how long before the answer it ended
	Ago Duration `json:"ago"`
}

// PMTUChange is one move of a session's budget
type PMTUChange struct {
	From   int    `json:"from"`
	To     int    `json:"to"`
	Reason string `json:"reason"`
	// Ago is how long before the answer it happened
	Ago Duration `json:"ago"`
}

func servePMTU(d *debugServer, w http.ResponseWriter, r *http.Request) {
	if !reading(w, r) {
		return
	}
	if source, ok := implements[PMTUSource](d, w, "pmtu"); ok {
		writeJSON(w, source.DebugPMTU(r.URL.Query().Get("peer")))
	}
}

// PMTU reads the node's part and the sessions of one peer, named by its path, org/name:serial, org/name or name, or of every peer where peer is empty
// ctx bounds the exchange beside the client's own timeout
func (c *Client) PMTU(ctx context.Context, peer string) (PMTUInfo, error) {
	path := PathDebugPMTU
	if peer != "" {
		path += "?" + url.Values{"peer": {peer}}.Encode()
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://control"+path, nil)
	if err != nil {
		return PMTUInfo{}, fmt.Errorf("control: %w", err)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return PMTUInfo{}, c.explain(err)
	}
	return decode[PMTUInfo](PathDebugPMTU, response)
}

// RenderPMTU writes the node's part as name and value pairs, then each session's the same way after a blank line
func RenderPMTU(w io.Writer, info PMTUInfo) {
	steering := "none"
	if info.Steering > 0 {
		steering = strconv.Itoa(info.Steering) + " B of segment list in front of a steered packet"
	}
	device := strconv.Itoa(info.DeviceMTU) + " B"
	if info.DeviceMTU == 0 {
		device = "unknown, the device did not answer"
	}
	pairs(w, [][]string{
		{"Link MTU", strconv.Itoa(info.LinkMTU) + " B"},
		{"Steering", steering},
		{"Device MTU", device},
		{"Too big", countOf(int(info.TooBigSent), "answer") + " sent to packets past their session's budget"},
		{"MSS clamped", countOf(int(info.MSSClamped), "SYN")},
		{"Answer sources", sourceText(info.RouterIDv4) + " for IPv4, " + sourceText(info.RouterIDv6) + " for IPv6"},
		{"Answer SID", sourceText(info.AnswerSID)},
	})
	for _, session := range info.Sessions {
		fmt.Fprintln(w)
		pairs(w, sessionPairs(session))
	}
}

func sourceText(address netip.Addr) string {
	if !address.IsValid() {
		return "none"
	}
	return address.String()
}

func sessionPairs(s PMTUSession) [][]string {
	sends := "with DF"
	if !s.DontFragment {
		sends = "without DF"
	}
	rows := [][]string{
		{"Session", s.Path},
		{"Peer", s.Peer},
		{"Endpoint", s.Endpoint + ", sent " + sends},
		{"State", s.State},
		{"Budget", fmt.Sprintf("%d B, clamping the MSS to %d over IPv4 and %d over IPv6", s.Budget, s.MSSv4, s.MSSv6)},
	}
	if s.State == PMTUNotSearched {
		return append(rows, []string{"Changed", changedLine(s.Changed)})
	}
	route := "unknown, the last read failed"
	if s.Route != 0 {
		route = fmt.Sprintf("%d B when last read, a target of %d B", s.Route, s.Target)
	}
	return append(rows,
		[]string{"Route", route},
		[]string{"Probe", probeLine(s.Probe, s.Last)},
		[]string{"Probes", fmt.Sprintf("%d sent, %d acked, %d lost", s.Sent, s.Acked, s.Lost)},
		[]string{"Refusals", strconv.FormatUint(s.Refusals, 10)},
		[]string{"Changed", changedLine(s.Changed)},
	)
}

func probeLine(probe *PMTUProbe, last *PMTUOutcome) string {
	line := "none out"
	if probe != nil {
		line = fmt.Sprintf("%d B out, attempt %d of %d", probe.Size, probe.Attempts, probe.MaxAttempts)
	}
	if last == nil {
		return line
	}
	result := "lost"
	if last.Acked {
		result = "acked"
	}
	return fmt.Sprintf("%s, the last of %d B %s %s ago", line, last.Size, result, sinceText(time.Duration(last.Ago)))
}

func changedLine(change *PMTUChange) string {
	if change == nil {
		return "no change recorded"
	}
	return fmt.Sprintf("from %d to %d B by %s, %s ago", change.From, change.To, change.Reason, sinceText(time.Duration(change.Ago)))
}
