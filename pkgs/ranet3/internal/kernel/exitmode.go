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
	"path"
	"slices"
	"strconv"
	"strings"

	"ranet3.com/pkgs/ranet3/schema"
)

// ExitMode is cap.exit, which makes the mesh's default of lowest metric this
// host's default, for its own traffic and for what it forwards from the links
// Forward names. Writing the block turns it on, and the reconciler runs it as
// part of cap.table (see Table.WithMode).
type ExitMode struct {
	// Forward is the links whose forwarded traffic follows the mode as the
	// host's own does, each a link's name or a shell pattern as path.Match reads
	// one, such as docker* or br-*. A link it leaves out keeps the routes it had
	// before ranet3.
	Forward []string `yaml:"forward,omitempty" json:"forward,omitempty" toml:"forward,omitempty"`
	// Fallback is where the host's traffic leaves while no exit is live,
	// FallbackUplink where it is unwritten
	Fallback Fallback `yaml:"fallback,omitempty" json:"fallback,omitempty" toml:"fallback,omitempty"`
	// Inbound is the services on the uplink's addresses whose replies the
	// table's reply lines pass while fallback is "none", on flows conntrack saw
	// the far side open, as routing.md's "The kill switch on Linux" lists, each
	// written "<port>/<protocol>" or "<first>-<last>/<protocol>" with the
	// protocol tcp or udp
	Inbound []string `yaml:"inbound,omitempty" json:"inbound,omitempty" toml:"inbound,omitempty"`
	// LAN is the prefixes beyond the private and link-local ranges whose part
	// of a connected network counts as the LAN while fallback is "none". It
	// adds no destination a link outside the mesh is not connected to.
	LAN []schema.Prefix `yaml:"lan,omitempty" json:"lan,omitempty" toml:"lan,omitempty"`
}

// Fallback is cap.exit fallback
type Fallback string

const (
	// FallbackUplink lets the host's traffic leave by the host's own default
	// while no exit is live
	FallbackUplink Fallback = "uplink"
	// FallbackNone writes the table ranet3_fallback, whose lines routing.md's
	// "The kill switch on Linux" lists, whether an exit is live or not. The
	// table stays after a stop that withdraws nothing, such as SIGKILL, and
	// every stop that withdraws deletes it, a failure's included. While it
	// reads back as written
	// the host's traffic leaves by a link outside the mesh only where one of
	// its lines passes it.
	FallbackNone Fallback = "none"
)

// Refuses reports that the mode asks for the kill switch, FallbackNone
func (m ExitMode) Refuses() bool { return m.Fallback == FallbackNone }

// Service is a range of ports of one transport protocol, as inbound lists one
type Service struct {
	// Protocol is "tcp" or "udp"
	Protocol    string
	First, Last uint16
}

func (s Service) String() string {
	if s.First == s.Last {
		return fmt.Sprintf("%d/%s", s.First, s.Protocol)
	}
	return fmt.Sprintf("%d-%d/%s", s.First, s.Last, s.Protocol)
}

// parseService reads an inbound entry
func parseService(entry string) (Service, error) {
	ports, protocol, found := strings.Cut(entry, "/")
	if !found {
		return Service{}, fmt.Errorf("kernel: cap.exit inbound %q is not <port>/<protocol> or <first>-<last>/<protocol>", entry)
	}
	if protocol != "tcp" && protocol != "udp" {
		return Service{}, fmt.Errorf("kernel: cap.exit inbound %q names the protocol %q, where inbound takes tcp or udp", entry, protocol)
	}
	first, last, ranged := strings.Cut(ports, "-")
	if !ranged {
		last = first
	}
	var bounds [2]uint16
	for i, text := range []string{first, last} {
		port, err := strconv.ParseUint(text, 10, 16)
		if err != nil {
			return Service{}, fmt.Errorf("kernel: cap.exit inbound %q is not <port>/<protocol> or <first>-<last>/<protocol>, each port from 1 to 65535", entry)
		}
		if port == 0 {
			return Service{}, fmt.Errorf("kernel: cap.exit inbound %q names port 0, which no service listens on", entry)
		}
		bounds[i] = uint16(port)
	}
	if bounds[0] > bounds[1] {
		return Service{}, fmt.Errorf("kernel: cap.exit inbound %q runs from %d down to %d: write the lower port first", entry, bounds[0], bounds[1])
	}
	return Service{Protocol: protocol, First: bounds[0], Last: bounds[1]}, nil
}

// Services is inbound's entries, tcp before udp, each protocol's ranges in
// order with those that overlap or touch joined, of a mode Validate took
func (m ExitMode) Services() []Service {
	var parsed []Service
	for _, entry := range m.Inbound {
		if service, err := parseService(entry); err == nil {
			parsed = append(parsed, service)
		}
	}
	slices.SortFunc(parsed, func(a, b Service) int {
		if c := strings.Compare(a.Protocol, b.Protocol); c != 0 {
			return c
		}
		return int(a.First) - int(b.First)
	})
	var out []Service
	for _, service := range parsed {
		if n := len(out); n > 0 && out[n-1].Protocol == service.Protocol && int(service.First) <= int(out[n-1].Last)+1 {
			out[n-1].Last = max(out[n-1].Last, service.Last)
			continue
		}
		out = append(out, service)
	}
	return out
}

// loopback is the name Linux gives its loopback link, whose index every lookup of the host's own traffic carries
const loopback = "lo"

// Validate refuses a forward entry that can name no link, an empty one or a
// malformed pattern, and lo by name, whose traffic is the host's own. It
// refuses a fallback other than "uplink" and "none", inbound unless fallback
// is "none", and an inbound entry that is malformed, names port 0 or another
// protocol, runs downward or is written twice. It refuses lan unless fallback
// is "none", and an entry of it as schema.CheckPrefixes does.
func (m ExitMode) Validate() error {
	if m.Fallback != "" && m.Fallback != FallbackUplink && m.Fallback != FallbackNone {
		return fmt.Errorf("kernel: cap.exit fallback %q is neither \"uplink\" nor \"none\"", m.Fallback)
	}
	if len(m.Inbound) > 0 && !m.Refuses() {
		return errors.New("kernel: cap.exit inbound lists the services that answer beyond the LAN while fallback = \"none\" refuses the rest, and fallback is not \"none\": write fallback = \"none\" or remove inbound")
	}
	if len(m.LAN) > 0 && !m.Refuses() {
		return errors.New("kernel: cap.exit lan lists the connected networks that count as the LAN while fallback = \"none\" refuses the rest, and fallback is not \"none\": write fallback = \"none\" or remove lan")
	}
	if err := schema.CheckPrefixes("kernel: cap.exit lan", m.LAN, nil); err != nil {
		return err
	}
	seen := make(map[Service]string, len(m.Inbound))
	for _, entry := range m.Inbound {
		service, err := parseService(entry)
		if err != nil {
			return err
		}
		if earlier, ok := seen[service]; ok {
			return fmt.Errorf("kernel: cap.exit inbound %q is written twice, the second time as %q", earlier, entry)
		}
		seen[service] = entry
	}
	for _, entry := range m.Forward {
		if entry == "" {
			return errors.New("kernel: cap.exit forward holds an empty entry, which names no link")
		}
		// path.Match parses every part of a pattern whatever the name, so the empty name finds each malformed one
		if _, err := path.Match(entry, ""); err != nil {
			return fmt.Errorf("kernel: cap.exit forward %q: %w", entry, err)
		}
		if entry == loopback {
			return errors.New("kernel: cap.exit forward lo is the loopback link, whose traffic is the host's own and follows the mode already")
		}
	}
	return nil
}

// Normalized is the capability as the reconciler runs it, forward and lan in
// one order and each entry once, and inbound as Services spells it, so a
// reload over a list written in another order or split another way is no
// change.
func (m ExitMode) Normalized() ExitMode {
	m.Forward = slices.Compact(slices.Sorted(slices.Values(m.Forward)))
	m.LAN = slices.Compact(slices.SortedFunc(slices.Values(m.LAN), schema.ComparePrefix))
	inbound := m.Services()
	m.Inbound = nil
	for _, service := range inbound {
		m.Inbound = append(m.Inbound, service.String())
	}
	return m
}

// RefuseNamed refuses a forward entry written as a name that is the mesh's tun
// or the link either family's default leaves by now. A pattern matching one is
// skipped where the reconciler expands it, as is a name that becomes the
// uplink later, since the host is the one that moved.
func (m ExitMode) RefuseNamed(tun string, network NetworkState) error {
	for _, entry := range m.Forward {
		if isPattern(entry) {
			continue
		}
		if reason := skipReason(entry, tun, network); reason != "" {
			return fmt.Errorf("kernel: cap.exit forward %s is %s, whose traffic never follows the mode: remove it from forward", entry, reason)
		}
	}
	return nil
}

// ForwardSkip is a link a cap.exit forward entry matches and the mode leaves
// out, with the entry and the reason.
type ForwardSkip struct {
	Entry, Link, Reason string
}

// expandForward is each link the network holds outside the mesh, and the tun,
// that an entry of forward matches, sorted and each once. The tun, lo and the
// link either family's default leaves by are left out, each reported with the
// first entry in forward's order that matched it.
func expandForward(forward []string, tun string, network NetworkState) ([]string, []ForwardSkip) {
	if len(forward) == 0 {
		return nil, nil
	}
	names := make(map[string]bool)
	for _, family := range []NetworkFamily{network.IPv4, network.IPv6} {
		for _, link := range family.Links {
			names[link.Name] = true
		}
	}
	if tun != "" {
		names[tun] = true
	}
	var out []string
	var skipped []ForwardSkip
	for _, name := range slices.Sorted(maps.Keys(names)) {
		// every entry passed Validate, so path.Match reports no error
		at := slices.IndexFunc(forward, func(entry string) bool { matched, _ := path.Match(entry, name); return matched })
		if at < 0 {
			continue
		}
		if reason := skipReason(name, tun, network); reason != "" {
			skipped = append(skipped, ForwardSkip{Entry: forward[at], Link: name, Reason: reason})
			continue
		}
		out = append(out, name)
	}
	return out, skipped
}

// ExitStatus is cap.exit's mode as the last rule pass ran it
type ExitStatus struct {
	// Forwarded is each link forward expanded to, whose forwarded traffic follows the mode
	Forwarded []string
	// Skipped is each link a forward entry matched that the mode leaves out
	Skipped []ForwardSkip
	// Unaddressed is each family the tun carries no overlay address of, which
	// runs mode off's rules
	Unaddressed []Family
	// Fallback is the switch fallback = "none" asks for, nil under "uplink"
	Fallback *FallbackStatus
}

// exitPass is mode 2 as the pass under way derives it, from the network as
// the watch last read it and the tun's addresses as the pass holds them, and
// its status, nil in mode off. A family counts as addressed by an address
// inside an overlay entry alone, whoever wrote it.
func (r *Reconciler) exitPass(held []netip.Prefix) (exitView, *ExitStatus) {
	mode := r.table.Mode()
	if mode == nil {
		return exitView{}, nil
	}
	var network NetworkState
	if r.rt.Network != nil {
		network = r.rt.Network()
	}
	forwarded, skipped := expandForward(mode.Forward, r.rt.Interface, network)
	status := &ExitStatus{Forwarded: forwarded, Skipped: skipped}
	for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
		inOverlay := func(address netip.Prefix) bool {
			return familyOf(address.Addr()) == family && schema.InsideOverlay(netip.PrefixFrom(address.Addr(), address.Addr().BitLen()), r.rt.Overlay)
		}
		if !slices.ContainsFunc(held, inOverlay) {
			status.Unaddressed = append(status.Unaddressed, family)
		}
	}
	return exitView{on: true, network: network, forwarded: forwarded, unaddressed: status.Unaddressed, fallback: mode.Refuses(), lan: schemaPrefixes(mode.LAN)}, status
}

// reportExit records each skip and each family the tun holds no overlay
// address of that now holds and the last pass's status did not as begun, and
// each the last held that now does not as ended, a pass in mode off and a
// withdrawal, whose status is nil, ending all of them, and keeps now as the last
func (r *Reconciler) reportExit(now *ExitStatus) {
	var was, is ExitStatus
	if r.exitStatus != nil {
		was = *r.exitStatus
	}
	if now != nil {
		is = *now
	}
	for _, skip := range is.Skipped {
		if !slices.Contains(was.Skipped, skip) {
			r.reportSkip(slog.LevelWarn, "kernel leaves a link cap.exit forward matches out of the mode", skip, true)
		}
	}
	for _, skip := range was.Skipped {
		if !slices.Contains(is.Skipped, skip) {
			r.reportSkip(slog.LevelInfo, "kernel no longer leaves a link cap.exit forward matched out of the mode", skip, false)
		}
	}
	for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
		if before, after := slices.Contains(was.Unaddressed, family), slices.Contains(is.Unaddressed, family); before != after {
			r.reportFamily(family, before)
		}
	}
	r.exitStatus = now
}

func (r *Reconciler) reportFamily(family Family, addressed bool) {
	level, message := slog.LevelWarn, "kernel runs mode off's rules in a family, the tun holding no overlay address of it"
	if addressed {
		level, message = slog.LevelInfo, "kernel no longer counts a family as one the tun holds no overlay address of"
	}
	slog.Log(context.Background(), level, message, "family", string(family))
	r.rt.Events.Emit("kernel.exit", "", slog.String("family", string(family)), slog.Bool("addressed", addressed))
}

func (r *Reconciler) reportSkip(level slog.Level, message string, skip ForwardSkip, skipped bool) {
	attrs := []slog.Attr{slog.String("entry", skip.Entry), slog.String("link", skip.Link), slog.String("reason", skip.Reason)}
	slog.LogAttrs(context.Background(), level, message, attrs...)
	r.rt.Events.Emit("kernel.forward", "", append(attrs, slog.Bool("skipped", skipped))...)
}

// skipReason says why the mode never forwards a link's traffic, or is empty
func skipReason(name, tun string, network NetworkState) string {
	switch name {
	case tun:
		return "the mesh's own tun"
	case loopback:
		return "the loopback link"
	case network.IPv4.Default.Interface:
		return "the link the IPv4 default leaves by"
	case network.IPv6.Default.Interface:
		return "the link the IPv6 default leaves by"
	}
	return ""
}

// isPattern reports an entry holding one of path.Match's special characters,
// which matches a set of names rather than naming one link
func isPattern(entry string) bool { return strings.ContainsAny(entry, `*?[\`) }
