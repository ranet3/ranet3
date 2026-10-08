// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package control

import (
	"io"
	"net/netip"
	"strings"
	"time"
)

// PathDebugNetmon is the host's network as the node's network watch reads it
const PathDebugNetmon = PathDebug + "netmon"

func init() {
	debugRead(PathDebugNetmon, classRead, "netmon", NetmonSource.DebugNetmon)
}

// NetmonSource is a Source that watches the host's network
type NetmonSource interface {
	DebugNetmon() NetmonInfo
}

// NetmonInfo is the network watch's latest reading and the last change it acted on
type NetmonInfo struct {
	// Watching is false on a platform without a network watch, which leaves the rest empty
	Watching bool           `json:"watching"`
	Families []NetmonFamily `json:"families,omitempty"`
	// LastChange is absent before the first
	LastChange *NetmonChange `json:"last_change,omitempty"`
}

// NetmonDefault is the host's own default route of one family, empty where it has none
type NetmonDefault struct {
	Interface string `json:"interface,omitempty"`
	// Gateway is absent where the route leaves through a link
	Gateway netip.Addr `json:"gateway,omitzero"`
}

func (d NetmonDefault) String() string {
	switch {
	case d.Interface == "":
		return "none"
	case !d.Gateway.IsValid():
		return d.Interface
	}
	return d.Interface + " via " + d.Gateway.String()
}

// NetmonFamily is one family outside the mesh, the global unicast addresses of its up interfaces among it
type NetmonFamily struct {
	Family    string        `json:"family"`
	Default   NetmonDefault `json:"default"`
	Addresses []netip.Addr  `json:"addresses"`
}

// NetmonChange is one change the watch signaled, which probed every session and woke every dialer
type NetmonChange struct {
	At time.Time `json:"at"`
	// Ago is how long before the answer it happened
	Ago      Duration             `json:"ago"`
	Families []NetmonFamilyChange `json:"families"`
}

// NetmonFamilyChange lists the moves in one family
type NetmonFamilyChange struct {
	Family string `json:"family"`
	// DefaultWas and Default are present where the default moved
	DefaultWas *NetmonDefault `json:"default_was,omitempty"`
	Default    *NetmonDefault `json:"default,omitempty"`
	Added      []netip.Addr   `json:"added,omitempty"`
	Removed    []netip.Addr   `json:"removed,omitempty"`
}

// Netmon reads the host's network as the daemon's watch last read it
func (c *Client) Netmon() (NetmonInfo, error) { return read[NetmonInfo](c, PathDebugNetmon) }

// RenderNetmon writes each family's default and addresses, then the last change by what moved
func RenderNetmon(w io.Writer, info NetmonInfo) {
	if !info.Watching {
		pairs(w, [][]string{{"Watching", "no, this platform has no network watch"}})
		return
	}
	var rows [][]string
	for _, family := range info.Families {
		name := familyLabel(family.Family)
		rows = append(rows,
			[]string{name + " default", family.Default.String()},
			[]string{name + " addresses", addressText(family.Addresses)})
	}
	if info.LastChange == nil {
		rows = append(rows, []string{"Changed", "not since the watch started"})
		pairs(w, rows)
		return
	}
	change := info.LastChange
	rows = append(rows, []string{"Changed", sinceText(time.Duration(change.Ago)) + " ago, at " + change.At.UTC().Format(time.DateTime) + " UTC"})
	for _, family := range change.Families {
		name := familyLabel(family.Family)
		if family.Default != nil && family.DefaultWas != nil {
			rows = append(rows, []string{name + " default", "now " + family.Default.String() + ", was " + family.DefaultWas.String()})
		}
		if len(family.Added) > 0 {
			rows = append(rows, []string{name + " added", addressText(family.Added)})
		}
		if len(family.Removed) > 0 {
			rows = append(rows, []string{name + " removed", addressText(family.Removed)})
		}
	}
	pairs(w, rows)
}

// familyLabel cases a family name as the acronym it is
func familyLabel(family string) string { return strings.Replace(family, "ip", "IP", 1) }

func addressText(addresses []netip.Addr) string {
	if len(addresses) == 0 {
		return "none"
	}
	text := make([]string, 0, len(addresses))
	for _, address := range addresses {
		text = append(text, address.String())
	}
	return strings.Join(text, " ")
}
