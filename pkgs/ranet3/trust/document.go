// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package trust

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"ranet3.com/pkgs/ranet3/identity"
)

// The field order is also the authored JSON member order.
type Document struct {
	Nodes []Node `json:"nodes"`
}

type Node struct {
	Endpoints []Endpoint `json:"endpoints"`
	Key       *string    `json:"key,omitempty"`
	Name      string     `json:"name"`
}

type Endpoint struct {
	Address *string `json:"address,omitempty"`
	Family  string  `json:"family"`
	ID      *string `json:"id,omitempty"`
	Port    uint32  `json:"port"`
}

func (d Document) Validate() error {
	if d.Nodes == nil || len(d.Nodes) > MaxEntries {
		return fmt.Errorf("trust: nodes must be present and have at most %d entries", MaxEntries)
	}
	names := make(map[string]bool, len(d.Nodes))
	keyOwners := make(map[string]string)
	for _, node := range d.Nodes {
		if err := printable(node.Name); err != nil {
			return fmt.Errorf("trust: node name: %w", err)
		}
		id, err := identity.Parse(node.Name)
		if err != nil || id.String() != node.Name || id.Node() != id {
			return fmt.Errorf("trust: invalid canonical node name %q", node.Name)
		}
		folded := strings.ToLower(node.Name)
		if names[folded] {
			return fmt.Errorf("trust: duplicate node name %q under ASCII case folding", node.Name)
		}
		names[folded] = true
		if node.Key != nil {
			key, err := ParseAuthorityKey(*node.Key)
			if err != nil || key.Algorithm != algorithmEd25519 {
				return fmt.Errorf("trust: node %q must have a valid Ed25519 key: %v", node.Name, err)
			}
			organization, _ := id.NodeParts()
			if owner, held := keyOwners[string(key.DER)]; held && owner != organization {
				return fmt.Errorf("trust: key of node %q is shared across organizations", node.Name)
			}
			keyOwners[string(key.DER)] = organization
		}
		if node.Endpoints == nil || len(node.Endpoints) > MaxEntries {
			return fmt.Errorf("trust: node %q needs endpoints with at most %d entries", node.Name, MaxEntries)
		}
		var endpointNames map[string]bool
		for _, endpoint := range node.Endpoints {
			if err := endpoint.validate(); err != nil {
				return fmt.Errorf("trust: node %q: %w", node.Name, err)
			}
			if endpoint.ID != nil {
				if endpointNames == nil {
					endpointNames = make(map[string]bool)
				}
				folded := strings.ToLower(*endpoint.ID)
				if endpointNames[folded] {
					return fmt.Errorf("trust: node %q has duplicate endpoint id %q", node.Name, *endpoint.ID)
				}
				endpointNames[folded] = true
			}
		}
	}
	return nil
}

func (e Endpoint) validate() error {
	if e.Family != "ip4" && e.Family != "ip6" {
		return fmt.Errorf("trust: invalid endpoint family %q", e.Family)
	}
	if e.Port == 0 || e.Port > 65535 {
		return fmt.Errorf("trust: invalid endpoint port %d", e.Port)
	}
	if e.ID != nil {
		if len(*e.ID) == 0 || len(*e.ID) > 64 {
			return fmt.Errorf("trust: invalid endpoint id %q", *e.ID)
		}
		if err := printable(*e.ID); err != nil {
			return err
		}
		if (*e.ID)[0] == ' ' || (*e.ID)[len(*e.ID)-1] == ' ' || strings.Contains(*e.ID, "  ") {
			return fmt.Errorf("trust: invalid spaces in endpoint id %q", *e.ID)
		}
		for i := range len(*e.ID) {
			c := (*e.ID)[i]
			if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || strings.ContainsRune(" '()+,-./:=?", rune(c))) {
				return fmt.Errorf("trust: invalid PrintableString endpoint id %q", *e.ID)
			}
		}
	}
	if e.Address != nil {
		if err := printable(*e.Address); err != nil {
			return fmt.Errorf("trust: endpoint address: %w", err)
		}
		if *e.Address == "" {
			return errors.New("trust: empty endpoint address")
		}
		if addr, err := netip.ParseAddr(*e.Address); err == nil {
			if addr.Is4In6() || addr.Zone() != "" || addr.String() != *e.Address || addr.Is4() != (e.Family == "ip4") {
				return fmt.Errorf("trust: noncanonical or mismatched endpoint address %q", *e.Address)
			}
		} else if err := hostName(*e.Address); err != nil {
			return err
		}
	}
	return nil
}

func printable(text string) error {
	for i := range len(text) {
		c := text[i]
		if c < 0x20 || c > 0x7e || c == '"' || c == '\\' {
			return fmt.Errorf("trust: text %q is not printable unescaped ASCII", text)
		}
	}
	return nil
}
