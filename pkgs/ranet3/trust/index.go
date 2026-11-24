// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package trust

import (
	"crypto/ed25519"
	"fmt"
	"net/netip"
	"slices"

	"ranet3.com/pkgs/ranet3/identity"
)

// Index keeps only keyed nodes' endpoints with a wire identity. It is immutable
// after construction. A caller must not mutate the document or returned slices.
type Index struct {
	nodes    map[identity.Identity]indexedNode
	order    []identity.Identity
	underlay []netip.Addr
}

type indexedNode struct {
	key     ed25519.PublicKey
	targets []Target
}

// Target names one peer endpoint and carries its address for dialing.
type Target struct {
	ID identity.Identity
	Endpoint
}

func NewIndex(document Document) (*Index, error) {
	if err := document.Validate(); err != nil {
		return nil, err
	}
	index := &Index{nodes: make(map[identity.Identity]indexedNode, len(document.Nodes)), order: make([]identity.Identity, 0, len(document.Nodes))}
	for _, node := range document.Nodes {
		id, err := identity.Parse(node.Name)
		if err != nil {
			return nil, fmt.Errorf("trust: index node: %w", err)
		}
		entry := indexedNode{}
		if node.Key != nil {
			key, err := ParseAuthorityKey(*node.Key)
			if err != nil {
				return nil, fmt.Errorf("trust: index key of %s: %w", id, err)
			}
			entry.key = key.Public.(ed25519.PublicKey)
			for _, endpoint := range node.Endpoints {
				if endpoint.ID == nil {
					continue
				}
				entry.targets = append(entry.targets, Target{ID: id.At(*endpoint.ID), Endpoint: endpoint})
				if endpoint.Address != nil {
					if address, err := netip.ParseAddr(*endpoint.Address); err == nil {
						index.underlay = append(index.underlay, address)
					}
				}
			}
		}
		index.nodes[id] = entry
		index.order = append(index.order, id)
	}
	return index, nil
}

// Key admits a node under its raw key, and an endpoint only if it has an id.
func (x *Index) Key(id identity.Identity) (ed25519.PublicKey, error) {
	node, ok := x.nodes[id.Node()]
	if !ok {
		return nil, fmt.Errorf("trust: %s is not in the document", id.Node())
	}
	if len(node.key) == 0 {
		return nil, fmt.Errorf("trust: node %s is admitted by no raw key", id.Node())
	}
	if id != id.Node() && !slices.ContainsFunc(node.targets, func(target Target) bool { return target.ID == id }) {
		return nil, fmt.Errorf("trust: node %s lists no endpoint %s", id.Node(), id)
	}
	return node.key, nil
}

// Targets returns a node's keyed, identified endpoints in document order, or
// the one endpoint named by id. A keyless node has no targets.
func (x *Index) Targets(id identity.Identity) []Target {
	node := x.nodes[id.Node()]
	if id == id.Node() {
		return node.targets
	}
	for i := range node.targets {
		if node.targets[i].ID == id {
			return node.targets[i : i+1]
		}
	}
	return nil
}

func (x *Index) Nodes() []identity.Identity { return x.order }

// Underlay returns only the literal addresses of endpoints that may be dialed.
func (x *Index) Underlay() []netip.Addr { return x.underlay }
