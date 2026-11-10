// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

// Package registry reads the trust document and indexes each node's key and endpoints.
package registry

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"

	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/internal/underlay"
	"ranet3.com/pkgs/ranet3/schema"
)

// errUnprepared refuses a resolution handed no Prepare, never read as one that does nothing,
// since a query left to the host's routes can follow the mesh's own into its tun
var errUnprepared = errors.New("registry: no Prepare to keep the resolver's sockets out of the mesh")

type Registry []Organization

type Organization struct {
	PublicKey    string `json:"public_key"` // PEM SubjectPublicKeyInfo, one Ed25519 key shared by every node in the org
	Organization string `json:"organization"`
	Nodes        []Node `json:"nodes"`
}

type Node struct {
	CommonName string          `json:"common_name"`
	Endpoints  []Endpoint      `json:"endpoints"`
	Remarks    json.RawMessage `json:"remarks"`
}

type Endpoint struct {
	SerialNumber  string  `json:"serial_number"`
	AddressFamily string  `json:"address_family"` // "ip4" or "ip6"
	Address       *string `json:"address"`        // literal IP, hostname, or absent (wildcard)
	Port          uint16  `json:"port"`
}

// Load reads the document at path and indexes it
func Load(path string) (*Index, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("registry: read %s: %w", path, err)
	}
	var r Registry
	if err := jsonv2.Unmarshal(b, &r, jsonv2.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("registry: parse %s: %w", path, err)
	}
	return New(r)
}

func (r Registry) Validate() error {
	// a common name is unique across every block of its organization, or two blocks with different keys would leave the order of the array to decide which key authenticates the node
	nodes := make(map[string]map[string]struct{}, len(r))
	for _, organization := range r {
		if organization.Organization == "" {
			return fmt.Errorf("registry: organization name is required")
		}
		if _, err := organization.publicKey(); err != nil {
			return err
		}
		named := nodes[organization.Organization]
		if named == nil {
			named = make(map[string]struct{}, len(organization.Nodes))
			nodes[organization.Organization] = named
		}
		for _, node := range organization.Nodes {
			if node.CommonName == "" {
				return fmt.Errorf("registry: organization %q has a node without common_name", organization.Organization)
			}
			if _, exists := named[node.CommonName]; exists {
				return fmt.Errorf("registry: duplicate node %q in organization %q", node.CommonName, organization.Organization)
			}
			named[node.CommonName] = struct{}{}
			endpoints := make(map[string]struct{}, len(node.Endpoints))
			for _, endpoint := range node.Endpoints {
				if endpoint.SerialNumber == "" || endpoint.Port == 0 || (endpoint.AddressFamily != "ip4" && endpoint.AddressFamily != "ip6") {
					return fmt.Errorf("registry: node %q has an invalid endpoint", node.CommonName)
				}
				if _, exists := endpoints[endpoint.SerialNumber]; exists {
					return fmt.Errorf("registry: duplicate endpoint %q on node %q", endpoint.SerialNumber, node.CommonName)
				}
				endpoints[endpoint.SerialNumber] = struct{}{}
			}
		}
	}
	return nil
}

// Index is a registry keyed by identity, every key parsed once
// it is never changed after New, so any number of handshakes read it at once
type Index struct {
	nodes         map[identity.Identity]indexedNode
	order         []identity.Identity
	organizations int
	underlay      []netip.Addr
}

// indexedNode keeps the key of the block that lists the node, since two blocks of one organization may hold different keys
type indexedNode struct {
	key     ed25519.PublicKey
	targets []Target
}

// Target is one endpoint of a node, with the identity the node answers to there
type Target struct {
	ID identity.Identity
	Endpoint
}

// New indexes a document Validate accepts
func New(document Registry) (*Index, error) {
	if err := document.Validate(); err != nil {
		return nil, err
	}
	x := &Index{nodes: make(map[identity.Identity]indexedNode), organizations: len(document)}
	for _, organization := range document {
		key, err := organization.publicKey()
		if err != nil {
			return nil, err
		}
		for _, node := range organization.Nodes {
			id, err := identity.From(organization.Organization, node.CommonName, "")
			if err != nil {
				return nil, err
			}
			indexed := indexedNode{key: key}
			for _, endpoint := range node.Endpoints {
				indexed.targets = append(indexed.targets, Target{ID: id.At(endpoint.SerialNumber), Endpoint: endpoint})
				if !endpoint.Dialable() {
					continue
				}
				if address, err := netip.ParseAddr(*endpoint.Address); err == nil {
					x.underlay = append(x.underlay, address)
				}
			}
			x.nodes[id] = indexed
			x.order = append(x.order, id)
		}
	}
	return x, nil
}

// Key is the key that must verify the AUTH of a peer asserting id, or why id may not join
// a node's identity asks about the node alone, and an endpoint's asks that the node lists that endpoint too
func (x *Index) Key(id identity.Identity) (ed25519.PublicKey, error) {
	node, ok := x.nodes[id.Node()]
	if !ok {
		return nil, fmt.Errorf("registry: %s is not in the trust document", id.Node())
	}
	if id != id.Node() && !slices.ContainsFunc(node.targets, func(target Target) bool { return target.ID == id }) {
		return nil, fmt.Errorf("registry: %s lists no endpoint %s", id.Node(), id)
	}
	return node.key, nil
}

// Targets is every endpoint of id's node in file order, or the one id names, and nothing the document does not list
func (x *Index) Targets(id identity.Identity) []Target {
	node := x.nodes[id.Node()]
	if id == id.Node() {
		return node.targets
	}
	for _, target := range node.targets {
		if target.ID == id {
			return []Target{target}
		}
	}
	return nil
}

// Nodes is every node the document lists, in file order
func (x *Index) Nodes() []identity.Identity { return x.order }

// Underlay is the address of every endpoint a dialer would take whose address is a literal
func (x *Index) Underlay() []netip.Addr { return x.underlay }

// Size is how many organization blocks and nodes the document holds
func (x *Index) Size() (organizations, nodes int) { return x.organizations, len(x.order) }

// publicKey parses the block's Ed25519 SubjectPublicKeyInfo PEM
func (o Organization) publicKey() (ed25519.PublicKey, error) {
	blk, _ := pem.Decode([]byte(o.PublicKey))
	if blk == nil {
		return nil, fmt.Errorf("registry: organization %q: no PEM block in public_key", o.Organization)
	}
	pub, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("registry: organization %q: parse public key: %w", o.Organization, err)
	}
	ed, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("registry: organization %q: public key is not Ed25519", o.Organization)
	}
	return ed, nil
}

// ResolveRemote resolves an endpoint's address for dialing. A literal IP of
// the endpoint's declared address family is used directly, and one of the
// other family is refused. A hostname is resolved through DNS and filtered to
// the declared family.
//
// The context makes shutdown prompt: a hostname whose resolver is
// unreachable otherwise holds the dialer for the resolver's own timeout, and
// the client waits for every dialer before it returns.
//
// overlay is the overlay as the dial reads it, which a reload moves. On linux
// and darwin, where Go's resolver opens its own sockets, prepare readies each
// query's socket toward a nameserver outside the overlay, and one inside it
// goes as it is. Elsewhere prepare reaches no query socket. A nil prepare is
// refused.
func (e Endpoint) ResolveRemote(ctx context.Context, overlay []schema.Prefix, prepare underlay.Prepare) (net.IP, error) {
	if prepare == nil {
		return nil, errUnprepared
	}
	if e.Address == nil {
		return nil, fmt.Errorf("registry: endpoint %s has no address", e.SerialNumber)
	}
	if ip := net.ParseIP(*e.Address); ip != nil {
		if !addressFamilyMatches(e.AddressFamily, ip) {
			return nil, fmt.Errorf("registry: endpoint %s address %s does not match declared family %s", e.SerialNumber, *e.Address, e.AddressFamily)
		}
		return ip, nil
	}
	ips, err := resolverFor(overlay, prepare).LookupIP(ctx, resolverNetwork(e.AddressFamily), *e.Address)
	if err != nil {
		return nil, fmt.Errorf("registry: resolve %s: %w", *e.Address, err)
	}
	for _, ip := range ips {
		if addressFamilyMatches(e.AddressFamily, ip) {
			return ip, nil
		}
	}
	return nil, fmt.Errorf("registry: %s has no %s address", *e.Address, e.AddressFamily)
}

// resolverNetwork narrows the lookup to the family this endpoint declares, so
// a name with only the other family's records fails at the resolver rather
// than after it.
func resolverNetwork(family string) string {
	switch family {
	case "ip4":
		return "ip4"
	case "ip6":
		return "ip6"
	default:
		return "ip"
	}
}

// Dialable reports whether this endpoint could ever be reached, deciding it
// without a resolver, so that a dialer is never started for one no attempt can
// fix. On a community registry most peers carry no address at all, and
// among the rest are an empty string and an address written as a prefix.
//
// A name is taken on trust, because only a resolver can answer for one and its
// answer changes. A literal is not: an address of the wrong family is a
// mistake in the registry that no lookup will fix.
func (e Endpoint) Dialable() bool {
	if e.Address == nil || *e.Address == "" {
		return false
	}
	if address, err := netip.ParseAddr(*e.Address); err == nil {
		// netip rather than net.ParseIP, which refuses a zone: a link-local
		// with one is a literal the resolver takes, so refusing it here would
		// give up on an endpoint a dial can use.
		return addressFamilyMatches(e.AddressFamily, address.WithZone("").AsSlice())
	}
	return !strings.ContainsAny(*e.Address, ":/ ")
}

func addressFamilyMatches(family string, ip net.IP) bool {
	switch family {
	case "ip4":
		return ip.To4() != nil
	case "ip6":
		return ip.To4() == nil
	default:
		return false
	}
}
