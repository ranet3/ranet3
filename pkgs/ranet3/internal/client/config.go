// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

package client

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log"
	"maps"
	"net/netip"
	"slices"
	"strings"

	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/ike"
	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/packet"
	"ranet3.com/pkgs/ranet3/internal/registry"
	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
)

// refuseExitModeHere refuses cap.exit where this platform has no exit mode, and fallback = "none" where it has no filter
// the start checks it ahead of every other capability's platform refusal, so a host writing cap.exit beside cap.border is told about cap.exit
// fallback goes first, so a host asking for the switch is told the switch is missing rather than only the mode
func refuseExitModeHere(cfg *config.Config) error {
	if cfg.Cap.Exit == nil {
		return nil
	}
	if err := kernel.RefuseFallback(*cfg.Cap.Exit); err != nil {
		return err
	}
	return kernel.RefuseExitMode()
}

// refuseForwardedHere refuses a cap.exit forward entry naming the tun or a link a default leaves by, as the watch reads the host now
func refuseForwardedHere(cfg *config.Config, tun string, network networkSource) error {
	if cfg.Cap.Exit == nil || network == nil {
		return nil
	}
	state, _ := network.State()
	return cfg.Cap.Exit.RefuseNamed(tun, state)
}

// validateRuntimeConfig is the startup check, which refuses a configuration the trust document does not support and logs a peer it only cannot dial
func validateRuntimeConfig(cfg *config.Config, privateKey ed25519.PrivateKey, x *registry.Index) error {
	if err := refuseExitModeHere(cfg); err != nil {
		return err
	}
	families, err := validateLocalConfig(cfg, privateKey, x)
	if err != nil {
		return err
	}
	if err := refuseEgressAdvertisedUnconditionally(cfg); err != nil {
		return err
	}
	refuse, skip := validatePeers(effectivePeers(cfg, x), x, families)
	for _, problem := range skip {
		log.Printf("%v, so nothing will dial it", problem)
	}
	refuse = append(refuse, validateAliases(cfg.Auth.Aliases, x)...)
	return errors.Join(refuse...)
}

// an entry naming what the trust document lacks is a typo or a peer the document no longer holds
func validateAliases(aliases ike.Aliases, x *registry.Index) []error {
	var problems []error
	for entry, named := range aliases.Entries() {
		if _, err := x.Key(named.Node()); err != nil {
			problems = append(problems, fmt.Errorf("config: %s names %s, a node the trust document does not name", entry, named))
			continue
		}
		if named != named.Node() && len(x.Targets(named)) == 0 {
			problems = append(problems, fmt.Errorf("config: %s names %s, an endpoint the trust document does not list", entry, named))
		}
	}
	return problems
}

// validateLocalConfig checks what this node says about itself, and reports the address families its own endpoints cover
// each refusal is fatal on a reload too, since a node the trust document no longer names, or whose key no longer matches, should not carry on with a new one
func validateLocalConfig(cfg *config.Config, privateKey ed25519.PrivateKey, x *registry.Index) (map[string]struct{}, error) {
	publicKey, err := x.Key(cfg.Node)
	if err != nil {
		return nil, fmt.Errorf("config: node: %w", err)
	}
	if !bytes.Equal(privateKey.Public().(ed25519.PublicKey), publicKey) {
		return nil, fmt.Errorf("config: auth.key does not match the key the trust document holds for %s", cfg.Node)
	}
	localFamilies := make(map[string]struct{}, len(cfg.Link.Endpoints))
	for i, local := range cfg.LocalEndpoints() {
		endpoint := cfg.Link.Endpoints[i]
		registered := x.Targets(local)
		if len(registered) == 0 || registered[0].AddressFamily != endpoint.Family {
			return nil, fmt.Errorf("config: link.endpoints %q/%s does not match the trust document", endpoint.Serial, endpoint.Family)
		}
		localFamilies[endpoint.Family] = struct{}{}
	}
	if err := validateExtraCost(cfg, x); err != nil {
		return nil, err
	}
	return localFamilies, nil
}

// validateExtraCost refuses an organization or node cap.babel cost.extra names and the trust document does not, since a misspelled name would charge nobody
func validateExtraCost(cfg *config.Config, x *registry.Index) error {
	extra := cfg.Babel().Cost.Extra
	known := make(map[string]struct{})
	for _, node := range x.Nodes() {
		organization, _ := node.NodeParts()
		known[organization] = struct{}{}
	}
	for _, organization := range slices.Sorted(maps.Keys(extra.Org)) {
		if _, ok := known[organization]; !ok {
			return fmt.Errorf("config: cap.babel cost.extra org %q is not an organization of the trust document", organization)
		}
	}
	for _, node := range extra.Nodes() {
		if _, err := x.Key(node); err != nil {
			return fmt.Errorf("config: cap.babel cost.extra node %s is not a node of the trust document", node)
		}
	}
	return nil
}

// refuseEgressAdvertisedUnconditionally rejects a prefix cap.egress offers to
// carry that cap.route announces as well. The capability withholds a prefix
// whose translation chain does not read back as written, so that this node
// stops attracting traffic it would have to drop. An unconditional
// announcement of the same prefix takes that back and leaves the withholding
// reporting as working while changing nothing on the wire.
//
// It is here rather than in either capability because each half is in a
// different block, which is the one check neither can make for itself.
func refuseEgressAdvertisedUnconditionally(cfg *config.Config) error {
	if cfg.Egress() == nil {
		return nil
	}
	for _, entry := range cfg.Egress().Advertise {
		for _, announced := range cfg.Routes().Announced() {
			if announced.Masked() != entry.Prefix {
				continue
			}
			return fmt.Errorf("config: cap.egress advertise %s is announced by cap.route as well, which would advertise it whether or not its translation rule is installed", entry)
		}
	}
	return nil
}

// MeshAddresses is every address this node carries on the mesh, which cap.egress translates into the mesh under
// it is the host prefixes cap.route announces and what cap.table assigns
// the announced ones count because a node that configures its tun externally assigns nothing
func MeshAddresses(cfg *config.Config) []netip.Addr {
	var out []netip.Addr
	for _, prefix := range slices.Concat(cfg.Routes().Announced(), assignedPrefixes(cfg)) {
		// Only a host prefix. A shorter one is a range this node carries
		// traffic for rather than an address it answers at, and translating
		// to its base address would send replies to a host that may not exist.
		if prefix.IsSingleIP() {
			out = append(out, prefix.Addr())
		}
	}
	return out
}

// assignedPrefixes is every prefix cap.table assigns, the ones cap.route announces among them where it asks for those
func assignedPrefixes(cfg *config.Config) []netip.Prefix {
	if cfg.Cap.Table == nil {
		return nil
	}
	return cfg.Cap.Table.Assigned(cfg.Routes().Announced())
}

// assignedAddresses is every address cap.table assigns, whatever the length of its prefix, each of which the speaker takes as owned by this node
func assignedAddresses(cfg *config.Config) []netip.Addr {
	assigned := assignedPrefixes(cfg)
	out := make([]netip.Addr, 0, len(assigned))
	for _, prefix := range assigned {
		out = append(out, prefix.Addr())
	}
	return out
}

// answerSources is the router-id of each family, RFC 1812 section 2.2.7, a cap.table address before a host prefix cap.route announces
// and the End SID of cap.segment local that transit's IPv6 errors come from
// each the first address of its kind a router forwards packets from, as InvalidSource says, that is no IPv4 address mapped into IPv6 and that an announced prefix with no source, and that does not count as a default with cap.border's overlay, covers
// a sender's strict reverse path check drops an answer from any other, which the mesh does not route back to this node
// it walks the node's addresses apart from MeshAddresses, which takes host prefixes alone and the announced ones first
// since a cap.table address leads, whatever the length of the prefix it is assigned in
func answerSources(cfg *config.Config) netstack.AnswerSources {
	routes, overlay := cfg.Routes(), cfg.Overlay()
	covered := func(address netip.Addr) bool {
		return !packet.InvalidSource(address) && !address.Is4In6() && slices.ContainsFunc(routes.Announce, func(entry schema.Announce) bool {
			return !entry.From.IsValid() && !schema.CapturesTheMachine(entry.Prefix.Prefix, overlay) && entry.Prefix.Contains(address)
		})
	}
	candidates := assignedPrefixes(cfg)
	for _, entry := range routes.Announce {
		if entry.Prefix.IsSingleIP() {
			candidates = append(candidates, entry.Prefix.Prefix)
		}
	}
	var sources netstack.AnswerSources
	for _, prefix := range candidates {
		address := prefix.Addr()
		switch {
		// a network's base address names no host, RFC 1812 section 4.2.2.11, and over IPv6 it is the Subnet-Router anycast address, RFC 4291 section 2.6.1
		// nor does an IPv4 network's all-ones host, its directed broadcast, which the same section bars as a source address
		case !prefix.IsSingleIP() && prefix.Masked().Addr() == address, directedBroadcast(prefix), !covered(address):
		case address.Is4() && !sources.Router4.IsValid():
			sources.Router4 = address
		case address.Is6() && !sources.Router6.IsValid():
			sources.Router6 = address
		}
	}
	for _, segment := range cfg.Segments().Local {
		if segment.Behavior == srv6.BehaviorEnd && covered(segment.SID.Addr) {
			sources.SID = segment.SID.Addr
			break
		}
	}
	return sources
}

// directedBroadcast reports whether prefix's address is the all-ones host of its IPv4 network, RFC 1812 section 4.2.2.11
// a /31 has none, its two addresses being its two hosts, RFC 3021
func directedBroadcast(prefix netip.Prefix) bool {
	if !prefix.Addr().Is4() || prefix.Bits() >= 31 {
		return false
	}
	address := prefix.Addr().As4()
	host := uint32(1)<<(32-prefix.Bits()) - 1
	return (uint32(address[0])<<24|uint32(address[1])<<16|uint32(address[2])<<8|uint32(address[3]))&host == host
}

// effectivePeers is who this node dials: the configured list, or when all is set that list followed by every other node the trust document names, the N-to-N reconciliation ranet does
// this node is never in it, and the document's order is kept, so one pair of files gives one order on every start
func effectivePeers(cfg *config.Config, x *registry.Index) []identity.Identity {
	if !cfg.Dial.All {
		return cfg.Dial.To
	}
	peers := slices.Clone(cfg.Dial.To)
	for _, node := range x.Nodes() {
		// an explicit entry wins for its node, since it can pin a serial and a generated one would dial every endpoint
		if node == cfg.Node || slices.ContainsFunc(cfg.Dial.To, func(peer identity.Identity) bool { return peer.Node() == node }) {
			continue
		}
		peers = append(peers, node)
	}
	return peers
}

type dial struct {
	// path names the dialer, and is the path of the session it opens where the peer is an endpoint
	path    string
	local   config.Endpoint
	localID identity.Identity
	// peer is a node, or the one endpoint of it dial.to pins
	peer identity.Identity
	// generated marks a peer dial.all took from the trust document
	generated bool
}

func dials(cfg *config.Config, x *registry.Index) []dial {
	peers, locals := effectivePeers(cfg, x), cfg.LocalEndpoints()
	out := make([]dial, 0, len(cfg.Link.Endpoints)*len(peers))
	for i, local := range cfg.Link.Endpoints {
		for j, peer := range peers {
			out = append(out, dial{path: identity.Path(peer, locals[i]), local: local, localID: locals[i],
				peer: peer, generated: j >= len(cfg.Dial.To)})
		}
	}
	return out
}

// validatePeers splits the peers the trust document cannot support into what a startup refuses and what it only logs, and a reload logs both
// a node with no endpoint in a local family is only logged, or a v4-only host could never start against a document holding v6-only nodes
func validatePeers(peers []identity.Identity, x *registry.Index, localFamilies map[string]struct{}) (refuse, skip []error) {
	for _, peer := range peers {
		if _, err := x.Key(peer.Node()); err != nil {
			refuse = append(refuse, fmt.Errorf("config: peer node %s not found", peer.Node()))
			continue
		}
		targets := x.Targets(peer)
		if peer != peer.Node() {
			if len(targets) == 0 {
				refuse = append(refuse, fmt.Errorf("config: peer endpoint %s not found", peer))
				continue
			}
			if _, ok := localFamilies[targets[0].AddressFamily]; !ok {
				refuse = append(refuse, fmt.Errorf("config: peer endpoint %s has no matching local address family", peer))
				continue
			}
			if !targets[0].Dialable() {
				skip = append(skip, fmt.Errorf("config: peer endpoint %s carries no address", peer))
			}
			continue
		}
		// an endpoint the dialer will not take is reported here once rather than on every attempt
		compatible, reachable := false, false
		for _, endpoint := range targets {
			if _, ok := localFamilies[endpoint.AddressFamily]; !ok {
				continue
			}
			compatible = true
			if endpoint.Dialable() {
				reachable = true
				break
			}
		}
		switch {
		case !compatible:
			skip = append(skip, fmt.Errorf("config: peer %s has no endpoint matching a local address family", peer))
		case !reachable:
			skip = append(skip, fmt.Errorf("config: peer %s has no endpoint carrying an address", peer))
		}
	}
	return refuse, skip
}

// warnUnbordered says so when the host forwards and the file writes no
// cap.border. A host on any of this node's links can then hand it a packet
// with a mesh source, which the kernel forwards into the tun and every peer
// takes as the mesh's own.
//
// a warning rather than a refusal, since forwarding moves under a running node
// and darwin, which forwards with no filter to offer, would otherwise not start at all
func warnUnbordered(cfg *config.Config, forwards func() (v4, v6 bool)) {
	if cfg.Cap.Border != nil {
		return
	}
	v4, v6 := forwards()
	var on []string
	if v4 {
		on = append(on, "IPv4")
	}
	if v6 {
		on = append(on, "IPv6")
	}
	if len(on) == 0 {
		return
	}
	log.Printf("config: this node forwards %s and holds no cap.border, so a host on any of its links can forge a mesh source through it into the mesh: add cap.border with the prefixes the mesh numbers its nodes from",
		strings.Join(on, " and "))
}

// warnCountedAdvertisements names each advertisement in cap.route or
// cap.egress that schema.CapturesTheMachine counts and that is not a default,
// which makes this node an exit for its family as a default does. The file
// loads all the same.
func warnCountedAdvertisements(cfg *config.Config) {
	warn := func(key, verb string, prefix netip.Prefix) {
		if prefix.Bits() > 0 && schema.CapturesTheMachine(prefix, cfg.Overlay()) {
			log.Printf("config: %s %s %s, outside the overlay and shorter than /%d for IPv4 or /%d for IPv6 or holding the unspecified address, which counts as a default and makes this node an exit for its family, as routing.md says",
				key, verb, prefix, schema.MinSubnetBits4, schema.MinSubnetBits6)
		}
	}
	for _, entry := range cfg.Routes().Announce {
		warn("cap.route", "announces", entry.Prefix.Prefix)
	}
	if exit := cfg.Egress(); exit != nil {
		for _, prefix := range exit.Advertise {
			warn("cap.egress", "advertises", prefix.Prefix)
		}
	}
}
