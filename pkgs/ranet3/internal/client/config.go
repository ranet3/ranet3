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
	"net/netip"
	"slices"
	"strings"

	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/registry"
)

// validateRuntimeConfig is the startup check, which refuses a configuration the trust document does not support and logs a peer it only cannot dial
func validateRuntimeConfig(cfg *config.Config, privateKey ed25519.PrivateKey, x *registry.Index) error {
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
	return errors.Join(refuse...)
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
	return localFamilies, nil
}

// refuseEgressAdvertisedUnconditionally rejects a prefix cap.egress offers to
// carry that cap.route announces as well. The capability withholds a prefix
// whose translation rule is not installed, so that this node stops attracting
// traffic it would have to drop. An unconditional announcement of the same
// prefix takes that back and leaves the withholding reporting as working while
// changing nothing on the wire.
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
	announced := cfg.Routes().Announced()
	var out []netip.Addr
	add := func(prefix netip.Prefix) {
		// Only a host prefix. A shorter one is a range this node carries
		// traffic for rather than an address it answers at, and translating
		// to its base address would send replies to a host that may not exist.
		if prefix.Bits() != prefix.Addr().BitLen() {
			return
		}
		out = append(out, prefix.Addr())
	}
	for _, prefix := range announced {
		add(prefix)
	}
	if table := cfg.Cap.Table; table != nil {
		for _, prefix := range table.Assigned(announced) {
			add(prefix)
		}
	}
	return out
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

// warnVRFWithoutL3mdev says so when this node's mesh lives in a VRF and no
// socket outside it will see a reply. See l3mdevAccept for what that costs.
//
// A warning rather than a refusal, as with forwarding: the sysctls can be set
// after this process starts, and a deployment that runs its services inside
// the VRF with "ip vrf exec" needs neither. What it must not be is silent,
// because the mesh comes up correct, the routes are right, and every service
// on the node is unreachable over it.
func warnVRFWithoutL3mdev(cfg *config.Config) {
	if cfg.Cap.Table == nil || cfg.Cap.Table.Name() == "" || l3mdevAccept() {
		return
	}
	log.Printf("config: the mesh is in vrf %s and net.ipv4.tcp_l3mdev_accept or net.ipv4.udp_l3mdev_accept is off, so a socket outside that vrf will not be matched by a reply arriving through it: every TCP and UDP flow to and from a mesh address fails while ping answers. Set both to 1, or run the services that use the mesh inside the vrf",
		cfg.Cap.Table.Name())
}

// warnUnforwardableTransit says so when this node offers to carry the mesh and
// the kernel will not.
//
// Babel carries no capability signal: a node that advertises a route is
// promising to forward it, and the only thing a peer ever learns is the
// advertisement. So a node that redistributes with forwarding off attracts
// traffic and drops it, and the sender is never told. Nothing here can fix
// that from the far end, which leaves saying it at the end that knows.
//
// A warning rather than a refusal, because forwarding can be turned on after
// this process starts and because cap.route transit is the setting that makes
// the promise match the machine.
func warnUnforwardableTransit(cfg *config.Config) {
	if !cfg.Routes().Transits() {
		return
	}
	v4, v6 := forwardingEnabled()
	if v4 && v6 {
		return
	}
	var off []string
	if !v4 {
		off = append(off, "IPv4")
	}
	if !v6 {
		off = append(off, "IPv6")
	}
	log.Printf("config: this node redistributes the routes it learns, so it is offering to carry the mesh, but %s forwarding is off: peers that select it will have their traffic dropped with nothing to tell them. Write transit = false under cap.route on a leaf, or turn forwarding on",
		strings.Join(off, " and "))
}
