// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package registry

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"slices"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// the pools are small, so a document often splits an organization across blocks under different keys and repeats a name
var (
	poolOrganizations = []string{"alpha", "beta", "gamma"}
	poolNames         = []string{"a", "b", "c", "d", "e"}
	poolSerials       = []string{"0", "1", "2", "3"}
	poolKeys          = map[string]ed25519.PublicKey{}
	poolPEMs          []string
)

func init() {
	for seed := range byte(4) {
		key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed + 1}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
		der, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			panic(err)
		}
		text := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
		poolKeys[text] = key
		poolPEMs = append(poolPEMs, text)
	}
}

func drawFrom(tc hegel.TestCase, pool []string) string {
	return pool[hegel.Draw(tc, pbt.Spanning(0, len(pool)-1))]
}

// drawDocument draws a document, an eighth of them carrying one of the mistakes Validate refuses that small pools do not make by themselves
func drawDocument(tc hegel.TestCase) Registry {
	document := make(Registry, hegel.Draw(tc, pbt.Spanning(0, 4)))
	for i := range document {
		block := &document[i]
		block.Organization, block.PublicKey = drawFrom(tc, poolOrganizations), drawFrom(tc, poolPEMs)
		block.Nodes = make([]Node, hegel.Draw(tc, pbt.Spanning(0, 3)))
		for j := range block.Nodes {
			node := &block.Nodes[j]
			node.CommonName = drawFrom(tc, poolNames)
			node.Endpoints = make([]Endpoint, hegel.Draw(tc, pbt.Spanning(0, 2)))
			for k := range node.Endpoints {
				node.Endpoints[k] = Endpoint{SerialNumber: drawFrom(tc, poolSerials), AddressFamily: "ip4", Port: 13000}
			}
		}
	}
	if len(document) == 0 || !hegel.Draw(tc, hegel.WeightedBooleans(1.0/8)) {
		return document
	}
	block := &document[hegel.Draw(tc, pbt.Spanning(0, len(document)-1))]
	switch hegel.Draw(tc, pbt.Spanning(0, 3)) {
	case 0:
		block.Organization = ""
	case 1:
		block.PublicKey = "not a key"
	case 2:
		block.Nodes = append(block.Nodes, Node{})
	default:
		block.Nodes = append(block.Nodes, Node{CommonName: "f", Endpoints: []Endpoint{{SerialNumber: "0", AddressFamily: "ip4"}}})
	}
	return document
}

// modelKey scans the document in file order: the block listing the node gives its key, where an endpoint is asked about only if the node lists that serial
func modelKey(document Registry, organization, name, serial string) (ed25519.PublicKey, bool) {
	for _, block := range document {
		for _, node := range block.Nodes {
			if block.Organization != organization || node.CommonName != name {
				continue
			}
			if serial != "" && !slices.ContainsFunc(node.Endpoints, func(e Endpoint) bool { return e.SerialNumber == serial }) {
				return nil, false
			}
			return poolKeys[block.PublicKey], true
		}
	}
	return nil, false
}

// modelTargets is the node's endpoints in file order, or the one serial names
func modelTargets(document Registry, organization, name, serial string) []Target {
	var out []Target
	for _, block := range document {
		for _, node := range block.Nodes {
			if block.Organization != organization || node.CommonName != name {
				continue
			}
			for _, endpoint := range node.Endpoints {
				if serial == "" || serial == endpoint.SerialNumber {
					out = append(out, Target{ID: mustFrom(organization, name, endpoint.SerialNumber), Endpoint: endpoint})
				}
			}
		}
	}
	return out
}

func mustFrom(organization, name, serial string) identity.Identity {
	id, err := identity.From(organization, name, serial)
	if err != nil {
		panic(err)
	}
	return id
}

// the index answers every query, at both levels and for names the document does not hold, as the scan of the document does
func TestIndexAnswersAsTheDocumentReads(t *testing.T) {
	organizations := append(slices.Clone(poolOrganizations), "delta")
	names := append(slices.Clone(poolNames), "z")
	serials := append([]string{""}, append(slices.Clone(poolSerials), "9")...)
	pbt.Check(t, func(ht *hegel.T) {
		document := drawDocument(ht)
		x, err := New(document)
		if (err == nil) != (document.Validate() == nil) {
			ht.Fatalf("New returned %v where Validate returned %v for %+v", err, document.Validate(), document)
		}
		if err != nil {
			return
		}
		var nodes []identity.Identity
		for _, block := range document {
			for _, node := range block.Nodes {
				nodes = append(nodes, mustFrom(block.Organization, node.CommonName, ""))
			}
		}
		if !slices.Equal(x.Nodes(), nodes) {
			ht.Fatalf("Nodes is %v, want %v", x.Nodes(), nodes)
		}
		if blocks, count := x.Size(); blocks != len(document) || count != len(nodes) {
			ht.Fatalf("Size is %d blocks and %d nodes, want %d and %d", blocks, count, len(document), len(nodes))
		}
		for _, organization := range organizations {
			for _, name := range names {
				for _, serial := range serials {
					id := mustFrom(organization, name, serial)
					want, admitted := modelKey(document, organization, name, serial)
					got, err := x.Key(id)
					if admitted != (err == nil) || admitted && !got.Equal(want) {
						ht.Fatalf("Key(%s) = %x, %v, want %x, admitted %v, in %+v", id, got, err, want, admitted, document)
					}
					if targets := modelTargets(document, organization, name, serial); !slices.Equal(x.Targets(id), targets) {
						ht.Fatalf("Targets(%s) = %+v, want %+v", id, x.Targets(id), targets)
					}
				}
			}
		}
	})
}
