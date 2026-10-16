// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package ike

import (
	"bytes"
	"encoding/hex"
	"maps"
	"net"
	"slices"
	"strconv"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// answerNames are the FQDNs the drawn tables write, few enough that one is often in both
var answerNames = []string{"a.testorg.example", "b.testorg.example", "c.testorg.example"}

// askings name each IDr the scripted initiator may ask for, each drawn outright
var askings = []string{"no IDr", "our DN", "another node's DN", "our KEY_ID text", "another node's KEY_ID text",
	"a remote alias", "a presented alias", "a remote alias it presents", "an ID neither table names"}

// loopbacks are the address each family's request arrives from
var loopbacks = map[Family]net.IP{IPv4: net.IPv4(127, 0, 0, 1), IPv6: net.IPv6loopback}

// over a drawn set of endpoints, arrival family, caller's family, auth.aliases and IDr, the responder answers as the endpoint the model names or refuses
// the model takes the caller only in the arrival family, and then an endpoint of that family alone
// with no IDr, or one that names no endpoint and that auth.aliases.local presents, it is the one endpoint of that family
// with one that names an endpoint, by its DN, its KEY_ID text or auth.aliases.remote, it is that endpoint, and with any other IDr there is none
// the IDr sent is this node's DN where a DN is asked for or nothing is presented, and otherwise the type and data asked for or presented with RESERVED zero
func TestResponderAnswersAsTheEndpointTheIDrAndTheFamilyName(t *testing.T) {
	client, other, server := identity.MustParse("testorg/client:2"), identity.MustParse("testorg/other:1"), identity.MustParse("testorg/server")
	otherFamily := map[Family]Family{IPv4: IPv6, IPv6: IPv4}
	idi := idBody(client.String())
	pbt.Check(t, func(ht *hegel.T) {
		in4 := hegel.Draw(ht, pbt.Spanning(0, 3))
		in6 := hegel.Draw(ht, pbt.Spanning(max(1-in4, 0), 3-in4))
		local := make(map[identity.Identity]Family, in4+in6)
		var ours []identity.Identity
		for i := range in4 + in6 {
			endpoint := server.At(strconv.Itoa(i + 1))
			local[endpoint] = IPv6
			if i < in4 {
				local[endpoint] = IPv4
			}
			ours = append(ours, endpoint)
		}
		arrived := hegel.Draw(ht, hegel.SampledFrom([]Family{IPv4, IPv6}))
		calling := hegel.Draw(ht, hegel.SampledFrom([]Family{arrived, otherFamily[arrived]}))

		targets := append(slices.Clone(ours), other)
		remote := map[string]identity.Identity{}
		for _, name := range answerNames {
			if hegel.Draw(ht, hegel.Booleans()) {
				remote[name] = hegel.Draw(ht, hegel.SampledFrom(targets))
			}
		}
		presents := map[string]LocalAlias{}
		for _, peer := range []string{"testorg/client", "testorg/third"} {
			if hegel.Draw(ht, hegel.Booleans()) {
				presents[peer] = LocalAlias{FQDN: hegel.Draw(ht, hegel.SampledFrom(answerNames))}
			}
		}
		presented := func(name string) bool {
			return slices.Contains(slices.Collect(maps.Values(presents)), LocalAlias{FQDN: name})
		}
		unpresent := func(name string) {
			maps.DeleteFunc(presents, func(_ string, alias LocalAlias) bool { return alias.FQDN == name })
		}

		var asked []byte
		var names identity.Identity
		name := hegel.Draw(ht, hegel.SampledFrom(answerNames))
		switch asking := hegel.Draw(ht, hegel.SampledFrom(askings)); asking {
		case "our DN", "our KEY_ID text", "another node's DN", "another node's KEY_ID text":
			names = other
			if asking == "our DN" || asking == "our KEY_ID text" {
				names = hegel.Draw(ht, hegel.SampledFrom(append(slices.Clone(ours), server.At("9"))))
			}
			asked = idBody(names.String())
			if asking == "our KEY_ID text" || asking == "another node's KEY_ID text" {
				asked = EncodeID(ID_KEY_ID, []byte(names.String()))
			}
		case "a remote alias", "a presented alias", "a remote alias it presents":
			asked = EncodeID(ID_FQDN, []byte(name))
			if asking == "a presented alias" {
				delete(remote, name)
			} else if _, ok := remote[name]; !ok {
				remote[name] = hegel.Draw(ht, hegel.SampledFrom(targets))
			}
			if asking == "a remote alias" {
				unpresent(name)
			} else if !presented(name) {
				presents[hegel.Draw(ht, hegel.SampledFrom([]string{"testorg/client", "testorg/third"}))] = LocalAlias{FQDN: name}
			}
			names = remote[name]
		case "an ID neither table names":
			asked = EncodeID(ID_FQDN, []byte("nobody.testorg.example"))
		}
		if asked != nil {
			copy(asked[1:4], hegel.Draw(ht, hegel.SampledFrom([][]byte{{0, 0, 0}, {0x01, 0x80, 0xff}})))
		}

		var in []identity.Identity
		for endpoint, family := range local {
			if family == arrived {
				in = append(in, endpoint)
			}
		}
		var want identity.Identity
		var answer []byte
		switch {
		case calling != arrived:
		case asked == nil:
			if len(in) == 1 {
				want, answer = in[0], idBody(in[0].String())
				if alias, ok := presents["testorg/client"]; ok {
					answer = EncodeID(ID_FQDN, []byte(alias.FQDN))
				}
			}
		case !names.IsZero():
			if local[names] == arrived {
				want = names
				answer = EncodeID(IDType(asked[0]), asked[4:])
				if IDType(asked[0]) == ID_DER_ASN1_DN {
					answer = idBody(names.String())
				}
			}
		case IDType(asked[0]) == ID_FQDN && presented(string(asked[4:])) && len(in) == 1:
			want, answer = in[0], EncodeID(ID_FQDN, asked[4:])
		}

		var closers []func()
		defer func() {
			for _, closer := range slices.Backward(closers) {
				closer()
			}
		}()
		inner, accepted, err := answerExchange(ht, payloadExchange{
			initiator: client, responder: ours[0], otherLocal: ours[1:], families: local, over: loopbacks[arrived], initiatorFamily: calling,
			responderAliases: Aliases{Remote: RemoteAliases{FQDN: remote}, Local: presents},
			idi:              hex.EncodeToString(idi), initiatorAuth: goldenInitiatorAuth(idi),
			requestIDr: hex.EncodeToString(asked), noIDr: asked == nil,
		}, nil, func(closer func()) { closers = append(closers, closer) })
		if want.IsZero() {
			if err == nil || findType(inner, PayloadN) == nil || findType(inner, PayloadIDr) != nil {
				ht.Fatalf("the responder answered %v as %s with %v, want its refusal alone", inner, accepted.Local, err)
			}
			return
		}
		if err != nil || accepted.Local != want || accepted.Peer != client {
			ht.Fatalf("the responder accepted %s at %s with %v, want %s at %s", accepted.Peer, accepted.Local, err, client, want)
		}
		if idr := findType(inner, PayloadIDr); idr == nil || !bytes.Equal(idr.Body, answer) {
			ht.Fatalf("the responder answered with IDr %v, want %x", idr, answer)
		}
	})
}
