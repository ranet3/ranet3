// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package ike

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/identity"
)

// refusals keeps the err of each ike.handshake.failed a responder records
type refusals struct {
	mu   sync.Mutex
	errs []string
}

func (r *refusals) record(_, _ identity.Identity, kind string, attrs ...slog.Attr) {
	for _, attr := range attrs {
		if kind == "ike.handshake.failed" && attr.Key == "err" {
			r.mu.Lock()
			r.errs = append(r.errs, attr.Value.String())
			r.mu.Unlock()
		}
	}
}

// awaitRefusal fails t unless the responder records a refusal naming want within answerBudget
func (r *refusals) awaitRefusal(t *testing.T, want string) {
	t.Helper()
	for deadline := time.Now().Add(answerBudget); ; time.Sleep(recordPoll) {
		r.mu.Lock()
		errs := slices.Clone(r.errs)
		r.mu.Unlock()
		if slices.ContainsFunc(errs, func(err string) bool { return strings.Contains(err, want) }) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the responder recorded the refusals %q, none naming %q", errs, want)
		}
	}
}

// each auth.aliases.local spelling goes on the wire as its type with RESERVED zero, an address in its own family
func TestLocalAliasBodies(t *testing.T) {
	for _, test := range []struct {
		alias LocalAlias
		want  string
	}{
		{LocalAlias{IP: "192.0.2.10"}, "01000000c000020a"},
		{LocalAlias{IP: "2001:db8::10"}, "0500000020010db8000000000000000000000010"},
		{LocalAlias{IP: "::ffff:192.0.2.10"}, "0500000000000000000000000000ffffc000020a"},
		{LocalAlias{FQDN: "laptop.example.net"}, "02000000" + hex.EncodeToString([]byte("laptop.example.net"))},
		{LocalAlias{Email: "ops@acme.example"}, "03000000" + hex.EncodeToString([]byte("ops@acme.example"))},
		{LocalAlias{KeyID: "0A1B2C3D"}, "0b0000000a1b2c3d"},
	} {
		body, err := test.alias.body()
		if err != nil || hex.EncodeToString(body) != test.want {
			t.Errorf("%+v went on the wire as %x, %v, want %s", test.alias, body, err, test.want)
		}
	}
}

// an endpoint's auth.aliases.local entry wins over its node's, and a peer neither names is sent the DN
func TestPresentedPrefersTheEndpointsEntry(t *testing.T) {
	aliases := Aliases{Local: map[string]LocalAlias{"acme/gw": {FQDN: "node.example"}, "acme/gw:2": {FQDN: "endpoint.example"}}}
	for peer, want := range map[string]string{
		"acme/gw:2": "02000000" + hex.EncodeToString([]byte("endpoint.example")),
		"acme/gw:1": "02000000" + hex.EncodeToString([]byte("node.example")),
		"acme/db:1": "",
	} {
		if body, err := aliases.presented(identity.MustParse(peer)); err != nil || hex.EncodeToString(body) != want {
			t.Errorf("toward %s this node presents %x, %v, want %q", peer, body, err, want)
		}
	}
}

// Validate refuses each entry no handshake could use, naming it as written, and takes the rest
// a local KEY_ID may spell an endpoint of this node, acme/me, and of no other
func TestAliasesValidateRefusesWhatNoHandshakeCouldUse(t *testing.T) {
	gw, me := identity.MustParse("acme/gw:1"), identity.MustParse("acme/me")
	remote := func(table RemoteAliases) Aliases { return Aliases{Remote: table} }
	ip := func(entries map[string]identity.Identity) Aliases { return remote(RemoteAliases{IP: entries}) }
	fqdn := func(entries map[string]identity.Identity) Aliases { return remote(RemoteAliases{FQDN: entries}) }
	email := func(entries map[string]identity.Identity) Aliases { return remote(RemoteAliases{Email: entries}) }
	keyid := func(entries map[string]identity.Identity) Aliases { return remote(RemoteAliases{KeyID: entries}) }
	local := func(peer string, alias LocalAlias) Aliases { return Aliases{Local: map[string]LocalAlias{peer: alias}} }
	for name, test := range map[string]struct {
		aliases Aliases
		want    string
	}{
		"a value naming nobody":              {ip(map[string]identity.Identity{"192.0.2.10": {}}), `auth.aliases.remote.ip "192.0.2.10" names nobody`},
		"a value naming a node":              {ip(map[string]identity.Identity{"192.0.2.10": gw.Node()}), `auth.aliases.remote.ip "192.0.2.10" names the node acme/gw`},
		"an address out of range":            {ip(map[string]identity.Identity{"192.0.2.300": gw}), `auth.aliases.remote.ip "192.0.2.300" is not an address`},
		"an address with a zone":             {ip(map[string]identity.Identity{"fe80::1%eth0": gw}), "carries a zone"},
		"two spellings of one address":       {ip(map[string]identity.Identity{"2001:db8::10": gw, "2001:DB8::10": gw}), `"2001:db8::10" and "2001:DB8::10" name one ID`},
		"two cases of one FQDN":              {fqdn(map[string]identity.Identity{"gw.acme.example": gw, "GW.acme.example": gw}), `"gw.acme.example" and "GW.acme.example" name one ID`},
		"an FQDN holding a terminator":       {fqdn(map[string]identity.Identity{"gw.acme.example\x00": gw}), `holds the terminator '\x00'`},
		"an FQDN holding a line separator":   {fqdn(map[string]identity.Identity{"gw\u2028acme.example": gw}), `holds the terminator '\u2028'`},
		"an FQDN outside ASCII":              {fqdn(map[string]identity.Identity{"gw.\u00e9.example": gw}), "an FQDN is ASCII"},
		"an empty FQDN":                      {fqdn(map[string]identity.Identity{"": gw}), `auth.aliases.remote.fqdn "" is empty`},
		"an email address with no domain":    {email(map[string]identity.Identity{"ops@": gw}), "is not an address of the form local@domain"},
		"an email address with no local":     {email(map[string]identity.Identity{"@acme.example": gw}), "is not an address of the form local@domain"},
		"an email address holding a CR":      {email(map[string]identity.Identity{"ops@acme.example\r": gw}), `holds the terminator '\r'`},
		"an email address that is not UTF-8": {email(map[string]identity.Identity{"ops@\xff.example": gw}), "is not UTF-8"},
		"two cases of one email domain":      {email(map[string]identity.Identity{"ops@acme.example": gw, "ops@ACME.example": gw}), `"ops@acme.example" and "ops@ACME.example" name one ID`},
		"an odd count of hex digits":         {keyid(map[string]identity.Identity{"0a1": gw}), "is not octets in hex"},
		"no octets":                          {keyid(map[string]identity.Identity{"": gw}), `auth.aliases.remote.keyid "" is empty`},
		"a KEY_ID spelling another endpoint": {keyid(map[string]identity.Identity{hex.EncodeToString([]byte("acme/db:1")): gw}), "spells acme/db:1, which a KEY_ID names with no alias"},
		"a local key that is no peer":        {local("acme", LocalAlias{FQDN: "laptop.example.net"}), `auth.aliases.local "acme"`},
		"a local entry writing no ID":        {local("acme/gw", LocalAlias{}), "writes 0 of ip, fqdn, email and keyid"},
		"a local entry writing two IDs":      {local("acme/gw", LocalAlias{FQDN: "laptop.example.net", Email: "ops@acme.example"}), "writes 2 of ip, fqdn, email and keyid"},
		"a local address out of range":       {local("acme/gw", LocalAlias{IP: "192.0.2.300"}), `ip "192.0.2.300" is not an address`},
		"a local FQDN holding a newline":     {local("acme/gw:1", LocalAlias{FQDN: "laptop\nexample.net"}), `fqdn "laptop\nexample.net" holds the terminator '\n'`},
		"a local KEY_ID spelling another node's endpoint": {local("acme/gw", LocalAlias{KeyID: hex.EncodeToString([]byte("acme/db:1"))}),
			`keyid "` + hex.EncodeToString([]byte("acme/db:1")) + `" spells acme/db:1, an endpoint of another node`},
		"a local KEY_ID spelling an endpoint of this node": {local("acme/gw", LocalAlias{KeyID: hex.EncodeToString([]byte("acme/me:2"))}), ""},
		"the shape a deployment writes": {Aliases{
			Remote: RemoteAliases{
				IP:    map[string]identity.Identity{"192.0.2.10": gw, "2001:db8::10": gw, "::ffff:192.0.2.10": gw},
				FQDN:  map[string]identity.Identity{"gw.acme.example": gw},
				Email: map[string]identity.Identity{"ops@acme.example": gw, "Ops@acme.example": gw},
				KeyID: map[string]identity.Identity{"0a1b2c3d": gw, hex.EncodeToString([]byte("acme/gw:1")): gw},
			},
			Local: map[string]LocalAlias{"acme/gw": {FQDN: "laptop.example.net"}, "acme/gw:1": {KeyID: "0a1b"}},
		}, ""},
	} {
		err := test.aliases.Validate(me)
		if test.want == "" && err != nil {
			t.Errorf("%s: refused with %v", name, err)
		}
		if test.want != "" && (err == nil || !strings.Contains(err.Error(), test.want)) {
			t.Errorf("%s: Validate returned %v, want a refusal naming %q", name, err, test.want)
		}
	}
}

// a quoted local part may hold an @, and only the domain after the last one compares without case
func TestResolveSplitsAnEmailAddressAtItsLastAt(t *testing.T) {
	upper, lower := identity.MustParse("acme/gw:1"), identity.MustParse("acme/gw:2")
	aliases := Aliases{Remote: RemoteAliases{Email: map[string]identity.Identity{`"o@Ps"@acme.example`: upper, `"o@ps"@acme.example`: lower}}}
	if err := aliases.Validate(identity.MustParse("acme/me")); err != nil {
		t.Fatalf("two local parts differing in a letter after their @ were refused: %v", err)
	}
	for received, want := range map[string]identity.Identity{`"o@Ps"@ACME.example`: upper, `"o@ps"@acme.EXAMPLE`: lower} {
		if got, err := aliases.resolve(EncodeID(ID_RFC822_ADDR, []byte(received))); err != nil || got.endpoint != want {
			t.Errorf("%s resolved to %s with %v, want %s", received, got.endpoint, err, want)
		}
	}
}

// aliasOf is an alias of kind written as written, as an auth.aliases.local entry and as an auth.aliases.remote table naming endpoint
func aliasOf(kind aliasKind, written string, endpoint identity.Identity) (LocalAlias, RemoteAliases) {
	var remote RemoteAliases
	switch kind {
	case aliasIP:
		remote.IP = map[string]identity.Identity{written: endpoint}
	case aliasFQDN:
		remote.FQDN = map[string]identity.Identity{written: endpoint}
	case aliasEmail:
		remote.Email = map[string]identity.Identity{written: endpoint}
	default:
		remote.KeyID = map[string]identity.Identity{written: endpoint}
	}
	return localAlias(kind, written), remote
}

// localAlias is the auth.aliases.local entry writing written in the field of kind
func localAlias(kind aliasKind, written string) LocalAlias {
	switch kind {
	case aliasIP:
		return LocalAlias{IP: written}
	case aliasFQDN:
		return LocalAlias{FQDN: written}
	case aliasEmail:
		return LocalAlias{Email: written}
	}
	return LocalAlias{KeyID: written}
}

// a dial through InitiateContext to a Serve-ing responder presents an alias of each kind each way, both ends resolve the other's, and each records what it resolved
// the initiator asks in IDr for the alias its table names the responder by, and the responder answers with it
// a KEY_ID spelling an endpoint resolves at the responder with no table, and the initiator lists the one it dials only to ask for it
func TestHandshakeResolvesAnAliasOfEachKindEachWay(t *testing.T) {
	client, server := identity.MustParse("testorg/client:2"), identity.MustParse("testorg/server:1")
	for name, test := range map[string]struct {
		kind               aliasKind
		clientID, serverID string // the alias each end presents
		serverListsNone    bool   // the responder lists no alias, where the client's KEY_ID spells it
		dialed, answered   string // the attributes of the ike.id.resolved each end records
	}{
		"ipv4":  {kind: aliasIP, clientID: "192.0.2.2", serverID: "192.0.2.1", dialed: "type=ipv4 id=192.0.2.1 sent=ipv4", answered: "type=ipv4 id=192.0.2.2 sent=ipv4"},
		"ipv6":  {kind: aliasIP, clientID: "2001:db8::2", serverID: "2001:db8::1", dialed: "type=ipv6 id=2001:db8::1 sent=ipv6", answered: "type=ipv6 id=2001:db8::2 sent=ipv6"},
		"fqdn":  {kind: aliasFQDN, clientID: "client.testorg.example", serverID: "server.testorg.example", dialed: "type=fqdn id=server.testorg.example sent=fqdn", answered: "type=fqdn id=client.testorg.example sent=fqdn"},
		"email": {kind: aliasEmail, clientID: "client@testorg.example", serverID: "server@testorg.example", dialed: "type=email id=server@testorg.example sent=email", answered: "type=email id=client@testorg.example sent=email"},
		"keyid": {kind: aliasKeyID, clientID: "0a1b2c3e", serverID: "0a1b2c3d", dialed: "type=keyid id=0a1b2c3d sent=keyid", answered: "type=keyid id=0a1b2c3e sent=keyid"},
		"keyid spelling the endpoint": {kind: aliasKeyID, serverListsNone: true,
			clientID: hex.EncodeToString([]byte("testorg/client:2")), serverID: hex.EncodeToString([]byte("testorg/server:1")),
			dialed:   "type=keyid id=" + hex.EncodeToString([]byte("testorg/server:1")) + " sent=keyid",
			answered: "type=keyid id=" + hex.EncodeToString([]byte("testorg/client:2")) + " sent=keyid"},
	} {
		t.Run(name, func(t *testing.T) {
			dialed, answered := &recorder{}, &recorder{}
			h := newResponderHarness(t, nil, answered.record)
			clientPresents, listsClient := aliasOf(test.kind, test.clientID, client)
			serverPresents, listsServer := aliasOf(test.kind, test.serverID, server)
			if test.serverListsNone {
				listsClient = RemoteAliases{}
			}
			h.aliases.Store(&Aliases{Remote: listsClient, Local: map[string]LocalAlias{"testorg/client:2": serverPresents}})
			cfg := h.peerConfig()
			cfg.Events = dialed.record
			cfg.Aliases = Aliases{Remote: listsServer, Local: map[string]LocalAlias{"testorg/server:1": clientPresents}}
			if err := h.aliases.Load().Validate(server.Node()); err != nil {
				t.Fatal(err)
			}
			if err := cfg.Aliases.Validate(client.Node()); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), answerBudget)
			defer cancel()
			initiator, err := InitiateContext(ctx, cfg)
			if err != nil {
				t.Fatalf("initiate: %v", err)
			}
			defer initiator.Mux().Close()
			responder := <-h.sessions
			defer responder.Mux().Close()
			if accepted := <-h.identities; accepted.Peer != client || accepted.Local != server {
				t.Errorf("the responder accepted %s at %s", accepted.Peer, accepted.Local)
			}
			if got, want := dialed.recorded(), []string{"ike.id.resolved testorg/client:2>testorg/server:1 " + test.dialed}; !slices.Equal(got, want) {
				t.Errorf("the dialed session recorded %q, want %q", got, want)
			}
			if got, want := answered.recorded(), []string{"ike.id.resolved testorg/server:1>testorg/client:2 " + test.answered}; !slices.Equal(got, want) {
				t.Errorf("the answered session recorded %q, want %q", got, want)
			}
		})
	}
}

// an IDi no alias names is refused as an unknown identity is, and the responder reads auth.aliases for each handshake, which lets an alias stored between two dials admit the second
func TestResponderReadsItsAliasesForEachHandshake(t *testing.T) {
	client := identity.MustParse("testorg/client:2")
	failures := &refusals{}
	h := newResponderHarness(t, nil, failures.record)
	cfg := h.peerConfig()
	cfg.Aliases = Aliases{Local: map[string]LocalAlias{"testorg/server:1": {FQDN: "client.testorg.example"}}}
	ctx, cancel := context.WithTimeout(context.Background(), answerBudget)
	defer cancel()
	if session, err := InitiateContext(ctx, cfg); err == nil {
		session.Mux().Close()
		t.Fatal("the responder admitted an FQDN it lists no alias for")
	} else if want := fmt.Sprintf("notify type %d", N_AUTHENTICATION_FAILED); !strings.Contains(err.Error(), want) {
		t.Fatalf("the initiator was refused with %q, want %q", err, want)
	}
	failures.awaitRefusal(t, `fqdn ID "client.testorg.example" names no endpoint auth.aliases.remote lists`)

	h.aliases.Store(&Aliases{Remote: RemoteAliases{FQDN: map[string]identity.Identity{"client.testorg.example": client}}})
	initiator, err := InitiateContext(ctx, cfg)
	if err != nil {
		t.Fatalf("the dial after the alias was stored: %v", err)
	}
	defer initiator.Mux().Close()
	responder := <-h.sessions
	defer responder.Mux().Close()
	if accepted := <-h.identities; accepted.Peer != client {
		t.Errorf("the responder accepted %s", accepted.Peer)
	}
}

// the initiator refuses an IDr its aliases resolve to nothing or to another endpoint than the one dialed, and tells the responder, whose session ends
// its tables name the responder by two addresses and it asks for neither, and the responder answers with the FQDN it presents
func TestInitiatorRefusesAnIDrNamingNoneOrAnotherEndpoint(t *testing.T) {
	server := identity.MustParse("testorg/server:1")
	twice := map[string]identity.Identity{"192.0.2.1": server, "192.0.2.9": server}
	for name, test := range map[string]struct {
		remote RemoteAliases
		want   string
	}{
		"an IDr no alias names": {
			remote: RemoteAliases{IP: twice},
			want:   `fqdn ID "server.testorg.example" names no endpoint auth.aliases.remote lists`},
		"an IDr whose alias names another endpoint": {
			remote: RemoteAliases{IP: twice, FQDN: map[string]identity.Identity{"server.testorg.example": identity.MustParse("testorg/server:3")}},
			want:   "the responder's IDr names testorg/server:3, and this node dialed testorg/server:1"},
	} {
		t.Run(name, func(t *testing.T) {
			h := newResponderHarness(t, nil)
			h.aliases.Store(&Aliases{Local: map[string]LocalAlias{"testorg/client:2": {FQDN: "server.testorg.example"}}})
			ended := serveResponder(t, h)
			cfg := h.peerConfig()
			cfg.Aliases = Aliases{Remote: test.remote}
			ctx, cancel := context.WithTimeout(context.Background(), answerBudget)
			defer cancel()
			session, err := InitiateContext(ctx, cfg)
			if err == nil {
				session.Mux().Close()
				t.Fatal("the initiator took an IDr it should have refused")
			}
			if !strings.Contains(err.Error(), test.want) || strings.Contains(err.Error(), "additionally failed") {
				t.Fatalf("the initiator refused with %q, which does not name %q alone", err, test.want)
			}
			select {
			case <-ended:
			case <-time.After(answerBudget):
				t.Fatal("the responder still held the SA its initiator refused when the budget ran out")
			}
		})
	}
}

// an IDr naming one of the responder's endpoints by its DN is answered as that endpoint by its DN, though an alias is there for the caller
// one its own tables resolve to one of its endpoints is answered as that endpoint, with the ID asked for
// one naming no endpoint is answered only where it matches an alias the responder presents to any peer
// every other one is refused, since RFC 7296 section 1.2's "use some other IDr to finish the exchange" is never taken, one it presents that names another node's endpoint included
func TestResponderAnswersTheIDrAskedFor(t *testing.T) {
	client, server := identity.MustParse("testorg/client:2"), identity.MustParse("testorg/server:1")
	other := identity.MustParse("testorg/other:1")
	presents := Aliases{
		Remote: RemoteAliases{FQDN: map[string]identity.Identity{"client.testorg.example": client, "other.testorg.example": other, "shared.testorg.example": other}},
		Local: map[string]LocalAlias{"testorg/client": {FQDN: "server.testorg.example"}, "testorg/other": {FQDN: "elsewhere.testorg.example"},
			"testorg/third": {FQDN: "shared.testorg.example"}},
	}
	idi := EncodeID(ID_FQDN, []byte("client.testorg.example"))
	asked := payloadExchange{initiator: client, responder: server, responderAliases: presents,
		idi: hex.EncodeToString(idi), initiatorAuth: goldenInitiatorAuth(idi)}
	fqdn := func(name string) string { return hex.EncodeToString(EncodeID(ID_FQDN, []byte(name))) }
	for name, test := range map[string]struct {
		idr  string
		want string // the refusal, where the IDr is not answered
	}{
		"by the alias it presents another peer": {idr: fqdn("ELSEWHERE.testorg.example")},
		"by another node's endpoint":            {idr: hex.EncodeToString(idBody("testorg/other:1")), want: "IKE_AUTH request names testorg/other:1, which we do not answer as"},
		"by an alias naming another node's endpoint": {idr: fqdn("other.testorg.example"),
			want: "IKE_AUTH request names testorg/other:1, which we do not answer as"},
		"by an alias naming another node's endpoint that it presents": {idr: fqdn("shared.testorg.example"),
			want: "IKE_AUTH request names testorg/other:1, which we do not answer as"},
		"by an endpoint of its own it does not answer as": {idr: hex.EncodeToString(idBody("testorg/server:9")),
			want: "IKE_AUTH request names testorg/server:9, which we do not answer as"},
		"by another FQDN": {idr: fqdn("nobody.testorg.example"), want: `IKE_AUTH request names fqdn ID "nobody.testorg.example", which we do not answer to`},
	} {
		t.Run(name, func(t *testing.T) {
			x := asked
			x.requestIDr = test.idr
			inner, accepted, err := responderExchange(t, x, nil)
			if test.want == "" {
				if err != nil || accepted.Local != server {
					t.Fatalf("the responder answered as %s with %v, want %s", accepted.Local, err, server)
				}
				samePayload(t, "IDr", findType(inner, PayloadIDr), test.idr)
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("the responder took the IDr with %v, want a refusal naming %q", err, test.want)
			}
			if refusal := findType(inner, PayloadN); refusal == nil || findType(inner, PayloadIDr) != nil {
				t.Errorf("the responder answered %v, want its refusal alone", inner)
			}
		})
	}
	t.Run("by its DN", func(t *testing.T) {
		second := identity.MustParse("testorg/server:2")
		h := newResponderHarnessAs(t, []identity.Identity{server, second}, nil)
		h.aliases.Store(&presents)
		cfg := h.peerConfig()
		cfg.Remote = second
		cfg.Aliases = Aliases{Local: map[string]LocalAlias{"testorg/server": {FQDN: "client.testorg.example"}}}
		ctx, cancel := context.WithTimeout(context.Background(), answerBudget)
		defer cancel()
		initiator, err := InitiateContext(ctx, cfg)
		if err != nil {
			t.Fatalf("initiate to %s: %v", second, err)
		}
		defer initiator.Mux().Close()
		responder := <-h.sessions
		defer responder.Mux().Close()
		if accepted := <-h.identities; accepted.Local != second {
			t.Errorf("the responder answered as %s, want %s", accepted.Local, second)
		}
	})
}

// RFC 7296 section 3.5 has RESERVED "MUST be sent as zero" and "MUST be ignored on receipt."
// an IDr asked for with RESERVED set is answered with the type and data asked for and RESERVED zero, beside the Child SA and beside NO_PROPOSAL_CHOSEN
func TestResponderSendsReservedZeroInTheIDrItWasAskedFor(t *testing.T) {
	client, server := identity.MustParse("testorg/client:2"), identity.MustParse("testorg/server:1")
	idi := EncodeID(ID_FQDN, []byte("client.testorg.example"))
	answer := EncodeID(ID_FQDN, []byte("server.testorg.example"))
	asked := EncodeID(ID_FQDN, []byte("server.testorg.example"))
	asked[1], asked[2], asked[3] = 0x01, 0x80, 0xff
	// an ESP proposal with no cipher parses and is refused
	unacceptable := []Proposal{{Number: 1, Protocol: ProtoESP, SPI: []byte{0, 0, 0, 9}, Transforms: []Transform{{Type: TransESN, ID: ESN_NO}}}}
	for name, aliases := range map[string]Aliases{
		"an ID its own table resolves": {
			Remote: RemoteAliases{FQDN: map[string]identity.Identity{"client.testorg.example": client, "server.testorg.example": server}},
		},
		"an alias it presents": {
			Remote: RemoteAliases{FQDN: map[string]identity.Identity{"client.testorg.example": client}},
			Local:  map[string]LocalAlias{"testorg/client": {FQDN: "server.testorg.example"}},
		},
	} {
		for answered, offer := range map[string][]Proposal{"beside the Child SA": nil, "beside NO_PROPOSAL_CHOSEN": unacceptable} {
			t.Run(name+" "+answered, func(t *testing.T) {
				inner, accepted, err := responderExchange(t, payloadExchange{
					initiator: client, responder: server, responderAliases: aliases, childOffer: offer,
					idi: hex.EncodeToString(idi), initiatorAuth: goldenInitiatorAuth(idi), requestIDr: hex.EncodeToString(asked),
				}, nil)
				if offer == nil {
					if err != nil || accepted.Local != server {
						t.Fatalf("the responder answered as %s with %v, want %s", accepted.Local, err, server)
					}
				} else {
					refusal := findType(inner, PayloadN)
					if err == nil || refusal == nil {
						t.Fatalf("the responder answered %v with %v, want NO_PROPOSAL_CHOSEN", inner, err)
					}
					if notify, err := DecodeNotify(refusal.Body); err != nil || notify.Type != N_NO_PROPOSAL_CHOSEN {
						t.Fatalf("the responder answered notify %d with %v, want NO_PROPOSAL_CHOSEN", notify.Type, err)
					}
				}
				samePayload(t, "IDr", findType(inner, PayloadIDr), hex.EncodeToString(answer))
			})
		}
	}
}

// a KEY_ID spelling an endpoint names it as IDi without an alias, and asked for as IDr
func TestResponderAnswersAKeyIDTextFormIDr(t *testing.T) {
	client, server := identity.MustParse("testorg/client:2"), identity.MustParse("testorg/server:1")
	idi := EncodeID(ID_KEY_ID, []byte(client.String()))
	_, accepted, err := responderExchange(t, payloadExchange{
		initiator: client, responder: server, idi: hex.EncodeToString(idi), initiatorAuth: goldenInitiatorAuth(idi),
		requestIDr: hex.EncodeToString(EncodeID(ID_KEY_ID, []byte(server.String()))),
	}, nil)
	t.Logf("accepted %+v, err %v", accepted, err)
	if err != nil {
		t.Errorf("a KEY_ID IDr spelling %s, our own endpoint, was refused: %v", server, err)
	}
}

// both ends carry one auth.aliases.remote written for the whole fleet, which names the responder's first ip4 endpoint by an FQDN
// the responder has a second ip4 endpoint, and answers as the one the table names, which the initiator asks for in IDr
func TestResponderWithTwoEndpointsInAFamilyAnswersAsTheOneItsTableNames(t *testing.T) {
	first, second := identity.MustParse("testorg/server:1"), identity.MustParse("testorg/server:3")
	fleet := RemoteAliases{FQDN: map[string]identity.Identity{
		"server.testorg.example": first, "client.testorg.example": identity.MustParse("testorg/client:2"),
	}}
	h := newResponderHarnessAs(t, []identity.Identity{first, second}, nil)
	h.aliases.Store(&Aliases{Remote: fleet})
	cfg := h.peerConfig()
	cfg.Aliases = Aliases{Remote: fleet}
	ctx, cancel := context.WithTimeout(context.Background(), answerBudget)
	defer cancel()
	initiator, err := InitiateContext(ctx, cfg)
	if err != nil {
		t.Fatalf("dialing %s: %v", first, err)
	}
	defer initiator.Mux().Close()
	responder := <-h.sessions
	defer responder.Mux().Close()
	if accepted := <-h.identities; accepted.Local != first {
		t.Errorf("the responder answered as %s, want %s", accepted.Local, first)
	}
}

// the initiator asks in IDr for the DN of the endpoint it dials where its tables name it by none, for the one ID they name it by, and for nothing where they name it by several
func TestInitiatorAsksInIDrForTheOneIDItsTablesName(t *testing.T) {
	server := identity.MustParse("testorg/server:1")
	fqdn := hex.EncodeToString(EncodeID(ID_FQDN, []byte("server.testorg.example")))
	for name, test := range map[string]struct {
		remote RemoteAliases
		want   string // the IDr sent in hex, empty for none
	}{
		"by none":    {RemoteAliases{IP: map[string]identity.Identity{"192.0.2.3": identity.MustParse("testorg/server:3")}}, hex.EncodeToString(idBody("testorg/server:1"))},
		"by one":     {RemoteAliases{FQDN: map[string]identity.Identity{"server.testorg.example": server}}, fqdn},
		"by several": {RemoteAliases{FQDN: map[string]identity.Identity{"server.testorg.example": server}, IP: map[string]identity.Identity{"192.0.2.1": server}}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			inner, _ := initiatorExchange(t, payloadExchange{initiator: identity.MustParse("testorg/client:2"), responder: server,
				initiatorAliases: Aliases{Remote: test.remote}, idr: fqdn}, nil)
			idr := findType(inner, PayloadIDr)
			switch {
			case test.want == "" && idr != nil:
				t.Errorf("the initiator sent IDr %x, want none", idr.Body)
			case test.want != "":
				samePayload(t, "IDr", idr, test.want)
			}
		})
	}
}

// RFC 7296 section 3.5 has the identity "used for policy lookup" and "to perform access control decisions"
// the responder refuses an IDi naming an endpoint of another family than the one the request arrived in, by its DN or by an alias, after AUTH verifies
func TestResponderRefusesAnIDiOfAnotherFamily(t *testing.T) {
	client, server := identity.MustParse("testorg/client:2"), identity.MustParse("testorg/server:1")
	dn := idBody(client.String())
	fqdn := EncodeID(ID_FQDN, []byte("client.testorg.example"))
	for name, test := range map[string]struct {
		idi     []byte
		aliases Aliases
		over    net.IP
		family  Family
		want    string
	}{
		"by its DN over IPv4": {idi: dn, over: net.IPv4(127, 0, 0, 1), family: IPv6,
			want: "IDi names testorg/client:2, an endpoint of the IPv6 family, and the request arrived in IPv4"},
		"by its DN over IPv6": {idi: dn, over: net.IPv6loopback, family: IPv4,
			want: "IDi names testorg/client:2, an endpoint of the IPv4 family, and the request arrived in IPv6"},
		"by an alias": {idi: fqdn, over: net.IPv4(127, 0, 0, 1), family: IPv6,
			aliases: Aliases{Remote: RemoteAliases{FQDN: map[string]identity.Identity{"client.testorg.example": client}}},
			want:    "IDi names testorg/client:2, an endpoint of the IPv6 family, and the request arrived in IPv4"},
	} {
		t.Run(name, func(t *testing.T) {
			events := &recorder{}
			inner, accepted, err := responderExchange(t, payloadExchange{
				initiator: client, responder: server, over: test.over, initiatorFamily: test.family, families: map[identity.Identity]Family{server: test.family},
				responderAliases: test.aliases, idi: hex.EncodeToString(test.idi), initiatorAuth: goldenInitiatorAuth(test.idi), noIDr: true,
			}, events.record)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("the responder took the request with %v, want a refusal naming %q", err, test.want)
			}
			if findType(inner, PayloadN) == nil || findType(inner, PayloadIDr) != nil || !accepted.Peer.IsZero() {
				t.Errorf("the responder answered %v and accepted %+v, want its refusal alone", inner, accepted)
			}
			if got := events.recorded(); len(got) != 0 {
				t.Errorf("the responder recorded %q", got)
			}
		})
	}
}

// a node whose auth.aliases.local entry is keyed by the responder's node presents one ID from each of its endpoints
// the responder's table names that ID's endpoint in IPv6, and the handshake from the IPv4 one is refused with nothing recorded under the IPv6 one
func TestNodeKeyedAliasFromAnotherEndpointIsRefused(t *testing.T) {
	v4, v6 := identity.MustParse("testorg/client:1"), identity.MustParse("testorg/client:2")
	key := new(atomic.Pointer[ed25519.PublicKey])
	events := &recorder{}
	h := newResponderHarness(t, trustIn(key, map[identity.Identity]Family{v4: IPv4, v6: IPv6}), events.record)
	key.Store(&h.public)
	h.aliases.Store(&Aliases{Remote: RemoteAliases{FQDN: map[string]identity.Identity{"client.testorg.example": v6}}})
	cfg := h.peerConfig()
	cfg.Local = v4
	cfg.Aliases = Aliases{Local: map[string]LocalAlias{"testorg/server": {FQDN: "client.testorg.example"}}}
	ctx, cancel := context.WithTimeout(context.Background(), answerBudget)
	defer cancel()
	if initiator, err := InitiateContext(ctx, cfg); err == nil {
		initiator.Mux().Close()
		t.Fatalf("the responder accepted the session from %s", v4)
	} else if want := fmt.Sprintf("notify type %d", N_AUTHENTICATION_FAILED); !strings.Contains(err.Error(), want) {
		t.Fatalf("the initiator was refused with %q, want %q", err, want)
	}
	select {
	case accepted := <-h.identities:
		t.Fatalf("the responder accepted %s", accepted.Peer)
	case <-time.After(quietPeriod):
	}
	for _, line := range events.recorded() {
		if strings.Contains(line, v6.String()) {
			t.Errorf("the responder recorded %q under %s", line, v6)
		}
	}
}

// RFC 7296 section 1.2 has IDr name "to which of the responder's identities it wants to talk"
// an IDr naming one of the responder's endpoints of another family than the request's is refused, as the request did not reach it
// an alias auth.aliases.remote resolves to such an endpoint is refused though auth.aliases.local also presents it, since an ID that names an endpoint names no other
func TestResponderRefusesAnIDrNamingItsEndpointOfAnotherFamily(t *testing.T) {
	client, v4, v6 := identity.MustParse("testorg/client:2"), identity.MustParse("testorg/server:1"), identity.MustParse("testorg/server:2")
	idi := idBody(client.String())
	for name, test := range map[string]struct {
		idr     []byte
		aliases Aliases
	}{
		"by its DN":          {idr: idBody(v6.String())},
		"by its KEY_ID text": {idr: EncodeID(ID_KEY_ID, []byte(v6.String()))},
		"by an alias its table resolves and it presents": {idr: EncodeID(ID_FQDN, []byte("server6.testorg.example")), aliases: Aliases{
			Remote: RemoteAliases{FQDN: map[string]identity.Identity{"server6.testorg.example": v6}},
			Local:  map[string]LocalAlias{"testorg/client": {FQDN: "server6.testorg.example"}},
		}},
	} {
		t.Run(name, func(t *testing.T) {
			inner, _, err := responderExchange(t, payloadExchange{
				initiator: client, responder: v4, otherLocal: []identity.Identity{v6}, families: map[identity.Identity]Family{v4: IPv4, v6: IPv6},
				responderAliases: test.aliases, idi: hex.EncodeToString(idi), initiatorAuth: goldenInitiatorAuth(idi), requestIDr: hex.EncodeToString(test.idr),
			}, nil)
			if want := "IKE_AUTH request names our testorg/server:2, an endpoint of the IPv6 family, and arrived in IPv4"; err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("the responder took the IDr with %v, want a refusal naming %q", err, want)
			}
			if findType(inner, PayloadN) == nil || findType(inner, PayloadIDr) != nil {
				t.Errorf("the responder answered %v, want its refusal alone", inner)
			}
		})
	}
}

// Entries names every remote value in the order of its tables and keys, then every local key, each entry as Validate names it, and stops where its caller does
func TestEntriesNameEachEndpointAndPeerInOrder(t *testing.T) {
	gw, relay := identity.MustParse("acme/gw:1"), identity.MustParse("acme/relay:2")
	aliases := Aliases{
		Remote: RemoteAliases{
			IP:    map[string]identity.Identity{"192.0.2.10": gw},
			FQDN:  map[string]identity.Identity{"relay.acme.example": relay, "gw.acme.example": gw},
			KeyID: map[string]identity.Identity{"0a1b": relay},
		},
		Local: map[string]LocalAlias{"acme/relay:2": {FQDN: "laptop.example.net"}, "acme/gw": {IP: "192.0.2.5"}},
	}
	var got []string
	for entry, named := range aliases.Entries() {
		got = append(got, entry+" "+named.String())
	}
	want := []string{
		`auth.aliases.remote.ip "192.0.2.10" acme/gw:1`,
		`auth.aliases.remote.fqdn "gw.acme.example" acme/gw:1`,
		`auth.aliases.remote.fqdn "relay.acme.example" acme/relay:2`,
		`auth.aliases.remote.keyid "0a1b" acme/relay:2`,
		`auth.aliases.local "acme/gw" acme/gw`,
		`auth.aliases.local "acme/relay:2" acme/relay:2`,
	}
	if !slices.Equal(got, want) {
		t.Errorf("the entries read %q, want %q", got, want)
	}
	// an iterator going on after its caller stopped panics the range
	for range aliases.Entries() {
		break
	}
}

// dualStackPresents is the auth.aliases of a responder that names testorg/client:2 by an FQDN and presents it one
var dualStackPresents = Aliases{
	Remote: RemoteAliases{FQDN: map[string]identity.Identity{"client.testorg.example": identity.MustParse("testorg/client:2")}},
	Local:  map[string]LocalAlias{"testorg/client": {FQDN: "server.testorg.example"}},
}

// a responder with an endpoint in each family answers a request whose IDr names neither as the endpoint of the family the request arrived in
// a client with an endpoint in each family dials each, presenting one alias from both, and asks in IDr for the alias the responder presents it
// with no IDr the responder answers by the family alone, which a strongSwan initiator naming it by an alias it does not send relies on
// and answers with the alias it presents the caller
func TestDualStackResponderAnswersAsTheEndpointOfTheFamilyReached(t *testing.T) {
	v4, v6 := identity.MustParse("testorg/server:1"), identity.MustParse("testorg/server:2")
	clients := map[Family]identity.Identity{IPv4: identity.MustParse("testorg/client:2"), IPv6: identity.MustParse("testorg/client:3")}
	families := map[identity.Identity]Family{v4: IPv4, v6: IPv6}
	presents := Aliases{
		Remote: RemoteAliases{FQDN: map[string]identity.Identity{"client4.testorg.example": clients[IPv4], "client6.testorg.example": clients[IPv6]}},
		Local:  map[string]LocalAlias{"testorg/client": {FQDN: "server.testorg.example"}},
	}
	for name, test := range map[string]struct {
		over   net.IP
		family Family
		want   identity.Identity
	}{
		"ipv4": {net.IPv4(127, 0, 0, 1), IPv4, v4},
		"ipv6": {net.IPv6loopback, IPv6, v6},
	} {
		client := clients[test.family]
		alias := map[Family]string{IPv4: "client4.testorg.example", IPv6: "client6.testorg.example"}[test.family]
		t.Run(name+" asked for its alias", func(t *testing.T) {
			h := newResponderHarnessIn(t, families, nil)
			h.aliases.Store(&presents)
			cfg := h.peerConfig()
			cfg.Local, cfg.Remote, cfg.RemoteAddr = client, test.want, test.over
			cfg.Aliases = Aliases{
				Remote: RemoteAliases{FQDN: map[string]identity.Identity{"server.testorg.example": test.want}},
				Local:  map[string]LocalAlias{"testorg/server": {FQDN: alias}},
			}
			ctx, cancel := context.WithTimeout(context.Background(), answerBudget)
			defer cancel()
			initiator, err := InitiateContext(ctx, cfg)
			if err != nil {
				t.Fatalf("initiate over %s: %v", test.over, err)
			}
			defer initiator.Mux().Close()
			responder := <-h.sessions
			defer responder.Mux().Close()
			if accepted := <-h.identities; accepted.Local != test.want {
				t.Errorf("the responder answered a request over %s as %s, want %s", test.over, accepted.Local, test.want)
			}
		})
		t.Run(name+" with no IDr", func(t *testing.T) {
			idi := EncodeID(ID_FQDN, []byte(alias))
			inner, accepted, err := responderExchange(t, payloadExchange{
				initiator: client, responder: v4, otherLocal: []identity.Identity{v6}, families: families, over: test.over,
				responderAliases: presents, idi: hex.EncodeToString(idi), initiatorAuth: goldenInitiatorAuth(idi), noIDr: true,
			}, nil)
			if err != nil {
				t.Fatalf("the responder refused a request with no IDr over %s: %v", test.over, err)
			}
			if accepted.Local != test.want {
				t.Errorf("the responder answered a request over %s as %s, want %s", test.over, accepted.Local, test.want)
			}
			if idr, want := findType(inner, PayloadIDr), EncodeID(ID_FQDN, []byte("server.testorg.example")); idr == nil || !slices.Equal(idr.Body, want) {
				t.Errorf("the responder answered a request over %s with IDr %v, want the alias it presents the caller %x", test.over, idr, want)
			}
		})
	}
}

// none or two endpoints in the family a request arrived in leave the endpoint it reached unknown, and the responder refuses rather than guess, with no IDr and asked for its alias alike
func TestResponderRefusesWhereTheFamilyHoldsNotOneEndpoint(t *testing.T) {
	client := identity.MustParse("testorg/client:2")
	first, second, v6 := identity.MustParse("testorg/server:1"), identity.MustParse("testorg/server:3"), identity.MustParse("testorg/server:2")
	idi := EncodeID(ID_FQDN, []byte("client.testorg.example"))
	for name, test := range map[string]struct {
		others   []identity.Identity // the responder's endpoints beside first
		families map[identity.Identity]Family
		over     net.IP
		want     string
	}{
		"two in the family": {[]identity.Identity{second, v6}, map[identity.Identity]Family{first: IPv4, second: IPv4, v6: IPv6}, net.IPv4(127, 0, 0, 1),
			"2 of our 3 are of the IPv4 family it arrived in"},
		"none in the family": {[]identity.Identity{second}, map[identity.Identity]Family{first: IPv4, second: IPv4}, net.IPv6loopback,
			"0 of our 2 are of the IPv6 family it arrived in"},
	} {
		for asked, idr := range map[string]string{"with no IDr": "", "asked for its alias": "02000000" + hex.EncodeToString([]byte("server.testorg.example"))} {
			t.Run(name+" "+asked, func(t *testing.T) {
				inner, _, err := responderExchange(t, payloadExchange{
					initiator: client, responder: first, otherLocal: test.others, families: test.families, over: test.over,
					responderAliases: dualStackPresents, idi: hex.EncodeToString(idi), initiatorAuth: goldenInitiatorAuth(idi),
					noIDr: idr == "", requestIDr: idr,
				}, nil)
				if err == nil || !strings.Contains(err.Error(), test.want) {
					t.Fatalf("the responder took a request over %s with %v, want a refusal naming %q", test.over, err, test.want)
				}
				if findType(inner, PayloadN) == nil || findType(inner, PayloadIDr) != nil {
					t.Errorf("the responder answered %v, want its refusal alone", inner)
				}
			})
		}
	}
}

// a responder with one endpoint answers as it a request arriving in its family alone, with no IDr and asked for its alias alike
// one arriving in the other family is refused, as rule 1 refuses one whose IDr names that endpoint
func TestOneEndpointResponderAnswersInItsFamilyAlone(t *testing.T) {
	client, server := identity.MustParse("testorg/client:2"), identity.MustParse("testorg/server:1")
	idi := EncodeID(ID_FQDN, []byte("client.testorg.example"))
	for name, test := range map[string]struct {
		over net.IP
		want string
	}{
		"in its family":       {net.IPv4(127, 0, 0, 1), ""},
		"in the other family": {net.IPv6loopback, "0 of our 1 are of the IPv6 family it arrived in"},
	} {
		for asked, idr := range map[string]string{"with no IDr": "", "asked for its alias": "02000000" + hex.EncodeToString([]byte("server.testorg.example"))} {
			t.Run(name+" "+asked, func(t *testing.T) {
				inner, accepted, err := responderExchange(t, payloadExchange{
					initiator: client, responder: server, families: map[identity.Identity]Family{server: IPv4}, over: test.over,
					responderAliases: dualStackPresents, idi: hex.EncodeToString(idi), initiatorAuth: goldenInitiatorAuth(idi),
					noIDr: idr == "", requestIDr: idr,
				}, nil)
				if test.want == "" {
					if err != nil || accepted.Local != server {
						t.Fatalf("the responder answered a request over %s as %s with %v, want %s", test.over, accepted.Local, err, server)
					}
					return
				}
				if err == nil || !strings.Contains(err.Error(), test.want) {
					t.Fatalf("the responder took a request over %s with %v, want a refusal naming %q", test.over, err, test.want)
				}
				if findType(inner, PayloadN) == nil || findType(inner, PayloadIDr) != nil || !accepted.Peer.IsZero() {
					t.Errorf("the responder answered %v and accepted %+v, want its refusal alone", inner, accepted)
				}
			})
		}
	}
}

// a responder refuses to start with an endpoint of no family, which no request could arrive in
func TestResponderNeedsAFamilyForEachEndpoint(t *testing.T) {
	_, err := NewResponder(ResponderConfig{
		Hub: listenHub(t), LocalPrivateKey: make(ed25519.PrivateKey, ed25519.PrivateKeySize), Trust: trustsNobody,
		Local: map[identity.Identity]Family{identity.MustParse("testorg/server:1"): IPv4, identity.MustParse("testorg/server:2"): 0},
	})
	if want := "ike: responder endpoint testorg/server:2 needs a family"; err == nil || err.Error() != want {
		t.Errorf("the responder started with %v, want %q", err, want)
	}
}

// a request a dual-stack socket reports by its IPv4-mapped address arrived in IPv4
func TestAnsweringReadsAMappedAddressAsIPv4(t *testing.T) {
	v4, v6 := identity.MustParse("testorg/server:1"), identity.MustParse("testorg/server:2")
	r := &Responder{cfg: ResponderConfig{Local: map[identity.Identity]Family{v4: IPv4, v6: IPv6}}}
	for arrived, want := range map[string]identity.Identity{"127.0.0.1": v4, "::ffff:127.0.0.1": v4, "::1": v6} {
		if got, err := r.answering(familyOf(netip.MustParseAddr(arrived))); err != nil || got != want {
			t.Errorf("a request from %s is answered as %s with %v, want %s", arrived, got, err, want)
		}
	}
}
