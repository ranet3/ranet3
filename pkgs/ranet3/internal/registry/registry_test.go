// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

package registry

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/internal/underlay"
)

// TestLoadRegistry exercises the real-world edge cases a production ranet
// registry actually contains (verified against one during development,
// which is not checked in here since registries list real deployments'
// public keys and addresses): null addresses, empty-string addresses
// (distinct from null), hostnames, literal IPv4/IPv6 addresses, and
// non-sequential serial numbers.
func TestLoadRegistry(t *testing.T) {
	x, err := Load("testdata/registry.json")
	if err != nil {
		t.Fatal(err)
	}
	if organizations, nodes := x.Size(); organizations != 2 || nodes != 5 {
		t.Fatalf("loaded %d organizations and %d nodes, want 2 and 5", organizations, nodes)
	}
	if _, err := x.Key(identity.MustParse("example/no-address-yet")); err != nil {
		t.Fatalf("example's key: %v", err)
	}

	// A node with address: null (no known address yet). ResolveRemote
	// must fail gracefully, not panic.
	ep := onlyTarget(t, x, "example/no-address-yet:0")
	if ep.Address != nil {
		t.Fatalf("expected nil address, got %v", *ep.Address)
	}
	if _, err := ep.ResolveRemote(t.Context(), nil, underlay.Unchanged); err == nil {
		t.Fatal("expected ResolveRemote to fail for a nil address")
	}

	// address: "" (empty string, distinct from null) must also fail
	// gracefully rather than being treated as a valid target.
	ep = onlyTarget(t, x, "example/empty-address:0")
	if ep.Address == nil || *ep.Address != "" {
		t.Fatalf("expected empty-string address, got %v", ep.Address)
	}
	if _, err := ep.ResolveRemote(t.Context(), nil, underlay.Unchanged); err == nil {
		t.Fatal("expected ResolveRemote to fail for an empty-string address")
	}

	// A hostname address: just confirm the field parsed correctly. DNS
	// resolution success/failure is environment-dependent and not what
	// this parser test should assert on.
	ep = onlyTarget(t, x, "example/gateway:0")
	if ep.Address == nil || *ep.Address != "gateway.example.invalid" {
		t.Fatalf("unexpected address: %v", ep.Address)
	}
	if ep.AddressFamily != "ip4" || ep.Port != 13000 {
		t.Fatalf("unexpected endpoint: %+v", ep)
	}

	// Non-sequential serial numbers (e.g. "4"/"6" instead of "0"/"1") are
	// used by some real deployments: confirm lookup isn't assuming 0/1.
	onlyTarget(t, x, "example/non-sequential-serials:4")
	onlyTarget(t, x, "example/non-sequential-serials:6")

	// A literal (non-hostname) address should resolve directly without DNS.
	ip, err := onlyTarget(t, x, "other-org/literal-address:0").ResolveRemote(t.Context(), nil, underlay.Unchanged)
	if err != nil {
		t.Fatalf("ResolveRemote: %v", err)
	}
	if ip.String() != "192.0.2.1" {
		t.Fatalf("got %v, want 192.0.2.1", ip)
	}
}

func onlyTarget(t *testing.T, x *Index, endpoint string) Endpoint {
	t.Helper()
	targets := x.Targets(identity.MustParse(endpoint))
	if len(targets) != 1 {
		t.Fatalf("%s has targets %+v, want one", endpoint, targets)
	}
	return targets[0].Endpoint
}

func fixture(t *testing.T) Registry {
	t.Helper()
	b, err := os.ReadFile("testdata/registry.json")
	if err != nil {
		t.Fatal(err)
	}
	var document Registry
	if err := json.Unmarshal(b, &document); err != nil {
		t.Fatal(err)
	}
	return document
}

func TestKeyComesFromTheBlockListingTheNode(t *testing.T) {
	document := fixture(t)
	first := document[0]
	left, right := first, first
	left.Nodes = first.Nodes[:2]
	right.Nodes = first.Nodes[2:]
	right.PublicKey = document[1].PublicKey
	x, err := New(Registry{left, right})
	if err != nil {
		t.Fatal(err)
	}
	want, err := right.publicKey()
	if err != nil {
		t.Fatal(err)
	}
	if got, err := x.Key(identity.MustParse(first.Organization + "/" + first.Nodes[3].CommonName)); err != nil || !got.Equal(want) {
		t.Fatalf("the node listed in the second block of its organization has key %x, %v, want that block's %x", got, err, want)
	}
}

// Resolution has to be cancellable, because Client.Run waits for every dialer
// before it returns and a dialer resolving a hostname whose resolver is
// unreachable would otherwise hold SIGTERM for the resolver's own timeout.
// Dialable decides without a resolver, so it has to refuse only what no
// attempt could fix. A literal the resolver would take, including one carrying
// a zone, is an endpoint a dialer must keep.
func TestDialableRefusesOnlyWhatNoAttemptCanFix(t *testing.T) {
	for address, want := range map[string]bool{
		"198.51.100.9":        true,
		"2001:db8::1":         false,
		"fe80::1%en0":         false,
		"gateway.example.com": true,
		"":                    false,
		"2400::/8":            false,
	} {
		endpoint := Endpoint{SerialNumber: "0", AddressFamily: "ip4", Address: &address}
		if address == "2001:db8::1" || address == "fe80::1%en0" {
			endpoint.AddressFamily = "ip6"
			want = true
		}
		if got := endpoint.Dialable(); got != want {
			t.Errorf("Dialable(%q as %s) = %v, want %v", address, endpoint.AddressFamily, got, want)
		}
	}
	if (Endpoint{SerialNumber: "0", AddressFamily: "ip4"}).Dialable() {
		t.Error("an endpoint with no address at all is dialable")
	}
	wrongFamily := "2001:db8::1"
	if (Endpoint{SerialNumber: "0", AddressFamily: "ip4", Address: &wrongFamily}).Dialable() {
		t.Error("a literal of the wrong family is dialable, and no lookup will fix it")
	}
}

func TestResolveRemoteStopsWhenTheContextDoes(t *testing.T) {
	address := "a-name-no-resolver-should-answer.invalid"
	ep := Endpoint{SerialNumber: "0", AddressFamily: "ip4", Address: &address}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	start := time.Now()
	if _, err := ep.ResolveRemote(ctx, nil, underlay.Unchanged); err == nil {
		t.Fatal("a canceled lookup reported an address")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("a canceled lookup took %s, so shutdown waits on the resolver", elapsed)
	}
}

// ResolveRemote handed no Prepare refuses, never read as one that does nothing, a literal address it would answer at once among them
func TestResolveRemoteRefusesAMissingPrepare(t *testing.T) {
	for _, address := range []string{"192.0.2.1", "gateway.example."} {
		endpoint := Endpoint{SerialNumber: "1", AddressFamily: "ip4", Address: &address, Port: 13000}
		if _, err := endpoint.ResolveRemote(t.Context(), nil, nil); !errors.Is(err, errUnprepared) {
			t.Errorf("resolving %s with no Prepare answered %v, want the refusal", address, err)
		}
	}
}

// The lookup is narrowed to the family the endpoint declares, so a name that
// has only the other family's records fails at the resolver rather than after
// it, and a dual-stack name costs one query rather than two.
func TestResolverNetworkFollowsTheDeclaredFamily(t *testing.T) {
	for family, want := range map[string]string{
		"ip4": "ip4",
		"ip6": "ip6",
		"":    "ip",
		"ip":  "ip",
	} {
		if got := resolverNetwork(family); got != want {
			t.Errorf("family %q resolves over %q, want %q", family, got, want)
		}
	}
}

// a common name listed twice names one node with two entries, and an organization split across several blocks, each with its own key, is a supported shape
func TestValidateRefusesADuplicateNodeInOneBlock(t *testing.T) {
	reg := fixture(t)
	first := reg[0]
	first.Nodes = append(append([]Node(nil), first.Nodes...), first.Nodes[0])
	if err := (Registry{first}).Validate(); err == nil {
		t.Error("a block naming one node twice was accepted, and the second is unreachable")
	}
	// The split shape is still accepted: the same name in two blocks is how
	// an organization is carried across them.
	left, right := reg[0], reg[0]
	left.Nodes, right.Nodes = reg[0].Nodes[:1], reg[0].Nodes[1:]
	if err := (Registry{left, right}).Validate(); err != nil {
		t.Errorf("an organization split across two blocks was refused: %v", err)
	}
	// two blocks naming one node under different keys would leave the order of the array deciding who authenticates
	left, right = reg[0], reg[0]
	left.Nodes, right.Nodes = reg[0].Nodes[:1], reg[0].Nodes[:1]
	right.PublicKey = reg[1].PublicKey
	if left.PublicKey == right.PublicKey {
		t.Fatal("the fixture's two organizations share a key, so this proves nothing")
	}
	if err := (Registry{left, right}).Validate(); err == nil {
		t.Error("one node carried two public keys across two blocks of one organization was accepted")
	}
}

// A second document after the first is the residue of a partial write or a
// bad concatenation, and a stray closing bracket is one character of that
// concatenation.
func TestLoadRefusesTrailingData(t *testing.T) {
	good, err := os.ReadFile("testdata/registry.json")
	if err != nil {
		t.Fatal(err)
	}
	for name, trailing := range map[string]string{
		"a second document":              "\n{\"anything\":\"at all\"}\n",
		"a stray bracket and a document": "]\n{\"anything\":\"at all\"}\n",
		"a stray brace and a document":   "}\n{\"anything\":\"at all\"}\n",
		"a stray bracket":                "]",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "registry.json")
			if err := os.WriteFile(path, append(append([]byte(nil), good...), trailing...), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil {
				t.Errorf("a registry followed by %s was loaded without complaint", name)
			}
		})
	}
	// Trailing whitespace is not trailing data.
	path := filepath.Join(t.TempDir(), "registry.json")
	if err := os.WriteFile(path, append(append([]byte(nil), good...), "\n\n  \n"...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Errorf("a registry with trailing whitespace was refused: %v", err)
	}
}

func keyPEM(seed byte) (string, ed25519.PublicKey) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		panic(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), key
}

func loadText(t testing.TB, text string) (*Index, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "registry.json")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(path)
}

// a member named twice and a string that is not UTF-8 refuse the whole document wherever they sit, remarks included, and a name in a spelling no field has refuses it outside remarks
func TestLoadRefusesRepeatedOrMisspelledNamesAndInvalidUTF8(t *testing.T) {
	firstPEM, firstKey := keyPEM(1)
	secondPEM, _ := keyPEM(2)
	first, second := strconv.Quote(firstPEM), strconv.Quote(secondPEM)
	endpoint := `{"serial_number":"0","address_family":"ip4","address":"192.0.2.1","port":13000}`
	gateway := `{"common_name":"gateway","endpoints":[` + endpoint + `],"remarks":{}}`
	laptop := `{"common_name":"laptop","endpoints":[],"remarks":{}}`
	block := func(members string) string { return `[{"organization":"example",` + members + `}]` }
	withNode := func(node string) string { return block(`"public_key":` + first + `,"nodes":[` + node + `]`) }
	kelvin, longS := string(rune(0x212A)), string(rune(0x017F))
	escapedUnderscore := "\\" + "u005f"

	x, err := loadText(t, withNode(gateway))
	if err != nil {
		t.Fatalf("the document every case below departs from was refused: %v", err)
	}
	if key, err := x.Key(identity.MustParse("example/gateway")); err != nil || !key.Equal(firstKey) {
		t.Fatalf("the document every case below departs from gives example/gateway the key %x, %v, want %x", key, err, firstKey)
	}

	for name, text := range map[string]string{
		"public_key twice":                                block(`"public_key":` + first + `,"public_key":` + second + `,"nodes":[` + gateway + `]`),
		"public_key twice, once through an escape":        block(`"public_key":` + first + `,"public` + escapedUnderscore + `key":` + second + `,"nodes":[` + gateway + `]`),
		"Public_Key alone":                                block(`"Public_Key":` + second + `,"nodes":[` + gateway + `]`),
		"PUBLIC_KEY beside public_key":                    block(`"public_key":` + first + `,"PUBLIC_KEY":` + second + `,"nodes":[` + gateway + `]`),
		"public_key with a Kelvin sign beside public_key": block(`"public_key":` + first + `,"public_` + kelvin + `ey":` + second + `,"nodes":[` + gateway + `]`),
		"nodes with a long s beside nodes":                block(`"public_key":` + first + `,"nodes":[` + gateway + `],"node` + longS + `":[` + laptop + `]`),
		"byte 0xff in a name inside remarks":              withNode("{\"common_name\":\"gateway\",\"endpoints\":[],\"remarks\":{\"si\xffte\":\"a\"}}"),
		"a lone surrogate escape in a common_name":        withNode(`{"common_name":"gate\ud800way","endpoints":[],"remarks":{}}`),
		"an unknown member":                               block(`"public_key":` + first + `,"nodes":[` + gateway + `],"extra":1`),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := loadText(t, text)
			if err == nil {
				t.Fatalf("a document with %s was loaded", name)
			}
			if !strings.HasPrefix(err.Error(), "registry: parse ") {
				t.Errorf("a document with %s was refused as %q, want the parse to refuse it", name, err)
			}
		})
	}
}
