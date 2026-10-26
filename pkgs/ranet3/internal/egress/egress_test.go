// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package egress

import (
	"encoding/json"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	"go.yaml.in/yaml/v3"

	"ranet3.com/pkgs/ranet3/schema"
)

func prefixes(t *testing.T, raw ...string) []schema.Prefix {
	t.Helper()
	out := make([]schema.Prefix, 0, len(raw))
	for _, one := range raw {
		prefix, err := schema.ParsePrefix(one)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, prefix)
	}
	return out
}

// plain is the file's spelling of a prefix list as the announcement carries it.
func plain(entries []schema.Prefix) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(entries))
	for _, entry := range entries {
		out = append(out, entry.Prefix)
	}
	return out
}

// Validation runs in this package rather than in internal/config, so a
// capability that arrived from a control plane is judged by the same rules a
// written one is.
func TestValidateRefusesWhatCannotBeTranslated(t *testing.T) {
	for _, one := range []struct {
		name string
		cfg  Egress
		want string
	}{
		{
			"a return with nothing advertised",
			Egress{Return: true},
			"no prefix to translate from",
		},
		{
			"a prefix with bits under its length",
			Egress{Advertise: []schema.Prefix{schema.MustPrefix("198.51.100.7/24")}},
			"bits set below its prefix length",
		},
		{
			"the same prefix twice",
			Egress{Advertise: prefixes(t, "::/0", "::/0")},
			"written twice",
		},
		{
			// The two spellings reach different tables here, so the mapped one
			// would be translated by an IPv6 rule matching an address family
			// no packet on the wire carries.
			"an IPv4 prefix written as IPv6",
			Egress{Advertise: prefixes(t, "::ffff:198.51.100.0/120")},
			"written as IPv6, so write it as 198.51.100.0/24",
		},
		{
			"a from written twice",
			Egress{Advertise: prefixes(t, "0.0.0.0/0"), Translate: []Class{class(t, "198.51.100.0/24", "none"), class(t, "198.51.100.0/24", "auto")}},
			"egress: cap.egress translate from 198.51.100.0/24 is written twice",
		},
		{
			"a from with bits under its length",
			Egress{Advertise: prefixes(t, "0.0.0.0/0"), Translate: []Class{class(t, "198.51.100.7/24", "auto")}},
			"egress: cap.egress translate from 198.51.100.7/24 has bits set below its prefix length",
		},
		{
			"an IPv4 from written as IPv6",
			Egress{Advertise: prefixes(t, "0.0.0.0/0"), Translate: []Class{class(t, "::ffff:198.51.100.0/120", "none")}},
			"egress: cap.egress translate from ::ffff:198.51.100.0/120 is an IPv4 prefix written as IPv6, so write it as 198.51.100.0/24",
		},
		{
			"a to of the other family",
			Egress{Advertise: prefixes(t, "0.0.0.0/0"), Translate: []Class{class(t, "0.0.0.0/0", "2001:db8::1")}},
			"egress: cap.egress translate class 0.0.0.0/0 to 2001:db8::1 is not of its from's family",
		},
		// The decoder unmaps this spelling, so a class carrying it renders to a
		// file that reads back as an IPv4 address, which an IPv6 class then
		// refuses: a capability taken here whose own file would not load.
		{
			"an IPv4 to of an IPv6 class written as IPv6",
			Egress{Advertise: prefixes(t, "::/0"), Translate: []Class{{From: schema.MustPrefix("::/0"), To: Translation{Addr: netip.MustParseAddr("::ffff:198.51.100.7")}}}},
			"egress: cap.egress translate class ::/0 to ::ffff:198.51.100.7 is an IPv4 address written as IPv6, so write it as 198.51.100.7",
		},
		{
			"an IPv4 to written as IPv6",
			Egress{Advertise: prefixes(t, "0.0.0.0/0"), Translate: []Class{{From: schema.MustPrefix("0.0.0.0/0"), To: Translation{Addr: netip.MustParseAddr("::ffff:198.51.100.7")}}}},
			"egress: cap.egress translate class 0.0.0.0/0 to ::ffff:198.51.100.7 is an IPv4 address written as IPv6",
		},
		// The decoder refuses a zone, so a class carrying one renders to a file
		// that does not load. Only the IPv4-mapped spelling of an IPv4 address
		// can carry one, and the zone is the refusal it is told about first.
		{
			"an IPv6 to carrying a zone",
			Egress{Advertise: prefixes(t, "::/0"), Translate: []Class{{From: schema.MustPrefix("::/0"), To: Translation{Addr: netip.MustParseAddr("2001:db8::1%eth0")}}}},
			"egress: cap.egress translate class ::/0 to 2001:db8::1%eth0 carries a zone",
		},
		{
			"an IPv4 to carrying a zone",
			Egress{Advertise: prefixes(t, "0.0.0.0/0"), Translate: []Class{{From: schema.MustPrefix("0.0.0.0/0"), To: Translation{Addr: netip.MustParseAddr("::ffff:198.51.100.7%eth0")}}}},
			"egress: cap.egress translate class 0.0.0.0/0 to ::ffff:198.51.100.7%eth0 carries a zone",
		},
		// A file writes a to as one of the three, and one carrying two is
		// written as one and read back without the other, so the capability
		// taken here is not the one its own file loads.
		{
			"a to both auto and an address",
			Egress{Advertise: prefixes(t, "0.0.0.0/0"), Translate: []Class{{From: schema.MustPrefix("0.0.0.0/0"), To: Translation{Auto: true, Addr: netip.MustParseAddr("198.51.100.7")}}}},
			"egress: cap.egress translate class 0.0.0.0/0 has the to auto and 198.51.100.7 at once",
		},
		{
			"a to both none and auto",
			Egress{Advertise: prefixes(t, "::/0"), Translate: []Class{{From: schema.MustPrefix("2001:db8::/32"), To: Translation{None: true, Auto: true}}}},
			"egress: cap.egress translate class 2001:db8::/32 has the to none and auto at once",
		},
		{
			"a class naming no to",
			Egress{Advertise: prefixes(t, "0.0.0.0/0"), Translate: []Class{{From: schema.MustPrefix("198.51.100.0/24")}}},
			"egress: cap.egress translate class 198.51.100.0/24 names no to",
		},
		{
			"a to nothing can reply to",
			Egress{Advertise: prefixes(t, "0.0.0.0/0"), Translate: []Class{class(t, "0.0.0.0/0", "127.0.0.1")}},
			"egress: cap.egress translate class 0.0.0.0/0 to 127.0.0.1 is not an address a reply can be sent to",
		},
		// An exit that translates nothing for anyone is an open relay for the
		// overlay's sources onto its upstream, which no operator of a product
		// deployment means.
		{
			"none from every IPv4 source",
			Egress{Advertise: prefixes(t, "0.0.0.0/0"), Translate: []Class{class(t, "0.0.0.0/0", "none")}},
			"egress: cap.egress translate class 0.0.0.0/0 is none, which leaves every ipv4 source untranslated: an exit that translates nothing for anyone is an open relay",
		},
		{
			"none from every IPv6 source",
			Egress{Advertise: prefixes(t, "::/0"), Translate: []Class{class(t, "2001:db8::/32", "none"), class(t, "::/0", "none")}},
			"egress: cap.egress translate class ::/0 is none, which leaves every ipv6 source untranslated",
		},
		{
			"a negative sweep",
			Egress{Advertise: prefixes(t, "0.0.0.0/0"), Sweep: schema.Duration(-time.Second)},
			"is negative",
		},
	} {
		t.Run(one.name, func(t *testing.T) {
			err := one.cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), one.want) {
				t.Fatalf("refused with %v, want a message containing %q", err, one.want)
			}
		})
	}
}

// The return direction translates to one address, so a node that cannot say
// which is refused rather than picked from: the choice decides the address
// every flow out of this node's LAN appears as, and guessing it would change
// under an unrelated edit to the address list.
func TestReturnWithoutOneMeshAddressIsRefusedByName(t *testing.T) {
	cfg := Egress{Return: true, Advertise: prefixes(t, "198.51.100.0/24")}
	for _, one := range []struct {
		name      string
		addresses []netip.Addr
		want      string
	}{
		{"none at all", nil, "carries no ipv4 mesh address"},
		{
			"two of the family",
			[]netip.Addr{netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.3")},
			"carries 2 ipv4 mesh addresses (192.0.2.2, 192.0.2.3)",
		},
		{
			"one of the other family",
			[]netip.Addr{netip.MustParseAddr("3fff::2")},
			"carries no ipv4 mesh address",
		},
	} {
		t.Run(one.name, func(t *testing.T) {
			_, err := cfg.ReturnSource(FamilyIPv4, one.addresses)
			if err == nil || !strings.Contains(err.Error(), one.want) {
				t.Fatalf("refused with %v, want a message containing %q", err, one.want)
			}
			if err != nil && !strings.Contains(err.Error(), "in cap.egress translate as the to of the class from 0.0.0.0/0") {
				t.Errorf("the refusal %q does not name the class that settles it", err)
			}
		})
	}
}

// The In direction translates to the address of its family's class from
// every source, and to the one mesh address where that class is auto or
// absent, whatever a narrower class names
func TestReturnTakesTheAddressOfTheClassFromEverySource(t *testing.T) {
	mesh := []netip.Addr{netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("3fff::2")}
	for _, one := range []struct {
		name      string
		translate []Class
		want      string
	}{
		{"no class", nil, "192.0.2.2"},
		{"an address from every source", []Class{class(t, "198.51.100.0/25", "198.51.100.9"), class(t, "0.0.0.0/0", "198.51.100.7")}, "198.51.100.7"},
		{"auto from every source", []Class{class(t, "0.0.0.0/0", "auto")}, "192.0.2.2"},
		{"an address from a narrower prefix alone", []Class{class(t, "0.0.0.0/1", "198.51.100.7")}, "192.0.2.2"},
		{"an address from every IPv6 source", []Class{class(t, "::/0", "2001:db8::7")}, "192.0.2.2"},
	} {
		cfg := Egress{Return: true, Advertise: prefixes(t, "198.51.100.0/24"), Translate: one.translate}
		if got, err := cfg.ReturnSource(FamilyIPv4, mesh); err != nil || got != netip.MustParseAddr(one.want) {
			t.Errorf("with %s the In direction translates to %v (%v), want %s", one.name, got, err, one.want)
		}
	}
}

// class is a class as a file writes it, its to read as the decoder reads one
func class(t *testing.T, from, to string) Class {
	t.Helper()
	prefix, err := schema.ParsePrefix(from)
	if err != nil {
		t.Fatal(err)
	}
	var translation Translation
	if err := translation.UnmarshalText([]byte(to)); err != nil {
		t.Fatal(err)
	}
	return Class{From: prefix, To: translation}
}

// A capability written in a file and one sent on the wire are the same
// capability, so an operator and a control plane cannot disagree about a
// field's spelling. All three decoders are checked, because the two the file
// reader dispatches on ask a type for different interfaces, and a field
// carrying one and not the other parses under one extension and is refused
// under the other.
func TestCapabilityRoundTripsThroughEverySerialization(t *testing.T) {
	want := Egress{
		Advertise: prefixes(t, "0.0.0.0/0", "2001:db8:1::/48"),
		// one of each spelling a to takes, so each crosses every encoder in this one case
		Translate: []Class{class(t, "198.51.100.0/24", "none"), class(t, "0.0.0.0/0", "auto"), class(t, "::/0", "2001:db8::1")},
		Return:    true,
		Sweep:     schema.Duration(90 * time.Second),
	}
	for _, one := range []struct {
		name    string
		encode  func(any) ([]byte, error)
		decode  func([]byte, any) error
		written string
	}{
		{"yaml", yaml.Marshal, yaml.Unmarshal, "to: none"},
		{"json", json.Marshal, json.Unmarshal, `{"from":"198.51.100.0/24","to":"none"}`},
		{"toml", encodeTOML, decodeTOML, `to = "none"`},
	} {
		t.Run(one.name, func(t *testing.T) {
			raw, err := one.encode(want)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(raw), one.written) {
				t.Errorf("wrote %s, which does not carry %s", raw, one.written)
			}
			var got Egress
			if err := one.decode(raw, &got); err != nil {
				t.Fatalf("%s: %v", raw, err)
			}
			if !sameCapability(got, want) {
				t.Errorf("came back as %+v, want %+v", got, want)
			}
		})
	}
}

func encodeTOML(value any) ([]byte, error) {
	var out strings.Builder
	if err := toml.NewEncoder(&out).Encode(value); err != nil {
		return nil, err
	}
	return []byte(out.String()), nil
}

func decodeTOML(body []byte, target any) error {
	_, err := toml.Decode(string(body), target)
	return err
}

// sameCapability compares two capabilities field by field, since a prefix
// slice does not compare with ==.
func sameCapability(a, b Egress) bool {
	if len(a.Advertise) != len(b.Advertise) {
		return false
	}
	for i := range a.Advertise {
		if a.Advertise[i].Prefix != b.Advertise[i].Prefix {
			return false
		}
	}
	return slices.Equal(a.Translate, b.Translate) && a.Return == b.Return && a.Sweep == b.Sweep
}

// An absent translate list asks for auto from every source, and reads back as
// no class rather than one the operator did not write.
func TestAbsentTranslateStaysAbsent(t *testing.T) {
	var cfg Egress
	if err := yaml.Unmarshal([]byte("advertise: [\"::/0\"]\n"), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Translate != nil {
		t.Errorf("an absent translate list parsed as %v", cfg.Translate)
	}
	raw, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "translate") {
		t.Errorf("wrote %s, which invents a class nobody configured", raw)
	}
}

// A duration is a scalar in every spelling. Reading the value off a sequence
// gives the empty string, and `invalid duration ""` names neither the line nor
// what was written there.
func TestSweepRefusesWhatIsNotAScalar(t *testing.T) {
	var cfg Egress
	err := yaml.Unmarshal([]byte("sweep: [30s]\n"), &cfg)
	if err == nil || !strings.Contains(err.Error(), "a sequence") {
		t.Fatalf("refused with %v, want a message saying what was written instead", err)
	}
}

// A to is none, auto or an address and nothing else, said in those words
// rather than as a parse error nobody can act on, under either decoder. The
// two ask a type for different interfaces, so a scalar answering only one of
// them parses under one file extension and is refused under the other.
func TestTranslationRefusesWhatIsNeitherNoneAutoNorAnAddress(t *testing.T) {
	var cfg Egress
	err := yaml.Unmarshal([]byte("translate: [{from: 198.51.100.0/24, to: eth0}]\n"), &cfg)
	if err == nil || !strings.Contains(err.Error(), "none, auto or an address") {
		t.Fatalf("yaml refused with %v, want a message naming the three spellings", err)
	}
	cfg = Egress{}
	err = decodeTOML([]byte("translate = [{ from = \"198.51.100.0/24\", to = \"eth0\" }]\n"), &cfg)
	if err == nil || !strings.Contains(err.Error(), "none, auto or an address") {
		t.Fatalf("toml refused with %v, want a message naming the three spellings", err)
	}
}

// A class of auto from every source says what no class says, and the order
// classes are written in decides nothing, so neither is a change between two
// capabilities as the translator runs them
func TestNormalizedClassesAreTheClassesTheTranslatorRuns(t *testing.T) {
	written := Egress{Advertise: prefixes(t, "0.0.0.0/0", "::/0"), Translate: []Class{
		class(t, "::/0", "auto"), class(t, "198.51.100.0/24", "none"), class(t, "0.0.0.0/0", "auto"), class(t, "192.0.2.0/24", "198.51.100.7"),
	}}
	want := []Class{class(t, "192.0.2.0/24", "198.51.100.7"), class(t, "198.51.100.0/24", "none")}
	if got := written.Normalized().Translate; !slices.Equal(got, want) {
		t.Errorf("normalized to %v, want %v", got, want)
	}
	if got := (Egress{Translate: []Class{class(t, "0.0.0.0/0", "auto")}}).Normalized().Translate; got != nil {
		t.Errorf("a class of auto from every source alone normalized to %v, want no class", got)
	}
	if got := (Egress{Translate: []Class{class(t, "0.0.0.0/0", "198.51.100.7")}}).Normalized().Translate; len(got) != 1 {
		t.Errorf("an address from every source normalized to %v, want it kept", got)
	}
}

// The block written in a file and the one sent on the wire are the same
func TestBorderRoundTripsThroughEverySerialization(t *testing.T) {
	want := Border{Overlay: prefixes(t, "198.18.0.0/15", "3fff::/20")}
	for _, one := range []struct {
		name    string
		encode  func(any) ([]byte, error)
		decode  func([]byte, any) error
		written string
	}{
		{"yaml", yaml.Marshal, yaml.Unmarshal, "overlay:"},
		{"json", json.Marshal, json.Unmarshal, `"overlay":["198.18.0.0/15","3fff::/20"]`},
		{"toml", encodeTOML, decodeTOML, `overlay = ["198.18.0.0/15", "3fff::/20"]`},
	} {
		t.Run(one.name, func(t *testing.T) {
			raw, err := one.encode(want)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(raw), one.written) {
				t.Errorf("wrote %s, which does not carry %s", raw, one.written)
			}
			var got Border
			if err := one.decode(raw, &got); err != nil {
				t.Fatalf("%s: %v", raw, err)
			}
			if !slices.Equal(plain(got.Overlay), plain(want.Overlay)) {
				t.Errorf("came back as %v, want %v", got.Overlay, want.Overlay)
			}
		})
	}
}
