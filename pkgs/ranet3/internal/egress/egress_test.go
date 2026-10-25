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
			"a source of the other family",
			Egress{Advertise: prefixes(t, "0.0.0.0/0"), Source4: Source{Addr: netip.MustParseAddr("2001:db8::1")}},
			"is not of that family",
		},
		// The decoder unmaps this spelling, so a source6 carrying it renders to
		// a file that reads back as an IPv4 source6, which this then refuses: a
		// capability taken here whose own file would not load.
		{
			"an IPv4 source6 written as IPv6",
			Egress{Advertise: prefixes(t, "::/0"), Source6: Source{Addr: netip.MustParseAddr("::ffff:198.51.100.7")}},
			"written as IPv6, so write it as 198.51.100.7",
		},
		{
			"an IPv4 source4 written as IPv6",
			Egress{Advertise: prefixes(t, "0.0.0.0/0"), Source4: Source{Addr: netip.MustParseAddr("::ffff:198.51.100.7")}},
			"written as IPv6, so write it as 198.51.100.7",
		},
		// The decoder refuses a zone, so a source carrying one renders to a
		// file that does not load. Only the IPv4-mapped spelling of a source4
		// can carry one, and the zone is the refusal it is told about first.
		{
			"a source6 carrying a zone",
			Egress{Advertise: prefixes(t, "::/0"), Source6: Source{Addr: netip.MustParseAddr("2001:db8::1%eth0")}},
			"carries a zone",
		},
		{
			"a source4 carrying a zone",
			Egress{Advertise: prefixes(t, "0.0.0.0/0"), Source4: Source{Addr: netip.MustParseAddr("::ffff:198.51.100.7%eth0")}},
			"carries a zone",
		},
		// A file writes a source as auto or as an address, and one carrying
		// both is written as the address and read back without the auto, so
		// the capability taken here is not the one its own file loads.
		{
			"a source4 both auto and an address",
			Egress{Advertise: prefixes(t, "0.0.0.0/0"), Source4: Source{Auto: true, Addr: netip.MustParseAddr("198.51.100.7")}},
			"both auto and 198.51.100.7",
		},
		{
			"a source6 both auto and an address",
			Egress{Advertise: prefixes(t, "::/0"), Source6: Source{Auto: true, Addr: netip.MustParseAddr("2001:db8::7")}},
			"both auto and 2001:db8::7",
		},
		{
			"a source nothing can reply to",
			Egress{Advertise: prefixes(t, "0.0.0.0/0"), Source4: Source{Addr: netip.MustParseAddr("127.0.0.1")}},
			"not an address a reply can be sent to",
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
			[]netip.Addr{netip.MustParseAddr("10.88.0.2"), netip.MustParseAddr("10.88.0.3")},
			"carries 2 ipv4 mesh addresses",
		},
		{
			"one of the other family",
			[]netip.Addr{netip.MustParseAddr("2001:db8::1")},
			"carries no ipv4 mesh address",
		},
	} {
		t.Run(one.name, func(t *testing.T) {
			_, err := cfg.ReturnSource(FamilyIPv4, one.addresses)
			if err == nil || !strings.Contains(err.Error(), one.want) {
				t.Fatalf("refused with %v, want a message containing %q", err, one.want)
			}
			if err != nil && !strings.Contains(err.Error(), "egress.source4") {
				t.Errorf("the refusal %q does not name the field that settles it", err)
			}
		})
	}
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
		Source4:   Source{Auto: true},
		Source6:   Source{Addr: netip.MustParseAddr("2001:db8::1")},
		Return:    true,
		Sweep:     schema.Duration(90 * time.Second),
	}
	for _, one := range []struct {
		name    string
		encode  func(any) ([]byte, error)
		decode  func([]byte, any) error
		written string
	}{
		{"yaml", yaml.Marshal, yaml.Unmarshal, "source4: auto"},
		{"json", json.Marshal, json.Unmarshal, `"source4":"auto"`},
		{"toml", encodeTOML, decodeTOML, `source4 = "auto"`},
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
	return a.Source4 == b.Source4 && a.Source6 == b.Source6 &&
		a.Return == b.Return && a.Sweep == b.Sweep
}

// An absent source and one written as auto ask for the same thing, and neither
// reads back as an address the operator did not write.
func TestAbsentSourceStaysAbsent(t *testing.T) {
	var cfg Egress
	if err := yaml.Unmarshal([]byte("advertise: [\"::/0\"]\n"), &cfg); err != nil {
		t.Fatal(err)
	}
	if !cfg.Source4.IsZero() || !cfg.Source6.IsZero() {
		t.Errorf("an absent source parsed as %v and %v", cfg.Source4, cfg.Source6)
	}
	raw, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "source4") {
		t.Errorf("wrote %s, which invents a source nobody configured", raw)
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

// A source is auto or an address and nothing else, said in those words rather
// than as a parse error nobody can act on, under either decoder. The two ask a
// type for different interfaces, so a scalar answering only one of them parses
// under one file extension and is refused under the other.
func TestSourceRefusesWhatIsNeitherAutoNorAnAddress(t *testing.T) {
	var cfg Egress
	err := yaml.Unmarshal([]byte("source4: eth0\n"), &cfg)
	if err == nil || !strings.Contains(err.Error(), "auto or an address") {
		t.Fatalf("yaml refused with %v, want a message naming both spellings", err)
	}
	cfg = Egress{}
	err = decodeTOML([]byte("source4 = \"eth0\"\n"), &cfg)
	if err == nil || !strings.Contains(err.Error(), "auto or an address") {
		t.Fatalf("toml refused with %v, want a message naming both spellings", err)
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
