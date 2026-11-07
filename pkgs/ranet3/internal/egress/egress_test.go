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

	"ranet3.com/pkgs/ranet3/internal/packet"
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
			"egress: cap.egress translate classes 2001:db8::/32 and ::/0 are none, which leaves every ipv6 source untranslated",
		},
		{
			"none from both halves of IPv4",
			Egress{Advertise: prefixes(t, "0.0.0.0/0"), Translate: []Class{class(t, "128.0.0.0/1", "none"), class(t, "0.0.0.0/1", "none")}},
			"egress: cap.egress translate classes 0.0.0.0/1 and 128.0.0.0/1 are none, which leaves every ipv4 source untranslated: an exit that translates nothing for anyone is an open relay",
		},
		// the auto class takes no address, both halves of it taking none
		{
			"none from every IPv6 source past an auto class it splits",
			Egress{Advertise: prefixes(t, "::/0"), Translate: []Class{
				class(t, "::/0", "none"), class(t, "2001:db8::/32", "auto"), class(t, "2001:db8::/33", "none"), class(t, "2001:db8:8000::/33", "none"),
			}},
			"egress: cap.egress translate classes 2001:db8::/33 and 2001:db8:8000::/33 and ::/0 are none, which leaves every ipv6 source untranslated",
		},
		{
			"none from every IPv4 source beside an auto class a longer none leaves only multicast and class E",
			Egress{Advertise: prefixes(t, "0.0.0.0/0"), Translate: []Class{class(t, "0.0.0.0/0", "none"), class(t, "192.0.0.0/2", "auto"), class(t, "192.0.0.0/3", "none")}},
			"egress: cap.egress translate classes 192.0.0.0/3 and 0.0.0.0/0 are none, which leaves every ipv4 source untranslated",
		},
		{
			"none from every IPv6 source beside an auto class a longer none leaves only the unspecified and loopback addresses",
			Egress{Advertise: prefixes(t, "::/0"), Translate: []Class{class(t, "::/0", "none"), class(t, "::/126", "auto"), class(t, "::2/127", "none")}},
			"egress: cap.egress translate classes ::2/127 and ::/0 are none, which leaves every ipv6 source untranslated",
		},
		{
			"a negative sweep",
			Egress{Advertise: prefixes(t, "0.0.0.0/0"), Sweep: schema.Duration(-time.Second)},
			"is negative",
		},
		{
			"a share past any connection table",
			Egress{Advertise: prefixes(t, "0.0.0.0/0"), FlowsPerSource: MaxFlowsPerSource + 1},
			"egress: cap.egress flows_per_source 2147483648 is past 2147483647",
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

// Classes of none that leave some source of each family translated load: a
// longer translating class inside a none from every source, and a none
// narrower than its family beside the auto every other source takes
func TestNoneLeavingASourceTranslatedLoads(t *testing.T) {
	for _, cfg := range []Egress{
		{Advertise: prefixes(t, "::/0"), Translate: []Class{class(t, "::/0", "none"), class(t, "2001:db8::/32", "auto")}},
		{Advertise: prefixes(t, "0.0.0.0/0", "::/0"), Translate: []Class{class(t, "0.0.0.0/1", "none"), class(t, "2001:db8::/32", "none")}},
	} {
		if err := cfg.Validate(); err != nil {
			t.Errorf("%v refused: %v", cfg.Translate, err)
		}
	}
}

// A class that translates only sources no router forwards a packet from
// translates nothing, and is refused by its from whether or not a class of
// none from every source stands beside it, while a class of none over the same
// sources, which relays nothing, loads. A class reaching past them holds a
// source a router forwards and loads beside the none from every source.
func TestClassTranslatingOnlySourcesNoRouterForwardsIsRefused(t *testing.T) {
	for _, from := range []string{
		"ff00::/8", "fe80::/10", "::1/128", "::/127",
		"224.0.0.0/4", "224.0.0.0/3", "240.0.0.0/4", "255.255.255.255/32", "127.0.0.0/8", "0.0.0.0/32", "0.0.0.0/8", "169.254.0.0/16",
	} {
		every, address := "0.0.0.0/0", "198.51.100.9"
		if strings.Contains(from, ":") {
			every, address = "::/0", "2001:db8::9"
		}
		for _, to := range []string{"auto", address} {
			want := "egress: cap.egress translate class " + from + " to " + to + " holds only sources a router forwards no packet from, so it translates nothing"
			for _, translate := range [][]Class{{class(t, every, "none"), class(t, from, to)}, {class(t, from, to)}} {
				if err := (Egress{Advertise: prefixes(t, every), Translate: translate}).Validate(); err == nil || err.Error() != want {
					t.Errorf("%v refused with %v, want %q", translate, err, want)
				}
			}
		}
		if err := (Egress{Advertise: prefixes(t, every), Translate: []Class{class(t, from, "none")}}).Validate(); err != nil {
			t.Errorf("%s none refused: %v", from, err)
		}
	}
	for _, from := range []string{"0.0.0.0/7", "126.0.0.0/7", "169.254.0.0/15", "192.0.0.0/2", "::/126", "fe80::/9", "fe00::/7"} {
		every := "0.0.0.0/0"
		if strings.Contains(from, ":") {
			every = "::/0"
		}
		translate := []Class{class(t, every, "none"), class(t, from, "auto")}
		if err := (Egress{Advertise: prefixes(t, every), Translate: translate}).Validate(); err != nil {
			t.Errorf("%v refused: %v", translate, err)
		}
	}
}

// sourceless holds exactly where packet.InvalidSource does, since untranslated
// takes every other source for one the exit forwards: a block InvalidSource
// gains alone lets a class translating only its sources stand beside a none
// from every source. The two are compared on each side of every edge of their
// blocks and of every IPv4 and IPv6 /16, so any block of a /16 or shorter that
// either gains holds an address compared. One class takes ::ffff:0:0/96 whole,
// since no From lies inside it, so sourceless holds for it exactly when
// InvalidSource holds at every mapped address, read at the mapped form of each
// IPv4 address compared.
func TestSourcelessHoldsExactlyWhereInvalidSourceDoes(t *testing.T) {
	mapped := true
	check := func(address netip.Addr) {
		if !address.IsValid() {
			return
		}
		if address.Is4() {
			mapped = mapped && packet.InvalidSource(netip.AddrFrom16(address.As16()))
		}
		if got, want := sourceless(netip.PrefixFrom(address, address.BitLen())), packet.InvalidSource(address); got != want {
			t.Errorf("sourceless at %s is %t, and packet.InvalidSource %t", address, got, want)
		}
	}
	// the first address of each block and the one past its last
	for _, edge := range []string{
		"0.0.0.0", "1.0.0.0", "127.0.0.0", "128.0.0.0", "169.254.0.0", "169.255.0.0", "224.0.0.0", "240.0.0.0",
		"::", "::1", "::2", "fe80::", "fec0::", "ff00::",
	} {
		check(netip.MustParseAddr(edge).Prev())
		check(netip.MustParseAddr(edge))
	}
	for i := range 1 << 16 {
		for _, first := range []netip.Addr{netip.AddrFrom4([4]byte{byte(i >> 8), byte(i)}), netip.AddrFrom16([16]byte{byte(i >> 8), byte(i)})} {
			check(first.Prev())
			check(first)
		}
	}
	check(netip.MustParseAddr("255.255.255.255"))
	check(netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"))
	if got := sourceless(netip.MustParsePrefix("::ffff:0:0/96")); got != mapped {
		t.Errorf("sourceless of ::ffff:0:0/96 is %t, and packet.InvalidSource at every mapped address %t", got, mapped)
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

// Under a class of none from every source a node carrying no mesh address or
// several is told to carry one, since naming the address as the to of that
// class would undo its none
func TestReturnUnderNoneFromEverySourceAsksForOneMeshAddress(t *testing.T) {
	cfg := Egress{Return: true, Advertise: prefixes(t, "198.51.100.0/24"), Translate: []Class{class(t, "0.0.0.0/0", "none"), class(t, "198.51.100.0/24", "auto")}}
	for _, one := range []struct {
		addresses []netip.Addr
		carries   string
	}{
		{nil, "0"},
		{[]netip.Addr{netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.3")}, "2"},
	} {
		want := "egress: return is set and the class from 0.0.0.0/0 is none, so this node translates to its own ipv4 mesh address, and it carries " + one.carries + " rather than one: give it exactly one through cap.route and cap.table"
		if _, err := cfg.ReturnSource(FamilyIPv4, one.addresses); err == nil || err.Error() != want {
			t.Errorf("with mesh addresses %v refused with %v, want %q", one.addresses, err, want)
		}
	}
}

// The In direction translates to the address of its family's class from
// every source, and to the one mesh address where that class is auto, none or
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
		{"none from every source", []Class{class(t, "0.0.0.0/0", "none")}, "192.0.2.2"},
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
		Translate:      []Class{class(t, "198.51.100.0/24", "none"), class(t, "0.0.0.0/0", "auto"), class(t, "::/0", "2001:db8::1")},
		Return:         true,
		FlowsPerSource: 1000,
		Sweep:          schema.Duration(90 * time.Second),
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
	return slices.Equal(a.Translate, b.Translate) && a.Return == b.Return && a.FlowsPerSource == b.FlowsPerSource && a.Sweep == b.Sweep
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

// A share left out runs the default, so it and one written as the default are
// one capability as the translator runs it, and SourceLimit reads the share in
// force either way and the one named where a file names another
func TestShareLeftOutIsTheDefault(t *testing.T) {
	written := Egress{FlowsPerSource: DefaultFlowsPerSource}
	if left, full := (Egress{}).Normalized(), written.Normalized(); left.FlowsPerSource != full.FlowsPerSource {
		t.Errorf("a share left out normalized to %d and one written as the default to %d, want one", left.FlowsPerSource, full.FlowsPerSource)
	}
	for _, e := range []Egress{{}, written, (Egress{}).Normalized()} {
		if got := e.SourceLimit(); got != DefaultFlowsPerSource {
			t.Errorf("%+v runs a share of %d, want the default %d", e, got, DefaultFlowsPerSource)
		}
	}
	if got := (Egress{FlowsPerSource: 300}).SourceLimit(); got != 300 {
		t.Errorf("a share of 300 runs as %d", got)
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
func TestAntispoofRoundTripsThroughEverySerialization(t *testing.T) {
	want := Antispoof{Exempt: prefixes(t, "198.18.0.0/24"), Interface: map[string]AntispoofInterface{"wl*": {Exempt: prefixes(t, "3fff::/48")}}}
	for _, one := range []struct {
		name    string
		encode  func(any) ([]byte, error)
		decode  func([]byte, any) error
		written string
	}{
		{"yaml", yaml.Marshal, yaml.Unmarshal, "wl*:"},
		{"json", json.Marshal, json.Unmarshal, `"interface":{"wl*":{"exempt":["3fff::/48"]}}`},
		{"toml", encodeTOML, decodeTOML, `[interface."wl*"]`},
	} {
		t.Run(one.name, func(t *testing.T) {
			raw, err := one.encode(want)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(raw), one.written) {
				t.Errorf("wrote %s, which does not carry %s", raw, one.written)
			}
			var got Antispoof
			if err := one.decode(raw, &got); err != nil {
				t.Fatalf("%s: %v", raw, err)
			}
			if !slices.Equal(plain(got.Exempt), plain(want.Exempt)) || len(got.Interface) != 1 || !slices.Equal(plain(got.Interface["wl*"].Exempt), plain(want.Interface["wl*"].Exempt)) {
				t.Errorf("came back as %+v, want %+v", got, want)
			}
		})
	}
}

// The exemptions are the shared ones first and then each interface's by name,
// each list sorted, and the carved prefixes are every carve-out's and every
// exemption's, which is where the mesh's own prefixes are dropped ahead of
// either accept
func TestBorderExemptionsAndCarvedPrefixes(t *testing.T) {
	border := Border{Overlay: prefixes(t, "198.18.0.0/15", "3fff::/20"), Antispoof: Antispoof{
		Exempt: prefixes(t, "3fff:0:1::/48", "198.18.1.0/24"),
		Interface: map[string]AntispoofInterface{
			"wl*":  {Exempt: prefixes(t, "198.18.3.0/24", "198.18.2.0/24")},
			"eth1": {Exempt: prefixes(t, "198.18.4.0/24")},
		},
	}}
	p := netip.MustParsePrefix
	want := []Exemption{
		{Prefix: p("198.18.1.0/24")}, {Prefix: p("3fff:0:1::/48")},
		{Interface: "eth1", Prefix: p("198.18.4.0/24")},
		{Interface: "wl*", Prefix: p("198.18.2.0/24")}, {Interface: "wl*", Prefix: p("198.18.3.0/24")},
	}
	if got := border.Exemptions(); !slices.Equal(got, want) {
		t.Errorf("the exemptions read %v, want %v", got, want)
	}
	carved := border.Carved([]CarveOut{{Link: "eth0", Prefix: p("198.18.0.0/24")}})
	if want := []netip.Prefix{p("198.18.0.0/24"), p("198.18.1.0/24"), p("3fff:0:1::/48"), p("198.18.4.0/24"), p("198.18.2.0/24"), p("198.18.3.0/24")}; !slices.Equal(carved, want) {
		t.Errorf("the carved prefixes read %v, want %v", carved, want)
	}
	if got := (Border{Overlay: border.Overlay}).Carved(nil); len(got) != 0 {
		t.Errorf("with no carve-out and no exemption the carved prefixes read %v, want none", got)
	}
}

// The filter refuses an exemption that would exempt nothing or that names no
// interface it can match, and takes every name with one trailing * or none
func TestBorderValidateRefusesWhatWouldExemptNothing(t *testing.T) {
	overlay := prefixes(t, "198.18.0.0/15", "3fff::/20")
	for name, c := range map[string]struct {
		antispoof Antispoof
		says      string
	}{
		"a shared prefix outside": {Antispoof{Exempt: prefixes(t, "192.0.2.0/24")}, "egress: cap.antispoof exempt 192.0.2.0/24 lies outside overlay"},
		"a prefix reaching past":  {Antispoof{Exempt: prefixes(t, "198.16.0.0/14")}, "egress: cap.antispoof exempt 198.16.0.0/14 lies outside overlay"},
		"an interface's outside": {Antispoof{Interface: map[string]AntispoofInterface{"eth1": {Exempt: prefixes(t, "2001:db8::/32")}}},
			`egress: cap.antispoof.interface."eth1" exempt 2001:db8::/32 lies outside overlay`},
		"an empty list":   {Antispoof{Interface: map[string]AntispoofInterface{"eth1": {}}}, `egress: cap.antispoof.interface."eth1" exempts nothing`},
		"a * alone":       {Antispoof{Interface: map[string]AntispoofInterface{"*": {Exempt: overlay[:1]}}}, `egress: cap.antispoof.interface."*" names every interface`},
		"a * inside":      {Antispoof{Interface: map[string]AntispoofInterface{"w*n": {Exempt: overlay[:1]}}}, `egress: cap.antispoof.interface."w*n" is not an interface name`},
		"two *":           {Antispoof{Interface: map[string]AntispoofInterface{"w**": {Exempt: overlay[:1]}}}, `egress: cap.antispoof.interface."w**" is not an interface name`},
		"no name":         {Antispoof{Interface: map[string]AntispoofInterface{"": {Exempt: overlay[:1]}}}, `egress: cap.antispoof.interface."" is not an interface name`},
		"a name past 15":  {Antispoof{Interface: map[string]AntispoofInterface{"sixteen-bytes-xy": {Exempt: overlay[:1]}}}, "is 16 bytes before any *, and an interface name is at most 15"},
		"a written twice": {Antispoof{Exempt: prefixes(t, "198.18.1.0/24", "198.18.1.0/24")}, "egress: cap.antispoof exempt 198.18.1.0/24 is written twice"},
		"host bits":       {Antispoof{Exempt: prefixes(t, "198.18.1.1/24")}, "egress: cap.antispoof exempt 198.18.1.1/24 has bits set below its prefix length"},
	} {
		if err := (Border{Overlay: overlay, Antispoof: c.antispoof}).Validate(); err == nil || !strings.Contains(err.Error(), c.says) {
			t.Errorf("%s: refused with %v, want %q", name, err, c.says)
		}
	}
	for _, name := range []string{"eth1", "wl*", "fifteen-bytes-x", "fifteen-bytes-x*", "w"} {
		if err := (Border{Overlay: overlay, Antispoof: Antispoof{Interface: map[string]AntispoofInterface{name: {Exempt: overlay}}}}).Validate(); err != nil {
			t.Errorf("%q exempting the whole overlay was refused: %v", name, err)
		}
	}
	// an exemption is inside the overlay where each of its addresses lies in some
	// entry, so two entries side by side together hold one no entry holds alone,
	// while one reaching over a gap between them lies outside
	halves := prefixes(t, "198.18.0.0/16", "198.19.0.0/16", "3fff::/21", "3fff:800::/21", "203.0.113.0/25", "203.0.114.0/24")
	for _, exempt := range []string{"198.18.0.0/15", "3fff::/20"} {
		if err := (Border{Overlay: halves, Antispoof: Antispoof{Exempt: prefixes(t, exempt)}}).Validate(); err != nil {
			t.Errorf("%s, held by two overlay entries together, was refused: %v", exempt, err)
		}
	}
	const straddle = "egress: cap.antispoof exempt 203.0.112.0/22 lies outside overlay"
	if err := (Border{Overlay: halves, Antispoof: Antispoof{Exempt: prefixes(t, "203.0.112.0/22")}}).Validate(); err == nil || !strings.Contains(err.Error(), straddle) {
		t.Errorf("an exemption over a gap between overlay entries was refused with %v, want %q", err, straddle)
	}
}

// a range prints as nft prints an interval set's element: one address bare, a
// prefix where one holds exactly its addresses, else its first and last address
func TestRangeStringPrintsAsNft(t *testing.T) {
	addr := netip.MustParseAddr
	for _, c := range []struct {
		r    Range
		want string
	}{
		{Range{addr("192.0.2.7"), addr("192.0.2.7")}, "192.0.2.7"},
		{Range{addr("2001:db8::7"), addr("2001:db8::7")}, "2001:db8::7"},
		{Range{addr("0.0.0.0"), addr("0.0.0.0")}, "0.0.0.0"},
		{Range{addr("192.0.2.6"), addr("192.0.2.7")}, "192.0.2.6/31"},
		{Range{addr("203.0.113.0"), addr("203.0.113.63")}, "203.0.113.0/26"},
		{Range{addr("0.0.0.0"), addr("255.255.255.255")}, "0.0.0.0/0"},
		{Range{addr("198.51.100.7"), addr("198.51.100.9")}, "198.51.100.7-198.51.100.9"},
		{Range{addr("2001:db8::1"), addr("2001:db8::2")}, "2001:db8::1-2001:db8::2"},
	} {
		if got := c.r.String(); got != c.want {
			t.Errorf("%v through %v prints %s, want %s", c.r.First, c.r.Last, got, c.want)
		}
	}
}
