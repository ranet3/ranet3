// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package schema

import (
	"encoding"
	"encoding/json"
	"math"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	"go.yaml.in/yaml/v3"
	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// onePrefix is a document holding a prefix and nothing else, under the key
// every decoder reads it from. holder cannot stand in for it, because a zero
// address has no spelling and so a holder with only a prefix set is refused by
// every encoder.
type onePrefix struct {
	Prefix Prefix `yaml:"prefix" json:"prefix" toml:"prefix"`
}

// optionalPrefix is onePrefix under omitempty, where yaml and json ask IsZero
// whether to write the field at all and the toml encoder does not ask.
type optionalPrefix struct {
	Prefix Prefix `yaml:"prefix,omitempty" json:"prefix,omitzero" toml:"prefix,omitempty"`
}

// oneAddr, oneDuration, oneTable and oneAnnouncement are onePrefix for the
// other scalars, each holding one value under the key holder reads it from.
type oneAddr struct {
	Address Addr `yaml:"address" json:"address" toml:"address"`
}

type oneDuration struct {
	Interval Duration `yaml:"interval" json:"interval" toml:"interval"`
}

type oneTable struct {
	Table TableID `yaml:"table" json:"table" toml:"table"`
}

type oneAnnouncement struct {
	Announce []Announce `yaml:"announce" json:"announce" toml:"announce"`
}

// edges draws from lo through hi with both ends drawn on their own as well,
// since a derandomized run of a few hundred cases need not land on either.
func edges[T interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 | ~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64
}](lo, hi T) hegel.Generator[T] {
	return hegel.OneOf(hegel.Integers(lo, hi), hegel.Just(lo), hegel.Just(hi))
}

// addresses draws an address of either family, the ends of each family's
// range among them.
func addresses() hegel.Generator[netip.Addr] {
	return hegel.OneOf(hegel.SampledFrom([]netip.Addr{
		netip.MustParseAddr("0.0.0.0"),
		netip.MustParseAddr("255.255.255.255"),
		netip.MustParseAddr("::"),
		netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
	}), hegel.IPAddresses())
}

// prefixes draws a prefix of either family at any length, the lengths at
// both ends drawn on their own, with whatever host bits the address carries.
// An IPv4 address is sometimes drawn in the IPv4-mapped spelling, at a length
// from 96 up, where the prefix has an IPv4 form, and at one below: a round
// trip that unmapped one would turn a prefix egress refuses by name into one
// it takes, and move a rule or an announcement from one family to the other.
func prefixes() hegel.Generator[Prefix] {
	return hegel.Composite(func(tc hegel.TestCase) Prefix {
		address := hegel.Draw(tc, addresses())
		bits := hegel.Draw(tc, edges(0, address.BitLen()))
		if address.Is4() && hegel.Draw(tc, hegel.Booleans()) {
			address = netip.AddrFrom16(address.As16())
			bits = hegel.Draw(tc, hegel.OneOf(edges(96, 128), edges(0, 95)))
		}
		return PrefixFrom(netip.PrefixFrom(address, bits))
	})
}

// malformedPrefixes draws a prefix that is set and is not one: an address
// under a length past its family's width, or under one below zero.
func malformedPrefixes() hegel.Generator[Prefix] {
	return hegel.Composite(func(tc hegel.TestCase) Prefix {
		address := hegel.Draw(tc, addresses())
		bits := hegel.Draw(tc, hegel.OneOf(hegel.Just(-1), edges(address.BitLen()+1, 255)))
		return PrefixFrom(netip.PrefixFrom(address, bits))
	})
}

// durations draws an interval anywhere in the type's range, its two ends and
// the smallest step either side of zero among them, and just as often one
// within a day of zero, which is where an operator writes them.
func durations() hegel.Generator[Duration] {
	return hegel.Map(hegel.OneOf(
		edges[int64](math.MinInt64, math.MaxInt64),
		hegel.SampledFrom([]int64{0, 1, -1}),
		hegel.Integers(int64(-24*time.Hour), int64(24*time.Hour)),
	), func(d int64) Duration { return Duration(d) })
}

// tables draws a table number, the three reserved ones and their neighbors
// among them.
func tables() hegel.Generator[TableID] {
	return hegel.Map(hegel.OneOf(
		hegel.SampledFrom([]uint32{0, 252, 253, 254, 255, 256}),
		edges[uint32](0, math.MaxUint32),
	), func(t uint32) TableID { return TableID(t) })
}

// zones draws the name of the link a zone selects, as an interface is named.
func zones() hegel.Generator[string] {
	return hegel.Text().Alphabet("abcdefghijklmnopqrstuvwxyz0123456789").MinSize(1).MaxSize(8)
}

// judge holds one encoding's reading against the value it was written from,
// so every property here fails the same way and names the encoding that lost
// the value.
func judge[V comparable](ht *hegel.T, encoding, written string, want, got V, err error) {
	ht.Helper()
	if err != nil {
		ht.Fatalf("%s wrote %q for %v and refused it back: %v", encoding, written, want, err)
	}
	if got != want {
		ht.Fatalf("%s wrote %q for %v and read it back as %v", encoding, written, want, got)
	}
}

// throughText is the round trip through the text form every other encoding
// wraps.
func throughText[V interface {
	comparable
	encoding.TextMarshaler
}, P interface {
	*V
	encoding.TextUnmarshaler
}](ht *hegel.T, want V) {
	ht.Helper()
	text, err := want.MarshalText()
	if err != nil {
		ht.Fatalf("text refused %v: %v", want, err)
	}
	var got V
	err = P(&got).UnmarshalText(text)
	judge(ht, "text", string(text), want, got, err)
}

// throughEveryFile renders document, which holds want and nothing else, as
// json, yaml and toml, and reads each back the way it is read in use: json
// through encoding/json, which is the control plane's decoder, and yaml and
// toml through the strict decoders a file goes through. read takes the value
// back out of the holder the document was read into.
func throughEveryFile[V comparable](ht *hegel.T, t *testing.T, want V, document any, read func(holder) V) {
	ht.Helper()
	asJSON, err := json.Marshal(document)
	if err != nil {
		ht.Fatalf("json refused %v: %v", want, err)
	}
	var fromJSON holder
	err = json.Unmarshal(asJSON, &fromJSON)
	judge(ht, "json", string(asJSON), want, read(fromJSON), err)

	asYAML, err := yaml.Marshal(document)
	if err != nil {
		ht.Fatalf("yaml refused %v: %v", want, err)
	}
	fromYAML, err := decodeYAML(t, string(asYAML))
	judge(ht, "yaml", string(asYAML), want, read(fromYAML), err)

	var asTOML strings.Builder
	if err := toml.NewEncoder(&asTOML).Encode(document); err != nil {
		ht.Fatalf("toml refused %v: %v", want, err)
	}
	fromTOML, err := decodeTOML(t, asTOML.String())
	judge(ht, "toml", asTOML.String(), want, read(fromTOML), err)
}

// refusedByEveryEncoder holds that a value with no spelling is refused by the
// text form, where the type has one, and by every encoder wrapping it, so none
// of them writes a file every decoder then refuses or drops what another one
// refuses.
func refusedByEveryEncoder(ht *hegel.T, want, document any) {
	ht.Helper()
	if marshaler, ok := want.(encoding.TextMarshaler); ok {
		if text, err := marshaler.MarshalText(); err == nil {
			ht.Fatalf("text wrote %q for %#v, which has no spelling", text, want)
		}
	}
	if body, err := json.Marshal(document); err == nil {
		ht.Fatalf("json wrote %s for %#v, which has no spelling", body, want)
	}
	if body, err := yaml.Marshal(document); err == nil {
		ht.Fatalf("yaml wrote %q for %#v, which has no spelling", body, want)
	}
	var asTOML strings.Builder
	if err := toml.NewEncoder(&asTOML).Encode(document); err == nil {
		ht.Fatalf("toml wrote %q for %#v, which has no spelling", asTOML.String(), want)
	}
}

// parse(render(p)) is p for any prefix, under the text form every scalar goes
// through and under the json, yaml and toml encoders that wrap it. A prefix
// that came back changed would make a rendered configuration describe a
// different node than the one it was rendered from. The address is drawn
// whole rather than masked to its length, because the type keeps the host bits
// it was given and a round trip that cleaned them up would change what a node
// announces. Both ends of the length are drawn on their own, since a default
// and a host route are both ordinary in a configuration.
//
// The same is held under omitempty, where yaml and json ask IsZero whether to
// write the field and toml does not: a prefix nobody wrote is left out by all
// three, and one that is set and is not a prefix is refused by all three,
// where yaml and json used to drop what toml refused.
func TestPrefixRoundTripsThroughEveryEncoding(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		want := hegel.Draw(ht, prefixes())
		// mostly a prefix the round trip carries, and a quarter of the time
		// one with no spelling
		if hegel.Draw(ht, hegel.WeightedBooleans(0.25)) {
			want = hegel.Draw(ht, hegel.OneOf(hegel.Just(Prefix{}), malformedPrefixes()))
		}
		read := func(h holder) Prefix { return h.Prefix }

		// told apart by the value rather than by IsZero, the method under
		// test
		switch {
		case want == Prefix{}:
			throughEveryFile(ht, t, want, optionalPrefix{want}, read)
		case !want.IsValid():
			refusedByEveryEncoder(ht, want, onePrefix{want})
			refusedByEveryEncoder(ht, want, optionalPrefix{want})
		default:
			throughText(ht, want)
			throughEveryFile(ht, t, want, onePrefix{want}, read)
			throughEveryFile(ht, t, want, optionalPrefix{want}, read)
		}
	})
}

// The same for an address, where a source, a segment or a preferred source
// is written. Both families are drawn, and an IPv4 address is sometimes drawn
// in the IPv4-mapped spelling as well, which the checks downstream tell apart
// from its IPv4 form: a round trip that unmapped it would move a value from
// one family to the other. An IPv6 address sometimes carries a zone, which no
// address written here can use, and then every encoder refuses to write it
// rather than writing a file every decoder refuses.
func TestAddrRoundTripsThroughEveryEncoding(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		address := hegel.Draw(ht, addresses())
		if address.Is4() && hegel.Draw(ht, hegel.Booleans()) {
			address = netip.AddrFrom16(address.As16())
		}
		if address.Is6() && hegel.Draw(ht, hegel.Booleans()) {
			address = address.WithZone(hegel.Draw(ht, zones()))
		}
		want := AddrFrom(address)

		if want.Zone() != "" {
			refusedByEveryEncoder(ht, want, oneAddr{want})
			return
		}
		throughText(ht, want)
		throughEveryFile(ht, t, want, oneAddr{want}, func(h holder) Addr { return h.Address })
	})
}

// The same for an interval, over every value the type takes rather than the
// few an operator writes, since the spelling is Go's own and a negative or a
// fractional one goes through it as readily as "4s". An interval that came
// back changed is a timer running at a rate nobody wrote.
func TestDurationRoundTripsThroughEveryEncoding(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		want := hegel.Draw(ht, durations())

		throughText(ht, want)
		throughEveryFile(ht, t, want, oneDuration{want}, func(h holder) Duration { return h.Interval })
	})
}

// The same for a table, over every number the kernel takes, so the three
// reserved ones go out under their names and come back as their numbers. A
// table that came back as another would send a rule's lookup somewhere it was
// never written to go.
func TestTableRoundTripsThroughEveryEncoding(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		want := hegel.Draw(ht, tables())

		throughText(ht, want)
		throughEveryFile(ht, t, want, oneTable{want}, func(h holder) TableID { return h.Table })
	})
}

// announcements draws an announcement in either spelling: a prefix alone, or
// a prefix and the source it is reachable from, of either family, since the
// spelling is the same whatever the routing rules later make of the pair.
func announcements() hegel.Generator[Announce] {
	return hegel.Composite(func(tc hegel.TestCase) Announce {
		announced := Announce{Prefix: hegel.Draw(tc, prefixes())}
		if hegel.Draw(tc, hegel.Booleans()) {
			announced.From = hegel.Draw(tc, prefixes())
		}
		return announced
	})
}

// An announcement goes out in the shorter spelling where it has one and as a
// mapping where it carries a source, and either comes back as the pair it was.
// One that lost its source would turn an exit's source-specific default into a
// plain one, which draws traffic from every node rather than from the prefix
// it was offered to. It has no text form of its own, so the text half is held
// for the bare spelling alone, which is the one an operator writes as a string.
//
// One with no spelling, carrying no prefix or a prefix or a source that is set
// and is not one, is refused by every encoder.
func TestAnnouncementRoundTripsThroughEveryEncoding(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		want := hegel.Draw(ht, announcements())
		switch hegel.Draw(ht, hegel.Integers(0, 7)) {
		case 1:
			want.Prefix = Prefix{}
		case 2:
			want.Prefix = hegel.Draw(ht, malformedPrefixes())
		case 3:
			want.From = hegel.Draw(ht, malformedPrefixes())
		}
		if !want.Prefix.IsValid() || want.From != (Prefix{}) && !want.From.IsValid() {
			refusedByEveryEncoder(ht, want, oneAnnouncement{[]Announce{want}})
			return
		}

		if !want.From.IsValid() {
			text, err := want.Prefix.MarshalText()
			if err != nil {
				ht.Fatalf("text refused %v: %v", want, err)
			}
			var fromText Announce
			err = fromText.UnmarshalText(text)
			judge(ht, "text", string(text), want, fromText, err)
		}
		throughEveryFile(ht, t, want, oneAnnouncement{[]Announce{want}}, func(h holder) Announce {
			if len(h.Announce) != 1 {
				return Announce{}
			}
			return h.Announce[0]
		})
	})
}

// readText reads written through a scalar's text form.
func readText[V any, P interface {
	*V
	encoding.TextUnmarshaler
}](written string) (any, error) {
	var value V
	err := P(&value).UnmarshalText([]byte(written))
	return value, err
}

// scalar is one scalar here: the key a document writes it under, whether it
// is written as a list entry, its text form and the place a holder keeps it.
type scalar struct {
	key  string
	list bool
	text func(string) (any, error)
	read func(holder) any
}

// scalars is every scalar here.
var scalars = []scalar{
	{key: "interval", text: readText[Duration], read: func(h holder) any { return h.Interval }},
	{key: "prefix", text: readText[Prefix], read: func(h holder) any { return h.Prefix }},
	{key: "address", text: readText[Addr], read: func(h holder) any { return h.Address }},
	{key: "table", text: readText[TableID], read: func(h holder) any { return h.Table }},
	{key: "announce", list: true, text: readText[Announce], read: func(h holder) any {
		if len(h.Announce) != 1 {
			return nil
		}
		return h.Announce[0]
	}},
}

// quoted is a document putting one written string where a file writes the
// scalar, for each encoder to spell as a string.
func (s scalar) quoted(written string) any {
	if s.list {
		return map[string]any{s.key: []string{written}}
	}
	return map[string]any{s.key: written}
}

// bare writes a number where a file writes the scalar, unquoted, in the json,
// yaml or toml spelling of a document.
func (s scalar) bare(encoding, numeral string) string {
	if s.list {
		numeral = "[" + numeral + "]"
	}
	switch encoding {
	case "json":
		return `{"` + s.key + `": ` + numeral + `}`
	case "toml":
		return s.key + " = " + numeral + "\n"
	}
	return s.key + ": " + numeral + "\n"
}

// agrees holds one encoding's reading of written against the text form's:
// refused by both, or taken by both as the same value.
func (s scalar) agrees(ht *hegel.T, encoding, written, body string, got holder, err error) {
	ht.Helper()
	want, refusal := s.text(written)
	switch {
	case (err == nil) != (refusal == nil):
		ht.Fatalf("%s %s %q: the text form says %v and %s says %v, in\n%s", s.key, encoding, written, refusal, encoding, err, body)
	case err == nil && s.read(got) != want:
		ht.Fatalf("%s %s %q: the text form reads %v and %s reads %v, in\n%s", s.key, encoding, written, want, encoding, s.read(got), body)
	}
}

// spelledWith is the characters every spelling here is made of, and a few
// that an operator mistypes into one: a sign, a space, a unit and a zone.
const spelledWith = "0123456789abcdefABCDEFx:./%-+_ hmsun\u00b5"

// spellings draws what an operator might write where a scalar goes: a valid
// spelling of one of them, the same spelling mistyped, an address carrying a
// zone, and short runs of the characters they are made of. The mistakes are
// the ones a wrapper is most likely to forgive on its own: whitespace around
// the value, a sign, the case of a name, and one character added, dropped or
// changed.
func spellings() hegel.Generator[string] {
	valid := hegel.OneOf(
		hegel.Map(durations(), Duration.String),
		hegel.Map(tables(), TableID.String),
		hegel.Map(addresses(), netip.Addr.String),
		hegel.Map(prefixes(), Prefix.String),
		hegel.SampledFrom([]string{"0", "main", "local", "default", "0x10", "4s", "::/0", "0.0.0.0/0"}),
	)
	characters := hegel.SampledFrom([]rune(spelledWith))
	mistyped := hegel.Composite(func(tc hegel.TestCase) string {
		runes := []rune(hegel.Draw(tc, valid))
		at := hegel.Draw(tc, hegel.Integers(0, len(runes)))
		switch hegel.Draw(tc, hegel.Integers(0, 5)) {
		case 0:
			space := hegel.Draw(tc, hegel.SampledFrom([]string{" ", "\t", "\n"}))
			if hegel.Draw(tc, hegel.Booleans()) {
				return space + string(runes)
			}
			return string(runes) + space
		case 1:
			return hegel.Draw(tc, hegel.SampledFrom([]string{"+", "-"})) + string(runes)
		case 2:
			return strings.ToUpper(string(runes))
		case 3:
			runes = append(runes[:at], append([]rune{hegel.Draw(tc, characters)}, runes[at:]...)...)
		case 4:
			if at < len(runes) {
				runes = append(runes[:at], runes[at+1:]...)
			}
		default:
			if at < len(runes) {
				runes[at] = hegel.Draw(tc, characters)
			}
		}
		return string(runes)
	})
	zoned := hegel.Composite(func(tc hegel.TestCase) string {
		return hegel.Draw(tc, hegel.IPAddresses().IPv6()).WithZone(hegel.Draw(tc, zones())).String()
	})
	return hegel.OneOf(valid, mistyped, zoned, hegel.Text().Alphabet(spelledWith).MaxSize(24))
}

// A string the text form refuses is refused by json, yaml and toml as well,
// and one it takes is taken by all three as the same value. Each encoding
// only wraps the text form, so a disagreement is a wrapper deciding something
// on its own: a file that loads under one extension and not another, or a
// control plane accepting a value the file it describes could not hold.
func TestEveryEncodingRefusesWhatTheTextFormRefuses(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		written := hegel.Draw(ht, spellings())
		for _, scalar := range scalars {
			asJSON, err := json.Marshal(scalar.quoted(written))
			if err != nil {
				ht.Fatalf("json refused the string %q: %v", written, err)
			}
			var fromJSON holder
			err = json.Unmarshal(asJSON, &fromJSON)
			scalar.agrees(ht, "json", written, string(asJSON), fromJSON, err)

			asYAML, err := yaml.Marshal(scalar.quoted(written))
			if err != nil {
				ht.Fatalf("yaml refused the string %q: %v", written, err)
			}
			fromYAML, err := decodeYAML(t, string(asYAML))
			scalar.agrees(ht, "yaml", written, string(asYAML), fromYAML, err)

			var asTOML strings.Builder
			if err := toml.NewEncoder(&asTOML).Encode(scalar.quoted(written)); err != nil {
				ht.Fatalf("toml refused the string %q: %v", written, err)
			}
			fromTOML, err := decodeTOML(t, asTOML.String())
			scalar.agrees(ht, "toml", written, asTOML.String(), fromTOML, err)
		}
	})
}

// numerals draws a number as a file might write one: a decimal integer with
// or without a sign, leading zeros or digit separators, an integer in another
// base, a fraction or an exponent, and the words toml reads as numbers. The
// ends of a table's range, its reserved numbers and the integers either side
// of each are drawn on their own, as are those either side of int64.
func numerals() hegel.Generator[string] {
	run := func(alphabet string) hegel.Generator[string] {
		return hegel.Text().Alphabet(alphabet).MinSize(1).MaxSize(12)
	}
	signed := func(tc hegel.TestCase, number string) string {
		return hegel.Draw(tc, hegel.SampledFrom([]string{"", "+", "-"})) + number
	}
	return hegel.OneOf(
		hegel.SampledFrom([]string{
			"0", "+0", "-0", "-1", "252", "253", "254", "255", "256",
			strconv.FormatUint(math.MaxUint32, 10), strconv.FormatUint(math.MaxUint32+1, 10),
			strconv.FormatInt(math.MaxInt64, 10), "9223372036854775808",
			"inf", "+inf", "-inf", "nan",
		}),
		hegel.Composite(func(tc hegel.TestCase) string {
			// a separator may land anywhere, and toml and Go both take one
			// only between two digits
			digits := []rune(hegel.Draw(tc, run("0123456789")))
			for range hegel.Draw(tc, hegel.Integers(0, 2)) {
				at := hegel.Draw(tc, hegel.Integers(0, len(digits)))
				digits = append(digits[:at], append([]rune{'_'}, digits[at:]...)...)
			}
			return signed(tc, string(digits))
		}),
		hegel.Composite(func(tc hegel.TestCase) string {
			base := hegel.Draw(tc, hegel.SampledFrom([][2]string{{"0x", "0123456789abcdefABCDEF"}, {"0o", "01234567"}, {"0b", "01"}}))
			return signed(tc, base[0]+hegel.Draw(tc, run(base[1])))
		}),
		hegel.Composite(func(tc hegel.TestCase) string {
			number := hegel.Draw(tc, run("0123456789"))
			if hegel.Draw(tc, hegel.Booleans()) {
				number += "." + hegel.Draw(tc, run("0123456789"))
			}
			if hegel.Draw(tc, hegel.Booleans()) {
				number += hegel.Draw(tc, hegel.SampledFrom([]string{"e", "E", "e+", "e-"})) + hegel.Draw(tc, run("0123456789"))
			}
			return signed(tc, number)
		}),
	)
}

// A number written bare reads the same under every encoding able to write it,
// and the same as the text form reads its digits: json and toml each spell
// only some numbers, and yaml spells any of them as a plain scalar. The three
// decoders hand the text form different things for one, json and yaml the
// digits as written and toml the number they make, so a table and a disabled
// timer are where they could come apart, and did: a toml file writing "+200"
// for a table loaded where a yaml one was refused, and the json wire refused
// 200, which both files took. Every other scalar refuses a number under all
// four.
func TestEveryEncodingReadsABareNumberAlike(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		written := hegel.Draw(ht, numerals())
		// one toml cannot parse is a number toml has no spelling for, rather
		// than one it refuses
		var parsed map[string]any
		_, unspelled := toml.Decode("v = "+written+"\n", &parsed)
		for _, scalar := range scalars {
			if json.Valid([]byte(written)) {
				body := scalar.bare("json", written)
				var fromJSON holder
				err := json.Unmarshal([]byte(body), &fromJSON)
				scalar.agrees(ht, "json", written, body, fromJSON, err)
			}
			body := scalar.bare("yaml", written)
			fromYAML, err := decodeYAML(t, body)
			scalar.agrees(ht, "yaml", written, body, fromYAML, err)
			if unspelled == nil {
				body := scalar.bare("toml", written)
				fromTOML, err := decodeTOML(t, body)
				scalar.agrees(ht, "toml", written, body, fromTOML, err)
			}
		}
	})
}
