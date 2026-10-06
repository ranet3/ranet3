// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package schema

import (
	"encoding"
	"encoding/json"
	"math"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	"go.yaml.in/yaml/v3"
)

// holder carries one of each scalar, so a case can be written once and read by
// both decoders. The keys are the same under all three tags, which is the
// property that lets one file and one wire form describe one schema.
type holder struct {
	Interval Duration   `yaml:"interval" json:"interval" toml:"interval"`
	Prefix   Prefix     `yaml:"prefix" json:"prefix" toml:"prefix"`
	Address  Addr       `yaml:"address" json:"address" toml:"address"`
	Table    TableID    `yaml:"table" json:"table" toml:"table"`
	Announce []Announce `yaml:"announce" json:"announce" toml:"announce"`
}

func decodeYAML(t *testing.T, body string) (holder, error) {
	t.Helper()
	var out holder
	decoder := yaml.NewDecoder(strings.NewReader(body))
	decoder.KnownFields(true)
	return out, decoder.Decode(&out)
}

func decodeTOML(t *testing.T, body string) (holder, error) {
	t.Helper()
	var out holder
	md, err := toml.Decode(body, &out)
	if err != nil {
		return out, err
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		return out, &unknownKey{undecoded[0].String()}
	}
	return out, nil
}

type unknownKey struct{ key string }

func (u *unknownKey) Error() string { return "unknown field " + u.key }

// One configuration written twice reaches the same struct. This is the
// property the two decoders exist for: a fleet that writes toml and a control
// plane that speaks json describe one node, not two.
func TestBothDecodersReadOneConfiguration(t *testing.T) {
	const asYAML = `
interval: 4s
prefix: 2001:db8::/48
address: 2001:db8::1
table: main
announce:
  - 10.66.0.5/32
  - { prefix: "::/0", from: 2001:db8::/48 }
`
	const asTOML = `
interval = "4s"
prefix = "2001:db8::/48"
address = "2001:db8::1"
table = "main"
announce = ["10.66.0.5/32", { prefix = "::/0", from = "2001:db8::/48" }]
`
	fromYAML, err := decodeYAML(t, asYAML)
	if err != nil {
		t.Fatalf("yaml: %v", err)
	}
	fromTOML, err := decodeTOML(t, asTOML)
	if err != nil {
		t.Fatalf("toml: %v", err)
	}
	if fromYAML.Interval != Duration(4*time.Second) || fromYAML.Table != TableMain {
		t.Fatalf("yaml read %+v", fromYAML)
	}
	if len(fromYAML.Announce) != 2 || fromYAML.Announce[0].From.IsValid() || !fromYAML.Announce[1].From.IsValid() {
		t.Fatalf("the two announcement spellings read as %v", fromYAML.Announce)
	}
	if !equal(fromYAML, fromTOML) {
		t.Errorf("yaml read %+v and toml read %+v", fromYAML, fromTOML)
	}
}

// parse(render(x)) is x under both decoders, so a generated configuration and
// a hand written one describe one node rather than two.
func TestRenderedScalarsParseBackToThemselves(t *testing.T) {
	cases := map[string]holder{
		"an ordinary node": {
			Interval: Duration(90 * time.Second),
			Prefix:   MustPrefix("10.66.0.5/32"),
			Address:  MustAddr("10.66.0.5"),
			Table:    200,
			Announce: []Announce{{Prefix: MustPrefix("10.66.0.5/32")}},
		},
		"a disabled timer and a named table": {
			Interval: 0,
			Prefix:   MustPrefix("::/0"),
			Address:  MustAddr("2001:db8::1"),
			Table:    TableMain,
			Announce: []Announce{
				{Prefix: MustPrefix("2001:db8::/48")},
				{Prefix: MustPrefix("::/0"), From: MustPrefix("2001:db8::/48")},
			},
		},
	}
	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			rendered, err := yaml.Marshal(want)
			if err != nil {
				t.Fatalf("render as yaml: %v", err)
			}
			got, err := decodeYAML(t, string(rendered))
			if err != nil {
				t.Fatalf("parse %s: %v", rendered, err)
			}
			if !equal(got, want) {
				t.Errorf("yaml round trip gave %+v from %s", got, rendered)
			}
			var buf strings.Builder
			if err := toml.NewEncoder(&buf).Encode(want); err != nil {
				t.Fatalf("render as toml: %v", err)
			}
			got, err = decodeTOML(t, buf.String())
			if err != nil {
				t.Fatalf("parse %s: %v", buf.String(), err)
			}
			if !equal(got, want) {
				t.Errorf("toml round trip gave %+v from %s", got, buf.String())
			}
		})
	}
}

// Every spelling below is refused by both decoders, rather than by the one
// whose extension the writer happened to pick.
func TestBothDecodersRefuseTheSameSpellings(t *testing.T) {
	for name, pair := range map[string]struct{ asYAML, asTOML string }{
		"an unknown field": {
			asYAML: "unknown: true\n",
			asTOML: "unknown = true\n",
		},
		"a duration with no unit": {
			asYAML: "interval: 4\n",
			asTOML: "interval = 4\n",
		},
		"an address carrying a prefix length": {
			asYAML: "address: 2001:db8::1/128\n",
			asTOML: "address = \"2001:db8::1/128\"\n",
		},
		"a prefix carrying no length": {
			asYAML: "prefix: 2001:db8::1\n",
			asTOML: "prefix = \"2001:db8::1\"\n",
		},
		"a table that is neither a number nor a name": {
			asYAML: "table: mane\n",
			asTOML: "table = \"mane\"\n",
		},
		// the names are the lowercase ones iproute2 matches case-sensitively, and a second spelling of each is not taken
		"a table name in another case": {
			asYAML: "table: Main\n",
			asTOML: "table = \"MAIN\"\n",
		},
		"an announcement with an unknown field": {
			asYAML: "announce: [{ prefix: \"::/0\", form: 2001:db8::/48 }]\n",
			asTOML: "announce = [{ prefix = \"::/0\", form = \"2001:db8::/48\" }]\n",
		},
		"an announcement with no prefix": {
			asYAML: "announce: [{ from: 2001:db8::/48 }]\n",
			asTOML: "announce = [{ from = \"2001:db8::/48\" }]\n",
		},
		// The strict decoder refuses a key written twice in every other
		// mapping in a file, and toml refuses it here too, so a yaml
		// announcement taking the last of two would announce a prefix or a
		// source the file names alongside another and say nothing.
		"an announcement with its prefix written twice": {
			asYAML: "announce: [{ prefix: \"::/0\", prefix: 2001:db8::/48 }]\n",
			asTOML: "announce = [{ prefix = \"::/0\", prefix = \"2001:db8::/48\" }]\n",
		},
		"an announcement with its source written twice": {
			asYAML: "announce: [{ prefix: \"::/0\", from: 2001:db8::/48, from: 2001:db8:1::/48 }]\n",
			asTOML: "announce = [{ prefix = \"::/0\", from = \"2001:db8::/48\", from = \"2001:db8:1::/48\" }]\n",
		},
		// a list inside the list is neither spelling
		// walked as a mapping's items two at a time, it announced the source-specific default its four words spell
		"an announcement written as a sequence": {
			asYAML: "announce: [[prefix, \"::/0\", from, 2001:db8::/48]]\n",
			asTOML: "announce = [[\"prefix\", \"::/0\", \"from\", \"2001:db8::/48\"]]\n",
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeYAML(t, pair.asYAML); err == nil {
				t.Errorf("yaml took %q", pair.asYAML)
			}
			if _, err := decodeTOML(t, pair.asTOML); err == nil {
				t.Errorf("toml took %q", pair.asTOML)
			}
		})
	}
}

// An alias reads inside an announcement as it reads everywhere else in a file,
// in a value and in a key. The decoder follows one before it hands a node to
// an unmarshaler, while the announcement's own walk handed the alias node on:
// the prefix refused it as a scalar written as an alias, and a key written as
// an alias was read by its alias name and refused as an unknown field.
//
// A key written twice is refused when one of the two is an alias as well,
// and the refusal names the lines the two are written on, the second first.
// Compared by its alias name, the second spelling would replace the first
// without a word, and a line read from the anchor would name a line in
// another announcement.
func TestAnnouncementFollowsAnAlias(t *testing.T) {
	for name, one := range map[string]struct {
		written string
		want    []Announce
		refused string
	}{
		"a source written as an alias": {
			written: "prefix: &p 2001:db8::/48\nannounce: [{ prefix: \"::/0\", from: *p }]\n",
			want:    []Announce{{Prefix: MustPrefix("::/0"), From: MustPrefix("2001:db8::/48")}},
		},
		"an announcement written as an alias": {
			written: "prefix: &p 2001:db8::/48\nannounce: [*p]\n",
			want:    []Announce{{Prefix: MustPrefix("2001:db8::/48")}},
		},
		"a key written as an alias": {
			written: "announce:\n  - { prefix: \"::/0\", &k from: 2001:db8::/48 }\n  - { prefix: \"::/0\", *k : 2001:db8:1::/48 }\n",
			want: []Announce{
				{Prefix: MustPrefix("::/0"), From: MustPrefix("2001:db8::/48")},
				{Prefix: MustPrefix("::/0"), From: MustPrefix("2001:db8:1::/48")},
			},
		},
		"a key written twice through an alias": {
			written: "announce:\n  - { prefix: \"::/0\", &k from: 2001:db8::/48, *k : 2001:db8:1::/48 }\n",
			refused: `line 2: mapping key "from" already defined at line 2`,
		},
		"a key written again through an alias anchored in another announcement": {
			written: "announce:\n  - { prefix: \"::/0\", &k from: 2001:db8::/48 }\n  - prefix: \"::/0\"\n    from: 2001:db8:1::/48\n    *k : 2001:db8:2::/48\n",
			refused: `line 5: mapping key "from" already defined at line 4`,
		},
		"a key first written through an alias anchored in another announcement": {
			written: "announce:\n  - { prefix: \"::/0\", &k from: 2001:db8::/48 }\n  - prefix: \"::/0\"\n    *k : 2001:db8:1::/48\n    from: 2001:db8:2::/48\n",
			refused: `line 5: mapping key "from" already defined at line 4`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := decodeYAML(t, one.written)
			if one.refused != "" {
				if err == nil || err.Error() != one.refused {
					t.Fatalf("read %v with the error %v, want the refusal %q", got.Announce, err, one.refused)
				}
				return
			}
			if err != nil {
				t.Fatalf("an alias was refused: %v", err)
			}
			if !slices.Equal(got.Announce, one.want) {
				t.Errorf("read %v, want %v", got.Announce, one.want)
			}
		})
	}
}

// A duration is a scalar. Reading Value off a mapping or a sequence gives the
// empty string, and `invalid duration ""` names neither the line nor what was
// written there.
func TestDurationRefusalNamesWhatWasWritten(t *testing.T) {
	_, err := decodeYAML(t, "interval: [4s]\n")
	if err == nil {
		t.Fatal("a sequence was taken as a duration")
	}
	if !strings.Contains(err.Error(), "a sequence") {
		t.Errorf("the error reads %q, which does not say what was written instead", err)
	}
}

// A bare zero disables a timer, and every other spelling in this file takes
// one, so the two decoders have to agree about it as well.
func TestZeroIntervalIsTakenByBothDecoders(t *testing.T) {
	for name, body := range map[string]func(*testing.T) (holder, error){
		"yaml": func(t *testing.T) (holder, error) { return decodeYAML(t, "interval: 0\n") },
		"toml": func(t *testing.T) (holder, error) { return decodeTOML(t, "interval = 0\n") },
	} {
		t.Run(name, func(t *testing.T) {
			got, err := body(t)
			if err != nil {
				t.Fatalf("a zero interval was refused: %v", err)
			}
			if got.Interval != 0 {
				t.Errorf("a zero interval parsed as %s", got.Interval)
			}
		})
	}
}

// An integer written for a table, or a zero written for a disabled timer,
// reads the same under both decoders. The toml one hands an integer over as
// the number it is, so "+200" and "-0" reach a table as 200 and 0 and "0x0"
// reaches an interval as 0, while the yaml one passes the same words through
// as written, and each of those loaded under one extension and was refused
// under the other.
func TestBothDecodersReadAnIntegerAlike(t *testing.T) {
	for _, one := range []struct {
		key, written string
		want         holder
		refused      bool
	}{
		{key: "table", written: "+200", want: holder{Table: 200}},
		{key: "table", written: "+0", want: holder{}},
		{key: "table", written: "-0", want: holder{}},
		{key: "table", written: "0x1F", want: holder{Table: 31}},
		{key: "table", written: "1_000", want: holder{Table: 1000}},
		{key: "table", written: "-5", refused: true},
		{key: "table", written: "4294967296", refused: true},
		{key: "interval", written: "0x0", want: holder{}},
		{key: "interval", written: "0o0", want: holder{}},
		{key: "interval", written: "0b0", want: holder{}},
		{key: "interval", written: "-0", want: holder{}},
		{key: "interval", written: "5", refused: true},
		{key: "interval", written: "0x5", refused: true},
	} {
		t.Run(one.key+" "+one.written, func(t *testing.T) {
			fromYAML, yamlErr := decodeYAML(t, one.key+": "+one.written+"\n")
			fromTOML, tomlErr := decodeTOML(t, one.key+" = "+one.written+"\n")
			for _, read := range []struct {
				decoder string
				got     holder
				err     error
			}{{"yaml", fromYAML, yamlErr}, {"toml", fromTOML, tomlErr}} {
				switch {
				case one.refused && read.err == nil:
					t.Errorf("%s took %s as %+v", read.decoder, one.written, read.got)
				case !one.refused && read.err != nil:
					t.Errorf("%s refused %s: %v", read.decoder, one.written, read.err)
				case !one.refused && !equal(read.got, one.want):
					t.Errorf("%s read %s as %+v, want %+v", read.decoder, one.written, read.got, one.want)
				}
			}
		})
	}
}

// encoding/json is the control plane's decoder, and the file and the wire form
// are one schema. It hands a bare number to a text unmarshaler as an error
// rather than as its digits, so the wire refused "table": 200 and a disabled
// timer written as 0, both of which every file takes, a .json one included.
// The same value written each way reads the same, and what a file refuses the
// wire refuses as well.
func TestJSONTakesTheBareNumbersAFileTakes(t *testing.T) {
	for _, one := range []struct {
		key, written string
		want         holder
		refused      bool
	}{
		{key: "table", written: "200", want: holder{Table: 200}},
		{key: "table", written: "254", want: holder{Table: TableMain}},
		{key: "table", written: "0", want: holder{}},
		{key: "table", written: "-0", want: holder{}},
		{key: "table", written: "4294967295", want: holder{Table: math.MaxUint32}},
		{key: "table", written: `"main"`, want: holder{Table: TableMain}},
		{key: "table", written: "4294967296", refused: true},
		{key: "table", written: "-5", refused: true},
		{key: "table", written: "2e2", refused: true},
		{key: "table", written: "true", refused: true},
		{key: "interval", written: "0", want: holder{}},
		{key: "interval", written: "-0", want: holder{}},
		{key: "interval", written: `"4s"`, want: holder{Interval: Duration(4 * time.Second)}},
		{key: "interval", written: "4", refused: true},
		{key: "interval", written: "0.0", refused: true},
		{key: "interval", written: "false", refused: true},
	} {
		t.Run(one.key+" "+one.written, func(t *testing.T) {
			document := `{"` + one.key + `": ` + one.written + `}`
			var overWire holder
			wireErr := json.Unmarshal([]byte(document), &overWire)
			// The same document as the loader reads a .json file, through the
			// yaml decoder.
			fromFile, fileErr := decodeYAML(t, document)
			fromTOML, tomlErr := decodeTOML(t, one.key+" = "+one.written+"\n")
			for _, read := range []struct {
				decoder string
				got     holder
				err     error
			}{{"json", overWire, wireErr}, {"a .json file", fromFile, fileErr}, {"toml", fromTOML, tomlErr}} {
				switch {
				case one.refused && read.err == nil:
					t.Errorf("%s took %s as %+v", read.decoder, one.written, read.got)
				case !one.refused && read.err != nil:
					t.Errorf("%s refused %s: %v", read.decoder, one.written, read.err)
				case !one.refused && !equal(read.got, one.want):
					t.Errorf("%s read %s as %+v, want %+v", read.decoder, one.written, read.got, one.want)
				}
			}
		})
	}
	// A null leaves a field as it was under encoding/json, as it does for any
	// text unmarshaler, rather than being read as a spelling and refused.
	var overWire holder
	if err := json.Unmarshal([]byte(`{"table": null, "interval": null}`), &overWire); err != nil || !equal(overWire, holder{}) {
		t.Errorf("json read null as %+v, %v", overWire, err)
	}
}

// An address written here names a host and never a link: every field typed
// Addr is a segment, a segment source or a preferred source. A zone is refused
// by every decoder rather than carried, since the segment checks refused one
// anyway and the reconciler dropped one from a preferred source without a
// word, and a value carrying one has no spelling, so no marshaller writes a
// file the decoders would then refuse.
func TestAddressCarryingAZoneIsRefused(t *testing.T) {
	for _, written := range []string{"fe80::1%eth0", "::ffff:10.66.0.5%eth0", "2001:db8::1%1"} {
		t.Run(written, func(t *testing.T) {
			if got, err := ParseAddr(written); err == nil {
				t.Errorf("the text form took it as %v", got)
			}
			var overWire holder
			if err := json.Unmarshal([]byte(`{"address": "`+written+`"}`), &overWire); err == nil {
				t.Errorf("json took it as %v", overWire.Address)
			}
			if got, err := decodeYAML(t, "address: "+written+"\n"); err == nil {
				t.Errorf("yaml took it as %v", got.Address)
			}
			if got, err := decodeTOML(t, "address = \""+written+"\"\n"); err == nil {
				t.Errorf("toml took it as %v", got.Address)
			}

			zoned := map[string]Addr{"address": AddrFrom(netip.MustParseAddr(written))}
			if text, err := zoned["address"].MarshalText(); err == nil {
				t.Errorf("the text form wrote %q", text)
			}
			if body, err := json.Marshal(zoned); err == nil {
				t.Errorf("json wrote %s", body)
			}
			if body, err := yaml.Marshal(zoned); err == nil {
				t.Errorf("yaml wrote %s", body)
			}
			var asTOML strings.Builder
			if err := toml.NewEncoder(&asTOML).Encode(zoned); err == nil {
				t.Errorf("toml wrote %s", asTOML.String())
			}
		})
	}
}

func TestTableNamesSurviveARoundTrip(t *testing.T) {
	for _, table := range []TableID{TableMain, TableLocal, TableDefault, 200, 51820} {
		text, err := table.MarshalText()
		if err != nil {
			t.Fatal(err)
		}
		var got TableID
		if err := got.UnmarshalText(text); err != nil {
			t.Fatalf("%s: %v", text, err)
		}
		if got != table {
			t.Errorf("table %d was written as %q and read back as %d", table, text, got)
		}
	}
}

// A value with no spelling is refused by every marshaller, since each of them
// writes through MarshalText. The "invalid Prefix" String gives for a zero
// prefix renders without complaint and no decoder reads it back, so a rendered
// configuration would be one nothing can load.
func TestEveryMarshallerRefusesAValueWithNoSpelling(t *testing.T) {
	for name, empty := range map[string]any{
		"a prefix carrying no address": Prefix{},
		"an address carrying no value": Addr{},
	} {
		t.Run(name, func(t *testing.T) {
			rendered, err := yaml.Marshal(empty)
			if err == nil {
				t.Errorf("yaml wrote %q, which nothing reads back", strings.TrimSpace(string(rendered)))
			}
			if _, err := empty.(encoding.TextMarshaler).MarshalText(); err == nil {
				t.Error("the text half wrote it too")
			}
		})
	}
}

// The same for a prefix inside a value that writes it. yaml and json ask
// IsZero whether to write an omitempty field at all and the toml encoder does
// not, so a prefix that is set and is not one, an address under a length it
// cannot carry, was dropped by the first two and refused by the third. An
// announcement carrying no prefix went out under yaml as the "invalid Prefix"
// String gives for one, which no decoder reads back, and one whose source was
// not a prefix went out without its source.
func TestEveryMarshallerRefusesAPrefixWithNoSpelling(t *testing.T) {
	notOne := PrefixFrom(netip.PrefixFrom(netip.MustParseAddr("2001:db8::"), 200))
	type optional struct {
		Prefix Prefix `yaml:"prefix,omitempty" json:"prefix,omitzero" toml:"prefix,omitempty"`
	}
	for name, value := range map[string]any{
		"an announcement carrying no prefix":         Announce{},
		"an announcement whose prefix is not one":    Announce{Prefix: notOne},
		"an announcement whose source is not one":    Announce{Prefix: MustPrefix("::/0"), From: notOne},
		"an optional prefix that is set and not one": optional{notOne},
	} {
		t.Run(name, func(t *testing.T) {
			if body, err := yaml.Marshal(value); err == nil {
				t.Errorf("yaml wrote %q", body)
			}
			if body, err := json.Marshal(value); err == nil {
				t.Errorf("json wrote %s", body)
			}
			var asTOML strings.Builder
			if err := toml.NewEncoder(&asTOML).Encode(value); err == nil {
				t.Errorf("toml wrote %q", asTOML.String())
			}
		})
	}
}

// encoding/json is the control plane's decoder, and the file and the wire form
// are one schema. Without UnmarshalJSON the bare spelling went through the
// text half and the mapping one was refused outright, so an exit's
// announcement could be written in a file and not sent over the wire.
func TestJSONReadsBothAnnouncementSpellings(t *testing.T) {
	want := []Announce{
		{Prefix: MustPrefix("10.66.0.5/32")},
		{Prefix: MustPrefix("::/0"), From: MustPrefix("2001:db8::/48")},
	}
	var got []Announce
	if err := json.Unmarshal([]byte(`["10.66.0.5/32", {"prefix": "::/0", "from": "2001:db8::/48"}]`), &got); err != nil {
		t.Fatalf("json: %v", err)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("json read %v, want %v", got, want)
	}
	// And it reads back what it rendered, so a capability sent to a daemon and
	// one written in a file describe the same node.
	rendered, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	got = nil
	if err := json.Unmarshal(rendered, &got); err != nil {
		t.Fatalf("parse %s: %v", rendered, err)
	}
	if !slices.Equal(got, want) {
		t.Errorf("the json round trip gave %v from %s", got, rendered)
	}
	// The same refusals the other two decoders make. A nested decoder is told
	// nothing about unknown keys, so the walk has to refuse them itself.
	for name, body := range map[string]string{
		"an unknown field":              `[{"prefix": "::/0", "form": "2001:db8::/48"}]`,
		"no prefix":                     `[{"from": "2001:db8::/48"}]`,
		"a prefix that is not a string": `[{"prefix": 5}]`,
		"neither spelling":              `[["10.66.0.5/32"]]`,
	} {
		t.Run(name, func(t *testing.T) {
			var refused []Announce
			if err := json.Unmarshal([]byte(body), &refused); err == nil {
				t.Errorf("json took %s as %v", body, refused)
			}
		})
	}
}

// An entry whose prefix and from are both wrong names the same half under
// every decoder. The toml walk sorted its keys, which puts from first, while
// the yaml walk and Routes.Validate both take prefix first, so the three
// disagreed about which half to name.
func TestEveryDecoderNamesTheSameHalfOfABadAnnouncement(t *testing.T) {
	// Each half is spelled wrong differently, so the refusal says which one it
	// reached rather than only that something was wrong.
	const badPrefix, badFrom = "xn--prefix", "xn--from"
	named := func(t *testing.T, err error) {
		t.Helper()
		if err == nil {
			t.Fatal("an announcement with two bad halves was taken")
		}
		if !strings.Contains(err.Error(), badPrefix) {
			t.Errorf("the refusal reads %q, and prefix is the half the yaml walk and Routes.Validate name first", err)
		}
	}
	var fromYAML Announce
	named(t, yaml.Unmarshal([]byte("{ prefix: "+badPrefix+", from: "+badFrom+" }"), &fromYAML))
	var fromTOML Announce
	named(t, fromTOML.UnmarshalTOML(map[string]any{"prefix": badPrefix, "from": badFrom}))
	var fromJSON Announce
	named(t, json.Unmarshal([]byte(`{"prefix": "`+badPrefix+`", "from": "`+badFrom+`"}`), &fromJSON))
}

func equal(a, b holder) bool {
	if a.Interval != b.Interval || a.Prefix != b.Prefix || a.Address != b.Address || a.Table != b.Table {
		return false
	}
	if len(a.Announce) != len(b.Announce) {
		return false
	}
	for i := range a.Announce {
		if a.Announce[i] != b.Announce[i] {
			return false
		}
	}
	return true
}
