// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package schema

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

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

// parse(render(p)) is p for any prefix, under the text form every scalar goes
// through and under the json, yaml and toml encoders that wrap it. A prefix
// that came back changed would make a rendered configuration describe a
// different node than the one it was rendered from. The address is drawn
// whole rather than masked to its length, because the type keeps the host bits
// it was given and a round trip that cleaned them up would change what a node
// announces.
func TestPrefixRoundTripsThroughEveryEncoding(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		address := hegel.Draw(ht, hegel.IPAddresses())
		bits := hegel.Draw(ht, hegel.Integers(0, address.BitLen()))
		want := PrefixFrom(netip.PrefixFrom(address, bits))

		// every encoding is judged alike, so a failure names the one that lost
		// the value
		judge := func(encoding, written string, got Prefix, err error) {
			ht.Helper()
			if err != nil {
				ht.Fatalf("%s wrote %q for %v and refused it back: %v", encoding, written, want, err)
			}
			if got != want {
				ht.Fatalf("%s wrote %q for %v and read it back as %v", encoding, written, want, got)
			}
		}

		text, err := want.MarshalText()
		if err != nil {
			ht.Fatalf("text refused %v: %v", want, err)
		}
		var fromText Prefix
		err = fromText.UnmarshalText(text)
		judge("text", string(text), fromText, err)

		asJSON, err := json.Marshal(onePrefix{want})
		if err != nil {
			ht.Fatalf("json refused %v: %v", want, err)
		}
		var fromJSON holder
		err = json.Unmarshal(asJSON, &fromJSON)
		judge("json", string(asJSON), fromJSON.Prefix, err)

		asYAML, err := yaml.Marshal(onePrefix{want})
		if err != nil {
			ht.Fatalf("yaml refused %v: %v", want, err)
		}
		fromYAML, err := decodeYAML(t, string(asYAML))
		judge("yaml", string(asYAML), fromYAML.Prefix, err)

		var asTOML strings.Builder
		if err := toml.NewEncoder(&asTOML).Encode(onePrefix{want}); err != nil {
			ht.Fatalf("toml refused %v: %v", want, err)
		}
		fromTOML, err := decodeTOML(t, asTOML.String())
		judge("toml", asTOML.String(), fromTOML.Prefix, err)
	})
}
