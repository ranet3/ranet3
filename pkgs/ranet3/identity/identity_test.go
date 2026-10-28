// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package identity

import (
	"strings"
	"testing"
)

func TestParseRefusesEveryOtherSpelling(t *testing.T) {
	for _, text := range []string{
		"",
		"example",
		"example/gateway:1:2",
		"example/:1",
		"/gateway",
		"example/gateway:",
		"example:1/gateway",
		"example/gateway@0",
		"example/gateway:1@0",
		"example/gate way",
		"example/gateway%3a1",
		"example/%41gateway",
		"example/gateway%2",
		"example/gateway%",
		"example/gateway%G0",
	} {
		if id, err := Parse(text); err == nil {
			t.Errorf("Parse(%q) took it as %#v", text, id)
		}
	}
}

func TestParseRefusesAnOrganizationOfMoreThanOneLevel(t *testing.T) {
	for _, text := range []string{"example/lab/gateway", "example/lab/gateway:0", "example/alpha/1"} {
		if id, err := Parse(text); err == nil || !strings.Contains(err.Error(), "an organization has one level") {
			t.Errorf("Parse(%q) = %#v, %v, want a refusal of the second level", text, id, err)
		}
	}
}

// selectors and ids may take this shape later, so nothing may mean it today, and no query gives a bare name a serial
func TestTextWithAColonAndNoSlashNamesNothing(t *testing.T) {
	queries := []string{"tag:router", "id:7f3a", "gateway:1"}
	for _, query := range queries {
		if id, err := Parse(query); err == nil {
			t.Errorf("Parse(%q) took it as %#v", query, id)
		}
	}
	for _, subject := range []string{"example/gateway:1@0", "example/gateway:1", "example/gateway@0", "example/tag:router@0", "example/id:7f3a"} {
		for _, query := range queries {
			if Names(subject, query) {
				t.Errorf("%q names %q", query, subject)
			}
		}
	}
}

func TestFromRefusesAnEmptyOrganizationOrName(t *testing.T) {
	for _, parts := range [][3]string{{"", "gateway", "1"}, {"example", "", "1"}, {"", "", ""}} {
		if id, err := From(parts[0], parts[1], parts[2]); err == nil {
			t.Errorf("From(%q) took it as %#v", parts, id)
		}
	}
}

func TestCanonicalFormsReadAsTheirParts(t *testing.T) {
	for text, want := range map[string]Identity{
		"example/laptop":            {"example", "laptop", ""},
		"example/laptop:13001":      {"example", "laptop", "13001"},
		"example%20org/gateway:0":   {"example org", "gateway", "0"},
		"r%C3%A9seau/a%2Fb%3Ac:%40": {"r\xc3\xa9seau", "a/b:c", "@"},
	} {
		got, err := Parse(text)
		if err != nil || got != want {
			t.Errorf("Parse(%q) = %#v, %v, want %#v", text, got, err, want)
		}
		if got.String() != text {
			t.Errorf("%#v is written %q, want %q", want, got.String(), text)
		}
	}
}

// every byte, written as a whole part, reads back as itself and never as a separator
func TestEveryByteRoundTripsInEveryPart(t *testing.T) {
	for b := range 256 {
		c := string([]byte{byte(b)})
		id, err := From("o"+c, c+"n", c)
		if err != nil {
			t.Fatal(err)
		}
		text := id.String()
		if strings.Count(text, "/") != 1 || strings.Count(text, ":") != 1 || strings.Contains(text, "@") {
			t.Errorf("byte %#x is written %q", b, text)
		}
		if got, err := Parse(text); err != nil || got != id {
			t.Errorf("byte %#x: Parse(%q) = %#v, %v", b, text, got, err)
		}
	}
}

func TestPathNamesTheRemoteAndTheLocalSerial(t *testing.T) {
	laptop := MustParse("example/laptop:0")
	for want, remote := range map[string]Identity{
		"example/bravo:0@0": MustParse("example/bravo:0"),
		"example/gateway@0": MustParse("example/gateway"),
	} {
		if got := Path(remote, laptop); got != want {
			t.Errorf("Path(%s, %s) = %q, want %q", remote, laptop, got, want)
		}
	}
}

func TestNamesComparesWholeSegments(t *testing.T) {
	for _, test := range []struct {
		subject, query string
		want           bool
	}{
		{"example/gateway:1@0", "example/gateway:1@0", true},
		{"example/gateway:1@0", "example/gateway:1", true},
		{"example/gateway:1@0", "example/gateway", true},
		{"example/gateway:1@0", "gateway", true},
		{"example/gateway@0", "example/gateway", true},
		{"example/gateway:1", "gateway", true},
		{"example/gateway", "gateway", true},
		{"example/gateway2:1@0", "example/gateway", false},
		{"example/gateway2:1@0", "gateway", false},
		{"example/gateway:1@0", "example/gateway:2", false},
		{"example/gateway:1@0", "example", false},
		{"example/gateway:1@0", "other/gateway", false},
		{"example/gateway:1@0", "1", false},
		{"example/gateway:1@0", ":1", false},
	} {
		if got := Names(test.subject, test.query); got != test.want {
			t.Errorf("Names(%q, %q) = %v, want %v", test.subject, test.query, got, test.want)
		}
	}
}
