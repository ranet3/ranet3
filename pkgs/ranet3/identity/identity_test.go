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
		"ysun",
		"ysun/isere:1:2",
		"ysun/:1",
		"/isere",
		"ysun/isere:",
		"ysun:1/isere",
		"ysun/isere@0",
		"ysun/isere:1@0",
		"ysun/is ere",
		"ysun/isere%3a1",
		"ysun/%41isere",
		"ysun/isere%2",
		"ysun/isere%",
		"ysun/isere%G0",
	} {
		if id, err := Parse(text); err == nil {
			t.Errorf("Parse(%q) took it as %#v", text, id)
		}
	}
}

func TestParseRefusesAnOrganizationOfMoreThanOneLevel(t *testing.T) {
	for _, text := range []string{"ysun/lab/gateway", "ysun/lab/gateway:0", "ysun/isere/1"} {
		if id, err := Parse(text); err == nil || !strings.Contains(err.Error(), "an organization has one level") {
			t.Errorf("Parse(%q) = %#v, %v, want a refusal of the second level", text, id, err)
		}
	}
}

// selectors and ids may take this shape later, so nothing may mean it today, and no query gives a bare name a serial
func TestTextWithAColonAndNoSlashNamesNothing(t *testing.T) {
	queries := []string{"tag:router", "id:7f3a", "isere:1"}
	for _, query := range queries {
		if id, err := Parse(query); err == nil {
			t.Errorf("Parse(%q) took it as %#v", query, id)
		}
	}
	for _, subject := range []string{"ysun/isere:1@0", "ysun/isere:1", "ysun/isere@0", "ysun/tag:router@0", "ysun/id:7f3a"} {
		for _, query := range queries {
			if Names(subject, query) {
				t.Errorf("%q names %q", query, subject)
			}
		}
	}
}

func TestFromRefusesAnEmptyOrganizationOrName(t *testing.T) {
	for _, parts := range [][3]string{{"", "isere", "1"}, {"ysun", "", "1"}, {"", "", ""}} {
		if id, err := From(parts[0], parts[1], parts[2]); err == nil {
			t.Errorf("From(%q) took it as %#v", parts, id)
		}
	}
}

func TestCanonicalFormsReadAsTheirParts(t *testing.T) {
	for text, want := range map[string]Identity{
		"ysun/framework":            {"ysun", "framework", ""},
		"ysun/framework:13001":      {"ysun", "framework", "13001"},
		"nick%20cao/gateway:0":      {"nick cao", "gateway", "0"},
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
	framework := MustParse("ysun/framework:0")
	for want, remote := range map[string]Identity{
		"ysun/butte:0@0": MustParse("ysun/butte:0"),
		"ysun/isere@0":   MustParse("ysun/isere"),
	} {
		if got := Path(remote, framework); got != want {
			t.Errorf("Path(%s, %s) = %q, want %q", remote, framework, got, want)
		}
	}
}

func TestNamesComparesWholeSegments(t *testing.T) {
	for _, test := range []struct {
		subject, query string
		want           bool
	}{
		{"ysun/isere:1@0", "ysun/isere:1@0", true},
		{"ysun/isere:1@0", "ysun/isere:1", true},
		{"ysun/isere:1@0", "ysun/isere", true},
		{"ysun/isere:1@0", "isere", true},
		{"ysun/isere@0", "ysun/isere", true},
		{"ysun/isere:1", "isere", true},
		{"ysun/isere", "isere", true},
		{"ysun/isere2:1@0", "ysun/isere", false},
		{"ysun/isere2:1@0", "isere", false},
		{"ysun/isere:1@0", "ysun/isere:2", false},
		{"ysun/isere:1@0", "ysun", false},
		{"ysun/isere:1@0", "other/isere", false},
		{"ysun/isere:1@0", "1", false},
		{"ysun/isere:1@0", ":1", false},
	} {
		if got := Names(test.subject, test.query); got != test.want {
			t.Errorf("Names(%q, %q) = %v, want %v", test.subject, test.query, got, test.want)
		}
	}
}
