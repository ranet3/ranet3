// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package identity

import (
	"slices"
	"strings"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// partBytes leads with the separators, the escape, a space, NUL, the bytes either side of each run of the unreserved set and bytes no UTF-8 text holds, then every byte
var partBytes = []byte("/@% \x00-.,:09AZ[`az{_^~\x7f\x80\xc3" + func() string {
	var all strings.Builder
	for b := range 256 {
		all.WriteByte(byte(b))
	}
	return all.String()
}() + "\xff")

// drawPart draws a part of at least least bytes, so least 0 can draw the empty serial
func drawPart(tc hegel.TestCase, least int) string {
	var part strings.Builder
	for range hegel.Draw(tc, pbt.Spanning(least, 6)) {
		part.WriteByte(partBytes[hegel.Draw(tc, pbt.Spanning(0, len(partBytes)-1))])
	}
	return part.String()
}

func drawIdentity(tc hegel.TestCase) Identity {
	id, err := From(drawPart(tc, 1), drawPart(tc, 1), drawPart(tc, 0))
	if err != nil {
		panic(err)
	}
	return id
}

// canonical and near canonical tokens of a part, a lowercase escape and the escape of an unreserved byte among them
var partTokens = []string{"a", "Z", "0", "-", ".", "_", "~", "%20", "%2F", "%3A", "%40", "%25", "%FF", "%00", "%2f", "%3a", "%41", "%7E", "%", "@", "/", ":", " "}

// the first canonicalTokens of partTokens are canonical, and the rest are not
const canonicalTokens = 14

// separators between parts, of which only organization/name and organization/name:serial are canonical
var separators = []string{"/", ":", "@"}

func TestIdentityRoundTripsThroughItsCanonicalForm(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		id := drawIdentity(ht)
		text := id.String()
		colons := 0
		if id.serial != "" {
			colons = 1
		}
		if strings.Contains(text, "@") || strings.Count(text, "/") != 1 || strings.Count(text, ":") != colons {
			ht.Fatalf("%#v is written %q", id, text)
		}
		if got, err := Parse(text); err != nil || got != id {
			ht.Fatalf("Parse(%q) = %#v, %v, want %#v", text, got, err, id)
		}
		serial := drawPart(ht, 0)
		if at := id.At(serial); at.Node() != id.Node() {
			ht.Fatalf("%#v at %q is %#v, whose node is not %#v", id, serial, at, id.Node())
		}
		var read Identity
		if written, err := id.MarshalText(); err != nil || read.UnmarshalText(written) != nil || read != id {
			ht.Fatalf("%#v is written %q, %v, and read back as %#v", id, written, err, read)
		}
		if (id.Node() == id) != (id.serial == "") {
			ht.Fatalf("%#v reads as a node %v", id, id.Node() == id)
		}
		organization, name := id.NodeParts()
		if node, err := From(organization, name, ""); err != nil || node != id.Node() {
			ht.Fatalf("%#v has the node parts %q and %q, which name %#v, %v", id, organization, name, node, err)
		}
	})
}

// a text Parse takes is the text String writes for what it read, and a text of canonical tokens is taken
func TestParsedTextIsItsOwnCanonicalForm(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		canonical := hegel.Draw(ht, hegel.Booleans())
		last := len(partTokens) - 1
		if canonical {
			last = canonicalTokens - 1
		}
		parts := make([]string, hegel.Draw(ht, pbt.Spanning(1, 4)))
		var text strings.Builder
		var between []string
		for i := range parts {
			if i > 0 {
				between = append(between, separators[hegel.Draw(ht, pbt.Spanning(0, len(separators)-1))])
				text.WriteString(between[i-1])
			}
			var part strings.Builder
			for range hegel.Draw(ht, pbt.Spanning(0, 4)) {
				part.WriteString(partTokens[hegel.Draw(ht, pbt.Spanning(0, last))])
			}
			parts[i] = part.String()
			text.WriteString(parts[i])
		}
		id, err := Parse(text.String())
		if err == nil && id.String() != text.String() {
			ht.Fatalf("Parse(%q) read %#v, which is written %q", text.String(), id, id.String())
		}
		shaped := slices.Equal(between, []string{"/"}) || slices.Equal(between, []string{"/", ":"})
		if canonical && shaped && !slices.Contains(parts, "") && err != nil {
			ht.Fatalf("Parse refused the canonical %q: %v", text.String(), err)
		}
	})
}

// a query names a path by the path, its remote, the remote's node or the node's name, never by the name with a serial, and names no path to a node whose name only starts with that name
func TestNamesTakesEachSpellingOfThePeerAndNoOther(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		remote, local := drawIdentity(ht), drawIdentity(ht)
		path := Path(remote, local)
		for _, query := range []string{path, remote.String(), remote.Node().String(), escape(remote.name)} {
			if !Names(path, query) {
				ht.Fatalf("%q does not name %q", query, path)
			}
		}
		if bare := escape(remote.name) + ":" + escape(remote.serial); remote.serial != "" && Names(path, bare) {
			ht.Fatalf("the bare name with a serial %q names %q", bare, path)
		}
		other, err := From(remote.organization, remote.name+drawPart(ht, 1), remote.serial)
		if err != nil {
			panic(err)
		}
		otherPath := Path(other, local)
		for _, query := range []string{remote.String(), remote.Node().String(), escape(remote.name)} {
			if Names(otherPath, query) {
				ht.Fatalf("%q names %q", query, otherPath)
			}
		}
	})
}
