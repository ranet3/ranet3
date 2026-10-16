// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package ike

import (
	"bytes"
	"encoding/hex"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// aliasEndpoints are the values a drawn entry takes, a node among them, which Validate refuses as a value
var aliasEndpoints = []identity.Identity{identity.MustParse("acme/gw:1"), identity.MustParse("acme/gw:2"),
	identity.MustParse("acme/db:1"), identity.MustParse("acme/gw")}

// aliasSelf is the node a drawn table is written for, which the remote tables drawn here never read
var aliasSelf = identity.MustParse("acme/me")

// drawDomain draws a name of one to three labels, now and then with a letter outside ASCII or a terminator in one
func drawDomain(tc hegel.TestCase) string {
	labels := make([]string, hegel.Draw(tc, withEdges(hegel.Integers(1, 3), 1, 3)))
	for i := range labels {
		labels[i] = hegel.Draw(tc, hegel.SampledFrom([]string{"gw", "GW", "acme", "Acme", "x-1", "\u00e9", "\u00c9", "a\x00", "a\r", "a\x7f", "a\u2028"}))
	}
	return strings.Join(labels, ".")
}

// drawWritten draws an ID as the table of kind writes one, from pieces few enough that two keys often name one ID, and now and then one Validate refuses
func drawWritten(tc hegel.TestCase, kind aliasKind) string {
	switch kind {
	case aliasIP:
		return hegel.Draw(tc, hegel.SampledFrom([]string{"192.0.2.10", "192.0.2.11", "2001:db8::10", "2001:DB8::10",
			"::ffff:192.0.2.10", "::", "192.0.2.300", "fe80::1%eth0"}))
	case aliasKeyID:
		return hegel.Draw(tc, hegel.SampledFrom([]string{"0a", "0A", "0a1b", "ff", "", "0a1", "zz",
			hex.EncodeToString([]byte("acme/gw:1")), hex.EncodeToString([]byte("acme/gw"))}))
	case aliasFQDN:
		return drawDomain(tc)
	}
	// a quoted local part may hold an @, and the letter after it compares exactly as the rest of the local part does
	return hegel.Draw(tc, hegel.SampledFrom([]string{"ops", "Ops", "a.b", "\u00e9", "", `"o@Ps"`, `"o@ps"`})) + "@" + drawDomain(tc)
}

// drawEntries draws a table of kind with up to three entries
func drawEntries(tc hegel.TestCase, kind aliasKind) map[string]identity.Identity {
	table := map[string]identity.Identity{}
	for range hegel.Draw(tc, withEdges(hegel.Integers(0, 3), 0, 3)) {
		table[drawWritten(tc, kind)] = hegel.Draw(tc, hegel.SampledFrom(aliasEndpoints))
	}
	return table
}

// wireForm is the ID type and data an ID written as kind goes on the wire as, an address in the type of its family as netip reads it
func wireForm(kind aliasKind, written string) (IDType, []byte, bool) {
	switch kind {
	case aliasIP:
		address, err := netip.ParseAddr(written)
		if err != nil || address.Zone() != "" {
			return 0, nil, false
		}
		if address.Is4() {
			return ID_IPV4_ADDR, address.AsSlice(), true
		}
		return ID_IPV6_ADDR, address.AsSlice(), true
	case aliasKeyID:
		octets, err := hex.DecodeString(written)
		return ID_KEY_ID, octets, err == nil
	case aliasFQDN:
		return ID_FQDN, []byte(written), true
	}
	return ID_RFC822_ADDR, []byte(written), true
}

// aliasEntry is one key of a drawn table and the kind of table holding it
type aliasEntry struct {
	kind    aliasKind
	written string
}

// changes are the edits drawReceived may make to an ID a key writes, each of which a matching rule turns on
var changes = []string{"none", "flip the case of a letter", "insert a terminator", "move to the other family", "change an octet"}

// drawReceived draws an ID a peer sends, one a key of table writes as written or changed, one drawn as a key is, or a KEY_ID spelling one of aliasEndpoints
func drawReceived(tc hegel.TestCase, table RemoteAliases) (IDType, []byte) {
	var entries []aliasEntry
	for _, kind := range aliasKinds {
		for _, written := range slices.Sorted(maps.Keys(table.table(kind))) {
			entries = append(entries, aliasEntry{kind, written})
		}
	}
	switch hegel.Draw(tc, hegel.SampledFrom([]string{"a key", "drawn", "an endpoint's text"})) {
	case "an endpoint's text":
		return ID_KEY_ID, []byte(hegel.Draw(tc, hegel.SampledFrom(aliasEndpoints)).String())
	case "a key":
		if len(entries) > 0 {
			entry := hegel.Draw(tc, hegel.SampledFrom(entries))
			if idType, data, ok := wireForm(entry.kind, entry.written); ok {
				return change(tc, idType, data)
			}
		}
	}
	kind := hegel.Draw(tc, hegel.SampledFrom(aliasKinds))
	if idType, data, ok := wireForm(kind, drawWritten(tc, kind)); ok {
		return idType, data
	}
	return ID_KEY_ID, drawBytes(tc, 8, 1)
}

// change applies one of changes to an ID of idType holding data
func change(tc hegel.TestCase, idType IDType, data []byte) (IDType, []byte) {
	data = slices.Clone(data)
	switch hegel.Draw(tc, hegel.SampledFrom(changes)) {
	case "flip the case of a letter":
		var letters []int
		for i, c := range data {
			if 'a' <= c|0x20 && c|0x20 <= 'z' {
				letters = append(letters, i)
			}
		}
		if len(letters) > 0 {
			data[hegel.Draw(tc, hegel.SampledFrom(letters))] ^= 'a' - 'A'
		}
	case "insert a terminator":
		at := hegel.Draw(tc, withEdges(hegel.Integers(0, len(data)), 0, len(data)))
		return idType, slices.Insert(data, at, hegel.Draw(tc, hegel.SampledFrom([]byte{0, '\r', '\n', 0x7f})))
	case "move to the other family":
		address, _ := netip.AddrFromSlice(data)
		switch {
		case idType == ID_IPV4_ADDR:
			return ID_IPV6_ADDR, netip.AddrFrom16(address.As16()).AsSlice()
		case idType == ID_IPV6_ADDR && address.Is4In6():
			return ID_IPV4_ADDR, address.Unmap().AsSlice()
		}
	case "change an octet":
		if len(data) > 0 {
			data[hegel.Draw(tc, hegel.Integers(0, len(data)-1))] ^= 1
		}
	}
	return idType, data
}

// rules are the boundaries the matching rules and Validate branch on, every one of which each case meets
var rules = []string{
	"case in an FQDN", "case in an email domain", "case in an email local part", "an @ in a quoted local part",
	"a line separator", "a letter outside ASCII", "a control character", "an IPv4-mapped address",
	"an IPv4-mapped address against its IPv4 key", "an empty local part", "an empty KEY_ID", "a KEY_ID spelling a node",
	"a KEY_ID spelling an endpoint", "two keys naming one ID", "a key spelling another endpoint",
}

// twice are two keys of one table that name one ID
var twice = []struct {
	kind aliasKind
	a, b string
}{
	{aliasIP, "2001:db8::77", "2001:DB8::77"},
	{aliasFQDN, "twice.example", "TWICE.example"},
	{aliasEmail, "op@twice.example", "op@TWICE.example"},
	{aliasKeyID, "0a77", "0A77"},
}

// meetRule writes into remote the key that meets rule and draws the ID a peer sends against that key, with the key where the rule writes one
// the keys it writes are spelled apart from every key drawWritten draws, except those that replace the tables and the empty KEY_ID, which matches no ID
// two keys naming one ID, or a key spelling another endpoint than its value, are the tables alone, which Validate refuses for that entry alone
func meetRule(tc hegel.TestCase, rule string, remote *RemoteAliases) (IDType, []byte, *aliasEntry) {
	endpoint := hegel.Draw(tc, hegel.SampledFrom(aliasEndpoints))
	write := func(kind aliasKind, written string) *aliasEntry {
		remote.table(kind)[written] = endpoint
		return &aliasEntry{kind, written}
	}
	mapped := netip.MustParseAddr("::ffff:192.0.2.77").As16()
	switch rule {
	case "case in an FQDN":
		return ID_FQDN, []byte("RULE.example"), write(aliasFQDN, "rule.example")
	case "case in an email domain":
		return ID_RFC822_ADDR, []byte("op@RULE.example"), write(aliasEmail, "op@rule.example")
	case "case in an email local part":
		return ID_RFC822_ADDR, []byte("op@rule.example"), write(aliasEmail, "Op@rule.example")
	case "an @ in a quoted local part":
		return ID_RFC822_ADDR, []byte(`"o@rule"@rule.example`), write(aliasEmail, `"o@Rule"@rule.example`)
	case "a line separator":
		written := "op" + string(rune(0x2028)) + "@rule.example"
		return ID_RFC822_ADDR, []byte(written), write(aliasEmail, written)
	case "a letter outside ASCII":
		written := "rul" + string(rune(0xe9)) + ".example"
		return ID_FQDN, []byte(written), write(aliasFQDN, written)
	case "a control character":
		written := "rule" + string(hegel.Draw(tc, hegel.SampledFrom([]rune{0, '\r', '\n', 0x7f}))) + ".example"
		return ID_FQDN, []byte(written), write(aliasFQDN, written)
	case "an IPv4-mapped address":
		return ID_IPV6_ADDR, mapped[:], write(aliasIP, "::ffff:192.0.2.77")
	case "an IPv4-mapped address against its IPv4 key":
		return ID_IPV6_ADDR, mapped[:], write(aliasIP, "192.0.2.77")
	case "an empty local part":
		return ID_RFC822_ADDR, []byte("@rule.example"), write(aliasEmail, "@rule.example")
	case "an empty KEY_ID":
		return ID_KEY_ID, nil, write(aliasKeyID, "")
	case "a KEY_ID spelling a node":
		return ID_KEY_ID, []byte("acme/gw"), nil
	case "a KEY_ID spelling an endpoint":
		return ID_KEY_ID, []byte(hegel.Draw(tc, hegel.SampledFrom(aliasEndpoints[:3])).String()), nil
	case "a key spelling another endpoint":
		_, *remote = aliasOf(aliasKeyID, hex.EncodeToString([]byte(aliasEndpoints[0].String())), aliasEndpoints[1])
		return ID_KEY_ID, []byte(aliasEndpoints[0].String()), nil
	}
	pair := hegel.Draw(tc, hegel.SampledFrom(twice))
	_, *remote = aliasOf(pair.kind, pair.a, aliasEndpoints[0])
	remote.table(pair.kind)[pair.b] = aliasEndpoints[1]
	idType, data, _ := wireForm(pair.kind, pair.a)
	return idType, data, &aliasEntry{pair.kind, pair.a}
}

// plainASCII reports whether text is one or more ASCII characters none of which is a control character
func plainASCII(text string) bool {
	return text != "" && !strings.ContainsFunc(text, func(r rune) bool { return r < ' ' || r > '~' })
}

// plainText reports whether text is UTF-8 and holds no control character and no line or paragraph separator, the terminators section 3.5 refuses
func plainText(text string) bool {
	return text != "" && utf8.ValidString(text) &&
		!strings.ContainsFunc(text, func(r rune) bool { return unicode.IsControl(r) || r == '\u2028' || r == '\u2029' })
}

// sameDomain reports whether two domains are one, ASCII letters compared without case as RFC 4343 compares them and every other byte as it is
func sameDomain(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range len(a) {
		letter := 'a' <= a[i]|0x20 && a[i]|0x20 <= 'z'
		if a[i] != b[i] && !(letter && a[i]^b[i] == 'a'-'A') {
			return false
		}
	}
	return true
}

// matches reports whether an entry of kind written as written matches an ID of idType holding data
// an address matches its own family alone, an FQDN matches without case, and an email address matches its local part exactly and its domain without case
func matches(kind aliasKind, written string, idType IDType, data []byte) bool {
	switch kind {
	case aliasIP:
		wantType, wantData, ok := wireForm(kind, written)
		return ok && idType == wantType && bytes.Equal(data, wantData)
	case aliasKeyID:
		octets, err := hex.DecodeString(written)
		return err == nil && len(octets) > 0 && idType == ID_KEY_ID && bytes.Equal(data, octets)
	case aliasFQDN:
		return idType == ID_FQDN && plainASCII(written) && plainASCII(string(data)) && strings.EqualFold(written, string(data))
	}
	if idType != ID_RFC822_ADDR || !plainText(written) || !plainText(string(data)) {
		return false
	}
	at, received := strings.LastIndexByte(written, '@'), strings.LastIndexByte(string(data), '@')
	return at > 0 && at < len(written)-1 && received > 0 &&
		written[:at] == string(data[:received]) && sameDomain(written[at+1:], string(data[received+1:]))
}

func cloneRemote(r RemoteAliases) RemoteAliases {
	return RemoteAliases{IP: maps.Clone(r.IP), FQDN: maps.Clone(r.FQDN), Email: maps.Clone(r.Email), KeyID: maps.Clone(r.KeyID)}
}

// over a drawn table and a drawn ID, resolve names one endpoint an entry matching the ID names, or the endpoint a KEY_ID spells with no entry, and refuses an ID neither names
// a table Validate takes has at most one answer for any ID, and RESERVED, whatever it holds, changes nothing
// sameID matches an ID to the alias auth.aliases.local presents under the same rules
// each case checks a drawn ID and then every one of rules on its own copy of the drawn table, the alias presented writing the key the rule wrote
func TestAliasResolutionFollowsTheMatchingRules(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		remote := RemoteAliases{IP: drawEntries(ht, aliasIP), FQDN: drawEntries(ht, aliasFQDN),
			Email: drawEntries(ht, aliasEmail), KeyID: drawEntries(ht, aliasKeyID)}
		idType, data := drawReceived(ht, remote)
		kind := hegel.Draw(ht, hegel.SampledFrom(aliasKinds))
		resolvesByTheRules(ht, "a drawn ID", remote, idType, data, aliasEntry{kind, drawWritten(ht, kind)})
		for _, rule := range rules {
			ruled := cloneRemote(remote)
			idType, data, entry := meetRule(ht, rule, &ruled)
			if entry == nil {
				kind := hegel.Draw(ht, hegel.SampledFrom(aliasKinds))
				entry = &aliasEntry{kind, drawWritten(ht, kind)}
			}
			resolvesByTheRules(ht, rule, ruled, idType, data, *entry)
		}
	})
}

// resolvesByTheRules fails ht unless resolve and sameID take an ID of idType holding data, under drawn RESERVED octets, as the matching rules say against remote and against the alias presented
func resolvesByTheRules(ht *hegel.T, rule string, remote RemoteAliases, idType IDType, data []byte, presenting aliasEntry) {
	aliases := Aliases{Remote: remote}
	body := EncodeID(idType, data)
	copy(body[1:4], hegel.Draw(ht, withEdges(hegel.Binary(3, 3), []byte{0, 0, 0}, []byte{0xff, 0xff, 0xff})))

	var want []identity.Identity
	for _, kind := range aliasKinds {
		for written, endpoint := range remote.table(kind) {
			if matches(kind, written, idType, data) && !slices.Contains(want, endpoint) {
				want = append(want, endpoint)
			}
		}
	}
	if spelled, err := identity.Parse(string(data)); idType == ID_KEY_ID && err == nil && spelled != spelled.Node() {
		if aliases.Validate(aliasSelf) == nil && len(want) > 0 && !slices.Equal(want, []identity.Identity{spelled}) {
			ht.Fatalf("%s: a table Validate took names %v for the KEY_ID spelling %s", rule, want, spelled)
		}
		want = []identity.Identity{spelled}
	}
	if aliases.Validate(aliasSelf) == nil && len(want) > 1 {
		ht.Fatalf("%s: a table Validate took names %v for %s ID %x", rule, want, idType, data)
	}

	got, err := aliases.resolve(body)
	switch {
	case len(want) == 0 && err == nil:
		ht.Fatalf("%s: %s ID %x resolved to %s, which no entry names", rule, idType, data, got.endpoint)
	case len(want) > 0 && err != nil:
		ht.Fatalf("%s: %s ID %x was refused with %v, want one of %v", rule, idType, data, err, want)
	case len(want) > 0 && (!slices.Contains(want, got.endpoint) || got.idType != idType || !bytes.Equal(got.data, data)):
		ht.Fatalf("%s: %s ID %x resolved to %s as %s ID %x, want one of %v", rule, idType, data, got.endpoint, got.idType, got.data, want)
	}

	kind, written := presenting.kind, presenting.written
	presented, err := localAlias(kind, written).body()
	if err == nil && sameID(body, presented) != matches(kind, written, idType, data) {
		ht.Fatalf("%s: sameID compared %s ID %x with the alias %s %q as %v", rule, idType, data, kind, written, !matches(kind, written, idType, data))
	}
}
