// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

// Package identity names a node of the mesh and each of its endpoints.
package identity

import (
	"errors"
	"fmt"
	"strings"
)

// Identity is the name a node, or one of its endpoints, authenticates as
// the zero Identity names nobody
type Identity struct{ organization, name, serial string }

// From names the endpoint serial of the node name in organization, or the node itself where serial is empty
func From(organization, name, serial string) (Identity, error) {
	switch {
	case organization == "":
		return Identity{}, errors.New("identity: the organization is empty")
	case name == "":
		return Identity{}, errors.New("identity: the name is empty")
	}
	return Identity{organization, name, serial}, nil
}

// Parse reads the canonical form String writes and refuses every other spelling
func Parse(text string) (Identity, error) {
	node, serial, endpoint := strings.Cut(text, ":")
	organization, name, ok := strings.Cut(node, "/")
	switch {
	case !ok:
		return Identity{}, fmt.Errorf("identity: %q is not organization/name or organization/name:serial", text)
	case strings.Contains(name, "/"):
		return Identity{}, fmt.Errorf("identity: %q has a second / before the name, and an organization has one level", text)
	}
	parts := []string{organization, name}
	if endpoint {
		parts = append(parts, serial)
	}
	var decoded [3]string
	for i, part := range parts {
		var err error
		if decoded[i], err = unescape(part); err != nil {
			return Identity{}, fmt.Errorf("identity: %q: %w", text, err)
		}
	}
	return From(decoded[0], decoded[1], decoded[2])
}

// MustParse is Parse for a text known to be canonical, and panics on any other
func MustParse(text string) Identity {
	id, err := Parse(text)
	if err != nil {
		panic(err)
	}
	return id
}

// String is the canonical form, organization/name or organization/name:serial
// each part keeps the bytes RFC 3986 leaves unreserved and writes every other as % and two uppercase hex digits
func (id Identity) String() string {
	if id.IsZero() {
		return ""
	}
	text := escape(id.organization) + "/" + escape(id.name)
	if id.serial != "" {
		text += ":" + escape(id.serial)
	}
	return text
}

// Node is the node id names, which is id itself for a node
func (id Identity) Node() Identity { return Identity{id.organization, id.name, ""} }

// At names the endpoint serial of id's node
func (id Identity) At(serial string) (Identity, error) { return From(id.organization, id.name, serial) }

// IsZero reports whether id names nobody
func (id Identity) IsZero() bool { return id == Identity{} }

// Compare orders a and b by their raw organization, name and serial joined with /
// both ends of two crossing sessions keep the one this order picks, whatever release each runs, so it never follows the text form
func Compare(a, b Identity) int {
	return strings.Compare(a.organization+"/"+a.name+"/"+a.serial, b.organization+"/"+b.name+"/"+b.serial)
}

// Path names the session between remote and the local endpoint local, the same whichever end dialed
func Path(remote, local Identity) string { return remote.String() + "@" + escape(local.serial) }

// Names reports whether query names the peer subject is about
// subject is a path or a canonical form, and query names it whole, by the identity before @, by that identity's node or by the node's name
// a text with no / that holds a : names nothing, which keeps that shape free for selectors
// it allocates nothing, since a follow runs it on every emit
func Names(subject, query string) bool {
	id, _, _ := strings.Cut(subject, "@")
	if subject == query || id == query {
		return true
	}
	node, _, _ := strings.Cut(id, ":")
	_, name, ok := strings.Cut(node, "/")
	return ok && (query == node || query == name)
}

const upperHex = "0123456789ABCDEF"

func escape(part string) string {
	var text strings.Builder
	for i := range len(part) {
		if c := part[i]; unreserved(c) {
			text.WriteByte(c)
		} else {
			text.Write([]byte{'%', upperHex[c>>4], upperHex[c&0xf]})
		}
	}
	return text.String()
}

func unescape(part string) (string, error) {
	if part == "" {
		return "", errors.New("a part is empty")
	}
	var text strings.Builder
	for i := 0; i < len(part); i++ {
		c := part[i]
		switch {
		case unreserved(c):
			text.WriteByte(c)
		case c != '%':
			return "", fmt.Errorf("%q is written unescaped", c)
		case i+2 >= len(part):
			return "", errors.New("an escape is cut short")
		default:
			high, low := strings.IndexByte(upperHex, part[i+1]), strings.IndexByte(upperHex, part[i+2])
			if high < 0 || low < 0 {
				return "", fmt.Errorf("%q is not %% and two uppercase hex digits", part[i:i+3])
			}
			if c = byte(high<<4 | low); unreserved(c) {
				return "", fmt.Errorf("%q escapes a byte written as itself", part[i:i+3])
			}
			text.WriteByte(c)
			i += 2
		}
	}
	return text.String(), nil
}

// unreserved is RFC 3986's unreserved set, section 2.3
func unreserved(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~'
}
