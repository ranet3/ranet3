// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package ike

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"unicode"
	"unicode/utf8"

	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/schema"
)

// Aliases is auth.aliases, the IDs of RFC 7296 section 3.5 besides a DN that a peer and this node name each other by
// the section has the contents of IDi and IDr "used purely to fetch the policy and authentication data related to the other party"
// an ID only names an endpoint of the trust document, whose key still has to verify AUTH
type Aliases struct {
	Remote RemoteAliases `yaml:"remote,omitempty" json:"remote,omitzero" toml:"remote,omitempty"`
	// Local is the ID this node presents to a peer in place of its DN, keyed by the peer as dial.to writes one
	// an endpoint's entry wins over its node's
	Local map[string]LocalAlias `yaml:"local,omitempty" json:"local,omitempty" toml:"local,omitempty"`
}

// RemoteAliases names the endpoint each ID a peer may present stands for, one table for each kind of ID
// a key is the ID as written, an address under ip, a name under fqdn, an address under email and the octets in hex under keyid
type RemoteAliases struct {
	IP    map[string]identity.Identity `yaml:"ip,omitempty" json:"ip,omitempty" toml:"ip,omitempty"`
	FQDN  map[string]identity.Identity `yaml:"fqdn,omitempty" json:"fqdn,omitempty" toml:"fqdn,omitempty"`
	Email map[string]identity.Identity `yaml:"email,omitempty" json:"email,omitempty" toml:"email,omitempty"`
	KeyID map[string]identity.Identity `yaml:"keyid,omitempty" json:"keyid,omitempty" toml:"keyid,omitempty"`
}

// LocalAlias is one ID this node presents, written in exactly one field as the table of its kind writes a key
type LocalAlias struct {
	IP    string `yaml:"ip,omitempty" json:"ip,omitempty" toml:"ip,omitempty"`
	FQDN  string `yaml:"fqdn,omitempty" json:"fqdn,omitempty" toml:"fqdn,omitempty"`
	Email string `yaml:"email,omitempty" json:"email,omitempty" toml:"email,omitempty"`
	KeyID string `yaml:"keyid,omitempty" json:"keyid,omitempty" toml:"keyid,omitempty"`
}

type aliasKind string

const (
	aliasIP    aliasKind = "ip"
	aliasFQDN  aliasKind = "fqdn"
	aliasEmail aliasKind = "email"
	aliasKeyID aliasKind = "keyid"
)

var aliasKinds = []aliasKind{aliasIP, aliasFQDN, aliasEmail, aliasKeyID}

// parse reads an IPv4 address as ID_IPV4_ADDR and every other address, an IPv4-mapped one included, as ID_IPV6_ADDR
func (kind aliasKind) parse(written string) (IDType, []byte, error) {
	switch kind {
	case aliasIP:
		address, err := schema.ParseAddr(written)
		if err != nil {
			return 0, nil, fmt.Errorf("is not an address: %w", err)
		}
		if address.Is4() {
			four := address.As4()
			return ID_IPV4_ADDR, four[:], nil
		}
		sixteen := address.As16()
		return ID_IPV6_ADDR, sixteen[:], nil
	case aliasKeyID:
		octets, err := hex.DecodeString(written)
		if err != nil {
			return 0, nil, fmt.Errorf("is not octets in hex: %w", err)
		}
		return ID_KEY_ID, octets, nil
	case aliasFQDN:
		return ID_FQDN, []byte(written), nil
	}
	return ID_RFC822_ADDR, []byte(written), nil
}

func (kind aliasKind) key(written string) (idKey, error) {
	idType, data, err := kind.parse(written)
	if err != nil {
		return idKey{}, err
	}
	return matchKey(idType, data)
}

// two IDs match exactly where their keys are equal
type idKey struct {
	idType IDType
	data   string
}

// matchKey refuses an ID no alias holds, which leaves a received one matching nothing
// an FQDN compares in ASCII without case, as RFC 4343 compares a DNS name
// an email address compares its domain the same way and its local part exactly
// an address or a KEY_ID compares by its octets
func matchKey(idType IDType, data []byte) (idKey, error) {
	switch idType {
	case ID_IPV4_ADDR, ID_IPV6_ADDR:
	case ID_KEY_ID:
		if len(data) == 0 {
			return idKey{}, errors.New("is empty")
		}
	case ID_FQDN:
		if err := unterminated(data, true); err != nil {
			return idKey{}, err
		}
		data = lowerASCII(data)
	case ID_RFC822_ADDR:
		if err := unterminated(data, false); err != nil {
			return idKey{}, err
		}
		at := bytes.LastIndexByte(data, '@')
		if at <= 0 || at == len(data)-1 {
			return idKey{}, errors.New("is not an address of the form local@domain")
		}
		data = append(slices.Clone(data[:at+1]), lowerASCII(data[at+1:])...)
	default:
		return idKey{}, errors.New("is of a type no alias holds")
	}
	return idKey{idType: idType, data: string(data)}, nil
}

// RFC 7296 section 3.5 says of ID_FQDN "The string MUST NOT contain any terminators (e.g., NULL, CR, etc.)"
// and "All characters in the ID_FQDN are ASCII"
// and of ID_RFC822_ADDR "The string MUST NOT contain any terminators"
// and "implementations would be wise to treat this field as UTF-8 encoded text, not as pure ASCII"
// a terminator is taken to be any control character and the line and paragraph separators
func unterminated(text []byte, ascii bool) error {
	if len(text) == 0 {
		return errors.New("is empty")
	}
	if !utf8.Valid(text) {
		return errors.New("is not UTF-8")
	}
	for _, r := range string(text) {
		switch {
		case unicode.IsControl(r) || r == '\u2028' || r == '\u2029':
			return fmt.Errorf("holds the terminator %q", r)
		case ascii && r > unicode.MaxASCII:
			return fmt.Errorf("holds %q, and an FQDN is ASCII, an internationalized name in its xn-- form", r)
		}
	}
	return nil
}

func lowerASCII(text []byte) []byte {
	out := slices.Clone(text)
	for i, c := range out {
		if 'A' <= c && c <= 'Z' {
			out[i] = c + 'a' - 'A'
		}
	}
	return out
}

func (r RemoteAliases) table(kind aliasKind) map[string]identity.Identity {
	switch kind {
	case aliasIP:
		return r.IP
	case aliasFQDN:
		return r.FQDN
	case aliasEmail:
		return r.Email
	}
	return r.KeyID
}

// Validate leaves at most one entry matching want
func (r RemoteAliases) find(want idKey) (identity.Identity, bool) {
	for _, kind := range aliasKinds {
		for written, endpoint := range r.table(kind) {
			if key, err := kind.key(written); err == nil && key == want {
				return endpoint, true
			}
		}
	}
	return identity.Identity{}, false
}

func (r RemoteAliases) naming(endpoint identity.Identity) ([][]byte, error) {
	var bodies [][]byte
	for _, kind := range aliasKinds {
		for written, named := range r.table(kind) {
			if named != endpoint {
				continue
			}
			idType, data, err := kind.parse(written)
			if err != nil {
				return nil, fmt.Errorf("ike: auth.aliases.remote.%s %q %w", kind, written, err)
			}
			bodies = append(bodies, EncodeID(idType, data))
		}
	}
	return bodies, nil
}

// Equal takes an empty table and none alike
func (r RemoteAliases) Equal(other RemoteAliases) bool {
	for _, kind := range aliasKinds {
		if !maps.Equal(r.table(kind), other.table(kind)) {
			return false
		}
	}
	return true
}

func (l LocalAlias) body() ([]byte, error) {
	var kind aliasKind
	var written string
	count := 0
	for _, field := range []struct {
		kind    aliasKind
		written string
	}{{aliasIP, l.IP}, {aliasFQDN, l.FQDN}, {aliasEmail, l.Email}, {aliasKeyID, l.KeyID}} {
		if field.written != "" {
			kind, written, count = field.kind, field.written, count+1
		}
	}
	if count != 1 {
		return nil, fmt.Errorf("writes %d of ip, fqdn, email and keyid, and an entry writes one", count)
	}
	idType, data, err := kind.parse(written)
	if err == nil {
		_, err = matchKey(idType, data)
	}
	if err != nil {
		return nil, fmt.Errorf("%s %q %w", kind, written, err)
	}
	return EncodeID(idType, data), nil
}

// Validate refuses a table no handshake could use as written, naming the entry as the operator wrote it
// self is the node the tables are written for
// two keys of one table naming one ID would leave the order of a map to pick the endpoint
// a KEY_ID spelling an endpoint names that endpoint with or without an entry, which leaves an entry naming another one unread
// a local KEY_ID spelling another node's endpoint has every peer verify AUTH with that node's key
func (a Aliases) Validate(self identity.Identity) error {
	for _, kind := range aliasKinds {
		table := a.Remote.table(kind)
		seen := make(map[idKey]string, len(table))
		for _, written := range slices.Sorted(maps.Keys(table)) {
			entry, endpoint := fmt.Sprintf("ike: auth.aliases.remote.%s %q", kind, written), table[written]
			switch {
			case endpoint.IsZero():
				return fmt.Errorf("%s names nobody", entry)
			case endpoint == endpoint.Node():
				return fmt.Errorf("%s names the node %s, and an alias names one endpoint of it", entry, endpoint)
			}
			key, err := kind.key(written)
			if err != nil {
				return fmt.Errorf("%s %w", entry, err)
			}
			if earlier, ok := seen[key]; ok {
				return fmt.Errorf("%s and %q name one ID", entry, earlier)
			}
			seen[key] = written
			if spelled, ok := endpointText(key); ok && spelled != endpoint {
				return fmt.Errorf("%s spells %s, which a KEY_ID names with no alias", entry, spelled)
			}
		}
	}
	for _, written := range slices.Sorted(maps.Keys(a.Local)) {
		if _, err := identity.Parse(written); err != nil {
			return fmt.Errorf("ike: auth.aliases.local %q: %w", written, err)
		}
		entry := a.Local[written]
		if _, err := entry.body(); err != nil {
			return fmt.Errorf("ike: auth.aliases.local %q %w", written, err)
		}
		if key, err := aliasKeyID.key(entry.KeyID); entry.KeyID != "" && err == nil {
			if spelled, ok := endpointText(key); ok && spelled.Node() != self {
				return fmt.Errorf("ike: auth.aliases.local %q keyid %q spells %s, an endpoint of another node, which a peer names with no alias", written, entry.KeyID, spelled)
			}
		}
	}
	return nil
}

// Entries is each entry with the endpoint or peer it names, the entry written as Validate names one
// every value of auth.aliases.remote comes in the order of its tables and their keys
// then every key of auth.aliases.local in order, leaving out a local key Validate refuses
func (a Aliases) Entries() iter.Seq2[string, identity.Identity] {
	return func(yield func(string, identity.Identity) bool) {
		for _, kind := range aliasKinds {
			table := a.Remote.table(kind)
			for _, written := range slices.Sorted(maps.Keys(table)) {
				if !yield(fmt.Sprintf("auth.aliases.remote.%s %q", kind, written), table[written]) {
					return
				}
			}
		}
		for _, written := range slices.Sorted(maps.Keys(a.Local)) {
			peer, err := identity.Parse(written)
			if err != nil {
				continue
			}
			if !yield(fmt.Sprintf("auth.aliases.local %q", written), peer) {
				return
			}
		}
	}
}

func endpointText(key idKey) (identity.Identity, bool) {
	if key.idType != ID_KEY_ID {
		return identity.Identity{}, false
	}
	id, err := identity.Parse(key.data)
	return id, err == nil && id != id.Node()
}

// presented is nil where neither peer nor its node has an entry
func (a Aliases) presented(peer identity.Identity) ([]byte, error) {
	entry, ok := a.Local[peer.String()]
	if !ok {
		entry, ok = a.Local[peer.Node().String()]
	}
	if !ok {
		return nil, nil
	}
	return entry.body()
}

func (a Aliases) presents(body []byte) bool {
	for _, entry := range a.Local {
		if presented, err := entry.body(); err == nil && sameID(body, presented) {
			return true
		}
	}
	return false
}

type named struct {
	endpoint identity.Identity
	idType   IDType
	data     []byte
}

// a DN names an endpoint itself, as does a KEY_ID holding its canonical text
// every other ID names one through auth.aliases.remote
// AUTH signs the body as received, which makes two IDs naming one endpoint one peer, neither accepted without its key
func (a Aliases) resolve(body []byte) (named, error) {
	idType, data, err := DecodeID(body)
	if err != nil {
		return named{}, err
	}
	if idType == ID_DER_ASN1_DN {
		endpoint, err := identity.FromDN(data)
		return named{endpoint: endpoint, idType: idType, data: data}, err
	}
	key, err := matchKey(idType, data)
	if err != nil {
		return named{}, fmt.Errorf("ike: %s ID %q names no endpoint, since it %w", idType, idText(idType, data), err)
	}
	if endpoint, ok := endpointText(key); ok {
		return named{endpoint: endpoint, idType: idType, data: data}, nil
	}
	endpoint, ok := a.Remote.find(key)
	if !ok {
		return named{}, fmt.Errorf("ike: %s ID %q names no endpoint auth.aliases.remote lists", idType, idText(idType, data))
	}
	return named{endpoint: endpoint, idType: idType, data: data}, nil
}

func idText(idType IDType, data []byte) string {
	switch idType {
	case ID_IPV4_ADDR, ID_IPV6_ADDR:
		address, _ := netip.AddrFromSlice(data)
		return address.String()
	case ID_KEY_ID:
		return hex.EncodeToString(data)
	}
	return string(data)
}

// String is the word an ike.id.resolved event names the type by, or the number of a type no ID here is read as
func (t IDType) String() string {
	switch t {
	case ID_IPV4_ADDR:
		return "ipv4"
	case ID_FQDN:
		return "fqdn"
	case ID_RFC822_ADDR:
		return "email"
	case ID_IPV6_ADDR:
		return "ipv6"
	case ID_DER_ASN1_DN:
		return "dn"
	case ID_KEY_ID:
		return "keyid"
	}
	return strconv.Itoa(int(t))
}

func (n named) attrs(sent []byte) []slog.Attr {
	attrs := []slog.Attr{slog.String("type", n.idType.String())}
	if n.idType != ID_DER_ASN1_DN {
		attrs = append(attrs, slog.String("id", idText(n.idType, n.data)))
	}
	return append(attrs, slog.String("sent", IDType(sent[0]).String()))
}
