// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

// Package config reads the file that says what this node is and what it does.
//
// The top level says what the node is: its name, the keys it authenticates
// with, the socket it speaks on and the peers it dials. Everything it does
// lives under cap, one block per capability, and the presence of a block is
// what turns that capability on. A default deployment writes node, auth, link
// and dial and nothing else.
//
// A capability block is defined by the package that implements it, carries its
// own serialization tags and validates itself. See [babel.Routes],
// [babel.Config], [kernel.Table], [srv6.Segments] and [ike.Crypto]. Nothing
// here mirrors those definitions, so a field added to a capability reaches the
// file, the control plane's wire form and the subsystem at once. What is left
// here is the node's own facts and the checks that span two capabilities,
// which is the one thing no capability can make for itself.
package config

import (
	"encoding"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/BurntSushi/toml"
	"go.yaml.in/yaml/v3"

	"ranet3.com/pkgs/ranet3/esp"
	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/ike"
	"ranet3.com/pkgs/ranet3/internal/babel"
	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
)

type Config struct {
	// Node is who this is, a node the document auth.trust names, since every peer checks the identity against that document
	Node identity.Identity `yaml:"node" json:"node" toml:"node"`
	Auth Auth              `yaml:"auth" json:"auth" toml:"auth"`
	Link Link              `yaml:"link" json:"link" toml:"link"`
	// Overlay is the prefixes the mesh numbers its nodes from, the same on every
	// node: a packet arriving from outside the mesh with a source in one of them
	// is forged, every local SID admits an outer source only inside them, and
	// the antispoof filter runs wherever it is written
	Overlay []schema.Prefix `yaml:"overlay,omitempty" json:"overlay,omitempty" toml:"overlay,omitempty"`
	Dial    Dial            `yaml:"dial,omitempty" json:"dial,omitzero" toml:"dial,omitempty"`
	Cap     Caps            `yaml:"cap,omitempty" json:"cap,omitzero" toml:"cap,omitempty"`
}

// LocalEndpoints is the identity of each link.endpoints entry, in order
func (c *Config) LocalEndpoints() []identity.Identity {
	out := make([]identity.Identity, 0, len(c.Link.Endpoints))
	for _, endpoint := range c.Link.Endpoints {
		out = append(out, c.Node.At(endpoint.Serial))
	}
	return out
}

func (c *Config) LocalFamilies() map[identity.Identity]ike.Family {
	out := make(map[identity.Identity]ike.Family, len(c.Link.Endpoints))
	for _, endpoint := range c.Link.Endpoints {
		out[c.Node.At(endpoint.Serial)] = Family(endpoint.Family)
	}
	return out
}

// Family reads a family as link.endpoints and the trust document's address_family spell it
func Family(spelling string) ike.Family {
	switch spelling {
	case "ip4":
		return ike.IPv4
	case "ip6":
		return ike.IPv6
	}
	return 0
}

// Auth is the key this node signs with, the document naming who it talks to
// and the IDs other than a DN that name either end of a handshake.
type Auth struct {
	// Key is this node's own private key, a PKCS8 PEM Ed25519 file.
	Key string `yaml:"key" json:"key" toml:"key"`
	// Trust is the document naming who may join, a ranet registry.json today.
	Trust string `yaml:"trust" json:"trust" toml:"trust"`
	// Aliases is the ID each peer may present in place of its DN and the ID this node presents to one, see [ike.Aliases]
	Aliases ike.Aliases `yaml:"aliases,omitempty" json:"aliases,omitzero" toml:"aliases,omitempty"`
}

// Link is the underlay: the port carrying IKE and ESP, and the device
// the mesh is carried on.
type Link struct {
	Port      uint16     `yaml:"port" json:"port" toml:"port"`
	Endpoints []Endpoint `yaml:"endpoints" json:"endpoints" toml:"endpoints"`
	// Listen answers peers that dial this node. Off by default because a leaf
	// never needs it: it has no reachable address to be dialed at, and an open
	// listener is the one surface an unauthenticated peer can reach. A full
	// mesh needs it on, since every node both dials and answers.
	Listen bool `yaml:"listen,omitempty" json:"listen,omitempty" toml:"listen,omitempty"`
	// TUN names an existing device to attach to, or the device to create when
	// it does not exist.
	// empty takes the platform's default, ranet3 on linux and the next free utun on darwin
	// ranet3 is only ever created
	// a second instance on one host names its own
	// darwin creates nothing but utun and utun followed by a unit number
	// the daemon refuses any other name there when it starts
	TUN string `yaml:"tun,omitempty" json:"tun,omitempty" toml:"tun,omitempty"`
	// MTU is the largest inner packet a session carries, the plaintext ESP seals
	// the device runs at it less the longest cap.segment steer list, which a steered packet carries inside the tunnel
	// zero takes netstack.DefaultMTU, see SessionMTU
	MTU uint16 `yaml:"mtu,omitempty" json:"mtu,omitempty" toml:"mtu,omitempty"`
}

// SessionMTU is link.mtu in force, netstack.DefaultMTU where the file leaves it out
// two files are compared through it, since an omitted mtu and one written as the default describe one node
func (l Link) SessionMTU() int {
	if l.MTU == 0 {
		return netstack.DefaultMTU
	}
	return int(l.MTU)
}

// Endpoint is one local socket identity. Address selection is global: the
// transport binds Link.Port for every family the platform gives it, one
// dual-stack socket on darwin and one per family on linux, and the kernel
// selects the source address by route. Each entry has to match an endpoint the
// trust document gives this node, since a peer dials that entry.
type Endpoint struct {
	Serial string `yaml:"serial" json:"serial" toml:"serial"`
	Family string `yaml:"family" json:"family" toml:"family"`
}

// Dial is who this node opens sessions to.
type Dial struct {
	// All dials every node the trust document names, the N-to-N
	// reconciliation ranet performs. Reach on a fleet whose other speaker
	// exports only its own directly connected routes needs it: a node learns
	// a prefix from the node originating it or not at all, so dialing a few
	// exits reaches those exits and nothing behind them. To still applies,
	// and an entry there wins for its node, which is the only way to pin a
	// serial since a generated peer names none.
	All bool `yaml:"all,omitempty" json:"all,omitempty" toml:"all,omitempty"`
	// To is each peer this node dials, a node or the one endpoint of it to dial
	// a node takes the first of its endpoints in a matching address family
	To []identity.Identity `yaml:"to,omitempty" json:"to,omitempty" toml:"to,omitempty"`
}

// Caps is everything this node does. Every member is a pointer and every one
// is absent by default. Writing a block turns its capability on, so there is no
// enabled field to forget, except cap.antispoof, a protection that runs
// wherever overlay is written and whose block only exempts.
type Caps struct {
	Route   *babel.Routes  `yaml:"route,omitempty" json:"route,omitempty" toml:"route,omitempty"`
	Transit *babel.Transit `yaml:"transit,omitempty" json:"transit,omitempty" toml:"transit,omitempty"`
	Babel   *babel.Config  `yaml:"babel,omitempty" json:"babel,omitempty" toml:"babel,omitempty"`
	Table   *kernel.Table  `yaml:"table,omitempty" json:"table,omitempty" toml:"table,omitempty"`
	Segment *srv6.Segments `yaml:"segment,omitempty" json:"segment,omitempty" toml:"segment,omitempty"`
	Crypto  *ike.Crypto    `yaml:"crypto,omitempty" json:"crypto,omitempty" toml:"crypto,omitempty"`
	Egress  *egress.Egress `yaml:"egress,omitempty" json:"egress,omitempty" toml:"egress,omitempty"`
	// Antispoof exempts prefixes of the overlay from the filter that drops what arrives from outside the mesh carrying a mesh source
	Antispoof *egress.Antispoof `yaml:"antispoof,omitempty" json:"antispoof,omitempty" toml:"antispoof,omitempty"`
	// Exit makes the mesh's default this host's default, which the reconciler of cap.table runs, see ReconcilerTable
	Exit *kernel.ExitMode `yaml:"exit,omitempty" json:"exit,omitempty" toml:"exit,omitempty"`
}

// ReconcilerTable is cap.table with cap.exit's mode, which the reconciler runs together, nil without cap.table
// in mode 3 it carries the outer source cap.exit via's path is sent from, which the reconciler resolves each SID from
func (c *Config) ReconcilerTable() *kernel.Table {
	if c.Cap.Table == nil {
		return nil
	}
	source, _ := c.ExitPath()
	table := c.Cap.Table.WithMode(c.Cap.Exit).WithPathSource(source)
	return &table
}

// Routes, Babel, Segments and Crypto are the capability in force, which for an
// absent block is its zero value: the defaults every one of them documents.
// They exist so that a caller reads one shape whether or not the block was
// written, rather than checking a pointer at each use.
func (c *Config) Routes() babel.Routes {
	if c.Cap.Route == nil {
		return babel.Routes{}
	}
	return *c.Cap.Route
}

func (c *Config) Babel() babel.Config {
	if c.Cap.Babel == nil {
		return babel.Config{}
	}
	return *c.Cap.Babel
}

func (c *Config) Segments() srv6.Segments {
	if c.Cap.Segment == nil {
		return srv6.Segments{}
	}
	return *c.Cap.Segment
}

// SegmentTables is cap.segment's two tables as the dataplane runs them, every
// local SID admitting only an outer source in the overlay, and the
// steering table holding cap.exit via's path as its default
func (c *Config) SegmentTables() (*srv6.LocalTable, *srv6.SteerTable, error) {
	local, steering, err := c.Segments().Tables(c.Overlay)
	if err != nil {
		return nil, nil, err
	}
	if source, path := c.ExitPath(); len(path) != 0 {
		if steering, err = steering.WithDefault(source, path); err != nil {
			return nil, nil, err
		}
	}
	return local, steering, nil
}

// ExitPath is cap.exit via as the dataplane steers along it, nil in modes off
// and 2, with the outer source it is sent from: cap.segment source where
// written, else the first IPv6 address cap.table writes inside the overlay,
// and invalid where neither gives one
func (c *Config) ExitPath() (netip.Addr, []netip.Addr) {
	if c.Cap.Exit == nil || len(c.Cap.Exit.Via) == 0 {
		return netip.Addr{}, nil
	}
	path := make([]netip.Addr, 0, len(c.Cap.Exit.Via))
	for _, sid := range c.Cap.Exit.Via {
		path = append(path, sid.Addr)
	}
	if source := c.Segments().Source; source.IsValid() {
		return source.Addr, path
	}
	if c.Cap.Table != nil {
		for _, address := range c.Cap.Table.Addresses {
			if address.Addr().Is6() && !address.Addr().Is4In6() && c.inOverlay(address.Addr()) {
				return address.Addr(), path
			}
		}
	}
	return netip.Addr{}, path
}

// inOverlay reports an address inside the overlay
func (c *Config) inOverlay(address netip.Addr) bool {
	return slices.ContainsFunc(c.Overlay, func(prefix schema.Prefix) bool { return prefix.Contains(address) })
}

// ExitReason names why this node is an exit under overlay, as the reconciler,
// a reload and the refusal of cap.exit all read it
func (c *Config) ExitReason(overlay []schema.Prefix) schema.Exit {
	return schema.ExitOf(c.Advertised(), c.Routes().Announced(), len(c.Segments().Egress()) > 0, overlay)
}

// Advertised is the prefixes cap.egress advertises, nil without the block
func (c *Config) Advertised() []netip.Prefix {
	if c.Cap.Egress == nil {
		return nil
	}
	out := make([]netip.Prefix, len(c.Cap.Egress.Advertise))
	for i, prefix := range c.Cap.Egress.Advertise {
		out[i] = prefix.Prefix
	}
	return out
}

// Border is the antispoof filter's configuration, overlay with cap.antispoof's
// exemptions and what OwnPrefixes gives, nil where overlay is not written. An
// overlay written empty is one the filter refuses, so it is handed on to be
// refused.
func (c *Config) Border() *egress.Border {
	if c.Overlay == nil {
		return nil
	}
	border := egress.Border{Overlay: c.Overlay}
	if c.Cap.Antispoof != nil {
		border.Antispoof = *c.Cap.Antispoof
	}
	border.Own, border.Addresses = c.OwnPrefixes()
	return &border
}

// OwnPrefixes gives the prefixes an exemption takes as this node's own: ranges, each
// prefix cap.route announces inside the overlay that is not one address, which
// an exemption inside admits, and addresses, each address of this node's as a
// host prefix, a host prefix cap.route announces or an address cap.table
// assigns, which the filter drops inside any exemption
func (c *Config) OwnPrefixes() (ranges, addresses []netip.Prefix) {
	announced := c.Routes().Announced()
	for _, prefix := range announced {
		switch prefix = prefix.Masked(); {
		case prefix.IsSingleIP():
			addresses = append(addresses, prefix)
		case schema.InsideOverlay(prefix, c.Overlay):
			ranges = append(ranges, prefix)
		}
	}
	if c.Cap.Table != nil {
		for _, prefix := range c.Cap.Table.Assigned(announced) {
			addresses = append(addresses, netip.PrefixFrom(prefix.Addr(), prefix.Addr().BitLen()))
		}
	}
	return ranges, addresses
}

func (c *Config) Crypto() ike.Crypto {
	if c.Cap.Crypto == nil {
		return ike.Crypto{}
	}
	return *c.Cap.Crypto
}

// Transits is whether this node relays the routes it learns
func (c *Config) Transits() bool { return c.Cap.Transit != nil }

// Egress has no zero value worth returning: an absent block means this node
// carries no traffic out of the mesh, and an empty capability is refused rather
// than taken as that. A caller asks for the pointer instead.
func (c *Config) Egress() *egress.Egress { return c.Cap.Egress }

// Load reads a configuration, picking the decoder by file extension: .toml
// goes to the TOML decoder and .yaml, .yml and .json to the YAML one. A .json
// file is read as YAML, and JSON that YAML reads otherwise loads differently
// or not at all. The YAML decoder refuses a \/ escape, the surrogate pair
// escape of a character outside the BMP, a raw DEL and a key written twice,
// among others, and reads a raw NEL, LS or PS in a string as a line break. An
// extension neither knows is refused by name rather than sniffed, because a
// file whose contents and whose name disagree is one somebody is going to
// have to debug.
//
// Both decoders run strict, so an unknown key is an error under either: a
// typo'd capability that silently does nothing is the worst failure a
// configuration file has.
func Load(path string) (*Config, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	var c Config
	switch extension := strings.ToLower(filepath.Ext(path)); extension {
	case ".toml":
		err = decodeTOML(body, &c)
	case ".yaml", ".yml", ".json":
		err = decodeYAML(body, &c)
	default:
		return nil, fmt.Errorf("config: %s: a configuration is written as .toml, .yaml, .yml or .json, and %q is none of those", path, extension)
	}
	if err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func decodeTOML(body []byte, c *Config) error {
	var written map[string]any
	if _, err := toml.Decode(string(body), &written); err != nil {
		return err
	}
	metadata, err := toml.Decode(string(body), c)
	if err != nil {
		return err
	}
	// The TOML decoder has no KnownFields of its own: it records what it did
	// not consume and leaves the judgment to the caller. Reported one key at a
	// time and in the order the document wrote them, so the message names a
	// line an operator can find.
	if undecoded := metadata.Undecoded(); len(undecoded) > 0 {
		return fmt.Errorf("unknown field %q", undecoded[0].String())
	}
	return exactKeys(written, reflect.TypeFor[Config](), "")
}

// exactKeys refuses a key whose spelling differs from the field's tag in case
// alone. The TOML decoder falls back to a case-insensitive match when the
// exact spelling misses, and records the key as decoded, so Undecoded says
// nothing about it: "ANNOUNCE" loads as "announce", and a document carrying
// both spellings takes whichever one a map walk reached last, which is a
// different node on different runs of the same file. The other decoder refuses
// it outright, and a typo that silently does something is worse than one that
// silently does nothing.
func exactKeys(written map[string]any, structure reflect.Type, path string) error {
	for _, key := range slices.Sorted(maps.Keys(written)) {
		field, exact := tomlField(structure, key)
		if !exact {
			// Undecoded has already reported a key matching no field at all,
			// so what is left here differs in case alone.
			return fmt.Errorf("unknown field %q", path+key)
		}
		if err := exactKeysIn(written[key], field.Type, path+key+"."); err != nil {
			return err
		}
	}
	return nil
}

// exactKeysIn walks whatever stands under one key. A type that decodes itself
// is left to its own walk, which refuses an unknown key the same way.
func exactKeysIn(written any, field reflect.Type, path string) error {
	if decodesItselfTOML(field) {
		return nil
	}
	if field.Kind() == reflect.Pointer {
		field = field.Elem()
	}
	// the decoder leaves a map empty, with no error and nothing undecoded, for a value that is not a table
	if _, table := written.(map[string]any); field.Kind() == reflect.Map && !table {
		return fmt.Errorf("%q takes a table", strings.TrimSuffix(path, "."))
	}
	switch value := written.(type) {
	case map[string]any:
		switch field.Kind() {
		case reflect.Struct:
			return exactKeys(value, field, path)
		case reflect.Map:
			// each entry is walked as a block of its own, under the key as the decoder names one
			for _, key := range slices.Sorted(maps.Keys(value)) {
				if err := exactKeysIn(value[key], field.Elem(), path+toml.Key{key}.String()+"."); err != nil {
					return err
				}
			}
		}
	case []map[string]any:
		// An array of tables, which is how the decoder hands over
		// [[cap.segment.steer]].
		if field.Kind() != reflect.Slice {
			return nil
		}
		for _, element := range value {
			if err := exactKeysIn(element, field.Elem(), path); err != nil {
				return err
			}
		}
	case []any:
		if field.Kind() != reflect.Slice {
			return nil
		}
		for _, element := range value {
			if err := exactKeysIn(element, field.Elem(), path); err != nil {
				return err
			}
		}
	}
	return nil
}

// tomlField finds the field a written key names and reports whether the
// spelling matched the tag exactly.
func tomlField(structure reflect.Type, key string) (reflect.StructField, bool) {
	if structure.Kind() != reflect.Struct {
		return reflect.StructField{}, false
	}
	for field := range structure.Fields() {
		if !field.IsExported() {
			continue
		}
		name, _, _ := strings.Cut(field.Tag.Get("toml"), ",")
		if name == "" {
			name = field.Name
		}
		if name == key {
			return field, true
		}
	}
	return reflect.StructField{}, false
}

// decodesItselfTOML reports a type that reads its own toml, by either of the
// two interfaces that decoder consults. Each of them refuses an unknown key on
// its own, so the walk above stops there.
func decodesItselfTOML(t reflect.Type) bool {
	if t.Kind() != reflect.Pointer {
		t = reflect.PointerTo(t)
	}
	return t.Implements(reflect.TypeFor[toml.Unmarshaler]()) ||
		t.Implements(reflect.TypeFor[encoding.TextUnmarshaler]())
}

func decodeYAML(body []byte, c *Config) error {
	decoder := yaml.NewDecoder(strings.NewReader(string(body)))
	decoder.KnownFields(true)
	if err := decoder.Decode(c); err != nil {
		return err
	}
	// KnownFields catches a stray key inside the document, while this catches a
	// second document after it. A file assembled by concatenation, or half
	// pasted below a stray "---", otherwise starts on the first half alone and
	// validates cleanly, so a node comes up with the listener off or the wrong
	// peer set and nothing says so. registry.Load refuses the identical case
	// in JSON.
	//
	// Read to the end rather than one document further. A file whose first
	// half ends in a separator decodes to an empty document between the two,
	// and stopping at the first empty one took the second half with it: cat of
	// two configurations, which is the case this refuses, is exactly where
	// that separator comes from.
	for {
		var trailing yaml.Node
		switch err := decoder.Decode(&trailing); {
		case errors.Is(err, io.EOF):
			return blocksWritten(body, c)
		case err != nil:
			return err
		case !emptyDocument(&trailing):
			return errors.New("a second document follows the first")
		}
	}
}

// blocksWritten turns a capability block an operator wrote into the capability
// it names, whatever stands under it. yaml.v3 leaves a pointer field nil for a
// key whose value is empty, so "table:" with its fields still commented out
// decodes to the same nil as no cap.table at all, while "[cap.table]" under
// the other decoder turns the reconciler on. Presence is therefore read off
// the document rather than off the value the decode produced, and a key that
// is present is present under either decoder.
//
// The strict decode above has already refused an unknown key and a value of
// the wrong shape, so this pass has only to find the keys and fill in the
// pointers an empty one left nil, to refuse a number the decode changed on its
// way into an integer field, and to refuse a merge key and a null list entry.
func blocksWritten(body []byte, c *Config) error {
	var document yaml.Node
	if err := yaml.Unmarshal(body, &document); err != nil {
		return err
	}
	if document.Kind != yaml.DocumentNode || len(document.Content) != 1 {
		return nil
	}
	return fillBlocks(document.Content[0], reflect.ValueOf(c).Elem(), "")
}

// fillBlocks walks the document beside the value it decoded to and allocates
// every block a written key left nil, at whatever depth. It descends by the
// yaml key rather than by field order, into every entry of a map as well, and
// stops at a type that reads its own yaml, since such a type spells a scalar
// and carries no block under it. It hands every other scalar to wholeNumber.
// path is the key node stands under, which a refusal names.
func fillBlocks(node *yaml.Node, target reflect.Value, path string) error {
	node = schema.Followed(node)
	if decodesItself(target.Type()) {
		return nil
	}
	if target.Kind() == reflect.Pointer {
		// A pointer to a scalar is left alone. An explicit null there asks for
		// the default rather than for a zero, and TOML cannot write a key with
		// no value at all, so there is no second spelling to agree with.
		if target.Type().Elem().Kind() != reflect.Struct {
			return wholeNumber(node, target.Type().Elem())
		}
		if target.IsNil() {
			target.Set(reflect.New(target.Type().Elem()))
		}
		target = target.Elem()
	}
	switch {
	case target.Kind() == reflect.Struct && node.Kind == yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			key := node.Content[i]
			if err := refuseMerge(key); err != nil {
				return err
			}
			// the key is read as the decoder reads it, through an alias and from a !!binary spelling
			var name string
			if err := key.Decode(&name); err != nil {
				return err
			}
			if field := fieldByKey(target, name); field.IsValid() {
				if err := fillBlocks(node.Content[i+1], field, keyPath(path, name)); err != nil {
					return err
				}
			}
		}
	case target.Kind() == reflect.Map && node.Kind == yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			if err := refuseMerge(node.Content[i]); err != nil {
				return err
			}
			// an entry is walked at a value of its own type for what it refuses
			// a merge key inside it or an amount not written as a whole number
			if err := fillBlocks(node.Content[i+1], reflect.New(target.Type().Elem()).Elem(), keyPath(path, schema.Followed(node.Content[i]).Value)); err != nil {
				return err
			}
		}
	case target.Kind() == reflect.Slice && node.Kind == yaml.SequenceNode:
		for i, item := range node.Content {
			// yaml.v3 drops a null item from the list, which encoding/json, the wire form's decoder, reads as an entry
			if schema.Followed(item).ShortTag() == "!!null" {
				return fmt.Errorf("line %d: a %s entry is null", item.Line, path)
			}
			if i < target.Len() {
				if err := fillBlocks(item, target.Index(i), path); err != nil {
					return err
				}
			}
		}
	default:
		return wholeNumber(node, target.Type())
	}
	return nil
}

// refuseMerge refuses a merge key rather than following it, as Announce refuses one
// following it would copy the decoder's precedence between a merged key and a written one
// and toml and json have no spelling for it
func refuseMerge(key *yaml.Node) error {
	if key.Tag == "!!merge" {
		return fmt.Errorf("line %d: a merge key is refused, since toml and json have no spelling for one", key.Line)
	}
	return nil
}

// wholeNumber refuses a number the decode changed on its way into an integer field
// 13000.5, 1.3e4 and 13000.0 became 13000 and -0 became 0, and encoding/json refuses all four
// the wire form of this schema is read by encoding/json, so a file and the control plane would disagree about the number
// every integer field the walk reaches is unsigned, since a signed one is a duration and reads its own text
func wholeNumber(node *yaml.Node, field reflect.Type) error {
	if node.Kind != yaml.ScalarNode {
		return nil
	}
	switch field.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if strings.HasPrefix(node.Value, "-") {
			return fmt.Errorf("line %d: %s has a minus sign, and this field is never negative", node.Line, node.Value)
		}
	default:
		return nil
	}
	if node.Tag == "!!float" {
		return fmt.Errorf("line %d: %s is written as a float, and this field takes a whole number in digits", node.Line, node.Value)
	}
	return nil
}

// fieldByKey finds the field a written key names, under the same tag the
// decoder read it by. An absent field answers the zero Value, which happens
// for a key the decode consumed some other way.
func fieldByKey(target reflect.Value, key string) reflect.Value {
	structure := target.Type()
	for i := range structure.NumField() {
		if field := structure.Field(i); field.IsExported() && yamlKey(field) == key {
			return target.Field(i)
		}
	}
	return reflect.Value{}
}

// yamlKey is the key a yaml file writes a field under
// the tag's name, or the lowercased field name where the tag has none
func yamlKey(field reflect.StructField) string {
	name, _, _ := strings.Cut(field.Tag.Get("yaml"), ",")
	if name == "" {
		name = strings.ToLower(field.Name)
	}
	return name
}

func keyPath(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

// decodesItself reports a type that reads its own yaml. Everything in
// package schema does, and each of them spells one scalar, so the walk above
// stops rather than taking the fields behind the spelling for keys.
func decodesItself(t reflect.Type) bool {
	if t.Kind() != reflect.Pointer {
		t = reflect.PointerTo(t)
	}
	return t.Implements(reflect.TypeFor[yaml.Unmarshaler]())
}

// emptyDocument reports a document carrying nothing, which a file ending in a
// separator decodes to: yaml.v3 answers that as a document wrapping a null
// scalar rather than as io.EOF. A file assembled by concatenation ends that
// way, and refusing it refuses a configuration that is whole.
func emptyDocument(node *yaml.Node) bool {
	if node.Kind != yaml.DocumentNode || len(node.Content) != 1 {
		return node.Kind == 0
	}
	child := node.Content[0]
	return child.Kind == yaml.ScalarNode && child.Tag == "!!null"
}

// Validate checks what this node says about itself, then asks each capability
// to check itself, then makes the checks that span two capabilities. The split
// is deliberate: what a policy rule may say belongs with the reconciler that
// installs it, and repeating it here is how the two come to disagree.
func (c *Config) Validate() error {
	if path, written, found := notText(reflect.ValueOf(c).Elem(), ""); found {
		return fmt.Errorf("config: %s %q is not valid UTF-8, which a toml or a json file cannot hold", path, written)
	}
	if err := c.validateNode(); err != nil {
		return err
	}
	// Returned as the capability wrote it. Each message already names the
	// package that refused and the block an operator can find in their own
	// file, and wrapping it in a second "config:" would say neither twice.
	for _, capability := range []interface{ Validate() error }{
		c.Routes(), c.Babel(), c.Crypto(), c.Segments(),
	} {
		if err := capability.Validate(); err != nil {
			return err
		}
	}
	// Table and Egress are asked only where the block was written: an absent
	// table writes no routes and an absent egress carries no traffic out of the
	// mesh, and an empty egress block is a mistake it refuses by name.
	if c.Cap.Table != nil {
		if err := c.Cap.Table.Validate(); err != nil {
			return err
		}
	}
	if c.Cap.Egress != nil {
		if err := c.Cap.Egress.Validate(); err != nil {
			return err
		}
	}
	if c.Cap.Exit != nil {
		if err := c.Cap.Exit.Validate(); err != nil {
			return err
		}
	}
	return c.validateAcrossCapabilities()
}

// notText finds the first string under value that is not valid UTF-8 and
// names it by the path a file writes it under. Every format a configuration is
// written in is text: toml refuses such a string, json rewrites it and yaml
// carries it only as binary, so a configuration holding one, built in Go or
// read from yaml, renders to a file that does not load or loads as another
// node. The walk takes in every block, since a capability's names are written
// in the same file.
func notText(value reflect.Value, path string) (string, string, bool) {
	switch value.Kind() {
	case reflect.String:
		if !utf8.ValidString(value.String()) {
			return path, value.String(), true
		}
	case reflect.Pointer:
		if !value.IsNil() {
			return notText(value.Elem(), path)
		}
	case reflect.Slice:
		for i := range value.Len() {
			if found, written, ok := notText(value.Index(i), path); ok {
				return found, written, true
			}
		}
	case reflect.Map:
		// in key order, which names the same entry every time a file holds two strings that are not text
		keys := value.MapKeys()
		slices.SortFunc(keys, func(a, b reflect.Value) int { return strings.Compare(a.String(), b.String()) })
		for _, key := range keys {
			if found, written, ok := notText(key, path); ok {
				return found, written, true
			}
			if found, written, ok := notText(value.MapIndex(key), path+"."+strconv.Quote(key.String())); ok {
				return found, written, true
			}
		}
	case reflect.Struct:
		for i := range value.NumField() {
			field := value.Type().Field(i)
			if !field.IsExported() {
				continue
			}
			if found, written, ok := notText(value.Field(i), strings.TrimPrefix(path+"."+yamlKey(field), ".")); ok {
				return found, written, true
			}
		}
	}
	return "", "", false
}

func (c *Config) validateNode() error {
	switch {
	case c.Node.IsZero():
		return errors.New("config: node is required")
	case c.Node.Node() != c.Node:
		return fmt.Errorf("config: node %s names an endpoint rather than the node, whose endpoints link.endpoints lists", c.Node)
	case c.Link.Port == 0:
		return errors.New("config: link.port is required")
	case c.Link.Port == 500:
		// Every IKE datagram here carries the non-ESP marker so IKE and ESP
		// can share one socket, and RFC 7296 section 2.23 says "UDP
		// encapsulation MUST NOT be done on port 500". A peer on 500 would
		// read the marker as the start of a header.
		return errors.New("config: link.port 500 cannot carry UDP-encapsulated IKE, use 4500 or a private port")
	case len(c.Link.Endpoints) == 0:
		return errors.New("config: at least one link.endpoints entry is required")
	case c.Auth.Key == "":
		return errors.New("config: auth.key is required")
	case c.Auth.Trust == "":
		return errors.New("config: auth.trust is required")
	case len(c.Dial.To) == 0 && !c.Link.Listen && !c.Dial.All:
		// A listener needs no peers: it answers whoever the trust document
		// knows. Without one, a node with neither would do nothing at all.
		return errors.New("config: at least one dial.to entry is required unless link.listen or dial.all is set")
	}
	// the most one ESP-in-UDP datagram carries over IPv4, whose 16 bit total length counts its own 20 byte header
	largest := esp.Inner(math.MaxUint16, 20)
	if mtu := c.Link.SessionMTU(); mtu < srv6.MinimumIPv6MTU || mtu > largest {
		return fmt.Errorf("config: link.mtu %d is outside %d to %d, the least IPv6 requires of every link to the most one ESP-in-UDP datagram carries over IPv4", mtu, srv6.MinimumIPv6MTU, largest)
	}
	serials := make(map[string]struct{}, len(c.Link.Endpoints))
	for _, endpoint := range c.Link.Endpoints {
		if endpoint.Serial == "" || (endpoint.Family != "ip4" && endpoint.Family != "ip6") {
			return errors.New("config: link.endpoints entries require serial and family (ip4 or ip6)")
		}
		if _, exists := serials[endpoint.Serial]; exists {
			return fmt.Errorf("config: duplicate link.endpoints serial %q", endpoint.Serial)
		}
		serials[endpoint.Serial] = struct{}{}
	}
	peers := make(map[identity.Identity]struct{}, len(c.Dial.To))
	for _, peer := range c.Dial.To {
		if peer.IsZero() {
			return errors.New("config: a dial.to entry names nobody")
		}
		if _, exists := peers[peer]; exists {
			return fmt.Errorf("config: duplicate dial.to entry %s", peer)
		}
		peers[peer] = struct{}{}
	}
	if len(c.Auth.Aliases.Local) > 0 {
		inFamily := make(map[string]int, 2)
		for _, endpoint := range c.Link.Endpoints {
			inFamily[endpoint.Family]++
		}
		for _, family := range []string{"ip4", "ip6"} {
			if inFamily[family] > 1 {
				return fmt.Errorf("config: auth.aliases.local is refused on a node whose link.endpoints holds %d endpoints of the %s family, since a peer could not tell them apart by an alias", inFamily[family], family)
			}
		}
	}
	return c.Auth.Aliases.Validate(c.Node)
}

// validateAcrossCapabilities is the part no capability can check alone,
// because each half is in a different block.
func (c *Config) validateAcrossCapabilities() error {
	// this node is never its own neighbor, so an amount for it charges nobody
	if slices.Contains(c.Babel().Cost.Extra.Nodes(), c.Node) {
		return fmt.Errorf("config: cap.babel cost.extra node %s is this node", c.Node)
	}
	egressSegments := c.Segments().Egress()
	if c.Cap.Egress != nil {
		if err := c.Cap.Egress.Serves(len(egressSegments) > 0); err != nil {
			return err
		}
	}
	if err := c.validateEgressSegments(egressSegments); err != nil {
		return err
	}
	if err := c.validateBorder(); err != nil {
		return err
	}
	if err := c.validateExit(); err != nil {
		return err
	}
	if err := c.validateSteerTo(); err != nil {
		return err
	}
	if err := c.validateSteeredMTU(); err != nil {
		return err
	}
	// A SID this node also carries as an ordinary address would go dark: the
	// inbound seam acts on a packet by its destination before the tun sees it,
	// so every packet to that address would be refused as carrying no routing
	// header, with nothing but a rate-limited warning to say why. On linux the
	// two coexist because a SID is a route rather than an address. Here they
	// cannot.
	if c.Cap.Table == nil || c.Cap.Segment == nil {
		return nil
	}
	carried := make(map[netip.Addr]bool)
	for _, prefix := range c.Cap.Table.Assigned(c.Routes().Announced()) {
		carried[prefix.Addr()] = true
	}
	for _, segment := range c.Cap.Segment.Local {
		if carried[segment.SID.Addr] {
			return fmt.Errorf("config: cap.segment local %s is an address cap.table assigns to this node's own device, so every packet to it would be taken as a segment", segment.SID)
		}
	}
	return nil
}

func (c *Config) validateEgressSegments(segments []srv6.Segment) error {
	if len(segments) == 0 {
		return nil
	}
	if c.Cap.Egress == nil {
		return fmt.Errorf("config: cap.segment local %s delivers to egress and cap.egress is absent, so nothing translates what leaves the mesh tun", segments[0].SID)
	}
	for _, segment := range segments {
		own := netip.PrefixFrom(segment.SID.Addr, segment.SID.BitLen())
		if slices.Contains(c.Routes().Announced(), own) {
			return fmt.Errorf("config: cap.route announces %s, the egress segment's own route, which would announce it whether or not the segment is ready", own)
		}
	}
	return nil
}

// validateBorder asks the antispoof filter's configuration to check itself
// where overlay is written, then refuses what the overlay, the filter and the
// local segments cannot both mean: an exemption with no overlay to exempt
// from or a block exempting nothing, a shared exemption overlapping a range
// inside the overlay that cap.route announces, which would pass the sources
// of the hosts behind this node from the uplink too, a segment no overlay
// bounds, a none class
// with no overlay to keep its hosts' addresses in the entry chain's sets, an
// overlay admitting no outer source, which is always IPv6, an allow entry
// outside the overlay, which admits an inner source alone, with no IPv6 entry
// inside it to admit the outer source, and an advertised prefix whose own
// hosts the filter would drop. The exit default overlaps everything and is
// left out, since nothing behind an exit is numbered from the mesh.
func (c *Config) validateBorder() error {
	local := c.Segments().Local
	border := c.Border()
	if border == nil {
		if c.Cap.Antispoof != nil {
			return errors.New("config: cap.antispoof is written and overlay is absent, so no filter runs for it to exempt from: write overlay with the prefixes the mesh numbers its nodes from")
		}
		if len(local) != 0 {
			return fmt.Errorf("config: cap.segment local %s is written and overlay is absent, so nothing bounds the outer sources it acts on: write overlay with the prefixes the mesh numbers its nodes from", local[0].SID)
		}
		// a learned route reads the same for a node's own address as for a LAN it advertises, so only the overlay tells them apart
		if c.Cap.Egress != nil {
			for _, class := range c.Cap.Egress.Translate {
				if class.To.None {
					return fmt.Errorf("config: cap.egress translate class %s is none and overlay is absent, so the entry chain cannot tell the mesh's node addresses from the LANs other nodes advertise, and would refuse every inbound connection to that class's hosts: write overlay with the prefixes the mesh numbers its nodes from", class.From)
				}
			}
		}
		return nil
	}
	if a := c.Cap.Antispoof; a != nil && len(a.Exempt) == 0 && len(a.Interface) == 0 {
		return errors.New("config: cap.antispoof exempts nothing, and the filter runs wherever overlay is written: write exempt or cap.antispoof.interface, or leave the block out")
	}
	if err := border.Validate(); err != nil {
		return err
	}
	for _, exempt := range border.Antispoof.Exempt {
		if at := slices.IndexFunc(border.Own, exempt.Overlaps); at >= 0 {
			return fmt.Errorf("config: cap.antispoof exempt %s overlaps %s, which cap.route announces, and the shared list passes its sources from every interface outside the mesh, the uplink among them: write it under cap.antispoof.interface.<name>.exempt for the interface its hosts are on", exempt, border.Own[at])
		}
	}
	if len(local) != 0 && !slices.ContainsFunc(border.Overlay, func(prefix schema.Prefix) bool { return prefix.Addr().Is6() }) {
		return fmt.Errorf("config: overlay holds no IPv6 prefix, so cap.segment local %s would refuse every packet, whose outer source is always IPv6", local[0].SID)
	}
	for _, segment := range c.Segments().Egress() {
		inside := func(allowed schema.Prefix) bool { return schema.InsideOverlay(allowed.Prefix, border.Overlay) }
		outside := slices.IndexFunc(segment.Allow, func(allowed schema.Prefix) bool { return !inside(allowed) })
		ipv6Inside := slices.ContainsFunc(segment.Allow, func(allowed schema.Prefix) bool { return allowed.Addr().Is6() && inside(allowed) })
		if outside >= 0 && !ipv6Inside {
			return fmt.Errorf("config: cap.segment local %s allow %s lies outside overlay, which admits it as an inner source alone, and no IPv6 entry of the list lies inside the overlay to admit an outer source, which is always IPv6", segment.SID, segment.Allow[outside])
		}
	}
	if c.Cap.Egress == nil {
		return nil
	}
	for _, advertised := range c.Cap.Egress.Advertise {
		if advertised.Bits() == 0 {
			continue
		}
		for _, overlay := range border.Overlay {
			if advertised.Overlaps(overlay.Prefix) {
				return fmt.Errorf("config: cap.egress advertise %s overlaps overlay %s, so the hosts behind this node arrive on a link outside the mesh with a mesh source and the antispoof filter drops them", advertised, overlay)
			}
		}
	}
	return nil
}

// validateExit refuses cap.exit without cap.table, whose reconciler makes the
// mode, with rules on linux and routes on darwin. It refuses it without
// overlay: linux's rules send the overlay to the mesh whatever the mode and keep
// it out of the selectors that send a source by the uplink, and darwin judges by
// it which families the mode covers. It refuses it on an exit, whose own
// traffic and egress leave by its own uplink, and refuses a lan entry
// overlapping the overlay and one schema.CapturesTheMachine counts.
func (c *Config) validateExit() error {
	if c.Cap.Exit == nil {
		return nil
	}
	switch exit := c.ExitReason(c.Overlay); {
	case c.Cap.Table == nil:
		return errors.New("config: cap.exit is written and cap.table is absent, so no reconciler makes the mode")
	case len(c.Overlay) == 0:
		return errors.New("config: cap.exit is written and overlay is absent, so the mode cannot tell the mesh's addresses from the uplink's: write overlay with the prefixes the mesh numbers its nodes from")
	case exit.Advertised.IsValid():
		return exitRefused(fmt.Sprintf("cap.egress advertises %s", exit.Advertised))
	case exit.Announced.IsValid():
		return exitRefused(fmt.Sprintf("cap.route announces %s, which counts as a default", exit.Announced))
	case exit.EgressSegment:
		return exitRefused(fmt.Sprintf("cap.segment local %s delivers to egress", c.Segments().Egress()[0].SID))
	}
	overlay := c.Overlay
	if err := schema.CheckPrefixes("config: cap.exit lan", c.Cap.Exit.LAN, func(prefix netip.Prefix) string {
		if at := slices.IndexFunc(overlay, func(entry schema.Prefix) bool { return entry.Overlaps(prefix) }); at >= 0 {
			return fmt.Sprintf("overlaps overlay %s, whose destinations the mesh carries whatever the LAN holds", overlay[at])
		}
		if schema.CapturesTheMachine(prefix, overlay) {
			return "counts as capturing the machine, so it would let the host's traffic leave by the uplink as a default does"
		}
		return ""
	}); err != nil {
		return err
	}
	return c.validateVia()
}

// validateVia refuses a cap.exit via whose packets no SID admits, since RFC
// 8754 section 5.1 has a SID drop an outer source from outside the domain, and
// a path that starts or ends at a segment of this node's own
func (c *Config) validateVia() error {
	via := c.Cap.Exit.Via
	if len(via) == 0 {
		return nil
	}
	if !slices.ContainsFunc(c.Overlay, func(prefix schema.Prefix) bool { return prefix.Addr().Is6() }) {
		return errors.New("config: cap.exit via is written and overlay holds no IPv6 prefix, so every segment refuses the path's outer source, which is always IPv6")
	}
	// the mesh routes no packet of this node's to its own first segment, and its own last one would make it an exit
	for _, segment := range c.Segments().Local {
		if segment.SID.Addr == via[0].Addr || segment.SID.Addr == via[len(via)-1].Addr {
			return fmt.Errorf("config: cap.exit via starts or ends at %s, a segment of this node's own cap.segment local, which acts only on a packet another node sends it", segment.SID)
		}
	}
	switch source, _ := c.ExitPath(); {
	case !source.IsValid():
		return errors.New("config: cap.exit via is written and neither cap.segment source nor an IPv6 cap.table address inside overlay gives the path an outer source: write cap.segment source")
	case !c.inOverlay(source):
		return fmt.Errorf("config: cap.segment source %s lies outside overlay, so every segment of cap.exit via refuses the path's packets by their outer source", source)
	}
	return nil
}

func exitRefused(because string) error {
	return fmt.Errorf("config: cap.exit sends this node's own traffic out through another exit, and this node is an exit (%s), whose own traffic and whose egress leave by its own uplink: remove cap.exit, or stop offering the exit", because)
}

// validateSteerTo refuses a cap.segment steer whose to counts as a default
// under the overlay, the one predicate every other reader of a
// default uses: steering the internet is cap.exit via's
func (c *Config) validateSteerTo() error {
	for _, entry := range c.Segments().Steer {
		if entry.To.IsValid() && schema.CapturesTheMachine(entry.To.Prefix, c.Overlay) {
			return fmt.Errorf("config: cap.segment steer to %s counts as a default, which is cap.exit via: write the path there", entry.To)
		}
	}
	return nil
}

// validateSteeredMTU refuses a link.mtu the longest cap.segment steer list or cap.exit via path takes under the 1280 bytes IPv6 requires of every link
// the device runs at link.mtu less that list
// the daemon makes the device with the same call, so a file this takes is one the daemon starts on
func (c *Config) validateSteeredMTU() error {
	_, steering, err := c.SegmentTables()
	if err != nil {
		return err
	}
	if _, err := steering.CheckMTU(c.Link.SessionMTU()); err != nil {
		return fmt.Errorf("config: link.mtu %d: %w", c.Link.SessionMTU(), err)
	}
	return nil
}
