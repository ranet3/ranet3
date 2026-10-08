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
// own serialization tags and validates itself; see [babel.Routes],
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
	"strings"
	"unicode/utf8"

	"github.com/BurntSushi/toml"
	"go.yaml.in/yaml/v3"

	"ranet3.com/pkgs/ranet3/esp"
	"ranet3.com/pkgs/ranet3/ike"
	"ranet3.com/pkgs/ranet3/internal/babel"
	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
	"ranet3.com/pkgs/ranet3/transport"
)

type Config struct {
	Node Node `yaml:"node" json:"node" toml:"node"`
	Auth Auth `yaml:"auth" json:"auth" toml:"auth"`
	Link Link `yaml:"link" json:"link" toml:"link"`
	Dial Dial `yaml:"dial,omitempty" json:"dial,omitzero" toml:"dial,omitempty"`
	Cap  Caps `yaml:"cap,omitempty" json:"cap,omitzero" toml:"cap,omitempty"`
}

// Node is who this is. Both halves have to match an entry in the document
// auth.trust names, since every peer checks the identity against that document.
type Node struct {
	Org  string `yaml:"org" json:"org" toml:"org"`
	Name string `yaml:"name" json:"name" toml:"name"`
}

// Auth is the key this node signs with and the document naming who it talks to.
type Auth struct {
	// Key is this node's own private key, a PKCS8 PEM Ed25519 file.
	Key string `yaml:"key" json:"key" toml:"key"`
	// Trust is the document naming who may join, a ranet registry.json today.
	Trust string `yaml:"trust" json:"trust" toml:"trust"`
}

// Link is the underlay: the one socket carrying IKE and ESP, and the device
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
	// the daemon refuses any other name there when it starts, as with Underlay
	TUN string `yaml:"tun,omitempty" json:"tun,omitempty" toml:"tun,omitempty"`
	// MTU is the largest inner packet a session carries, the plaintext ESP seals
	// the device runs at it less the longest cap.segment steer list, which a steered packet carries inside the tunnel
	// zero takes netstack.DefaultMTU, see SessionMTU
	MTU uint16 `yaml:"mtu,omitempty" json:"mtu,omitempty" toml:"mtu,omitempty"`
	// Underlay keeps the one UDP socket carrying IKE and ESP out of the reach
	// of the routes the mesh installs, which lets an exit-announced default be
	// a real default rather than one no ordinary socket can see.
	// Needed on a node whose mesh address is the only global address of its
	// family: the kernel then sources this socket from it, a "from <mesh
	// address>" rule sends it to the mesh table, and an exit-announced default
	// there routes the underlay into the tun carrying it.
	//
	// One block for both platforms because it is one idea, spelled two ways;
	// the type in transport says which field each of them reads, and
	// each is refused by name on the platform that has no meaning for it. That
	// refusal is at startup rather than at load, as cap.table's rules and VRF
	// are, so one file can carry a fleet's settings and a laptop's.
	Underlay transport.Underlay `yaml:"underlay,omitempty" json:"underlay,omitzero" toml:"underlay,omitempty"`
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
	All bool   `yaml:"all,omitempty" json:"all,omitempty" toml:"all,omitempty"`
	To  []Peer `yaml:"to,omitempty" json:"to,omitempty" toml:"to,omitempty"`
}

type Peer struct {
	// Org defaults to this node's own, which is almost always what is wanted;
	// only a cross-organization peer names its own.
	Org  string `yaml:"org,omitempty" json:"org,omitempty" toml:"org,omitempty"`
	Name string `yaml:"name" json:"name" toml:"name"`
	// Serial selects one of the peer's endpoints; empty takes the first of a
	// matching address family.
	Serial string `yaml:"serial,omitempty" json:"serial,omitempty" toml:"serial,omitempty"`
}

// Caps is everything this node does. Every member is a pointer and every one
// is absent by default: writing the block turns that capability on, so there is
// no enabled field to forget and no block that parses and does nothing.
type Caps struct {
	Route   *babel.Routes  `yaml:"route,omitempty" json:"route,omitempty" toml:"route,omitempty"`
	Babel   *babel.Config  `yaml:"babel,omitempty" json:"babel,omitempty" toml:"babel,omitempty"`
	Table   *kernel.Table  `yaml:"table,omitempty" json:"table,omitempty" toml:"table,omitempty"`
	Segment *srv6.Segments `yaml:"segment,omitempty" json:"segment,omitempty" toml:"segment,omitempty"`
	Crypto  *ike.Crypto    `yaml:"crypto,omitempty" json:"crypto,omitempty" toml:"crypto,omitempty"`
	Egress  *egress.Egress `yaml:"egress,omitempty" json:"egress,omitempty" toml:"egress,omitempty"`
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

func (c *Config) Crypto() ike.Crypto {
	if c.Cap.Crypto == nil {
		return ike.Crypto{}
	}
	return *c.Cap.Crypto
}

// Egress has no zero value worth returning: an absent block means this node
// carries nobody else's traffic, and an empty capability is refused rather
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
	c.setDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func decodeTOML(body []byte, c *Config) error {
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
	var written map[string]any
	if _, err := toml.Decode(string(body), &written); err != nil {
		return err
	}
	return exactKeys(written, reflect.TypeOf(*c), "")
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
	switch value := written.(type) {
	case map[string]any:
		if field.Kind() != reflect.Struct {
			return nil
		}
		return exactKeys(value, field, path)
	case []map[string]any:
		// An array of tables, which is how the decoder hands over
		// [[cap.table.rules]].
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
	// KnownFields catches a stray key inside the document; this catches a
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
// way into an integer field, and to refuse a merge key.
func blocksWritten(body []byte, c *Config) error {
	var document yaml.Node
	if err := yaml.Unmarshal(body, &document); err != nil {
		return err
	}
	if document.Kind != yaml.DocumentNode || len(document.Content) != 1 {
		return nil
	}
	return fillBlocks(document.Content[0], reflect.ValueOf(c).Elem())
}

// fillBlocks walks the document beside the value it decoded to and allocates
// every block a written key left nil, at whatever depth: cap.table.vrf obeys
// the same rule cap.table does. It descends by the yaml key rather than by
// field order, and stops at a type that reads its own yaml, since such a type
// spells a scalar and carries no block under it. It hands every other scalar
// to wholeNumber.
func fillBlocks(node *yaml.Node, target reflect.Value) error {
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
			// a merge key is refused rather than followed, as Announce refuses one
			// following it would copy the decoder's precedence between a merged key and a written one
			// and toml and json have no spelling for it
			if key.Tag == "!!merge" {
				return fmt.Errorf("line %d: a merge key is refused, since toml and json have no spelling for one", key.Line)
			}
			// the key is read as the decoder reads it, through an alias and from a !!binary spelling
			var name string
			if err := key.Decode(&name); err != nil {
				return err
			}
			if field := fieldByKey(target, name); field.IsValid() {
				if err := fillBlocks(node.Content[i+1], field); err != nil {
					return err
				}
			}
		}
	case target.Kind() == reflect.Slice && node.Kind == yaml.SequenceNode:
		for i := 0; i < len(node.Content) && i < target.Len(); i++ {
			if err := fillBlocks(node.Content[i], target.Index(i)); err != nil {
				return err
			}
		}
	default:
		return wholeNumber(node, target.Type())
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

func (c *Config) setDefaults() {
	for i := range c.Dial.To {
		if c.Dial.To[i].Org == "" {
			c.Dial.To[i].Org = c.Node.Org
		}
	}
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
		c.Routes(), c.Babel(), c.Crypto(),
	} {
		if err := capability.Validate(); err != nil {
			return err
		}
	}
	// cap.segment is asked alone here
	// its longest steering list is checked against link.mtu with the checks spanning two blocks
	if err := c.Segments().Validate(0); err != nil {
		return err
	}
	// Table and Egress are asked only where the block was written, because
	// neither has a zero value worth checking: an absent table writes no
	// routes and an absent egress carries nobody else's traffic, while an
	// empty block of either is a mistake each refuses by name.
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
	case c.Node.Org == "":
		return errors.New("config: node.org is required")
	case c.Node.Name == "":
		return errors.New("config: node.name is required")
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
	peers := make(map[string]struct{}, len(c.Dial.To))
	for _, peer := range c.Dial.To {
		if peer.Org == "" || peer.Name == "" {
			return errors.New("config: dial.to entries require org and name")
		}
		key := peer.Org + "\x00" + peer.Name + "\x00" + peer.Serial
		if _, exists := peers[key]; exists {
			return fmt.Errorf("config: duplicate dial.to entry %s/%s endpoint %q", peer.Org, peer.Name, peer.Serial)
		}
		peers[key] = struct{}{}
	}
	return nil
}

// validateAcrossCapabilities is the part no capability can check alone,
// because each half is in a different block.
func (c *Config) validateAcrossCapabilities() error {
	if err := c.validateUnderlayMark(); err != nil {
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

// validateSteeredMTU refuses a link.mtu the longest cap.segment steer list takes under the 1280 bytes IPv6 requires of every link
// the device runs at link.mtu less that list
// the daemon makes the device with the same call, so a file this takes is one the daemon starts on
func (c *Config) validateSteeredMTU() error {
	_, steering, err := c.Segments().Tables()
	if err != nil {
		return err
	}
	if _, err := steering.CheckMTU(c.Link.SessionMTU()); err != nil {
		return fmt.Errorf("config: link.mtu %d: %w", c.Link.SessionMTU(), err)
	}
	return nil
}

// validateUnderlayMark refuses a mark nothing looks at. The two halves of the
// setting are written in different blocks: link.underlay mark puts SO_MARK on
// the one socket carrying IKE and ESP, and a cap.table rules entry selecting
// that mark sends it to a table the mesh does not write. With only the first,
// the marked socket follows the mesh table exactly as an unmarked one
// would, and a default an exit announced there routes this node's own IKE into
// the tun carrying it. Measured on a live leaf: 52 IKE datagrams entered the
// tun in eight seconds, none of those sessions could establish, and nothing
// said so.
//
// Only where cap.table is written, because that is the only place this file
// can put a rule. A deployment configuring its routes elsewhere writes the
// rule elsewhere too, and refusing that would refuse a node that works.
func (c *Config) validateUnderlayMark() error {
	mark := c.Link.Underlay.Mark
	if mark == 0 || c.Cap.Table == nil || c.Cap.Table.ReadsMark(mark) {
		return nil
	}
	return fmt.Errorf("config: link.underlay mark %#x is selected by no cap.table rules entry, so the marked socket still follows the mesh table: add { fwmark = %#x, table = \"main\", priority = 40, family = \"both\" } to cap.table rules, or take the mark out", mark, mark)
}
