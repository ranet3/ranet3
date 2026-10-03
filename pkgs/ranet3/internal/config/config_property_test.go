// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package config

import (
	"encoding"
	"encoding/json"
	"fmt"
	"maps"
	"math"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	"go.yaml.in/yaml/v3"
	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/ike"
	"ranet3.com/pkgs/ranet3/internal/babel"
	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
	"ranet3.com/pkgs/ranet3/transport"
)

// nameCharacters is every printable ASCII character and three letters beyond
// it. Most of the punctuation means something to one encoder or another, so a
// name made of it has to be quoted somewhere, and digits and letters let a name
// read as a number or a keyword. Control characters are left out:
// encoding/json writes DEL and the C1 controls raw, which the yaml reader a
// .json file goes through refuses, and yaml.v3 writes a value starting with a
// tab and holding a newline as a block its own reader refuses.
const nameCharacters = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~\u00e9\u00fc\u4e2d"

// text draws a name of up to longest characters from nameCharacters, and now
// and then one carrying a byte that is not UTF-8, which Validate refuses since
// no file holds it as written.
func text(longest int) hegel.Generator[string] {
	characters := hegel.SampledFrom([]rune(nameCharacters))
	return hegel.Composite(func(tc hegel.TestCase) string {
		name := string(hegel.Draw(tc, hegel.Lists(characters).MinSize(1).MaxSize(longest)))
		if hegel.Draw(tc, hegel.WeightedBooleans(0.01)) {
			at := hegel.Draw(tc, hegel.Integers(0, len(name)))
			name = name[:at] + "\xff" + name[at:]
		}
		return name
	})
}

// names draws what a file names a node, a peer, a serial or a device with.
func names() hegel.Generator[string] { return text(12) }

// paths draws a file name, which is a name allowed to run longer.
func paths() hegel.Generator[string] { return text(24) }

// notPrefixes draws a prefix with no spelling: one nobody wrote, or one that
// is set and is not a prefix, an address under a length past its family's
// width or below zero.
func notPrefixes() hegel.Generator[schema.Prefix] {
	return hegel.OneOf(hegel.Just(schema.Prefix{}), malformed())
}

// malformed draws a prefix that is set and is not one.
func malformed() hegel.Generator[schema.Prefix] {
	return hegel.Composite(func(tc hegel.TestCase) schema.Prefix {
		address := hegel.Draw(tc, hegel.IPAddresses())
		bits := hegel.Draw(tc, hegel.OneOf(hegel.Just(-1), edges(address.BitLen()+1, 255)))
		return schema.PrefixFrom(netip.PrefixFrom(address, bits))
	})
}

// edges draws from lo through hi with both ends drawn on their own as well,
// since a derandomized run of a few hundred cases need not land on either.
func edges[T interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 | ~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64
}](lo, hi T) hegel.Generator[T] {
	return hegel.OneOf(hegel.Integers(lo, hi), hegel.Just(lo), hegel.Just(hi))
}

// between draws an interval from lo through hi, to the nanosecond, since the
// spelling has to carry any value the type holds and not only round ones.
func between(lo, hi time.Duration) hegel.Generator[schema.Duration] {
	return hegel.Map(edges(int64(lo), int64(hi)), func(n int64) schema.Duration { return schema.Duration(n) })
}

// unset is the zero a field left out of a file decodes to, drawn beside the
// values it can take when written, since an encoder decides on its own
// whether a zero is written at all.
func unset[T any](values hegel.Generator[T]) hegel.Generator[T] {
	var zero T
	return hegel.OneOf(values, hegel.Just(zero))
}

// family draws an address of one family, IPv4 when v6 is false.
func family(v6 bool) hegel.Generator[netip.Addr] {
	if v6 {
		return hegel.IPAddresses().IPv6()
	}
	return hegel.IPAddresses().IPv4()
}

// prefixOf draws a prefix of one family at a length from one through the
// family's width. A selector here may not carry host bits, so masked clears
// them, while an announcement and an assigned address keep the ones written.
func prefixOf(v6, masked bool) hegel.Generator[schema.Prefix] {
	return hegel.Composite(func(tc hegel.TestCase) schema.Prefix {
		address := hegel.Draw(tc, family(v6))
		prefix := netip.PrefixFrom(address, hegel.Draw(tc, edges(1, address.BitLen())))
		if masked {
			prefix = prefix.Masked()
		}
		return schema.PrefixFrom(prefix)
	})
}

// eitherFamily is prefixOf with the family drawn as well.
func eitherFamily(masked bool) hegel.Generator[schema.Prefix] {
	return hegel.FlatMap(hegel.Booleans(), func(v6 bool) hegel.Generator[schema.Prefix] { return prefixOf(v6, masked) })
}

// segmentAddresses draws an address a segment routed packet can be sent to or
// from, the only kind cap.segment takes.
func segmentAddresses() hegel.Generator[schema.Addr] {
	return hegel.Map(hegel.Filter(hegel.IPAddresses().IPv6(), srv6.Usable), schema.AddrFrom)
}

// announcements draws one cap.route announce entry: a default or a prefix of
// either family, an IPv6 one sometimes carrying the source it is offered to.
func announcements() hegel.Generator[schema.Announce] {
	return hegel.Composite(func(tc hegel.TestCase) schema.Announce {
		v6 := hegel.Draw(tc, hegel.Booleans())
		announced := schema.Announce{Prefix: schema.MustPrefix("0.0.0.0/0")}
		if v6 {
			announced.Prefix = schema.MustPrefix("::/0")
		}
		if hegel.Draw(tc, hegel.Booleans()) {
			announced.Prefix = hegel.Draw(tc, prefixOf(v6, false))
		}
		// only IPv6 carries a source, which is how an exit offers its default
		// to its own customers alone
		if v6 && hegel.Draw(tc, hegel.Booleans()) {
			announced.From = hegel.Draw(tc, prefixOf(true, false))
		}
		return announced
	})
}

// routes draws cap.route.
func routes() hegel.Generator[babel.Routes] {
	return hegel.Composite(func(tc hegel.TestCase) babel.Routes {
		return babel.Routes{
			Announce: hegel.Draw(tc, hegel.Lists(announcements()).MaxSize(4)),
			Transit:  hegel.Draw(tc, hegel.Optional(hegel.Booleans())),
		}
	})
}

// speakers draws cap.babel. Every interval sits inside what the protocol can
// carry, and the cost window cannot be written backwards whichever half is
// left at its default.
func speakers() hegel.Generator[babel.Config] {
	intervals := unset(between(10*time.Millisecond, 65535*10*time.Millisecond))
	return hegel.Composite(func(tc hegel.TestCase) babel.Config {
		return babel.Config{
			Hello:   hegel.Draw(tc, intervals),
			Update:  hegel.Draw(tc, intervals),
			Quality: hegel.Draw(tc, hegel.SampledFrom([]babel.LinkQuality{babel.LinkQualityETX, babel.LinkQualityNone})),
			Cost: babel.CostOptions{
				Rx: hegel.Draw(tc, hegel.Optional(edges[uint16](1, 1024))),
				RTT: babel.RTTOptions{
					Weight: hegel.Draw(tc, hegel.Optional(edges[uint16](0, 4096))),
					Min:    hegel.Draw(tc, hegel.Optional(between(0, time.Second))),
					Max:    hegel.Draw(tc, hegel.Optional(between(time.Second, 5*time.Second))),
				},
			},
		}
	})
}

// tables draws a table a rule looks up: one of the reserved names or any
// number either side of them.
func tables() hegel.Generator[schema.TableID] {
	return hegel.Map(hegel.OneOf(
		hegel.SampledFrom([]uint32{uint32(schema.TableMain), uint32(schema.TableLocal), uint32(schema.TableDefault)}),
		edges[uint32](1, math.MaxUint32),
	), func(n uint32) schema.TableID { return schema.TableID(n) })
}

// owned draws the table cap.table owns, which is never a reserved one, or
// leaves it to the default.
func owned() hegel.Generator[schema.TableID] {
	return hegel.Map(hegel.OneOf(
		hegel.Just(uint32(0)),
		edges[uint32](1, uint32(schema.TableDefault)-1),
		edges[uint32](uint32(schema.TableLocal)+1, math.MaxUint32),
	), func(n uint32) schema.TableID { return schema.TableID(n) })
}

// rules draws one cap.table rules entry in either shape a file writes: one
// selecting on addresses, which take their family from the address, and one
// selecting on a mark alone, which names its family. A mark rule now and then
// carries a selector that is set and is not a prefix, which Validate refuses.
func rules() hegel.Generator[kernel.Rule] {
	return hegel.Composite(func(tc hegel.TestCase) kernel.Rule {
		rule := kernel.Rule{
			Table:    hegel.Draw(tc, tables()),
			Priority: hegel.Draw(tc, edges[uint32](1, math.MaxUint32)),
		}
		marked := hegel.Draw(tc, hegel.Booleans())
		if marked {
			rule.FWMark = hegel.Draw(tc, edges[uint32](1, math.MaxUint32))
			rule.FWMask = hegel.Draw(tc, edges[uint32](0, math.MaxUint32))
		}
		if marked && hegel.Draw(tc, hegel.Booleans()) {
			rule.Family = hegel.Draw(tc, hegel.SampledFrom([]kernel.Family{kernel.FamilyIPv4, kernel.FamilyIPv6, kernel.FamilyBoth}))
			if hegel.Draw(tc, hegel.WeightedBooleans(0.1)) {
				rule.To = hegel.Draw(tc, malformed())
			}
			return rule
		}
		v6 := hegel.Draw(tc, hegel.Booleans())
		switch hegel.Draw(tc, hegel.Integers(0, 2)) {
		case 0:
			rule.To = hegel.Draw(tc, prefixOf(v6, true))
		case 1:
			rule.From = hegel.Draw(tc, prefixOf(v6, true))
		default:
			rule.To = hegel.Draw(tc, prefixOf(v6, true))
			rule.From = hegel.Draw(tc, prefixOf(v6, true))
		}
		return rule
	})
}

// reconcilers draws cap.table. The preferred source is an IPv4 address in
// either spelling, which the reconciler unmaps and the file keeps as written,
// and the IPv4-mapped one sometimes carries a zone. Now and then an address
// entry has no spelling either, and Validate refuses both.
func reconcilers() hegel.Generator[kernel.Table] {
	return hegel.Composite(func(tc hegel.TestCase) kernel.Table {
		table := kernel.Table{
			ID:              hegel.Draw(tc, owned()),
			Proto:           hegel.Draw(tc, unset(edges[uint8](5, math.MaxUint8))),
			Metric:          hegel.Draw(tc, edges[uint32](0, math.MaxUint32)),
			Addresses:       hegel.Draw(tc, hegel.Lists(eitherFamily(false)).MaxSize(3)),
			AssignAnnounced: hegel.Draw(tc, hegel.Booleans()),
			Rules:           hegel.Draw(tc, hegel.Lists(rules()).MaxSize(4)),
			Reconcile:       hegel.Draw(tc, unset(between(time.Millisecond, time.Hour))),
			CaptureGrace:    hegel.Draw(tc, unset(between(kernel.MinCaptureGrace, time.Hour))),
		}
		if hegel.Draw(tc, hegel.Booleans()) {
			address := hegel.Draw(tc, hegel.IPAddresses().IPv4())
			if hegel.Draw(tc, hegel.Booleans()) {
				address = netip.AddrFrom16(address.As16())
			}
			if address.Is6() && hegel.Draw(tc, hegel.Booleans()) {
				address = address.WithZone(hegel.Draw(tc, names()))
			}
			table.PrefSrc4 = schema.AddrFrom(address)
		}
		if hegel.Draw(tc, hegel.WeightedBooleans(0.1)) {
			table.Addresses = append(table.Addresses, hegel.Draw(tc, notPrefixes()))
		}
		if hegel.Draw(tc, hegel.Booleans()) {
			table.VRF = &kernel.VRF{Name: hegel.Draw(tc, names()), Create: hegel.Draw(tc, hegel.Booleans())}
		}
		return table
	})
}

// steering draws one cap.segment steer entry. It names its own source when
// the block has none to lend it, and otherwise only sometimes.
func steering(inherited bool) hegel.Generator[srv6.Steer] {
	return hegel.Composite(func(tc hegel.TestCase) srv6.Steer {
		v6 := hegel.Draw(tc, hegel.Booleans())
		var entry srv6.Steer
		switch hegel.Draw(tc, hegel.Integers(0, 2)) {
		case 0:
			entry.To = hegel.Draw(tc, prefixOf(v6, true))
		case 1:
			entry.From = hegel.Draw(tc, prefixOf(v6, true))
		default:
			entry.To = hegel.Draw(tc, prefixOf(v6, true))
			entry.From = hegel.Draw(tc, prefixOf(v6, true))
		}
		if !inherited || hegel.Draw(tc, hegel.Booleans()) {
			entry.Source = hegel.Draw(tc, segmentAddresses())
		}
		// four is the longest list the default device carries above the 1280
		// bytes IPv6 requires of every link
		entry.Via = hegel.Draw(tc, hegel.Lists(segmentAddresses()).MinSize(1).MaxSize(4))
		return entry
	})
}

// segments draws cap.segment.
func segments() hegel.Generator[srv6.Segments] {
	local := hegel.Composite(func(tc hegel.TestCase) srv6.Segment {
		return srv6.Segment{
			SID:      hegel.Draw(tc, segmentAddresses()),
			Behavior: hegel.Draw(tc, hegel.SampledFrom([]srv6.Behavior{srv6.BehaviorEnd, srv6.BehaviorEndDT46})),
		}
	})
	return hegel.Composite(func(tc hegel.TestCase) srv6.Segments {
		var block srv6.Segments
		if hegel.Draw(tc, hegel.Booleans()) {
			block.Source = hegel.Draw(tc, segmentAddresses())
		}
		block.Local = hegel.Draw(tc, hegel.Lists(local).MaxSize(3))
		block.Steer = hegel.Draw(tc, hegel.Lists(steering(block.Source.IsValid())).MaxSize(2))
		return block
	})
}

// cryptos draws cap.crypto. A rekey interval is long enough to hold any
// margin and jitter drawn beside it, and the first retry never passes the
// last, whichever of each pair is left at its default.
func cryptos() hegel.Generator[ike.Crypto] {
	intervals := unset(between(30*time.Minute, 24*time.Hour))
	return hegel.Composite(func(tc hegel.TestCase) ike.Crypto {
		return ike.Crypto{
			Replay: hegel.Draw(tc, hegel.Optional(edges[uint32](0, 1<<20))),
			Rekey: ike.Rekey{
				Child:  hegel.Draw(tc, hegel.Optional(intervals)),
				IKE:    hegel.Draw(tc, hegel.Optional(intervals)),
				Margin: hegel.Draw(tc, hegel.Optional(between(0, 10*time.Minute))),
				Jitter: hegel.Draw(tc, hegel.Optional(between(0, 10*time.Minute))),
				Retry: ike.Retry{
					First: hegel.Draw(tc, hegel.Optional(between(time.Millisecond, time.Minute))),
					Max:   hegel.Draw(tc, hegel.Optional(between(time.Minute, time.Hour))),
				},
			},
		}
	})
}

// sources draws an egress source of one family: absent, the word auto, an
// address, or one of the three a file cannot write and Validate refuses by
// name: an IPv4 address in the IPv4-mapped spelling, an address carrying a
// zone, and a source that is both auto and an address. The mapped spelling is
// drawn on its own because the address generator lands in that range too
// seldom to be counted on.
func sources(v6 bool) hegel.Generator[egress.Source] {
	unwritable := hegel.OneOf(
		hegel.Map(hegel.IPAddresses().IPv4(), func(address netip.Addr) egress.Source {
			return egress.Source{Addr: netip.AddrFrom16(address.As16())}
		}),
		hegel.Composite(func(tc hegel.TestCase) egress.Source {
			return egress.Source{Addr: hegel.Draw(tc, hegel.IPAddresses().IPv6()).WithZone(hegel.Draw(tc, names()))}
		}),
		hegel.Map(family(v6), func(address netip.Addr) egress.Source { return egress.Source{Auto: true, Addr: address} }),
	)
	return hegel.OneOf(
		hegel.Just(egress.Source{}),
		hegel.Just(egress.Source{Auto: true}),
		hegel.Map(family(v6), func(address netip.Addr) egress.Source { return egress.Source{Addr: address} }),
		unwritable,
	)
}

// exits draws cap.egress. An advertised prefix is written once, since a prefix
// written twice is refused by name, and is drawn in the IPv4-mapped spelling
// as readily as in any other, which is refused by name as well.
func exits() hegel.Generator[egress.Egress] {
	advertised := hegel.OneOf(
		hegel.SampledFrom([]schema.Prefix{schema.MustPrefix("0.0.0.0/0"), schema.MustPrefix("::/0")}),
		eitherFamily(true),
	)
	return hegel.Composite(func(tc hegel.TestCase) egress.Egress {
		var advertise []schema.Prefix
		for _, prefix := range hegel.Draw(tc, hegel.Lists(advertised).MinSize(1).MaxSize(3)) {
			if !slices.Contains(advertise, prefix) {
				advertise = append(advertise, prefix)
			}
		}
		return egress.Egress{
			Advertise: advertise,
			Source4:   hegel.Draw(tc, sources(false)),
			Source6:   hegel.Draw(tc, sources(true)),
			Return:    hegel.Draw(tc, hegel.Booleans()),
			Sweep:     hegel.Draw(tc, unset(between(time.Second, time.Hour))),
		}
	})
}

// presence decides which capability blocks a configuration writes: none of
// them, every one, or each on its own, so the two ends of the range are drawn
// as surely as anything between them.
type presence int

const (
	eachOnItsOwn presence = iota
	noBlock
	everyBlock
)

// block draws a capability or leaves it out, which is the whole of how a file
// turns one on.
func block[T any](tc hegel.TestCase, blocks presence, capability hegel.Generator[T]) *T {
	switch blocks {
	case noBlock:
		return nil
	case everyBlock:
		drawn := hegel.Draw(tc, capability)
		return &drawn
	}
	return hegel.Draw(tc, hegel.Optional(capability))
}

// nodes draws what a configuration says about the node itself, every
// capability block left out.
func nodes() hegel.Generator[Config] {
	endpoint := hegel.Composite(func(tc hegel.TestCase) Endpoint {
		return Endpoint{Serial: hegel.Draw(tc, names()), Family: hegel.Draw(tc, hegel.SampledFrom([]string{"ip4", "ip6"}))}
	})
	peer := hegel.Composite(func(tc hegel.TestCase) Peer {
		peer := Peer{Name: hegel.Draw(tc, names())}
		if hegel.Draw(tc, hegel.Booleans()) {
			peer.Org = hegel.Draw(tc, names())
		}
		if hegel.Draw(tc, hegel.Booleans()) {
			peer.Serial = hegel.Draw(tc, names())
		}
		return peer
	})
	return hegel.Composite(func(tc hegel.TestCase) Config {
		c := Config{
			Node: Node{Org: hegel.Draw(tc, names()), Name: hegel.Draw(tc, names())},
			Auth: Auth{Key: hegel.Draw(tc, paths()), Trust: hegel.Draw(tc, paths())},
			Link: Link{
				Port:      hegel.Draw(tc, edges[uint16](1, math.MaxUint16)),
				Endpoints: hegel.Draw(tc, hegel.Lists(endpoint).MinSize(1).MaxSize(3)),
				Listen:    hegel.Draw(tc, hegel.Booleans()),
				Underlay: transport.Underlay{
					Mark: hegel.Draw(tc, unset(edges[uint32](1, math.MaxUint32))),
					Bind: hegel.Draw(tc, hegel.Booleans()),
				},
			},
			Dial: Dial{
				All: hegel.Draw(tc, hegel.Booleans()),
				To:  hegel.Draw(tc, hegel.Lists(peer).MaxSize(3)),
			},
		}
		if hegel.Draw(tc, hegel.Booleans()) {
			c.Link.TUN = hegel.Draw(tc, names())
		}
		return c
	})
}

// configurations draws a node and any subset of its capability blocks. Each
// block present draws mostly values its own validation takes, plus now and
// then one of the values no file can write that its helper names, which
// Validate refuses by name. Most of what Validate refuses is those, by design.
// The rest falls in three classes. One is a collision between two drawn
// values, a duplicate or a segment the table also assigns. One is a node with
// nothing to dial. The last is a value an ordinary branch of a helper draws
// and the block's own validation refuses. For example, an egress source may
// be one nothing can reply to, such as a loopback or multicast address, a
// cap.table address may be the unspecified address, and a cap.segment
// steering selector may be a v4-mapped prefix.
func configurations() hegel.Generator[Config] {
	return hegel.Composite(func(tc hegel.TestCase) Config {
		c := hegel.Draw(tc, nodes())
		blocks := hegel.Draw(tc, hegel.SampledFrom([]presence{eachOnItsOwn, noBlock, everyBlock}))
		c.Cap = Caps{
			Route:   block(tc, blocks, routes()),
			Babel:   block(tc, blocks, speakers()),
			Table:   block(tc, blocks, reconcilers()),
			Segment: block(tc, blocks, segments()),
			Crypto:  block(tc, blocks, cryptos()),
			Egress:  block(tc, blocks, exits()),
		}
		// a mark needs a rule reading it wherever this file writes rules, so a
		// marked node with a table carries the rule its refusal spells out
		if mark := c.Link.Underlay.Mark; mark != 0 && c.Cap.Table != nil && !c.Cap.Table.ReadsMark(mark) {
			c.Cap.Table.Rules = append(c.Cap.Table.Rules, kernel.Rule{
				FWMark:   mark,
				Table:    schema.TableMain,
				Priority: hegel.Draw(tc, edges[uint32](1, math.MaxUint32)),
				Family:   kernel.FamilyBoth,
			})
		}
		return c
	})
}

// defaulted is the configuration Load hands the daemon for c, by the one
// default the documentation gives: a dial.to entry naming no org takes the
// node's own. It is written out here rather than taken from setDefaults, so a
// default that rewrote a field the file wrote is a difference this sees,
// rather than a change made to both sides of the comparison.
func defaulted(c Config) Config {
	c.Dial.To = slices.Clone(c.Dial.To)
	for i := range c.Dial.To {
		if c.Dial.To[i].Org == "" {
			c.Dial.To[i].Org = c.Node.Org
		}
	}
	return c
}

// difference names the first field at which got parts from want, in the path
// a file writes it under, so a failure reads as one setting rather than as two
// renderings that may share the fault being looked for.
func difference(want, got reflect.Value, path string) string {
	switch {
	case want.Kind() == reflect.Pointer && !want.IsNil() && !got.IsNil():
		return difference(want.Elem(), got.Elem(), path)
	case want.Kind() == reflect.Struct && !spellsItself(want.Type()):
		for i := range want.NumField() {
			field := want.Type().Field(i)
			if !field.IsExported() {
				continue
			}
			key, _, _ := strings.Cut(field.Tag.Get("yaml"), ",")
			if key == "" {
				key = strings.ToLower(field.Name)
			}
			if !reflect.DeepEqual(want.Field(i).Interface(), got.Field(i).Interface()) {
				return difference(want.Field(i), got.Field(i), strings.TrimPrefix(path+"."+key, "."))
			}
		}
	case want.Kind() == reflect.Slice && want.Len() == got.Len():
		for i := range want.Len() {
			if !reflect.DeepEqual(want.Index(i).Interface(), got.Index(i).Interface()) {
				return difference(want.Index(i), got.Index(i), fmt.Sprintf("%s[%d]", path, i))
			}
		}
	}
	gotShown, wantShown := shown(got, "%v"), shown(want, "%v")
	if gotShown == wantShown {
		gotShown, wantShown = shown(got, "%#v"), shown(want, "%#v")
	}
	return fmt.Sprintf("%s is %s, want %s", path, gotShown, wantShown)
}

// shown spells one side of a difference, through the pointer where there is
// one, since an address says nothing about what it points at. verb is %v, or
// %#v where the two sides would print alike under it.
func shown(value reflect.Value, verb string) string {
	if value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return "absent"
		}
		value = value.Elem()
	}
	return fmt.Sprintf(verb, value.Interface())
}

// sameAfterEachEncoder renders drawn under each file encoder, loads each
// rendering the way the daemon loads its file and fails at the first one that
// reads back anything but want, naming the setting it changed. want is drawn
// with the documented default filled in by defaulted. The json rendering is
// read by the control plane's own decoder as well, which fills in no default
// and so has to read back drawn, since the file and the wire form are one
// schema.
func sameAfterEachEncoder(ht *hegel.T, t *testing.T, drawn, want Config) {
	ht.Helper()
	for _, encoder := range []struct {
		extension string
		render    func(any) ([]byte, error)
	}{
		{".yaml", yaml.Marshal},
		{".toml", renderTOML},
		{".json", json.Marshal},
	} {
		body, err := encoder.render(&drawn)
		if err != nil {
			ht.Fatalf("render %s: %v", encoder.extension, err)
		}
		got, err := load(t, encoder.extension, string(body))
		if err != nil {
			ht.Fatalf("%s refused the configuration it rendered:\n%s\n%v", encoder.extension, body, err)
		}
		// a peer org the file wrote reads back as written, whatever the
		// default does for one the file left out
		for i, peer := range drawn.Dial.To {
			if peer.Org != "" && i < len(got.Dial.To) && got.Dial.To[i].Org != peer.Org {
				ht.Fatalf("%s read dial.to[%d] org %q as %q, from\n%s", encoder.extension, i, peer.Org, got.Dial.To[i].Org, body)
			}
		}
		if !reflect.DeepEqual(*got, want) {
			ht.Fatalf("%s read back %s, from\n%s", encoder.extension, difference(reflect.ValueOf(want), reflect.ValueOf(*got), ""), body)
		}
		if encoder.extension != ".json" {
			continue
		}
		var overWire Config
		if err := json.Unmarshal(body, &overWire); err != nil {
			ht.Fatalf("the control plane refused\n%s\n%v", body, err)
		}
		if !reflect.DeepEqual(overWire, drawn) {
			ht.Fatalf("the control plane read back %s, from\n%s", difference(reflect.ValueOf(drawn), reflect.ValueOf(overWire), ""), body)
		}
	}
}

// A configuration with any subset of its capability blocks, each written with
// values an operator could write, reaches the daemon unchanged whichever of
// the three encoders carried it. A field an encoder drops or rewrites is a
// setting the node never applies and nothing reports, and a block that goes
// missing turns a capability off.
//
// Only what Validate takes is held, and it is held through the loader rather
// than a decoder, so the defaults and the checks run as they do for a file. A
// configuration the package accepts and then refuses once rendered is a
// failure: it is a node its own file will not start. What the loader has to
// hand back is the drawn configuration with the documented default filled in
// by defaulted rather than by the loader's own setDefaults, so a default that
// rewrote a peer org the file wrote, and changed who the node dials, fails
// here.
func TestGeneratedConfigurationSurvivesEachEncoder(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		drawn := hegel.Draw(ht, configurations())
		want := defaulted(drawn)
		ht.Assume(want.Validate() == nil)
		sameAfterEachEncoder(ht, t, drawn, want)
	})
}

// The same for a node whose only block is cap.egress, which draws a source in
// each spelling far more often than a whole configuration does. Validate took
// three sources whose file did not read back: an IPv4-mapped source6, which
// the decoder unmapped and then refused, one carrying a zone, which the
// decoder refused, and one both auto and an address, which read back as the
// address alone. Shrunk: advertise 0.0.0.0/0 with source6 ::ffff:0.0.0.1.
func TestValidatedEgressSourceReadsBackFromItsFile(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		drawn := hegel.Draw(ht, nodes())
		drawn.Dial.All = true
		exit := hegel.Draw(ht, exits())
		drawn.Cap.Egress = &exit
		want := defaulted(drawn)
		ht.Assume(want.Validate() == nil)
		sameAfterEachEncoder(ht, t, drawn, want)
	})
}

// The same for cap.route, cap.babel and cap.segment, drawn mostly with values
// their own Validate takes and, a quarter of the time, with one value added
// that no file can write: an announcement whose prefix or source has no
// spelling, a link quality other than etx and none, which is written as etx,
// or a steering selector that is set and is not a prefix. A configuration
// carrying none of them reads back unchanged. One carrying one of them has to
// be refused, and since the configuration without it was taken, the refusal
// is the value's own. Most cases still reach the round trip rather than every
// one being refused.
func TestValidatedRouteSpeakerAndSegmentsReadBackFromTheirFile(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		drawn := hegel.Draw(ht, nodes())
		drawn.Dial.All = true
		route, speaker, segment := hegel.Draw(ht, routes()), hegel.Draw(ht, speakers()), hegel.Draw(ht, segments())
		drawn.Cap = Caps{Route: &route, Babel: &speaker, Segment: &segment}
		want := defaulted(drawn)
		ht.Assume(want.Validate() == nil)
		if !hegel.Draw(ht, hegel.WeightedBooleans(0.25)) {
			sameAfterEachEncoder(ht, t, drawn, want)
			return
		}

		// one value no file holds, added to a configuration Validate took
		// without it, in a copy of the block it goes in
		injected, what := want, ""
		switch hegel.Draw(ht, hegel.Integers(0, 3)) {
		case 0:
			added := route
			added.Announce = append(slices.Clone(route.Announce), schema.Announce{Prefix: hegel.Draw(ht, notPrefixes())})
			injected.Cap.Route, what = &added, "an announcement with no prefix"
		case 1:
			added := route
			added.Announce = append(slices.Clone(route.Announce), schema.Announce{Prefix: schema.MustPrefix("::/0"), From: hegel.Draw(ht, malformed())})
			injected.Cap.Route, what = &added, "an announcement whose source is not a prefix"
		case 2:
			added := speaker
			added.Quality = babel.LinkQuality(hegel.Draw(ht, hegel.Integers[uint8](2, math.MaxUint8)))
			injected.Cap.Babel, what = &added, fmt.Sprintf("link quality %d", added.Quality)
		default:
			entry := hegel.Draw(ht, steering(segment.Source.IsValid()))
			if !entry.From.IsValid() {
				entry.From = hegel.Draw(ht, prefixOf(true, true))
			}
			entry.To = hegel.Draw(ht, malformed())
			added := segment
			added.Steer = append(slices.Clone(segment.Steer), entry)
			injected.Cap.Segment, what = &added, "a steering selector that is not a prefix"
		}
		if err := injected.Validate(); err == nil {
			ht.Fatalf("Validate took %s, which no file holds", what)
		}
	})
}

// scalarTypes collects every type under ty that reads itself from text, which
// is every scalar a configuration file can write, the schema's and each
// capability's own. The walk stops at one, since what stands behind a
// spelling is the type's own business.
func scalarTypes(ty reflect.Type, found map[reflect.Type]bool) {
	for ty.Kind() == reflect.Pointer || ty.Kind() == reflect.Slice {
		ty = ty.Elem()
	}
	switch {
	case reflect.PointerTo(ty).Implements(reflect.TypeFor[encoding.TextUnmarshaler]()):
		found[ty] = true
	case ty.Kind() == reflect.Struct:
		for field := range ty.Fields() {
			if field.IsExported() {
				scalarTypes(field.Type, found)
			}
		}
	}
}

// digits is every number a file writes as one digit.
var digits = []string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9"}

// edgeNumerals is the numbers a decoder is likeliest to read differently: a
// signed zero, a negative, the ends of a table's range and one past it, and
// the words toml reads as numbers.
var edgeNumerals = []string{"0", "+0", "-0", "-1", "254", "4294967295", "4294967296", "inf", "nan"}

// numerals draws a number as a file might write one: a single digit, an
// integer up to 255, a decimal integer with or without a sign or digit
// separators, one in another base, a fraction or an exponent, a word toml
// reads as a number, and the ends of a table's range. The digits and the
// short integers are drawn on their own, since a scalar taking a small code,
// a family as 4 or 6, is the likeliest to take a number at all, and a long
// run of digits almost never lands on one. A digit is one integer draw
// whichever way it is written, as one of ten spellings or as an integer up to
// 9, and the engine spreads that draw so unevenly that a run leaves some
// digits out. The test reads every digit and every edge before it draws, and
// that sweep alone makes sure each one is read.
func numerals() hegel.Generator[string] {
	run := func(alphabet string) hegel.Generator[string] {
		return hegel.Text().Alphabet(alphabet).MinSize(1).MaxSize(12)
	}
	sign := hegel.SampledFrom([]string{"", "+", "-"})
	return hegel.OneOf(
		hegel.SampledFrom(digits),
		hegel.Map(hegel.Integers(0, 255), strconv.Itoa),
		hegel.SampledFrom(edgeNumerals),
		hegel.Composite(func(tc hegel.TestCase) string {
			return hegel.Draw(tc, sign) + hegel.Draw(tc, run("0123456789_"))
		}),
		hegel.Composite(func(tc hegel.TestCase) string {
			base := hegel.Draw(tc, hegel.SampledFrom([][2]string{{"0x", "0123456789abcdef"}, {"0o", "01234567"}, {"0b", "01"}}))
			return hegel.Draw(tc, sign) + base[0] + hegel.Draw(tc, run(base[1]))
		}),
		hegel.Composite(func(tc hegel.TestCase) string {
			return hegel.Draw(tc, sign) + hegel.Draw(tc, run("0123456789")) + "." + hegel.Draw(tc, run("0123456789")) +
				hegel.Draw(tc, hegel.SampledFrom([]string{"", "e3", "E-2"}))
		}),
	)
}

// decodeOne reads one toml value into target, under the key a document needs
// in order to hold one.
func decodeOne(numeral string, target any) error {
	field := reflect.StructField{Name: "V", Type: reflect.TypeOf(target).Elem(), Tag: `toml:"v"`}
	document := reflect.New(reflect.StructOf([]reflect.StructField{field}))
	if _, err := toml.Decode("v = "+numeral+"\n", document.Interface()); err != nil {
		return err
	}
	reflect.ValueOf(target).Elem().Set(document.Elem().Field(0))
	return nil
}

// A number written bare reads alike under every decoder able to read one, for
// every scalar a configuration carries, found by reflection so that a scalar
// added later is held as well. encoding/json hands a number to a text
// unmarshaler as an error while the file decoders pass it through, so a
// scalar a file may write as a number has to take one on the json wire too,
// as a table and a disabled timer do, and every other scalar refuses one
// under all of them. json and toml each spell only some numbers, and a number
// one of them cannot spell is left out of its comparison.
func TestEveryScalarReadsABareNumberAlike(t *testing.T) {
	found := make(map[reflect.Type]bool)
	scalarTypes(reflect.TypeFor[Config](), found)
	types := slices.SortedFunc(maps.Keys(found), func(a, b reflect.Type) int { return strings.Compare(a.String(), b.String()) })
	// every digit and every edge is read before anything is drawn, since a run
	// leaves some of each undrawn, and a scalar taking one of them, a family as
	// 4 or a table as 254, is the likeliest to take a number at all
	for _, numeral := range slices.Concat(digits, edgeNumerals) {
		readsAlike(t, types, numeral)
	}
	pbt.Check(t, func(ht *hegel.T) {
		readsAlike(ht, types, hegel.Draw(ht, numerals()))
	})
}

// readsAlike fails unless numeral reads as each of types alike under every
// decoder able to read it, the text form included. It fails through tb, the
// test itself or one property case, so vet's printf check sees its format
// strings.
func readsAlike(tb testing.TB, types []reflect.Type, numeral string) {
	tb.Helper()
	var parsed map[string]any
	_, unspelled := toml.Decode("v = "+numeral+"\n", &parsed)
	for _, ty := range types {
		want := reflect.New(ty)
		refusal := want.Interface().(encoding.TextUnmarshaler).UnmarshalText([]byte(numeral))
		readings := map[string]func(any) error{
			"yaml": func(target any) error { return yaml.Unmarshal([]byte(numeral), target) },
		}
		if json.Valid([]byte(numeral)) {
			readings["json"] = func(target any) error { return json.Unmarshal([]byte(numeral), target) }
		}
		if unspelled == nil {
			readings["toml"] = func(target any) error { return decodeOne(numeral, target) }
		}
		for _, decoder := range slices.Sorted(maps.Keys(readings)) {
			got := reflect.New(ty)
			err := readings[decoder](got.Interface())
			switch {
			case (err == nil) != (refusal == nil):
				tb.Fatalf("%s %s %q: the text form says %v and %s says %v", ty, decoder, numeral, refusal, decoder, err)
			case err == nil && !reflect.DeepEqual(got.Elem().Interface(), want.Elem().Interface()):
				tb.Fatalf("%s %s %q: the text form reads %v and %s reads %v", ty, decoder, numeral, want.Elem(), decoder, got.Elem())
			}
		}
	}
}
