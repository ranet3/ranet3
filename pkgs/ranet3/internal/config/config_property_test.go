// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package config

import (
	"encoding"
	"encoding/hex"
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
	"unicode"

	"github.com/BurntSushi/toml"
	"go.yaml.in/yaml/v3"
	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/identity"
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
func text(longest int) hegel.Generator[string] { return textOf(nameCharacters, longest) }

// textOf is text drawn from alphabet in place of nameCharacters
func textOf(alphabet string, longest int) hegel.Generator[string] {
	characters := hegel.SampledFrom([]rune(alphabet))
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

// orMergeKey draws << outright and a key otherwise, since << is a valid key that a name generator seldom draws
func orMergeKey(keys hegel.Generator[string]) hegel.Generator[string] {
	return hegel.Composite(func(tc hegel.TestCase) string {
		if hegel.Draw(tc, hegel.WeightedBooleans(0.1)) {
			return "<<"
		}
		return hegel.Draw(tc, keys)
	})
}

// paths draws a file name, which is a name allowed to run longer.
func paths() hegel.Generator[string] { return text(24) }

// hostnames draws an FQDN as names draws a name, from the printable ASCII nameCharacters starts with, all an FQDN holds
func hostnames() hegel.Generator[string] {
	return textOf(strings.TrimRightFunc(nameCharacters, func(r rune) bool { return r > unicode.MaxASCII }), 12)
}

// identityAt draws a node of a drawn organization and name, or its endpoint serial where serial is set
// a name written in a file is escaped where its text form needs it, so any name a file can hold is a name an identity holds
func identityAt(tc hegel.TestCase, serial string) identity.Identity {
	id, err := identity.From(hegel.Draw(tc, names()), hegel.Draw(tc, names()), serial)
	if err != nil {
		panic(err)
	}
	return id
}

// peers draws a peer as dial.to writes one, a node or one endpoint of it
func peers() hegel.Generator[identity.Identity] {
	return hegel.Composite(func(tc hegel.TestCase) identity.Identity {
		if hegel.Draw(tc, hegel.Booleans()) {
			return identityAt(tc, hegel.Draw(tc, names()))
		}
		return identityAt(tc, "")
	})
}

// aliasKinds is each table of auth.aliases.remote, and each field of an auth.aliases.local entry
var aliasKinds = []string{"ip", "fqdn", "email", "keyid"}

// aliasIDs draws an ID as auth.aliases writes one of kind, an address of either family under ip, a name under fqdn, an address under email and octets in hex of either case under keyid
func aliasIDs(kind string) hegel.Generator[string] {
	return hegel.Composite(func(tc hegel.TestCase) string {
		switch kind {
		case "ip":
			return hegel.Draw(tc, hegel.IPAddresses()).String()
		case "fqdn":
			return hegel.Draw(tc, hostnames())
		case "email":
			return hegel.Draw(tc, names()) + "@" + hegel.Draw(tc, names())
		}
		written := hex.EncodeToString(hegel.Draw(tc, hegel.Binary(1, 16)))
		if hegel.Draw(tc, hegel.Booleans()) {
			return strings.ToUpper(written)
		}
		return written
	})
}

// localAlias is the entry of auth.aliases.local writing written as kind
func localAlias(kind, written string) ike.LocalAlias {
	switch kind {
	case "ip":
		return ike.LocalAlias{IP: written}
	case "fqdn":
		return ike.LocalAlias{FQDN: written}
	case "email":
		return ike.LocalAlias{Email: written}
	}
	return ike.LocalAlias{KeyID: written}
}

// aliasTables draws auth.aliases, up to three entries in each table of remote and in local, and no table where one draws no entry, which is how an empty one reads back
// a remote keyid entry now and then spells the endpoint it names, which Validate takes as the one KEY_ID entry for an endpoint text
func aliasTables() hegel.Generator[ike.Aliases] {
	remote := func(tc hegel.TestCase, kind string) map[string]identity.Identity {
		table := make(map[string]identity.Identity)
		keys := aliasIDs(kind)
		if kind == "fqdn" {
			keys = orMergeKey(keys)
		}
		for range hegel.Draw(tc, hegel.Integers(0, 3)) {
			table[hegel.Draw(tc, keys)] = identityAt(tc, hegel.Draw(tc, names()))
		}
		if kind == "keyid" && hegel.Draw(tc, hegel.WeightedBooleans(0.1)) {
			endpoint := identityAt(tc, hegel.Draw(tc, names()))
			table[hex.EncodeToString([]byte(endpoint.String()))] = endpoint
		}
		if len(table) == 0 {
			return nil
		}
		return table
	}
	return hegel.Composite(func(tc hegel.TestCase) ike.Aliases {
		aliases := ike.Aliases{Remote: ike.RemoteAliases{
			IP:    remote(tc, "ip"),
			FQDN:  remote(tc, "fqdn"),
			Email: remote(tc, "email"),
			KeyID: remote(tc, "keyid"),
		}}
		for range hegel.Draw(tc, hegel.Integers(0, 3)) {
			if aliases.Local == nil {
				aliases.Local = make(map[string]ike.LocalAlias)
			}
			kind := hegel.Draw(tc, hegel.SampledFrom(aliasKinds))
			aliases.Local[hegel.Draw(tc, peers()).String()] = localAlias(kind, hegel.Draw(tc, aliasIDs(kind)))
		}
		return aliases
	})
}

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
		return babel.Routes{Announce: hegel.Draw(tc, hegel.Lists(announcements()).MaxSize(4))}
	})
}

// transits draws cap.transit, now and then with no enable, which Validate refuses
func transits() hegel.Generator[babel.Transit] {
	return hegel.Composite(func(tc hegel.TestCase) babel.Transit {
		return babel.Transit{Enable: hegel.Draw(tc, hegel.Optional(hegel.Booleans()))}
	})
}

// speakers draws cap.babel. Every interval sits inside what the protocol can
// carry, and the cost window cannot be written backwards whichever half is
// left at its default.
func speakers() hegel.Generator[babel.Config] {
	intervals := unset(between(10*time.Millisecond, 65535*10*time.Millisecond))
	// now and then a node key is a bare name or an endpoint, which Validate refuses
	nodeKeys := hegel.Composite(func(tc hegel.TestCase) string {
		if hegel.Draw(tc, hegel.WeightedBooleans(0.05)) {
			return hegel.Draw(tc, names())
		}
		serial := ""
		if hegel.Draw(tc, hegel.WeightedBooleans(0.05)) {
			serial = hegel.Draw(tc, names())
		}
		id, err := identity.From(hegel.Draw(tc, names()), hegel.Draw(tc, names()), serial)
		if err != nil {
			panic(err)
		}
		return id.String()
	})
	// an empty map is written as no map, which reads back as nil
	// now and then an amount is infinity, which Validate refuses, and drawn as an edge it would refuse most maps
	amount := hegel.Composite(func(tc hegel.TestCase) uint16 {
		if hegel.Draw(tc, hegel.WeightedBooleans(0.05)) {
			return babel.MetricInfinity
		}
		return hegel.Draw(tc, edges[uint16](0, babel.MetricInfinity-1))
	})
	amounts := func(tc hegel.TestCase, keys hegel.Generator[string]) map[string]uint16 {
		drawn := hegel.Draw(tc, hegel.Maps(keys, amount).MaxSize(3))
		if len(drawn) == 0 {
			return nil
		}
		return drawn
	}
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
				Extra: babel.ExtraCost{
					Foreign: hegel.Draw(tc, edges[uint16](0, babel.MetricInfinity-1)),
					Org:     amounts(tc, orMergeKey(names())),
					Node:    amounts(tc, nodeKeys),
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
// selecting on a mark or an input device alone, which names its family. Such
// a rule now and then carries a selector that is set and is not a prefix,
// which Validate refuses.
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
		if hegel.Draw(tc, hegel.Booleans()) {
			rule.IIF = hegel.Draw(tc, names())
		}
		if (marked || rule.IIF != "") && hegel.Draw(tc, hegel.Booleans()) {
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

// reconcilers draws cap.table. Now and then an address entry has no spelling,
// and Validate refuses it.
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
			table.PrefSrc4 = schema.AddrFrom(hegel.Draw(tc, hegel.IPAddresses().IPv4()))
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

// allowPool is the prefixes a drawn egress segment's allow list is taken from,
// each a length the loader takes
var allowPool = []schema.Prefix{
	schema.MustPrefix("3fff:a::/32"), schema.MustPrefix("2602:f590::/36"),
	schema.MustPrefix("23.161.104.0/24"), schema.MustPrefix("10.0.0.0/8"),
}

// segments draws cap.segment, an End.DT46 entry half the time delivering to
// egress through an allow list holding an IPv6 prefix and up to three more
func segments() hegel.Generator[srv6.Segments] {
	local := hegel.Composite(func(tc hegel.TestCase) srv6.Segment {
		segment := srv6.Segment{
			SID:      hegel.Draw(tc, segmentAddresses()),
			Behavior: hegel.Draw(tc, hegel.SampledFrom([]srv6.Behavior{srv6.BehaviorEnd, srv6.BehaviorEndDT46})),
		}
		if segment.Behavior == srv6.BehaviorEndDT46 && hegel.Draw(tc, hegel.Booleans()) {
			segment.Deliver = srv6.DeliverEgress
			segment.Allow = []schema.Prefix{allowPool[0]}
			for _, prefix := range hegel.Draw(tc, hegel.Lists(hegel.SampledFrom(allowPool[1:])).MaxSize(3)) {
				if !slices.Contains(segment.Allow, prefix) {
					segment.Allow = append(segment.Allow, prefix)
				}
			}
		}
		return segment
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

// cryptos draws cap.crypto, each list left out or a run of distinct names it takes in drawn order
// a rekey interval holds any margin and jitter drawn beside it
// and the first retry never passes the last, whichever of each pair is left at its default
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
			IKE: ike.IKESuites{Cipher: pbt.List(tc, cipherNames), PRF: pbt.List(tc, prfNames), Kex: pbt.List(tc, kexEntries)},
			ESP: ike.ESPSuites{Cipher: pbt.List(tc, cipherNames)},
		}
	})
}

// the names each cap.crypto list takes, cipher and prf in the order a list left out holds them
var (
	cipherNames = []string{"aes256gcm", "aes128gcm", "chacha20poly1305"}
	prfNames    = []string{"sha384", "sha256"}
	kexNames    = []string{"x25519", "p384", "p256"}
	// postQuantum are the key exchanges a kex entry joins after a classical one
	postQuantum = []string{"mlkem768", "mlkem1024"}
)

// kexEntries are the entries cap.crypto ike kex takes, each classical key exchange alone or joined by one ML-KEM method
var kexEntries = slices.Concat(kexNames,
	[]string{"x25519+mlkem768", "p384+mlkem768", "p256+mlkem768", "x25519+mlkem1024", "p384+mlkem1024", "p256+mlkem1024"})

// strangers are names no cap.crypto list takes
var strangers = []string{"", "mlkem512", "aes192gcm", "AES256GCM", "sha512", "x448", "p521", " x25519", "MLKEM768"}

// cryptoList is one cap.crypto list, under block and key in a file and named field in a refusal
type cryptoList struct {
	block, key, field string
	every             []string
}

var cryptoLists = []cryptoList{
	{"ike", "cipher", "ike cipher", cipherNames},
	{"ike", "prf", "ike prf", prfNames},
	{"ike", "kex", "ike kex", kexEntries},
	{"esp", "cipher", "esp cipher", cipherNames},
}

// defects names each defect a list can be written with, the list empty, a name written twice, a name the list does not take or one it takes in capitals
// a kex entry can also join a classical key exchange, join more than one, join a name no list takes or lead with an ML-KEM name
func defects(list cryptoList) []string {
	if list.key == "kex" {
		return []string{"empty", "twice", "unknown", "capitals", "classical", "chained", "stranger", "leading"}
	}
	return []string{"empty", "twice", "unknown", "capitals"}
}

// defective is a run of names list takes with the defect kind drawn into it, with the words its refusal carries
func defective(tc hegel.TestCase, list cryptoList, kind string) ([]string, string) {
	names := pbt.Subset(tc, list.every, 1, len(list.every))
	insert := func(entry string) []string {
		at := hegel.Draw(tc, hegel.Integers(0, len(names)))
		return slices.Insert(names, at, entry)
	}
	switch kind {
	case "empty":
		return []string{}, fmt.Sprintf("cap.crypto %s is empty", list.field)
	case "twice":
		at := hegel.Draw(tc, hegel.Integers(0, len(names)-1))
		again := at + 1
		// half the time a name stands between the two, which a check of the neighbor alone misses
		if len(names) > 1 && hegel.Draw(tc, hegel.Booleans()) {
			at = hegel.Draw(tc, hegel.Integers(0, len(names)-2))
			again = hegel.Draw(tc, hegel.Integers(at+2, len(names)))
		}
		return slices.Insert(names, again, names[at]), fmt.Sprintf("cap.crypto %s names %s twice", list.field, names[at])
	case "unknown":
		var others []string
		for _, name := range slices.Concat(cipherNames, prfNames, kexEntries, postQuantum, strangers) {
			if !slices.Contains(list.every, name) && !(list.key == "kex" && slices.Contains(postQuantum, name)) && !slices.Contains(others, name) {
				others = append(others, name)
			}
		}
		name := hegel.Draw(tc, hegel.SampledFrom(others))
		return insert(name), fmt.Sprintf("cap.crypto %s names %q, which is not one of", list.field, name)
	case "capitals":
		name := strings.ToUpper(hegel.Draw(tc, hegel.SampledFrom(list.every)))
		// a joined entry is refused by its first name, the first it does not take
		if first, _, joined := strings.Cut(name, "+"); joined {
			return insert(name), fmt.Sprintf("cap.crypto ike kex entry %q names %q, which is not one of", name, first)
		}
		return insert(name), fmt.Sprintf("cap.crypto %s names %q, which is not one of", list.field, name)
	case "classical":
		joined := hegel.Draw(tc, hegel.SampledFrom(kexNames))
		entry := hegel.Draw(tc, hegel.SampledFrom(kexNames)) + "+" + joined
		return insert(entry), fmt.Sprintf("cap.crypto ike kex entry %q joins %s, and an entry joins only an ML-KEM method after its first", entry, joined)
	case "chained":
		joined := hegel.Draw(tc, hegel.Lists(hegel.SampledFrom(slices.Concat(postQuantum, kexNames))).MinSize(2).MaxSize(3))
		entry := strings.Join(slices.Concat([]string{hegel.Draw(tc, hegel.SampledFrom(kexNames))}, joined), "+")
		return insert(entry), fmt.Sprintf("cap.crypto ike kex entry %q joins %d key exchanges after its first, and an entry joins one", entry, len(joined))
	case "stranger":
		// a name no list takes, joined after a classical key exchange or leading one an entry joins
		stranger := hegel.Draw(tc, hegel.SampledFrom(strangers))
		entry := hegel.Draw(tc, hegel.SampledFrom(kexNames)) + "+" + stranger
		if hegel.Draw(tc, hegel.Booleans()) {
			entry = stranger + "+" + hegel.Draw(tc, hegel.SampledFrom(slices.Concat(postQuantum, kexNames)))
		}
		return insert(entry), fmt.Sprintf("cap.crypto ike kex entry %q names %q, which is not one of", entry, stranger)
	default:
		leading := hegel.Draw(tc, hegel.SampledFrom(postQuantum))
		entry := leading
		if hegel.Draw(tc, hegel.Booleans()) {
			entry += "+" + hegel.Draw(tc, hegel.SampledFrom(kexNames))
		}
		return insert(entry), fmt.Sprintf("cap.crypto ike kex entry %q starts with %s, which runs only after a classical key exchange", entry, leading)
	}
}

// cryptoFile is the test node with a cap.crypto block writing each of lists that is not nil under its key, in the format of extension
func cryptoFile(extension string, lists [][]string) string {
	type entry struct{ key, value string }
	blocks := map[string][]entry{}
	for i, list := range cryptoLists {
		if lists[i] == nil {
			continue
		}
		quoted := make([]string, len(lists[i]))
		for j, name := range lists[i] {
			quoted[j] = strconv.Quote(name)
		}
		blocks[list.block] = append(blocks[list.block], entry{list.key, "[" + strings.Join(quoted, ", ") + "]"})
	}
	if extension == ".toml" {
		var b strings.Builder
		b.WriteString(nodeTOML + "[cap.crypto]\n")
		for _, block := range []string{"ike", "esp"} {
			if len(blocks[block]) > 0 {
				fmt.Fprintf(&b, "[cap.crypto.%s]\n", block)
			}
			for _, e := range blocks[block] {
				fmt.Fprintf(&b, "%s = %s\n", e.key, e.value)
			}
		}
		return b.String()
	}
	// a flow mapping of double quoted strings reads the same as yaml and as json
	var objects []string
	for _, block := range []string{"ike", "esp"} {
		if len(blocks[block]) == 0 {
			continue
		}
		var members []string
		for _, e := range blocks[block] {
			members = append(members, fmt.Sprintf("%q: %s", e.key, e.value))
		}
		objects = append(objects, fmt.Sprintf("%q: {%s}", block, strings.Join(members, ", ")))
	}
	crypto := "{" + strings.Join(objects, ", ") + "}"
	if extension == ".yaml" {
		return nodeYAML + "cap:\n  crypto: " + crypto + "\n"
	}
	return `{"node": "example/laptop", "auth": {"key": "key.pem", "trust": "trust.json"},
"link": {"port": 13000, "endpoints": [{"serial": "0", "family": "ip4"}]}, "dial": {"to": ["example/gateway"]},
"cap": {"crypto": ` + crypto + `}}`
}

// the four cap.crypto lists load as written, names and order, in each of the three formats, where each is left out or a run of distinct names it takes
// one defect drawn into one list is refused, naming the list and the defect, for each list and each defect it can carry
func TestCryptoListsLoadAsWrittenOrAreRefusedByName(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		written := make([][]string, len(cryptoLists))
		for i, list := range cryptoLists {
			written[i] = pbt.List(ht, list.every)
		}
		extension := hegel.Draw(ht, hegel.SampledFrom([]string{".toml", ".yaml", ".json"}))
		for at, list := range cryptoLists {
			for _, kind := range defects(list) {
				lists := slices.Clone(written)
				var want string
				lists[at], want = defective(ht, list, kind)
				if _, err := load(ht, extension, cryptoFile(extension, lists)); err == nil || !strings.Contains(err.Error(), want) {
					ht.Fatalf("a %s file was refused with %v, want %q", extension, err, want)
				}
			}
		}
		cfg, err := load(ht, extension, cryptoFile(extension, written))
		if err != nil {
			ht.Fatalf("a %s file writing %q was refused: %v", extension, written, err)
		}
		read := [][]string{cfg.Cap.Crypto.IKE.Cipher, cfg.Cap.Crypto.IKE.PRF, cfg.Cap.Crypto.IKE.Kex, cfg.Cap.Crypto.ESP.Cipher}
		for i, list := range cryptoLists {
			if !slices.Equal(read[i], written[i]) || (read[i] == nil) != (written[i] == nil) {
				ht.Fatalf("a %s file writing %s %q read back %q", extension, list.field, written[i], read[i])
			}
		}
	})
}

// each format reads a list written as [] as a list holding nothing
// the loader refuses that list
// a list left out reads as the default
func TestEmptyCryptoListIsRefusedInEveryFormat(t *testing.T) {
	for _, extension := range []string{".toml", ".yaml", ".json"} {
		for i, list := range cryptoLists {
			lists := make([][]string, len(cryptoLists))
			lists[i] = []string{}
			if _, err := load(t, extension, cryptoFile(extension, lists)); err == nil || !strings.Contains(err.Error(), "cap.crypto "+list.field+" is empty") {
				t.Errorf("a %s file writing %s empty drew %v, want it refused as empty", extension, list.field, err)
			}
		}
		if _, err := load(t, extension, cryptoFile(extension, make([][]string, len(cryptoLists)))); err != nil {
			t.Errorf("a %s file leaving every list out was refused: %v", extension, err)
		}
	}
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

// overlayPool is the prefixes a drawn cap.border overlay is taken from, each
// a length the loader takes, together covering every entry of allowPool
var overlayPool = []schema.Prefix{
	schema.MustPrefix("3fff::/20"), schema.MustPrefix("2602:f590::/36"),
	schema.MustPrefix("23.161.104.0/24"), schema.MustPrefix("10.0.0.0/8"), schema.MustPrefix("198.18.0.0/15"),
}

// borders draws cap.border from overlayPool, each entry once, and now and then
// with one entry added that Validate refuses by name: an IPv4 prefix in the
// mapped spelling, a zero length, a prefix shorter than its family's floor,
// host bits below the length, or an entry written twice
func borders() hegel.Generator[egress.Border] {
	refused := hegel.SampledFrom([]schema.Prefix{
		schema.MustPrefix("::ffff:198.18.0.0/111"), schema.MustPrefix("0.0.0.0/0"), schema.MustPrefix("::/0"),
		schema.MustPrefix("8.0.0.0/7"), schema.MustPrefix("2000::/11"), schema.MustPrefix("198.18.0.1/15"),
	})
	return hegel.Composite(func(tc hegel.TestCase) egress.Border {
		var overlay []schema.Prefix
		for _, prefix := range hegel.Draw(tc, hegel.Lists(hegel.SampledFrom(overlayPool)).MinSize(1).MaxSize(4)) {
			if !slices.Contains(overlay, prefix) {
				overlay = append(overlay, prefix)
			}
		}
		switch {
		case hegel.Draw(tc, hegel.WeightedBooleans(0.05)):
			overlay = append(overlay, hegel.Draw(tc, refused))
		case hegel.Draw(tc, hegel.WeightedBooleans(0.05)):
			overlay = append(overlay, overlay[0])
		}
		return egress.Border{Overlay: overlay}
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

// nodes draws what a configuration says about the node itself, auth.aliases
// half the time and every capability block left out.
func nodes() hegel.Generator[Config] {
	endpoint := hegel.Composite(func(tc hegel.TestCase) Endpoint {
		return Endpoint{Serial: hegel.Draw(tc, names()), Family: hegel.Draw(tc, hegel.SampledFrom([]string{"ip4", "ip6"}))}
	})
	return hegel.Composite(func(tc hegel.TestCase) Config {
		c := Config{
			Node: identityAt(tc, ""),
			Auth: Auth{Key: hegel.Draw(tc, paths()), Trust: hegel.Draw(tc, paths()), Aliases: hegel.Draw(tc, unset(aliasTables()))},
			Link: Link{
				Port:      hegel.Draw(tc, edges[uint16](1, math.MaxUint16)),
				Endpoints: hegel.Draw(tc, hegel.Lists(endpoint).MinSize(1).MaxSize(3)),
				Listen:    hegel.Draw(tc, hegel.Booleans()),
				// from the least IPv6 requires to the most one ESP-in-UDP datagram carries over IPv4
				// a steering list drawn beside it can take the least of these out of bounds, which Validate refuses
				MTU: hegel.Draw(tc, unset(edges[uint16](1280, 65470))),
				Underlay: transport.Underlay{
					Mark: hegel.Draw(tc, unset(edges[uint32](1, math.MaxUint32))),
					Bind: hegel.Draw(tc, hegel.Booleans()),
				},
			},
			Dial: Dial{
				All: hegel.Draw(tc, hegel.Booleans()),
				To:  hegel.Draw(tc, hegel.Lists(peers()).MaxSize(3)),
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
// cap.table address may be the unspecified address, a cap.segment steering
// selector may be a v4-mapped prefix, and an email address under auth.aliases
// may end at its last @.
func configurations() hegel.Generator[Config] {
	return hegel.Composite(func(tc hegel.TestCase) Config {
		c := hegel.Draw(tc, nodes())
		blocks := hegel.Draw(tc, hegel.SampledFrom([]presence{eachOnItsOwn, noBlock, everyBlock}))
		c.Cap = Caps{
			Route:   block(tc, blocks, routes()),
			Transit: block(tc, blocks, transits()),
			Babel:   block(tc, blocks, speakers()),
			Table:   block(tc, blocks, reconcilers()),
			Segment: block(tc, blocks, segments()),
			Crypto:  block(tc, blocks, cryptos()),
			Egress:  block(tc, blocks, exits()),
			Border:  block(tc, blocks, borders()),
		}
		// now and then cost.extra charges the node itself, which Validate refuses
		if c.Cap.Babel != nil && hegel.Draw(tc, hegel.WeightedBooleans(0.05)) {
			c.Cap.Babel.Cost.Extra.Node = map[string]uint16{c.Node.String(): hegel.Draw(tc, edges[uint16](0, math.MaxUint16))}
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

// A configuration with any subset of its capability blocks, each written with
// values an operator could write, reaches the daemon unchanged whichever of
// the three encoders carried it. A field an encoder drops or rewrites is a
// setting the node never applies and nothing reports, and a block that goes
// missing turns a capability off.
//
// Only what Validate takes is held, and it is held through the loader rather
// than a decoder, so the checks run as they do for a file. A configuration
// the package accepts and then refuses once rendered is a failure: it is a
// node its own file will not start.
func TestGeneratedConfigurationSurvivesEachEncoder(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		drawn := hegel.Draw(ht, configurations())
		ht.Assume(drawn.Validate() == nil)
		sameAfterEachEncoder(ht, drawn)
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
		ht.Assume(drawn.Validate() == nil)
		sameAfterEachEncoder(ht, drawn)
	})
}

// The same for auth.aliases, drawn on every node, mostly with entries Validate
// takes and, a quarter of the time, with one entry added that no handshake
// could use. That entry is an FQDN or an email address holding a terminator,
// as a remote key or as the ID a local entry writes, an FQDN beyond ASCII, a
// remote entry naming a node, or a local entry writing none or two of its four
// fields. A configuration carrying none of them reads back unchanged. One
// carrying one of them is refused by the table holding the entry, and since
// the configuration without it was taken, the refusal is the entry's own. A
// node drawn with two endpoints in a family and a local table is refused for
// that, where the same node without the table is taken, as is the table on
// the node keeping one endpoint of each family.
func TestValidatedAliasesReadBackFromTheirFile(t *testing.T) {
	// a terminator is any control character and the line and paragraph separators
	terminators := hegel.OneOf(
		hegel.SampledFrom([]rune{0, '\t', '\n', '\r', 0x1f, 0x7f, 0x80, 0x9f, 0x2028, 0x2029}),
		hegel.Filter(hegel.Integers[rune](0, 0x9f), unicode.IsControl),
	)
	beyondASCII := hegel.SampledFrom([]rune(strings.TrimLeftFunc(nameCharacters, func(r rune) bool { return r <= unicode.MaxASCII })))
	// insert puts r into written at a drawn place
	insert := func(ht *hegel.T, written string, r rune) string {
		at := hegel.Draw(ht, hegel.Integers(0, len(written)))
		return written[:at] + string(r) + written[at:]
	}
	pbt.Check(t, func(ht *hegel.T) {
		drawn := hegel.Draw(ht, nodes())
		drawn.Dial.All = true
		drawn.Auth.Aliases = hegel.Draw(ht, aliasTables())
		// a node with two endpoints in a family presents no alias, and its tables are otherwise ones Validate takes
		inFamily := map[string]int{}
		for _, endpoint := range drawn.Link.Endpoints {
			inFamily[endpoint.Family]++
		}
		for family, count := range inFamily {
			if count < 2 || len(drawn.Auth.Aliases.Local) == 0 {
				continue
			}
			bare := drawn
			bare.Auth.Aliases.Local = nil
			ht.Assume(bare.Validate() == nil)
			single := drawn
			single.Link.Endpoints = nil
			for _, endpoint := range drawn.Link.Endpoints {
				if !slices.ContainsFunc(single.Link.Endpoints, func(kept Endpoint) bool { return kept.Family == endpoint.Family }) {
					single.Link.Endpoints = append(single.Link.Endpoints, endpoint)
				}
			}
			ht.Assume(single.Validate() == nil)
			want := fmt.Sprintf("auth.aliases.local is refused on a node whose link.endpoints holds %d endpoints of the %s family", count, family)
			if err := drawn.Validate(); err == nil || !strings.Contains(err.Error(), want) {
				ht.Fatalf("a node with %d endpoints in %s presenting %v was answered %v, want a refusal naming %q", count, family, drawn.Auth.Aliases.Local, err, want)
			}
			return
		}
		ht.Assume(drawn.Validate() == nil)
		if !hegel.Draw(ht, hegel.WeightedBooleans(0.25)) {
			sameAfterEachEncoder(ht, drawn)
			return
		}

		// one entry no handshake could use, added to a configuration Validate took
		// without it, in a copy of the table it goes in
		injected, aliases := drawn, drawn.Auth.Aliases
		addRemote := func(kind, written string, endpoint identity.Identity) string {
			tables := map[string]*map[string]identity.Identity{
				"ip": &aliases.Remote.IP, "fqdn": &aliases.Remote.FQDN, "email": &aliases.Remote.Email, "keyid": &aliases.Remote.KeyID,
			}
			added := maps.Clone(*tables[kind])
			if added == nil {
				added = make(map[string]identity.Identity)
			}
			added[written] = endpoint
			*tables[kind] = added
			return "auth.aliases.remote." + kind
		}
		addLocal := func(entry ike.LocalAlias) string {
			added := maps.Clone(aliases.Local)
			if added == nil {
				added = make(map[string]ike.LocalAlias)
			}
			added[hegel.Draw(ht, peers()).String()] = entry
			aliases.Local = added
			return "auth.aliases.local"
		}
		endpoint := identityAt(ht, hegel.Draw(ht, names()))
		var table, what string
		switch hegel.Draw(ht, hegel.Integers(0, 5)) {
		case 0:
			kind := hegel.Draw(ht, hegel.SampledFrom([]string{"fqdn", "email"}))
			table, what = addRemote(kind, insert(ht, hegel.Draw(ht, aliasIDs(kind)), hegel.Draw(ht, terminators)), endpoint), "a remote key holding a terminator"
		case 1:
			kind := hegel.Draw(ht, hegel.SampledFrom([]string{"fqdn", "email"}))
			table, what = addLocal(localAlias(kind, insert(ht, hegel.Draw(ht, aliasIDs(kind)), hegel.Draw(ht, terminators)))), "a local ID holding a terminator"
		case 2:
			written := insert(ht, hegel.Draw(ht, hostnames()), hegel.Draw(ht, beyondASCII))
			if hegel.Draw(ht, hegel.Booleans()) {
				table, what = addRemote("fqdn", written, endpoint), "a remote FQDN beyond ASCII"
			} else {
				table, what = addLocal(localAlias("fqdn", written)), "a local FQDN beyond ASCII"
			}
		case 3:
			kind := hegel.Draw(ht, hegel.SampledFrom(aliasKinds))
			table, what = addRemote(kind, hegel.Draw(ht, aliasIDs(kind)), endpoint.Node()), "a remote entry naming a node"
		case 4:
			table, what = addLocal(ike.LocalAlias{}), "a local entry writing no ID"
		default:
			entry := localAlias(hegel.Draw(ht, hegel.SampledFrom(aliasKinds[:3])), "x")
			entry.KeyID = hegel.Draw(ht, aliasIDs("keyid"))
			table, what = addLocal(entry), "a local entry writing two IDs"
		}
		injected.Auth.Aliases = aliases
		err := injected.Validate()
		if err == nil {
			ht.Fatalf("Validate took %s", what)
		}
		if !strings.Contains(err.Error(), table) {
			ht.Fatalf("Validate refused %s with %q, which does not name %s", what, err, table)
		}
	})
}

// The same for cap.route, cap.babel and cap.segment, drawn mostly with values
// their own Validate takes and, a quarter of the time, with one value added
// that no file can write: an announcement whose prefix or source has no
// spelling, a link quality other than etx and none, which is written as etx,
// a cost.extra organization that is not UTF-8, or a steering selector that is set and is not a prefix. A configuration
// carrying none of them reads back unchanged. One carrying one of them has to
// be refused, and since the configuration without it was taken, the refusal
// is the value's own. Most cases still reach the round trip rather than every
// one being refused.
func TestValidatedRouteSpeakerAndSegmentsReadBackFromTheirFile(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		drawn := hegel.Draw(ht, nodes())
		drawn.Dial.All = true
		route, speaker, segment := hegel.Draw(ht, routes()), hegel.Draw(ht, speakers()), hegel.Draw(ht, segments())
		// the overlay every local segment needs, covering every allow entry
		drawn.Cap = Caps{Route: &route, Babel: &speaker, Segment: &segment, Border: &egress.Border{Overlay: overlayPool}}
		ht.Assume(drawn.Validate() == nil)
		if !hegel.Draw(ht, hegel.WeightedBooleans(0.25)) {
			sameAfterEachEncoder(ht, drawn)
			return
		}

		// one value no file holds, added to a configuration Validate took
		// without it, in a copy of the block it goes in
		injected, what := drawn, ""
		switch hegel.Draw(ht, hegel.Integers(0, 4)) {
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
		case 3:
			added := speaker
			added.Cost.Extra.Org = maps.Clone(speaker.Cost.Extra.Org)
			if added.Cost.Extra.Org == nil {
				added.Cost.Extra.Org = make(map[string]uint16)
			}
			added.Cost.Extra.Org[hegel.Draw(ht, names())+"\xff"] = hegel.Draw(ht, edges[uint16](0, babel.MetricInfinity-1))
			injected.Cap.Babel, what = &added, "a cost.extra organization that is not UTF-8"
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

// mtuNode is a node that loads, with link.mtu written as mtu
// and with a cap.segment steering one source through segments waypoints when segments is above zero
func mtuNode(mtu uint16, segments int) Config {
	c := Config{
		Node: identity.MustParse("example/laptop"),
		Auth: Auth{Key: "key.pem", Trust: "trust.json"},
		Link: Link{Port: 13000, Endpoints: []Endpoint{{Serial: "0", Family: "ip4"}}, MTU: mtu},
		Dial: Dial{All: true},
	}
	if segments == 0 {
		return c
	}
	via := make([]schema.Addr, segments)
	for i := range via {
		via[i] = schema.AddrFrom(netip.AddrFrom16([16]byte{0x3f, 0xff, 0, 1, 15: byte(i + 1)}))
	}
	c.Cap.Segment = &srv6.Segments{
		Source: schema.MustAddr("3fff:1:69c:8c0::1"),
		Steer:  []srv6.Steer{{From: schema.MustPrefix("3fff:a::1/128"), Via: via}},
	}
	return c
}

// link.mtu is taken exactly from 1280 plus the header the longest steering list puts on a packet
// up to 65470, the most one ESP-in-UDP datagram carries over IPv4
// a refusal names the field, and an mtu that is taken reads back from its file through every encoder
// every list length meets the values either side of both of its bounds before anything is drawn
func TestLinkMTUIsTakenExactlyWithinItsBounds(t *testing.T) {
	// an outer IPv6 header, the fixed part of the segment routing header and 16 bytes a segment, RFC 8754
	floor := func(segments int) int {
		if segments == 0 {
			return 1280
		}
		return 1280 + 40 + 8 + 16*segments
	}
	check := func(tb testing.TB, mtu uint16, segments int) {
		tb.Helper()
		c := mtuNode(mtu, segments)
		inForce := int(mtu)
		if mtu == 0 {
			inForce = 1400
		}
		within := floor(segments) <= inForce && inForce <= 65470
		err := c.Validate()
		switch {
		case within && err != nil:
			tb.Fatalf("link.mtu %d with a list of %d segments was refused: %v", mtu, segments, err)
		case !within && err == nil:
			tb.Fatalf("link.mtu %d with a list of %d segments was taken, outside %d to 65470", mtu, segments, floor(segments))
		case err != nil && !strings.Contains(err.Error(), "link.mtu"):
			tb.Fatalf("the refusal of link.mtu %d with a list of %d segments reads %q, which does not name link.mtu", mtu, segments, err)
		case err == nil:
			sameAfterEachEncoder(tb, c)
		}
	}
	for segments := range srv6.MaxSegments + 1 {
		for _, mtu := range []int{0, floor(segments) - 1, floor(segments), 65470, 65471, math.MaxUint16} {
			check(t, uint16(mtu), segments)
		}
	}
	pbt.Check(t, func(ht *hegel.T) {
		segments := hegel.Draw(ht, pbt.Spanning(0, srv6.MaxSegments))
		check(ht, hegel.Draw(ht, pbt.Spanning[uint16](0, math.MaxUint16)), segments)
	})
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
	types := scalarTypes()
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

// a list or a mapping written where a scalar belongs is refused, for every scalar a configuration can write
// the text half of a scalar reads the empty text such a node leaves, and one that takes it for a default or a word ran quality: [none] as etx
func TestEveryScalarRefusesAListOrAMappingWrittenInItsPlace(t *testing.T) {
	types := scalarTypes()
	if len(types) < 8 {
		t.Fatalf("found %d scalar types, so the walk lost the ones a configuration carries: %v", len(types), types)
	}
	for _, ty := range types {
		for _, written := range []string{"[x]", "[]", "{}", "{ x: y }"} {
			holder := reflect.New(reflect.StructOf([]reflect.StructField{{Name: "V", Type: ty, Tag: `yaml:"v"`}}))
			if err := yaml.Unmarshal([]byte("v: "+written+"\n"), holder.Interface()); err == nil {
				t.Errorf("%s took %s as its value", ty, written)
			}
		}
	}
}

// schemaField is a field or a block a file writes, by the yaml keys that lead to it
// a key ending in [] holds a list, and the field is the one in its first entry
// a map field is followed by its value under the key mapEntry
// scalar is the type of a field that reads itself from text, and nil for any other
type schemaField struct {
	path             []string
	integer, boolean bool
	scalar           reflect.Type
}

// schemaFields finds every field under ty, by reflection so that a field added later is held as well
// a scalar that reads its own text is a field of its own, and the walk goes no further into it
func schemaFields(ty reflect.Type, path []string, found *[]schemaField) {
	for field := range ty.Fields() {
		if !field.IsExported() {
			continue
		}
		key := yamlKey(field)
		under := field.Type
		for under.Kind() == reflect.Pointer {
			under = under.Elem()
		}
		if under.Kind() == reflect.Slice {
			under, key = under.Elem(), key+"[]"
		}
		schemaValue(under, append(slices.Clone(path), key), found)
	}
}

const mapEntry = "entry"

func schemaValue(under reflect.Type, path []string, found *[]schemaField) {
	this := schemaField{path: path}
	switch {
	case reflect.PointerTo(under).Implements(reflect.TypeFor[encoding.TextUnmarshaler]()):
		this.scalar = under
	case under.Kind() >= reflect.Int && under.Kind() <= reflect.Uint64:
		this.integer = true
	case under.Kind() == reflect.Bool:
		this.boolean = true
	}
	*found = append(*found, this)
	switch {
	case this.scalar == nil && under.Kind() == reflect.Struct:
		schemaFields(under, path, found)
	case under.Kind() == reflect.Map && under.Key().Kind() == reflect.String:
		schemaValue(under.Elem(), append(slices.Clone(path), mapEntry), found)
	}
}

// scalarTypes is every distinct type a configuration file writes as one scalar, in a stable order
// each of them reads itself from text, the schema's and each capability's own
func scalarTypes() []reflect.Type {
	var fields []schemaField
	schemaFields(reflect.TypeFor[Config](), nil, &fields)
	found := make(map[reflect.Type]bool)
	for _, field := range fields {
		if field.scalar != nil {
			found[field.scalar] = true
		}
	}
	return slices.SortedFunc(maps.Keys(found), func(a, b reflect.Type) int { return strings.Compare(a.String(), b.String()) })
}

// nested writes a document that sets the field to value, in the flow syntax json and yaml share
// or in toml inline tables, which are the one nesting toml can write on a line
func (f schemaField) nested(value string, inTOML bool) string {
	for i := len(f.path) - 1; i >= 0; i-- {
		key, list := strings.CutSuffix(f.path[i], "[]")
		if list {
			value = "[" + value + "]"
		}
		switch {
		case i == 0 && inTOML:
			return key + " = " + value + "\n"
		case inTOML:
			value = "{ " + key + " = " + value + " }"
		default:
			value = `{"` + key + `": ` + value + "}"
		}
	}
	return value + "\n"
}

// readInteger reads the field out of a decoded configuration
func (f schemaField) readInteger(c Config) uint64 {
	value := reflect.ValueOf(c)
	for _, step := range f.path {
		key, list := strings.CutSuffix(step, "[]")
		for value.Kind() == reflect.Pointer && !value.IsNil() {
			value = value.Elem()
		}
		switch value.Kind() {
		case reflect.Struct:
			value = fieldByKey(value, key)
		case reflect.Map:
			value = value.MapIndex(reflect.ValueOf(key).Convert(value.Type().Key()))
		default:
			return 0
		}
		if list && value.Len() > 0 {
			value = value.Index(0)
		}
	}
	for value.Kind() == reflect.Pointer && !value.IsNil() {
		value = value.Elem()
	}
	if !value.IsValid() || !value.CanUint() {
		return 0
	}
	return value.Uint()
}

// a whole number is read alike by every decoder that can read it, wherever a file writes an integer
// the yaml decoder cut 13000.5, 1.3e4 and 13000.0 to 13000 and read -0 as zero, where encoding/json refuses all four
// json and toml each spell only some numbers, and a number one of them cannot spell is left out of its comparison
// toml takes a signed zero as the zero it is and the loader sees the number it hands over, so -0 is left out of that comparison
// every digit is read as a whole number first, which fits every field and has to be taken by all three
func TestEveryIntegerFieldReadsABareNumberAlike(t *testing.T) {
	var all, fields []schemaField
	schemaFields(reflect.TypeFor[Config](), nil, &all)
	for _, field := range all {
		if field.integer {
			fields = append(fields, field)
		}
	}
	if len(fields) < 8 {
		t.Fatalf("found %d integer fields, so the walk lost the ones a configuration carries: %v", len(fields), fields)
	}
	check := func(tb testing.TB, field schemaField, numeral string) {
		tb.Helper()
		var fromYAML Config
		yamlErr := decodeYAML([]byte(field.nested(numeral, false)), &fromYAML)
		yamlValue := field.readInteger(fromYAML)
		digit := len(numeral) == 1 && numeral[0] >= '0' && numeral[0] <= '9'
		if digit && (yamlErr != nil || yamlValue != uint64(numeral[0]-'0')) {
			tb.Fatalf("%v: yaml read %s as %d (%v)", field.path, numeral, yamlValue, yamlErr)
		}
		var parsed map[string]any
		if _, unspelled := toml.Decode("v = "+numeral+"\n", &parsed); unspelled == nil {
			var fromTOML Config
			tomlErr := decodeTOML([]byte(field.nested(numeral, true)), &fromTOML)
			tomlValue := field.readInteger(fromTOML)
			switch {
			case digit && (tomlErr != nil || tomlValue != yamlValue):
				tb.Fatalf("%v: toml read %s as %d (%v)", field.path, numeral, tomlValue, tomlErr)
			case numeral == "-0":
			case (tomlErr == nil) != (yamlErr == nil):
				tb.Fatalf("%v: %s is %v under yaml and %v under toml", field.path, numeral, yamlErr, tomlErr)
			case tomlErr == nil && tomlValue != yamlValue:
				tb.Fatalf("%v: %s reads as %d under yaml and %d under toml", field.path, numeral, yamlValue, tomlValue)
			}
		}
		if json.Valid([]byte(numeral)) {
			var overWire Config
			wireErr := json.Unmarshal([]byte(field.nested(numeral, false)), &overWire)
			wireValue := field.readInteger(overWire)
			switch {
			case (wireErr == nil) != (yamlErr == nil):
				tb.Fatalf("%v: %s is %v under yaml and %v over the wire", field.path, numeral, yamlErr, wireErr)
			case wireErr == nil && wireValue != yamlValue:
				tb.Fatalf("%v: %s reads as %d under yaml and %d over the wire", field.path, numeral, yamlValue, wireValue)
			}
		}
	}
	// every digit and every edge is read before anything is drawn, since a run leaves some of each undrawn
	for _, numeral := range slices.Concat(digits, edgeNumerals, []string{"13000.5", "1.3e4", "13000.0", "13000"}) {
		for _, field := range fields {
			check(t, field, numeral)
		}
	}
	pbt.Check(t, func(ht *hegel.T) {
		check(ht, fields[hegel.Draw(ht, hegel.Integers(0, len(fields)-1))], hegel.Draw(ht, numerals()))
	})
}

// a toml value of the wrong kind is refused wherever it is written, whichever key or block it is
// the decoder stops at the first value it cannot take, and the keys it had not reached are left to read as unknown ones
// a document of one key has nothing left for that, so the refusal has to be the decoder's own
func TestTOMLRefusesAValueOfTheWrongKindWhereverItIsWritten(t *testing.T) {
	var fields []schemaField
	schemaFields(reflect.TypeFor[Config](), nil, &fields)
	for _, field := range fields {
		wrong := "true"
		if field.boolean {
			wrong = `"x"`
		}
		document := field.nested(wrong, true)
		var c Config
		if err := decodeTOML([]byte(document), &c); err == nil {
			t.Errorf("toml took %q, which has the wrong kind for %v", strings.TrimSpace(document), field.path)
		}
	}
}

// a document after the first that does not parse is refused, behind any number of empty ones, under every extension that reads yaml
// the first document alone was taken and the failure of the second said nothing, so a half pasted file started on its first half
// every construct is tried once before anything is drawn, since a run leaves some of them undrawn
func TestDocumentAfterTheNodeThatDoesNotParseIsRefused(t *testing.T) {
	constructs := []func(word string) string{
		func(word string) string { return "link: [" + word + "\n" },
		func(word string) string { return "link: {" + word + "\n" },
		func(word string) string { return "\t" + word + ": x\n" },
		func(word string) string { return "link: *" + word + "\n" },
		func(word string) string { return `link: "` + word + "\n" },
		func(word string) string { return "- - [" + word + "\n" },
	}
	check := func(tb testing.TB, construct func(string) string, word string, empty int) {
		tb.Helper()
		body := nodeYAML + strings.Repeat("---\n", empty+1) + construct(word)
		for _, extension := range []string{".yaml", ".yml", ".json"} {
			if _, err := load(tb, extension, body); err == nil {
				tb.Fatalf("%s took %q, whose last document does not parse", extension, body)
			}
		}
	}
	for _, construct := range constructs {
		check(t, construct, "word", 0)
	}
	pbt.Check(t, func(ht *hegel.T) {
		word := hegel.Draw(ht, hegel.Text().Alphabet("abcdefghijklmnopqrstuvwxyz").MinSize(1).MaxSize(8))
		check(ht, constructs[hegel.Draw(ht, hegel.Integers(0, len(constructs)-1))], word, hegel.Draw(ht, hegel.Integers(0, 3)))
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
