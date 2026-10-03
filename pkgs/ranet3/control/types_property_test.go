// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package control

import (
	"encoding/json"
	"math"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

var (
	timeType   = reflect.TypeFor[time.Time]()
	addrType   = reflect.TypeFor[netip.Addr]()
	prefixType = reflect.TypeFor[netip.Prefix]()
)

// edges draws from lo through hi with both ends drawn on their own as well,
// since a derandomized run of a few hundred cases need not land on either.
func edges[T interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 | ~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64
}](lo, hi T) hegel.Generator[T] {
	return hegel.OneOf(hegel.Integers(lo, hi), hegel.Just(lo), hegel.Just(hi))
}

// instants draws a time a node reports: none at all, or an instant from 1970
// on, to the nanosecond, in UTC or under a fixed offset as time.Local gives
// one. The offsets are whole minutes, the finest RFC 3339 writes, and every
// zone in use today has one.
func instants() hegel.Generator[time.Time] {
	return hegel.OneOf(hegel.Just(time.Time{}), hegel.Composite(func(tc hegel.TestCase) time.Time {
		instant := time.Unix(hegel.Draw(tc, edges[int64](0, 1<<33)), hegel.Draw(tc, edges[int64](0, int64(time.Second)-1)))
		if hegel.Draw(tc, hegel.Booleans()) {
			return instant.UTC()
		}
		return instant.In(time.FixedZone("", 60*hegel.Draw(tc, edges(-14*60, 14*60))))
	}))
}

// addresses draws an address of either family, an IPv6 one sometimes carrying
// the zone a link-local neighbor is reached through, or none.
func addresses() hegel.Generator[netip.Addr] {
	return hegel.OneOf(hegel.Just(netip.Addr{}), hegel.Composite(func(tc hegel.TestCase) netip.Addr {
		address := hegel.Draw(tc, hegel.IPAddresses())
		if address.Is6() && hegel.Draw(tc, hegel.Booleans()) {
			address = address.WithZone(hegel.Draw(tc, hegel.Text().Alphabet("abcdefghijklmnopqrstuvwxyz0123456789").MinSize(1).MaxSize(8)))
		}
		return address
	}))
}

// prefixes draws a prefix of either family with whatever host bits it was
// given, or none.
func prefixes() hegel.Generator[netip.Prefix] {
	return hegel.OneOf(hegel.Just(netip.Prefix{}), hegel.Composite(func(tc hegel.TestCase) netip.Prefix {
		address := hegel.Draw(tc, hegel.IPAddresses())
		return netip.PrefixFrom(address, hegel.Draw(tc, edges(0, address.BitLen())))
	}))
}

// fill draws every exported field under value, by its kind rather than by
// its name, so a field added to a wire type later is drawn without anybody
// remembering to. A pointer is sometimes nil and a list sometimes empty, and an
// empty list is drawn as nil: a field written with omitempty leaves an empty
// one out, a reader gets nil back, and nothing reading it tells the two apart.
func fill(tc hegel.TestCase, value reflect.Value) {
	switch value.Type() {
	case timeType:
		value.Set(reflect.ValueOf(hegel.Draw(tc, instants())))
		return
	case addrType:
		value.Set(reflect.ValueOf(hegel.Draw(tc, addresses())))
		return
	case prefixType:
		value.Set(reflect.ValueOf(hegel.Draw(tc, prefixes())))
		return
	}
	switch value.Kind() {
	case reflect.String:
		value.SetString(hegel.Draw(tc, hegel.Text().MaxSize(16)))
	case reflect.Bool:
		value.SetBool(hegel.Draw(tc, hegel.Booleans()))
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		bits := value.Type().Bits()
		value.SetInt(hegel.Draw(tc, hegel.OneOf(edges[int64](-1<<(bits-1), 1<<(bits-1)-1), hegel.Just(int64(0)))))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		value.SetUint(hegel.Draw(tc, edges[uint64](0, math.MaxUint64>>(64-value.Type().Bits()))))
	case reflect.Pointer:
		if hegel.Draw(tc, hegel.Booleans()) {
			pointed := reflect.New(value.Type().Elem())
			fill(tc, pointed.Elem())
			value.Set(pointed)
		}
	case reflect.Slice:
		if length := hegel.Draw(tc, edges(0, 4)); length > 0 {
			list := reflect.MakeSlice(value.Type(), length, length)
			for i := range length {
				fill(tc, list.Index(i))
			}
			value.Set(list)
		}
	case reflect.Struct:
		for i := range value.NumField() {
			if value.Type().Field(i).IsExported() {
				fill(tc, value.Field(i))
			}
		}
	default:
		panic("fill has no draw for " + value.Type().String())
	}
}

// inUTC rewrites every time under value to the same instant in UTC. The wire
// carries a time's instant and its offset and nothing else, so a decoded time
// sits in a location of its own and the comparison has to be of instants,
// which is all a reader takes from one: Render asks how long ago a pass was.
func inUTC(value reflect.Value) {
	switch {
	case value.Type() == timeType:
		value.Set(reflect.ValueOf(value.Interface().(time.Time).UTC()))
	case value.Kind() == reflect.Pointer && !value.IsNil():
		inUTC(value.Elem())
	case value.Kind() == reflect.Slice:
		for i := range value.Len() {
			inUTC(value.Index(i))
		}
	case value.Kind() == reflect.Struct:
		for i := range value.NumField() {
			if value.Type().Field(i).IsExported() {
				inUTC(value.Field(i))
			}
		}
	}
}

// Every value the socket carries, the five reads and both halves of a write,
// decodes to the value it was encoded from, through encoding/json as the
// handler and the client use it. A field that came back changed is a
// node reporting something other than what it holds, to the operator and to
// any control plane reading it, and a write that came back changed is a verb
// acting on something nobody named.
func TestEveryWireTypeRoundTripsThroughJSON(t *testing.T) {
	for _, wire := range []any{Status{}, []Neighbor{}, []Route{}, []Session{}, []Peer{}, Request{}, Result{}} {
		kind := reflect.TypeOf(wire)
		t.Run(kind.String(), func(t *testing.T) {
			pbt.Check(t, func(ht *hegel.T) {
				want := reflect.New(kind).Elem()
				fill(ht, want)
				body, err := json.Marshal(want.Interface())
				if err != nil {
					ht.Fatalf("json refused %#v: %v", want.Interface(), err)
				}
				got := reflect.New(kind)
				if err := json.Unmarshal(body, got.Interface()); err != nil {
					ht.Fatalf("json wrote %s and refused it back: %v", body, err)
				}
				inUTC(want)
				inUTC(got.Elem())
				if !reflect.DeepEqual(got.Elem().Interface(), want.Interface()) {
					ht.Fatalf("json wrote %s for\n%#v\nand read it back as\n%#v", body, want.Interface(), got.Elem().Interface())
				}
			})
		})
	}
}
