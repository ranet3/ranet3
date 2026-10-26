// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"encoding/binary"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// the ways a drawn next hop names its gateway, beside a hop through its link
// that names none
const (
	viaGateway = iota + 1
	viaOtherFamily
)

// corruptedHopsDeadline bounds each read of an answer's hops, corrupted or
// ending in a last hop of unaligned length, which ends at once unless the read
// stops advancing
const corruptedHopsDeadline = 2 * time.Second

func drawAddress(tc hegel.TestCase, width int) netip.Addr {
	if width == 32 {
		return hegel.Draw(tc, hegel.IPAddresses().IPv4())
	}
	return hegel.Draw(tc, hegel.IPAddresses().IPv6())
}

// matchedAnswer lays out the answer to a route lookup as the kernel's
// fib_dump_info and rt6_fill_node do, the table in the header only where it
// fits and the destination and source left out at length 0
func matchedAnswer(tc hegel.TestCase, width, hops int, object uint32) (nlMessage, MatchedRoute, []uint32) {
	family := uint8(unix.AF_INET6)
	if width == 32 {
		family = unix.AF_INET
	}
	want := MatchedRoute{
		Prefix: netip.PrefixFrom(drawAddress(tc, width), hegel.Draw(tc, pbt.Spanning(0, width))).Masked(),
		Table:  hegel.Draw(tc, pbt.Spanning[uint32](0, math.MaxUint32)),
	}
	kind := hegel.Draw(tc, pbt.Spanning[uint8](0, math.MaxUint8))
	want.Type = fmt.Sprintf("type %d", kind)
	if int(kind) < len(routeTypes) {
		want.Type = routeTypes[kind]
	}
	header := make([]byte, unix.SizeofRtMsg)
	header[0], header[1], header[7] = family, uint8(want.Prefix.Bits()), kind
	header[4] = unix.RT_TABLE_COMPAT
	if want.Table < 256 {
		header[4] = uint8(want.Table)
	}
	flags := hegel.Draw(tc, hegel.Integers[uint32](0, math.MaxUint32))
	binary.NativeEndian.PutUint32(header[8:], flags)
	var attrs [][]byte
	attrs = append(attrs, putAttrU32(nil, unix.RTA_TABLE, want.Table))
	if object != 0 {
		attrs = append(attrs, putAttrU32(nil, rtaNHID, object))
	}
	if want.Prefix.Bits() > 0 {
		attrs = append(attrs, putAttr(nil, unix.RTA_DST, addressBytes(want.Prefix.Addr())))
	}
	if width == 128 && hegel.Draw(tc, hegel.Booleans()) {
		want.Source = netip.PrefixFrom(drawAddress(tc, width), hegel.Draw(tc, pbt.Spanning(1, width))).Masked()
		header[2] = uint8(want.Source.Bits())
		attrs = append(attrs, putAttr(nil, unix.RTA_SRC, addressBytes(want.Source.Addr())))
	}
	attrs = append(attrs,
		putAttrU32(nil, unix.RTA_PRIORITY, hegel.Draw(tc, hegel.Integers[uint32](0, math.MaxUint32))),
		putAttr(nil, unix.RTA_PREFSRC, addressBytes(drawAddress(tc, width))))

	offset := hegel.Draw(tc, hegel.Integers(0, 2))
	var multipath []byte
	var indexes []uint32
	for i := range hops {
		index := hegel.Draw(tc, pbt.Spanning[uint32](1, math.MaxInt32))
		indexes = append(indexes, index)
		var hop NextHop
		var gateway []byte
		switch (i + offset) % 3 {
		case viaGateway:
			hop.Gateway = drawAddress(tc, width)
			gateway = putAttr(nil, unix.RTA_GATEWAY, addressBytes(hop.Gateway))
		case viaOtherFamily:
			otherWidth, otherFamily := 128, uint16(unix.AF_INET6)
			if width == 128 {
				otherWidth, otherFamily = 32, unix.AF_INET
			}
			hop.Gateway = drawAddress(tc, otherWidth)
			via := binary.NativeEndian.AppendUint16(nil, otherFamily)
			gateway = putAttr(nil, unix.RTA_VIA, append(via, addressBytes(hop.Gateway)...))
		}
		if hops == 1 {
			hop.Dead, hop.LinkDown = flags&unix.RTNH_F_DEAD != 0, flags&unix.RTNH_F_LINKDOWN != 0
			want.NextHops = append(want.NextHops, hop)
			attrs = append(attrs, putAttrU32(nil, unix.RTA_OIF, index))
			if gateway != nil {
				attrs = append(attrs, gateway)
			}
			continue
		}
		nexthop := make([]byte, unix.SizeofRtNexthop, unix.SizeofRtNexthop+len(gateway))
		binary.NativeEndian.PutUint16(nexthop, uint16(unix.SizeofRtNexthop+len(gateway)))
		nexthop[2], nexthop[3] = hegel.Draw(tc, hegel.Integers[uint8](0, math.MaxUint8)), hegel.Draw(tc, hegel.Integers[uint8](0, math.MaxUint8))
		hop.Dead, hop.LinkDown = nexthop[2]&unix.RTNH_F_DEAD != 0, nexthop[2]&unix.RTNH_F_LINKDOWN != 0
		want.NextHops = append(want.NextHops, hop)
		binary.NativeEndian.PutUint32(nexthop[4:], index)
		multipath = append(multipath, append(nexthop, gateway...)...)
	}
	if multipath != nil {
		attrs = append(attrs, putAttr(nil, unix.RTA_MULTIPATH, multipath))
	}
	// the decoder holds no order the kernel promises
	turn := hegel.Draw(tc, hegel.Integers(0, len(attrs)-1))
	data := header
	for _, attr := range append(attrs[turn:], attrs[:turn]...) {
		data = append(data, attr...)
	}
	return nlMessage{Kind: unix.RTM_NEWROUTE, Data: data}, want, indexes
}

// Every field of the route is decoded from the answer's layout, its prefixes,
// its type, the table past the header's one byte, and every next hop a
// multipath route leaves by with the kernel's marks on it and a gateway of the
// other family too. A route that names a nexthop object and none of its hops
// is not read as a route without one
func TestRouteGetDecodesTheAnswerAsTheKernelLaysItOut(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		for _, width := range []int{32, 128} {
			for hops := range 4 {
				var object uint32
				if hegel.Draw(ht, hegel.Booleans()) {
					object = hegel.Draw(ht, pbt.Spanning[uint32](1, math.MaxUint32))
				}
				message, want, wantIndexes := matchedAnswer(ht, width, hops, object)
				got, indexes, err := decodeMatchedRoute(message)
				if object != 0 && hops == 0 {
					if err == nil {
						ht.Fatalf("an answer naming nexthop object %d and no hop decoded as %+v", object, got)
					}
					continue
				}
				if err != nil {
					ht.Fatalf("an answer of %d hops in a %d-bit family did not decode: %v", hops, width, err)
				}
				if got.Prefix != want.Prefix || got.Source != want.Source || got.Table != want.Table || got.Type != want.Type ||
					!slices.Equal(got.NextHops, want.NextHops) || !slices.Equal(indexes, wantIndexes) {
					ht.Fatalf("an answer of %d hops in a %d-bit family decoded as %+v through %v, want %+v through %v", hops, width, got, indexes, want, wantIndexes)
				}
			}
		}
	})
}

// A hop length short of a hop or one past the attribute's end, and a last hop
// cut short, end the hops of a route in an error, never in a read that stops
// advancing or one past the attribute. A last hop of unaligned length that ends
// the attribute is read with every hop before it and no error
func TestRouteNextHopsEndACorruptedMultipathInAnError(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		width := 32
		if hegel.Draw(ht, hegel.Booleans()) {
			width = 128
		}
		var payload []byte
		var starts []int
		for range hegel.Draw(ht, hegel.Integers(1, 3)) {
			starts = append(starts, len(payload))
			index := hegel.Draw(ht, pbt.Spanning[uint32](1, math.MaxUint32))
			flags := hegel.Draw(ht, hegel.Integers[uint8](0, math.MaxUint8))
			var gateway netip.Addr
			if hegel.Draw(ht, hegel.Booleans()) {
				gateway = drawAddress(ht, width)
			}
			payload = append(payload, nexthop(index, flags, gateway)...)
		}
		at := starts[hegel.Draw(ht, hegel.Integers(0, len(starts)-1))]
		var corrupted [][]byte
		for size := range unix.SizeofRtNexthop {
			hops := slices.Clone(payload)
			binary.NativeEndian.PutUint16(hops[at:], uint16(size))
			corrupted = append(corrupted, hops)
		}
		past := slices.Clone(payload)
		binary.NativeEndian.PutUint16(past[at:], uint16(len(past)-at+1))
		corrupted = append(corrupted, past)
		for cut := 1; cut < unix.SizeofRtNexthop; cut++ {
			corrupted = append(corrupted, slices.Concat(payload, nexthop(1, 0, netip.Addr{})[:cut]))
		}
		type walk struct {
			hops int
			err  error
		}
		read := func(hops []byte) walk {
			header := make([]byte, unix.SizeofRtMsg)
			header[0] = unix.AF_INET6
			if width == 32 {
				header[0] = unix.AF_INET
			}
			message := nlMessage{Kind: unix.RTM_NEWROUTE, Data: putAttr(header, unix.RTA_MULTIPATH, hops)}
			done := make(chan walk, 1)
			go func() {
				var got walk
				for _, err := range routeNextHops(message) {
					if err != nil {
						got.err = err
						continue
					}
					got.hops++
				}
				done <- got
			}()
			select {
			case got := <-done:
				return got
			case <-time.After(corruptedHopsDeadline):
				ht.Fatalf("the hops %x were still being read after %v", hops, corruptedHopsDeadline)
				return walk{}
			}
		}
		for _, hops := range corrupted {
			if read(hops).err == nil {
				ht.Fatalf("the corrupted hops %x were read without an error", hops)
			}
		}
		last := starts[len(starts)-1]
		for pad := 1; pad < unix.RTA_ALIGNTO; pad++ {
			hops := slices.Concat(payload, make([]byte, pad))
			binary.NativeEndian.PutUint16(hops[last:], uint16(len(hops)-last))
			if got := read(hops); got.err != nil || got.hops != len(starts) {
				ht.Fatalf("the hops %x, the last of unaligned length, were read as %d hops and %v, want %d and no error", hops, got.hops, got.err, len(starts))
			}
		}
	})
}
