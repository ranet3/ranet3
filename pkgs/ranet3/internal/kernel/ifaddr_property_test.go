// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package kernel

import (
	"encoding/binary"
	"encoding/hex"
	"maps"
	"net/netip"
	"slices"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// ifaddrNames are the interfaces a drawn host has, which take the indexes 1 to 4 in a drawn order
var ifaddrNames = []string{"en0", Loopback, "utun3", "utun9"}

// ifaddrPool holds the addresses a drawn interface takes a subset of, global and not, of both families
var ifaddrPool = []netip.Addr{
	netip.MustParseAddr("198.51.100.7"), netip.MustParseAddr("203.0.113.9"), netip.MustParseAddr("169.254.1.1"), netip.MustParseAddr("127.0.0.1"),
	netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("3fff::7"), netip.MustParseAddr("fe80::1"), netip.MustParseAddr("::1"),
}

// ifaddrOthers are two far ends of each family that are neither an address of the pool nor unspecified
var ifaddrOthers = map[bool][]netip.Addr{
	true:  {netip.MustParseAddr("192.0.2.77"), netip.MustParseAddr("192.0.2.66")},
	false: {netip.MustParseAddr("2001:db8:ff::7"), netip.MustParseAddr("2001:db8:ff::6")},
}

// ifaddrPair is the interface a drawn host may have beside ifaddrNames, whose two addresses carry far ends of their own or one between them
const ifaddrPair = "utun5"

// drawnHost draws the interfaces of a host and the mesh's index among them, zero for none
// the names take the indexes in a drawn order and each interface its addresses in a drawn order, so the read alone sorts what it reports
// each address draws its length with both ends outright, its far end as none, the unspecified address, the address itself or one of two
// others, and whether it is ready
// whether the host has ifaddrPair is drawn outright: up, point to point and never the mesh, it holds the two global addresses of a drawn
// family, ready, in either order, with one far end between them or the two others in either order
func drawnHost(ht *hegel.T) ([]HostInterface, int) {
	var out []HostInterface
	for i, name := range pbt.Subset(ht, ifaddrNames, len(ifaddrNames), len(ifaddrNames)) {
		flags := hegel.Draw(ht, pbt.Spanning[uint8](0, 7))
		device := HostInterface{Index: i + 1, Name: name, Up: flags&1 != 0, PointToPoint: flags&2 != 0, Loopback: flags&4 != 0}
		for _, local := range pbt.Subset(ht, ifaddrPool, 0, len(ifaddrPool)) {
			bits := int(hegel.Draw(ht, pbt.Spanning[uint8](0, uint8(local.BitLen()))))
			address := HostAddress{Prefix: netip.PrefixFrom(local, bits), Unready: hegel.Draw(ht, pbt.Spanning[uint8](0, 1)) == 1}
			switch far := hegel.Draw(ht, pbt.Spanning[uint8](0, 4)); far {
			case 1:
				address.Far = netip.IPv4Unspecified()
				if local.Is6() {
					address.Far = netip.IPv6Unspecified()
				}
			case 2:
				address.Far = local
			case 3, 4:
				address.Far = ifaddrOthers[local.Is4()][far-3]
			}
			device.Addresses = append(device.Addresses, address)
		}
		out = append(out, device)
	}
	mesh := int(hegel.Draw(ht, pbt.Spanning[uint8](0, uint8(len(ifaddrNames)))))
	if hegel.Draw(ht, pbt.Spanning[uint8](0, 1)) == 1 {
		is4 := hegel.Draw(ht, pbt.Spanning[uint8](0, 1)) == 1
		ends := [][]int{{0, 0}, {0, 1}, {1, 0}}[hegel.Draw(ht, pbt.Spanning[uint8](0, 2))]
		pair := HostInterface{Index: len(ifaddrNames) + 1, Name: ifaddrPair, Up: true, PointToPoint: true}
		for _, local := range ifaddrPool {
			if local.Is4() == is4 && local.IsGlobalUnicast() {
				far := ifaddrOthers[is4][ends[len(pair.Addresses)]]
				pair.Addresses = append(pair.Addresses, HostAddress{Prefix: netip.PrefixFrom(local, local.BitLen()), Far: far})
			}
		}
		if hegel.Draw(ht, pbt.Spanning[uint8](0, 1)) == 1 {
			slices.Reverse(pair.Addresses)
		}
		out = append(out, pair)
	}
	return out, mesh
}

// modelLinks is the links of one family a host holds, written from Linux's reader and XNU's rule for a point-to-point link
// a link is every up interface but the mesh's, and holds each global unicast address of the family that is ready, under its netmask's length,
// but for an IPv4 address on a point-to-point or loopback link, which XNU routes as a host
// a peer is the far end of an address on a point-to-point link, a host, where it is set and neither unspecified nor the address itself
func modelLinks(interfaces []HostInterface, mesh int, is4 bool) map[string]drawnLink {
	out := make(map[string]drawnLink)
	for _, device := range interfaces {
		if !device.Up || device.Index == mesh {
			continue
		}
		held, peers := make(map[netip.Prefix]bool), make(map[netip.Prefix]bool)
		for _, address := range device.Addresses {
			local := address.Prefix.Addr()
			if local.Is4() != is4 || !local.IsGlobalUnicast() || address.Unready {
				continue
			}
			if is4 && (device.PointToPoint || device.Loopback) {
				held[netip.PrefixFrom(local, 32)] = true
			} else {
				held[address.Prefix] = true
			}
			if device.PointToPoint && address.Far.IsValid() && !address.Far.IsUnspecified() && address.Far != local {
				peers[netip.PrefixFrom(address.Far, address.Far.BitLen())] = true
			}
		}
		out[device.Name] = drawnLink{prefixes: sortedKeys(held), peers: sortedKeys(peers)}
	}
	return out
}

func sortedKeys(set map[netip.Prefix]bool) []netip.Prefix {
	return slices.SortedFunc(maps.Keys(set), comparePrefixes)
}

// the links of each family are exactly the model's, sorted by name with sorted prefixes and peers, and the addresses are the set of the links'
func TestHostLinksAgreeWithAModel(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		interfaces, mesh := drawnHost(ht)
		v4, v6 := hostLinks(interfaces, mesh)
		for _, family := range []struct {
			is4 bool
			got NetworkFamily
		}{{true, v4}, {false, v6}} {
			want := modelLinks(interfaces, mesh, family.is4)
			names := slices.Sorted(maps.Keys(want))
			if len(family.got.Links) != len(names) {
				ht.Fatalf("IPv4 %v: %d links %+v, want %v", family.is4, len(family.got.Links), family.got.Links, want)
			}
			var addresses []netip.Addr
			for i, link := range family.got.Links {
				model := want[names[i]]
				if link.Name != names[i] || !slices.Equal(link.Prefixes, model.prefixes) || !slices.Equal(link.Peers, model.peers) {
					ht.Fatalf("IPv4 %v: link %d reads %+v, want %s with %v and peers %v, from %+v", family.is4, i, link, names[i], model.prefixes, model.peers, interfaces)
				}
				for _, prefix := range model.prefixes {
					if !slices.Contains(addresses, prefix.Addr()) {
						addresses = append(addresses, prefix.Addr())
					}
				}
			}
			slices.SortFunc(addresses, netip.Addr.Compare)
			if !slices.Equal(family.got.Addresses, addresses) {
				ht.Fatalf("IPv4 %v: the addresses read %v, want %v", family.is4, family.got.Addresses, addresses)
			}
		}
	})
}

// encodeAddrMessage is an RTM_NEWADDR as XNU's rt_msg2 writes one into an address dump: struct ifa_msghdr, then each sockaddr in RTAX order,
// each padded to four bytes and a zero length taking four
// the netmask is cut after its last nonzero byte, as in_socktrim cuts an IPv4 one, where trim is set
// last is the offset of the last sockaddr
func encodeAddrMessage(index uint16, prefix netip.Prefix, far netip.Addr, link string, trim bool) (raw []byte, last int) {
	sockaddr := func(address netip.Addr) []byte {
		if address.Is4() {
			out := make([]byte, 16)
			out[0], out[1] = 16, darwinAFInet
			copy(out[4:], address.AsSlice())
			return out
		}
		out := make([]byte, 28)
		out[0], out[1] = 28, darwinAFInet6
		copy(out[8:], address.AsSlice())
		return out
	}
	maskBytes := make([]byte, prefix.Addr().BitLen()/8)
	for i := range prefix.Bits() {
		maskBytes[i/8] |= 0x80 >> (i % 8)
	}
	mask, _ := netip.AddrFromSlice(maskBytes)
	netmask := sockaddr(mask)
	if trim && prefix.Addr().Is4() {
		netmask = netmask[:0]
		for i := 3; i >= 0; i-- {
			if maskBytes[i] != 0 {
				netmask = sockaddr(mask)[:4+i+1]
				netmask[0] = byte(4 + i + 1)
				break
			}
		}
	}
	slots := map[int][]byte{darwinNetmask: netmask, darwinIFA: sockaddr(prefix.Addr())}
	if link != "" {
		// struct sockaddr_dl, AF_LINK, with the interface's name and no link-level address
		dl := make([]byte, 8+len(link))
		dl[0], dl[1], dl[5] = byte(len(dl)), 18, byte(len(link))
		copy(dl[8:], link)
		slots[4] = dl
	}
	if far.IsValid() {
		slots[darwinBRD] = sockaddr(far)
	}
	raw = make([]byte, darwinIfaHeader)
	var present uint32
	for slot := range darwinRTAXMax {
		value, ok := slots[slot]
		if !ok {
			continue
		}
		present |= 1 << slot
		padded := make([]byte, sockaddrSpace(len(value)))
		copy(padded, value)
		last = len(raw)
		raw = append(raw, padded...)
	}
	binary.NativeEndian.PutUint16(raw, uint16(len(raw)))
	raw[2], raw[3] = darwinRTMVersion, darwinRTMNewAddr
	binary.NativeEndian.PutUint32(raw[4:], present)
	binary.NativeEndian.PutUint32(raw[8:], 0x101)
	binary.NativeEndian.PutUint16(raw[12:], index)
	return raw, last
}

// drawnAddr draws an address of one family a byte at a time
func drawnAddr(ht *hegel.T, is4 bool) netip.Addr {
	raw := make([]byte, 16)
	if is4 {
		raw = raw[:4]
	}
	for i := range raw {
		raw[i] = hegel.Draw(ht, pbt.Spanning[uint8](0, 255))
	}
	address, _ := netip.AddrFromSlice(raw)
	return address
}

// an address message decodes to the index, the address under its netmask's length and the far end it was encoded with, for every address,
// length and far end of either family, the netmask whole or cut, and the interface's link-level sockaddr there or not
// an IPv4 netmask of length zero, cut to a sockaddr of no bytes that takes four, is drawn outright
// a far end of the other family decodes to none, and a message of another version or type, one whose last sockaddr runs past its end, or one
// cut short by a byte does not decode
func TestAddrMessagesDecodeAsEncoded(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		zero := hegel.Draw(ht, pbt.Spanning[uint8](0, 3)) == 0
		is4 := zero || hegel.Draw(ht, pbt.Spanning[uint8](0, 1)) == 1
		address := drawnAddr(ht, is4)
		bits := 0
		if !zero {
			bits = int(hegel.Draw(ht, pbt.Spanning[uint8](0, uint8(address.BitLen()))))
		}
		prefix := netip.PrefixFrom(address, bits)
		index := binary.NativeEndian.Uint16([]byte{hegel.Draw(ht, pbt.Spanning[uint8](0, 255)), hegel.Draw(ht, pbt.Spanning[uint8](0, 255))})
		var far, wantFar netip.Addr
		switch hegel.Draw(ht, pbt.Spanning[uint8](0, 3)) {
		case 1:
			far = drawnAddr(ht, is4)
			wantFar = far
		case 2:
			far, wantFar = address, address
		case 3:
			far = drawnAddr(ht, !is4)
		}
		link := []string{"", "en0", "bridge100"}[hegel.Draw(ht, pbt.Spanning[uint8](0, 2))]
		trim := zero || hegel.Draw(ht, pbt.Spanning[uint8](0, 1)) == 1
		raw, last := encodeAddrMessage(index, prefix, far, link, trim)
		gotIndex, got, ok := decodeAddrMessage(raw)
		if !ok || gotIndex != int(index) || got != (HostAddress{Prefix: prefix, Far: wantFar}) {
			ht.Fatalf("%x decodes to %d %+v %v, want %d %s far %s", raw, gotIndex, got, ok, index, prefix, wantFar)
		}
		malformed := slices.Clone(raw)
		switch hegel.Draw(ht, pbt.Spanning[uint8](0, 2)) {
		case 0:
			malformed[2] ^= 1 + hegel.Draw(ht, pbt.Spanning[uint8](0, 254))
		case 1:
			malformed[3] ^= 1 + hegel.Draw(ht, pbt.Spanning[uint8](0, 254))
		case 2:
			malformed[last] = byte(len(raw)-last) + 1 + hegel.Draw(ht, pbt.Spanning[uint8](0, 200))
		}
		if _, _, ok := decodeAddrMessage(malformed); ok {
			ht.Fatalf("%x, a malformed %x, decodes", malformed, raw)
		}
		if _, _, ok := decodeAddrMessage(raw[:len(raw)-1]); ok {
			ht.Fatalf("%x cut short by a byte decodes", raw)
		}
	})
}

// four RTM_NEWADDR messages laid out byte for byte as a darwin host's address dump laid them out, with documentation addresses and indexes in
// place of the ones it carried: a utun's IPv4 address with its far end, a broadcast link's with its broadcast, both with the netmask cut, an
// IPv6 /64 whose broadcast slot is an empty sockaddr, and an IPv6 /128 with its far end
func TestRecordedAddrMessagesDecode(t *testing.T) {
	for _, recorded := range []struct {
		raw   string
		index int
		want  HostAddress
	}{
		{"3c00050ca400000001000000070000000000000007020000ffffff0010020000c0000201000000000000000010020000c00002020000000000000000",
			7, HostAddress{Prefix: netip.MustParsePrefix("192.0.2.1/24"), Far: netip.MustParseAddr("192.0.2.2")}},
		{"3c00050ca400000001010000090000000000000007020000ffffff0010020000c6336401000000000000000010020000c63364ff0000000000000000",
			9, HostAddress{Prefix: netip.MustParsePrefix("198.51.100.1/24"), Far: netip.MustParseAddr("198.51.100.255")}},
		{"5000050ca40000000001000007000000000000001c1e000000000000ffffffffffffffff0000000000000000000000001c1e00000000000020010db80005000000000000000000010000000000000000",
			7, HostAddress{Prefix: netip.MustParsePrefix("2001:db8:5::1/64")}},
		{"6800050ca40000000100000007000000000000001c1e000000000000ffffffffffffffffffffffffffffffff000000001c1e00000000000020010db8000500000000000000000009000000001c1e00000000000020010db800050000000000000000000a00000000",
			7, HostAddress{Prefix: netip.MustParsePrefix("2001:db8:5::9/128"), Far: netip.MustParseAddr("2001:db8:5::a")}},
	} {
		raw, err := hex.DecodeString(recorded.raw)
		if err != nil {
			t.Fatal(err)
		}
		index, got, ok := decodeAddrMessage(raw)
		if !ok || index != recorded.index || got != recorded.want {
			t.Errorf("%s decodes to %d %+v %v, want %d %+v", recorded.raw, index, got, ok, recorded.index, recorded.want)
		}
	}
}
