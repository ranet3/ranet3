// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package kernel

import (
	"encoding/binary"
	"net"
	"net/netip"
	"slices"
	"strings"
)

// darwin's address messages, built on Linux too so the properties of their decoding run there
// the numbers are XNU's ABI (net/route.h, sys/socket.h), which Linux's constants of the same names do not share
const (
	darwinRTMVersion = 5
	darwinRTMNewAddr = 0xc
	darwinAFInet     = 2
	darwinAFInet6    = 30
	// darwinIfaHeader is sizeof(struct ifa_msghdr), the sockaddrs following it in RTAX order
	darwinIfaHeader = 20
	darwinRTAXMax   = 8
	darwinNetmask   = 2
	darwinIFA       = 5
	darwinBRD       = 7
)

// decodeAddrMessage reads one RTM_NEWADDR of darwin's address dump: the interface's index, and the address under the length of its netmask with
// RTAX_BRD beside it
// false is a message of another type or version, one shorter than its sockaddrs, or one whose address or netmask does not decode
func decodeAddrMessage(raw []byte) (int, HostAddress, bool) {
	if len(raw) < darwinIfaHeader || int(binary.NativeEndian.Uint16(raw)) != len(raw) || raw[2] != darwinRTMVersion || raw[3] != darwinRTMNewAddr {
		return 0, HostAddress{}, false
	}
	present := binary.NativeEndian.Uint32(raw[4:])
	var slots [darwinRTAXMax][]byte
	rest := raw[darwinIfaHeader:]
	for slot := range darwinRTAXMax {
		if present&(1<<slot) == 0 {
			continue
		}
		if len(rest) == 0 || int(rest[0]) > len(rest) {
			return 0, HostAddress{}, false
		}
		slots[slot] = rest[:rest[0]]
		rest = rest[min(sockaddrSpace(int(rest[0])), len(rest)):]
	}
	address, ok := sockaddrAddress(slots[darwinIFA])
	if !ok {
		return 0, HostAddress{}, false
	}
	bits, ok := netmaskLength(slots[darwinNetmask], address)
	if !ok {
		return 0, HostAddress{}, false
	}
	out := HostAddress{Prefix: netip.PrefixFrom(address, bits)}
	if far, ok := sockaddrAddress(slots[darwinBRD]); ok && far.BitLen() == address.BitLen() {
		out.Far = far
	}
	return int(binary.NativeEndian.Uint16(raw[12:])), out, true
}

// sockaddrSpace is the room one sockaddr of length size takes in a routing message, ROUNDUP32 in XNU's rtsock.c, which gives a zero length four
func sockaddrSpace(size int) int {
	if size == 0 {
		return 4
	}
	return (size + 3) &^ 3
}

// sockaddrAddress is the address a sockaddr_in or sockaddr_in6 holds
func sockaddrAddress(sockaddr []byte) (netip.Addr, bool) {
	switch {
	case len(sockaddr) >= 8 && sockaddr[1] == darwinAFInet:
		return netip.AddrFrom4([4]byte(sockaddr[4:8])), true
	case len(sockaddr) >= 24 && sockaddr[1] == darwinAFInet6:
		return netip.AddrFrom16([16]byte(sockaddr[8:24])), true
	}
	return netip.Addr{}, false
}

// netmaskLength is the length of a netmask in address's family, which XNU may send cut after its last nonzero byte (in_socktrim)
func netmaskLength(sockaddr []byte, address netip.Addr) (int, bool) {
	if sockaddr == nil {
		return 0, false
	}
	offset := 4
	if address.Is6() {
		offset = 8
	}
	mask := make([]byte, address.BitLen()/8)
	if len(sockaddr) > offset {
		copy(mask, sockaddr[offset:])
	}
	value, _ := netip.AddrFromSlice(mask)
	return maskBits(value)
}

// maskBits is the length of a netmask. A mask whose ones are not contiguous
// denotes no prefix at all, which net.IPMask.Size reports as a zero total.
func maskBits(mask netip.Addr) (int, bool) {
	ones, total := net.IPMask(mask.AsSlice()).Size()
	if total == 0 {
		return 0, false
	}
	return ones, true
}

// hostLinks is the Links and Addresses of each family's NetworkFamily on darwin, read from the host's interfaces with the one of index mesh
// left out
func hostLinks(interfaces []HostInterface, mesh int) (v4, v6 NetworkFamily) {
	for _, device := range interfaces {
		if !device.Up || device.Index == mesh {
			continue
		}
		var held, far [2][]netip.Prefix
		for _, address := range device.Addresses {
			local := address.Prefix.Addr()
			if !local.IsGlobalUnicast() || address.Unready {
				continue
			}
			family, bits := 0, address.Prefix.Bits()
			if local.Is6() {
				family = 1
			}
			if device.PointToPoint && address.Far.IsValid() && !address.Far.IsUnspecified() && address.Far != local {
				far[family] = append(far[family], netip.PrefixFrom(address.Far, address.Far.BitLen()))
			}
			if local.Is4() && (device.PointToPoint || device.Loopback) {
				bits = local.BitLen()
			}
			held[family] = append(held[family], netip.PrefixFrom(local, bits))
		}
		for family, out := range []*NetworkFamily{&v4, &v6} {
			slices.SortFunc(held[family], comparePrefixes)
			slices.SortFunc(far[family], comparePrefixes)
			out.Links = append(out.Links, Link{Name: device.Name, Prefixes: held[family], Peers: slices.Compact(far[family])})
		}
	}
	for _, out := range []*NetworkFamily{&v4, &v6} {
		slices.SortFunc(out.Links, func(a, b Link) int { return strings.Compare(a.Name, b.Name) })
		out.Addresses = linkAddresses(out.Links)
	}
	return v4, v6
}

// linkAddresses is every address links carry, in the form diffFamily walks
func linkAddresses(links []Link) []netip.Addr {
	var out []netip.Addr
	for _, link := range links {
		for _, prefix := range link.Prefixes {
			out = append(out, prefix.Addr())
		}
	}
	return addressSet(out)
}
