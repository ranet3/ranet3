// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package kernel

import (
	"encoding/binary"
	"net"
	"net/netip"
	"slices"
	"strconv"
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

// the ia6_flags of an IPv6 address (netinet6/in6_var.h), which SIOCGIFAFLAG_IN6 reads: TENTATIVE or OPTIMISTIC while duplicate address
// detection runs (IN6_IFF_DADPROGRESS), and DUPLICATED once it found the address in use
const (
	in6IffTentative  = 0x2
	in6IffDuplicated = 0x4
	in6IffOptimistic = 0x200
)

// darwin's kernel events of the network class (sys/kern_event.h, net/net_kev.h, net/if_var.h)
const (
	darwinKEVVendorApple  = 1
	darwinKEVNetworkClass = 1
	// the subclasses whose events can move a link, each event's data starting with struct net_event_data
	darwinKEVInet  = 1
	darwinKEVDL    = 2
	darwinKEVInet6 = 6
	darwinKEVND6   = 7
	// darwinKEVHeader is KEV_MSG_HEADER_SIZE, struct kern_event_msg up to event_data: total_size, vendor_code, kev_class, kev_subclass, id
	// and event_code, a 32-bit word each
	darwinKEVHeader = 24
	// darwinNetEventData is sizeof(struct net_event_data): if_family, if_unit, and if_name of IFNAMSIZ bytes
	darwinNetEventData = 24
)

// kernelEvent is the header of one struct kern_event_msg
type kernelEvent struct {
	vendor, class, subclass uint32
	// link is the interface the event's net_event_data names, its driver's name and unit, empty where the data names none
	link string
}

// decodeKernelEvent reads the one event a read of a kernel event socket holds, the socket being PR_ATOMIC and each event a record of its
// own (bsd/kern/kern_event.c, eventsw and kev_post_msg_internal)
// false is a read shorter than the header, or one whose total_size is not its length
func decodeKernelEvent(raw []byte) (kernelEvent, bool) {
	if len(raw) < darwinKEVHeader || int(binary.NativeEndian.Uint32(raw)) != len(raw) {
		return kernelEvent{}, false
	}
	event := kernelEvent{
		vendor:   binary.NativeEndian.Uint32(raw[4:]),
		class:    binary.NativeEndian.Uint32(raw[8:]),
		subclass: binary.NativeEndian.Uint32(raw[12:]),
	}
	if data := raw[darwinKEVHeader:]; event.movesLink() && len(data) >= darwinNetEventData {
		name, _, _ := strings.Cut(string(data[8:darwinNetEventData]), "\x00")
		event.link = name + strconv.FormatUint(uint64(binary.NativeEndian.Uint32(data[4:])), 10)
	}
	return event, true
}

// movesLink reports whether the event is of a subclass that can bring a link, take it away or move its addresses
// NECP, NETPOLICY and the rest of the network class move none, and NECP posts after most address changes
func (e kernelEvent) movesLink() bool {
	if e.vendor != darwinKEVVendorApple || e.class != darwinKEVNetworkClass {
		return false
	}
	switch e.subclass {
	case darwinKEVInet, darwinKEVDL, darwinKEVInet6, darwinKEVND6:
		return true
	}
	return false
}

// kernelEventWakes reports whether one read of a kernel event socket wakes the network watch: an event that can move a link on any
// interface but mesh, named as the event names it, or a read that does not decode
// an event that can move a link and names no interface wakes it too, since the reread decides
func kernelEventWakes(raw []byte, mesh string) bool {
	event, ok := decodeKernelEvent(raw)
	if !ok {
		return true
	}
	return event.movesLink() && (mesh == "" || event.link != mesh)
}

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
			if !local.IsGlobalUnicast() || address.Flags&(in6IffTentative|in6IffOptimistic|in6IffDuplicated) != 0 {
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
