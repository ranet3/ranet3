// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package packet

import (
	"encoding/binary"
	"net/netip"
	"time"
)

// the IPv4 options RFC 791 section 3.1 lays out that a router forwarding a packet acts on
const (
	optionLooseSource  = 131
	optionStrictSource = 137
	optionRecordRoute  = 7
	optionTimestamp    = 68
	// the smallest pointer each option's layout allows, which counts from the option's type octet as 1
	firstRouteSlot     = 4
	firstTimestampSlot = 5
	// the timestamp option's flags, in the low 4 bits of the octet after its pointer
	timestampsOnly     = 0
	timestampAndSource = 1
	timestampsAtNamed  = 3
	timestampOverflow  = 0xf0
	addressLen         = 4
	timestampLen       = 4
)

// HeaderValid reports whether p, an IPv4 packet as the link delivered it, passes RFC 1812 section 5.2.2's five tests
// the length the link reported, the checksum, the version, the header length and the total length
// it also holds the total length within what the link delivered, which the same section has a router verify
func HeaderValid(p []byte) bool {
	if _, version := Payload(p); version != 4 {
		return false
	}
	return Sum(0, p[:int(p[0]&0x0f)*4]) == 0xffff
}

// DecrementTTL takes one off the TTL of p, an IPv4 header HeaderValid passed, and reports false, changing nothing, for a TTL of 1 or 0
// which RFC 1812 section 5.3.1 has a router discard and answer
// the checksum follows the TTL and protocol word by RFC 1624 section 3's equation 3
func DecrementTTL(p []byte) bool {
	if p[8] <= 1 {
		return false
	}
	before := binary.BigEndian.Uint16(p[8:10])
	p[8]--
	binary.BigEndian.PutUint16(p[10:], AdjustChecksum(binary.BigEndian.Uint16(p[10:12]), before, binary.BigEndian.Uint16(p[8:10]), false))
	return true
}

// Options is the verdict ForwardOptions reaches on a header's options
type Options uint8

const (
	// OptionsForwarded is a header whose options were processed, its checksum updated, or that carries none
	OptionsForwarded Options = iota
	// OptionsSourceRouted is a header carrying a loose or strict source route, which nothing changed
	OptionsSourceRouted
	// OptionsMalformed is a header whose options RFC 791 cannot read, which nothing changed
	// the pointer ForwardOptions returns with it names the octet at fault, counted from the header's first
	OptionsMalformed
)

// ForwardOptions processes the options of p, an IPv4 header HeaderValid passed, as a router forwarding it does
// in the order Linux's ip_options_compile checks them on its forwarding path
// Record Route records address in its next slot
// Timestamp records the milliseconds since midnight UT of now in its next slot, after address where its flags ask for one
// a prespecified address takes the timestamp where ours reports it as this node's own, RFC 791's rule
// where Linux stamps any address that is not a routed unicast one
// a full option counts one more overflow, but for one of prespecified addresses, which passes unchanged as Linux leaves it
// so a packet forwarded here meets the rule the kernel's forwarding path applies, where RFC 791 counts the overflow under every flag
// every other option passes unchanged
// a header changes only when every option reads as RFC 791 lays it out and none is a source route
// address must be a valid IPv4 address, the router-id RFC 1812 section 4.2.2.2 has an unnumbered link insert
// or on a node holding none 192.0.0.8, the dummy address that names no host and that its IPv4 errors come from
func ForwardOptions(p []byte, address netip.Addr, ours func(netip.Addr) bool, now time.Time) (Options, int) {
	headerLen := int(p[0]&0x0f) * 4
	if headerLen == ipv4HeaderLen {
		return OptionsForwarded, 0
	}
	options := p[ipv4HeaderLen:headerLen]
	var route, stamp []byte
	sourceRouted := false
	for i := 0; ; {
		start, end, framing := nextOption(options, i)
		if framing {
			return OptionsMalformed, ipv4HeaderLen + start
		}
		if start == end {
			break
		}
		option, at := options[start:end], ipv4HeaderLen+start
		// each of the three appears at most once, a second refused at its type octet in the order Linux checks
		fault := -1
		switch kind := option[0]; {
		case kind == optionLooseSource || kind == optionStrictSource:
			if fault = routeFault(option, false); fault < 0 && sourceRouted {
				fault = 0
			}
			sourceRouted = true
		case kind == optionRecordRoute && route != nil, kind == optionTimestamp && stamp != nil:
			fault = 0
		case kind == optionRecordRoute:
			fault, route = routeFault(option, true), option
		case kind == optionTimestamp:
			fault, stamp = timestampFault(option), option
		}
		if fault >= 0 {
			return OptionsMalformed, at + fault
		}
		i = end
	}
	if sourceRouted {
		return OptionsSourceRouted, 0
	}
	if route != nil {
		recordRoute(route, address)
	}
	if stamp != nil {
		recordTimestamp(stamp, address, ours, now)
	}
	if route != nil || stamp != nil {
		putHeaderChecksum(p[:headerLen])
	}
	return OptionsForwarded, 0
}

// routeFault is the offset in option, a source route or Record Route, of the octet RFC 791's layout refuses, -1 for none
// Record Route with room for less than one address is refused at its pointer, and a full one is not
func routeFault(option []byte, record bool) int {
	switch {
	case len(option) < 3:
		return 1
	case option[2] < firstRouteSlot:
		return 2
	case record && int(option[2]) <= len(option) && int(option[2])+addressLen-1 > len(option):
		return 2
	}
	return -1
}

// timestampFault is the offset in option, a Timestamp, of the octet RFC 791's layout refuses, -1 for none
// a slot with room for less than its flags record is refused at the pointer, and an overflow count that would pass 15 at the flags
// but for a full option of prespecified addresses, which Linux's ip_options_compile counts no overflow for and so never refuses
func timestampFault(option []byte) int {
	switch {
	case len(option) < 4:
		return 1
	case option[2] < firstTimestampSlot:
		return 2
	}
	pointer, flags := int(option[2]), option[3]&^timestampOverflow
	if pointer > len(option) {
		if flags != timestampsAtNamed && option[3]&timestampOverflow == timestampOverflow {
			return 3
		}
		return -1
	}
	slot := timestampLen
	if flags == timestampAndSource || flags == timestampsAtNamed {
		slot = addressLen + timestampLen
	}
	if pointer+slot-1 > len(option) {
		return 2
	}
	return -1
}

// recordRoute writes address into the next slot of option, a Record Route routeFault let through, unless it is full
func recordRoute(option []byte, address netip.Addr) {
	pointer := int(option[2])
	if pointer > len(option) {
		return
	}
	from := address.As4()
	copy(option[pointer-1:], from[:])
	option[2] += addressLen
}

// recordTimestamp writes into option, a Timestamp timestampFault let through, what its flags ask of this node
// a full option counts one more overflow under any flags but 3, and one with room left under flags RFC 791 does not define stays unchanged, as Linux's ip_options_compile has both
func recordTimestamp(option []byte, address netip.Addr, ours func(netip.Addr) bool, now time.Time) {
	pointer, flags := int(option[2]), option[3]&^timestampOverflow
	if pointer > len(option) {
		if flags != timestampsAtNamed {
			option[3] += 1 << 4
		}
		return
	}
	slot := option[pointer-1:]
	switch flags {
	case timestampsOnly:
		binary.BigEndian.PutUint32(slot, sinceMidnight(now))
		option[2] += timestampLen
	case timestampAndSource:
		from := address.As4()
		copy(slot, from[:])
		binary.BigEndian.PutUint32(slot[addressLen:], sinceMidnight(now))
		option[2] += addressLen + timestampLen
	case timestampsAtNamed:
		if !ours(netip.AddrFrom4([4]byte(slot[:addressLen]))) {
			return
		}
		binary.BigEndian.PutUint32(slot[addressLen:], sinceMidnight(now))
		option[2] += addressLen + timestampLen
	}
}

// sinceMidnight is RFC 791's standard timestamp, the milliseconds since midnight UT
// a Unix day is 86400 seconds, which leaves out leap seconds as UT does
func sinceMidnight(now time.Time) uint32 {
	return uint32(now.UnixMilli() % (86400 * 1000))
}
