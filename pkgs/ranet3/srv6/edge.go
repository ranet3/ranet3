// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package srv6

// EdgeVerdict is WalkEdge's finding on a packet entering the SR domain from outside it
type EdgeVerdict uint8

const (
	// EdgePass is a chain the walk reads to its end, the header it stopped at being one it does not examine
	EdgePass EdgeVerdict = iota
	// EdgeRoutingHeader is a routing header of a type the edge refuses
	EdgeRoutingHeader
	// EdgeInvalid is a chain longer than maxEdgeHeaders, or cut short inside a header the walk reads
	EdgeInvalid
)

// WalkEdge walks raw, an IPv6 packet entering the SR domain, past its hop-by-hop, destination options and routing headers, RFC 8200 section 4
// and refuses a routing header of the deprecated types 0 and 1, of type 4, the SRH, which RFC 8754 section 5.1 drops at the domain's edge
// or of a type this node does not recognize, which can steer a packet as the SRH does
// it reports where the walk stopped, the next header there and its offset, a fragment, AH, ESP or any other header passing unexamined as RFC 7045 section 2.1 asks
// raw holds at least the fixed header
func WalkEdge(raw []byte) (verdict EdgeVerdict, next byte, offset int) {
	next, offset = raw[6], ipv6HeaderLen
	for read := 0; next == nextHeaderHopByHop || next == nextHeaderDestOpts || next == nextHeaderRouting; read++ {
		if read == maxEdgeHeaders {
			return EdgeInvalid, next, offset
		}
		following, end, ok := stepExtension(raw, next, offset)
		if !ok || end > len(raw) {
			return EdgeInvalid, next, offset
		}
		if next == nextHeaderRouting && !forwardedRouting(raw[offset+2]) {
			return EdgeRoutingHeader, next, offset
		}
		next, offset = following, end
	}
	return EdgePass, next, offset
}

// forwardedRouting reports a routing type the edge forwards, the standardized and undeprecated ones RFC 7045 section 2.1 names
// type 2 of RFC 6275, type 3 of RFC 6554 and the experimental 253 and 254 of RFC 4727
func forwardedRouting(kind byte) bool {
	switch kind {
	case 2, 3, 253, 254:
		return true
	}
	return false
}
