// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package srv6

const (
	// maxExtensionHeaders bounds the extension headers walk and carriesUnanswerable step past in one packet, so a sender sets no cost per packet past it
	maxExtensionHeaders = 8
	// maxEdgeHeaders bounds the extension headers a code 8 answer's search and WalkEdge step past, and is at least maxExtensionHeaders so the edge steps past every header a SID's walk does
	maxEdgeHeaders = 16

	// MaxSegments bounds a segment list this node builds or acts on, so the 16 bytes each segment puts in front of every packet are this node's choice rather than a peer's
	MaxSegments = 16
)

// DefaultHopLimit is the hop limit of the packets this package builds where none is copied or given, an IPv4 inner packet's outer header and every answer a caller passes no hop limit for, the one linux gives the packets it sends (IPV6_DEFAULT_HOPLIMIT), so a segment list that loops dies at the same count anything else does
const DefaultHopLimit = 64
