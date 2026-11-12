// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

package babel

import "time"

const (
	Magic   = 42
	Version = 2
	Port    = 6696

	headerLen = 4 // Magic(1) Version(1) BodyLength(2)
)

// TLV types, RFC 8966 section 4.6.
type TLVType uint8

const (
	TLVPad1         TLVType = 0
	TLVPadN         TLVType = 1
	TLVAckReq       TLVType = 2
	TLVAck          TLVType = 3
	TLVHello        TLVType = 4
	TLVIHU          TLVType = 5
	TLVRouterID     TLVType = 6
	TLVNextHop      TLVType = 7
	TLVUpdate       TLVType = 8
	TLVRouteRequest TLVType = 9
	TLVSeqnoRequest TLVType = 10
)

// Sub-TLV types shared by Hello/IHU (and, per RFC 8966, any TLV), section 4.4.
const (
	SubTLVPad1 uint8 = 0
	SubTLVPadN uint8 = 1
	// SubTLVTimestamp carries the timestamps of RFC 9616 section 6.
	SubTLVTimestamp uint8 = 3
)

// SubTLVSourcePrefix is the mandatory Source Prefix sub-TLV (RFC 9079).
// Unknown mandatory sub-TLVs invalidate the enclosing Update.
const SubTLVSourcePrefix uint8 = 128

// updateFlagPrefix and updateFlagRouterID are flags of the Update TLV, RFC
// 8966 section 4.6.9.
const (
	updateFlagPrefix   = 0x80
	updateFlagRouterID = 0x40
)

// Address Encodings, RFC 8966 section 4.1.4.
const (
	AEWildcard      uint8 = 0
	AEIPv4          uint8 = 1
	AEIPv6          uint8 = 2
	AEIPv6LinkLocal uint8 = 3
	AEIPv4ViaIPv6   uint8 = 4 // RFC 9229: IPv4 prefix with an IPv6 next hop
)

// Special metric value meaning "unreachable" / route retraction, RFC 8966 section 4.6.9.
const MetricInfinity uint16 = 0xffff

// maxInterval is the longest interval the 16-bit centisecond fields of RFC
// 8966 section 4.6 carry.
const maxInterval = 65535 * 10 * time.Millisecond

// maxUpdateInterval is the longest update interval that names a time: RFC 8966
// section 4.6.9 gives FFFF the meaning "this announcement will not be repeated
// unless a request is received".
const maxUpdateInterval = maxInterval - 10*time.Millisecond

// historyDepth is the width of the Hello history vector, and rebootDrift the
// gap past which Appendix A.1 treats the sender as having rebooted and lost its
// counter.
const (
	historyDepth = 16
	rebootDrift  = 16
)
