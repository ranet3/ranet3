// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package nftables

const (
	// SizeofNfgenmsg is struct nfgenmsg, which x/sys does not carry
	SizeofNfgenmsg = 4
	// nfnetlinkV0 is NFNETLINK_V0, the only version there is
	nfnetlinkV0 = 0
	// Accept is NF_ACCEPT, the policy every chain written here carries
	Accept = 1
	// nlaTypeMask is NLA_TYPE_MASK, which masks NLA_F_NESTED off on the way
	// in. libnftnl sets that flag, so it is set on the way out.
	nlaTypeMask = 0x3fff
	// udataComment and udataSetComment are NFTNL_UDATA_RULE_COMMENT and
	// NFTNL_UDATA_SET_COMMENT, the userdata types `nft` prints as a rule's
	// comment and a set's
	udataComment    = 0
	udataSetComment = 7
	// udataCommentMax is the comment length nft itself accepts
	udataCommentMax = 128
	// where the source address sits in each network header
	ipv4SourceOffset = 12
	ipv6SourceOffset = 8
	// NFTA_CT_TIMEOUT_L3PROTO, _L4PROTO and _DATA, the attributes of a ct
	// timeout object, which x/sys does not carry
	ctTimeoutL3Proto = 1
	ctTimeoutL4Proto = 2
	ctTimeoutData    = 3
	// NFTA_CONNLIMIT_COUNT and NFTA_CONNLIMIT_FLAGS, and NFT_CONNLIMIT_F_INV,
	// which matches while the count is over the limit, none of which x/sys
	// carries
	connlimitCount  = 1
	connlimitFlags  = 2
	connlimitInvert = 1
	// CTStateNew is NF_CT_STATE_BIT(IP_CT_NEW) in ct state, CTStateInvalid and
	// CTStateUntracked NF_CT_STATE_INVALID_BIT and NF_CT_STATE_UNTRACKED_BIT,
	// what ct state reads for a packet with no entry, and CTStatusConfirmed
	// IPS_CONFIRMED in ct status, each a host order word
	CTStateNew        = 1 << 3
	CTStateInvalid    = 1 << 0
	CTStateUntracked  = 1 << 6
	CTStatusConfirmed = 1 << 3
	// TypeIPv4Addr and TypeIPv6Addr are nft's numbers for the address types,
	// TYPE_IPADDR and TYPE_IP6ADDR of its datatype.h. The kernel stores a set's
	// key type without reading it, and nft lists the set by it.
	TypeIPv4Addr = 7
	TypeIPv6Addr = 8
	// replyTimeout bounds a wait on the kernel, in seconds. A batch is
	// acknowledged message by message and a dump ends at NLMSG_DONE, so a
	// reply that never comes is a kernel that did not understand the request.
	replyTimeout = 10
	// receiveBuffer holds a whole transaction's acknowledgments while the
	// sender is still sending. See Dial.
	receiveBuffer = 1 << 20
	// replyReadSize is the first reply buffer of a Conn, above the 32 KiB the
	// kernel caps a dump datagram at, so a dump reads into it without the
	// buffer growing
	replyReadSize = 64 << 10
	// notificationReadSize is the read buffer of the notification socket,
	// above NLMSG_GOODSIZE, the most the kernel puts in one notification
	// datagram
	notificationReadSize = 64 << 10
)
