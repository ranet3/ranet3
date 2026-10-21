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
	// udataComment is NFTNL_UDATA_RULE_COMMENT, the userdata type `nft` prints
	// as a rule's comment
	udataComment = 0
	// udataCommentMax is the comment length nft itself accepts
	udataCommentMax = 128
	// where the source address sits in each network header
	ipv4SourceOffset = 12
	ipv6SourceOffset = 8
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
