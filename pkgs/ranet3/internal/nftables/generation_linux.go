// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package nftables

import (
	"encoding/binary"
	"errors"

	"golang.org/x/sys/unix"
)

// Generation is the nf_tables generation of the socket's network namespace,
// NFTA_GEN_ID of NFT_MSG_GETGEN, and 0 with every error. Each committed
// transaction of any table and any writer moves it by one, and nothing else
// does. The kernel moves it before it applies the transaction's set elements
// (the bump in nf_tables_commit, https://github.com/torvalds/linux/blob/940de590b839f71d6dc846160534bf202401b8b7/net/netfilter/nf_tables_api.c#L11011-L11027),
// and GETGEN takes no lock, so a dump read beside a generation can predate the
// transaction that made it. The request asks for no ack, since the kernel
// answers GETGEN with its one reply.
func (c *Conn) Generation() (uint32, error) {
	replies, err := c.link.Execute(Command(unix.NFT_MSG_GETGEN), 0, PutNfgenmsg(nil, unix.NFPROTO_UNSPEC))
	if err != nil {
		return 0, err
	}
	for _, reply := range replies {
		if reply.Kind != Command(unix.NFT_MSG_NEWGEN) || len(reply.Data) < SizeofNfgenmsg {
			continue
		}
		for kind, value := range reply.Attributes(SizeofNfgenmsg) {
			if kind == unix.NFTA_GEN_ID && len(value) == 4 {
				return binary.BigEndian.Uint32(value), nil
			}
		}
	}
	return 0, errors.New("nftables: no generation in the reply")
}
