// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package nftables

import (
	"encoding/binary"
	"errors"

	"golang.org/x/sys/unix"
)

// errNoGeneration is a GETGEN whose reply carries no generation
var errNoGeneration = errors.New("nftables: no generation in the reply")

// Generation is the nf_tables generation of the socket's network namespace,
// NFTA_GEN_ID of NFT_MSG_GETGEN. Every transaction that commits a change, of
// any table and any writer, moves it by one, and nothing else does (the bump
// in nf_tables_commit, net/netfilter/nf_tables_api.c). So an unmoved
// generation shows that no transaction committed since it was read, and
// nothing about what a read paired with it saw: the kernel moves it before it
// applies the transaction's set elements, and GETGEN takes no lock, so a read
// can find a generation and the state before its transaction.
func (c *Conn) Generation() (uint32, error) {
	replies, err := c.link.Execute(Command(unix.NFT_MSG_GETGEN), unix.NLM_F_ACK, PutNfgenmsg(nil, unix.NFPROTO_UNSPEC))
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
	return 0, errNoGeneration
}
