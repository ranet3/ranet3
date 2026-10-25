// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package egresstest

const (
	// the links Namespaces makes: the leaf's tun and the mesh's, the exit's
	// uplink to the router, and the router's two links to the server, the
	// narrow one of narrowMTU
	leafLink     = "leaf0"
	meshLink     = "mesh0"
	exitUplink   = "up0"
	routerUplink = "up1"
	routerFar    = "far0"
	serverFar    = "far1"
	routerNarrow = "nar0"
	serverNarrow = "nar1"
	// uplinkMTU is the exit's uplink's, below the mesh's, and narrowMTU below
	// it at the least MTU RFC 8200 section 5 lets an IPv6 link have
	uplinkMTU = 1340
	narrowMTU = 1280
	// carryBatch is the most packets the carrier hands Egress at once, and
	// carryQueue how many of the leaf's packets wait for it
	carryBatch = 64
	carryQueue = 1024
	// neighborProbes and neighborRetransmit are the router's tries at an
	// address nothing holds, so its host unreachable comes within a row's step
	neighborProbes     = "1\n"
	neighborRetransmit = "100\n"
	// fakeTable is the table the suite's own fake backends hold in both
	// families, mappedLow to mappedHigh the ports the mapping fake translates
	// to, none of them a port the leaf sends from, mappedCheckPort the
	// server's port its mapping is read at, and terminatorPort where the
	// terminating fake takes the leaf's TCP
	fakeTable       = "egresstest"
	mappedLow       = 20000
	mappedHigh      = 29999
	mappedCheckPort = 9850
	terminatorPort  = 9900
)
