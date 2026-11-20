// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package dnstest

import "time"

// initialNamespace is the link of each initial namespace, whose inode Linux
// fixes from 6.17 on (include/uapi/linux/nsfs.h)
var initialNamespace = map[string]string{"net": "net:[4026531833]", "mnt": "mnt:[4026531832]"}

// QueryTimeout is how long Go's resolver waits for each nameserver, the timeout
// the resolv.conf Start binds names
const QueryTimeout = time.Second

const (
	// resolverWait bounds the wait for Go's resolver to read the resolv.conf
	// Start binds, past its reread of the file at most every 5 seconds
	resolverWait = 10 * time.Second
	// awaitLookup bounds each lookup of that wait
	awaitLookup = time.Second
	// awaitStep is the pause between those lookups
	awaitStep = 100 * time.Millisecond
	// queryReadSize is the nameserver's read buffer, larger than any query Go's
	// resolver sends
	queryReadSize = 4096
	// controlMessageSize is the room for the control messages of each query,
	// which carry its mark
	controlMessageSize = 512
)
