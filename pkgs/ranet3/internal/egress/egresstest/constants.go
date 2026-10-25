// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package egresstest

import "time"

const (
	// readyBudget is how long a backend takes to report both families ready and announce both defaults
	readyBudget = 20 * time.Second
	// stepBudget is how long one exchange of a row waits for its answer, sending again every retryInterval
	stepBudget    = 5 * time.Second
	retryInterval = 250 * time.Millisecond
	// quietPeriod is how long an answer that must not come is waited for
	quietPeriod = time.Second
	// pollInterval is how often a wait reads what came back toward the leaf
	pollInterval = 10 * time.Millisecond
	// transferBytes is the size the transfer carries each way, within transferBudget
	transferBytes  = 512 << 10
	transferBudget = 30 * time.Second
	// reconnectBudget stays below the initial retransmission timeout of RFC 6298 section 2.1, one second, so a reconnect whose first SYN was lost exceeds it
	reconnectBudget = 900 * time.Millisecond
	// stopBudget is how long Run takes to return once its context ends
	stopBudget = 10 * time.Second
	// leafTTL is the TTL and hop limit of the packets the rows build, room for every hop on the way
	leafTTL = 64
	// readSize holds any packet a link of the network carries
	readSize = 1 << 16
	// concurrentSessions is how many goroutines call Egress at once, each
	// with sessionDatagrams datagrams of a flow of its own
	concurrentSessions = 4
	sessionDatagrams   = 16
)

// the ports of each row and step, the server's and the leaf's, apart so no exchange meets another's state at the exit
const (
	serverSeesPort   = 9100
	echoID           = 9101
	closedPort       = 9200
	unreachablePort  = 9201
	leafErrorPort    = 9202
	pathPort         = 9300
	fragmentPort     = 9301
	hopPort          = 9400
	reconnectPort    = 9500
	pairPort         = 9501
	pairEchoID       = 9502
	sessionsPort     = 9600
	enabledPort      = 9700
	windowPort       = 9800
	leafPathPort     = 40300
	leafHopPort      = 40400
	leafReusePort    = 40500
	leafPairPort     = 40501
	leafSessionsPort = 40600
	leafWindowPort   = 40800
)
