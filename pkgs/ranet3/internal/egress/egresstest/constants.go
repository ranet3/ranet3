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
	// the least a NAT keeps a flow idle: a UDP mapping by RFC 4787 REQ-5, a
	// TCP connection opening or closing and one established by RFC 5382 REQ-5,
	// and an ICMP query by RFC 5508 REQ-2
	udpFloor         = 2 * time.Minute
	transitoryFloor  = 4 * time.Minute
	establishedFloor = 2*time.Hour + 4*time.Minute
	queryFloor       = time.Minute
	// leftRounding is the second Flow.Left is rounded down to
	leftRounding = time.Second
	// answeredAge is how long an answered UDP flow lasts before the leaf sends
	// again, past the two seconds after which Linux's connection tracking keeps
	// such a flow under its replied timeout rather than its unreplied one
	answeredAge = 3 * time.Second
	// unansweredDial is how long a connect whose answers are lost waits, past
	// which its SYN has crossed the exit
	unansweredDial = 300 * time.Millisecond
	// resolverPort is a resolver's, whose UDP flows RFC 4787 REQ-5a lets a NAT
	// keep below udpFloor, as a well-known destination port's
	resolverPort = 53
	// suiteSweep is the backend's sweep, so Status reads what a step counted
	// within the step
	suiteSweep = time.Second
	// fillBatch is the most of the spare address's flows handed at once, each
	// batch read at the server before the next, which its socket's default
	// buffer holds
	fillBatch = 128
	// namedLimit is the share of flows the suite's last exit runs at, below
	// egress.DefaultFlowsPerSource so a backend that kept the default admits
	// the flow past it, and no whole number of fill batches
	namedLimit = 200
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
	untrackedPort    = 9850
	untrackedEchoID  = 9851
	behindPort       = 9900
	aheadPort        = 9901
	unansweredPort   = 10000
	openingPort      = 10001
	unackedPort      = 10002
	halfClosedPort   = 10003
	closingPort      = 10004
	timersEchoID     = 10005
	intoPort         = 10007
	intoOpeningPort  = 10008
	intoEchoID       = 10009
	answeredPort     = 10010
	ownAddressPort   = 10006
	limitPort        = 10100
	limitTCPPort     = 10101
	limitRefusedPort = 10102
	leafPathPort     = 40300
	leafHopPort      = 40400
	leafReusePort    = 40500
	leafPairPort     = 40501
	leafSessionsPort = 40600
	leafWindowPort   = 40800
	// the spare address's two flows past its limit, and the first of the ports
	// its admitted flows leave from, one a flow
	spareRefusedPort = 40900
	spareFurtherPort = 40901
	spareFillPort    = 41000

	// the leaf's port a connection into the mesh no flow is tracked for a
	// segment of opens to, its extended echo's identifier, and the ends of the
	// datagram no flow carried that its port unreachable quotes
	intoUntrackedPort   = 10011
	intoUntrackedEchoID = 10012
	unmatchedPort       = 10013
	leafUnmatchedPort   = 40801
)
