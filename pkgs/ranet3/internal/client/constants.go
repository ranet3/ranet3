// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import "time"

// espDropReportInterval bounds how often refused ESP packets are said out
// loud, and how often a session records the ECN combinations no tunnel sends.
// The counters behind them are exact, and an operator reads those. The log
// line and the record only have to point at them.
const espDropReportInterval = 10 * time.Second

const (
	// defaultReconnectDelay is how long a dialer waits between attempts unless a test shortens it
	defaultReconnectDelay = 10 * time.Second
	// dialFailureInterval is how long a dialer keeps a failure it already reported at debug
	// one name that never resolves would otherwise say so every reconnect delay
	dialFailureInterval = 10 * time.Minute
	// dialFailureFloor is how soon a dialer reports a failure whose reason changed
	// a reason that carries a port the resolver picked is never the same twice
	dialFailureFloor = time.Minute
	// deleteGrace bounds how long a teardown waits for the peer to acknowledge the Delete
	// the point is to tell the peer, not to be sure it heard
	deleteGrace = 2 * time.Second
	// proactiveRekeyJitter bounds the random delay of the first ask for a rekey past esp.ProactiveRekeySequence
	// it is at most a tenth of the time the sequence margin lasts at the highest packet rate one SA carries, and at least three round trips of an exchange across the mesh
	proactiveRekeyJitter = time.Second
)

const (
	// defaultProbeTimeout is how long a probe of a session's path MTU waits for its Ack before it counts as lost, unless a test shortens it
	// FRR answered an Ack Request within 4.8 seconds where it was measured, babeld within 1.5 and BIRD and ranet3 at once
	// RFC 8899 section 5.1.1 asks at least 1 second and recommends more than 15, which a search through a dozen sizes would wait minutes on
	defaultProbeTimeout = 6 * time.Second
	// maxProbes is how many probes of one size go unanswered in a row before the path counts as losing the size, RFC 8899's MAX_PROBES
	maxProbes = 3
	// confirmInterval is how often a confirmed search probes its budget while data flows
	// a black hole that opens on the path loses the session's largest packets for this long and three probe timeouts at most
	confirmInterval = 30 * time.Second
	// raiseInterval is how long a confirmed search keeps its budget before it reads the route again and searches up
	// RFC 8899's PMTU_RAISE_TIMER, and as long as linux keeps a path MTU it learned
	raiseInterval = 10 * time.Minute
)

const (
	// downFlag is the file in the state directory whose presence keeps the node off the mesh
	downFlag = "down"
	// babelStateFile is the file in the state directory holding the Babel router id and seqno limit a start takes, with the node they belong to
	babelStateFile = "babel.json"
	// stateTemp is the suffix of the file a state file is written whole in before it is renamed into place
	stateTemp = ".tmp"
	// stateFileMode keeps a state file to the daemon's own user, which writes it and alone reads it
	stateFileMode = 0o600
	// stateDirMode is the state directory's mode where the daemon makes it, for the same reason
	stateDirMode = 0o700
)

// routeHopLimit is the hop limit of the packet debug route follows, the one linux and darwin send with by default
const routeHopLimit = 64
