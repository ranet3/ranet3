// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package control

import "time"

// DefaultSocket is where the daemon listens and the client looks
// darwin has /var/run alone and linux resolves it to /run, so one path serves both
const DefaultSocket = "/var/run/ranet3/control.sock"

const (
	// socketMode lets the daemon's group use the socket as well as its owner
	// so an operator in the group needs no root, and the unit names that group
	socketMode = 0o660
	// dirMode lets that group reach the socket through its directory
	dirMode = 0o750
	// bindPattern names the directory beside the socket that Listen binds it in first
	bindPattern = ".control-*"
	// bindPathExtra is how much longer than its path the socket's first path is at most
	// a slash and the pattern, whose star os.MkdirTemp replaces with at most the 10 digits of a uint32
	bindPathExtra = len("/"+bindPattern) - len("*") + 10
	// MaxRequest is the largest write body the daemon takes, in bytes
	// Client.Raw sends a longer body for the daemon to refuse, and a caller that refuses one first holds its body to this
	// a request is a few short fields, so a client near this has lost track of what it sends
	MaxRequest = 64 << 10
	// maxAnswer is the largest answer the client reads, in bytes, so a daemon cannot make it allocate without bound
	maxAnswer = 64 << 20
	// maxConnections is how many connections the daemon holds open at once
	// a diagnostic makes one request and exits, and each connection costs a goroutine and a descriptor
	maxConnections = 32
	// requestTimeout bounds reading a request, its headers and its body together, which a local client sends at once
	requestTimeout = 5 * time.Second
	// writeTimeout bounds a request from the end of its headers to the end of its answer, a stream excepted
	// its deadline is fixed when the headers are read, so the wait for the body, the verb's run and the answer's write all
	// count against it
	writeTimeout = 30 * time.Second
	// idleTimeout closes a connection that finished a request and went quiet, which nothing else bounds
	idleTimeout = 30 * time.Second
	// ReadTimeout bounds one exchange of the client with the daemon, a stream excepted
	ReadTimeout = 10 * time.Second
	// RekeyWait bounds how long the rekey verb waits for the rekeys it asked for
	// half of ReadTimeout leaves the answer the other half to reach the subcommand while it still reads
	RekeyWait = ReadTimeout / 2
	// maxStreams is how many streams a daemon holds open at once, leaving the rest of maxConnections to the reads
	maxStreams = 4
	// streamBudget is how long one stream write may wait on its reader before the stream is dropped
	// long enough for a reader on a loaded host
	streamBudget = 5 * time.Second
	// streamHeartbeat is how often a quiet stream writes, so a reader can tell a quiet daemon from a dead one
	streamHeartbeat = 15 * time.Second
	// streamTick is how often a stream reports what its feed refused since it last did, as a trace's stream.dropped note
	streamTick = time.Second
	// streamBatch is how many events or trace records one drain of a live stream takes at most before it flushes, beside the
	// notes it adds, which bounds the time between flushes
	streamBatch = 64
	// maxLine is the longest stream line a client reads, in bytes, far past any event and short of a runaway
	maxLine = 1 << 20
	// maxEventKinds is how many kinds one events query may name, more than a selection a person spells needs
	// past it a query asks the daemon for work and memory nobody bounds
	maxEventKinds = 16
	// maxEventAttrs is how many attributes one events query may name, more than a wait a person spells needs
	// past it a query costs the daemon a parse and a match nobody bounds when it subscribes
	// the match's work at an emit is bounded by the event's own attributes, since it stops at the first named one the event lacks
	maxEventAttrs = 16
	// maxTracePrefixes is how many prefixes a trace query may name for its sources, and as many for its destinations
	// the filter tests each against every packet the trace sees, so the bound is on the emitters' work
	maxTracePrefixes = 16
)

// how durations and columns are written for a person to read
const (
	// tablePadding is the spaces between two aligned columns, more than the single space inside a header such as Invalid SPI
	tablePadding = 2
	// shortRoundUnderSecond is the compact form's precision under a second, which a round trip across a LAN is told apart by
	shortRoundUnderSecond = 100 * time.Microsecond
	// shortRoundUnderMinute is its precision under a minute, which a session's idle time is read at
	shortRoundUnderMinute = 100 * time.Millisecond
	// shortRoundUnderHour is its precision under an hour, where a tenth of a second beside the minutes tells nothing
	shortRoundUnderHour = time.Second
	// shortRoundFromHour is its precision from an hour on, where the seconds of an uptime or of a session's age tell nothing
	shortRoundFromHour = time.Minute
)

// a trace's bounds, which the daemon's tracer holds to as well
const (
	// TraceRateMin and TraceRateMax bound the records one trace takes a second, and TraceRateDefault is a trace's where it names none
	TraceRateMin     = 1
	TraceRateMax     = 10000
	TraceRateDefault = 1000
	// TracePayloadMax is the most of its packet a record carries, the largest IPv4 packet and the largest IPv6 one but a jumbogram
	TracePayloadMax = 65535
)
