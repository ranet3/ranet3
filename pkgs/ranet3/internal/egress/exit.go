// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package egress

import (
	"context"
	"net/netip"
	"time"

	"ranet3.com/pkgs/ranet3/internal/events"
)

// Exit carries other nodes' traffic out of the mesh: the packets of the
// prefixes cap.egress advertises that count as a default and those of the
// egress segments, each family announced only while it is ready. The daemon
// starts, stops, enables, announces through and reports from it, and both
// egress verdicts of the dataplane hand it their batches.
type Exit interface {
	// Run carries until ctx ends, then returns once readiness has gone false
	// in both families, the announcement has been published empty and the
	// backend holds nothing. It is called once, and its error is the
	// withdrawal's.
	Run(ctx context.Context) error
	// SetEnabled withdraws everything while Run runs, in the order Run's end
	// takes, and restores it, for a node taken off the mesh and put back. It
	// returns before the backend has caught up, which Status then reports.
	SetEnabled(on bool)
	// Egress takes the packets a verdict decided to egress, all of them in
	// families Ready last named ready and those through an advertised prefix
	// also in families Announce last answered. The caller has read the
	// family's readiness first, so Egress judges none.
	//
	// Every backend takes concurrent calls, one from each session's receive
	// path. Each frame is TUNHeadroom bytes of internal/netstack that a tun
	// write may overwrite and then the packet to the frame's end, and the
	// frames are the exit's from the call on the terms the mesh's
	// DeliverInboundBatch states for itself: until written, or copied before
	// the call returns.
	Egress(frames [][]byte)
	// Announce is the advertised prefixes of the families ready now, and
	// nothing before the first pass
	Announce() []netip.Prefix
	// Status answers the status and the debug views
	Status() Status
}

// Hooks are the calls every backend reports through, which each backend's
// constructor takes
type Hooks struct {
	// Ready receives each family's readiness, and whether the egress SIDs are
	// served, whenever one of the three moves, starting from none. A family is
	// reported not ready before what carries it is withdrawn. Nil where nothing
	// reads it, which only a test does.
	Ready func(v4, v6, serves bool)
	// Republish says that Announce has moved, once per move, Run's end
	// moving it to empty. Nil where nothing announces, which only a test does.
	Republish func()
	// Events records every pass that rewrote what the backend holds, moved
	// the announcement or failed, nil records nothing
	Events *events.Bus
}

// Status is the report every backend gives, with a detail of its own
type Status struct {
	// Backend names the backend, and Where the space it owns on the host
	Backend, Where string
	// Ready4 and Ready6 are each family's readiness. Unready says why a
	// family the backend carries is not ready, and Skipped what its readiness
	// lookups left out and why, each empty where there is nothing to say
	Ready4, Ready6   bool
	Unready, Skipped string
	// Advertise is the prefixes the capability advertises, and Announced
	// those of the families ready at the last pass
	Advertise, Announced []netip.Prefix
	// Translate and Return are the capability's translation
	Translate []Class
	Return    bool
	// FlowsPerSource is the limit in force on the flows one source address of
	// one family holds open, and Refused4 and Refused6 the packets refused past
	// it in each family, each retry of a refused flow counted, from zero again
	// wherever the backend wrote what counts them anew
	FlowsPerSource     int
	Refused4, Refused6 uint64
	// Dropped4 and Dropped6 are the packets out of the mesh, and into it under
	// return, dropped in each family for want of a tracked flow, which a rule
	// that translates would otherwise send on under their own source, counted
	// as Refused4 and Refused6 are
	Dropped4, Dropped6 uint64
	// PassAt is the last pass, zero before the first, and Err its error
	PassAt time.Time
	Err    string
	// Rules is the detail of a backend that installs rules in the host's
	// packet filter, nil for one that holds none
	Rules *Rules
}

// ExitDebug is an exit's detail as a debug read finds it, which a backend
// holding rules in the host's packet filter answers beside its Status: each
// rule with its counter read now, and each family's readiness as the last pass
// judged it
type ExitDebug struct {
	Status Status
	// Rules is each rule the backend asks for in order, then each its chains
	// hold that it does not ask for, and ReadErr why they could not be read now
	Rules   []RuleReading
	ReadErr string
	// Families is each family the backend translates
	Families []FamilyReading
	// RPFilter is IPv4's rp_filter on all and on each device a route of the
	// last pass's lookups leaves by, read now
	RPFilter []Setting
}

// RuleReading is one rule as a debug read finds it. Counter is the unit of
// its counter: flows for a rule of the translation's chain, which meets a
// flow's first packet alone, packets for one of the forward hook's chain, and
// empty for a rule that keeps none.
type RuleReading struct {
	Spec           string
	Wanted, Held   bool
	Counter        string
	Packets, Bytes uint64
}

// FamilyReading is one family's readiness condition by condition as the last
// pass judged it: its chains read back, the host's forwarding, then each route
// lookup the pass read for it with its answer
type FamilyReading struct {
	Family uint8
	Ready  bool
	// Why is why the family is not ready, and Unwritten why its chains do not
	// read back as written, each empty where there is nothing to say
	Why, Unwritten string
	Forwarding     bool
	// Lookups is empty where the pass read none for the family, and Answers
	// holds each one's answer at its place, empty where the batch failed or
	// answered short, which Why says
	Lookups []Lookup
	Answers []Answer
}

// Lookup is one of the kernel's route lookups a pass reads, for a packet from
// Source to Destination arriving on IIF. Reply asks for the lookup of its
// reply as well, from Destination to Source, arriving on the device of the
// answer's first live hop. A lookup from no source arriving on no device reads
// the route this host itself sends to Destination by, its local route where it
// holds the address.
type Lookup struct {
	Source, Destination netip.Addr
	IIF                 string
	Reply               bool
}

// Answer is a lookup's route or its error and, for a lookup asking for its
// reply, the device the reply's lookup arrived on, empty where none was made,
// with that lookup's route or error
type Answer struct {
	Route    Route
	Err      error
	ReplyIIF string
	Reply    Route
	ReplyErr error
}

// Route is a route a lookup found, its type as ip-route(8) names it and its
// next hops
type Route struct {
	Type string
	Hops []Hop
}

// Hop is one next hop of a route, live unless the kernel marks it Dead or
// LinkDown
type Hop struct {
	Device         string
	Dead, LinkDown bool
}

// Setting is one sysctl by its path under /proc/sys, Value empty where it
// could not be read
type Setting struct {
	Name, Value string
}

// Rules is the rules a backend installed, as its last pass read them back
type Rules struct {
	Installed int
	// Flows counts the connections the rules have translated, and Bytes the
	// first packet of each, since a translation rule is consulted once per
	// connection. Untranslated counts those the rules of a class of none bound
	// to the source they carry.
	Flows, Bytes, Untranslated uint64
	// ConntrackCount and ConntrackMax are the host's connection tracking
	// table, the entries it holds and the most it takes, which the limit's
	// shares come out of. Each is nil where the pass could not read it.
	ConntrackCount, ConntrackMax *uint64
	// Conflicts names the other source translation on the host this node's
	// traffic can meet
	Conflicts []string
}
