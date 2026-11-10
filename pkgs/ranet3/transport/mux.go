// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

// Package transport shares one UDP port between IKE control messages and
// UDP-encapsulated ESP packets. IKE packets carry a four-byte non-ESP marker,
// ESP packets are bare and begin with their nonzero inbound SPI. That rule is
// RFC 3948 section 2.2, and it carries IKE and its own ESP traffic across a
// NAT on one port.
//
// # What a caller uses
//
// [NewHub] binds the port and owns its sockets, one per family that every peer
// shares and, on linux, android, darwin and ios, one connected to each busy
// peer. Each peer then gets a [Mux] from [Hub.NewMux] or [Hub.NewMuxTo], which
// is that peer's logical channel:
// the caller registers the inbound SPIs it has negotiated with
// [Mux.RegisterIKE] and [Mux.RegisterESP], and from then on [Mux.SendIKE]
// sends control messages, which arrive on [Mux.IKE] or through
// [Mux.RecvIKEFromUntil], while [Mux.SendESPBatch] and
// [Mux.RecvESPBatchConcurrent] carry the data. An IKE datagram whose SPI no
// Mux has registered arrives on [Hub.Listen] as an [Unclaimed], which is how
// a peer that has never dialed this node opens an IKE_SA_INIT.
//
// A peer that moves keeps working because a received datagram carries the
// [Endpoint] it came from. [Mux.AdoptEndpoint] repoints the channel at it once
// IKE has authenticated the move, so this package never decides on its own
// that a peer's address changed.
//
// # Keeping the sockets out of their own tunnel
//
// No setting keeps these sockets off the routes a mesh running over it
// installs. [Runtime]'s Prepare, which a caller always supplies, readies each
// socket that carries a datagram before it binds or connects, on linux,
// android, darwin and ios, the builds with a hook for it. Two darwin and ios
// sockets that only look a route up pass none: the one reading a pair's source
// is scoped to the pair's interface, and the one reading the interface a send
// takes runs only with no [Selection], where Prepare leaves a socket as it is.
// Elsewhere wireguard's StdNetBind offers no hook and no socket passes it.
// A linux daemon's Prepare sets schema.UnderlayMark where the process may set
// it, which the reconciler's derived rules read to keep them off, as
// routing.md's "Where a lookup ends on Linux" gives with its scope. A darwin
// daemon's scopes each socket connected to a peer to the interface its
// [Selection] names for the peer, and each datagram of the shared socket names
// that interface, the host's own routes with ranet3's interface left out.
// [Runtime] carries what the caller has to resolve at startup.
//
// # What it does not do
//
// Nothing here encrypts, authenticates or parses a payload: an IKE message
// leaves and arrives as bytes, and an ESP packet is opaque. Nothing here
// writes a policy rule either, including the ones that match
// [schema.UnderlayMark].
package transport

import (
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"ranet3.com/pkgs/ranet3/internal/packet"
)

const (
	// nonESPMarkerLen is the four zero octets of RFC 3948 section 2.2 that
	// tell an IKE message from an ESP packet on one port.
	//
	// A NAT keepalive is one octet of 0xff, section 2.3, which says "The
	// receiver SHOULD ignore a received NAT-keepalive packet": recognized by
	// name below rather than swept up by the length test, so a peer that sends
	// one every twenty seconds does not spend the counter an operator reads
	// for hostile traffic. It raises keepalives instead, because ignoring a
	// datagram is a rule about processing it and not about counting it.
	//
	// This end sends none, which section 4 asks for: "A peer SHOULD send a
	// NAT-keepalive packet if a need for it is detected according to [RFC3947]
	// and if no other packet to the peer has been sent in M seconds. M is a
	// locally configurable parameter with a default value of 20 seconds." What
	// keeps the mapping open here is the babel hellos, and nothing else does:
	// the liveness probe fires only once inbound traffic has stopped for its
	// interval, so a peer that keeps sending draws no outbound IKE at all.
	// babel.hello_interval is configurable and Validate accepts up to 655
	// seconds, which is past the two minute mapping timer RFC 4787 REQ-5
	// permits, so a NATed node at a long interval can lose the mapping while
	// traffic is still arriving.
	nonESPMarkerLen = 4
	// natKeepaliveByte is the payload of that one octet datagram.
	natKeepaliveByte = 0xff
)

// Hub owns one local UDP port and routes incoming packets to registered Muxes.
type Hub struct {
	bind packetBind
	port uint16
	// pairs is nil where the bind cannot connect a socket to one peer
	pairs *pairTable
	// pool holds the receive buffers every receiver of the hub reads into
	pool blockPool

	// events is Runtime.Events, nil where the caller records nothing
	events func(kind string, attrs ...slog.Attr)

	mu sync.Mutex
	// tables is replaced whole under mu and loaded by the receive loops without it
	tables    atomic.Pointer[spiTables]
	muxes     map[*Mux]struct{}
	done      chan struct{}
	closed    atomic.Bool
	closeOnce sync.Once

	// dropped counts every datagram refused because its session's receive queue was full or held all its receive buffers, and reported
	// bounds how often that is said out loud. One receive loop serves every
	// session on this hub, and anyone who can reach the port can fill a
	// queue: at line rate a line per datagram is a synchronous write to
	// stderr per packet, on the goroutine that receives for all of them.
	// An operator reads the counter, and the log line only has to point at it.
	dropped atomic.Uint64
	// refused counts datagrams this node read and did not deliver because
	// nothing here wanted them: too short to carry an SPI, zero length, cut by
	// the kernel or with a control message it cut, naming an SPI no Mux holds,
	// arriving for an unclaimed queue that is already full, or carrying a
	// control message or source address the receiver could not read. Anyone
	// who can reach the port can raise it, which is why it is a counter and
	// not a log line, and why it is separate from dropped: a rising dropped
	// means this node is behind on receive, and mixing the two would make the
	// one number an operator watches unreadable.
	refused [refusalCount]atomic.Uint64
	// keepalives counts the one-octet NAT keepalives of RFC 3948 section 2.3.
	// They are ignored rather than delivered, but they are expected traffic
	// from a NATed peer rather than traffic nothing wanted, so they stay off
	// refused: an operator watching that number for a flood should not see it
	// move because a peer is holding its mapping open.
	keepalives atomic.Uint64
	// reported is nanoseconds since started, which is read through time.Since
	// so it comes from the monotonic clock: on the wall clock a step backwards
	// silences the report for the length of the step. It starts one interval
	// in the past, so the first drop is said out loud rather than swallowed by
	// a hub that has only just opened.
	reported atomic.Int64
	started  time.Time
	// scanned is when an unknown ESP SPI last made the hub look for a mux whose destination sent it, on the clock reported reads
	scanned atomic.Int64
	// retired are the ESP SPIs a mux let go of, by UnregisterESP or Close, with when on the clock reported reads, under mu
	retired map[uint32]int64
}

// spiTables maps each registered SPI to its mux, for the receive loops to demultiplex by
// a published one is never written, so a loop reads it without a lock
// a change copies it and publishes the copy under Hub.mu
type spiTables struct {
	ike map[uint64]*Mux
	esp map[uint32]*Mux
	// listen is nil until Listen opens the queue of IKE datagrams no mux claimed
	listen chan Unclaimed
}

// Dropped is how many inbound datagrams were refused because their session's
// receive queue was full or held all its receive buffers. It is the inbound
// counterpart of Peer.Dropped, and the only signal that this node is behind on
// receive rather than losing packets on the wire.
func (h *Hub) Dropped() uint64 { return h.dropped.Load() }

// Refused is how many inbound datagrams this node read and had nowhere to put:
// see Hub.refused.
func (h *Hub) Refused() uint64 {
	var total uint64
	for i := range h.refused {
		total += h.refused[i].Load()
	}
	return total
}

// Refusals is Refused by cause, in the order RefusalCauses names them
func (h *Hub) Refusals() (counts [len(RefusalCauses)]uint64) {
	for i := range h.refused {
		counts[i] = h.refused[i].Load()
	}
	return counts
}

// refusal is the cause a datagram this node read is refused for
type refusal int

const (
	// refusedShort is a datagram too short to name an SPI
	refusedShort refusal = iota
	// refusedShortIKE is an IKE datagram too short behind its non-ESP marker to name its initiator's SPI
	refusedShortIKE
	// refusedUnknownIKE is an IKE datagram of an SA no mux holds, on a hub that does not listen or with no endpoint to answer
	refusedUnknownIKE
	// refusedUnknownESP is an ESP datagram of an SPI no mux holds
	refusedUnknownESP
	// refusedUnclaimedFull is an IKE datagram of an SA no mux holds, for a listening hub's queue of them that is full
	refusedUnclaimedFull
	// refusedTruncated is a datagram the kernel cut, or whose control message it cut, or one of zero length
	refusedTruncated
	// refusedControl is a datagram whose control message would not parse
	refusedControl
	// refusedEndpoint is an IKE datagram whose source or the address it arrived at would not read into an endpoint to answer
	refusedEndpoint
	refusalCount
)

// RefusalCauses names each cause a datagram is refused for, as the cause label of ranet3_receive_refused_total does
var RefusalCauses = [refusalCount]string{
	refusedShort:         "short",
	refusedShortIKE:      "short_ike",
	refusedUnknownIKE:    "unknown_ike",
	refusedUnknownESP:    "unknown_esp",
	refusedUnclaimedFull: "unclaimed_full",
	refusedTruncated:     "truncated",
	refusedControl:       "control",
	refusedEndpoint:      "endpoint",
}

// refusals holds a read's refusals by cause until addRefusals counts them and zeroes it, so a receiver may add to it across retries
// held is set by every add, and a read that refused nothing leaves it unset and costs addRefusals one compare
type refusals struct {
	counts [refusalCount]int
	held   bool
}

func (r *refusals) add(cause refusal, n int) {
	r.counts[cause] += n
	r.held = true
}

func (h *Hub) addRefusals(r *refusals) {
	if !r.held {
		return
	}
	for cause, n := range r.counts {
		if n > 0 {
			h.refused[cause].Add(uint64(n))
		}
	}
	*r = refusals{}
}

// Keepalives reports the RFC 3948 section 2.3 NAT keepalives this hub read and
// ignored. They are separate from Refused because a NATed peer holding its
// mapping open is expected traffic, not traffic nothing wanted.
func (h *Hub) Keepalives() uint64 { return h.keepalives.Load() }

// noteDrop counts refused datagrams and reports them at most once an interval.
func (h *Hub) noteDrop(count int, reason string) {
	total := h.dropped.Add(uint64(count))
	now := int64(time.Since(h.started))
	last := h.reported.Load()
	if now-last < int64(dropReportInterval) || !h.reported.CompareAndSwap(last, now) {
		return
	}
	slog.Warn("transport refused datagrams because their session's receive queue was full or held all its receive buffers", "detail", reason, "dropped_total", total)
}

// Unclaimed is one IKE datagram whose SPI belongs to no registered Mux, which
// is how an IKE_SA_INIT from a peer that has never dialed us arrives. Raw is
// the message with the non-ESP marker already stripped, and Endpoint is the
// source to answer, which is also the endpoint a new Mux is created for.
type Unclaimed struct {
	Raw      []byte
	Endpoint Endpoint
}

// Endpoint is the authenticated datagram source retained by IKE so replies
// can follow a peer whose NAT mapping changed. It prints as an address, which
// a responder needs both to log an unauthenticated peer and to bind a cookie
// to the address it was issued to.
type Endpoint interface {
	transportEndpoint()
	String() string
	// AddrPort is the peer's address as this socket observed it, which NAT
	// detection has to hash (RFC 7296 section 2.23).
	AddrPort() netip.AddrPort
	// zone names the interface a link-local address is on, as the bind's receive records name it, and is empty where the endpoint names none
	zone() string
	// sameDestination reports whether other names the same address and port and arrived with the same pin
	// an endpoint whose sends fell back from its pin counts as one without it, except for unroutedHold after a refusal with EHOSTUNREACH
	sameDestination(other Endpoint) bool
	// withoutSource is this endpoint with the source address and interface left to the kernel
	withoutSource() Endpoint
}

type packetBind interface {
	ParseEndpoint(string) (Endpoint, error)
	Send([][]byte, Endpoint) error
	Close() error
}

// receiveFunc fills the vectors and reports how many datagrams it produced.
// It adds those it read and could not use to refused, and returns an error
// before it adds any, so an operator can tell a receive path that is
// discarding from one that is idle.
// It fills a record for every datagram and an endpoint for every IKE datagram, which the memory and portable binds fill for every datagram.
// It reads into blocks of pool, the hub's, and a view stays valid until its
// next call unless a batch retains its block. The datagrams of one block are
// consecutive in what one call hands out.
type receiveFunc func(pool *blockPool, bufs [][]byte, sizes []int, endpoints []Endpoint, records []receiveRecord, refused *refusals) (n int, err error)

// receiveRecord holds what a receiver read about one datagram beside its bytes, as values and the block's pointer, so filling one allocates nothing
type receiveRecord struct {
	// source is the address and port the datagram came from, with the zone the bind's endpoints name a link-local source's interface by
	source netip.AddrPort
	// ecn is the ECN field of the datagram's outer IP header, Not-ECT where the receiver reads none
	ecn packet.ECN
	// block is the receive buffer the datagram lies in
	block *rxBlock
}

// Datagram is one received IKE message and the endpoint it arrived from.
type Datagram struct {
	Raw      []byte
	Endpoint Endpoint
}

// espChain is one mux's ESP datagrams of one read, linked from its last through receiveLoop's prev by their index in the read
type espChain struct {
	mux                *Mux
	last, count, bytes int
	// block is the receive buffer of the chain's last datagram not copied, and charge the size of each copy and of each distinct such buffer, which counts them exactly since a buffer's datagrams are consecutive in a read
	block  *rxBlock
	charge int
	// marked says a datagram of the chain arrived with an outer ECN field other than Not-ECT
	marked bool
}

// errUnprepared refuses a hub whose runtime names no Prepare, never read as one that does nothing,
// since a socket left to the host's routes can follow the mesh's own into its tun
var errUnprepared = errors.New("transport: the runtime names no Prepare to keep the hub's sockets out of the mesh")

// NewHub binds the one UDP socket every session shares, on port, an ephemeral
// one where it is zero, and on all local IPv4 and IPv6 interfaces. rt carries
// what the caller resolved at startup.
func NewHub(port uint16, rt Runtime) (*Hub, error) {
	if rt.Prepare == nil {
		return nil, errUnprepared
	}
	bind, fns, port, err := openPacketBind(port, rt.Prepare, rt.Selection, rt.Events)
	if err != nil {
		return nil, fmt.Errorf("transport: open bind: %w", err)
	}
	return startHub(bind, fns, port, rt), nil
}

func startHub(bind packetBind, fns []receiveFunc, port uint16, rt Runtime) *Hub {
	h := &Hub{bind: bind, port: port, events: rt.Events,
		muxes: make(map[*Mux]struct{}), done: make(chan struct{}), started: time.Now(), retired: make(map[uint32]int64)}
	h.tables.Store(&spiTables{ike: map[uint64]*Mux{}, esp: map[uint32]*Mux{}})
	h.reported.Store(-int64(dropReportInterval))
	h.scanned.Store(-int64(invalidSPIInterval))
	if p, ok := bind.(poisoner); ok {
		h.pool.poison = p.poison
	}
	for _, fn := range fns {
		go h.receiveLoop(fn, h.readFailed)
	}
	if connector, ok := bind.(pairConnector); ok {
		h.pairs = &pairTable{connector: connector, events: rt.Events, pairs: make(map[pairKey]*pair)}
		go h.sweepPairsEvery()
	}
	return h
}

// NewMux creates a logical peer channel on this hub.
func (h *Hub) NewMux(remoteIP net.IP, remotePort int) (*Mux, error) {
	endpoint, err := h.bind.ParseEndpoint(net.JoinHostPort(remoteIP.String(), strconv.Itoa(remotePort)))
	if err != nil {
		return nil, fmt.Errorf("transport: parse remote endpoint: %w", err)
	}
	return h.newMux(endpoint, true)
}

// NewMuxTo creates a logical peer channel for an endpoint a datagram arrived
// from, rather than for a configured address. A responder learns where its
// peer is only from that datagram, and the endpoint carries the reply source
// address and interface the datagram was received on.
func (h *Hub) NewMuxTo(endpoint Endpoint) (*Mux, error) {
	if endpoint == nil {
		return nil, fmt.Errorf("transport: nil remote endpoint")
	}
	return h.newMux(endpoint, false)
}

func (h *Hub) newMux(endpoint Endpoint, dialed bool) (*Mux, error) {
	m := &Mux{hub: h, endpoint: endpoint, dialed: dialed, ikeCh: make(chan Datagram, ikeQueueSize), espCh: make(chan *Received, espChanSize), done: make(chan struct{}),
		invalidSPI: make(chan uint32, 1)}
	h.mu.Lock()
	if h.closed.Load() {
		h.mu.Unlock()
		return nil, fmt.Errorf("transport: hub closed")
	}
	h.muxes[m] = struct{}{}
	h.mu.Unlock()
	return m, nil
}

// Listen turns on delivery of unclaimed IKE datagrams and returns the channel
// they arrive on. Until it is called nothing accumulates: an initiator-only
// node keeps dropping them exactly as before. Calling it again before
// StopListening returns the same channel. No channel it returns is ever
// closed, and Done says when to stop.
//
// The queue is bounded and a full queue drops the datagram rather than
// blocking the receive loop, because an unauthenticated peer must not be able
// to stall the dataplane. IKE retransmits, so a dropped IKE_SA_INIT costs a
// retransmission interval and nothing else.
func (h *Hub) Listen() <-chan Unclaimed {
	h.mu.Lock()
	defer h.mu.Unlock()
	tables := h.tables.Load()
	if tables.listen != nil {
		return tables.listen
	}
	next := *tables
	next.listen = make(chan Unclaimed, unclaimedQueueSize)
	h.tables.Store(&next)
	return next.listen
}

// StopListening turns delivery of unclaimed IKE datagrams off and lets go of the queue
// the next Listen opens a new queue, and a responder started then reads only handshakes that arrived after it
// the old queue stays open, and what a receive loop still on the old tables adds to it reaches no later responder
func (h *Hub) StopListening() {
	h.mu.Lock()
	defer h.mu.Unlock()
	next := *h.tables.Load()
	next.listen = nil
	h.tables.Store(&next)
}

// SendIKETo writes one IKE message to an endpoint without a Mux. A responder
// under load answers an unauthenticated IKE_SA_INIT with a COOKIE or an
// INVALID_KE_PAYLOAD notify and keeps no state for it, which is the whole
// point of those exchanges, so there is nothing for a Mux to own.
func (h *Hub) SendIKETo(b []byte, endpoint Endpoint) error {
	out := make([]byte, nonESPMarkerLen+len(b))
	copy(out[nonESPMarkerLen:], b)
	return h.bind.Send([][]byte{out}, endpoint)
}

// Done is closed when the hub's socket is gone, so an accept loop can stop.
func (h *Hub) Done() <-chan struct{} { return h.done }

// LocalAddr returns the hub's wildcard local address, but only its port is useful.
func (h *Hub) LocalAddr() net.Addr { return &net.UDPAddr{Port: int(h.port)} }

// Close closes the socket and every mux using it.
func (h *Hub) Close() error {
	return h.fail(ErrClosed)
}

func (h *Hub) fail(cause error) (bindErr error) {
	h.closeOnce.Do(func() {
		h.closed.Store(true)
		bindErr = h.bind.Close()
		h.dropPairs(pairHubClose)
		close(h.done)
		h.mu.Lock()
		muxes := make([]*Mux, 0, len(h.muxes))
		for m := range h.muxes {
			muxes = append(muxes, m)
		}
		h.tables.Store(&spiTables{ike: map[uint64]*Mux{}, esp: map[uint32]*Mux{}, listen: h.tables.Load().listen})
		h.muxes = make(map[*Mux]struct{})
		h.mu.Unlock()
		for _, m := range muxes {
			m.closed.Store(true)
			m.closeDone(cause)
		}
	})
	return bindErr
}

// readFailed fails the hub on a read error from the socket every session shares
func (h *Hub) readFailed(err error) {
	h.fail(fmt.Errorf("transport: read: %w", err))
}

// receiveLoop demultiplexes what fn reads until it fails, and then hands failed the error
func (h *Hub) receiveLoop(fn receiveFunc, failed func(error)) {
	batch := espSendBatch
	bufs, sizes, eps, records := make([][]byte, batch), make([]int, batch), make([]Endpoint, batch), make([]receiveRecord, batch)
	// demultiplexing records where each datagram goes and copies nothing
	// an IKE or unclaimed datagram is copied below once its queue has room for it
	// an ESP datagram copies names a size for is copied once its mux has room for its batch, and any other the batch holds a view of in its block
	type pendingIKE struct {
		mux   *Mux
		index int
	}
	// prev holds the index of the datagram before each ESP datagram in its mux's chain
	prev := make([]int, batch)
	// copies holds the size of the copy each ESP datagram goes into, 0 for one its batch holds a view of
	copies := make([]int, batch)
	// chains holds each mux's chain of one read, and chainOf a mux's index in chains
	chains, chainOf := make([]espChain, 0, batch), make(map[*Mux]int)
	ikeDatagrams := make([]pendingIKE, 0, batch)
	unclaimed := make([]int, 0, batch)
	var refused refusals
	for {
		n, err := fn(&h.pool, bufs, sizes, eps, records, &refused)
		if err != nil {
			failed(err)
			return
		}
		// chains and chainOf are cleared rather than only cut, so neither keeps a closed mux alive past the next read
		clear(chains)
		chains = chains[:0]
		clear(chainOf)
		ikeDatagrams = ikeDatagrams[:0]
		unclaimed = unclaimed[:0]
		// a batch's first unknown ESP SPI alone reads the clock and the last look, since the hub looks at most once an interval
		looked := false
		// one load for the whole batch, under no lock
		// a mux that closes after this load can still be handed this batch
		// nobody reads that mux's queues any more, and the collector frees the batch with the mux
		tables := h.tables.Load()
		for i := range n {
			raw := bufs[i][:sizes[i]]
			// Every arm that reaches no Mux is counted. The SPI is cleartext,
			// so anyone who can reach the port can send these, which is the
			// case an operator needs a number for rather than a log line.
			if len(raw) == 1 && raw[0] == natKeepaliveByte {
				// RFC 3948 section 2.3 has the receiver ignore these. Counted
				// all the same, on its own counter, since a flood of them costs
				// a read and a demultiplex each.
				h.keepalives.Add(1)
				continue
			}
			if len(raw) < nonESPMarkerLen {
				refused.add(refusedShort, 1)
				continue
			}
			if raw[0]|raw[1]|raw[2]|raw[3] == 0 {
				if len(raw) < nonESPMarkerLen+8 {
					refused.add(refusedShortIKE, 1)
					continue
				}
				spi := uint64(raw[4])<<56 | uint64(raw[5])<<48 | uint64(raw[6])<<40 | uint64(raw[7])<<32 | uint64(raw[8])<<24 | uint64(raw[9])<<16 | uint64(raw[10])<<8 | uint64(raw[11])
				if m := tables.ike[spi]; m != nil {
					ikeDatagrams = append(ikeDatagrams, pendingIKE{mux: m, index: i})
				} else if tables.listen != nil && eps[i] != nil {
					// An SA no Mux owns yet, which only a listening hub keeps.
					unclaimed = append(unclaimed, i)
				} else {
					refused.add(refusedUnknownIKE, 1)
				}
			} else {
				spi := uint32(raw[0])<<24 | uint32(raw[1])<<16 | uint32(raw[2])<<8 | uint32(raw[3])
				if m := tables.esp[spi]; m != nil {
					// A chain names datagrams of this read alone, and only the
					// batch made of it below holds their blocks past the read.
					k, ok := chainOf[m]
					if !ok {
						k = len(chains)
						chainOf[m] = k
						chains = append(chains, espChain{mux: m})
					}
					c := &chains[k]
					prev[i], c.last = c.last, i
					c.count++
					c.bytes += len(raw)
					// a block's datagrams are consecutive in a read, so one whose neighbors lie in other blocks is the only one of its block the read hands out
					// a copy charges its mux the copy's size, where a read of one datagram a buffer would otherwise pin a whole buffer for each
					block := records[i].block
					copies[i] = 0
					if (i == 0 || records[i-1].block != block) && (i == n-1 || records[i+1].block != block) {
						copies[i] = copySize(len(raw))
					}
					if copies[i] != 0 {
						c.charge += copies[i]
					} else if block != c.block {
						c.block = block
						c.charge += len(block.data)
					}
					c.marked = c.marked || records[i].ecn != packet.NotECT
				} else {
					refused.add(refusedUnknownESP, 1)
					if !looked {
						looked = true
						h.unknownSPI(spi, records[i].source)
					}
				}
			}
		}
		// The queue is tested before the datagram is copied, not after, so a
		// flood from an unauthenticated peer is refused without allocating for
		// it. The send still cannot block: a hub runs one receive loop per
		// bound socket, IPv4 and IPv6 separately on linux, so room seen here
		// may be gone by the time this one gets there.
		for _, pending := range ikeDatagrams {
			if len(pending.mux.ikeCh) == cap(pending.mux.ikeCh) {
				h.noteDrop(1, "an IKE SA's receive queue")
				continue
			}
			raw := bufs[pending.index][:sizes[pending.index]]
			datagram := Datagram{
				Raw:      append([]byte(nil), raw[nonESPMarkerLen:]...),
				Endpoint: eps[pending.index],
			}
			select {
			case pending.mux.ikeCh <- datagram:
			default:
				h.noteDrop(1, "an IKE SA's receive queue")
			}
		}
		// Counted as refused rather than dropped, on a responder as much as
		// anywhere: this queue holds messages from peers that have not dialed
		// us, so anyone who can reach the port fills it, and dropped is the
		// one signal that says this node is behind on receive.
		for _, i := range unclaimed {
			if len(tables.listen) == cap(tables.listen) {
				refused.add(refusedUnclaimedFull, 1)
				continue
			}
			raw := bufs[i][:sizes[i]]
			datagram := Unclaimed{
				Raw:      append([]byte(nil), raw[nonESPMarkerLen:]...),
				Endpoint: eps[i],
			}
			select {
			case tables.listen <- datagram:
			default:
				refused.add(refusedUnclaimedFull, 1)
			}
		}
		h.addRefusals(&refused)
		for _, c := range chains {
			m := c.mux
			if p := m.pair.Load(); p != nil {
				h.carry(p, c.bytes)
			}
			// tested before the batch takes a block, a copy or a pooled batch, so a refused chain leaves each block to the reader's next read
			if !m.hasRoomForESP(c.charge) || !m.dispatchESP(h.received(c, bufs, sizes, records, prev, copies)) {
				h.noteDrop(c.count, "a peer's ESP receive queue")
			}
		}
	}
}

// received is c's datagrams as a batch holding each copy copies names and a reference to each block the others lie in
// each packet ends at its datagram, since past it lie datagrams other workers decrypt for other batches
func (h *Hub) received(c espChain, bufs [][]byte, sizes []int, records []receiveRecord, prev, copies []int) *Received {
	r := h.pool.batch()
	r.packets, r.blocks, r.charge = r.packetSlots[:c.count], r.blockSlots[:0], c.charge
	if c.marked {
		r.ecn = r.ecnSlots[:c.count]
	}
	var last *rxBlock
	for j, i := c.count-1, c.last; j >= 0; j, i = j-1, prev[i] {
		if c.marked {
			r.ecn[j] = records[i].ecn
		}
		if size := copies[i]; size != 0 {
			b := h.pool.take(size)
			r.packets[j] = b.data[:copy(b.data, bufs[i][:sizes[i]]):sizes[i]]
			r.blocks = append(r.blocks, b)
			continue
		}
		r.packets[j] = bufs[i][:sizes[i]:sizes[i]]
		if block := records[i].block; block != last {
			block.retain()
			r.blocks, last = append(r.blocks, block), block
		}
	}
	return r
}

// unknownSPI hands spi to each mux whose destination is source, unless the hub knows spi
// RFC 7296 section 2.21.4: "A node needs to limit the rate at which it will send messages in response to unprotected messages."
// so the hub looks at most once an interval whoever sent, which also hands each mux at most one SPI an interval
func (h *Hub) unknownSPI(spi uint32, source netip.AddrPort) {
	now := int64(time.Since(h.started))
	last := h.scanned.Load()
	if now-last < int64(invalidSPIInterval) || !h.scanned.CompareAndSwap(last, now) {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.knows(spi, now) {
		return
	}
	for m := range h.muxes {
		if !sentFrom(m.Endpoint(), source) {
			continue
		}
		select {
		case m.invalidSPI <- spi:
		default:
		}
	}
}

// sentFrom reports whether source is endpoint's address and port, unmapped, on the interface endpoint names where it names one
// two link-local peers on two links can share one address and port
func sentFrom(endpoint Endpoint, source netip.AddrPort) bool {
	zone := endpoint.zone()
	return destination(endpoint.AddrPort()) == destination(source) && (zone == "" || zone == source.Addr().Zone())
}

// destination is addr unmapped and without its zone, which Endpoint.AddrPort drops
func destination(addr netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(addr.Addr().Unmap().WithZone(""), addr.Port())
}

// knows reports whether a mux holds spi or let go of it within invalidSPIInterval before now, under h.mu
// it reads the tables published last, since a mux may have taken spi after a receive loop loaded its batch's
func (h *Hub) knows(spi uint32, now int64) bool {
	h.forgetRetired(now)
	_, retired := h.retired[spi]
	return retired || h.tables.Load().esp[spi] != nil
}

// forgetRetired drops the SPIs let go of invalidSPIInterval or more before now, so the hub keeps what one interval lets go of, under h.mu
func (h *Hub) forgetRetired(now int64) {
	maps.DeleteFunc(h.retired, func(_ uint32, at int64) bool { return now-at >= int64(invalidSPIInterval) })
}

// Mux is one peer's logical IKE and ESP channel on a Hub.
type Mux struct {
	hub           *Hub
	endpointMu    sync.RWMutex
	endpoint      Endpoint
	dialed        bool
	ikeCh         chan Datagram
	espDispatchMu sync.Mutex
	espTicket     uint64
	espCh         chan *Received
	// espHeld is the receive storage the batches dispatched to m and not yet released hold, queued or on their way to the tun
	espHeld  atomic.Int64
	done     chan struct{}
	doneOnce sync.Once
	doneErr  atomic.Value
	closed   atomic.Bool
	ownHub   bool
	// fragmented is the endpoint Fragment let the host fragment sends to, nil while it lets none
	fragmentMu sync.Mutex
	fragmented Endpoint
	// pair is the address pair m last sent on, which counts what m receives too
	pair atomic.Pointer[pair]
	// invalidSPI holds an SPI no mux holds that ESP from m's destination carried, for the session to tell its peer of
	invalidSPI chan uint32
}

// hasRoomForESP is consulted before a batch takes its blocks. dispatchESP
// still decides, while this keeps a batch that is about to be dropped anyway
// from holding a block the reader could read into again.
func (m *Mux) hasRoomForESP(charge int) bool {
	return len(m.espCh) < cap(m.espCh) && m.espHeld.Load()+int64(charge) <= espHeldBytes
}

// dispatchESP hands one demultiplexed batch to this peer's receive queue under
// the ticket that fixes its order, and reports whether the queue took it. A
// dropped batch consumes no ticket, because a hub may have separate IPv4 and
// IPv6 receive loops and the gap would stall whichever emitter waits for it.
// A dropped batch is freed at once, and a taken one charged before a worker can release it.
func (m *Mux) dispatchESP(batch *Received) bool {
	m.espDispatchMu.Lock()
	defer m.espDispatchMu.Unlock()
	charge := int64(batch.charge)
	if m.espHeld.Load()+charge <= espHeldBytes {
		batch.ticket, batch.mux = m.espTicket, m
		m.espHeld.Add(charge)
		select {
		case m.espCh <- batch:
			m.espTicket++
			return true
		default:
			m.espHeld.Add(-charge)
		}
	}
	batch.free()
	return false
}

func dialOn(h *Hub, remoteIP net.IP, remotePort int) (*Mux, error) {
	m, err := h.NewMux(remoteIP, remotePort)
	if err != nil {
		_ = h.Close()
		return nil, err
	}
	m.ownHub = true
	return m, nil
}

func (m *Mux) LocalAddr() net.Addr { return m.hub.LocalAddr() }
func (m *Mux) IsClosed() bool      { return m.closed.Load() || m.hub.closed.Load() }

// Done is closed when this peer's transport becomes unavailable.
func (m *Mux) Done() <-chan struct{} { return m.done }

// RegisterIKE routes packets whose marked IKE header has spi as SPIi to m.
func (m *Mux) RegisterIKE(spi uint64) error {
	if spi == 0 {
		// RFC 7296 section 3.1 on the initiator's SPI: "This value MUST NOT be
		// zero." Claiming it here would route every datagram carrying one to
		// this mux, which is the same reason RegisterESP refuses it.
		return fmt.Errorf("transport: IKE SPI must be nonzero")
	}
	m.hub.mu.Lock()
	defer m.hub.mu.Unlock()
	if m.closed.Load() || m.hub.closed.Load() {
		return ErrClosed
	}
	tables := m.hub.tables.Load()
	owner := tables.ike[spi]
	if owner == m {
		return nil
	}
	if owner != nil {
		return fmt.Errorf("transport: IKE SPI %016x already registered", spi)
	}
	next := *tables
	next.ike = maps.Clone(tables.ike)
	next.ike[spi] = m
	m.hub.tables.Store(&next)
	return nil
}

// UnregisterIKE stops routing IKE packets for spi to m.
func (m *Mux) UnregisterIKE(spi uint64) {
	m.hub.mu.Lock()
	defer m.hub.mu.Unlock()
	tables := m.hub.tables.Load()
	if tables.ike[spi] != m {
		return
	}
	next := *tables
	next.ike = maps.Clone(tables.ike)
	delete(next.ike, spi)
	m.hub.tables.Store(&next)
}

// RegisterESP routes bare ESP packets whose inbound SPI is spi to m.
func (m *Mux) RegisterESP(spi uint32) error {
	if spi == 0 {
		return fmt.Errorf("transport: ESP SPI must be nonzero")
	}
	m.hub.mu.Lock()
	defer m.hub.mu.Unlock()
	if m.closed.Load() || m.hub.closed.Load() {
		return ErrClosed
	}
	tables := m.hub.tables.Load()
	owner := tables.esp[spi]
	if owner == m {
		return nil
	}
	if owner != nil {
		return fmt.Errorf("transport: ESP SPI %08x already registered", spi)
	}
	next := *tables
	next.esp = maps.Clone(tables.esp)
	next.esp[spi] = m
	m.hub.tables.Store(&next)
	return nil
}

// UnregisterESP stops routing ESP packets for spi to m.
// the hub keeps spi for invalidSPIInterval and hands none of the ESP that still arrives on it to InvalidSPI, since the peer sends on it until it has read the Delete
func (m *Mux) UnregisterESP(spi uint32) {
	m.hub.mu.Lock()
	defer m.hub.mu.Unlock()
	tables := m.hub.tables.Load()
	if tables.esp[spi] != m {
		return
	}
	next := *tables
	next.esp = maps.Clone(tables.esp)
	delete(next.esp, spi)
	m.hub.tables.Store(&next)
	now := int64(time.Since(m.hub.started))
	m.hub.forgetRetired(now)
	m.hub.retired[spi] = now
}

// InvalidSPI carries an SPI that ESP from m's destination named and no mux of the hub holds, for the session to tell its peer of
// it holds one at a time and drops what arrives while it is full, and the hub hands it at most one an interval
func (m *Mux) InvalidSPI() <-chan uint32 { return m.invalidSPI }

// KnowsSPI reports whether a mux of m's hub holds spi or let go of it within invalidSPIInterval
// an SPI InvalidSPI carried is known by the time the session reads it where a mux took it between the hub's look and that read
func (m *Mux) KnowsSPI(spi uint32) bool {
	m.hub.mu.Lock()
	defer m.hub.mu.Unlock()
	return m.hub.knows(spi, int64(time.Since(m.hub.started)))
}

func (m *Mux) SendIKE(b []byte) error {
	out := make([]byte, nonESPMarkerLen+len(b))
	copy(out[nonESPMarkerLen:], b)
	return m.send([][]byte{out}, m.Endpoint())
}

// AdoptEndpoint moves this mux to endpoint unless the two are the same destination, and reports whether it moved
// IKE calls it with the source of a fresh request or of an answer to its own request, once either authenticated
// a mux NewMux made takes the address and port alone and leaves the source to the kernel
// so a session this node dialed sends from whatever address this host holds now
func (m *Mux) AdoptEndpoint(endpoint Endpoint) bool {
	if m.dialed {
		endpoint = endpoint.withoutSource()
	}
	m.endpointMu.Lock()
	defer m.endpointMu.Unlock()
	// the current endpoint keeps what its sends learned about the path
	if m.endpoint.sameDestination(endpoint) {
		return false
	}
	m.endpoint = endpoint
	return true
}

// Endpoint is the destination this mux currently sends to, which a NAT may
// have moved since the session opened.
func (m *Mux) Endpoint() Endpoint {
	m.endpointMu.RLock()
	defer m.endpointMu.RUnlock()
	return m.endpoint
}

func (m *Mux) SendIKETo(b []byte, endpoint Endpoint) error {
	out := make([]byte, nonESPMarkerLen+len(b))
	copy(out[nonESPMarkerLen:], b)
	return m.hub.bind.Send([][]byte{out}, endpoint)
}

// SendESPBatch writes directly to the shared UDP bind. Production batches are
// already adjacent slices of one encryption allocation, which lets Bind use
// UDP GSO without another packing copy. Bind may append into spare capacity
// while coalescing, so callers transfer exclusive ownership of that capacity
// for the duration of the send, just as for the packet contents themselves.
//
// A bare PathMTUError refused only the datagrams past the path, so the sends
// after one still go. The batch then answers the bare report of the narrowest
// path, which holds for every send of it, and any other error stops the batch
// and is answered wrapped, after the report where one came first.
func (m *Mux) SendESPBatch(bufs [][]byte) error {
	if len(bufs) == 0 {
		return nil
	}
	select {
	case <-m.done:
		return m.doneError()
	default:
	}

	endpoint := m.Endpoint()
	var report *PathMTUError
	for len(bufs) != 0 {
		n := min(len(bufs), espSendBatch)
		err := m.send(bufs[:n], endpoint)
		bufs = bufs[n:]
		if err == nil {
			continue
		}
		next, ok := err.(*PathMTUError)
		switch {
		// the mux closed under this send
		case !ok && m.IsClosed():
			return fmt.Errorf("transport: send ESP batch: %w: %w", ErrClosed, err)
		case !ok && report != nil:
			return fmt.Errorf("transport: send ESP batch: %w, then %w", report, err)
		case !ok:
			return fmt.Errorf("transport: send ESP batch: %w", err)
		case report == nil || next.MTU < report.MTU:
			report = next
		}
	}
	if report != nil {
		return report
	}
	return nil
}

// send writes bufs to endpoint, on its pair's socket once the pair has one
// what that socket did not send leaves the shared socket under every rule a send there follows
// and a socket that no longer carries the pair is dropped
func (m *Mux) send(bufs [][]byte, endpoint Endpoint) error {
	if p := m.pairFor(endpoint); p != nil {
		n := 0
		for _, b := range bufs {
			n += len(b)
		}
		m.hub.carry(p, n)
		if socket := p.socket.Load(); socket != nil {
			sent, kept, err := (*socket).transmit(bufs, endpoint)
			if err == nil {
				return nil
			}
			if !kept {
				m.hub.dropPair(p, socket, err)
			}
			bufs = bufs[sent:]
		}
	}
	return m.hub.bind.Send(bufs, endpoint)
}

// IKE is the channel this peer's IKE messages arrive on, so a control loop can
// select over it together with its own work instead of waking on a timer to
// check both. It is the same queue RecvIKEFromUntil drains, so only one reader
// may use either at a time: the handshake uses RecvIKEFromUntil and hands over
// to the control loop once the SA is established.
func (m *Mux) IKE() <-chan Datagram { return m.ikeCh }

// Err is why this mux is done, for a caller that selected on Done itself.
func (m *Mux) Err() error { return m.doneError() }
func (m *Mux) RecvIKEFromUntil(deadline time.Time) ([]byte, Endpoint, error) {
	select {
	case d := <-m.ikeCh:
		return d.Raw, d.Endpoint, nil
	case <-m.done:
		return nil, nil, m.doneError()
	case <-time.After(time.Until(deadline)):
		return nil, nil, errTimeout
	}
}

// RecvESPBatchConcurrent returns one complete socket-demultiplexed batch,
// which holds its receive-order ticket and the outer ECN field of each of its
// packets. It is safe for multiple data-plane workers to call concurrently,
// since the transport channel distributes batches, while the ticket lets their
// independently decrypted results be emitted in original order. The caller
// releases the batch once nothing reads its packets any more, and until then
// it counts against this mux's receive storage.
func (m *Mux) RecvESPBatchConcurrent() (*Received, error) {
	select {
	case batch := <-m.espCh:
		return batch, nil
	case <-m.done:
		return nil, m.doneError()
	}
}

var errTimeout = fmt.Errorf("transport: receive timeout")

// ErrClosed answers a receive or an ESP send on a mux that its own Close or its hub's Close closed, an ESP send the mux closed under, and an SPI registration on any closed mux
var ErrClosed = errors.New("transport: closed")

func (m *Mux) closeDone(err error) { m.doneOnce.Do(func() { m.doneErr.Store(err); close(m.done) }) }
func (m *Mux) doneError() error {
	err, _ := m.doneErr.Load().(error)
	return err
}

// Close unregisters this peer. It does not close the shared hub.
// the hub keeps each ESP SPI m held as UnregisterESP keeps one, since the peer sends on it until it learns the session ended
func (m *Mux) Close() error {
	if m.closed.Swap(true) {
		return nil
	}
	m.hub.mu.Lock()
	tables := m.hub.tables.Load()
	next := *tables
	next.ike = maps.Clone(tables.ike)
	maps.DeleteFunc(next.ike, func(_ uint64, owner *Mux) bool { return owner == m })
	next.esp = maps.Clone(tables.esp)
	now := int64(time.Since(m.hub.started))
	m.hub.forgetRetired(now)
	for spi, owner := range tables.esp {
		if owner == m {
			delete(next.esp, spi)
			m.hub.retired[spi] = now
		}
	}
	m.hub.tables.Store(&next)
	delete(m.hub.muxes, m)
	m.hub.mu.Unlock()
	m.leavePair()
	m.closeDone(ErrClosed)
	// a family fragmenting for this mux alone sends with DF again
	if err := m.Fragment(false); err != nil && !errors.Is(err, errors.ErrUnsupported) {
		slog.Warn("transport could not stop fragmenting sends for a closed mux", "endpoint", m.Endpoint().String(), "err", err)
	}
	if m.ownHub {
		return m.hub.Close()
	}
	return nil
}
