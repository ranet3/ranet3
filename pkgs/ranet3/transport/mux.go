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
// shares and, on linux and darwin, one connected to each busy peer. Each peer
// then gets a [Mux] from [Hub.NewMux] or [Hub.NewMuxTo], which is that peer's
// logical channel:
// the caller registers the inbound SPIs it has negotiated with
// [Mux.RegisterIKE] and [Mux.RegisterESP], and from then on [Mux.SendIKE] and
// [Mux.RecvIKE] carry control messages while [Mux.SendESP], [Mux.RecvESP] and
// their batch forms carry the data. An IKE datagram whose SPI no Mux has
// registered arrives on [Hub.Listen] as an [Unclaimed], which is how a peer
// that has never dialed this node opens an IKE_SA_INIT. [Dial] is the one-peer
// shorthand: a hub and a single mux, closed together.
//
// A peer that moves keeps working because a received datagram carries the
// [Endpoint] it came from. [Mux.AdoptEndpoint] repoints the channel at it once
// IKE has authenticated the move, so this package never decides on its own
// that a peer's address changed.
//
// # Keeping the sockets out of their own tunnel
//
// [Underlay] and [Runtime] are the one setting that keeps these sockets off the
// routes a mesh running over it installs on darwin, an interface binding. On
// linux no setting does it: every socket carries schema.UnderlayMark where the
// process may set it, which the reconciler's derived rules read to keep them
// off, as routing.md's "Where a lookup ends on Linux" gives with its scope.
// [Underlay] is a plain value a config file or a control plane can produce
// whole, and [Runtime] carries what the caller has to resolve at startup, so a
// caller that wants neither passes both zero.
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
	"log"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
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

	// underlay is the configuration the socket was opened under, and boundTo
	// the interface index it currently carries, zero for none. Both are read
	// under mu, which the follower goroutine and a status reader share.
	underlay Underlay
	boundTo  int
	// events is Runtime.Events, nil where the caller records nothing
	events func(kind string, attrs ...slog.Attr)

	mu sync.Mutex
	// tables is replaced whole under mu and loaded by the receive loops without it
	tables    atomic.Pointer[spiTables]
	muxes     map[*Mux]struct{}
	done      chan struct{}
	closed    atomic.Bool
	closeOnce sync.Once

	// dropped counts every datagram a full receive queue refused, and reported
	// bounds how often that is said out loud. One receive loop serves every
	// session on this hub, and anyone who can reach the port can fill a
	// queue: at line rate a line per datagram is a synchronous write to
	// stderr per packet, on the goroutine that receives for all of them.
	// An operator reads the counter, and the log line only has to point at it.
	dropped atomic.Uint64
	// refused counts datagrams this node read and did not deliver because
	// nothing here wanted them: too short to carry an SPI, zero length, naming
	// an SPI no Mux holds, arriving for an unclaimed queue that is already
	// full, or carrying a control message or source address the receiver could
	// not read. Anyone who can reach the port can raise it, which is why it is
	// a counter and not a log line, and why it is separate from dropped: a
	// rising dropped means this node is behind on receive, and mixing the two
	// would make the one number an operator watches unreadable.
	refused atomic.Uint64
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

// Dropped is how many inbound datagrams a full receive queue has refused. It
// is the inbound counterpart of Peer.Dropped, and the only signal that this
// node is behind on receive rather than losing packets on the wire.
func (h *Hub) Dropped() uint64 { return h.dropped.Load() }

// Refused is how many inbound datagrams this node read and had nowhere to put:
// see Hub.refused.
func (h *Hub) Refused() uint64 { return h.refused.Load() }

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
	slog.Warn("transport receive queue full", "detail", reason, "dropped_total", total)
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

// A receiver owns its buffers. Their views remain valid until its next call.
// receiveFunc fills the vectors and reports how many datagrams it produced
// and how many it read and could not use, which the hub counts so an operator
// can tell a receive path that is discarding from one that is idle.
// It fills a record for every datagram and an endpoint for every IKE datagram, which the memory and portable binds fill for every datagram.
type receiveFunc func([][]byte, []int, []Endpoint, []receiveRecord) (n, refused int, err error)

// receiveRecord holds what a receiver read about one datagram beside its bytes, as values, so filling one allocates nothing
type receiveRecord struct {
	// source is the address and port the datagram came from, with the zone the bind's endpoints name a link-local source's interface by
	source netip.AddrPort
}

// Datagram is one received IKE message and the endpoint it arrived from.
type Datagram struct {
	Raw      []byte
	Endpoint Endpoint
}

type espDatagramBatch struct {
	ticket  uint64
	packets [][]byte
	// bytes is this batch's charge against the queue's byte budget, kept with
	// it so every receive path releases exactly what was reserved.
	bytes int
}

// NewHub binds the one UDP socket every session shares, on localAddr's port
// and on all local IPv4 and IPv6 interfaces. underlay says how that socket is
// kept out of the reach of the routes the mesh installs, and rt carries what
// the caller had to resolve to answer it. See Underlay for why both platforms
// need one and why they need different things.
func NewHub(localAddr string, underlay Underlay, rt Runtime) (*Hub, error) {
	laddr, err := net.ResolveUDPAddr("udp", localAddr)
	if err != nil {
		return nil, fmt.Errorf("transport: resolve local addr: %w", err)
	}
	if laddr.IP != nil && !laddr.IP.IsUnspecified() {
		log.Printf("transport: binding to a specific local address (%s) is not supported, binding all interfaces on port %d instead", laddr.IP, laddr.Port)
	}
	index, err := bindUnderlay(underlay, rt)
	if err != nil {
		return nil, fmt.Errorf("transport: %w", err)
	}
	// Before the socket exists, for the same reason a move prepares before it
	// rebinds: the first datagram this node sends goes out of a socket that is
	// already bound, and nothing else will make that interface usable first.
	if index != 0 && rt.Routes != nil {
		if err := rt.Routes.Prepare(index); err != nil {
			return nil, fmt.Errorf("transport: prepare interface %d: %w", index, err)
		}
	}
	bind, fns, port, err := openPacketBind(uint16(laddr.Port), underlay, index, rt.Routes != nil, rt.Events)
	if err != nil {
		return nil, fmt.Errorf("transport: open bind: %w", err)
	}
	if index != 0 && rt.Routes != nil {
		if err := rt.Routes.Settle(index); err != nil {
			// The sockets are already open at this point, so returning
			// without closing them leaves both bound to the port for the life
			// of the process and the next attempt on it fails with EADDRINUSE.
			_ = bind.Close()
			return nil, fmt.Errorf("transport: settle on interface %d: %w", index, err)
		}
	}
	return startHub(bind, fns, port, underlay, index, rt), nil
}

func startHub(bind packetBind, fns []receiveFunc, port uint16, underlay Underlay, index int, rt Runtime) *Hub {
	h := &Hub{bind: bind, port: port, underlay: underlay, boundTo: index, events: rt.Events,
		muxes: make(map[*Mux]struct{}), done: make(chan struct{}), started: time.Now(), retired: make(map[uint32]int64)}
	h.tables.Store(&spiTables{ike: map[uint64]*Mux{}, esp: map[uint32]*Mux{}})
	h.reported.Store(-int64(dropReportInterval))
	h.scanned.Store(-int64(invalidSPIInterval))
	for _, fn := range fns {
		go h.receiveLoop(fn, h.readFailed)
	}
	if connector, ok := bind.(pairConnector); ok {
		h.pairs = &pairTable{connector: connector, events: rt.Events, pairs: make(map[pairKey]*pair)}
		go h.sweepPairsEvery()
	}
	// Started only where the binding has to follow something, so a hub that
	// binds nothing carries no goroutine and no link source.
	if underlay.Bind && rt.Links != nil {
		go h.follow(rt.Links, rt.Routes)
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
	m := &Mux{hub: h, endpoint: endpoint, dialed: dialed, ikeCh: make(chan Datagram, ikeQueueSize), espCh: make(chan espDatagramBatch, espChanSize), done: make(chan struct{}),
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
	return h.fail(fmt.Errorf("transport: closed"))
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
	if h.closed.Load() {
		h.fail(fmt.Errorf("transport: closed"))
	} else {
		h.fail(fmt.Errorf("transport: read: %w", err))
	}
}

// receiveLoop demultiplexes what fn reads until it fails, and then hands failed the error
func (h *Hub) receiveLoop(fn receiveFunc, failed func(error)) {
	batch := espSendBatch
	bufs, sizes, eps, records := make([][]byte, batch), make([]int, batch), make([]Endpoint, batch), make([]receiveRecord, batch)
	// demultiplexing records where each datagram goes and copies nothing
	// a datagram is copied below, once its queue has room for it
	type pendingIKE struct {
		mux   *Mux
		index int
	}
	espBatches := make(map[*Mux][][]byte)
	ikeDatagrams := make([]pendingIKE, 0, batch)
	unclaimed := make([]int, 0, batch)
	for {
		n, refused, err := fn(bufs, sizes, eps, records)
		if refused > 0 {
			h.refused.Add(uint64(refused))
		}
		if err != nil {
			failed(err)
			return
		}
		clear(espBatches)
		ikeDatagrams = ikeDatagrams[:0]
		unclaimed = unclaimed[:0]
		unwanted := 0
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
				unwanted++
				continue
			}
			if raw[0]|raw[1]|raw[2]|raw[3] == 0 {
				if len(raw) < nonESPMarkerLen+8 {
					unwanted++
					continue
				}
				spi := uint64(raw[4])<<56 | uint64(raw[5])<<48 | uint64(raw[6])<<40 | uint64(raw[7])<<32 | uint64(raw[8])<<24 | uint64(raw[9])<<16 | uint64(raw[10])<<8 | uint64(raw[11])
				if m := tables.ike[spi]; m != nil {
					ikeDatagrams = append(ikeDatagrams, pendingIKE{mux: m, index: i})
				} else if tables.listen != nil && eps[i] != nil {
					// An SA no Mux owns yet, which only a listening hub keeps.
					unclaimed = append(unclaimed, i)
				} else {
					unwanted++
				}
			} else {
				spi := uint32(raw[0])<<24 | uint32(raw[1])<<16 | uint32(raw[2])<<8 | uint32(raw[3])
				if m := tables.esp[spi]; m != nil {
					// Keep views into the receive buffers only until this socket
					// batch has been demultiplexed. packReceivedBatch below moves
					// all packets for a peer into one allocation before fn is
					// allowed to reuse the buffers.
					espBatches[m] = append(espBatches[m], raw)
				} else {
					unwanted++
					if !looked {
						looked = true
						h.unknownSPI(spi, records[i].source)
					}
				}
			}
		}
		if unwanted > 0 {
			h.refused.Add(uint64(unwanted))
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
				h.refused.Add(1)
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
				h.refused.Add(1)
			}
		}
		for m, packets := range espBatches {
			total := 0
			for _, packet := range packets {
				total += len(packet)
			}
			if p := m.pair.Load(); p != nil {
				h.carry(p, total)
			}
			// Tested before packReceivedBatch copies, so a flood is refused
			// without allocating for it.
			if !m.hasRoomForESP(total) || !m.dispatchESP(packReceivedBatch(packets), total) {
				h.noteDrop(len(packets), "a peer's ESP receive queue")
			}
		}
	}
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
		if !sentFrom(m.currentEndpoint(), source) {
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

// packReceivedBatch detaches packets from receiveLoop's reusable recvmmsg
// buffers with one allocation per peer and socket read, rather than one heap
// allocation per datagram. Packet slice boundaries are retained so parallel
// ESP workers can authenticate the batch without any further framing work.
func packReceivedBatch(packets [][]byte) [][]byte {
	total := 0
	for _, packet := range packets {
		total += len(packet)
	}
	storage := make([]byte, total)
	offset := 0
	for i, packet := range packets {
		n := copy(storage[offset:], packet)
		packets[i] = storage[offset : offset+n]
		offset += n
	}
	return packets
}

// Mux is one peer's logical IKE and ESP channel on a Hub.
type Mux struct {
	hub           *Hub
	endpointMu    sync.RWMutex
	endpoint      Endpoint
	dialed        bool
	ikeCh         chan Datagram
	espRecvMu     sync.Mutex
	espDispatchMu sync.Mutex
	espTicket     uint64
	espCh         chan espDatagramBatch
	espQueued     atomic.Int64
	espPending    [][]byte
	done          chan struct{}
	doneOnce      sync.Once
	doneErr       atomic.Value
	closed        atomic.Bool
	ownHub        bool
	// fragmented is the endpoint Fragment let the host fragment sends to, nil while it lets none
	fragmentMu sync.Mutex
	fragmented Endpoint
	// pair is the address pair m last sent on, which counts what m receives too
	pair atomic.Pointer[pair]
	// invalidSPI holds an SPI no mux holds that ESP from m's destination carried, for the session to tell its peer of
	invalidSPI chan uint32
}

// hasRoomForESP is consulted before packReceivedBatch copies a batch onto the
// heap. dispatchESP still decides, while this only keeps the copy from happening for
// a batch that is about to be dropped anyway.
func (m *Mux) hasRoomForESP(bytes int) bool {
	return len(m.espCh) < cap(m.espCh) && m.espQueued.Load()+int64(bytes) <= espQueueBytes
}

// dispatchESP hands one demultiplexed batch to this peer's receive queue under
// the ticket that fixes its order, and reports whether the queue took it. A
// dropped batch consumes no ticket, because a hub may have separate IPv4 and
// IPv6 receive loops and the gap would stall whichever emitter waits for it.
func (m *Mux) dispatchESP(packets [][]byte, bytes int) bool {
	m.espDispatchMu.Lock()
	defer m.espDispatchMu.Unlock()
	if m.espQueued.Load()+int64(bytes) > espQueueBytes {
		return false
	}
	batch := espDatagramBatch{ticket: m.espTicket, packets: packets, bytes: bytes}
	select {
	case m.espCh <- batch:
		m.espQueued.Add(int64(bytes))
		m.espTicket++
		return true
	default:
		return false
	}
}

// takeESP releases a batch's share of the queue's byte budget. Every path that
// reads from espCh goes through it, or the budget only ever shrinks.
func (m *Mux) takeESP(batch espDatagramBatch) [][]byte {
	m.espQueued.Add(-int64(batch.bytes))
	return batch.packets
}

// Dial preserves the one-peer convenience path. The returned mux owns its
// newly-created hub and closes it when closed.
func Dial(localAddr string, remoteIP net.IP, remotePort int) (*Mux, error) {
	h, err := NewHub(localAddr, Underlay{}, Runtime{})
	if err != nil {
		return nil, err
	}
	return dialOn(h, remoteIP, remotePort)
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
		return fmt.Errorf("transport: closed")
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
		return fmt.Errorf("transport: closed")
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
	return m.send([][]byte{out}, m.currentEndpoint())
}

func (m *Mux) currentEndpoint() Endpoint {
	m.endpointMu.RLock()
	defer m.endpointMu.RUnlock()
	return m.endpoint
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
// have moved since the session opened. It takes the same lock AdoptEndpoint
// writes under, so a diagnostic reads one endpoint rather than a torn one.
func (m *Mux) Endpoint() Endpoint {
	m.endpointMu.Lock()
	defer m.endpointMu.Unlock()
	return m.endpoint
}

func (m *Mux) SendIKETo(b []byte, endpoint Endpoint) error {
	out := make([]byte, nonESPMarkerLen+len(b))
	copy(out[nonESPMarkerLen:], b)
	return m.hub.bind.Send([][]byte{out}, endpoint)
}
func (m *Mux) SendESP(b []byte) error { return m.SendESPBatch([][]byte{b}) }

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

	endpoint := m.currentEndpoint()
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

func (m *Mux) RecvIKE() ([]byte, error) {
	b, _, err := m.RecvIKEFrom()
	return b, err
}
func (m *Mux) RecvIKEFrom() ([]byte, Endpoint, error) {
	select {
	case d := <-m.ikeCh:
		return d.Raw, d.Endpoint, nil
	case <-m.done:
		return nil, nil, m.doneError()
	}
}

// IKE is the channel this peer's IKE messages arrive on, so a control loop can
// select over it together with its own work instead of waking on a timer to
// check both. It is the same queue the Recv methods drain, so only one reader
// may use either at a time: the handshake uses Recv and hands over to the
// control loop once the SA is established.
func (m *Mux) IKE() <-chan Datagram { return m.ikeCh }

// Err is why this mux is done, for a caller that selected on Done itself.
func (m *Mux) Err() error { return m.doneError() }
func (m *Mux) RecvIKEUntil(deadline time.Time) ([]byte, error) {
	b, _, err := m.RecvIKEFromUntil(deadline)
	return b, err
}
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
func (m *Mux) RecvESP() ([]byte, error) {
	m.espRecvMu.Lock()
	defer m.espRecvMu.Unlock()
	if len(m.espPending) == 0 {
		select {
		case batch := <-m.espCh:
			m.espPending = m.takeESP(batch)
		case <-m.done:
			return nil, m.doneError()
		}
	}
	b := m.espPending[0]
	m.espPending = m.espPending[1:]
	return b, nil
}

// RecvESPBatchConcurrent returns one complete socket-demultiplexed batch and
// its receive-order ticket. It is safe for multiple data-plane workers to call
// concurrently: the transport channel distributes batches, while the ticket
// lets their independently decrypted results be emitted in original order.
// It must not be mixed with RecvESP, RecvESPBatch, or RecvESPUntil on one Mux.
func (m *Mux) RecvESPBatchConcurrent() (uint64, [][]byte, error) {
	select {
	case batch := <-m.espCh:
		return batch.ticket, m.takeESP(batch), nil
	case <-m.done:
		return 0, nil, m.doneError()
	}
}

// RecvESPBatch blocks for one ESP packet, then drains immediately available
// packets into dst up to its capacity. A nil dst gets the transport's normal
// batch capacity. Keeping the receive batch intact lets callers amortize
// decrypt-pipeline and TUN write overhead without delaying a lone packet.
func (m *Mux) RecvESPBatch(dst [][]byte) ([][]byte, error) {
	m.espRecvMu.Lock()
	defer m.espRecvMu.Unlock()
	if cap(dst) == 0 {
		dst = make([][]byte, 0, espSendBatch)
	} else {
		dst = dst[:0]
	}
	for len(dst) < cap(dst) {
		if len(m.espPending) == 0 {
			if len(dst) == 0 {
				select {
				case batch := <-m.espCh:
					m.espPending = m.takeESP(batch)
				case <-m.done:
					return nil, m.doneError()
				}
			} else {
				select {
				case batch := <-m.espCh:
					m.espPending = m.takeESP(batch)
				case <-m.done:
					return dst, nil
				default:
					return dst, nil
				}
			}
		}
		n := min(cap(dst)-len(dst), len(m.espPending))
		dst = append(dst, m.espPending[:n]...)
		m.espPending = m.espPending[n:]
	}
	return dst, nil
}

func (m *Mux) RecvESPUntil(deadline time.Time) ([]byte, error) {
	m.espRecvMu.Lock()
	defer m.espRecvMu.Unlock()
	if len(m.espPending) == 0 {
		select {
		case batch := <-m.espCh:
			m.espPending = m.takeESP(batch)
		case <-m.done:
			return nil, m.doneError()
		case <-time.After(time.Until(deadline)):
			return nil, errTimeout
		}
	}
	b := m.espPending[0]
	m.espPending = m.espPending[1:]
	return b, nil
}

var errTimeout = fmt.Errorf("transport: receive timeout")

func (m *Mux) closeDone(err error) { m.doneOnce.Do(func() { m.doneErr.Store(err); close(m.done) }) }
func (m *Mux) doneError() error {
	if err, _ := m.doneErr.Load().(error); err != nil {
		return err
	}
	return fmt.Errorf("transport: closed")
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
	m.closeDone(fmt.Errorf("transport: closed"))
	// a family fragmenting for this mux alone sends with DF again
	if err := m.Fragment(false); err != nil && !errors.Is(err, errors.ErrUnsupported) {
		slog.Warn("transport could not stop fragmenting sends for a closed mux", "endpoint", m.currentEndpoint().String(), "err", err)
	}
	if m.ownHub {
		return m.hub.Close()
	}
	return nil
}
