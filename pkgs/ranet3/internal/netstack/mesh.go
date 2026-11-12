// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

// Package netstack wires a real Linux TUN device to the ranet mesh: outbound
// packets the kernel routes to it are forwarded to whichever peer's Child SA
// can reach the destination (see RouteTable), and inbound packets decrypted
// from any peer are decided in the same table, and are written back to the
// device as if they'd arrived over any other interface where they are this
// node's, sent on to the next peer, or answered as a router answers (see
// DeliverInboundBatch).
// It knows nothing about ESP or IKE directly: peers are just a send function
// plus routes, so this package is testable without real crypto.
//
// This package never touches the device's address or route configuration:
// creating it, bringing it up and, on linux, setting its gso_max_segs is all it does. Assigning an address,
// and adding kernel routes to the TUN are the operator's responsibility.
// The embedded Babel speaker exchanges control traffic only inside ESP.
package netstack

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"ranet3.com/pkgs/ranet3/esp"
	"ranet3.com/pkgs/ranet3/internal/packet"
	"ranet3.com/pkgs/ranet3/srv6"
	"ranet3.com/pkgs/wireguard/tun"
)

type Mesh struct {
	Routes *RouteTable
	// Name is the TUN device's real interface name (e.g. "utun6" for "utun"), as
	// reported by the kernel, needed by whoever configures its address
	// and routes, since the kernel doesn't always honor the requested
	// name exactly.
	Name string

	// dev is the tun, nil for a mesh with none, and each of its queues a lane
	// a lane has a reader of its own, and write hands packets to the queue the lane names
	dev              tun.Device
	queues           []tun.Queue
	write            func(lane int, bufs [][]byte, offset int) (int, error)
	outboundJobs     chan *outboundBatch
	outboundFree     chan *outboundBatch
	inboundWriters   []chan inboundWriteBatch
	closed           chan struct{}
	closeOnce        sync.Once
	outboundReaderWG sync.WaitGroup
	outboundWorkerWG sync.WaitGroup
	writerWG         sync.WaitGroup

	// setMTU sets the MTU of the device named name, nil for a mesh with no device
	// a field so a test can record when it runs against the steering table in force
	setMTU func(name string, mtu int) error

	// readsTruncated counts the reads that lost the tail of a GSO frame, framesRefused the frames the device refused, and writesFailed the writes it refused
	readsTruncated, framesRefused, writesFailed reportedCount
	// events records the mesh's changes of state, nil recording nothing
	events func(kind, peer string, attrs ...slog.Attr)
	// ownedOnly is the read dropping a packet from a source this node does not own toward every destination but an IPv6 link-local one, rather than only toward an exit
	// where the kernel runs an entry rule that rule judges the rest, and passes an exit's egress replies, which the read cannot tell apart
	// written before the readers start and never after, so they read it without a lock
	ownedOnly bool
	// failed is closed once a reader finds the device gone while the mesh is not closing, nil for a mesh with no device
	failed     chan struct{}
	failedOnce sync.Once
	// mssClamped counts the lowerings ClampMSS made, a forwarded SYN lowered at two sessions counting twice, and tooBigAnswered the answers to packets past their session's budget it sent
	mssClamped, tooBigAnswered atomic.Uint64

	// segmentCounters is the segment routing state, in its own struct so that
	// everything this file does not touch stays in segments.go with the code
	// that does.
	segmentCounters
	egressReadiness
	laneState
	answerState
	transitState
	traceState
}

// outboundBatch owns the TUN buffers from one read until a crypto worker has
// encrypted every routed packet. Readers can therefore immediately continue
// with another buffer set instead of tying one encryption worker to each TUN
// queue (and to whatever flows the kernel happened to hash onto that queue).
type outboundBatch struct {
	n int
	// slab holds the packets of one read where reads says the device put them
	slab  []byte
	reads []tun.ReadPacket
	// packets is the view each packet of the read that goes to peers leaves as, of the slab or, once steered, of its side buffer
	// nothing writes the slab outside the packets it holds
	packets [][]byte
	// steered is each packet's side buffer, kept from read to read
	steered   [][]byte
	peers     []*Peer
	headers   []byte
	shares    map[*Peer]outboundShare
	batches   map[*Peer]*peerBatch
	peerOrder []*Peer
	// cut holds the fragments of the read's packets too large for their peers' sessions
	cut fragmentList
	// answers is the answers the reader whose read the batch holds keeps from one of its reads to the next, for the checks of a read off the tun
	answers *keptAnswers
	// free is the pool the batch goes back to once sealed, nil for a tun reader's, which goes back to outboundFree
	free chan *outboundBatch
	// from is the peer of the session whose packets a forward batch holds, nil for a tun reader's and for packets of no session
	// decide sets it at every take, traced or not, since a trace that opens while decide holds the batch reads it for its budget drops, and reset leaves it
	from *Peer
	// hold keeps the frames a forward batch's packets lie in until reset, after every peer's share is sealed, nil for a tun reader's
	hold Hold
	// tun is a tun reader's batch, whose packets were read off the tun
	tun bool
}

// outboundShare is one peer's part of a read
// count is the packets and fragments the read sends it, bytes what they come to, and mtu the largest packet its session carries, loaded once a read
type outboundShare struct {
	count int
	bytes int
	mtu   int
}

// outboundFragment is one fragment cut for a peer, with the next header its ESP trailer names
type outboundFragment struct {
	peer   *Peer
	header byte
	raw    []byte
}

// fragmentList is the fragments cut from the packets of one batch
// bytes holds them, and an outbound batch keeps its storage from read to read
type fragmentList struct {
	fragments []outboundFragment
	bytes     []byte
}

// add cuts inner, an IPv4 packet without DF, into the fragments RFC 791 makes of it, and queues them for peer under nextHeader
// header is the outer IPv6 header and routing header steering put in front of the packet, empty for a packet not steered
// each fragment goes behind its own copy of header, whose payload length then counts that fragment
// each fits mtu with its header
// it reports how many fragments it queued and their bytes, none for a packet that cannot be cut
// with the octet at fault AppendFragments names for one whose option list does not describe itself
func (l *fragmentList) add(peer *Peer, nextHeader byte, header, inner []byte, mtu int) (count, bytes, fault int) {
	start := len(l.bytes)
	var ok bool
	if l.bytes, fault, ok = packet.AppendFragments(l.bytes, header, inner, mtu-len(header)); !ok {
		return 0, 0, fault
	}
	for rest := l.bytes[start:]; len(rest) != 0; count++ {
		fragment, _ := packet.Payload(rest[len(header):])
		piece := rest[:len(header)+len(fragment)]
		rest = rest[len(piece):]
		if len(header) != 0 {
			// RFC 8200 section 3, the payload length counts everything after the 40 byte fixed header
			binary.BigEndian.PutUint16(piece[4:], uint16(len(piece)-40))
		}
		l.fragments = append(l.fragments, outboundFragment{peer: peer, header: nextHeader, raw: piece})
	}
	return count, len(l.bytes) - start, 0
}

// appendTo hands every fragment to its peer's batch, and leaves out those of a peer with none
func (l *fragmentList) appendTo(batches map[*Peer]*peerBatch) {
	for _, fragment := range l.fragments {
		if batch := batches[fragment.peer]; batch != nil {
			batch.append(fragment.raw, fragment.header)
		}
	}
}

// inboundWriteBatch is frames for one writer lane, which keeps hold until it has written them
type inboundWriteBatch struct {
	frames [][]byte
	hold   Hold
}

// NewRoutesOnly is a mesh with a forwarding table and no device, for a test
// that exercises routing and sessions rather than the dataplane. Creating a
// TUN needs root on every platform, and babel intercepts its own traffic
// before delivery, so a mesh that never carries a data packet does not need
// one. Delivering one to it is a no-op.
// SetMTU installs the steering and sets no MTU
func NewRoutesOnly() *Mesh {
	return &Mesh{Routes: NewRouteTable(), closed: make(chan struct{})}
}

// NewOnDevice is NewRoutesOnly writing what it delivers to dev, for a test
// outside this package that must see a packet the mesh hands to the host
// without the root a tun needs. It starts no reader or forward pipeline, so a
// forward goes nowhere, finding no batch to join. A delivery is written on the
// caller's goroutine where dev has one queue, and by the writer lanes it
// starts where dev has more, which Close stops.
func NewOnDevice(dev tun.Device) *Mesh {
	m := NewRoutesOnly()
	m.setDevice(dev)
	m.startInboundWriters()
	return m
}

// NewNamed attaches to or creates name through wireguard-go's TUN backend.
// an empty name opens defaultTUNName, which is always created and never attached to
// mtu is the device's MTU, zero taking DefaultMTU
// ownedOnly is the mesh's for its life, a host whose kernel runs no entry rule passing true
// events records the mesh's changes of state, nil recording nothing
func NewNamed(mtu int, name string, ownedOnly bool, events func(kind, peer string, attrs ...slog.Attr)) (*Mesh, error) {
	if mtu == 0 {
		mtu = DefaultMTU
	}
	if name == "" {
		name = defaultTUNName
	}
	// refused when the daemon starts, the file naming it having loaded on every platform
	// wireguard-go would open utun5x as utun5 and turn a unit past 32 bits into another one
	if utunNamesOnly && !isUTUNName(name) {
		return nil, fmt.Errorf("netstack: create tun device: link.tun %q is a name darwin cannot create: its utun control makes %s, the next free unit, and %s followed by a unit number, and nothing else", name, utunName, utunName)
	}
	queueCount := max(1, runtime.GOMAXPROCS(0))
	dev, actualName, err := createTUNQueues(name, mtu, queueCount)
	if err != nil {
		// wireguard-go hands back the utun control's errno without the name it was asked for
		if utunNamesOnly {
			err = fmt.Errorf("link.tun %q: %w", name, err)
		}
		return nil, fmt.Errorf("netstack: create tun device: %w", err)
	}
	if err := bringTUNUp(actualName); err != nil {
		_ = dev.Close()
		return nil, fmt.Errorf("netstack: bring tun device up: %w", err)
	}
	m := &Mesh{
		Routes:    NewRouteTable(),
		Name:      actualName,
		setMTU:    setTUNMTU,
		closed:    make(chan struct{}),
		events:    events,
		ownedOnly: ownedOnly,
	}
	m.setDevice(dev)
	m.startSegmentReports()
	m.startInboundWriters()
	m.startOutboundPipeline()
	return m, nil
}

// setDevice makes dev the mesh's tun, each of its queues a lane
func (m *Mesh) setDevice(dev tun.Device) {
	m.dev, m.queues, m.write = dev, tun.QueuesOf(dev), tun.WriteToOf(dev)
	m.failed = make(chan struct{})
}

// QueueCount reports the number of independent TUN I/O lanes.
func (m *Mesh) QueueCount() int { return len(m.queues) }

// MTU is the device's own, asked of the kernel each time
// NewNamed sets it on a device it attaches to as on one it creates, and SetMTU on a reload
// anything else on the host may change it after, which this reports as it finds it
// zero means the device could not answer, which is a device on its way out
func (m *Mesh) MTU() int {
	if m.dev == nil {
		return 0
	}
	mtu, err := m.dev.MTU()
	if err != nil {
		return 0
	}
	return mtu
}

// CheckMTU refuses a move of the tun's MTU this mesh cannot take without a restart
func (m *Mesh) CheckMTU() error {
	if !tunMTUSettable {
		return errors.New("netstack: this platform sets the tun mtu only when the mesh opens it, restart to apply")
	}
	return nil
}

// SetMTU sets the device's MTU to mtu and installs steering, the table the device runs under
// a longer list than the one in force goes in after the device comes down for it
// a shorter one goes in before the device goes up
// so no read off the tun, with the steering header in force on it, outgrows the larger of the two link MTUs at any moment
// CheckMTU has to have taken the move
func (m *Mesh) SetMTU(mtu int, steering *srv6.SteerTable) error {
	set := func() error {
		if m.setMTU == nil {
			return nil
		}
		if err := m.setMTU(m.Name, mtu); err != nil {
			return fmt.Errorf("netstack: set the mtu of %s to %d: %w", m.Name, mtu, err)
		}
		return nil
	}
	if steering.Overhead() > m.Steering().Overhead() {
		if err := set(); err != nil {
			return err
		}
		m.SetSteering(steering)
		return nil
	}
	m.SetSteering(steering)
	return set()
}

func (m *Mesh) startOutboundPipeline() {
	workers := max(1, runtime.GOMAXPROCS(0))
	// the sessions' forwarded packets fill batches of their own, and the job queue holds those beside the readers'
	m.forwardFree = make(chan *outboundBatch, outboundJobsPerWorker*workers)
	m.outboundJobs = make(chan *outboundBatch, outboundJobsPerWorker*workers+cap(m.forwardFree))
	m.outboundFree = make(chan *outboundBatch, outboundJobsPerWorker*workers+len(m.queues))
	for range cap(m.outboundFree) {
		m.outboundFree <- newOutboundBatch(m.dev.BatchSize())
	}
	for range cap(m.forwardFree) {
		m.forwardFree <- newForwardBatch(m.dev.BatchSize(), m.forwardFree)
	}
	for range workers {
		m.outboundWorkerWG.Add(1)
		go m.outboundWorker()
	}
	for _, queue := range m.queues {
		m.outboundReaderWG.Add(1)
		go m.outboundReader(queue)
	}
}

func newOutboundBatch(size int) *outboundBatch {
	return &outboundBatch{
		slab:      make([]byte, outboundSlabSize),
		reads:     make([]tun.ReadPacket, size),
		packets:   make([][]byte, size),
		steered:   make([][]byte, size),
		peers:     make([]*Peer, size),
		headers:   make([]byte, size),
		shares:    make(map[*Peer]outboundShare),
		batches:   make(map[*Peer]*peerBatch),
		peerOrder: make([]*Peer, 0, size),
		tun:       true,
	}
}

// newForwardBatch is a batch of size packets a session's delivery forwards, going back to free once sealed
// its packets stay in the frames the session delivered them in, so it holds no slab
func newForwardBatch(size int, free chan *outboundBatch) *outboundBatch {
	return &outboundBatch{
		packets:   make([][]byte, size),
		peers:     make([]*Peer, size),
		headers:   make([]byte, size),
		shares:    make(map[*Peer]outboundShare),
		batches:   make(map[*Peer]*peerBatch),
		peerOrder: make([]*Peer, 0, size),
		free:      free,
	}
}

// PoolBytes is the bytes the mesh's pools hold, which the node counts in its own Go heap: the read batches startOutboundPipeline makes, a slab each and their packets' slices, the forward batches' slices, and each tun queue's own buffers
// none for a mesh with no device
func (m *Mesh) PoolBytes() int64 {
	if m.dev == nil {
		return 0
	}
	size := int64(m.dev.BatchSize())
	// packets, peers, peerOrder and headers, and a read batch's reads and steered beside them
	forward := size * int64(unsafe.Sizeof([]byte(nil))+2*unsafe.Sizeof((*Peer)(nil))+1)
	read := outboundSlabSize + forward + size*int64(unsafe.Sizeof(tun.ReadPacket{})+unsafe.Sizeof([]byte(nil)))
	return int64(cap(m.outboundFree))*read + int64(cap(m.forwardFree))*forward + int64(len(m.queues))*tunQueueBytes
}

// outboundReader only reads and classifies packets. Reserving each peer's ESP
// sequence range here fixes the order before independently scheduled workers
// encrypt later batches, so the ordered sender can restore per-flow FIFO.
func (m *Mesh) outboundReader(queue tun.Queue) {
	defer m.outboundReaderWG.Done()
	// the reader keeps the answers rather than a batch, which the readers of every queue take in turn
	// the kernel holds each flow to one queue at a time, so the answers are for the flows this queue reads
	var answers keptAnswers
	for {
		var b *outboundBatch
		select {
		case b = <-m.outboundFree:
		case <-m.closed:
			return
		}
		n, err := queue.Read(b.slab, b.reads)
		// ErrTooManySegments comes with the n packets of the GSO frame that fit, each whole, and ErrInvalidFrame with none
		// either way only that one frame is lost and the device stays readable
		switch {
		case err == nil:
		case errors.Is(err, tun.ErrTooManySegments):
			m.noteTruncatedRead()
		case errors.Is(err, tun.ErrInvalidFrame):
			m.noteRefusedFrame(err)
		default:
			// any other error is the device gone, or closed by Close
			m.outboundFree <- b
			m.noteDeviceGone(err)
			return
		}
		b.n, b.answers = n, &answers
		m.classify(b)
		if len(b.peerOrder) == 0 {
			b.reset()
			m.outboundFree <- b
			continue
		}
		m.dispatchOutbound(b)
	}
}

// classify picks the peer of every packet of a read that passes the checks of what enters the mesh, and holds each packet to the largest its peer's session carries
// a packet past that is answered, cut into fragments or dropped rather than sent, and a SYN within it has its MSS clamped to it
func (m *Mesh) classify(b *outboundBatch) {
	trace := m.tracer.Load()
	var tally transitTally
	defer m.addTally(&tally)
	var steers steerTally
	defer m.addSteerTally(&steers)
	segments := m.segmentTable.Load()
	// read once a read beside the segments, so the owned-source arm and the steer judge each packet by one table
	steering := m.steerTable.Load()
	// read once a read, so every change in force as the read begins reaches each of its packets
	b.answers.keepFor(m.Routes.generation.Load())
	for i := range b.n {
		r := b.reads[i]
		raw := b.slab[r.Offset : r.Offset+r.Size : r.Offset+r.Size]
		src, dst, nh, ok := addrsOf(raw)
		if !ok {
			m.dropTransit(&tally, transitInvalid, netip.Addr{}, netip.Addr{})
			if trace != nil {
				trace.read(TraceDrop, transitInvalid, netip.Addr{}, raw)
			}
			continue
		}
		// the mesh routes no group and forwards no limited broadcast, RFC 1812 section 5.3.5.1
		// and a covering unicast route, a default among them, would carry either to one peer
		if group(dst) {
			tally.add(transitMulticast)
			if trace != nil {
				trace.read(TraceDrop, transitMulticast, netip.Addr{}, raw)
			}
			continue
		}
		// the checks judge a steered packet by the destination it was read with
		peer, verdict, match := m.Routes.Resolve(src, dst)
		// mode off pays the nil test alone, since takesPath is past the inliner's budget
		alongPath, leaves := false, match.Counted
		if steering.Default() != nil {
			alongPath, leaves = m.takesPath(steering, verdict, match, dst)
		}
		if reason, dropped := m.edgeCheck(b.answers, segments, raw, nh, src, dst, leaves); dropped {
			m.dropTransit(&tally, reason, src, dst)
			if trace != nil {
				trace.read(TraceDrop, reason, netip.Addr{}, raw)
			}
			continue
		}
		// a steered packet is routed by the segment it is going to rather than by the address it was read with
		// and its record names the read's addresses and the first segment
		sent, segment := raw, netip.Addr{}
		if policy, path := m.steerPolicy(steering, src, dst, alongPath); policy != nil {
			if b.steered[i], ok = m.steer(b.steered[i][:0], raw, policy); !ok {
				tally.add(transitTooBig)
				if trace != nil {
					trace.read(TraceDrop, transitTooBig, policy.Path[0], raw)
				}
				continue
			}
			steers.steered++
			if path {
				steers.pathSteered++
			}
			// steer's encapsulation is a whole IPv6 packet
			sent, nh = b.steered[i], esp.NextHeaderIPv6
			outer, first := addressesOf(sent, 6)
			var firstMatch Match
			if peer, verdict, firstMatch = m.Routes.Resolve(outer, first); firstUnrouted(path, verdict, firstMatch) {
				steers.unrouted++
				if path {
					steers.pathUnrouted++
				}
				m.reportUnroutedSegment(first, verdict, firstMatch)
				verdict, match, segment = RouteNone, Match{}, first
			}
		}
		if verdict != RoutePeer {
			switch {
			case verdict == RouteLocal && m.holdsAddress(dst):
				// raw is the read itself, since a steered read whose first segment is this node's own is RouteNone
				m.writeBack(raw)
				tally.add(transitDelivered)
				if trace != nil {
					trace.read(TraceDeliver, transitDelivered, netip.Addr{}, raw)
				}
			default:
				reason := unroutedReason(verdict)
				if verdict == RouteLocal {
					m.dropTransit(&tally, reason, src, dst)
				} else {
					tally.add(reason)
				}
				switch {
				// no error answers a broadcast or comes from an address naming no host
				case verdict == RouteLocal && namesNoHost(dst, match.Bits):
					if trace != nil {
						trace.read(TraceDrop, reason, segment, raw)
					}
				case trace != nil:
					trace.unroutedRead(m, raw, verdict, match, src, dst, segment)
				default:
					m.answerUnroutedRead(raw, verdict, match, src, dst, (*Mesh).takeICMPToken)
				}
			}
			continue
		}
		share, seen := b.shares[peer]
		if !seen {
			share.mtu = peer.MTU()
			b.peerOrder = append(b.peerOrder, peer)
		}
		// a steered packet sits behind the header steering put on it, which the session carries as well
		overhead := len(sent) - len(raw)
		if len(sent) > share.mtu {
			var count, bytes int
			var kind answerKind
			if trace != nil {
				count, bytes, kind = trace.tooBig(m, b, raw, sent, peer, nh, share.mtu)
			} else {
				count, bytes, kind, _ = m.tooBig(b, sent, overhead, peer, nh, share.mtu, (*Mesh).takeICMPToken)
			}
			if count == 0 {
				m.dropTransit(&tally, tooBigReason(kind), src, dst)
			}
			share.count += count
			share.bytes += bytes
		} else {
			if trace != nil {
				trace.readSent(raw, sent, peer, false, 0, answerNone, TraceNoAnswer)
			}
			m.ClampMSS(sent[overhead:], share.mtu-overhead)
			b.packets[i], b.peers[i], b.headers[i] = sent, peer, nh
			share.count++
			share.bytes += len(sent)
		}
		b.shares[peer] = share
	}
}

// answerUnroutedRead answers raw, where an ICMP error may answer it and as src's bucket and the node's cap allow, a packet the host routed into the tun from src to dst, where the table, answering verdict and match, reaches dst by no route or holds it
// the answer is the one unreachable gives, from dst, and goes back into the tun, the one link the packet came by, whatever src is
// answer's reply route is a session's, and would send the answer to a host packet from an uplink address out through the mesh or nowhere
// verdict is RouteNone or RouteHeld, or RouteLocal for a read the table answers as this node's own, its own default included, that the tun does not hold and the mesh could only hand back to the host
// a steered read whose first segment firstUnrouted finds unrouted is answered as RouteNone, RFC 4443 section 3.1 having the originating node's IPv6 layer answer it
// it draws through take, and reports the kind of the answer and its fate as answerTaking does
func (m *Mesh) answerUnroutedRead(raw []byte, verdict Verdict, match Match, src, dst netip.Addr, take takeAnswer) (answerKind, TraceOutcome) {
	kind := m.unreachable(verdict, match, dst)
	out := buildAnswer(raw, raw[0]>>4, kind, 0, dst, m.AnswerTTL(), m.allowAnswer(take, src))
	if out == nil {
		return kind, TraceNotAnswerable
	}
	m.writeHostPacket(out)
	m.noteAnswered(kind)
	return kind, TraceSent
}

// tooBigReason is the reason a packet too big for its session and cut into no fragment is dropped for, invalid where its answer is about its options
func tooBigReason(kind answerKind) transitReason {
	if kind == answerParameter {
		return transitInvalid
	}
	return transitTooBig
}

// tooBig takes a packet larger than mtu, the largest its peer's session carries, and reports how many fragments it queued for the peer and their bytes
// and the kind of the answer it drew through take and that answer's fate as answerTaking reports it, TraceNoAnswer where the cut left no fault to answer
// overhead is the header steering put in front of the packet
// the packet behind it is held to mtu less that header
// an answer goes into the tun, whichever side of it the source sits
func (m *Mesh) tooBig(b *outboundBatch, raw []byte, overhead int, peer *Peer, nextHeader byte, mtu int, take takeAnswer) (int, int, answerKind, TraceOutcome) {
	inner := raw[overhead:]
	answer, cut, _ := m.answerTooBig(inner, mtu-overhead, false, netip.Addr{}, take)
	if cut {
		count, bytes, fault := b.cut.add(peer, nextHeader, raw[:overhead], inner, mtu)
		if fault == 0 {
			return count, bytes, answerNone, TraceNoAnswer
		}
		if answer, _ = m.answerOptions(inner, fault, false, take); answer == nil {
			return count, bytes, answerParameter, TraceNotAnswerable
		}
		m.writeHostPacket(answer)
		m.noteAnswered(answerParameter)
		return count, bytes, answerParameter, TraceSent
	}
	if answer == nil {
		return 0, 0, answerTooBig, TraceNotAnswerable
	}
	m.writeHostPacket(answer)
	m.noteAnswered(answerTooBig)
	return 0, 0, answerTooBig, TraceSent
}

// TUNReadsTruncated is how many reads off the tun lost the tail of a GSO frame
// because it split into more segments than one read holds
func (m *Mesh) TUNReadsTruncated() uint64 { return m.readsTruncated.total.Load() }

// TUNFramesRefused is how many frames read off the tun the device could not decode into packets
func (m *Mesh) TUNFramesRefused() uint64 { return m.framesRefused.total.Load() }

// TUNWritesFailed is how many writes to the tun returned an error, each up to inboundWriteBatchSize frames
func (m *Mesh) TUNWritesFailed() uint64 { return m.writesFailed.total.Load() }

// Failed is closed once the device is gone, the error line and the event netstack.tun.failed written before it
// nothing in the process can make the device again, and a mesh with no device never fails
func (m *Mesh) Failed() <-chan struct{} { return m.failed }

// noteTruncatedRead counts one read cut short
// and warns at most once an interval with the count since the last warning
func (m *Mesh) noteTruncatedRead() {
	if reads, warn := m.readsTruncated.add(int64(time.Since(m.segmentsStarted))); warn {
		slog.Warn("netstack tun reads lost the tail of a gso frame", "interface", m.Name, "reads", reads)
	}
}

// noteRefusedFrame counts one frame the device refused with err
// and warns and records an event at most once an interval with the count since the last warning
func (m *Mesh) noteRefusedFrame(err error) {
	frames, warn := m.framesRefused.add(int64(time.Since(m.segmentsStarted)))
	if !warn {
		return
	}
	slog.Warn("netstack tun refused a frame", "interface", m.Name, "frames", frames, "err", err)
	if m.events != nil {
		m.events("netstack.tun.refused", "", slog.String("interface", m.Name), slog.Uint64("frames", frames), slog.String("err", err.Error()))
	}
}

// noteFailedWrite counts one write to lane that the device refused with err
// and warns at most once an interval with the count since the last warning, unless the mesh is closing or the device is gone
func (m *Mesh) noteFailedWrite(lane int, err error) {
	writes, warn := m.writesFailed.add(int64(time.Since(m.segmentsStarted)))
	if !warn {
		return
	}
	// a device reported gone refuses every write until the shutdown it started closes the mesh
	select {
	case <-m.closed:
	case <-m.failed:
	default:
		slog.Warn("netstack tun refused a write", "interface", m.Name, "queue", lane, "writes", writes, "err", err)
	}
}

// noteDeviceGone reports err, which ended a queue's reader, unless the mesh is closing
// the first reader to see the device gone reports it, and the readers after it stop with nothing to add
func (m *Mesh) noteDeviceGone(err error) {
	select {
	case <-m.closed:
		return
	default:
	}
	m.failedOnce.Do(func() {
		slog.Error("netstack tun failed", "interface", m.Name, "err", err)
		if m.events != nil {
			m.events("netstack.tun.failed", "", slog.String("interface", m.Name), slog.String("err", err.Error()))
		}
		close(m.failed)
	})
}

// reportedCount spaces the reports of one kind of trouble, a warning or an event, an interval apart
// add counts the trouble in total and claims the report, and a report whose count is kept elsewhere uses claim, with since where it gives the count since the last report
type reportedCount struct {
	total atomic.Uint64
	// next is the earliest the next report may go out
	// in nanoseconds since its owner's start, segmentsStarted or Peer.started, which keeps it on the monotonic clock
	// zero lets the first one report at once
	next atomic.Int64
	// reported is total as the last report gave it
	reported atomic.Uint64
	// interval is the least time between two reports, zero meaning reportInterval
	interval time.Duration
}

// add counts one at now, in nanoseconds since segmentsStarted
// and reports whether the caller reports, with the count since the last report
func (c *reportedCount) add(now int64) (uint64, bool) {
	total := c.total.Add(1)
	if !c.claim(now, c.next.Load()) {
		return 0, false
	}
	return c.since(total), true
}

// since is how many of total came since the last report, which the caller holding the claim writes with total
func (c *reportedCount) since(total uint64) uint64 {
	return total - c.reported.Swap(total)
}

// claim says whether the caller that counted one at now writes the report
// next is the earliest time of the next report as that caller loaded it
// of the callers that loaded the same next only the first to claim it writes one
// and its claim moves the next report an interval past now
// a reading of a clock no constructor started saturates, so the first claim's now+interval wraps below now
// and every claim whose next was loaded after it succeeds, swapping next for the value it already holds
func (c *reportedCount) claim(now, next int64) bool {
	interval := c.interval
	if interval == 0 {
		interval = reportInterval
	}
	return now >= next && c.next.CompareAndSwap(next, now+int64(interval))
}

// a reservation takes its peer's reserveMu alone
// so a reader preempted between two reservations holds back only the peers whose places it holds
//
// Nothing here waits for a peer's budget, only for room in the job queue. A batch read off one queue carries whichever
// destinations the kernel hashed onto it, so waiting for room in one peer's
// budget would stop forwarding to every other peer as well: a single
// backpressured socket would take the whole dataplane down with it, and a
// budget that is full stays full for as long as the transport is behind. That
// peer's share of the batch is dropped instead, the way a full egress queue
// drops, and every other peer's packets go out on time. The drop is counted
// per peer.
func (m *Mesh) dispatchOutbound(b *outboundBatch) {
	for _, peer := range b.peerOrder {
		// a peer whose packets of the read were all answered or refused takes no place
		if share := b.shares[peer]; share.count != 0 {
			if batch := peer.reserveBatchNow(share.count, share.bytes); batch != nil {
				b.batches[peer] = batch
			} else if trace := m.tracer.Load(); trace != nil {
				trace.refused(b, peer)
			}
		}
	}
	// a send that finds the queue full waits, which holds back the tun reader or the session delivery sending b
	// and the peers whose places b holds, whose senders wait for b's batches to be sealed
	// workers drain the queue during Close, every reserved place included
	m.outboundJobs <- b
}

func (m *Mesh) outboundWorker() {
	defer m.outboundWorkerWG.Done()
	for b := range m.outboundJobs {
		for i := 0; i < b.n; i++ {
			// A peer with no batch had no room in its budget, so its share of
			// this read was dropped before the places were handed out.
			if peer := b.peers[i]; peer != nil && b.batches[peer] != nil {
				b.batches[peer].append(b.packets[i], b.headers[i])
			}
		}
		// fragments go out after the read's other packets, where a later packet of the same read may overtake a cut one
		// only IPv4 without DF is cut, and IP promises its datagrams no order
		b.cut.appendTo(b.batches)
		for _, peer := range b.peerOrder {
			batch := b.batches[peer]
			if batch == nil {
				continue
			}
			if err := batch.finish(); err != nil {
				peer.noteSendError(err, false)
			}
		}
		b.reset()
		free := b.free
		if free == nil {
			free = m.outboundFree
		}
		select {
		case free <- b:
		case <-m.closed:
		}
	}
}

func (b *outboundBatch) reset() {
	if b.hold != nil {
		b.hold.Release()
		b.hold = nil
	}
	for i := 0; i < b.n; i++ {
		b.peers[i] = nil
	}
	b.n = 0
	clear(b.shares)
	clear(b.batches)
	clear(b.peerOrder)
	b.peerOrder = b.peerOrder[:0]
	clear(b.cut.fragments)
	b.cut.fragments = b.cut.fragments[:0]
	b.cut.bytes = b.cut.bytes[:0]
}

// addrsOf extracts both the source and destination address from a raw IP
// packet. The route table needs both to support source-specific (SADR)
// routes, not just the destination.
func addrsOf(raw []byte) (src, dst netip.Addr, nextHeader byte, ok bool) {
	src, dst, version := packet.Addrs(raw)
	switch version {
	case 4:
		return src, dst, esp.NextHeaderIPv4, true
	case 6:
		return src, dst, esp.NextHeaderIPv6, true
	default:
		return src, dst, 0, false
	}
}

// DeliverInbound hands the mesh one already-decapsulated tunnel-mode IP packet of no session, as DeliverInboundBatch does
// it copies raw into a frame of its own, raw staying the caller's
// mtu is the largest packet the session it came through carries, as DeliverInboundBatch takes it
// only tests call it, those of internal/babel, internal/client and internal/netstack
func (m *Mesh) DeliverInbound(raw []byte, mtu int) {
	m.DeliverInboundBatch([][]byte{m.hostFrame(raw)}, mtu, nil, nil)
}

// DeliverInboundBatch hands the mesh a group of already-decapsulated tunnel-mode IP packets a session delivered, in the order it delivered them
// this node's segments act on the packets addressed to them, and the forwarding decision takes the rest
// each frame is TUNHeadroom bytes a write to the tun may overwrite, then the packet to the frame's end
// the frames are the mesh's from the call until a lane has written them or a worker has sealed them, and the tun is handed them as they are
// hold covers their storage, and the caller keeps its own reference until the call returns, so a lane, a forward batch or an exit that reads a frame later retains it
// mtu is the largest packet the session they came through carries, zero for packets of no session
// a SYN that an End.DT46 of this node takes out of its outer header has its MSS clamped to it
// from is the peer of that session, which an answer about a link-local source goes back to, nil for packets of no session
func (m *Mesh) DeliverInboundBatch(frames [][]byte, mtu int, from *Peer, hold Hold) {
	// A mesh with no device only exists in a test, where nothing should reach
	// here: babel's own traffic is intercepted before delivery.
	if len(frames) == 0 || m.dev == nil {
		return
	}
	routed, granted := m.applySegments(frames, mtu, from, hold)
	m.WriteHost(m.decide(routed, granted, from, hold), hold)
}

// hostFrame is raw copied into a frame of its own for the tun, TUNHeadroom bytes and then the packet, nil for a mesh with no device
func (m *Mesh) hostFrame(raw []byte) []byte {
	if m.dev == nil {
		return nil
	}
	frame := make([]byte, TUNHeadroom+len(raw))
	copy(frame[TUNHeadroom:], raw)
	return frame
}

// writeHostPacket writes one packet to the tun, copied into a frame of its own
func (m *Mesh) writeHostPacket(raw []byte) {
	if frame := m.hostFrame(raw); frame != nil {
		m.WriteHost([][]byte{frame}, nil)
	}
}

// writeBack writes raw, a read off the tun to an address the tun holds, back into it, where the host's kernel takes it as arriving for that address
// as read, but for the transport checksum completeChecksum completes
func (m *Mesh) writeBack(raw []byte) {
	if frame := m.hostFrame(raw); frame != nil {
		completeChecksum(frame[TUNHeadroom:])
		m.WriteHost([][]byte{frame}, nil)
	}
}

// completeChecksum sets the checksum of raw, an IPv6 packet whose next header is UDP or TCP, to the one its bytes call for where it does not verify, and changes nothing else
// a host sending to an address of its own computes that checksum for its loopback interface, whose offload never runs on the copy it routes into the tun
// with an extension header the host computes the checksum itself, and an IPv4 packet routed into the tun carries a computed one
// raw is a read addrsOf took, which is exactly one packet, so an IPv6 read's segment runs from its fixed header to its end
func completeChecksum(raw []byte) {
	if raw[0]>>4 != 6 {
		return
	}
	segment, protocol := raw[40:], raw[6]
	var field int
	switch {
	// RFC 768
	case protocol == 17 && len(segment) >= 8:
		field = 6
	case protocol == tcpProtocol && len(segment) >= tcpHeaderLen:
		field = tcpChecksum
	default:
		return
	}
	old := binary.BigEndian.Uint16(segment[field:])
	// the pseudo-header of RFC 8200 section 8.1, its upper-layer length the payload length, which fits 16 bits
	sum := tun.Checksum(segment, tun.PseudoHeaderChecksum(protocol, raw[8:24], raw[24:40], uint16(len(segment))))
	// RFC 8200 section 8.1 has a receiver discard an IPv6 UDP datagram whose checksum field is zero, whatever the sum
	if sum == 0xffff && (protocol != 17 || old != 0) {
		return
	}
	// RFC 1624 section 3, the field's old value taken out of the sum
	without := uint32(sum) + uint32(^old)
	checksum := ^uint16(without&0xffff + without>>16)
	// RFC 8200 section 8.1 sends a UDP checksum computed as zero as all ones
	if checksum == 0 && protocol == 17 {
		checksum = 0xffff
	}
	binary.BigEndian.PutUint16(segment[field:], checksum)
}

// WriteHost writes frames to the tun, on a multiqueue tun each to the persistent writer lane of its inner flow
// which keeps each flow's order and lets the kernel take unrelated flows in parallel
// each frame is TUNHeadroom bytes and then the packet, the mesh's until a lane has written it
// hold covers their storage as DeliverInboundBatch's does, and each lane handed a group retains it until that group is written
// the kernel exit writes what it egresses through it, as the mesh writes what it delivers
func (m *Mesh) WriteHost(frames [][]byte, hold Hold) {
	if len(frames) == 0 {
		return
	}
	if len(m.queues) == 1 {
		for len(frames) != 0 {
			n := min(len(frames), inboundWriteBatchSize)
			m.writeInbound(0, frames[:n])
			frames = frames[n:]
		}
		return
	}

	groups := make([][][]byte, len(m.queues))
	for _, frame := range frames {
		lane := int(innerFlowHash(frame[TUNHeadroom:]) % uint64(len(m.queues)))
		groups[lane] = append(groups[lane], frame)
	}
	for lane, group := range groups {
		if len(group) == 0 {
			continue
		}
		// retained before the send, since the lane may write and release before the send returns
		// an entry left in a lane after Close is never written or released, and its storage is the collector's
		if hold != nil {
			hold.Retain()
		}
		select {
		case m.inboundWriters[lane] <- inboundWriteBatch{frames: group, hold: hold}:
		case <-m.closed:
			if hold != nil {
				hold.Release()
			}
		}
	}
}

func (m *Mesh) startInboundWriters() {
	if len(m.queues) <= 1 {
		return
	}
	m.inboundWriters = make([]chan inboundWriteBatch, len(m.queues))
	for lane := range m.queues {
		queue := make(chan inboundWriteBatch, inboundWriteQueueSize)
		m.inboundWriters[lane] = queue
		m.writerWG.Go(func() {
			pending := make([][]byte, 0, inboundPendingBatches*inboundWriteBatchSize)
			holds := make([]Hold, 0, inboundPendingBatches)
			for {
				var first inboundWriteBatch
				select {
				case first = <-queue:
				case <-m.closed:
					return
				}

				pending, holds = collectReadyInbound(first, queue, pending, holds)
				for offset := 0; offset < len(pending); offset += inboundWriteBatchSize {
					end := min(offset+inboundWriteBatchSize, len(pending))
					m.writeInbound(lane, pending[offset:end])
				}
				// a tun write keeps no frame past its return
				for _, hold := range holds {
					hold.Release()
				}
				clear(pending)
				pending = pending[:0]
				clear(holds)
				holds = holds[:0]
			}
		})
	}
}

// collectReadyInbound drains only work that is already available. This keeps
// the idle-path latency unchanged while giving a busy writer a full batch for
// the tun write's GRO pass, reducing the number of TUN write syscalls. It
// appends the hold of each batch it takes to holds.
func collectReadyInbound(first inboundWriteBatch, queue <-chan inboundWriteBatch, pending [][]byte, holds []Hold) ([][]byte, []Hold) {
	pending, holds = appendInbound(first, pending, holds)
	for len(pending) < inboundWriteBatchSize {
		select {
		case batch := <-queue:
			pending, holds = appendInbound(batch, pending, holds)
		default:
			return pending, holds
		}
	}
	return pending, holds
}

func appendInbound(batch inboundWriteBatch, pending [][]byte, holds []Hold) ([][]byte, []Hold) {
	if batch.hold != nil {
		holds = append(holds, batch.hold)
	}
	return append(pending, batch.frames...), holds
}

func (m *Mesh) writeInbound(lane int, frames [][]byte) {
	if _, err := m.write(lane, frames, TUNHeadroom); err != nil {
		m.noteFailedWrite(lane, err)
	}
}

// innerFlowHash assigns both directions of an inner TCP/UDP flow to the same
// lane. The commutative endpoint mix is useful for request/response workloads,
// while the final avalanche avoids the sequential-port clustering produced by
// taking low hash bits.
func innerFlowHash(packet []byte) uint64 {
	var src, dst []byte
	var protocol byte
	var payload []byte
	fragmented := false
	if len(packet) >= 20 && packet[0]>>4 == 4 {
		headerLength := int(packet[0]&0x0f) * 4
		if headerLength < 20 || headerLength > len(packet) {
			return hashBytes(packet)
		}
		protocol, src, dst = packet[9], packet[12:16], packet[16:20]
		payload = packet[headerLength:]
		fragmented = binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0
	} else if len(packet) >= 40 && packet[0]>>4 == 6 {
		protocol, src, dst = packet[6], packet[8:24], packet[24:40]
		payload = packet[40:]
	} else {
		return hashBytes(packet)
	}

	srcHash, dstHash := hashBytes(src), hashBytes(dst)
	if !fragmented && len(payload) >= 4 && (protocol == 6 || protocol == 17) {
		srcPort := binary.BigEndian.Uint16(payload[:2])
		dstPort := binary.BigEndian.Uint16(payload[2:4])
		srcHash ^= uint64(srcPort) * 0x9e3779b185ebca87
		dstHash ^= uint64(dstPort) * 0x9e3779b185ebca87
	}
	h := srcHash ^ dstHash ^ uint64(protocol)*0x517cc1b727220a95
	h ^= h >> 30
	h *= 0xbf58476d1ce4e5b9
	h ^= h >> 27
	h *= 0x94d049bb133111eb
	return h ^ h>>31
}

func hashBytes(raw []byte) uint64 {
	h := uint64(14695981039346656037)
	for _, b := range raw {
		h ^= uint64(b)
		h *= 1099511628211
	}
	return h
}

// a session's delivery may run during or after Close, and touches only what outlives the mesh
// the route table and the peers it forwards segments and answers through, a closed descriptor, which refuses the write,
// a lane nobody reads any more, where it leaves its entry or gives way to the closed mesh,
// and the forward pool, whose batch it gives back once the job queue is closing
func (m *Mesh) Close() {
	m.closeOnce.Do(func() {
		close(m.closed)
		m.closeTraces()
		if m.dev != nil {
			_ = m.dev.Close()
		}
		m.closeLanes()
		m.outboundReaderWG.Wait()
		// a session's delivery may still be submitting a forward batch, and one submitted after the close would panic
		m.submitMu.Lock()
		m.closing = true
		m.submitMu.Unlock()
		if m.outboundJobs != nil {
			close(m.outboundJobs)
		}
		m.outboundWorkerWG.Wait()
		m.writerWG.Wait()
	})
}
