// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

// Package netstack wires a real Linux TUN device to the ranet mesh: outbound
// packets the kernel routes to it are forwarded to whichever peer's Child SA
// can reach the destination (see RouteTable), and inbound packets decrypted
// from any peer are written back to the device as if they'd arrived over any
// other interface. It knows nothing about ESP or IKE directly: peers are
// just a send function plus routes, so this package is testable without real
// crypto.
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
	"log"
	"log/slog"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

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

	// readsTruncated counts the reads that lost the tail of a GSO frame, and framesRefused the frames the device refused
	readsTruncated, framesRefused reportedCount
	// events records the mesh's changes of state, nil recording nothing
	events func(kind, peer string, attrs ...slog.Attr)
	// failed is closed once a reader finds the device gone while the mesh is not closing, nil for a mesh with no device
	failed     chan struct{}
	failedOnce sync.Once
	// mssClamped counts the SYNs ClampMSS lowered, and tooBigAnswered the answers to packets past their session's budget it sent
	mssClamped, tooBigAnswered atomic.Uint64

	// segmentCounters is the segment routing state, in its own struct so that
	// everything this file does not touch stays in segments.go with the code
	// that does.
	segmentCounters
	egressSlot
	answerState
	transitState
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
	// free is the pool the batch goes back to once sealed, nil for a tun reader's, which goes back to outboundFree
	free chan *outboundBatch
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

type inboundWriteBatch struct {
	frames [][]byte
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

// NewNamed attaches to or creates name through wireguard-go's TUN backend.
// an empty name opens defaultTUNName, which is always created and never attached to
// mtu is the device's MTU, zero taking DefaultMTU
// events records the mesh's changes of state, nil recording nothing
func NewNamed(mtu int, name string, events func(kind, peer string, attrs ...slog.Attr)) (*Mesh, error) {
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
	if err := bringTUNUp(actualName, 0); err != nil {
		_ = dev.Close()
		return nil, fmt.Errorf("netstack: bring tun device up: %w", err)
	}
	m := &Mesh{
		Routes: NewRouteTable(),
		Name:   actualName,
		setMTU: setTUNMTU,
		closed: make(chan struct{}),
		events: events,
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

// outboundReader only reads and classifies packets. Reserving each peer's ESP
// sequence range here fixes the order before independently scheduled workers
// encrypt later batches, so the ordered sender can restore per-flow FIFO.
func (m *Mesh) outboundReader(queue tun.Queue) {
	defer m.outboundReaderWG.Done()
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
		b.n = n
		m.classify(b)
		if len(b.peerOrder) == 0 {
			b.reset()
			m.outboundFree <- b
			continue
		}
		m.dispatchOutbound(b)
	}
}

// classify picks the peer of every packet of a read and holds each packet to the largest its peer's session carries
// a packet past that is answered or cut into fragments rather than sent, and a SYN within it has its MSS clamped to it
func (m *Mesh) classify(b *outboundBatch) {
	for i := range b.n {
		r := b.reads[i]
		raw := b.slab[r.Offset : r.Offset+r.Size : r.Offset+r.Size]
		src, dst, nh, ok := addrsOf(raw)
		if !ok {
			continue
		}
		// Steering happens before the route lookup, because a steered
		// packet is routed by the segment it is going to rather than by
		// the address it was addressed to.
		sent, policy := raw, m.steerPolicy(src, dst)
		if policy != nil {
			if b.steered[i], ok = m.steer(b.steered[i][:0], raw, policy); !ok {
				continue
			}
			sent = b.steered[i]
			if src, dst, nh, ok = addrsOf(sent); !ok {
				continue
			}
		}
		peer, verdict, _ := m.Routes.Resolve(src, dst)
		if verdict != RoutePeer {
			if policy != nil {
				m.segmentsUnrouted.Add(1)
				m.reportSegmentDrop("no route to the first segment of a steered packet", "segment", dst)
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
			count, bytes := m.tooBig(b, sent, overhead, peer, nh, share.mtu)
			share.count += count
			share.bytes += bytes
		} else {
			m.ClampMSS(sent[overhead:], share.mtu-overhead)
			b.packets[i], b.peers[i], b.headers[i] = sent, peer, nh
			share.count++
			share.bytes += len(sent)
		}
		b.shares[peer] = share
	}
}

// tooBig takes a packet larger than mtu, the largest its peer's session carries, and reports how many fragments it queued for the peer and their bytes
// overhead is the header steering put in front of the packet
// the packet behind it is held to mtu less that header
// an answer goes into the tun, whichever side of it the source sits
func (m *Mesh) tooBig(b *outboundBatch, raw []byte, overhead int, peer *Peer, nextHeader byte, mtu int) (int, int) {
	inner := raw[overhead:]
	answer, cut := m.answerTooBig(inner, mtu-overhead, false, netip.Addr{})
	if cut {
		count, bytes, fault := b.cut.add(peer, nextHeader, raw[:overhead], inner, mtu)
		if answer = m.answerOptions(inner, fault, false); answer != nil {
			m.writeHostPacket(answer)
		}
		return count, bytes
	}
	if answer != nil {
		m.writeHostPacket(answer)
		m.tooBigAnswered.Add(1)
	}
	return 0, 0
}

// TUNReadsTruncated is how many reads off the tun lost the tail of a GSO frame
// because it split into more segments than one read holds
func (m *Mesh) TUNReadsTruncated() uint64 { return m.readsTruncated.total.Load() }

// TUNFramesRefused is how many frames read off the tun the device could not decode into packets
func (m *Mesh) TUNFramesRefused() uint64 { return m.framesRefused.total.Load() }

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

// reportedCount counts one kind of trouble on the tun's reads and spaces the reports about it, a warning or an event, an interval apart
// the forwarding decision's drop report spaces its reports with claim alone, its counters keeping the count
// and each ICMP limit's report with claim and since, the limit's shards keeping the count
type reportedCount struct {
	total atomic.Uint64
	// next is the earliest the next report may go out
	// in nanoseconds since segmentsStarted, which keeps it on the monotonic clock
	// zero lets the first one report at once
	next atomic.Int64
	// reported is total as the last report gave it
	reported atomic.Uint64
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
func (c *reportedCount) claim(now, next int64) bool {
	return now >= next && c.next.CompareAndSwap(next, now+int64(reportInterval))
}

// a reservation takes its peer's reserveMu alone
// so a reader preempted between two reservations holds back only the peers whose tickets it holds
//
// Nothing here waits. A batch read off one queue carries whichever
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
			}
		}
	}
	// Submission never blocks: outboundFree is sized so that every batch in
	// flight fits here. Workers drain the queue during Close, including every
	// reserved ticket.
	m.outboundJobs <- b
}

func (m *Mesh) outboundWorker() {
	defer m.outboundWorkerWG.Done()
	for b := range m.outboundJobs {
		for i := 0; i < b.n; i++ {
			// A peer with no batch had no room in its budget, so its share of
			// this read was dropped before the tickets were handed out.
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
			if err := batch.enqueue(); err != nil {
				log.Printf("netstack: send batch through peer %s: %v", peer.ID, err)
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
func (m *Mesh) DeliverInbound(raw []byte, mtu int) {
	frame := make([]byte, TUNHeadroom+len(raw))
	copy(frame[TUNHeadroom:], raw)
	m.DeliverInboundBatch([][]byte{frame}, mtu, nil)
}

// DeliverInboundBatch hands the mesh a group of already-decapsulated tunnel-mode IP packets a session delivered, in the order it delivered them
// this node's segments act on the packets addressed to them, and the forwarding decision takes the rest
// each frame is TUNHeadroom bytes a write to the tun may overwrite, then the packet to the frame's end
// the frames are the mesh's from the call until a lane has written them or a worker has sealed them, and the tun is handed them as they are
// mtu is the largest packet the session they came through carries, zero for packets of no session
// a SYN that an End.DT46 of this node takes out of its outer header has its MSS clamped to it
// from is the peer of that session, which an answer about a link-local source goes back to, nil for packets of no session
func (m *Mesh) DeliverInboundBatch(frames [][]byte, mtu int, from *Peer) {
	// A mesh with no device only exists in a test, where nothing should reach
	// here: babel's own traffic is intercepted before delivery.
	if len(frames) == 0 || m.dev == nil {
		return
	}
	routed, granted := m.applySegments(frames, mtu)
	m.writeHost(m.decide(routed, granted, from))
}

// writeHostPacket writes one packet to the tun, copied into a frame of its own
func (m *Mesh) writeHostPacket(raw []byte) {
	if m.dev == nil {
		return
	}
	frame := make([]byte, TUNHeadroom+len(raw))
	copy(frame[TUNHeadroom:], raw)
	m.writeHost([][]byte{frame})
}

// writeHost writes frames to the tun, on a multiqueue tun each to the persistent writer lane of its inner flow
// which keeps each flow's order and lets the kernel take unrelated flows in parallel
func (m *Mesh) writeHost(frames [][]byte) {
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
		// an entry left in a lane after Close holds views of the session's own storage and nothing to give back
		batch := inboundWriteBatch{frames: group}
		select {
		case m.inboundWriters[lane] <- batch:
		case <-m.closed:
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
			for {
				var first inboundWriteBatch
				select {
				case first = <-queue:
				case <-m.closed:
					return
				}

				pending = collectReadyInbound(first, queue, pending)
				for offset := 0; offset < len(pending); offset += inboundWriteBatchSize {
					end := min(offset+inboundWriteBatchSize, len(pending))
					m.writeInbound(lane, pending[offset:end])
				}
				clear(pending)
				pending = pending[:0]
			}
		})
	}
}

// collectReadyInbound drains only work that is already available. This keeps
// the idle-path latency unchanged while giving a busy writer a full batch for
// the tun write's GRO pass, reducing the number of TUN write syscalls.
func collectReadyInbound(first inboundWriteBatch, queue <-chan inboundWriteBatch, pending [][]byte) [][]byte {
	pending = append(pending, first.frames...)
	for len(pending) < inboundWriteBatchSize {
		select {
		case batch := <-queue:
			pending = append(pending, batch.frames...)
		default:
			return pending
		}
	}
	return pending
}

func (m *Mesh) writeInbound(lane int, frames [][]byte) {
	if _, err := m.write(lane, frames, TUNHeadroom); err != nil {
		// a device reported gone refuses every write until the shutdown it started closes the mesh
		select {
		case <-m.closed:
		case <-m.failed:
		default:
			log.Printf("netstack: write to tun device queue %d: %v", lane, err)
		}
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
		m.SetEgress(nil)
		if m.dev != nil {
			_ = m.dev.Close()
		}
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
