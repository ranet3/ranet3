// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

// Package netstack wires a real Linux TUN device to the ranet mesh: outbound
// packets the kernel routes to it are forwarded to whichever peer's Child SA
// can reach the destination (see RouteTable), and inbound packets decrypted
// from any peer are written back to the device as if they'd arrived over any
// other interface. It knows nothing about ESP or IKE directly — peers are
// just a send function plus routes, so this package is testable without real
// crypto.
//
// This package never touches the device's address or route configuration —
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

	"golang.zx2c4.com/wireguard/tun"
	"ranet3.com/pkgs/ranet3/esp"
	"ranet3.com/pkgs/ranet3/internal/packet"
	"ranet3.com/pkgs/ranet3/srv6"
)

var (
	// Pooled as a pointer to the array rather than as a slice. A sync.Pool
	// takes an any, and a slice header does not fit in one, so putting a slice
	// back boxes it: one heap allocation for every inbound packet released, on
	// the path every inbound packet takes. The array pointer fits, so the same
	// release allocates nothing. Measured over 128 packets per release by
	// BenchmarkInboundCopyAndRelease: 4226 ns and 129 allocations against 3472
	// ns and 1 at 64 bytes, 8358 against 6561 at 1400.
	inboundPacketPool = sync.Pool{New: func() any { return new([inboundPacketBufferSize]byte) }}
)

type Mesh struct {
	Routes *RouteTable
	// Name is the TUN device's real interface name (e.g. "utun6" for "utun"), as
	// reported by the kernel — needed by whoever configures its address
	// and routes, since the kernel doesn't always honor the requested
	// name exactly.
	Name string

	devs               []tun.Device
	outboundBufferSize int
	outboundJobs       chan *outboundBatch
	outboundFree       chan *outboundBatch
	outboundDispatchMu sync.Mutex
	inboundWriters     []chan inboundWriteBatch
	closed             chan struct{}
	closeOnce          sync.Once
	deliveryMu         sync.Mutex
	deliveryWG         sync.WaitGroup
	closing            bool
	outboundReaderWG   sync.WaitGroup
	outboundWorkerWG   sync.WaitGroup
	writerWG           sync.WaitGroup

	// setMTU sets the MTU of the device named name, nil for a mesh with no device
	// a field so a test can record when it runs against the steering table in force
	setMTU func(name string, mtu int) error

	// tunReadsTruncated counts the reads that lost the tail of a GSO frame
	tunReadsTruncated atomic.Uint64
	// truncatedNextWarning is the earliest the next warning about those reads may go out
	// in nanoseconds since segmentsStarted, which keeps it on the monotonic clock
	// zero lets the first cut read warn at once
	// truncatedAtWarning is tunReadsTruncated as the last warning reported it
	truncatedNextWarning atomic.Int64
	truncatedAtWarning   atomic.Uint64

	// segmentCounters is the segment routing state, in its own struct so that
	// everything this file does not touch stays in segments.go with the code
	// that does.
	segmentCounters
}

// outboundBatch owns the TUN buffers from one read until a crypto worker has
// encrypted every routed packet. Readers can therefore immediately continue
// with another buffer set instead of tying one encryption worker to each TUN
// queue (and to whatever flows the kernel happened to hash onto that queue).
type outboundBatch struct {
	n         int
	bufs      [][]byte
	sizes     []int
	peers     []*Peer
	headers   []byte
	shares    map[*Peer]outboundShare
	batches   map[*Peer]*peerBatch
	peerOrder []*Peer
	// fragments are the packets of the read cut to fit their peers' sessions, which the worker sends after the rest of the read
	// fragmentBytes holds them and keeps its storage from read to read
	fragments     []outboundFragment
	fragmentBytes []byte
}

// outboundShare is one peer's part of a read
// count is the packets and fragments the read sends it, and mtu the largest packet its session carries, loaded once a read
type outboundShare struct {
	count int
	mtu   int
}

// outboundFragment is one fragment a read cut for a peer, with the next header its ESP trailer names
type outboundFragment struct {
	peer   *Peer
	header byte
	raw    []byte
}

type inboundWriteBatch struct {
	packets [][]byte
}

// NewRoutesOnly is a mesh with a forwarding table and no device, for a test
// that exercises routing and sessions rather than the dataplane. Creating a
// TUN needs root on every platform, and babel intercepts its own traffic
// before delivery, so a mesh that never carries a data packet does not need
// one. Delivering one to it is a no-op.
// CheckMTU takes what it takes on a mesh opened at DefaultMTU
// SetMTU installs the steering and sets no MTU
func NewRoutesOnly() *Mesh {
	return &Mesh{Routes: NewRouteTable(), outboundBufferSize: tunOffset + outboundPacketBufferSize, closed: make(chan struct{})}
}

// NewNamed attaches to or creates name through wireguard-go's TUN backend.
// an empty name opens defaultTUNName, which is always created and never attached to
// mtu is the device's MTU
// largest is the largest packet a session carries, which a steering header grows a read off the tun to in place
// every outbound read buffer holds the larger of the two
// zero takes DefaultMTU for either
func NewNamed(mtu, largest int, name string) (*Mesh, error) {
	if mtu == 0 {
		mtu = DefaultMTU
	}
	if largest == 0 {
		largest = DefaultMTU
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
	devs, actualName, err := createTUNQueues(name, mtu, queueCount)
	if err != nil {
		// wireguard-go hands back the utun control's errno without the name it was asked for
		if utunNamesOnly {
			err = fmt.Errorf("link.tun %q: %w", name, err)
		}
		return nil, fmt.Errorf("netstack: create tun device: %w", err)
	}
	if err := bringTUNUp(actualName); err != nil {
		for _, dev := range devs {
			_ = dev.Close()
		}
		return nil, fmt.Errorf("netstack: bring tun device up: %w", err)
	}
	m := &Mesh{
		Routes:             NewRouteTable(),
		Name:               actualName,
		devs:               devs,
		setMTU:             setTUNMTU,
		outboundBufferSize: tunOffset + max(mtu, largest, outboundPacketBufferSize),
		closed:             make(chan struct{}),
	}
	m.startSegmentReports()
	m.startInboundWriters()
	m.startOutboundPipeline()
	return m, nil
}

// QueueCount reports the number of independent TUN I/O lanes.
func (m *Mesh) QueueCount() int { return len(m.devs) }

// MTU is the device's own, asked of the kernel each time
// NewNamed sets it on a device it attaches to as on one it creates, and SetMTU on a reload
// anything else on the host may change it after, which this reports as it finds it
// zero means the device could not answer, which is a device on its way out
func (m *Mesh) MTU() int {
	if len(m.devs) == 0 {
		return 0
	}
	mtu, err := m.devs[0].MTU()
	if err != nil {
		return 0
	}
	return mtu
}

// CheckMTU refuses a move of the tun's MTU this mesh cannot take without a restart
// largest is link.mtu after the move, the largest packet a session carries, which a steering header grows a read off the tun to in place
// each outbound read buffer has to hold it, and NewNamed sized them once
func (m *Mesh) CheckMTU(largest int) error {
	if !tunMTUSettable {
		return errors.New("netstack: this platform sets the tun mtu only when the mesh opens it, restart to apply")
	}
	if capacity := m.outboundBufferSize - tunOffset; largest > capacity {
		return fmt.Errorf("netstack: a %d byte packet needs a tun read buffer of that size and this mesh opened its buffers at %d bytes, restart to apply", largest, capacity)
	}
	return nil
}

// SetMTU sets the device's MTU to mtu and installs steering, the table the device runs under
// a longer list than the one in force goes in after the device comes down for it
// a shorter one goes in before the device goes up
// so no read off the tun, with the steering header in force on it, outgrows the larger of the two link MTUs at any moment
// CheckMTU has to have taken the largest packet beside mtu
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
	m.outboundJobs = make(chan *outboundBatch, outboundJobsPerWorker*workers)
	batchSize := 1
	for _, dev := range m.devs {
		batchSize = max(batchSize, dev.BatchSize())
	}
	m.outboundFree = make(chan *outboundBatch, cap(m.outboundJobs)+len(m.devs))
	for range cap(m.outboundFree) {
		m.outboundFree <- m.newOutboundBatch(batchSize)
	}
	for range workers {
		m.outboundWorkerWG.Add(1)
		go m.outboundWorker()
	}
	for _, dev := range m.devs {
		m.outboundReaderWG.Add(1)
		go m.outboundReader(dev)
	}
}

func (m *Mesh) newOutboundBatch(size int) *outboundBatch {
	b := &outboundBatch{
		bufs:      make([][]byte, size),
		sizes:     make([]int, size),
		peers:     make([]*Peer, size),
		headers:   make([]byte, size),
		shares:    make(map[*Peer]outboundShare),
		batches:   make(map[*Peer]*peerBatch),
		peerOrder: make([]*Peer, 0, size),
	}
	for i := range b.bufs {
		b.bufs[i] = make([]byte, m.outboundBufferSize)
	}
	return b
}

// outboundReader only reads and classifies packets. Reserving each peer's ESP
// sequence range here fixes the order before independently scheduled workers
// encrypt later batches, so the ordered sender can restore per-flow FIFO.
func (m *Mesh) outboundReader(dev tun.Device) {
	defer m.outboundReaderWG.Done()
	for {
		var b *outboundBatch
		select {
		case b = <-m.outboundFree:
		case <-m.closed:
			return
		}
		n, err := dev.Read(b.bufs, b.sizes, tunOffset)
		// ErrTooManySegments comes with n packets, one fewer than the batch holds
		// only the rest of that one GSO frame is lost
		// the device stays readable
		if err != nil && !errors.Is(err, tun.ErrTooManySegments) {
			// Closure is the ordinary reason and says nothing. Anything else
			// ends this queue's reader for the life of the process, and on
			// linux the kernel keeps steering its share of flows to the queue
			// it belongs to, so a share of the mesh black-holes with nothing
			// in the log. The device's own error channel carries a netlink
			// failure on linux and a route-socket overflow on darwin, neither
			// of which is closure.
			select {
			case <-m.closed:
			default:
				slog.Error("netstack tun reader stopped", "interface", m.Name, "err", err)
			}
			m.outboundFree <- b
			return
		}
		if err != nil {
			m.noteTruncatedRead()
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
// a packet past that is answered or cut into fragments rather than sent
func (m *Mesh) classify(b *outboundBatch) {
	for i := range b.n {
		raw := b.bufs[i][tunOffset : tunOffset+b.sizes[i]]
		src, dst, nh, ok := addrsOf(raw)
		if !ok {
			continue
		}
		// Steering happens before the route lookup, because a steered
		// packet is routed by the segment it is going to rather than by
		// the address it was addressed to.
		size, policy, action := m.steer(b.bufs[i], b.sizes[i], src, dst)
		if action == steerDrop {
			continue
		}
		steered := action == steerSent
		if steered {
			b.sizes[i] = size
			if src, dst, nh, ok = addrsOf(b.bufs[i][tunOffset : tunOffset+size]); !ok {
				continue
			}
		}
		peer, ok := m.Routes.Lookup(src, dst)
		if !ok {
			// A steered packet whose first segment the mesh cannot reach
			// is gone at this point, so it is counted here: without this
			// the steered counter climbs while the traffic disappears. It
			// is counted apart from Dropped, which holds the packets this
			// node refused to act on for a peer: an operator who
			// configures steering and no local segment would otherwise
			// see the loss on a line reporting a table they do not have.
			if steered {
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
		if b.sizes[i] > share.mtu {
			share.count += m.tooBig(b, b.bufs[i][tunOffset:tunOffset+b.sizes[i]], peer, nh, policy, share.mtu)
		} else {
			b.peers[i], b.headers[i] = peer, nh
			share.count++
		}
		b.shares[peer] = share
	}
}

// tooBig takes a packet larger than mtu, the largest its peer's session carries, and reports how many fragments it queued for the peer
// a steered packet is taken as the packet it carries, against mtu less the header steering put on it
// IPv6, and IPv4 with DF, are answered from the packet's own destination with packet too big or fragmentation needed
// written into the tun, whichever side of it the source sits, under the bucket answerRefused draws from
// the token goes first, as in answerTooBig, which spares a flood the answers it would build and drop
// IPv4 without DF is cut into fragments as a router cuts it
func (m *Mesh) tooBig(b *outboundBatch, raw []byte, peer *Peer, nextHeader byte, policy *srv6.Policy, mtu int) int {
	overhead := policy.Overhead()
	inner := raw[overhead:]
	mtu -= overhead
	var answer []byte
	var ok bool
	switch {
	case inner[0]>>4 == 6:
		if !m.takeICMPToken() {
			return 0
		}
		answer, ok = srv6.PacketTooBig(inner, netip.AddrFrom16([16]byte(inner[24:40])), mtu)
	// DF, RFC 791 section 3.1
	case inner[6]&0x40 != 0:
		if !m.takeICMPToken() {
			return 0
		}
		answer, ok = packet.FragmentationNeeded(inner, netip.AddrFrom4([4]byte(inner[16:20])), mtu)
	default:
		return m.cut(b, inner, peer, nextHeader, policy, mtu)
	}
	if ok {
		m.DeliverInboundBatch([][]byte{answer})
	}
	return 0
}

// cut queues for peer the fragments of an IPv4 packet without DF, each under the header steering put on the packet, if any
// they wait in the read's own storage, counted in the peer's share for its reservation to hold them
func (m *Mesh) cut(b *outboundBatch, inner []byte, peer *Peer, nextHeader byte, policy *srv6.Policy, mtu int) int {
	start := len(b.fragmentBytes)
	var ok bool
	if b.fragmentBytes, ok = packet.AppendFragments(b.fragmentBytes, inner, mtu); !ok {
		return 0
	}
	count := 0
	for rest := b.fragmentBytes[start:]; len(rest) != 0; count++ {
		fragment, _ := packet.Payload(rest)
		rest = rest[len(fragment):]
		if policy != nil {
			var err error
			if fragment, err = srv6.Encapsulate(fragment, policy.Source, policy.Path); err != nil {
				m.segmentsUnsteered.Add(1)
				m.reportSegmentDrop("a fragment of a packet a policy claimed could not be encapsulated", "policy", policy, "err", err)
				return count
			}
		}
		b.fragments = append(b.fragments, outboundFragment{peer: peer, header: nextHeader, raw: fragment})
	}
	return count
}

// TUNReadsTruncated is how many reads off the tun lost the tail of a GSO frame
// because it split into more segments than one read holds
func (m *Mesh) TUNReadsTruncated() uint64 { return m.tunReadsTruncated.Load() }

// noteTruncatedRead counts one read cut short
// and warns at most once an interval with the count since the last warning
func (m *Mesh) noteTruncatedRead() {
	total := m.tunReadsTruncated.Add(1)
	if !m.claimTruncatedWarning(int64(time.Since(m.segmentsStarted)), m.truncatedNextWarning.Load()) {
		return
	}
	slog.Warn("netstack tun reads lost the tail of a gso frame", "interface", m.Name, "reads", total-m.truncatedAtWarning.Swap(total))
}

// claimTruncatedWarning says whether the reader that cut a read at now writes the warning
// next is the earliest time of the next warning as that reader loaded it
// of the readers that loaded the same next only the first to claim it writes one
// and its claim moves the next warning an interval past now
func (m *Mesh) claimTruncatedWarning(now, next int64) bool {
	return now >= next && m.truncatedNextWarning.CompareAndSwap(next, now+int64(truncatedReadInterval))
}

// Reserve and submit each batch as one operation. Otherwise two readers can
// retain the first tickets for different peers while later completed batches
// fill both peers' budgets, preventing either reader from reserving its second
// peer. Submission order also keeps compatibility workers from all waiting on
// an earlier ticket that is still queued behind them.
//
// Nothing here waits. Every TUN reader passes through this lock, and a batch
// read off one queue carries whichever destinations the kernel hashed onto it,
// so waiting for room in one peer's budget would stop forwarding to every
// other peer as well: a single backpressured socket would take the whole
// dataplane down with it, and a budget that is full stays full for as long as
// the transport is behind. That peer's share of the batch is dropped instead,
// the way a full egress queue drops, and every other peer's packets go out on
// time. The drop is counted per peer.
func (m *Mesh) dispatchOutbound(b *outboundBatch) {
	m.outboundDispatchMu.Lock()
	defer m.outboundDispatchMu.Unlock()
	for _, peer := range b.peerOrder {
		// a peer whose packets of the read were all answered or refused takes no place
		if count := b.shares[peer].count; count != 0 {
			if batch := peer.reserveBatchNow(count); batch != nil {
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
				b.batches[peer].append(b.bufs[i][tunOffset:tunOffset+b.sizes[i]], b.headers[i])
			}
		}
		// fragments go out after the read's other packets, where a later packet of the same read may overtake a cut one
		// only IPv4 without DF is cut, and IP promises its datagrams no order
		for _, fragment := range b.fragments {
			if batch := b.batches[fragment.peer]; batch != nil {
				batch.append(fragment.raw, fragment.header)
			}
		}
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
		select {
		case m.outboundFree <- b:
		case <-m.closed:
		}
	}
}

func (b *outboundBatch) reset() {
	for i := 0; i < b.n; i++ {
		b.peers[i] = nil
		b.sizes[i] = 0
	}
	b.n = 0
	clear(b.shares)
	clear(b.batches)
	clear(b.peerOrder)
	b.peerOrder = b.peerOrder[:0]
	clear(b.fragments)
	b.fragments = b.fragments[:0]
	b.fragmentBytes = b.fragmentBytes[:0]
}

// addrsOf extracts both the source and destination address from a raw IP
// packet — the route table needs both to support source-specific (SADR)
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

// DeliverInbound injects an already-decapsulated tunnel-mode IP packet into
// the TUN device, as if it had arrived on the wire.
func (m *Mesh) DeliverInbound(raw []byte) {
	m.DeliverInboundBatch([][]byte{raw})
}

// DeliverInboundBatch injects a group of already-decapsulated tunnel-mode IP
// packets. On a multiqueue TUN, packets are assigned by their inner flow to a
// persistent writer lane. That preserves each flow's packet order and lets the
// kernel process unrelated streams in parallel. Buffers are copied to leave
// the headroom and tail capacity required by the TUN backend's virtio/GRO
// implementation.
func (m *Mesh) DeliverInboundBatch(raw [][]byte) {
	// A mesh with no device only exists in a test, where nothing should reach
	// here: babel's own traffic is intercepted before delivery.
	if len(raw) == 0 || len(m.devs) == 0 {
		return
	}
	m.deliveryMu.Lock()
	if m.closing {
		m.deliveryMu.Unlock()
		return
	}
	m.deliveryWG.Add(1)
	m.deliveryMu.Unlock()
	defer m.deliveryWG.Done()
	// A packet addressed to one of this node's own segments is acted on here
	// rather than written to the tun, where it would arrive as an
	// undeliverable packet addressed to an address of ours.
	raw = m.applySegments(raw)
	if len(raw) == 0 {
		return
	}
	if len(m.devs) == 1 {
		for len(raw) != 0 {
			n := min(len(raw), inboundWriteBatchSize)
			m.writeInbound(0, copyInboundPackets(raw[:n]))
			raw = raw[n:]
		}
		return
	}

	groups := make([][][]byte, len(m.devs))
	for _, packet := range raw {
		lane := int(innerFlowHash(packet) % uint64(len(m.devs)))
		groups[lane] = append(groups[lane], packet)
	}
	for lane, packets := range groups {
		if len(packets) == 0 {
			continue
		}
		// The authenticated plaintext remains owned by this queue entry.
		// Deferring the required headroom copy to the writer keeps it off the
		// ordered ESP commit path and lets the writer merge adjacent entries
		// into a larger GRO batch.
		batch := inboundWriteBatch{packets: packets}
		select {
		case m.inboundWriters[lane] <- batch:
		case <-m.closed:
		}
	}
}

func (m *Mesh) startInboundWriters() {
	if len(m.devs) <= 1 {
		return
	}
	m.inboundWriters = make([]chan inboundWriteBatch, len(m.devs))
	for lane := range m.devs {
		queue := make(chan inboundWriteBatch, inboundWriteQueueSize)
		m.inboundWriters[lane] = queue
		m.writerWG.Go(func() {
			pending := make([][]byte, 0, inboundPendingBatches*inboundWriteBatchSize)
			for {
				var first inboundWriteBatch
				select {
				case first = <-queue:
				case <-m.closed:
					// Deliveries that began before Close may still choose the
					// buffered send arm after closed becomes readable. Wait for
					// those sends before abandoning their plaintext references.
					m.deliveryWG.Wait()
					return
				}

				pending = collectReadyInbound(first, queue, pending)
				for offset := 0; offset < len(pending); offset += inboundWriteBatchSize {
					end := min(offset+inboundWriteBatchSize, len(pending))
					m.writeInbound(lane, copyInboundPackets(pending[offset:end]))
				}
				clear(pending)
				pending = pending[:0]
			}
		})
	}
}

// collectReadyInbound drains only work that is already available. This keeps
// the idle-path latency unchanged while giving a busy writer a full batch for
// NativeTun.Write's GRO pass, reducing the number of TUN write syscalls.
func collectReadyInbound(first inboundWriteBatch, queue <-chan inboundWriteBatch, pending [][]byte) [][]byte {
	pending = append(pending, first.packets...)
	for len(pending) < inboundWriteBatchSize {
		select {
		case batch := <-queue:
			pending = append(pending, batch.packets...)
		default:
			return pending
		}
	}
	return pending
}

func copyInboundPackets(raw [][]byte) [][]byte {
	bufs := make([][]byte, len(raw))
	for i := range raw {
		buf := inboundPacketPool.Get().(*[inboundPacketBufferSize]byte)[:]
		if cap(buf) < tunOffset+len(raw[i]) {
			buf = make([]byte, tunOffset+len(raw[i]))
		} else {
			buf = buf[:tunOffset+len(raw[i])]
		}
		bufs[i] = buf
		copy(bufs[i][tunOffset:], raw[i])
	}
	return bufs
}

func releaseInboundPackets(bufs [][]byte) {
	for _, buf := range bufs {
		if cap(buf) == inboundPacketBufferSize {
			// The capacity check keeps out a buffer this package did not
			// hand out, and one grown past the pool's size. A buffer is
			// re-sliced on every use for the header offset, and recovering
			// the array from the full-capacity slice is exact.
			inboundPacketPool.Put((*[inboundPacketBufferSize]byte)(buf[:inboundPacketBufferSize]))
		}
	}
}

func (m *Mesh) writeInbound(lane int, bufs [][]byte) {
	if _, err := m.devs[lane].Write(bufs, tunOffset); err != nil {
		select {
		case <-m.closed:
		default:
			log.Printf("netstack: write to tun device queue %d: %v", lane, err)
		}
	}
	releaseInboundPackets(bufs)
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

func (m *Mesh) Close() {
	m.closeOnce.Do(func() {
		m.deliveryMu.Lock()
		m.closing = true
		close(m.closed)
		m.deliveryMu.Unlock()
		for _, dev := range m.devs {
			_ = dev.Close()
		}
		m.outboundReaderWG.Wait()
		if m.outboundJobs != nil {
			close(m.outboundJobs)
		}
		m.outboundWorkerWG.Wait()
		m.deliveryWG.Wait()
		m.writerWG.Wait()
	})
}
