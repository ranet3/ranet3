// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build (linux && !android) || (darwin && !ios)

package userspace

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/egress/egresstest"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/wireguard/tun"
)

// A carrier runs the exit behavior suite on one host and the exit on another.
// The suite's host keeps the leaf, the mesh, the router and the server, and
// its arm builds a proxy egress.Exit, and the exit's host builds the exit.
// Two connections join them: a datagram socket carrying each packet of the
// exit's uplink whole, between the router's tun and the exit host's own, and
// a stream, the wire, carrying the proxy's calls, the exit's hooks, and the
// packets between the exit and the mesh. The exit's lanes are the wire's, and
// each lands on a lane of the suite's mesh, which judges, answers and sends
// toward the leaf as it does for an exit beside it.

const (
	// untimed is Flow.Left for a flow the exit keeps with no idle timer,
	// until an end closes or resets it
	untimed = time.Duration(1 << 62)
	// wireHeader is a message's kind, the id its reply carries back and the
	// length of its bytes, and wireMost the most bytes one message carries
	wireHeader = 9
	wireMost   = 16 << 20
	// carriedSlab and carriedReads size the batch a lane of the wire hands
	// its fill, as a mesh's outbound batch is sized
	carriedSlab  = 2 * 65535
	carriedReads = 128
	// rigMTU is the exit host's uplink's, the suite's uplink MTU, which with
	// the carrier's IPv4 and UDP headers fits a 1500 byte LAN
	rigMTU = 1340
)

// The rig's variables on the exit's host, which the rig's runner passes. Real
// addresses pass here at run time alone.
const (
	// rigEthernet names the exit host's link to the suite's host, rigPeer
	// that host's IPv4 address, and rigPort and rigControlPort the carrier's
	// and the wire's ports on the exit's host
	rigEthernet    = "RANET3_RIG_ETHERNET"
	rigPeer        = "RANET3_RIG_PEER"
	rigPort        = "RANET3_RIG_PORT"
	rigControlPort = "RANET3_RIG_CONTROL_PORT"
	// rigWait bounds the wait for the suite's host's first datagram and
	// connection
	rigWait = 5 * time.Minute
)

var (
	// rigAddresses are the exit host's on its uplink, the suite's uplink
	// addresses, and rigClasses its class addresses, which a host holds on
	// another link, so that no socket bound to none takes one as its source
	rigAddresses = []netip.Prefix{netip.MustParsePrefix("198.51.100.1/28"), netip.MustParsePrefix("2001:db8:1::1/64")}
	rigClasses   = []netip.Prefix{netip.MustParsePrefix("198.51.100.17/32"), netip.MustParsePrefix("2001:db8:1:1::1/128")}
	// rigRoutes are the suite's server prefixes, through the router on the
	// uplink's far side, the exit host's only routes over its uplink
	rigRoutes = []struct {
		to  netip.Prefix
		via netip.Addr
	}{
		{netip.MustParsePrefix("203.0.113.0/24"), netip.MustParseAddr("198.51.100.2")},
		{netip.MustParsePrefix("2001:db8::/32"), netip.MustParseAddr("2001:db8:1::2")},
	}
)

// what each message on the wire is
const (
	// the suite's side asks, each by an id but cancel, egress and the mesh
	// closing, which have no reply
	callNew byte = iota + 1
	callRun
	callCancel
	callClose
	callEnable
	callEgress
	callAnnounce
	callStatus
	callHolds
	callFlows
	callMeshClosed
	// the exit's host asks, each by an id but a fill
	hookReady
	hookRepublish
	laneFill
	laneAnswer
	laneMTU
	laneSameSession
	// either side answers a request by its id
	wireReply
)

var errWireEnded = errors.New("the wire to the far host ended")

// stream is one end of the wire between the two hosts
type stream struct {
	conn net.Conn
	// writing orders whole messages on the stream
	writing sync.Mutex

	mu      sync.Mutex
	next    uint32
	waiting map[uint32]chan []byte
	// done is closed once serve has read the stream's end
	done chan struct{}
}

func newStream(conn net.Conn) *stream {
	return &stream{conn: conn, waiting: map[uint32]chan []byte{}, done: make(chan struct{})}
}

func (w *stream) send(kind byte, id uint32, payload []byte) error {
	message := make([]byte, wireHeader, wireHeader+len(payload))
	message[0] = kind
	binary.BigEndian.PutUint32(message[1:], id)
	binary.BigEndian.PutUint32(message[5:], uint32(len(payload)))
	message = append(message, payload...)
	w.writing.Lock()
	defer w.writing.Unlock()
	_, err := w.conn.Write(message)
	return err
}

// call sends a request and waits for its reply, answering the reply's bytes
// or the error the far side gave
func (w *stream) call(kind byte, payload []byte) ([]byte, error) {
	replies := make(chan []byte, 1)
	w.mu.Lock()
	w.next++
	id := w.next
	w.waiting[id] = replies
	w.mu.Unlock()
	defer func() {
		w.mu.Lock()
		delete(w.waiting, id)
		w.mu.Unlock()
	}()
	if err := w.send(kind, id, payload); err != nil {
		return nil, err
	}
	select {
	case reply := <-replies:
		return parseReply(reply)
	case <-w.done:
		return nil, errWireEnded
	}
}

func (w *stream) reply(id uint32, payload []byte, err error) error {
	if err != nil {
		return w.send(wireReply, id, append([]byte{1}, err.Error()...))
	}
	return w.send(wireReply, id, append([]byte{0}, payload...))
}

func parseReply(reply []byte) ([]byte, error) {
	if len(reply) == 0 {
		return nil, errors.New("an empty reply")
	}
	if reply[0] != 0 {
		return nil, errors.New(string(reply[1:]))
	}
	return reply[1:], nil
}

// serve reads each message until the stream ends, handing a reply to its
// caller and every other message to handle on the reading goroutine, which
// handle leaves at once for anything that waits on the far side. A stream the
// far side closed between messages ends with errWireEnded, and one cut inside
// a message with io.ErrUnexpectedEOF.
func (w *stream) serve(handle func(kind byte, id uint32, payload []byte)) error {
	defer close(w.done)
	r := bufio.NewReader(w.conn)
	header := make([]byte, wireHeader)
	for {
		if _, err := io.ReadFull(r, header); err != nil {
			if err == io.EOF {
				return errWireEnded
			}
			return err
		}
		kind, id, size := header[0], binary.BigEndian.Uint32(header[1:]), binary.BigEndian.Uint32(header[5:])
		if size > wireMost {
			return fmt.Errorf("a message of %d bytes, past %d", size, wireMost)
		}
		payload := make([]byte, size)
		if _, err := io.ReadFull(r, payload); err != nil {
			if err == io.EOF {
				return io.ErrUnexpectedEOF
			}
			return err
		}
		if kind != wireReply {
			handle(kind, id, payload)
			continue
		}
		w.mu.Lock()
		replies, ok := w.waiting[id]
		w.mu.Unlock()
		if ok {
			replies <- payload
		}
	}
}

// appendPackets appends each packet with its length ahead of it
func appendPackets(dst []byte, packets ...[]byte) []byte {
	for _, packet := range packets {
		dst = binary.BigEndian.AppendUint32(dst, uint32(len(packet)))
		dst = append(dst, packet...)
	}
	return dst
}

// packetsOf reads what appendPackets wrote
func packetsOf(payload []byte) ([][]byte, error) {
	var packets [][]byte
	for len(payload) != 0 {
		if len(payload) < 4 {
			return nil, errors.New("a packet's length cut short")
		}
		size := binary.BigEndian.Uint32(payload)
		if uint64(len(payload)-4) < uint64(size) {
			return nil, errors.New("a packet cut short")
		}
		packets = append(packets, payload[4:4+size])
		payload = payload[4+size:]
	}
	return packets, nil
}

// spec is the exit the suite's side asks for: its capability, the mesh's
// addresses, and its number, which the cancel and the mesh's closing name
type spec struct {
	Egress egress.Egress
	Mesh   []netip.Addr
	Number uint32
}

// exitHost is the exit's end of a carrier. It builds an exit for each spec
// the suite's side sends, over a platform of its own and lanes of the wire,
// and answers the proxy's calls on it, one exit at a time.
type exitHost struct {
	w *stream
	// platform readies each exit's sockets, limits sizes it, and uplink is
	// made anew for it
	platform func() (Platform, error)
	limits   Limits
	uplink   *carriedUplink

	mu     sync.Mutex
	x      *Exit
	number uint32
	ctx    context.Context
	cancel context.CancelFunc
	// meshDone is the current exit's lanes' Done, closed once the suite's
	// mesh closes or the wire ends
	meshDone  chan struct{}
	closeMesh func()
}

func newExitHost(conn net.Conn, platform func() (Platform, error), limits Limits, uplink *carriedUplink) *exitHost {
	return &exitHost{w: newStream(conn), platform: platform, limits: limits, uplink: uplink}
}

// serve answers the suite's side until the wire ends, and then closes the
// last exit's lanes
func (h *exitHost) serve() error {
	defer func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.closeMesh != nil {
			h.closeMesh()
		}
	}()
	return h.w.serve(h.handle)
}

// handle takes egress, the cancel, the mesh's closing and a new exit in the
// order they came, none of which waits on the far side, and answers every
// other request on a goroutine of its own
func (h *exitHost) handle(kind byte, id uint32, payload []byte) {
	switch kind {
	case callEgress:
		packets, err := packetsOf(payload)
		x, _ := h.current()
		if err != nil || x == nil {
			return
		}
		frames := make([][]byte, len(packets))
		for i, packet := range packets {
			frames[i] = make([]byte, netstack.TUNHeadroom+len(packet))
			copy(frames[i][netstack.TUNHeadroom:], packet)
		}
		x.Egress(frames, nil)
	case callCancel, callMeshClosed:
		if len(payload) != 4 {
			return
		}
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.x == nil || h.number != binary.BigEndian.Uint32(payload) {
			return
		}
		if kind == callCancel {
			h.cancel()
		} else {
			h.closeMesh()
		}
	case callNew:
		_ = h.w.reply(id, nil, h.build(payload))
	default:
		go h.answer(kind, id, payload)
	}
}

func (h *exitHost) current() (*Exit, context.Context) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.x, h.ctx
}

// build makes the exit spec names, the last one's Run having ended
func (h *exitHost) build(payload []byte) error {
	var s spec
	if err := json.Unmarshal(payload, &s); err != nil {
		return err
	}
	if err := h.uplink.renew(); err != nil {
		return fmt.Errorf("make the uplink anew: %w", err)
	}
	platform, err := h.platform()
	if err != nil {
		return err
	}
	done := make(chan struct{})
	var once sync.Once
	x, err := New(s.Egress, Runtime{
		Mesh:          wireLanes{w: h.w, done: done},
		Platform:      platform,
		Limits:        h.limits,
		MeshAddresses: s.Mesh,
		Hooks:         egress.Hooks{Ready: h.ready, Republish: h.republish},
	})
	if err != nil {
		if platform.Raw != nil {
			_ = platform.Raw.Close()
		}
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closeMesh != nil {
		h.closeMesh()
	}
	h.x, h.number, h.ctx, h.cancel = x, s.Number, ctx, cancel
	h.meshDone, h.closeMesh = done, func() { once.Do(func() { close(done) }) }
	return nil
}

// answer answers a request that may wait on the far side, as Run does on the
// hooks
func (h *exitHost) answer(kind byte, id uint32, payload []byte) {
	x, ctx := h.current()
	if x == nil {
		_ = h.w.reply(id, nil, errors.New("no exit was built on the host"))
		return
	}
	var reply []byte
	var err error
	switch kind {
	case callRun:
		err = x.Run(ctx)
	case callClose:
		err = x.Close()
	case callEnable:
		x.SetEnabled(len(payload) == 1 && payload[0] == 1)
	case callAnnounce:
		reply, err = json.Marshal(x.Announce())
	case callStatus:
		reply, err = json.Marshal(x.Status())
	case callHolds:
		reply, err = json.Marshal(holdsOf(x))
	case callFlows:
		reply, err = json.Marshal(tableOf(x))
	default:
		err = fmt.Errorf("a request of kind %d", kind)
	}
	_ = h.w.reply(id, reply, err)
}

// ready and republish are the exit's hooks, each returning once the suite's
// side has run its own, as a hook in the same process returns
func (h *exitHost) ready(v4, v6, serves bool) {
	_, _ = h.w.call(hookReady, []byte{flag(v4), flag(v6), flag(serves)})
}

func (h *exitHost) republish() { _, _ = h.w.call(hookRepublish, nil) }

func flag(set bool) byte {
	if set {
		return 1
	}
	return 0
}

// wireLanes is the exit host's lanes: each sends what the exit lays toward
// the leaf over the wire, where a lane of the suite's mesh takes it, and asks
// that lane for each answer and MTU
type wireLanes struct {
	w    *stream
	done <-chan struct{}
}

func (l wireLanes) OpenLane() Lane {
	return &wireLane{w: l.w, done: l.done, slab: make([]byte, carriedSlab), reads: make([]tun.ReadPacket, carriedReads)}
}

// wireLane is one lane of the wire. Its Fill runs on one goroutine, which
// owns the slab and the reads, and Answer and MTU on any.
type wireLane struct {
	w     *stream
	done  <-chan struct{}
	slab  []byte
	reads []tun.ReadPacket

	mu     sync.Mutex
	closed bool
}

func (l *wireLane) Fill(fill func(slab []byte, reads []tun.ReadPacket) int) bool {
	l.mu.Lock()
	closed := l.closed
	l.mu.Unlock()
	if closed {
		return false
	}
	select {
	case <-l.done:
		return false
	default:
	}
	n := fill(l.slab, l.reads)
	if n == 0 {
		return true
	}
	var payload []byte
	for _, read := range l.reads[:n] {
		payload = appendPackets(payload, l.slab[read.Offset:read.Offset+read.Size])
	}
	return l.w.send(laneFill, 0, payload) == nil
}

func (l *wireLane) Answer(offending []byte, kind netstack.ExitAnswer, mtu int) bool {
	payload := binary.BigEndian.AppendUint32([]byte{byte(kind)}, uint32(mtu))
	reply, err := l.w.call(laneAnswer, append(payload, offending...))
	return err == nil && len(reply) == 1 && reply[0] == 1
}

func (l *wireLane) MTU(source, destination netip.Addr) int {
	reply, err := l.w.call(laneMTU, []byte(source.String()+" "+destination.String()))
	if err != nil || len(reply) != 4 {
		return 0
	}
	return int(binary.BigEndian.Uint32(reply))
}

func (l *wireLane) SameSession(source, a, b netip.Addr) bool {
	reply, err := l.w.call(laneSameSession, []byte(source.String()+" "+a.String()+" "+b.String()))
	return err == nil && len(reply) == 1 && reply[0] == 1
}

func (l *wireLane) Done() <-chan struct{} { return l.done }

func (l *wireLane) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
}

// carriedUplink is the exit host's uplink and its pump to and from the
// carrier. The uplink is made anew for each exit, so that no exit meets a path
// MTU an earlier one's sockets learned, as each class's network on the suite's
// side is new.
type carriedUplink struct {
	carrier *net.UDPConn
	open    func() (io.ReadWriteCloser, error)

	mu      sync.Mutex
	current io.ReadWriteCloser
	// reading is the current uplink's reader, and carried the carrier's
	reading, carried sync.WaitGroup
}

// start reads the carrier until stop: each IP packet goes to the current
// uplink, and the probe and anything else that is no IP packet goes back
// where it came from
func (u *carriedUplink) start() {
	u.carried.Go(func() {
		buf := make([]byte, 1<<16)
		for {
			size, err := u.carrier.Read(buf)
			if errors.Is(err, syscall.ECONNREFUSED) {
				continue
			}
			if err != nil {
				return
			}
			if version := buf[0] >> 4; size == 0 || version != 4 && version != 6 {
				_, _ = u.carrier.Write(buf[:size])
				continue
			}
			u.mu.Lock()
			uplink := u.current
			u.mu.Unlock()
			if uplink != nil {
				// a write the closing uplink refuses is a packet it lost
				_, _ = uplink.Write(buf[:size])
			}
		}
	})
}

// renew closes the uplink and opens another, whose every read goes to the
// carrier
func (u *carriedUplink) renew() error {
	u.close()
	uplink, err := u.open()
	if err != nil {
		return err
	}
	u.mu.Lock()
	u.current = uplink
	u.mu.Unlock()
	u.reading.Go(func() {
		buf := make([]byte, 1<<16)
		for {
			size, err := uplink.Read(buf)
			if err != nil {
				return
			}
			// a datagram the far end refuses is a packet the uplink lost
			_, _ = u.carrier.Write(buf[:size])
		}
	})
	return nil
}

func (u *carriedUplink) close() {
	u.mu.Lock()
	uplink := u.current
	u.current = nil
	u.mu.Unlock()
	if uplink != nil {
		_ = uplink.Close()
	}
	u.reading.Wait()
}

func (u *carriedUplink) stop() {
	u.close()
	_ = u.carrier.SetReadDeadline(time.Now())
	u.carried.Wait()
}

// connectUDP connects conn to to, an IPv4 address and port, so it reads from
// to alone and writes there
func connectUDP(conn *net.UDPConn, to netip.AddrPort) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var connectErr error
	if err := raw.Control(func(fd uintptr) {
		connectErr = unix.Connect(int(fd), &unix.SockaddrInet4{Port: int(to.Port()), Addr: to.Addr().As4()})
	}); err != nil {
		return err
	}
	return connectErr
}

// rigVariables reads the rig's variables on the exit's host, skipping the
// test where any is unset or the process is not root
func rigVariables(t *testing.T) (link string, peer netip.Addr, port, controlPort uint16) {
	t.Helper()
	values := map[string]string{}
	for _, name := range []string{rigEthernet, rigPeer, rigPort, rigControlPort} {
		if values[name] = os.Getenv(name); values[name] == "" {
			t.Skipf("%s is unset, so no rig runs this host", name)
		}
	}
	if os.Geteuid() != 0 {
		t.Skip("the exit's host makes its uplink and raw sockets, which only root may")
	}
	peer, err := netip.ParseAddr(values[rigPeer])
	if err != nil || !peer.Is4() {
		t.Fatalf("%s is no IPv4 address", rigPeer)
	}
	ports := make([]uint16, 2)
	for i, name := range []string{rigPort, rigControlPort} {
		n, err := strconv.ParseUint(values[name], 10, 16)
		if err != nil || n == 0 {
			t.Fatalf("%s is no port", name)
		}
		ports[i] = uint16(n)
	}
	return values[rigEthernet], peer, ports[0], ports[1]
}

// awaitPeer connects carrier to where peer's first datagram came from, which
// it sends back, so it takes peer's alone
func awaitPeer(t *testing.T, carrier *net.UDPConn, peer netip.Addr) {
	t.Helper()
	buf := make([]byte, 1<<16)
	_ = carrier.SetReadDeadline(time.Now().Add(rigWait))
	defer func() { _ = carrier.SetReadDeadline(time.Time{}) }()
	for {
		n, from, err := carrier.ReadFromUDPAddrPort(buf)
		if err != nil {
			t.Fatalf("rig: no datagram from the peer: %v", err)
		}
		if from.Addr().Unmap() != peer {
			continue
		}
		if err := connectUDP(carrier, netip.AddrPortFrom(peer, from.Port())); err != nil {
			t.Fatalf("connect the carrier to the peer: %v", err)
		}
		_, _ = carrier.Write(buf[:n])
		return
	}
}

// acceptFrom is the first connection listener takes from peer, any other
// closed
func acceptFrom(t *testing.T, listener net.Listener, peer netip.Addr) net.Conn {
	t.Helper()
	_ = listener.(*net.TCPListener).SetDeadline(time.Now().Add(rigWait))
	for {
		conn, err := listener.Accept()
		if err != nil {
			t.Fatalf("rig: no wire from the peer: %v", err)
		}
		if conn.RemoteAddr().(*net.TCPAddr).AddrPort().Addr().Unmap() == peer {
			t.Cleanup(func() { _ = conn.Close() })
			return conn
		}
		_ = conn.Close()
	}
}

// holdsOf names what x holds: its lanes while they take packets, each TCP
// connection, each UDP destination and each echo mapping
func holdsOf(x *Exit) []string {
	var held []string
	if x.taking.Load() {
		held = append(held, "lanes taking packets")
	}
	for _, f := range tableOf(x) {
		held = append(held, fmt.Sprintf("protocol %d from %s to %s", f.Protocol, f.From, f.To))
	}
	slices.Sort(held)
	return held
}

// tableOf is each connection being dialed and relayed, each UDP
// destination with its time left, and each echo mapping with its time left,
// an echo's identifier in place of both ports
func tableOf(x *Exit) []egresstest.Flow {
	now := time.Now()
	var flows []egresstest.Flow
	x.tcp.mu.Lock()
	for id := range x.tcp.dialing {
		flows = append(flows, egresstest.Flow{Protocol: syscall.IPPROTO_TCP, From: leafEnd(id), To: serverEnd(id), Phase: egresstest.Opening, Left: untimed})
	}
	for f := range x.tcp.flows {
		info, ok := f.ep.Info().(*stack.TransportEndpointInfo)
		if !ok {
			continue
		}
		phase, left := tcpPhase(tcp.EndpointState(f.ep.State()))
		flows = append(flows, egresstest.Flow{Protocol: syscall.IPPROTO_TCP, From: leafEnd(info.ID), To: serverEnd(info.ID), Phase: phase, Left: left})
	}
	x.tcp.mu.Unlock()
	x.udp.mu.RLock()
	for _, m := range x.udp.mappings {
		m.mu.RLock()
		for to, dst := range m.destinations {
			flows = append(flows, egresstest.Flow{Protocol: syscall.IPPROTO_UDP, From: m.leaf, To: to, Left: time.Unix(0, dst.deadline.Load()).Sub(now).Truncate(time.Second)})
		}
		m.mu.RUnlock()
	}
	x.udp.mu.RUnlock()
	x.echo.mu.Lock()
	for key, m := range x.echo.mappings {
		protocol := byte(syscall.IPPROTO_ICMP)
		if key.leaf.Is6() {
			protocol = syscall.IPPROTO_ICMPV6
		}
		left := time.Unix(0, m.last.Load()).Add(echoIdle).Sub(now).Truncate(time.Second)
		flows = append(flows, egresstest.Flow{Protocol: protocol, From: netip.AddrPortFrom(key.leaf, key.id), Left: left})
	}
	x.echo.mu.Unlock()
	return flows
}

func leafEnd(id stack.TransportEndpointID) netip.AddrPort {
	return netip.AddrPortFrom(addrOf(id.RemoteAddress), id.RemotePort)
}

func serverEnd(id stack.TransportEndpointID) netip.AddrPort {
	return netip.AddrPortFrom(addrOf(id.LocalAddress), id.LocalPort)
}

// tcpPhase is RFC 5382 section 5's phase of a leaf's endpoint, which the
// exit keeps with no idle timer until an end closes or resets it
func tcpPhase(state tcp.EndpointState) (egresstest.Phase, time.Duration) {
	switch state {
	case tcp.StateSynRecv:
		return egresstest.Opening, untimed
	case tcp.StateEstablished, tcp.StateCloseWait, tcp.StateFinWait1, tcp.StateFinWait2:
		return egresstest.Established, untimed
	case tcp.StateLastAck, tcp.StateClosing:
		return egresstest.Closing, untimed
	}
	return egresstest.NoPhase, 0
}
