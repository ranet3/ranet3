// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package userspace

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/egress/egresstest"
	"ranet3.com/pkgs/ranet3/internal/egress/userspace/raw"
	"ranet3.com/pkgs/ranet3/internal/netnstest"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/wireguard/tun"
)

const (
	// rigCarried names, on the rig's Linux host, that descriptors 3 and 4 are
	// the carrier and the wire whatever starts the test opened
	rigCarried = "RANET3_RIG_CARRIED"
	// rigUplink is the Linux exit host's uplink, a tun in the namespace the
	// exit opens its sockets in, and loopbackIndex the index Linux gives every
	// namespace's loopback
	rigUplink     = "rig0"
	loopbackIndex = 1
	// hookQueue and fillQueue hold the hooks and the fills the far host sent
	// that the proxy's goroutines have not taken yet
	hookQueue = 4
	fillQueue = 64
	// rigProbe is the datagram the suite's host sends through the carrier
	// before any row, which the exit's host sends back, its first nibble
	// neither IP version, and probeWait how long the suite's host waits for
	// it, sending it again each probeSpacing
	rigProbe     = "ranet3 rig probe"
	probeWait    = 5 * time.Second
	probeSpacing = 500 * time.Millisecond
)

// rigRoute is Platform.Route naming the exit host's uplink for every address,
// as the rig's selection does
func rigRoute(uplink string) func(netip.Addr) (Link, bool, error) {
	return func(netip.Addr) (Link, bool, error) { return Link{Name: uplink, MTU: rigMTU}, true, nil }
}

// probeCarrier sends the probe through carrier until the exit's host sends
// it back, and fails the test where it has not within probeWait
func probeCarrier(t testing.TB, carrier *net.UDPConn) {
	t.Helper()
	start := time.Now()
	defer func() { _ = carrier.SetReadDeadline(time.Time{}) }()
	buf := make([]byte, len(rigProbe)+1)
	for time.Since(start) < probeWait {
		_, _ = carrier.Write([]byte(rigProbe))
		_ = carrier.SetReadDeadline(time.Now().Add(min(probeSpacing, probeWait-time.Since(start))))
		for {
			size, err := carrier.Read(buf)
			if errors.Is(err, syscall.ECONNREFUSED) {
				continue
			}
			if err != nil {
				break
			}
			if string(buf[:size]) == rigProbe {
				t.Logf("rig: carrier echo after %s", time.Since(start).Round(time.Millisecond))
				return
			}
		}
	}
	t.Fatal("rig: no echo through the carrier, check the application firewall")
}

// the userspace exit meets the exit behavior suite in both families under
// auto and the address class with the suite on the rig's Linux host and the
// exit on the host at the carrier's far end
func TestUserspaceExitPassesTheSuiteOverTheCarrier(t *testing.T) {
	if os.Getenv(rigCarried) == "" {
		t.Skipf("%s is unset, so no two-host rig handed this test its carrier socket on descriptor 3 and its control connection on descriptor 4", rigCarried)
	}
	carrier, err := net.FileConn(os.NewFile(3, "carrier"))
	if err != nil {
		t.Fatalf("take the carrier from descriptor 3: %v", err)
	}
	control, err := net.FileConn(os.NewFile(4, "wire"))
	if err != nil {
		t.Fatalf("take the wire from descriptor 4: %v", err)
	}
	datagrams, ok := carrier.(*net.UDPConn)
	if !ok {
		t.Fatalf("descriptor 3 is a %T, want a datagram socket", carrier)
	}
	runOverCarrier(t, datagrams, control)
}

// the suite passes over a carrier on this namespace's loopback to an exit
// host in the same process, which the rig's two hosts split
func TestUserspaceExitPassesTheSuiteOverALoopbackCarrier(t *testing.T) {
	claim(t)
	suiteCarrier, hostCarrier := udpPair(t)
	suiteControl, hostControl := tcpPair(t)
	serveLinuxExitHost(t, hostCarrier, hostControl)
	runOverCarrier(t, suiteCarrier, suiteControl)
}

// the userspace exit's host on a Linux host, the twin of the Mac's, so the
// rig's two runners run on one host: the carrier and the wire on the rig's
// ports held to the rig's link, and the exit the suite at the far end asks
// for served in this process's namespace, which it claims
func TestUserspaceExitHostOverTheCarrier(t *testing.T) {
	name, peer, port, controlPort := rigVariables(t)
	claim(t)
	link, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatalf("rig: carrier not on %s: %v", name, err)
	}
	carrier := rigCarrier(t, link, port)
	listener := rigListener(t, link, controlPort)
	awaitPeer(t, carrier, peer)
	control := acceptFrom(t, listener, peer)
	_ = listener.Close()
	// cleanups run last first, so this line comes after the exit host's
	t.Cleanup(func() { t.Log("rig: uplink and routes removed") })
	<-serveLinuxExitHost(t, carrier, control)
}

// rigCarrier is the carrier's datagram socket on port, held to link with
// SO_BINDTODEVICE, read back
func rigCarrier(t *testing.T, link *net.Interface, port uint16) *net.UDPConn {
	t.Helper()
	conn, err := heldTo(link).ListenPacket(context.Background(), "udp4", fmt.Sprintf(":%d", port))
	if err != nil {
		t.Fatalf("open the carrier: %v", err)
	}
	carrier := conn.(*net.UDPConn)
	t.Cleanup(func() { _ = carrier.Close() })
	raw, err := carrier.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var device string
	if controlErr := raw.Control(func(fd uintptr) {
		device, err = unix.GetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE)
	}); controlErr != nil || err != nil {
		t.Fatalf("read the carrier's link back: %v %v", controlErr, err)
	}
	if device != link.Name {
		t.Fatalf("rig: carrier not on %s: held to %q", link.Name, device)
	}
	t.Logf("rig: carrier bound to %s index %d", link.Name, link.Index)
	return carrier
}

// rigListener is the wire's listener on port, held to link
func rigListener(t *testing.T, link *net.Interface, port uint16) net.Listener {
	t.Helper()
	listener, err := heldTo(link).Listen(context.Background(), "tcp4", fmt.Sprintf(":%d", port))
	if err != nil {
		t.Fatalf("listen for the wire: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}

// heldTo is a listen whose socket SO_BINDTODEVICE holds to link
func heldTo(link *net.Interface) *net.ListenConfig {
	return &net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		var err error
		if controlErr := raw.Control(func(fd uintptr) { err = unix.BindToDevice(int(fd), link.Name) }); controlErr != nil {
			return controlErr
		}
		return err
	}}
}

// runOverCarrier probes carrier, then runs the suite with each network's
// router uplink on carrier and each exit a proxy over control
func runOverCarrier(t *testing.T, carrier *net.UDPConn, control net.Conn) {
	probeCarrier(t, carrier)
	s := &suiteEnd{w: newStream(control)}
	go func() { _ = s.w.serve(s.handle) }()
	t.Cleanup(func() {
		_ = control.Close()
		<-s.w.done
	})
	egresstest.Run(t, func(t testing.TB) egresstest.Network { return egresstest.Carried(t, carrier) }, egresstest.Arm{
		Classes:    []egresstest.Class{egresstest.Auto, egresstest.Address},
		Limits:     linuxLimits(),
		Terminates: true,
		New:        s.open,
		Holds:      s.holds,
		Flows:      s.flows,
	})
}

// suiteEnd is the suite's end of a carrier, which builds each exit the suite
// asks for on the far host behind a proxy
type suiteEnd struct {
	w *stream

	mu    sync.Mutex
	p     *proxyExit
	exits uint32
}

// open has the far host build the exit for cfg, whose lanes land on a lane of
// host's mesh
func (s *suiteEnd) open(t testing.TB, host egresstest.Host, cfg egress.Egress, hooks egress.Hooks) egress.Exit {
	t.Helper()
	s.mu.Lock()
	s.exits++
	p := &proxyExit{
		w: s.w, number: s.exits, hooks: hooks, lane: host.Lanes.OpenLane(),
		called: make(chan wireCall, hookQueue), fills: make(chan [][]byte, fillQueue),
		fed: make(chan struct{}), ran: make(chan struct{}),
	}
	s.p = p
	s.mu.Unlock()
	go p.feed()
	go p.runHooks()
	payload, err := json.Marshal(spec{Egress: cfg, Mesh: host.Mesh, Number: p.number})
	if err != nil {
		t.Fatalf("write the exit's spec: %v", err)
	}
	if _, err := s.w.call(callNew, payload); err != nil {
		t.Fatalf("build the userspace exit on the far host: %v", err)
	}
	return p
}

func (s *suiteEnd) holds(egresstest.Host) ([]string, error) {
	var held []string
	return held, s.read(callHolds, &held)
}

func (s *suiteEnd) flows(egresstest.Host) ([]egresstest.Flow, error) {
	var flows []egresstest.Flow
	return flows, s.read(callFlows, &flows)
}

func (s *suiteEnd) read(kind byte, into any) error {
	reply, err := s.w.call(kind, nil)
	if err != nil {
		return err
	}
	return json.Unmarshal(reply, into)
}

// handle hands the far host's hooks to the proxy's hook goroutine in order
// and its fills to the feeder in order, and answers each lane's request on a
// goroutine of its own
func (s *suiteEnd) handle(kind byte, id uint32, payload []byte) {
	s.mu.Lock()
	p := s.p
	s.mu.Unlock()
	if p == nil {
		if kind != laneFill {
			_ = s.w.reply(id, nil, errors.New("no exit was asked for"))
		}
		return
	}
	switch kind {
	case hookReady, hookRepublish:
		select {
		case p.called <- wireCall{kind, id, payload}:
		case <-p.ran:
			_ = s.w.reply(id, nil, errors.New("the exit's run ended"))
		}
	case laneFill:
		packets, err := packetsOf(payload)
		if err != nil {
			return
		}
		select {
		case p.fills <- packets:
		case <-p.fed:
		}
	case laneAnswer, laneMTU, laneSameSession:
		go p.answer(kind, id, payload)
	default:
		_ = s.w.reply(id, nil, fmt.Errorf("a request of kind %d", kind))
	}
}

type wireCall struct {
	kind    byte
	id      uint32
	payload []byte
}

// proxyExit is the exit on the far host as the suite drives it
type proxyExit struct {
	w      *stream
	number uint32
	hooks  egress.Hooks
	// lane is the lane of the suite's mesh the far exit's lanes land on
	lane *netstack.Lane
	// called and fills are the far host's hooks and fills in the order sent,
	// fed is closed once the feeder gave the lane back, and ran once Run
	// returned
	called chan wireCall
	fills  chan [][]byte
	fed    chan struct{}
	ran    chan struct{}
}

var _ egress.Exit = (*proxyExit)(nil)

func (p *proxyExit) Run(ctx context.Context) error {
	defer close(p.ran)
	stop := context.AfterFunc(ctx, func() { _ = p.w.send(callCancel, 0, p.numbered()) })
	defer stop()
	_, err := p.w.call(callRun, nil)
	return err
}

func (p *proxyExit) Close() error {
	_, err := p.w.call(callClose, nil)
	return err
}

func (p *proxyExit) SetEnabled(on bool) { _, _ = p.w.call(callEnable, []byte{flag(on)}) }

func (p *proxyExit) Egress(frames [][]byte, _ netstack.Hold) {
	var payload []byte
	for _, frame := range frames {
		payload = appendPackets(payload, frame[netstack.TUNHeadroom:])
	}
	// a wire that ended is a session's receive path with no exit to hand to
	_ = p.w.send(callEgress, 0, payload)
}

func (p *proxyExit) Announce() []netip.Prefix {
	var prefixes []netip.Prefix
	reply, err := p.w.call(callAnnounce, nil)
	if err == nil {
		_ = json.Unmarshal(reply, &prefixes)
	}
	return prefixes
}

func (p *proxyExit) Status() egress.Status {
	var status egress.Status
	reply, err := p.w.call(callStatus, nil)
	if err == nil {
		err = json.Unmarshal(reply, &status)
	}
	if err != nil {
		return egress.Status{Backend: "userspace", Err: err.Error()}
	}
	return status
}

func (p *proxyExit) numbered() []byte { return binary.BigEndian.AppendUint32(nil, p.number) }

// runHooks runs each hook the far exit called, in order, and answers it once
// the hook returned, until Run returns
func (p *proxyExit) runHooks() {
	for {
		select {
		case call := <-p.called:
			switch {
			case call.kind == hookReady && len(call.payload) == 3 && p.hooks.Ready != nil:
				p.hooks.Ready(call.payload[0] == 1, call.payload[1] == 1, call.payload[2] == 1)
			case call.kind == hookRepublish && p.hooks.Republish != nil:
				p.hooks.Republish()
			}
			_ = p.w.reply(call.id, nil, nil)
		case <-p.ran:
			return
		case <-p.w.done:
			return
		}
	}
}

// feed lays each fill the far exit sent in batches of the lane, until the
// mesh closes, and then tells the far host its lanes are done
func (p *proxyExit) feed() {
	defer close(p.fed)
	defer p.lane.Close()
	for {
		select {
		case packets := <-p.fills:
			for len(packets) != 0 {
				var taken int
				if !p.lane.Fill(func(slab []byte, reads []tun.ReadPacket) int {
					var n int
					n, taken = layWhole(slab, reads, packets)
					return n
				}) {
					_ = p.w.send(callMeshClosed, 0, p.numbered())
					return
				}
				packets = packets[taken:]
			}
		case <-p.lane.Done():
			_ = p.w.send(callMeshClosed, 0, p.numbered())
			return
		}
	}
}

// layWhole lays packets in slab as a tun read lays them, while they fit, and
// reports the reads it made and the packets it took, among them a packet that
// fits no empty batch, which it drops
func layWhole(slab []byte, reads []tun.ReadPacket, packets [][]byte) (n, taken int) {
	used := 0
	for _, packet := range packets {
		at := used + tun.ReadPacketSpacing
		if n == len(reads) || at+len(packet)+tun.ReadPacketSpacing > len(slab) {
			if n == 0 {
				return 0, 1
			}
			return n, taken
		}
		copy(slab[at:], packet)
		reads[n] = tun.ReadPacket{Offset: at, Size: len(packet)}
		n, used, taken = n+1, at+len(packet), taken+1
	}
	return n, taken
}

func (p *proxyExit) answer(kind byte, id uint32, payload []byte) {
	switch kind {
	case laneAnswer:
		if len(payload) < 5 {
			_ = p.w.reply(id, nil, errors.New("an answer request cut short"))
			return
		}
		sent := p.lane.Answer(payload[5:], netstack.ExitAnswer(payload[0]), int(binary.BigEndian.Uint32(payload[1:])))
		_ = p.w.reply(id, []byte{flag(sent)}, nil)
	case laneMTU:
		from, to, _ := strings.Cut(string(payload), " ")
		source, err := netip.ParseAddr(from)
		var destination netip.Addr
		if err == nil {
			destination, err = netip.ParseAddr(to)
		}
		if err != nil {
			_ = p.w.reply(id, nil, err)
			return
		}
		_ = p.w.reply(id, binary.BigEndian.AppendUint32(nil, uint32(p.lane.MTU(source, destination))), nil)
	case laneSameSession:
		var addresses [3]netip.Addr
		fields := strings.Fields(string(payload))
		if len(fields) != len(addresses) {
			_ = p.w.reply(id, nil, errors.New("a session request of other than three addresses"))
			return
		}
		for i, field := range fields {
			address, err := netip.ParseAddr(field)
			if err != nil {
				_ = p.w.reply(id, nil, err)
				return
			}
			addresses[i] = address
		}
		_ = p.w.reply(id, []byte{flag(p.lane.SameSession(addresses[0], addresses[1], addresses[2]))}, nil)
	}
}

// serveLinuxExitHost runs the exit's end of a carrier in this process's
// namespace, which the caller claimed, with an uplink of its own, until
// control ends. Every socket the exit opens passes a Prepare that records it
// and a watch that fails the test on any other, the carrier and control
// aside. The returned channel is closed once control ended.
func serveLinuxExitHost(t *testing.T, carrier *net.UDPConn, control net.Conn) <-chan struct{} {
	t.Helper()
	// a new namespace lets no group open an ICMP datagram socket, and the
	// daemon's group is one the host's range admits
	if err := os.WriteFile("/proc/sys/net/ipv4/ping_group_range", fmt.Appendf(nil, "%d %d\n", os.Getegid(), os.Getegid()), 0o644); err != nil {
		t.Fatalf("admit this process's group to echo sockets: %v", err)
	}
	memory, err := HostMemory()
	if err != nil {
		t.Fatalf("read the host's memory: %v", err)
	}
	limits, err := Within(memory, Files())
	if err != nil {
		t.Fatalf("size the exit: %v", err)
	}
	if err := os.WriteFile("/proc/sys/net/ipv6/conf/default/accept_dad", []byte("0\n"), 0o644); err != nil {
		t.Fatalf("make links skip duplicate address detection: %v", err)
	}
	if err := classesOnLoopback(true); err != nil {
		t.Fatalf("give the loopback the class addresses: %v", err)
	}
	w := &socketWatch{prepared: map[uint64]bool{}, loopback: true}
	for _, rig := range []any{carrier, control} {
		if conn, ok := rig.(syscall.Conn); ok {
			if raw, err := conn.SyscallConn(); err == nil {
				_ = w.prepare("", netip.AddrPort{}, raw)
			}
		}
	}
	w.run(t)
	uplink := &carriedUplink{carrier: carrier, open: openRigUplink}
	uplink.start()
	h := newExitHost(control, func() (Platform, error) {
		sockets, err := raw.New()
		if err != nil {
			return Platform{}, err
		}
		return Platform{Prepare: w.prepare, Route: rigRoute(rigUplink), Held: namespaceHolds, Raw: sockets}, nil
	}, limits, uplink)
	served := make(chan struct{})
	// control may end only between messages, as the Mac's host takes it
	go func() {
		defer close(served)
		if err := h.serve(); err != nil && !errors.Is(err, errWireEnded) {
			t.Errorf("the wire: %v", err)
		}
	}()
	t.Cleanup(func() {
		// the far side ends control, which is closed here only where it has
		// not within exitWait, and the read of the closed end fails the test
		select {
		case <-served:
		case <-time.After(exitWait):
			_ = control.Close()
			<-served
		}
		// the tun goes with its last descriptor, its addresses and routes with it
		uplink.stop()
		_ = classesOnLoopback(false)
	})
	return served
}

// classesOnLoopback gives this namespace's loopback the class addresses where
// add is set and takes them off where it is not, since the namespace outlives
// the exit host
func classesOnLoopback(add bool) error {
	netlink, err := netnstest.OpenNetlink()
	if err != nil {
		return err
	}
	defer netlink.Close()
	for _, class := range rigClasses {
		if !add {
			err = errors.Join(err, netlink.DelAddress(loopbackIndex, class))
		} else if err = netlink.AddAddress(loopbackIndex, class); err != nil {
			return err
		}
	}
	return err
}

// openRigUplink makes the exit host's uplink in this process's namespace with
// the rig's addresses and routes, as the rig's Mac gives its utun
func openRigUplink() (io.ReadWriteCloser, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	ifr, err := unix.NewIfreq(rigUplink)
	if err == nil {
		ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
		err = unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr)
	}
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("make %s: %w", rigUplink, err)
	}
	uplink := os.NewFile(uintptr(fd), rigUplink)
	if err := addressRigUplink(); err != nil {
		_ = uplink.Close()
		return nil, fmt.Errorf("address %s: %w", rigUplink, err)
	}
	return uplink, nil
}

func addressRigUplink() error {
	link, err := net.InterfaceByName(rigUplink)
	if err != nil {
		return err
	}
	if err := netnstest.SetLinkMTU(link.Index, rigMTU); err != nil {
		return err
	}
	netlink, err := netnstest.OpenNetlink()
	if err != nil {
		return err
	}
	defer netlink.Close()
	if err := netlink.AddAddresses(rigUplink, rigAddresses...); err != nil {
		return err
	}
	for _, route := range rigRoutes {
		if err := netlink.RouteVia(link.Index, route.to, route.via); err != nil {
			return fmt.Errorf("route %s through %s: %w", route.to, route.via, err)
		}
	}
	return nil
}

// udpPair is two datagram sockets on this namespace's loopback connected to
// each other
func udpPair(t *testing.T) (*net.UDPConn, *net.UDPConn) {
	t.Helper()
	var ends [2]*net.UDPConn
	for i := range ends {
		end, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 0)))
		if err != nil {
			t.Fatalf("open a datagram socket on the loopback: %v", err)
		}
		t.Cleanup(func() { _ = end.Close() })
		ends[i] = end
	}
	for i, end := range ends {
		if err := connectUDP(end, ends[1-i].LocalAddr().(*net.UDPAddr).AddrPort()); err != nil {
			t.Fatalf("connect the carrier's ends: %v", err)
		}
	}
	return ends[0], ends[1]
}

// tcpPair is two ends of a connection on this namespace's loopback
func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen on the loopback: %v", err)
	}
	defer listener.Close()
	near, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatalf("connect on the loopback: %v", err)
	}
	t.Cleanup(func() { _ = near.Close() })
	far, err := listener.Accept()
	if err != nil {
		t.Fatalf("accept on the loopback: %v", err)
	}
	t.Cleanup(func() { _ = far.Close() })
	return near, far
}
