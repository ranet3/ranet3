// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux

package netstack

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"weak"
)

// the stream TestTUNCoalescesFramesIntoAKernelSocket sends, groBursts bursts of groSegments segments of groMSS bytes, one delivery a burst
// a burst fits the window a kernel socket opens with, so each one is acknowledged whole before the next goes
// groPort is the port the kernel listens on and groFarPort the one the far end sends from
const (
	groBursts   = 16
	groSegments = 32
	groMSS      = DefaultMTU - 40 - tcpHeaderLen
	groPort     = 5201
	groFarPort  = 40001
	// ackFlag is TCP's ACK, RFC 9293 section 3.1
	ackFlag = 0x10
)

// tcpStream is the far end of one TCP connection into a kernel socket behind a mesh's tun, at tunPeer6
// it learns the kernel's sequence number and acknowledgments from what the mesh sends to the far end
type tcpStream struct {
	mu     sync.Mutex
	synAck bool
	rcvNxt uint32
	sndUna uint32
}

// segment is the IPv6 TCP segment the far end sends at seq acknowledging ack, with flags, options and payload, its checksum valid
func (s *tcpStream) segment(seq, ack uint32, flags byte, options, payload []byte) []byte {
	length := tcpHeaderLen + len(options) + len(payload)
	raw := make([]byte, 40+length)
	raw[0] = 0x60
	binary.BigEndian.PutUint16(raw[4:], uint16(length))
	raw[6], raw[7] = tcpProtocol, 64
	copy(raw[8:24], tunPeer6.AsSlice())
	copy(raw[24:40], tunAddress6.Addr().AsSlice())
	tcp := raw[40:]
	binary.BigEndian.PutUint16(tcp[0:], groFarPort)
	binary.BigEndian.PutUint16(tcp[2:], groPort)
	binary.BigEndian.PutUint32(tcp[4:], seq)
	binary.BigEndian.PutUint32(tcp[8:], ack)
	tcp[12] = byte((tcpHeaderLen+len(options))/4) << 4
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:], 65535)
	copy(tcp[tcpHeaderLen:], options)
	copy(tcp[tcpHeaderLen+len(options):], payload)
	binary.BigEndian.PutUint16(tcp[tcpChecksum:], tcpSum(raw, 40))
	return raw
}

// burst is the segments carrying the stream from offset, sent at seq acknowledging ack, framed as a session hands them over
func (s *tcpStream) burst(seq, ack uint32, offset int) [][]byte {
	segments := make([][]byte, groSegments)
	for i := range segments {
		at := offset + i*groMSS
		segments[i] = s.segment(seq+uint32(at), ack, ackFlag, nil, streamBytes(at, groMSS))
	}
	return framed(segments...)
}

// observe takes the kernel's SYN-ACK and acknowledgments out of what the mesh sent to the far end
func (s *tcpStream) observe(sent [][]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, raw := range sent {
		// the kernel's segments carry TCP straight behind the fixed IPv6 header
		if len(raw) < 40+tcpHeaderLen || raw[0]>>4 != 6 || raw[6] != tcpProtocol {
			continue
		}
		tcp := raw[40:]
		if binary.BigEndian.Uint16(tcp[0:]) != groPort || binary.BigEndian.Uint16(tcp[2:]) != groFarPort {
			continue
		}
		flags, ack := tcp[13], binary.BigEndian.Uint32(tcp[8:])
		if flags&(synFlag|ackFlag) == synFlag|ackFlag {
			s.synAck, s.rcvNxt = true, binary.BigEndian.Uint32(tcp[4:])+1
		}
		if flags&ackFlag != 0 && int32(ack-s.sndUna) > 0 {
			s.sndUna = ack
		}
	}
}

// acknowledged is the far end's next sequence number the kernel has acknowledged, and whether its SYN-ACK came
func (s *tcpStream) acknowledged() (uint32, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sndUna, s.synAck
}

// streamBytes is the n bytes of the stream from offset, each one set by where it sits
func streamBytes(offset, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		x := offset + i
		out[i] = byte(x*31 + x>>9)
	}
	return out
}

// readStream accepts one connection on listener and reads total bytes off it, refusing any that differ from streamBytes
// each read waits at most deliveryTimeout, so a stream that stops ends the read
func readStream(listener *net.TCPListener, total int) error {
	conn, err := listener.Accept()
	if err != nil {
		return fmt.Errorf("accept the stream: %w", err)
	}
	defer conn.Close()
	buf := make([]byte, 1<<16)
	for n := 0; n < total; {
		if err := conn.SetReadDeadline(time.Now().Add(deliveryTimeout)); err != nil {
			return fmt.Errorf("bound the read at %d bytes: %w", n, err)
		}
		k, err := conn.Read(buf)
		if !bytes.Equal(buf[:k], streamBytes(n, k)) {
			return fmt.Errorf("the socket read %d bytes at %d of the stream that differ from the bytes sent", k, n)
		}
		n += k
		if err != nil && n < total {
			return fmt.Errorf("read the stream at %d of %d bytes: %w", n, total, err)
		}
	}
	return nil
}

// tunReceived is how many packets the kernel counts the link name as having received, one for each packet a write put into the tun
// read in the calling thread's own namespace, where the mesh opened the tun
func tunReceived(t *testing.T, name string) uint64 {
	t.Helper()
	dev, err := os.ReadFile("/proc/thread-self/net/dev")
	if err != nil {
		t.Fatalf("read the link counters: %v", err)
	}
	for line := range strings.Lines(string(dev)) {
		link, counters, ok := strings.Cut(line, ":")
		// the receive counters come first, bytes and then packets
		if fields := strings.Fields(counters); ok && strings.TrimSpace(link) == name && len(fields) > 1 {
			packets, err := strconv.ParseUint(fields[1], 10, 64)
			if err != nil {
				t.Fatalf("read the packets %s received off %q: %v", name, line, err)
			}
			return packets
		}
	}
	t.Fatalf("the kernel lists no counters for %s", name)
	return 0
}

// in-order segments of one TCP flow reach a kernel socket through the tun as frames lying in one buffer, as a session's datagrams do
// each burst of them is one delivery, which the tun's GRO coalesces into fewer packets than it has segments
// and the socket reads back exactly the bytes sent, so no write and no coalescing reached past a frame into the packet behind it
func TestTUNCoalescesFramesIntoAKernelSocket(t *testing.T) {
	const iss = 7000
	enterEmptyNamespace(t)
	m, err := NewNamed(DefaultMTU, "grotest0", nil)
	if err != nil {
		t.Fatalf("open the mesh: %v", err)
	}
	t.Cleanup(m.Close)
	assignIPv6(t, m.Name, tunAddress6)
	listener, err := net.ListenTCP("tcp6", net.TCPAddrFromAddrPort(netip.AddrPortFrom(tunAddress6.Addr(), groPort)))
	if err != nil {
		t.Fatalf("listen on %s: %v", tunAddress6.Addr(), err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	total := groBursts * groSegments * groMSS
	read := make(chan error, 1)
	go func() { read <- readStream(listener, total) }()

	stream := &tcpStream{}
	far := NewPeer("far", func(int) (BatchSealer, error) { return cloning, nil }, func(sent [][]byte) error {
		stream.observe(sent)
		return nil
	}, nil)
	t.Cleanup(far.Close)
	m.Routes.Set(netip.Prefix{}, netip.PrefixFrom(tunPeer6, 128), far)

	mss := binary.BigEndian.AppendUint16([]byte{optionMSS, mssLen}, groMSS)
	m.DeliverInboundBatch(framed(stream.segment(iss, 0, synFlag, mss, nil)), DefaultMTU)
	waitUntil(t, "the kernel's SYN-ACK", func() bool { _, synAck := stream.acknowledged(); return synAck })
	stream.mu.Lock()
	ack := stream.rcvNxt
	stream.mu.Unlock()
	m.DeliverInboundBatch(framed(stream.segment(iss+1, ack, ackFlag, nil, nil)), DefaultMTU)

	before := tunReceived(t, m.Name)
	for burst := range groBursts {
		offset := burst * groSegments * groMSS
		m.DeliverInboundBatch(stream.burst(iss+1, ack, offset), DefaultMTU)
		want := uint32(iss + 1 + offset + groSegments*groMSS)
		waitUntil(t, fmt.Sprintf("burst %d to be acknowledged", burst), func() bool { got, _ := stream.acknowledged(); return got == want })
	}
	written := tunReceived(t, m.Name) - before
	t.Logf("%d segments went into the tun as %d packets", groBursts*groSegments, written)
	if written >= groBursts*groSegments {
		t.Errorf("%d segments went into the tun as %d packets, so its GRO coalesced none of them", groBursts*groSegments, written)
	}
	select {
	case err := <-read:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(deliveryTimeout):
		t.Fatal("the kernel socket never read the whole stream")
	}
}

// laneWrite is one write of the tests below, frames as a session hands them over
type laneWrite struct {
	name   string
	frames [][]byte
}

// laneWrites is a packet alone, pure ACKs the tun's GRO writes one at a time, and segments of one flow it coalesces
func laneWrites() []laneWrite {
	stream := &tcpStream{}
	acks := make([][]byte, groSegments)
	for i := range acks {
		acks[i] = stream.segment(1, 1, ackFlag, nil, nil)
	}
	return []laneWrite{
		{"a packet alone", framed(acks[0])},
		{"pure ACKs", framed(acks...)},
		{"segments that coalesce", stream.burst(1, 1, 0)},
	}
}

// a lane's write into the tun allocates nothing, whether its packets go one a writev or coalesce
func TestTUNWriteAllocatesNothing(t *testing.T) {
	enterEmptyNamespace(t)
	m, err := NewNamed(DefaultMTU, "allocs0", nil)
	if err != nil {
		t.Fatalf("open the mesh: %v", err)
	}
	t.Cleanup(m.Close)
	before := tunReceived(t, m.Name)
	for _, write := range laneWrites() {
		// GRO rewrites the packets it coalesces, so each write is of a fresh copy laid out as the frames are
		work := framed(unframed(write.frames)...)
		if _, err := m.write(0, work, TUNHeadroom); err != nil {
			t.Fatalf("write %s: %v", write.name, err)
		}
		allocations := testing.AllocsPerRun(100, func() {
			for i, frame := range write.frames {
				copy(work[i], frame)
			}
			m.writeInbound(0, work)
		})
		if allocations != 0 {
			t.Errorf("a lane's write of %s allocated %v times, want none", write.name, allocations)
		}
	}
	if tunReceived(t, m.Name) == before {
		t.Fatal("the writes put no packet into the tun, so this proves nothing")
	}
}

// a lane's write leaves nothing of the frames it wrote reachable from the mesh or its tun
// so the storage a session's datagrams lie in goes once the packets in it are written, whether they went alone or coalesced
func TestTUNWriteKeepsNoReferenceToItsFrames(t *testing.T) {
	enterEmptyNamespace(t)
	m, err := NewNamed(DefaultMTU, "keep0", nil)
	if err != nil {
		t.Fatalf("open the mesh: %v", err)
	}
	t.Cleanup(m.Close)
	for _, write := range laneWrites() {
		storage := func() weak.Pointer[byte] {
			frames := framed(unframed(write.frames)...)
			m.writeInbound(0, frames)
			return weak.Make(&frames[0][0])
		}()
		runtime.GC()
		if storage.Value() != nil {
			t.Errorf("the storage of %s outlived the write", write.name)
		}
	}
}
