// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin

package netstack

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/control"
)

// the addresses of the test below, in RFC 5737's 192.0.2.0/24 and RFC 9637's 3fff::/20
// own is the utun's own address in each family, and unheld an address of the mesh's own prefix that the utun does not hold
var (
	ownBack    = map[int]netip.Addr{4: netip.MustParseAddr("192.0.2.1"), 6: netip.MustParseAddr("3fff:10::1")}
	unheldBack = map[int]netip.Addr{4: netip.MustParseAddr("192.0.2.5"), 6: netip.MustParseAddr("3fff:10::5")}
	// ownPrefixes is the prefix of this node's own in each family, which the subnet layout routes into the utun as ranet3 routes its overlay
	ownPrefixes = map[int]netip.Prefix{4: netip.MustParsePrefix("192.0.2.0/24"), 6: netip.MustParsePrefix("3fff:10::/32")}
)

const (
	// bulkStream is how many bytes the bulk arm echoes over TCP, and bulkDatagram the size of its one UDP datagram
	bulkStream   = 256 << 10
	bulkDatagram = 8 << 10
	// bulkTimeout bounds each bulk transfer
	bulkTimeout = 20 * time.Second
)

// ownLayouts are the two ways ranet3 addresses its utun, as host prefixes or below them
var ownLayouts = []struct {
	name   string
	bits   map[int]int
	subnet bool
}{
	{"host prefixes", map[int]int{4: 32, 6: 128}, false},
	{"subnet prefixes", map[int]int{4: 24, 6: 64}, true},
}

// a mesh on a real utun, opened ownedOnly as the daemon opens it on darwin, its utun addressed as ranet3 addresses it and holding those addresses
// hands a datagram from an unbound socket to its own address back to the kernel, which delivers it and its reply the same way, and a TCP connect completes and echoes
// and so do a bulk TCP echo and a datagram larger than any of those, which log their time and the longest read written back
// in both families, counted delivered and never looped
// under the subnet layout a datagram to an address of the mesh's own prefix the utun does not hold is counted looped, answered and never written back
// creating a utun needs root, which a run does here only with RANET3_DARWIN_NETTEST=1
func TestTUNHandsAReadToItsOwnAddressBack(t *testing.T) {
	requireUTUN(t)
	routesKept(t)
	for _, layout := range ownLayouts {
		t.Run(layout.name, func(t *testing.T) {
			m := openUTUNMesh(t, true)
			// the TTL the daemon hands the mesh from the host's default, without which the mesh builds no ICMPv4 error
			m.SetAnswerTTL(64)
			for _, family := range []int{4, 6} {
				aliasUTUN(t, m.Name, netip.PrefixFrom(ownBack[family], layout.bits[family]))
				m.Routes.Set(netip.Prefix{}, hostPrefix(ownBack[family]), Local)
			}
			if err := runTool(ifconfigBin, m.Name, "up"); err != nil {
				t.Fatal(err)
			}
			m.SetTunAddresses([]netip.Addr{ownBack[4], ownBack[6]})
			for _, family := range []int{4, 6} {
				own := ownBack[family]
				was := m.TransitCounters()
				if err := exchangeWithOwn(own); err != nil {
					t.Errorf("%s a UDP exchange with %s: %v, the counters reading %+v", layout.name, own, err, m.TransitCounters())
				}
				if err := connectToOwn(own); err != nil {
					t.Errorf("%s a TCP connect to %s: %v, the counters reading %+v", layout.name, own, err, m.TransitCounters())
				}
				// the datagram, its reply and the connect's segments each went back, and the tally lands once each read is decided
				waitUntil(t, fmt.Sprintf("%s the reads to %s counted delivered", layout.name, own), func() bool { return m.TransitCounters().Delivered-was.Delivered >= 4 })
				moveBulk(t, m, layout.name, own)
				if now := m.TransitCounters(); now.Looped != was.Looped {
					t.Errorf("%s reads to %s counted looped %d times", layout.name, own, now.Looped-was.Looped)
				}
			}
			if !layout.subnet {
				return
			}
			for _, family := range []int{4, 6} {
				routeIntoUTUN(t, ownPrefixes[family], m.Name)
				m.Routes.Set(netip.Prefix{}, ownPrefixes[family], Local)
			}
			for _, family := range []int{4, 6} {
				was := m.TransitCounters()
				waitLoopedAndAnswered(t, m, unheldBack[family])
				if now := m.TransitCounters(); now.Delivered != was.Delivered {
					t.Errorf("the read to %s, which the utun does not hold, was counted delivered %d times", unheldBack[family], now.Delivered-was.Delivered)
				}
			}
		})
	}
}

// waitLoopedAndAnswered sends one datagram to unheld, an address of the mesh's own prefix the utun does not hold, and waits for the read to be counted looped and answered, each once
// a failed wait reports the looped and answered counts and the answers the limits withheld, before and after, and what a trace of the read recorded
func waitLoopedAndAnswered(t *testing.T, m *Mesh, unheld netip.Addr) {
	t.Helper()
	feed, err := m.Trace(TraceFilter{Destinations: []netip.Prefix{hostPrefix(unheld)}}, 0, control.TraceRateMax)
	if err != nil {
		t.Fatal(err)
	}
	defer feed.Close()
	was := m.TransitCounters()
	wasBySource, wasByNode := m.ICMPWithheld()
	if err := sendUnbound(unheld); err != nil {
		t.Fatalf("send to %s: %v", unheld, err)
	}
	for deadline := time.Now().Add(deliveryTimeout); ; time.Sleep(deliveryPoll) {
		now := m.TransitCounters()
		if now.Looped-was.Looped == 1 && now.Answered-was.Answered == 1 {
			return
		}
		if time.Now().After(deadline) {
			bySource, byNode := m.ICMPWithheld()
			var records []string
			for len(records) < 8 {
				select {
				case r := <-feed.Records():
					records = append(records, fmt.Sprintf("%s %s from %s, %s %s, answer %q %s", r.Decision, r.Reason, r.Source, r.Destination, r.Headers, r.Answer, r.Outcome))
					continue
				default:
				}
				break
			}
			t.Fatalf("waited %s for the read to %s counted looped and answered once: looped %d to %d, answered %d to %d, withheld by source %d to %d and by node %d to %d, the trace recording %q",
				deliveryTimeout, unheld, was.Looped, now.Looped, was.Answered, now.Answered, wasBySource, bySource, wasByNode, byNode, records)
		}
	}
}

// listenOwn binds a socket on own through listen, retrying while an IPv6 address is still tentative
func listenOwn[T any](own netip.Addr, listen func(netip.AddrPort) (T, error)) (T, error) {
	var conn T
	var err error
	for deadline := time.Now().Add(tentativeWait); ; time.Sleep(tentativePoll) {
		if conn, err = listen(netip.AddrPortFrom(own, 0)); err == nil || time.Now().After(deadline) {
			return conn, err
		}
	}
}

// exchangeWithOwn sends a datagram from an unbound socket to a listener on own and the listener's reply back to where it came from
func exchangeWithOwn(own netip.Addr) error {
	server, err := listenOwn(own, func(at netip.AddrPort) (*net.UDPConn, error) {
		return net.ListenUDP("udp", net.UDPAddrFromAddrPort(at))
	})
	if err != nil {
		return err
	}
	defer server.Close()
	client, err := net.DialUDP("udp", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		return err
	}
	defer client.Close()
	ask, answer := []byte("ask"), []byte("answer")
	if _, err := client.Write(ask); err != nil {
		return err
	}
	buf := make([]byte, 64)
	if err := server.SetReadDeadline(time.Now().Add(deliveryTimeout)); err != nil {
		return err
	}
	n, from, err := server.ReadFromUDPAddrPort(buf)
	if err != nil {
		return fmt.Errorf("the datagram from %s was not delivered: %w", client.LocalAddr(), err)
	}
	if !bytes.Equal(buf[:n], ask) {
		return fmt.Errorf("the listener read %q, want %q", buf[:n], ask)
	}
	if _, err := server.WriteToUDPAddrPort(answer, from); err != nil {
		return err
	}
	if err := client.SetReadDeadline(time.Now().Add(deliveryTimeout)); err != nil {
		return err
	}
	if n, err = client.Read(buf); err != nil || !bytes.Equal(buf[:n], answer) {
		return fmt.Errorf("the reply read %q, %v, want %q", buf[:n], err, answer)
	}
	return nil
}

// connectToOwn connects to a TCP listener on own and has it echo one byte
func connectToOwn(own netip.Addr) error {
	listener, err := listenOwn(own, func(at netip.AddrPort) (*net.TCPListener, error) {
		return net.ListenTCP("tcp", net.TCPAddrFromAddrPort(at))
	})
	if err != nil {
		return err
	}
	defer listener.Close()
	echoed := make(chan error, 1)
	go func() {
		if err := listener.SetDeadline(time.Now().Add(deliveryTimeout)); err != nil {
			echoed <- err
			return
		}
		conn, err := listener.Accept()
		if err != nil {
			echoed <- err
			return
		}
		defer conn.Close()
		one := make([]byte, 1)
		if _, err := io.ReadFull(conn, one); err != nil {
			echoed <- err
			return
		}
		_, err = conn.Write(one)
		echoed <- err
	}()
	conn, err := net.DialTimeout("tcp", listener.Addr().String(), deliveryTimeout)
	if err != nil {
		return errors.Join(err, <-echoed)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(deliveryTimeout)); err != nil {
		return err
	}
	if _, err := conn.Write([]byte{'x'}); err != nil {
		return err
	}
	one := make([]byte, 1)
	if _, err := io.ReadFull(conn, one); err != nil || one[0] != 'x' {
		return fmt.Errorf("the echo read %q, %v", one, err)
	}
	return <-echoed
}

// moveBulk echoes bulkStream bytes over TCP and sends one datagram of bulkDatagram bytes to own
// logging each transfer's time and the longest read the mesh wrote back during it
func moveBulk(t *testing.T, m *Mesh, layout string, own netip.Addr) {
	t.Helper()
	for _, transfer := range []struct {
		name string
		size int
		move func(netip.Addr, int) error
	}{
		{"a TCP echo", bulkStream, echoBulk},
		{"a UDP datagram", bulkDatagram, sendBulk},
	} {
		longest := longestWrittenBack(t, m, own)
		start := time.Now()
		err := transfer.move(own, transfer.size)
		took := time.Since(start)
		read, refused := longest()
		if err != nil {
			t.Errorf("%s %s of %d bytes to %s: %v, the longest read written back %d bytes, the counters reading %+v", layout, transfer.name, transfer.size, own, err, read, m.TransitCounters())
			continue
		}
		t.Logf("%s %s of %d bytes to %s took %s, the longest read written back %d bytes, %d reads past the trace's rate or queue", layout, transfer.name, transfer.size, own, took, read, refused)
	}
}

// longestWrittenBack traces the reads to own the mesh writes back until the returned function closes the trace
// which reports the longest of them and how many reads the trace refused
func longestWrittenBack(t *testing.T, m *Mesh, own netip.Addr) func() (int, uint64) {
	t.Helper()
	feed, err := m.Trace(TraceFilter{Destinations: []netip.Prefix{netip.PrefixFrom(own, own.BitLen())}, Decision: TraceDeliver}, 0, control.TraceRateMax)
	if err != nil {
		t.Fatal(err)
	}
	longest := make(chan int, 1)
	go func() {
		n := 0
		for {
			select {
			case record := <-feed.Records():
				n = max(n, record.Length)
			case <-feed.Done():
				for {
					select {
					case record := <-feed.Records():
						n = max(n, record.Length)
					default:
						longest <- n
						return
					}
				}
			}
		}
	}()
	return func() (int, uint64) {
		feed.Close()
		counts := feed.Counts()
		return <-longest, counts.RefusedRate + counts.RefusedQueue
	}
}

// echoBulk sends size bytes over a TCP connection to a listener on own, which echoes them, and reads them back
func echoBulk(own netip.Addr, size int) error {
	listener, err := listenOwn(own, func(at netip.AddrPort) (*net.TCPListener, error) {
		return net.ListenTCP("tcp", net.TCPAddrFromAddrPort(at))
	})
	if err != nil {
		return err
	}
	defer listener.Close()
	echoed := make(chan error, 1)
	go func() {
		if err := listener.SetDeadline(time.Now().Add(bulkTimeout)); err != nil {
			echoed <- err
			return
		}
		conn, err := listener.Accept()
		if err != nil {
			echoed <- err
			return
		}
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(bulkTimeout)); err != nil {
			echoed <- err
			return
		}
		_, err = io.CopyN(conn, conn, int64(size))
		echoed <- err
	}()
	conn, err := net.DialTimeout("tcp", listener.Addr().String(), deliveryTimeout)
	if err != nil {
		return errors.Join(err, <-echoed)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(bulkTimeout)); err != nil {
		return err
	}
	sent := bulkBytes(size)
	wrote := make(chan error, 1)
	go func() {
		_, err := conn.Write(sent)
		wrote <- err
	}()
	back := make([]byte, size)
	if _, err := io.ReadFull(conn, back); err != nil {
		return errors.Join(fmt.Errorf("the echo of %d bytes: %w", size, err), <-wrote, <-echoed)
	}
	if !bytes.Equal(back, sent) {
		return fmt.Errorf("the echo of %d bytes came back changed", size)
	}
	return errors.Join(<-wrote, <-echoed)
}

// sendBulk sends one datagram of size bytes from an unbound socket to a listener on own
func sendBulk(own netip.Addr, size int) error {
	server, err := listenOwn(own, func(at netip.AddrPort) (*net.UDPConn, error) {
		return net.ListenUDP("udp", net.UDPAddrFromAddrPort(at))
	})
	if err != nil {
		return err
	}
	defer server.Close()
	client, err := net.DialUDP("udp", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		return err
	}
	defer client.Close()
	sent := bulkBytes(size)
	if _, err := client.Write(sent); err != nil {
		return err
	}
	if err := server.SetReadDeadline(time.Now().Add(bulkTimeout)); err != nil {
		return err
	}
	got := make([]byte, size+1)
	n, err := server.Read(got)
	if err != nil {
		return fmt.Errorf("the datagram of %d bytes was not delivered: %w", size, err)
	}
	if !bytes.Equal(got[:n], sent) {
		return fmt.Errorf("the datagram of %d bytes arrived as %d bytes, or changed", size, n)
	}
	return nil
}

// bulkBytes is size bytes of a pattern with a prime period, so a segment out of place reads as changed
func bulkBytes(size int) []byte {
	out := make([]byte, size)
	for i := range out {
		out[i] = byte(i % 251)
	}
	return out
}

// sendUnbound sends one datagram to destination's port 9 from a socket the kernel picks the source of
func sendUnbound(destination netip.Addr) error {
	conn, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(destination, 9)))
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte("unheld"))
	return err
}
