// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package userspace

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/egress/userspace/raw"
)

// A queued error's sock_extended_err names its type, code and offender, and
// ee_info in the host's byte order, a too big's MTU. An error the kernel
// raised itself names none.
func TestExtendedErrorReadsItsInfo(t *testing.T) {
	router4, router6 := netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("2001:db8:2::1")
	// extended is a sock_extended_err and the offender's sockaddr_in or
	// sockaddr_in6 after it, of which the family and the address are written
	extended := func(origin, kind, code byte, info uint32, offender netip.Addr) []byte {
		size, family, at := unix.SizeofSockaddrInet4, uint16(unix.AF_INET), 4
		if offender.Is6() {
			size, family, at = unix.SizeofSockaddrInet6, unix.AF_INET6, 8
		}
		data := make([]byte, sockExtendedErr+size)
		data[4], data[5], data[6] = origin, kind, code
		binary.NativeEndian.PutUint32(data[8:12], info)
		binary.NativeEndian.PutUint16(data[sockExtendedErr:], family)
		copy(data[sockExtendedErr+at:], offender.AsSlice())
		return data
	}
	for _, c := range []struct {
		name string
		data []byte
		want icmpError
		ok   bool
	}{
		{"ipv4 too big", extended(unix.SO_EE_ORIGIN_ICMP, 3, 4, 1300, router4), icmpError{router4, 3, 4, 1300}, true},
		{"ipv6 too big", extended(unix.SO_EE_ORIGIN_ICMP6, 2, 0, 1280, router6), icmpError{router6, 2, 0, 1280}, true},
		{"local", extended(unix.SO_EE_ORIGIN_LOCAL, 0, 0, 1500, router4), icmpError{}, false},
	} {
		if got, ok := extendedError(c.data); got != c.want || ok != c.ok {
			t.Errorf("%s: read %+v %t, want %+v %t", c.name, got, ok, c.want, c.ok)
		}
	}
}

// A server's error about a leaf's datagram ends neither the mapping nor its
// socket toward the server (RFC 4787 REQ-12): a datagram to another server
// goes out from the same port after it. Over IPv6's loopback alone, the one
// address a test of no namespace holds, and loopback is a source the mesh
// refuses, so the error reaches the leaf as nothing, which the window below
// watches for. The exit's reader takes a socket's errors only under the
// destination's lock, so an error drawn while the test holds it stays on the
// socket, which shows it reached the exit, and is gone once the window ends,
// which shows the reader took it. The root test below has the error reach the
// leaf in both families.
func TestServersErrorFromLoopbackIsNotRelayedAndEndsNoMapping(t *testing.T) {
	server := netip.IPv6Loopback()
	live := loopbackServer(t, server)
	closed := netip.AddrPortFrom(server, freeUDPPort(t, server))
	h := newRelayHarness(t, nil)
	leaf := netip.AddrPortFrom(leaf6, freeUDPPort(t, leaf6))
	datagram := udpDatagram(leaf, closed, []byte("to a port no socket holds"))
	h.x.udp.take(datagram, false)
	_, dst := h.x.udp.opened(leaf, closed)
	if dst == nil {
		t.Fatal("no socket toward the server")
	}
	if !errorHeld(t, dst, []byte("again to a port no socket holds")) {
		t.Fatal("no error from loopback reached the exit's socket")
	}
	h.noneLaid(t, "an error from loopback", exitWait/10, func(raw []byte) bool {
		p, ok := parse(raw)
		return ok && p.protocol == protoICMPv6
	})
	if errorShows(t, dst.conn) {
		t.Error("the exit's reader left the error on its socket")
	}
	port, ok := h.mappingOf(leaf)
	if !ok {
		t.Fatal("the error ended the leaf's mapping")
	}
	if !destinationLive(h.x, leaf, closed) {
		t.Error("the error ended the mapping's socket toward the server")
	}
	h.x.udp.take(udpDatagram(leaf, serverAt(live), []byte("after the error")), false)
	if from := readDatagramFrom(t, live, []byte("after the error")); from.Port() != port {
		t.Errorf("the datagram after the error left from port %d, want the mapping's %d", from.Port(), port)
	}
}

// errorHeld reports whether an error shows on dst's socket within exitWait
// while the test holds dst.mu, under which alone the exit's reader takes the
// socket's errors: one queued already, else the one a write of payload draws.
// A write fails with the errno of an error the socket holds still, taking
// the errno the reader would have woken to, so a write after the lock draws
// one more error to wake it.
func errorHeld(t *testing.T, dst *destination, payload []byte) bool {
	t.Helper()
	held, took := func() (bool, bool) {
		dst.mu.Lock()
		defer dst.mu.Unlock()
		if errorShows(t, dst.conn) {
			return true, false
		}
		if _, err := dst.conn.Write(payload); err != nil {
			if !icmpErrno(err) {
				t.Fatal(err)
			}
			return errorShows(t, dst.conn), true
		}
		for deadline := time.Now().Add(exitWait); time.Now().Before(deadline); time.Sleep(layPoll) {
			if errorShows(t, dst.conn) {
				return true, false
			}
		}
		return false, false
	}()
	if took {
		if _, err := dst.conn.Write(payload); err != nil && !icmpErrno(err) {
			t.Fatal(err)
		}
	}
	return held
}

// errorShows is whether conn's socket holds an error no read has taken, as
// poll's POLLERR gives, which takes none
func errorShows(t *testing.T, conn *net.UDPConn) bool {
	t.Helper()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	fds := []unix.PollFd{{}}
	var polled error
	if err := raw.Control(func(fd uintptr) {
		fds[0].Fd = int32(fd)
		for {
			if _, polled = unix.Poll(fds, 0); polled != unix.EINTR {
				return
			}
		}
	}); err != nil || polled != nil {
		t.Fatalf("poll the socket: %v %v", err, polled)
	}
	return fds[0].Revents&unix.POLLERR != 0
}

// A server's port unreachable about a leaf's datagram reaches the leaf's own
// socket, whose kernel matches the quote to the datagram it sent and tells it
// of the error from the server with the payload it sent, in both families,
// at the host's TTL or hop limit. The mapping and its socket toward the server
// live on.
func TestServersErrorReachesTheLeafsSocket(t *testing.T) {
	r := newLeafRig(t, func(rt Runtime) (*Exit, error) { return New(exitConfig(), rt) })
	r.exit.SetHopLimits(hostTTL, hostHopLimit)
	for _, family := range rigFamilies {
		t.Run(family.name, func(t *testing.T) {
			kind, code := byte(3), byte(3)
			if family.leaf.Is6() {
				kind, code = 1, 4
			}
			laid := make(chan uint8, 1)
			back := func(raw []byte) {
				if p, ok := parse(raw); ok && p.protocol == icmpProtocol(family.leaf) && p.kind == kind {
					select {
					case laid <- hopsOf(raw):
					default:
					}
				}
			}
			r.back.Store(&back)
			defer r.back.Store(nil)
			closed := netip.AddrPortFrom(family.servers[0], freeUDPPort(t, family.servers[0]))
			leaf := r.leafSocket(t, netip.AddrPortFrom(family.leaf, 0), func(fd int) error { return watchErrors(fd, family.leaf.Is6()) })
			payload := []byte("to a port no socket holds")
			if _, err := leaf.WriteToUDPAddrPort(payload, closed); err != nil {
				t.Fatal(err)
			}
			told, quoted := waitTold(t, r, leaf)
			if want := (icmpError{offender: closed.Addr(), kind: kind, code: code}); told != want || !bytes.Equal(quoted, payload) {
				t.Errorf("the leaf was told of %+v quoting %q, want %+v quoting %q", told, quoted, want, payload)
			}
			select {
			case got := <-laid:
				if got != hostHops(family.leaf) {
					t.Errorf("laid the error at %d, want the host's %d", got, hostHops(family.leaf))
				}
			default:
				t.Error("laid no error toward the leaf")
			}
			if !destinationLive(r.exit, serverAt(leaf), closed) {
				t.Error("the error ended the leaf's mapping or its socket toward the server")
			}
		})
	}
}

// Every error a server raises about a destination's datagram reaches the
// leaf's own socket, whose kernel takes the quote the exit builds where the
// datagrams differed, with the payload the leaf sent: port unreachables about
// each of four datagrams of three sizes to a closed port, and about a
// datagram after 17 to a server that then went away. With the host's errors
// carrying RFC 5837's interface information in an RFC 4884 extension, the
// payload the leaf is told of is still its own, no padding or extension
// after it.
func TestEveryErrorOfADestinationReachesTheLeafsSocket(t *testing.T) {
	r := newLeafRig(t, func(rt Runtime) (*Exit, error) { return New(exitConfig(), rt) })
	for _, extension := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "extension"}[extension], func(t *testing.T) {
			if extension {
				for _, path := range []string{"/proc/sys/net/ipv4/icmp_errors_extension_mask", "/proc/sys/net/ipv6/icmp/errors_extension_mask"} {
					if err := os.WriteFile(path, []byte("1\n"), 0o644); err != nil {
						t.Skipf("set %s: %v", path, err)
					}
					t.Cleanup(func() { _ = os.WriteFile(path, []byte("0\n"), 0o644) })
				}
			}
			for _, family := range rigFamilies {
				t.Run(family.name, func(t *testing.T) {
					told := func(leaf *net.UDPConn, to netip.AddrPort, payload []byte) {
						t.Helper()
						if _, err := leaf.WriteToUDPAddrPort(payload, to); err != nil {
							t.Fatal(err)
						}
						if e, quoted := waitTold(t, r, leaf); e.offender != to.Addr() || !bytes.Equal(quoted, payload) {
							t.Errorf("the leaf was told of %+v quoting %x, want an error from %s quoting %x", e, quoted, to.Addr(), payload)
						}
					}
					watch := func(fd int) error { return watchErrors(fd, family.leaf.Is6()) }
					closed := netip.AddrPortFrom(family.servers[0], freeUDPPort(t, family.servers[0]))
					leaf := r.leafSocket(t, netip.AddrPortFrom(family.leaf, 0), watch)
					for _, payload := range [][]byte{bytes.Repeat([]byte{0x11}, 25), bytes.Repeat([]byte{0x22}, 10), bytes.Repeat([]byte{0x33}, 40), bytes.Repeat([]byte{0x44}, 40)} {
						told(leaf, closed, payload)
					}
					server := r.server(t, family.servers[1])
					flow := r.leafSocket(t, netip.AddrPortFrom(family.leaf, 0), watch)
					for i := range 17 {
						payload := []byte{byte(i), 0x55, 0x55, 0x55}
						if _, err := flow.WriteToUDPAddrPort(payload, serverAt(server)); err != nil {
							t.Fatal(err)
						}
						readDatagramFrom(t, server, payload)
					}
					at := serverAt(server)
					_ = server.Close()
					told(flow, at, []byte{0x66, 0x66, 0x66, 0x66})
				})
			}
		})
	}
}

// waitTold is the first ICMP error conn's error queue holds within exitWait,
// and the payload it quoted
func waitTold(t *testing.T, r *leafRig, conn *net.UDPConn) (icmpError, []byte) {
	t.Helper()
	var told []icmpError
	var quoted [][]byte
	waitFor(t, "an error queued on "+serverAt(conn).String(), func() bool {
		_ = onSocket(conn, func(fd int) error {
			drainErrors(fd, make([]byte, 2048), func(e icmpError, prefix []byte, _ bool) {
				told, quoted = append(told, e), append(quoted, bytes.Clone(prefix))
			})
			return nil
		})
		return len(told) != 0
	})
	return told[0], quoted[0]
}

// A leaf's port unreachable about a datagram its mapping delivered reaches
// the datagram's server through the raw socket, from the address the mapping
// sends to the server from, quoting the server's datagram, so the server's
// own socket is told of it with that offender and the payload it sent (RFC
// 5508 REQ-5). The mapping lives on.
func TestLeafErrorReachesTheServerThroughRaw(t *testing.T) {
	r := newLeafRig(t, func(rt Runtime) (*Exit, error) {
		sockets, err := raw.New()
		if err != nil {
			return nil, err
		}
		rt.Platform.Raw = sockets
		return New(exitConfig(), rt)
	})
	for _, family := range rigFamilies {
		t.Run(family.name, func(t *testing.T) {
			kind, code := byte(3), byte(3)
			if family.leaf.Is6() {
				kind, code = 1, 4
			}
			server := r.server(t, family.servers[0])
			if err := onSocket(server, func(fd int) error { return watchErrors(fd, family.leaf.Is6()) }); err != nil {
				t.Fatal(err)
			}
			leaf := r.leafSocket(t, netip.AddrPortFrom(family.leaf, 0), nil)
			local := serverAt(leaf)
			if _, err := leaf.WriteToUDPAddrPort([]byte("request"), serverAt(server)); err != nil {
				t.Fatal(err)
			}
			outside := readDatagramFrom(t, server, []byte("request"))
			_ = leaf.Close()
			reply := []byte("to a port the leaf closed")
			if _, err := server.WriteToUDPAddrPort(reply, outside); err != nil {
				t.Fatal(err)
			}
			told, quoted := waitTold(t, r, server)
			if want := (icmpError{offender: outside.Addr(), kind: kind, code: code}); told != want || !bytes.Equal(quoted, reply) {
				t.Errorf("the server was told of %+v quoting %q, want %+v quoting %q", told, quoted, want, reply)
			}
			if !destinationLive(r.exit, local, serverAt(server)) {
				t.Errorf("the leaf's error ended the mapping of %s or its socket toward the server", local)
			}
		})
	}
}
