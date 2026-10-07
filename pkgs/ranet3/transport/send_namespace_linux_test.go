// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package transport

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// vethInfoPeer is VETH_INFO_PEER of linux/veth.h, which describes the other end of a new pair
const vethInfoPeer = 1

// lockedPathMTU is the path MTU to the far end, which path MTU discovery cannot change
// 1400-byte segments exceed it
// while single datagrams of that size cross it in fragments
const lockedPathMTU = 1280

// linux refuses a segmented send whose segments exceed a locked path MTU
// with EMSGSIZE, or with EINVAL on older kernels
// the bind then sends the batch one datagram to a message
// every datagram reaches the peer, and segmentation stops for that peer once
// the peer listens at the far end of a veth pair, in a network namespace of its own
func TestKernelRefusesSegmentsALockedPathCannotCarry(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("building a veth pair needs root on linux")
	}
	runtime.LockOSThread()
	if err := unshareEmptyNamespace(); err != nil {
		t.Fatal(err)
	}
	near, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open this namespace: %v", err)
	}
	opened := make(chan farEnd, 1)
	go func() { opened <- openFarEnd(near) }()
	far := <-opened
	_ = unix.Close(near)
	if far.err != nil {
		t.Fatal(far.err)
	}
	for _, listener := range far.listeners {
		t.Cleanup(func() { _ = listener.Close() })
	}
	link, err := net.InterfaceByName("near")
	if err != nil {
		t.Fatalf("look up the near end: %v", err)
	}
	netlink, err := openRouteNetlink()
	if err != nil {
		t.Fatal(err)
	}
	defer netlink.close()
	if err := netlink.configure(link.Index, nearAddresses); err != nil {
		t.Fatalf("configure the near end: %v", err)
	}
	for _, address := range farAddresses {
		if err := netlink.lockPathMTU(link.Index, address.Addr(), lockedPathMTU); err != nil {
			t.Fatalf("lock the path MTU to %s: %v", address.Addr(), err)
		}
	}

	events := &eventLog{}
	bind, _, _, err := listenPacketBind(0, 0, events.record)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bind.Close() })
	var seen []string
	for i, address := range farAddresses {
		listener := far.listeners[i]
		ep := dialed(netip.AddrPortFrom(address.Addr(), uint16(listener.LocalAddr().(*net.UDPAddr).Port)).String())
		for range 2 {
			if err := bind.Send(numbered(8, 1400), ep); err != nil {
				t.Fatalf("a batch whose single datagrams the path carries failed: %v", err)
			}
			if got := readNumbered(t, listener, 8); !slices.Equal(got, sequence(8)) {
				t.Fatalf("%s received %v, want each datagram once", address.Addr(), got)
			}
		}
		got := events.recorded()
		if len(got) != len(seen)+1 {
			t.Fatalf("two batches to %s recorded %q, want one stop", ep, got[len(seen):])
		}
		errno, ok := strings.CutPrefix(got[len(seen)], fmt.Sprintf("transport.endpoint.unsegmented endpoint=%s errno=", ep))
		if !ok || (errno != "EMSGSIZE" && errno != "EINVAL") {
			t.Fatalf("the batch to %s recorded %q, want segmentation stopped for a segment the path refused", ep, got[len(seen)])
		}
		t.Logf("linux refused the segments to %s with %s", address.Addr(), errno)
		seen = got
	}
}

// the near end's addresses, then the far end's, one of each family on the same prefixes
var (
	nearAddresses = []netip.Prefix{netip.MustParsePrefix("192.0.2.1/24"), netip.MustParsePrefix("2001:db8::1/64")}
	farAddresses  = []netip.Prefix{netip.MustParsePrefix("192.0.2.2/24"), netip.MustParsePrefix("2001:db8::2/64")}
)

// readNumbered reads count datagrams from listener and returns the numbers they carry in ascending order
func readNumbered(t *testing.T, listener *net.UDPConn, count int) []uint32 {
	t.Helper()
	if err := listener.SetReadDeadline(time.Now().Add(arrivalBudget)); err != nil {
		t.Fatal(err)
	}
	numbers := make([]uint32, 0, count)
	buf := make([]byte, 2048)
	for range count {
		n, err := listener.Read(buf)
		if err != nil {
			t.Fatalf("%d of %d datagrams arrived: %v", len(numbers), count, err)
		}
		if n != 1400 {
			t.Fatalf("a datagram arrived as %d bytes, want 1400", n)
		}
		numbers = append(numbers, binary.BigEndian.Uint32(buf))
	}
	slices.Sort(numbers)
	return numbers
}

// farEnd is the peer's half of the veth pair, listening in a network namespace of its own
type farEnd struct {
	// listeners hold one socket of each family, in the order of farAddresses
	listeners []*net.UDPConn
	err       error
}

// openFarEnd makes the veth pair in a network namespace of its own and hands the near end to the namespace near names
// it locks its thread and never unlocks it, and the runtime retires the thread with the goroutine
// nothing else runs in the namespace, which lives on in the listeners' sockets
func openFarEnd(near int) farEnd {
	runtime.LockOSThread()
	if err := unshareEmptyNamespace(); err != nil {
		return farEnd{err: err}
	}
	netlink, err := openRouteNetlink()
	if err != nil {
		return farEnd{err: err}
	}
	defer netlink.close()
	peer := slices.Concat(linkMessage(0, 0), attribute(unix.IFLA_IFNAME, cString("near")), attribute(unix.IFLA_NET_NS_FD, word(uint32(near))))
	kind := slices.Concat(attribute(unix.IFLA_INFO_KIND, cString("veth")), attribute(unix.IFLA_INFO_DATA, attribute(vethInfoPeer, peer)))
	pair := slices.Concat(linkMessage(0, 0), attribute(unix.IFLA_IFNAME, cString("far")), attribute(unix.IFLA_LINKINFO, kind))
	if err := netlink.request(unix.RTM_NEWLINK, unix.NLM_F_CREATE|unix.NLM_F_EXCL, pair); err != nil {
		return farEnd{err: fmt.Errorf("make the veth pair: %w", err)}
	}
	link, err := net.InterfaceByName("far")
	if err != nil {
		return farEnd{err: fmt.Errorf("look up the far end: %w", err)}
	}
	if err := netlink.configure(link.Index, farAddresses); err != nil {
		return farEnd{err: fmt.Errorf("configure the far end: %w", err)}
	}
	var end farEnd
	for _, network := range []string{"udp4", "udp6"} {
		listener, err := net.ListenUDP(network, &net.UDPAddr{})
		if err != nil {
			for _, open := range end.listeners {
				_ = open.Close()
			}
			return farEnd{err: fmt.Errorf("listen on the far end: %w", err)}
		}
		end.listeners = append(end.listeners, listener)
	}
	return end
}

// unshareEmptyNamespace moves the calling thread, which its caller locked, into a new network namespace
// and refuses to go on unless the namespace changed and holds no route
func unshareEmptyNamespace() error {
	before, err := namespaceOf()
	if err != nil {
		return err
	}
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		return fmt.Errorf("unshare a network namespace: %w", err)
	}
	after, err := namespaceOf()
	if err != nil {
		return err
	}
	if after == before {
		return errors.New("refusing to continue: the network namespace did not change")
	}
	rib, err := syscall.NetlinkRIB(syscall.RTM_GETROUTE, syscall.AF_UNSPEC)
	if err != nil {
		return fmt.Errorf("dump the routes of the new namespace: %w", err)
	}
	messages, err := syscall.ParseNetlinkMessage(rib)
	if err != nil {
		return fmt.Errorf("parse the route dump: %w", err)
	}
	for _, message := range messages {
		if message.Header.Type == syscall.RTM_NEWROUTE {
			return errors.New("refusing to continue: this network namespace already holds routes")
		}
	}
	return nil
}

// namespaceOf is the inode of the calling thread's network namespace
func namespaceOf() (uint64, error) {
	var st unix.Stat_t
	if err := unix.Stat("/proc/thread-self/ns/net", &st); err != nil {
		return 0, fmt.Errorf("stat this thread's network namespace: %w", err)
	}
	return st.Ino, nil
}

// routeNetlink is a route netlink socket in the network namespace of the thread that opened it
type routeNetlink int

func openRouteNetlink() (routeNetlink, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return -1, fmt.Errorf("open route netlink: %w", err)
	}
	return routeNetlink(fd), nil
}

func (n routeNetlink) close() { _ = unix.Close(int(n)) }

// request sends one message and answers the error the kernel acknowledged it with
func (n routeNetlink) request(kind, flags uint16, body []byte) error {
	message := make([]byte, unix.NLMSG_HDRLEN, unix.NLMSG_HDRLEN+len(body))
	message = append(message, body...)
	binary.NativeEndian.PutUint32(message[0:], uint32(len(message)))
	binary.NativeEndian.PutUint16(message[4:], kind)
	binary.NativeEndian.PutUint16(message[6:], flags|unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	if err := unix.Sendto(int(n), message, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	reply := make([]byte, os.Getpagesize())
	got, _, err := unix.Recvfrom(int(n), reply, 0)
	if err != nil {
		return err
	}
	messages, err := syscall.ParseNetlinkMessage(reply[:got])
	if err != nil {
		return err
	}
	if len(messages) != 1 || messages[0].Header.Type != unix.NLMSG_ERROR || len(messages[0].Data) < 4 {
		return errors.New("the kernel answered with something other than an acknowledgment")
	}
	if errno := -int32(binary.NativeEndian.Uint32(messages[0].Data)); errno != 0 {
		return unix.Errno(errno)
	}
	return nil
}

// configure gives link index its addresses without duplicate address detection, then brings it up
func (n routeNetlink) configure(index int, addresses []netip.Prefix) error {
	for _, address := range addresses {
		header := []byte{addressFamily(address.Addr()), byte(address.Bits()), unix.IFA_F_NODAD, unix.RT_SCOPE_UNIVERSE, 0, 0, 0, 0}
		binary.NativeEndian.PutUint32(header[4:], uint32(index))
		raw := address.Addr().AsSlice()
		body := slices.Concat(header, attribute(unix.IFA_LOCAL, raw), attribute(unix.IFA_ADDRESS, raw))
		if err := n.request(unix.RTM_NEWADDR, unix.NLM_F_CREATE|unix.NLM_F_EXCL, body); err != nil {
			return fmt.Errorf("add %s: %w", address, err)
		}
	}
	return n.request(unix.RTM_NEWLINK, 0, linkMessage(index, unix.IFF_UP))
}

// lockPathMTU routes to an address over link index with a path MTU that path MTU discovery cannot change
func (n routeNetlink) lockPathMTU(index int, to netip.Addr, mtu int) error {
	scope := byte(unix.RT_SCOPE_UNIVERSE)
	if to.Is4() {
		scope = unix.RT_SCOPE_LINK
	}
	header := []byte{addressFamily(to), byte(to.BitLen()), 0, 0, unix.RT_TABLE_MAIN, unix.RTPROT_BOOT, scope, unix.RTN_UNICAST, 0, 0, 0, 0}
	metrics := slices.Concat(attribute(unix.RTAX_MTU, word(uint32(mtu))), attribute(unix.RTAX_LOCK, word(1<<unix.RTAX_MTU)))
	body := slices.Concat(header, attribute(unix.RTA_DST, to.AsSlice()), attribute(unix.RTA_OIF, word(uint32(index))),
		attribute(unix.RTA_METRICS, metrics))
	return n.request(unix.RTM_NEWROUTE, unix.NLM_F_CREATE|unix.NLM_F_EXCL, body)
}

// linkMessage is an ifinfomsg for link index that sets flags and changes nothing else
func linkMessage(index int, flags uint32) []byte {
	message := make([]byte, unix.SizeofIfInfomsg)
	binary.NativeEndian.PutUint32(message[4:], uint32(index))
	binary.NativeEndian.PutUint32(message[8:], flags)
	binary.NativeEndian.PutUint32(message[12:], flags)
	return message
}

func attribute(kind uint16, value []byte) []byte {
	length := unix.SizeofRtAttr + len(value)
	encoded := make([]byte, (length+unix.RTA_ALIGNTO-1)&^(unix.RTA_ALIGNTO-1))
	binary.NativeEndian.PutUint16(encoded[0:], uint16(length))
	binary.NativeEndian.PutUint16(encoded[2:], kind)
	copy(encoded[unix.SizeofRtAttr:], value)
	return encoded
}

func word(value uint32) []byte { return binary.NativeEndian.AppendUint32(nil, value) }

func cString(value string) []byte { return append([]byte(value), 0) }

func addressFamily(address netip.Addr) byte {
	if address.Is4() {
		return unix.AF_INET
	}
	return unix.AF_INET6
}
