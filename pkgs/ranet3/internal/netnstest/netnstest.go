// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

// Package netnstest holds what a root test needs to build a network of its own
// in network namespaces: a thread in a new and empty namespace, and the route
// netlink requests that make links, addresses and routes there. Test files
// import it and nothing else does.
package netnstest

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// VethPeer is VETH_INFO_PEER of linux/veth.h, which describes the other end of a new pair
const VethPeer = 1

// EnterEmpty moves the test's thread into a network namespace of its own and brings its loopback up
// and refuses to go on unless that namespace is new and held no route before
// the tun, the sockets and the capture a test opens on its own goroutine live there
// the thread stays locked
// and the runtime retires it with the test rather than run another goroutine in the namespace
func EnterEmpty(t testing.TB) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("creating a tun needs root on linux")
	}
	runtime.LockOSThread()
	if err := EnterEmptyNetwork(); err != nil {
		t.Fatal(err)
	}
}

// EnterEmptyNetwork moves the calling thread, which its caller locked, into a new network namespace and brings its loopback up
// and refuses to go on unless the namespace changed and holds no route
func EnterEmptyNetwork() error {
	var before, after unix.Stat_t
	if err := unix.Stat("/proc/thread-self/ns/net", &before); err != nil {
		return fmt.Errorf("stat this thread's network namespace: %w", err)
	}
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		return fmt.Errorf("unshare a network namespace: %w", err)
	}
	if err := unix.Stat("/proc/thread-self/ns/net", &after); err != nil {
		return fmt.Errorf("stat this thread's network namespace: %w", err)
	}
	if after.Ino == before.Ino {
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
	return BringUp("lo")
}

// BringUp sets the up flag of the link name, as netstack does for a tun it opens
func BringUp(name string) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open a socket to bring %s up: %w", name, err)
	}
	defer unix.Close(fd)
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return fmt.Errorf("read the flags of %s: %w", name, err)
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP)
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr); err != nil {
		return fmt.Errorf("bring %s up: %w", name, err)
	}
	return nil
}

// Thread runs functions on a thread of its own, in a network namespace of its own that held nothing, whose loopback is up
// the thread stays locked, and the runtime retires it and its hold on the namespace with the goroutine
type Thread struct {
	// Path opens the namespace from another thread
	Path string
	work chan func()
}

func StartThread(t testing.TB) *Thread {
	t.Helper()
	n := &Thread{work: make(chan func())}
	started := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		err := EnterEmptyNetwork()
		n.Path = fmt.Sprintf("/proc/%d/task/%d/ns/net", os.Getpid(), unix.Gettid())
		started <- err
		if err != nil {
			return
		}
		for f := range n.work {
			f()
		}
	}()
	if err := <-started; err != nil {
		t.Fatalf("start a thread in a network namespace of its own: %v", err)
	}
	t.Cleanup(func() { close(n.work) })
	return n
}

// Do runs f on the namespace's thread and returns what it returned
func (n *Thread) Do(f func() error) error {
	done := make(chan error, 1)
	n.work <- func() { done <- f() }
	return <-done
}

// Netlink is a route netlink socket in the network namespace of the thread that opened it
type Netlink int

func OpenNetlink() (Netlink, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return -1, fmt.Errorf("open route netlink: %w", err)
	}
	return Netlink(fd), nil
}

func (n Netlink) Close() { _ = unix.Close(int(n)) }

// Request sends one message and answers the error the kernel acknowledged it with
func (n Netlink) Request(kind, flags uint16, body []byte) error {
	return Acknowledged(int(n), Message(kind, flags|unix.NLM_F_ACK, body))
}

// Message is one netlink request of kind carrying body, with flags added
func Message(kind, flags uint16, body []byte) []byte {
	message := make([]byte, unix.NLMSG_HDRLEN, unix.NLMSG_HDRLEN+len(body))
	message = append(message, body...)
	binary.NativeEndian.PutUint32(message[0:], uint32(len(message)))
	binary.NativeEndian.PutUint16(message[4:], kind)
	binary.NativeEndian.PutUint16(message[6:], flags|unix.NLM_F_REQUEST)
	return message
}

// Acknowledged sends the messages in raw, one of them asking for an acknowledgment, on the netlink socket fd and answers the error the kernel acknowledged it with
func Acknowledged(fd int, raw []byte) error {
	if err := unix.Sendto(fd, raw, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	reply := make([]byte, os.Getpagesize())
	got, _, err := unix.Recvfrom(fd, reply, 0)
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

// AddAddress gives link index address without duplicate address detection, then brings the link up
func (n Netlink) AddAddress(index int, address netip.Prefix) error {
	family := byte(unix.AF_INET6)
	if address.Addr().Is4() {
		family = unix.AF_INET
	}
	header := []byte{family, byte(address.Bits()), unix.IFA_F_NODAD, unix.RT_SCOPE_UNIVERSE, 0, 0, 0, 0}
	binary.NativeEndian.PutUint32(header[4:], uint32(index))
	raw := address.Addr().AsSlice()
	if err := n.Request(unix.RTM_NEWADDR, unix.NLM_F_CREATE|unix.NLM_F_EXCL, slices.Concat(header, Attr(unix.IFA_LOCAL, raw), Attr(unix.IFA_ADDRESS, raw))); err != nil {
		return err
	}
	return n.Request(unix.RTM_NEWLINK, 0, IfInfo(index, unix.IFF_UP))
}

// RouteThrough routes the IPv6 prefix to over link index in the main table
func (n Netlink) RouteThrough(index int, to netip.Prefix) error {
	header := []byte{unix.AF_INET6, byte(to.Bits()), 0, 0, unix.RT_TABLE_MAIN, unix.RTPROT_BOOT, unix.RT_SCOPE_UNIVERSE, unix.RTN_UNICAST, 0, 0, 0, 0}
	body := slices.Concat(header, Attr(unix.RTA_DST, to.Addr().AsSlice()), Attr(unix.RTA_OIF, U32(uint32(index))))
	return n.Request(unix.RTM_NEWROUTE, unix.NLM_F_CREATE|unix.NLM_F_EXCL, body)
}

// SetLinkMTU sets the MTU of the link at index in the namespace of the calling thread
func SetLinkMTU(index, mtu int) error {
	netlink, err := OpenNetlink()
	if err != nil {
		return err
	}
	defer netlink.Close()
	return netlink.Request(unix.RTM_NEWLINK, 0, slices.Concat(IfInfo(index, 0), Attr(unix.IFLA_MTU, U32(uint32(mtu)))))
}

// IfInfo is an ifinfomsg for link index that sets flags and changes nothing else
func IfInfo(index int, flags uint32) []byte {
	message := make([]byte, unix.SizeofIfInfomsg)
	binary.NativeEndian.PutUint32(message[4:], uint32(index))
	binary.NativeEndian.PutUint32(message[8:], flags)
	binary.NativeEndian.PutUint32(message[12:], flags)
	return message
}

// Attr is one route netlink attribute of kind carrying value, padded to its alignment
func Attr(kind uint16, value []byte) []byte {
	length := unix.SizeofRtAttr + len(value)
	encoded := make([]byte, (length+unix.RTA_ALIGNTO-1)&^(unix.RTA_ALIGNTO-1))
	binary.NativeEndian.PutUint16(encoded[0:], uint16(length))
	binary.NativeEndian.PutUint16(encoded[2:], kind)
	copy(encoded[unix.SizeofRtAttr:], value)
	return encoded
}

func U32(value uint32) []byte { return binary.NativeEndian.AppendUint32(nil, value) }

func CString(value string) []byte { return append([]byte(value), 0) }
