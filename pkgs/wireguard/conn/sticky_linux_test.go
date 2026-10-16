//go:build linux && !android

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func setSrc(ep *StdNetEndpoint, addr netip.Addr, ifidx int32) {
	var buf []byte
	if addr.Is4() {
		buf = make([]byte, unix.CmsgSpace(unix.SizeofInet4Pktinfo))
		hdr := unix.Cmsghdr{
			Level: unix.IPPROTO_IP,
			Type:  unix.IP_PKTINFO,
		}
		hdr.SetLen(unix.CmsgLen(unix.SizeofInet4Pktinfo))
		copy(buf, unsafe.Slice((*byte)(unsafe.Pointer(&hdr)), int(unsafe.Sizeof(hdr))))

		info := unix.Inet4Pktinfo{
			Ifindex:  ifidx,
			Spec_dst: addr.As4(),
		}
		copy(buf[unix.CmsgLen(0):], unsafe.Slice((*byte)(unsafe.Pointer(&info)), unix.SizeofInet4Pktinfo))
	} else {
		buf = make([]byte, unix.CmsgSpace(unix.SizeofInet6Pktinfo))
		hdr := unix.Cmsghdr{
			Level: unix.IPPROTO_IPV6,
			Type:  unix.IPV6_PKTINFO,
		}
		hdr.SetLen(unix.CmsgLen(unix.SizeofInet6Pktinfo))
		copy(buf, unsafe.Slice((*byte)(unsafe.Pointer(&hdr)), int(unsafe.Sizeof(hdr))))

		info := unix.Inet6Pktinfo{
			Ifindex: uint32(ifidx),
			Addr:    addr.As16(),
		}
		copy(buf[unix.CmsgLen(0):], unsafe.Slice((*byte)(unsafe.Pointer(&info)), unix.SizeofInet6Pktinfo))
	}

	ep.src = buf
}

func Test_setSrcControl(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		ep := &StdNetEndpoint{
			AddrPort: netip.MustParseAddrPort("127.0.0.1:1234"),
		}
		setSrc(ep, netip.MustParseAddr("127.0.0.1"), 5)

		control := make([]byte, stickyControlSize)

		setSrcControl(&control, ep)

		hdr := (*unix.Cmsghdr)(unsafe.Pointer(&control[0]))
		if hdr.Level != unix.IPPROTO_IP {
			t.Errorf("unexpected level: %d", hdr.Level)
		}
		if hdr.Type != unix.IP_PKTINFO {
			t.Errorf("unexpected type: %d", hdr.Type)
		}
		if uint(hdr.Len) != uint(unix.CmsgLen(int(unsafe.Sizeof(unix.Inet4Pktinfo{})))) {
			t.Errorf("unexpected length: %d", hdr.Len)
		}
		info := (*unix.Inet4Pktinfo)(unsafe.Pointer(&control[unix.CmsgLen(0)]))
		if info.Spec_dst[0] != 127 || info.Spec_dst[1] != 0 || info.Spec_dst[2] != 0 || info.Spec_dst[3] != 1 {
			t.Errorf("unexpected address: %v", info.Spec_dst)
		}
		if info.Ifindex != 5 {
			t.Errorf("unexpected ifindex: %d", info.Ifindex)
		}
	})

	t.Run("IPv6", func(t *testing.T) {
		ep := &StdNetEndpoint{
			AddrPort: netip.MustParseAddrPort("[::1]:1234"),
		}
		setSrc(ep, netip.MustParseAddr("::1"), 5)

		control := make([]byte, stickyControlSize)

		setSrcControl(&control, ep)

		hdr := (*unix.Cmsghdr)(unsafe.Pointer(&control[0]))
		if hdr.Level != unix.IPPROTO_IPV6 {
			t.Errorf("unexpected level: %d", hdr.Level)
		}
		if hdr.Type != unix.IPV6_PKTINFO {
			t.Errorf("unexpected type: %d", hdr.Type)
		}
		if uint(hdr.Len) != uint(unix.CmsgLen(int(unsafe.Sizeof(unix.Inet6Pktinfo{})))) {
			t.Errorf("unexpected length: %d", hdr.Len)
		}
		info := (*unix.Inet6Pktinfo)(unsafe.Pointer(&control[unix.CmsgLen(0)]))
		if info.Addr != ep.SrcIP().As16() {
			t.Errorf("unexpected address: %v", info.Addr)
		}
		if info.Ifindex != 5 {
			t.Errorf("unexpected ifindex: %d", info.Ifindex)
		}
	})

	t.Run("ClearOnNoSrc", func(t *testing.T) {
		control := make([]byte, stickyControlSize)
		hdr := (*unix.Cmsghdr)(unsafe.Pointer(&control[0]))
		hdr.Level = 1
		hdr.Type = 2
		hdr.Len = 3

		setSrcControl(&control, &StdNetEndpoint{})

		if len(control) != 0 {
			t.Errorf("unexpected control: %v", control)
		}
	})
}

func Test_getSrcFromControl(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		control := make([]byte, stickyControlSize)
		hdr := (*unix.Cmsghdr)(unsafe.Pointer(&control[0]))
		hdr.Level = unix.IPPROTO_IP
		hdr.Type = unix.IP_PKTINFO
		hdr.SetLen(unix.CmsgLen(int(unsafe.Sizeof(unix.Inet4Pktinfo{}))))
		info := (*unix.Inet4Pktinfo)(unsafe.Pointer(&control[unix.CmsgLen(0)]))
		info.Spec_dst = [4]byte{127, 0, 0, 1}
		info.Ifindex = 5

		ep := &StdNetEndpoint{}
		getSrcFromControl(control, ep)

		if ep.SrcIP() != netip.MustParseAddr("127.0.0.1") {
			t.Errorf("unexpected address: %v", ep.SrcIP())
		}
		if ep.SrcIfidx() != 5 {
			t.Errorf("unexpected ifindex: %d", ep.SrcIfidx())
		}
	})
	t.Run("IPv6", func(t *testing.T) {
		control := make([]byte, stickyControlSize)
		hdr := (*unix.Cmsghdr)(unsafe.Pointer(&control[0]))
		hdr.Level = unix.IPPROTO_IPV6
		hdr.Type = unix.IPV6_PKTINFO
		hdr.SetLen(unix.CmsgLen(int(unsafe.Sizeof(unix.Inet6Pktinfo{}))))
		info := (*unix.Inet6Pktinfo)(unsafe.Pointer(&control[unix.CmsgLen(0)]))
		info.Addr = [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
		info.Ifindex = 5

		ep := &StdNetEndpoint{}
		getSrcFromControl(control, ep)

		if ep.SrcIP() != netip.MustParseAddr("::1") {
			t.Errorf("unexpected address: %v", ep.SrcIP())
		}
		if ep.SrcIfidx() != 5 {
			t.Errorf("unexpected ifindex: %d", ep.SrcIfidx())
		}
	})
	t.Run("ClearOnEmpty", func(t *testing.T) {
		var control []byte
		ep := &StdNetEndpoint{}
		setSrc(ep, netip.MustParseAddr("::1"), 5)

		getSrcFromControl(control, ep)
		if ep.SrcIP().IsValid() {
			t.Errorf("unexpected address: %v", ep.SrcIP())
		}
		if ep.SrcIfidx() != 0 {
			t.Errorf("unexpected ifindex: %d", ep.SrcIfidx())
		}
	})
	t.Run("Multiple", func(t *testing.T) {
		zeroControl := make([]byte, unix.CmsgSpace(0))
		zeroHdr := (*unix.Cmsghdr)(unsafe.Pointer(&zeroControl[0]))
		zeroHdr.SetLen(unix.CmsgLen(0))

		control := make([]byte, unix.CmsgSpace(unix.SizeofInet4Pktinfo))
		hdr := (*unix.Cmsghdr)(unsafe.Pointer(&control[0]))
		hdr.Level = unix.IPPROTO_IP
		hdr.Type = unix.IP_PKTINFO
		hdr.SetLen(unix.CmsgLen(int(unsafe.Sizeof(unix.Inet4Pktinfo{}))))
		info := (*unix.Inet4Pktinfo)(unsafe.Pointer(&control[unix.CmsgLen(0)]))
		info.Spec_dst = [4]byte{127, 0, 0, 1}
		info.Ifindex = 5

		combined := make([]byte, 0)
		combined = append(combined, zeroControl...)
		combined = append(combined, control...)

		ep := &StdNetEndpoint{}
		getSrcFromControl(combined, ep)

		if ep.SrcIP() != netip.MustParseAddr("127.0.0.1") {
			t.Errorf("unexpected address: %v", ep.SrcIP())
		}
		if ep.SrcIfidx() != 5 {
			t.Errorf("unexpected ifindex: %d", ep.SrcIfidx())
		}
	})
}

func Test_listenConfig(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		conn, err := listenConfig().ListenPacket(context.Background(), "udp4", ":0")
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		sc, err := conn.(*net.UDPConn).SyscallConn()
		if err != nil {
			t.Fatal(err)
		}

		if runtime.GOOS == "linux" {
			var i int
			sc.Control(func(fd uintptr) {
				i, err = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_PKTINFO)
			})
			if err != nil {
				t.Fatal(err)
			}
			if i != 1 {
				t.Error("IP_PKTINFO not set!")
			}
		} else {
			t.Logf("listenConfig() does not set IPV6_RECVPKTINFO on %s", runtime.GOOS)
		}
	})
	t.Run("IPv6", func(t *testing.T) {
		conn, err := listenConfig().ListenPacket(context.Background(), "udp6", ":0")
		if err != nil {
			t.Fatal(err)
		}
		sc, err := conn.(*net.UDPConn).SyscallConn()
		if err != nil {
			t.Fatal(err)
		}

		if runtime.GOOS == "linux" {
			var i int
			sc.Control(func(fd uintptr) {
				i, err = unix.GetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVPKTINFO)
			})
			if err != nil {
				t.Fatal(err)
			}
			if i != 1 {
				t.Error("IPV6_PKTINFO not set!")
			}
		} else {
			t.Logf("listenConfig() does not set IPV6_RECVPKTINFO on %s", runtime.GOOS)
		}
	})
}

// TestStdNetBindSendRetryWithoutGSO checks that when the kernel refuses a
// UDP_SEGMENT send with EIO, the retry without GSO sends every datagram on its
// own, not again behind the datagram it was coalesced into. udp_send_skb()
// refuses UDP_SEGMENT with EIO on a route an xfrm policy covers, so the test
// sends over loopback through a null-cipher ESP SA, in a network namespace of
// its own.
func TestStdNetBindSendRetryWithoutGSO(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("needs root to create a network namespace")
	}
	enterEmptyNetNS(t)

	recv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer recv.Close()
	port := recv.LocalAddr().(*net.UDPAddr).Port
	addNullESPTransport(t, netip.MustParseAddr("127.0.0.1"), uint16(port))

	bind := NewStdNetBind().(*StdNetBind)
	if _, _, err := bind.Open(0); err != nil {
		t.Fatal(err)
	}
	defer bind.Close()
	if !bind.ipv4TxOffload {
		t.Fatal("UDP_SEGMENT is unavailable")
	}
	ep, err := bind.ParseEndpoint(fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}

	const (
		offset = 8
		size   = 100
		count  = 3
	)
	bufs := make([][]byte, count)
	for i := range bufs {
		bufs[i] = bytes.Repeat([]byte{byte(i + 1)}, offset+size)
	}
	err = bind.Send(bufs, ep, offset)
	var gsoErr ErrUDPGSODisabled
	if !errors.As(err, &gsoErr) {
		t.Fatalf("Send() = %v, want ErrUDPGSODisabled", err)
	}
	if gsoErr.RetryErr != nil {
		t.Fatalf("retry without GSO failed: %v", gsoErr.RetryErr)
	}

	recv.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, maxDatagramSize)
	for i := range bufs {
		n, err := recv.Read(got)
		if err != nil {
			t.Fatalf("datagram %d: %v", i, err)
		}
		if !bytes.Equal(got[:n], bufs[i][offset:]) {
			t.Fatalf("datagram %d has %d bytes starting with %d, want %d bytes of %d", i, n, got[0], size, i+1)
		}
	}
}

// enterEmptyNetNS moves the calling goroutine, locked to its thread for the
// rest of the test, into a new network namespace, and fails unless that
// namespace holds nothing but a loopback interface that is down. It then
// brings loopback up with xfrm allowed on it, which the kernel disables on
// loopback by default.
func enterEmptyNetNS(t *testing.T) {
	t.Helper()
	// The thread stays locked when the test returns, so the runtime discards
	// it with the namespace.
	runtime.LockOSThread()
	before, err := netNSInode()
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		t.Fatalf("failed to create a network namespace: %v", err)
	}
	after, err := netNSInode()
	if err != nil {
		t.Fatal(err)
	}
	if after == before {
		t.Fatal("refusing to run: the network namespace did not change")
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	if len(ifaces) != 1 || ifaces[0].Flags&net.FlagLoopback == 0 || ifaces[0].Flags&net.FlagUp != 0 {
		t.Fatalf("refusing to run: the new network namespace is not empty: %v", ifaces)
	}
	lo := ifaces[0].Name

	if err := os.WriteFile("/proc/sys/net/ipv4/conf/"+lo+"/disable_xfrm", []byte("0"), 0); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	ifr, err := unix.NewIfreq(lo)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		t.Fatal(err)
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP)
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr); err != nil {
		t.Fatal(err)
	}
}

func netNSInode() (uint64, error) {
	var st unix.Stat_t
	if err := unix.Stat("/proc/thread-self/ns/net", &st); err != nil {
		return 0, err
	}
	return st.Ino, nil
}

// The definitions below follow include/uapi/linux/xfrm.h, which x/sys/unix
// does not carry.
const (
	xfrmMsgNewSA      = 0x10
	xfrmMsgNewPolicy  = 0x13
	xfrmaAlgCrypt     = 2
	xfrmaTmpl         = 5
	xfrmPolicyOut     = 1
	xfrmModeTransport = 0
	xfrmInf           = ^uint64(0)
)

type xfrmSelector struct {
	Daddr      [16]byte
	Saddr      [16]byte
	Dport      [2]byte
	DportMask  [2]byte
	Sport      [2]byte
	SportMask  [2]byte
	Family     uint16
	PrefixlenD uint8
	PrefixlenS uint8
	Proto      uint8
	_          [3]byte
	Ifindex    int32
	User       uint32
}

type xfrmID struct {
	Daddr [16]byte
	SPI   [4]byte
	Proto uint8
	_     [3]byte
}

type xfrmLifetimeCfg struct {
	SoftByteLimit         uint64
	HardByteLimit         uint64
	SoftPacketLimit       uint64
	HardPacketLimit       uint64
	SoftAddExpiresSeconds uint64
	HardAddExpiresSeconds uint64
	SoftUseExpiresSeconds uint64
	HardUseExpiresSeconds uint64
}

type xfrmLifetimeCur struct {
	Bytes   uint64
	Packets uint64
	AddTime uint64
	UseTime uint64
}

type xfrmUsersaInfo struct {
	Sel          xfrmSelector
	ID           xfrmID
	Saddr        [16]byte
	Lft          xfrmLifetimeCfg
	Curlft       xfrmLifetimeCur
	Stats        [3]uint32
	Seq          uint32
	Reqid        uint32
	Family       uint16
	Mode         uint8
	ReplayWindow uint8
	Flags        uint8
	_            [7]byte
}

type xfrmUserpolicyInfo struct {
	Sel      xfrmSelector
	Lft      xfrmLifetimeCfg
	Curlft   xfrmLifetimeCur
	Priority uint32
	Index    uint32
	Dir      uint8
	Action   uint8
	Flags    uint8
	Share    uint8
	_        [4]byte
}

type xfrmUserTmpl struct {
	ID       xfrmID
	Family   uint16
	_        [2]byte
	Saddr    [16]byte
	Reqid    uint32
	Mode     uint8
	Share    uint8
	Optional uint8
	_        uint8
	Aalgos   uint32
	Ealgos   uint32
	Calgos   uint32
}

type xfrmAlgo struct {
	Name   [64]byte
	KeyLen uint32
}

func infiniteLifetime() xfrmLifetimeCfg {
	return xfrmLifetimeCfg{
		SoftByteLimit:   xfrmInf,
		HardByteLimit:   xfrmInf,
		SoftPacketLimit: xfrmInf,
		HardPacketLimit: xfrmInf,
	}
}

func asBytes[T any](v *T) []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(v)), unsafe.Sizeof(*v))
}

// addNullESPTransport covers UDP to addr:port with an output policy and an
// ESP SA in transport mode that neither encrypts nor authenticates, so the
// datagrams arrive as they were sent.
func addNullESPTransport(t *testing.T, addr netip.Addr, port uint16) {
	t.Helper()
	for _, c := range []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"xfrm_usersa_info", unsafe.Sizeof(xfrmUsersaInfo{}), 224},
		{"xfrm_userpolicy_info", unsafe.Sizeof(xfrmUserpolicyInfo{}), 168},
		{"xfrm_user_tmpl", unsafe.Sizeof(xfrmUserTmpl{}), 64},
		{"xfrm_algo", unsafe.Sizeof(xfrmAlgo{}), 68},
	} {
		if c.got != c.want {
			t.Fatalf("sizeof(struct %s) = %d, want %d", c.name, c.got, c.want)
		}
	}

	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_XFRM)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)

	var a [16]byte
	copy(a[:], addr.AsSlice())
	const spi = 0x100

	sa := xfrmUsersaInfo{
		Sel:    xfrmSelector{Family: unix.AF_INET},
		ID:     xfrmID{Daddr: a, Proto: unix.IPPROTO_ESP},
		Saddr:  a,
		Lft:    infiniteLifetime(),
		Family: unix.AF_INET,
		Mode:   xfrmModeTransport,
	}
	binary.BigEndian.PutUint32(sa.ID.SPI[:], spi)
	var alg xfrmAlgo
	copy(alg.Name[:], "ecb(cipher_null)")
	xfrmRequest(t, fd, xfrmMsgNewSA, asBytes(&sa), netlinkAttr(xfrmaAlgCrypt, asBytes(&alg)))

	policy := xfrmUserpolicyInfo{
		Sel: xfrmSelector{
			Daddr:      a,
			DportMask:  [2]byte{0xff, 0xff},
			Family:     unix.AF_INET,
			PrefixlenD: 32,
			Proto:      unix.IPPROTO_UDP,
		},
		Lft: infiniteLifetime(),
		Dir: xfrmPolicyOut,
	}
	binary.BigEndian.PutUint16(policy.Sel.Dport[:], port)
	tmpl := xfrmUserTmpl{
		ID:     xfrmID{Daddr: a, Proto: unix.IPPROTO_ESP},
		Family: unix.AF_INET,
		Saddr:  a,
		Mode:   xfrmModeTransport,
		Aalgos: ^uint32(0),
		Ealgos: ^uint32(0),
		Calgos: ^uint32(0),
	}
	xfrmRequest(t, fd, xfrmMsgNewPolicy, asBytes(&policy), netlinkAttr(xfrmaTmpl, asBytes(&tmpl)))
}

func netlinkAttr(typ uint16, data []byte) []byte {
	b := make([]byte, unix.SizeofRtAttr+len(data))
	*(*unix.RtAttr)(unsafe.Pointer(&b[0])) = unix.RtAttr{Len: uint16(len(b)), Type: typ}
	copy(b[unix.SizeofRtAttr:], data)
	return b
}

// xfrmRequest sends one request made of parts, each padded to the netlink
// alignment, and fails unless the kernel acknowledges it.
func xfrmRequest(t *testing.T, fd int, typ uint16, parts ...[]byte) {
	t.Helper()
	msg := make([]byte, unix.SizeofNlMsghdr)
	for _, p := range parts {
		msg = append(msg, p...)
		msg = append(msg, make([]byte, (unix.NLMSG_ALIGNTO-len(p)%unix.NLMSG_ALIGNTO)%unix.NLMSG_ALIGNTO)...)
	}
	*(*unix.NlMsghdr)(unsafe.Pointer(&msg[0])) = unix.NlMsghdr{
		Len:   uint32(len(msg)),
		Type:  typ,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_ACK | unix.NLM_F_CREATE | unix.NLM_F_EXCL,
		Seq:   1,
	}
	if err := unix.Sendto(fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		t.Fatalf("xfrm message %#x: %v", typ, err)
	}
	reply := make([]byte, os.Getpagesize())
	n, _, err := unix.Recvfrom(fd, reply, 0)
	if err != nil {
		t.Fatalf("xfrm message %#x: %v", typ, err)
	}
	if n < unix.SizeofNlMsghdr+4 {
		t.Fatalf("xfrm message %#x: short reply of %d bytes", typ, n)
	}
	hdr := (*unix.NlMsghdr)(unsafe.Pointer(&reply[0]))
	if hdr.Type != unix.NLMSG_ERROR {
		t.Fatalf("xfrm message %#x: reply of type %d, want NLMSG_ERROR", typ, hdr.Type)
	}
	if errno := *(*int32)(unsafe.Pointer(&reply[unix.SizeofNlMsghdr])); errno != 0 {
		t.Fatalf("xfrm message %#x: %v", typ, syscall.Errno(-errno))
	}
}
