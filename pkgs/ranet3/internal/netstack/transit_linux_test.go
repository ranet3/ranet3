// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux

package netstack

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// answeredFamily is one family the host behind the tun sends from, to an address it routes out of the tun
// with the socket options that set its hop limit and ask for its errors, and the ICMP type of time exceeded
// offenderLen is the size of the address an error names the sender of the ICMP error by
type answeredFamily struct {
	name                string
	domain, level       int
	hops, recvErr, cmsg int
	origin              uint8
	expired             uint8
	local, far          netip.Addr
	offenderLen         int
	assign              func(t *testing.T, name string)
	address             func(netip.Addr) unix.Sockaddr
	offender            func([]byte) netip.Addr
}

var answeredFamilies = []answeredFamily{
	{"IPv4", unix.AF_INET, unix.IPPROTO_IP, unix.IP_TTL, unix.IP_RECVERR, unix.IP_RECVERR, unix.SO_EE_ORIGIN_ICMP, 11,
		segAddr("192.0.2.1"), segAddr("203.0.113.9"), unix.SizeofSockaddrInet4,
		func(t *testing.T, name string) { assignPeer(t, name, segAddr("192.0.2.1"), segAddr("203.0.113.9")) },
		func(far netip.Addr) unix.Sockaddr { return &unix.SockaddrInet4{Port: 9, Addr: far.As4()} },
		// struct sockaddr_in, its address at byte 4
		func(raw []byte) netip.Addr { return netip.AddrFrom4([4]byte(raw[4:8])) }},
	{"IPv6", unix.AF_INET6, unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, unix.IPV6_RECVERR, unix.IPV6_RECVERR, unix.SO_EE_ORIGIN_ICMP6, 3,
		segAddr("3fff::1"), segAddr("3fff::9"), unix.SizeofSockaddrInet6,
		func(t *testing.T, name string) { assignIPv6(t, name, segPrefix("3fff::1/64")) },
		func(far netip.Addr) unix.Sockaddr { return &unix.SockaddrInet6{Port: 9, Addr: far.As16()} },
		// struct sockaddr_in6, its address at byte 8
		func(raw []byte) netip.Addr { return netip.AddrFrom16([16]byte(raw[8:24])) }},
}

// a packet this host sent that a session brings back with its hop limit spent is answered into the tun from the address it went to
// past the reverse path check NixOS's firewall puts in prerouting, strict and loose, and the sending socket reads the error
// the router-id is the host's own address here, which both checks drop as a source arriving on the tun, as the host drops an IPv4 one of its own
func TestTUNAnswerToThisHostPassesAReversePathCheck(t *testing.T) {
	for _, family := range answeredFamilies {
		for _, chain := range reversePathChains {
			t.Run(fmt.Sprintf("%s under the %s chain", family.name, chain.name), func(t *testing.T) {
				enterEmptyNamespace(t)
				nft, err := exec.LookPath("nft")
				if err != nil {
					t.Fatal("the reverse path chain is written through nft, which is not on the path")
				}
				load := exec.Command(nft, "-f", "-")
				load.Stdin = strings.NewReader(reversePathRuleset(chain.match))
				if out, err := load.CombinedOutput(); err != nil {
					t.Fatalf("load the %s reverse path chain: %v\n%s", chain.name, err, out)
				}
				m, err := NewNamed(DefaultMTU, "rpatest0", nil)
				if err != nil {
					t.Fatalf("open the mesh: %v", err)
				}
				t.Cleanup(m.Close)
				family.assign(t, m.Name)
				m.SetTransit(true)
				m.SetAnswerSources(AnswerSources{Router4: answeredFamilies[0].local, Router6: answeredFamilies[1].local})
				// the TTL a client takes from the host's default, without which the node sends no IPv4 answer
				m.SetAnswerTTL(64)
				m.Routes.Set(netip.Prefix{}, hostPrefix(family.local), Local)

				// the far end of a session that sends what it is sent for the far address straight back
				far, _ := startTransitMesh(nil)
				t.Cleanup(far.Close)
				var toFar, back *Peer
				toFar = NewPeer("far", func(int) (BatchSealer, error) { return cloning, nil }, func(sealed [][]byte) error {
					far.DeliverInboundBatch(framed(sealed...), DefaultMTU, back)
					return nil
				}, nil)
				back = NewPeer("back", func(int) (BatchSealer, error) { return cloning, nil }, func(sealed [][]byte) error {
					m.DeliverInboundBatch(framed(sealed...), DefaultMTU, toFar)
					return nil
				}, nil)
				t.Cleanup(toFar.Close)
				t.Cleanup(back.Close)
				m.Routes.Set(netip.Prefix{}, hostPrefix(family.far), toFar)
				far.Routes.Set(netip.Prefix{}, hostPrefix(family.far), back)

				// two hops, one taken by the far end, so the hop limit runs out at this node
				fd, err := unix.Socket(family.domain, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
				if err != nil {
					t.Fatalf("open a socket: %v", err)
				}
				t.Cleanup(func() { _ = unix.Close(fd) })
				for option, value := range map[int]int{family.hops: 2, family.recvErr: 1} {
					if err := unix.SetsockoptInt(fd, family.level, option, value); err != nil {
						t.Fatalf("set socket option %d: %v", option, err)
					}
				}
				if err := unix.Connect(fd, family.address(family.far)); err != nil {
					t.Fatalf("connect to %s: %v", family.far, err)
				}
				if _, err := unix.Write(fd, []byte("spent")); err != nil {
					t.Fatalf("send a datagram: %v", err)
				}
				waitUntil(t, "the answer to be written into the tun", func() bool { return m.TransitCounters().Answered == 1 })
				if got := m.TransitCounters(); got.Expired != 1 || got.Forwarded != 0 {
					t.Errorf("the node counted %+v, want the one packet expired", got)
				}
				kind, from := readSocketError(t, fd, family)
				if kind != family.expired || from != family.far {
					t.Errorf("the socket read ICMP type %d from %s, want time exceeded from %s", kind, from, family.far)
				}
			})
		}
	}
}

// readSocketError waits for the error the kernel queues on fd for an ICMP error, and returns its type and the address it came from
// struct sock_extended_err of include/uapi/linux/errqueue.h, its origin at byte 4 and its type at byte 5, the offender's address after it
func readSocketError(t *testing.T, fd int, family answeredFamily) (uint8, netip.Addr) {
	t.Helper()
	buf, oob := make([]byte, 512), make([]byte, 512)
	for deadline := time.Now().Add(deliveryTimeout); time.Now().Before(deadline); time.Sleep(deliveryPoll) {
		_, oobn, _, _, err := unix.Recvmsg(fd, buf, oob, unix.MSG_ERRQUEUE|unix.MSG_DONTWAIT)
		if err == unix.EAGAIN {
			continue
		}
		if err != nil {
			t.Fatalf("read the socket's error queue: %v", err)
		}
		messages, err := unix.ParseSocketControlMessage(oob[:oobn])
		if err != nil {
			t.Fatalf("parse the socket's control messages: %v", err)
		}
		for _, message := range messages {
			if int(message.Header.Level) != family.level || int(message.Header.Type) != family.cmsg || len(message.Data) < 16+family.offenderLen {
				continue
			}
			if origin := message.Data[4]; origin != family.origin {
				t.Fatalf("the socket read an error of origin %d, want one of ICMP", origin)
			}
			return message.Data[5], family.offender(message.Data[16:])
		}
	}
	t.Fatal("the socket read no error")
	return 0, netip.Addr{}
}
