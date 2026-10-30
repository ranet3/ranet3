// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package client

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/netnstest"
)

const (
	// switchGRE and switchWireGuard are the leaf's kernel tunnels, each with a private network that counts as its LAN, and
	// switchBoundGRE a GRE tunnel bound to the uplink whose far end is switchOnLo
	switchGRE       = "rulg"
	switchWireGuard = "rulw"
	switchBoundGRE  = "rulk"
	// switchWireGuardPort is the port the WireGuard peers listen on beyond the uplink
	switchWireGuardPort = 51821
	// greLink, greLocal and greRemote are IFLA_GRE_LINK, IFLA_GRE_LOCAL and IFLA_GRE_REMOTE of linux/if_tunnel.h, which x/sys
	// does not carry
	greLink   = 1
	greLocal  = 6
	greRemote = 7
)

var (
	// the tunnels' networks are private, so the table passes the inner packet as the LAN and only the outer one is at stake
	switchGREPrefix       = netip.MustParsePrefix("10.0.1.1/30")
	switchWireGuardPrefix = netip.MustParsePrefix("10.0.2.1/24")
	switchBoundGREPrefix  = netip.MustParsePrefix("10.0.4.1/30")
	// switchWireGuardInner is the WireGuard peers' inner addresses, one behind an IPv4 endpoint and one behind an IPv6 one
	switchWireGuardInner = []netip.Addr{netip.MustParseAddr("10.0.2.2"), netip.MustParseAddr("10.0.2.3")}
	// switchInner is each inner destination: the GRE tunnel's far end, the WireGuard peers and the bound GRE tunnel's far end
	switchInner = slices.Concat([]netip.Addr{netip.MustParseAddr("10.0.1.2")}, switchWireGuardInner, []netip.Addr{netip.MustParseAddr("10.0.4.2")})
	// switchOnLo is an address the leaf holds on lo outside the LAN, the overlay and its own prefixes. The bound tunnel's outer
	// lookup passes over its local route, which another link holds, and sends the outer packet out of the uplink.
	switchOnLo = netip.MustParsePrefix("203.0.113.200/32")
)

// a leaf in mode 2 with fallback = "none" holding a kernel GRE tunnel and a kernel WireGuard device whose networks count as the LAN, and a
// GRE tunnel bound to the uplink whose far end is an address the leaf holds on lo, in each state: the host's datagram into each passes as
// the LAN, and the tunnel's outer packet, which leaves by the uplink carrying the tunnel device as its input link, does not reach the
// internet host
func TestTUNKillSwitchKeepsKernelTunnelsOffTheUplink(t *testing.T) {
	// the tunnels' modules load at the link's creation, which these tests never ask of a kernel that has not loaded them
	for _, module := range []string{"ip_gre", "wireguard"} {
		if _, err := os.Stat("/sys/module/" + module); err != nil {
			t.Skipf("the kernel has not loaded %s", module)
		}
	}
	lab := newSwitchLab(t)
	if err := lab.leaf.Do(func() error { return errors.Join(switchTunnels(), otherMarkRule(unix.RTM_NEWRULE)) }); err != nil {
		t.Fatalf("make the leaf's tunnels: %v", err)
	}
	for _, state := range switchStates {
		t.Run(string(state), func(t *testing.T) {
			lab.settle(t, switchArm{state: state})
			waitFor(t, rulesSettle, "the table's lan4 to hold the tunnels' networks", func() bool {
				var held kernel.FallbackDebug
				if err := lab.leaf.Do(func() (err error) { held, err = kernel.ReadFallback(); return err }); err != nil {
					return false
				}
				for _, set := range held.Sets {
					if set.Name == "lan4" {
						return !slices.ContainsFunc([]netip.Prefix{switchGREPrefix, switchWireGuardPrefix, switchBoundGREPrefix}, func(network netip.Prefix) bool {
							return !slices.Contains(set.Elements, network.Masked().String())
						})
					}
				}
				return false
			})
			rulesDrain(lab.farCapture)
			if err := lab.leaf.Do(func() error {
				if err := switchWireGuardPeers(); err != nil {
					return fmt.Errorf("give %s its peers: %w", switchWireGuard, err)
				}
				for _, inner := range switchInner {
					fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
					if err != nil {
						return err
					}
					err = unix.Sendto(fd, []byte("inner"), 0, rulesSockaddr(inner, rulesDiscard))
					_ = unix.Close(fd)
					if err != nil {
						return fmt.Errorf("send to %s through its tunnel: %w", inner, err)
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if gre, wireguard := switchOuters(lab.farCapture); gre+wireguard > 0 {
				t.Errorf("the internet host read %d GRE packets and %d WireGuard datagrams of the leaf's tunnels out of the uplink, want none", gre, wireguard)
			}
		})
	}
}

// switchOuters reads the capture until a read waits out its timeout, and counts the GRE packets and the datagrams to switchWireGuardPort it read
func switchOuters(capture int) (gre, wireguard int) {
	buf := make([]byte, 1<<16)
	for {
		n, _, err := unix.Recvfrom(capture, buf, 0)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return gre, wireguard
		}
		raw := buf[:n]
		var protocol byte
		var transport []byte
		switch {
		case len(raw) >= 20 && raw[0]>>4 == 4:
			protocol, transport = raw[9], raw[int(raw[0]&0xf)*4:]
		case len(raw) >= 40 && raw[0]>>4 == 6:
			protocol, transport = raw[6], raw[40:]
		default:
			continue
		}
		switch {
		case protocol == unix.IPPROTO_GRE:
			gre++
		case protocol == unix.IPPROTO_UDP && len(transport) >= 4 && binary.BigEndian.Uint16(transport[2:]) == switchWireGuardPort:
			wireguard++
		}
	}
}

// switchTunnels makes, in the calling thread's namespace, a GRE tunnel from the uplink's address to the internet host, a WireGuard
// device, and a GRE tunnel bound to the uplink from its address to switchOnLo, which lo holds, each addressed and up
func switchTunnels() error {
	netlink, err := netnstest.OpenNetlink()
	if err != nil {
		return err
	}
	defer netlink.Close()
	uplink, err := net.InterfaceByName(rulesUplink)
	if err != nil {
		return err
	}
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		return err
	}
	if err := netlink.AddAddress(lo.Index, switchOnLo); err != nil {
		return fmt.Errorf("give lo %s: %w", switchOnLo, err)
	}
	local := netnstest.Attr(greLocal, rulesHost[4].uplink.Addr().AsSlice())
	gre := slices.Concat(local, netnstest.Attr(greRemote, exitLabHost[4].internet.Addr().AsSlice()))
	bound := slices.Concat(netnstest.Attr(greLink, netnstest.U32(uint32(uplink.Index))), local, netnstest.Attr(greRemote, switchOnLo.Addr().AsSlice()))
	for _, link := range []struct {
		name, kind string
		data       []byte
	}{{switchGRE, "gre", gre}, {switchWireGuard, "wireguard", nil}, {switchBoundGRE, "gre", bound}} {
		info := netnstest.Attr(unix.IFLA_INFO_KIND, []byte(link.kind))
		if link.data != nil {
			info = append(info, netnstest.Attr(unix.IFLA_INFO_DATA|unix.NLA_F_NESTED, link.data)...)
		}
		body := slices.Concat(netnstest.IfInfo(0, 0), netnstest.Attr(unix.IFLA_IFNAME, netnstest.CString(link.name)), netnstest.Attr(unix.IFLA_LINKINFO|unix.NLA_F_NESTED, info))
		if err := netlink.Request(unix.RTM_NEWLINK, unix.NLM_F_CREATE|unix.NLM_F_EXCL, body); err != nil {
			return fmt.Errorf("make the %s link %s: %w", link.kind, link.name, err)
		}
	}
	for name, prefix := range map[string]netip.Prefix{switchGRE: switchGREPrefix, switchWireGuard: switchWireGuardPrefix, switchBoundGRE: switchBoundGREPrefix} {
		link, err := net.InterfaceByName(name)
		if err != nil {
			return err
		}
		if err := errors.Join(netlink.AddAddress(link.Index, prefix), netnstest.BringUp(name)); err != nil {
			return fmt.Errorf("address and bring up %s: %w", name, err)
		}
	}
	return nil
}

// switchWireGuardPeers gives switchWireGuard, in the calling thread's namespace, sockets carrying the mark the other program's rule sends
// to main and new peers at the internet host's address of each family, so its next datagram to each starts a handshake
func switchWireGuardPeers() error {
	endpoints := []netip.AddrPort{
		netip.AddrPortFrom(exitLabHost[4].internet.Addr(), switchWireGuardPort), netip.AddrPortFrom(exitLabHost[6].internet.Addr(), switchWireGuardPort),
	}
	return wireguardDevice(switchWireGuard, switchOtherMark, endpoints, switchWireGuardInner)
}

// wireguardDevice gives the kernel WireGuard device name a private key, the mark its sockets carry and, in place of the peers it has, a
// peer at each endpoint whose allowed address is the one of allowed at its index, through the generic netlink family wg(8) writes, each
// key drawn at random
func wireguardDevice(name string, mark uint32, endpoints []netip.AddrPort, allowed []netip.Addr) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_GENERIC)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	family, err := genericFamily(fd, unix.WG_GENL_NAME)
	if err != nil {
		return err
	}
	key := func() []byte {
		out := make([]byte, 32)
		_, _ = rand.Read(out)
		return out
	}
	var peers []byte
	for i, endpoint := range endpoints {
		ip := allowed[i]
		allowedIP := slices.Concat(netnstest.Attr(unix.WGALLOWEDIP_A_FAMILY, binary.NativeEndian.AppendUint16(nil, unix.AF_INET)),
			netnstest.Attr(unix.WGALLOWEDIP_A_IPADDR, ip.AsSlice()), netnstest.Attr(unix.WGALLOWEDIP_A_CIDR_MASK, []byte{32}))
		peer := slices.Concat(netnstest.Attr(unix.WGPEER_A_PUBLIC_KEY, key()), netnstest.Attr(unix.WGPEER_A_ENDPOINT, sockaddrBytes(endpoint)),
			netnstest.Attr(unix.WGPEER_A_ALLOWEDIPS|unix.NLA_F_NESTED, netnstest.Attr(unix.NLA_F_NESTED, allowedIP)))
		peers = append(peers, netnstest.Attr(uint16(i)|unix.NLA_F_NESTED, peer)...)
	}
	body := slices.Concat([]byte{unix.WG_CMD_SET_DEVICE, unix.WG_GENL_VERSION, 0, 0}, netnstest.Attr(unix.WGDEVICE_A_IFNAME, netnstest.CString(name)),
		netnstest.Attr(unix.WGDEVICE_A_FLAGS, netnstest.U32(unix.WGDEVICE_F_REPLACE_PEERS)),
		netnstest.Attr(unix.WGDEVICE_A_PRIVATE_KEY, key()), netnstest.Attr(unix.WGDEVICE_A_FWMARK, netnstest.U32(mark)),
		netnstest.Attr(unix.WGDEVICE_A_PEERS|unix.NLA_F_NESTED, peers))
	return netnstest.Acknowledged(fd, netnstest.Message(family, unix.NLM_F_ACK, body))
}

// genericFamily asks the generic netlink controller on fd for the message kind of the family name
func genericFamily(fd int, name string) (uint16, error) {
	body := slices.Concat([]byte{unix.CTRL_CMD_GETFAMILY, 1, 0, 0}, netnstest.Attr(unix.CTRL_ATTR_FAMILY_NAME, netnstest.CString(name)))
	if err := unix.Sendto(fd, netnstest.Message(unix.GENL_ID_CTRL, 0, body), 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return 0, err
	}
	buf := make([]byte, 1<<16)
	n, _, err := unix.Recvfrom(fd, buf, 0)
	if err != nil {
		return 0, err
	}
	messages, err := syscall.ParseNetlinkMessage(buf[:n])
	if err != nil {
		return 0, err
	}
	for _, message := range messages {
		if message.Header.Type == unix.NLMSG_ERROR && len(message.Data) >= 4 {
			if code := int32(binary.NativeEndian.Uint32(message.Data)); code != 0 {
				return 0, fmt.Errorf("the generic netlink family %s: %w", name, unix.Errno(-code))
			}
		}
		if message.Header.Type != unix.GENL_ID_CTRL || len(message.Data) < unix.GENL_HDRLEN {
			continue
		}
		for data := message.Data[unix.GENL_HDRLEN:]; len(data) >= unix.SizeofRtAttr; {
			length, kind := int(binary.NativeEndian.Uint16(data)), binary.NativeEndian.Uint16(data[2:])
			if length < unix.SizeofRtAttr || length > len(data) {
				break
			}
			if kind == unix.CTRL_ATTR_FAMILY_ID && length >= unix.SizeofRtAttr+2 {
				return binary.NativeEndian.Uint16(data[unix.SizeofRtAttr:]), nil
			}
			data = data[min((length+unix.RTA_ALIGNTO-1)&^(unix.RTA_ALIGNTO-1), len(data)):]
		}
	}
	return 0, fmt.Errorf("the generic netlink controller named no family %s", name)
}

// sockaddrBytes is endpoint as the kernel's struct sockaddr_in or sockaddr_in6
func sockaddrBytes(endpoint netip.AddrPort) []byte {
	port := binary.BigEndian.AppendUint16(nil, endpoint.Port())
	if endpoint.Addr().Is4() {
		return slices.Concat(binary.NativeEndian.AppendUint16(nil, unix.AF_INET), port, endpoint.Addr().AsSlice(), make([]byte, 8))
	}
	return slices.Concat(binary.NativeEndian.AppendUint16(nil, unix.AF_INET6), port, make([]byte, 4), endpoint.Addr().AsSlice(), make([]byte, 4))
}
