// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Another writer's source NAT runs after the forward decision. A protected
// source must be refused before it could be translated out of the class.
// A source outside the class must pass even when NAT changes its delivered
// source to an own address. The client observes that translated source.
func TestNetlinkFallbackRoutedDecidesBeforeOtherWriterSNAT(t *testing.T) {
	for _, family := range routedServiceFamilies {
		for _, source := range []struct {
			name    string
			address netip.Addr
			allowed bool
		}{{"own source", family.server.Addr(), false}, {"outside source", family.outsideServer.Addr(), true}} {
			t.Run(family.name+" "+source.name, func(t *testing.T) {
				_, client, _, server := routedServiceSwitch(t)
				natFamily := "ip"
				if family.server.Addr().Is6() {
					natFamily = "ip6"
				}
				script := fmt.Sprintf("table inet ranetsnat {\n chain postrouting { type nat hook postrouting priority 100; policy accept;\n"+
					" %s saddr %s oifname \"ranetup0\" snat %s to %s\n"+
					" %s saddr %s oifname \"ranetup0\" snat %s to %s\n }\n}\n",
					natFamily, family.server.Addr(), natFamily, family.rootUp.Addr(),
					natFamily, family.outsideServer.Addr(), natFamily, family.server.Addr())
				write := exec.Command("nft", "-f", "-")
				write.Stdin = strings.NewReader(script)
				if out, err := write.CombinedOutput(); err != nil {
					t.Fatalf("install the other writer's source NAT: %v\n%s", err, out)
				}
				t.Cleanup(func() {
					if out, err := exec.Command("nft", "delete", "table", "inet", "ranetsnat").CombinedOutput(); err != nil {
						t.Errorf("delete the other writer's source NAT: %v\n%s", err, out)
					}
				})
				const port = 54321
				var sender, listener *net.UDPConn
				if err := server.Do(func() (err error) {
					sender, err = net.DialUDP(family.network,
						net.UDPAddrFromAddrPort(netip.AddrPortFrom(source.address, 0)),
						net.UDPAddrFromAddrPort(netip.AddrPortFrom(family.client.Addr(), port)))
					return err
				}); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = sender.Close() })
				if err := client.Do(func() (err error) {
					listener, err = net.ListenUDP(family.network,
						net.UDPAddrFromAddrPort(netip.AddrPortFrom(family.client.Addr(), port)))
					return err
				}); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = listener.Close() })
				trace := routedTraceFor(t, 1)
				before := routedCounters(t)
				if _, err := sender.Write([]byte("translated only after the decision")); err != nil {
					t.Fatal(err)
				}
				if err := listener.SetReadDeadline(time.Now().Add(350 * time.Millisecond)); err != nil {
					t.Fatal(err)
				}
				buf := make([]byte, 64)
				n, peer, err := listener.ReadFromUDP(buf)
				if source.allowed {
					if err != nil || !bytes.Equal(buf[:n], []byte("translated only after the decision")) ||
						peer.AddrPort().Addr() != family.server.Addr() {
						t.Errorf("the client received %q from %v (%v), want the delivered source NAT to the own address",
							buf[:n], peer, err)
					}
				} else {
					var timeout net.Error
					if !errors.As(err, &timeout) || !timeout.Timeout() {
						t.Errorf("the client received %q (%v), want the protected source refused before NAT", buf[:n], err)
					}
				}
				after := routedCounters(t)
				drops := uint64(1)
				first := fallbackDrop
				if source.allowed {
					drops = 0
					first = "ip saddr != @from4 accept"
					if family.server.Addr().Is6() {
						first = "ip6 saddr != @from6 accept"
					}
				}
				if after.drop-before.drop != drops || after.icmp4 != before.icmp4 || after.icmp6 != before.icmp6 {
					t.Errorf("the NAT path changed forward counters from %+v to %+v, want %d drop and no form-e accept", before, after, drops)
				}
				routedFirstMatches(t, trace, []routedCase{
					{name: "source NAT follows the forward decision", in: "ranetother0",
						source: source.address.String(), target: family.client.Addr().String(), first: first, pass: source.allowed},
				})
			})
		}
	}
}

// A second writer translates the external destination port before this
// node forwards the request. The own-prefix server's reply is decided using
// the port the client originally addressed, not the port after translation.
func TestNetlinkFallbackRoutedUsesOriginalPortAfterOtherWriterDNAT(t *testing.T) {
	for _, family := range routedServiceFamilies {
		for _, service := range []struct {
			name                string
			original, delivered uint16
			listed              bool
		}{{"listed original", 53, 54321, true}, {"unlisted original", 54321, 53, false}} {
			t.Run(family.name+" "+service.name, func(t *testing.T) {
				_, client, _, server := routedServiceSwitch(t)
				natFamily, delivered := "ip", family.server.Addr().String()
				if family.server.Addr().Is6() {
					natFamily, delivered = "ip6", "["+delivered+"]"
				}
				script := fmt.Sprintf("table inet ranetdnat {\n chain prerouting { type nat hook prerouting priority -100; policy accept;\n"+
					" %s daddr %s udp dport %d dnat %s to %s:%d\n }\n}\n",
					natFamily, family.rootUp.Addr(), service.original, natFamily, delivered, service.delivered)
				write := exec.Command("nft", "-f", "-")
				write.Stdin = strings.NewReader(script)
				if out, err := write.CombinedOutput(); err != nil {
					t.Fatalf("install the other writer's destination NAT: %v\n%s", err, out)
				}
				t.Cleanup(func() {
					if out, err := exec.Command("nft", "delete", "table", "inet", "ranetdnat").CombinedOutput(); err != nil {
						t.Errorf("delete the other writer's destination NAT: %v\n%s", err, out)
					}
				})
				var sender, listener *net.UDPConn
				if err := client.Do(func() (err error) {
					sender, err = net.DialUDP(family.network, nil,
						net.UDPAddrFromAddrPort(netip.AddrPortFrom(family.rootUp.Addr(), service.original)))
					return err
				}); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = sender.Close() })
				if err := server.Do(func() (err error) {
					listener, err = net.ListenUDP(family.network,
						net.UDPAddrFromAddrPort(netip.AddrPortFrom(family.server.Addr(), service.delivered)))
					return err
				}); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = listener.Close() })
				trace := routedTraceFor(t, 2)
				before := routedCounters(t)
				if _, err := sender.Write([]byte("asked")); err != nil {
					t.Fatal(err)
				}
				if err := listener.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
					t.Fatal(err)
				}
				buf := make([]byte, 64)
				n, address, err := listener.ReadFromUDP(buf)
				if err != nil || !bytes.Equal(buf[:n], []byte("asked")) {
					t.Fatalf("the translated own-prefix server read %q (%v), want the client's request", buf[:n], err)
				}
				if _, err := listener.WriteToUDP([]byte("answered"), address); err != nil {
					t.Fatal(err)
				}
				if err := sender.SetReadDeadline(time.Now().Add(350 * time.Millisecond)); err != nil {
					t.Fatal(err)
				}
				n, peer, err := sender.ReadFromUDP(buf)
				if service.listed {
					if err != nil || !bytes.Equal(buf[:n], []byte("answered")) ||
						peer.AddrPort() != netip.AddrPortFrom(family.rootUp.Addr(), service.original) {
						t.Errorf("the listed client read %q from %v (%v), want the reply at its original endpoint", buf[:n], peer, err)
					}
				} else {
					var timeout net.Error
					if !errors.As(err, &timeout) || !timeout.Timeout() {
						t.Errorf("the unlisted client read %q (%v), want no reply despite the translated listed port", buf[:n], err)
					}
				}
				after := routedCounters(t)
				drops := uint64(0)
				reply := "ct direction reply ct protocol udp ct original proto-dst @udpports accept"
				if !service.listed {
					drops, reply = 1, fallbackDrop
				}
				if after.drop-before.drop != drops || after.icmp4 != before.icmp4 || after.icmp6 != before.icmp6 {
					t.Errorf("the destination-NAT path changed forward counters from %+v to %+v, want %d drop and no form-e accept", before, after, drops)
				}
				outside := "ip saddr != @from4 accept"
				if family.server.Addr().Is6() {
					outside = "ip6 saddr != @from6 accept"
				}
				routedFirstMatches(t, trace, []routedCase{
					{name: "translated client request", in: "ranetup0", source: family.client.Addr().String(), target: family.server.Addr().String(), first: outside, pass: true},
					{name: "server reply uses the pre-translation port", in: "ranetother0", source: family.server.Addr().String(), target: family.client.Addr().String(), first: reply, pass: service.listed},
				})
			})
		}
	}
}
