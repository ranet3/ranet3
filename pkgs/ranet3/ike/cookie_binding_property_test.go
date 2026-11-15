// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package ike

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/transport"
)

// cookieAddress carries the zone that NewMux's net.IP argument cannot carry.
type cookieAddress struct {
	transport.Endpoint
	addr netip.AddrPort
}

func (e cookieAddress) String() string           { return net.UDPAddrFromAddrPort(e.addr).String() }
func (e cookieAddress) AddrPort() netip.AddrPort { return e.addr }

func TestCookiesBindEveryRequestField(t *testing.T) {
	hub := listenHub(t)
	pbt.Check(t, func(ht *hegel.T) {
		type request struct {
			nonce []byte
			spi   uint64
			addr  netip.AddrPort
		}
		secret := [cookieSecretLen]byte(hegel.Draw(ht, hegel.Binary(cookieSecretLen, cookieSecretLen)))
		version := hegel.Draw(ht, pbt.Spanning[uint8](0, 255))
		cookie := func(r request) []byte {
			m, err := hub.NewMux(net.IP(r.addr.Addr().AsSlice()), int(r.addr.Port()))
			if err != nil {
				ht.Fatal(err)
			}
			ep := cookieAddress{m.Endpoint(), r.addr}
			m.Close()
			// the MAC input must recover the whole canonical request, not just distinguish selected pairs
			source := net.JoinHostPort(r.addr.Addr().Unmap().String(), strconv.Itoa(int(r.addr.Port())))
			input := binary.BigEndian.AppendUint16(nil, uint16(len(r.nonce)))
			input = binary.BigEndian.AppendUint64(input, r.spi)
			input = append(input, r.nonce...)
			input = append(input, source...)
			n := int(binary.BigEndian.Uint16(input[:2]))
			if n > len(input)-10 {
				ht.Fatal("cookie input nonce extends past the input")
			}
			decoded, err := netip.ParseAddrPort(string(input[10+n:]))
			if err != nil {
				ht.Fatal(err)
			}
			if binary.BigEndian.Uint64(input[2:10]) != r.spi ||
				!slices.Equal(input[10:10+n], r.nonce) ||
				decoded != netip.AddrPortFrom(r.addr.Addr().Unmap(), r.addr.Port()) {
				ht.Fatal("cookie input does not recover the request")
			}
			mac := hmac.New(sha256.New, secret[:])
			mac.Write(input)
			want := append([]byte{version}, mac.Sum(nil)...)
			got := cookieValue(secret, version, r.nonce, r.spi, ep)
			if !slices.Equal(got, want) {
				ht.Fatal("cookie differs from the recoverable request encoding")
			}
			return got
		}
		check := func(name string, a, b request) {
			sameAddress := a.addr.Addr().Unmap() == b.addr.Addr().Unmap() &&
				a.addr.Addr().Zone() == b.addr.Addr().Zone() && a.addr.Port() == b.addr.Port()
			sameRequest := slices.Equal(a.nonce, b.nonce) && a.spi == b.spi && sameAddress
			if sameCookie := slices.Equal(cookie(a), cookie(b)); sameCookie != sameRequest {
				ht.Fatalf("%s: cookie equality %v, request equality %v; nonce lengths %d/%d, SPI %x/%x, source %s/%s",
					name, sameCookie, sameRequest, len(a.nonce), len(b.nonce), a.spi, b.spi, a.addr, b.addr)
			}
		}
		address := func(family int) netip.AddrPort {
			ip, ok := netip.AddrFromSlice(hegel.Draw(ht, hegel.Binary(family, family)))
			if !ok {
				ht.Fatal("invalid generated address")
			}
			if family == 16 {
				ip = ip.WithZone(hegel.Draw(ht, hegel.SampledFrom([]string{"", "eth0", "eth1", "1", "12"})))
			}
			return netip.AddrPortFrom(ip, hegel.Draw(ht, pbt.Spanning[uint16](1, 65535)))
		}
		for _, family := range []int{4, 16} {
			for _, length := range []int{16, 17, 255, 256, hegel.Draw(ht, pbt.Spanning(16, 256))} {
				a := request{
					hegel.Draw(ht, hegel.Binary(length, length)),
					hegel.Draw(ht, pbt.Spanning[uint64](1, ^uint64(0))),
					address(family),
				}
				check("same request", a, a)
				check("independent requests", a, request{
					hegel.Draw(ht, hegel.Binary(16, 256)),
					hegel.Draw(ht, pbt.Spanning[uint64](1, ^uint64(0))),
					address(hegel.Draw(ht, hegel.SampledFrom([]int{4, 16}))),
				})
				b := a
				b.nonce = slices.Clone(a.nonce)
				b.nonce[0] ^= 1
				check("nonce content", a, b)
				b = a
				if length == 256 {
					b.nonce = a.nonce[:255]
				} else {
					b.nonce = append(slices.Clone(a.nonce), hegel.Draw(ht, pbt.Spanning[byte](0, 255)))
				}
				check("nonce length", a, b)
				b = a
				b.spi ^= uint64(1) << hegel.Draw(ht, pbt.Spanning(0, 63))
				check("SPI", a, b)
				b = a
				ip := a.addr.Addr().AsSlice()
				ip[len(ip)-1] ^= 1
				changed, _ := netip.AddrFromSlice(ip)
				b.addr = netip.AddrPortFrom(changed.WithZone(a.addr.Addr().Zone()), a.addr.Port())
				check("address", a, b)
				b = a
				b.addr = netip.AddrPortFrom(a.addr.Addr(), a.addr.Port()%65535+1)
				check("port", a, b)
				b = a
				b.addr = netip.AddrPortFrom(address(20-family).Addr(), a.addr.Port())
				check("family", a, b)
				if family == 16 {
					b = a
					b.addr = netip.AddrPortFrom(a.addr.Addr().WithZone(a.addr.Addr().Zone()+"1"), a.addr.Port())
					check("zone", a, b)
				} else {
					b = a
					b.addr = netip.AddrPortFrom(netip.AddrFrom16(a.addr.Addr().As16()), a.addr.Port())
					check("mapped address", a, b)
				}
			}
		}
	})
}
