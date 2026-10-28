// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

//go:build !linux && !darwin

package transport

import (
	"log/slog"
	"net/netip"

	"ranet3.com/pkgs/wireguard/conn"
)

type portableBind struct{ conn.Bind }
type portableEndpoint struct{ conn.Endpoint }

func (*portableEndpoint) transportEndpoint() {}
func (e *portableEndpoint) String() string   { return e.DstToString() }

// no endpoint here carries a source, which wireguard's keeps on linux alone
func (e *portableEndpoint) sameDestination(other Endpoint) bool {
	o, ok := other.(*portableEndpoint)
	return ok && e.DstToString() == o.DstToString()
}

func (e *portableEndpoint) withoutSource() Endpoint { return e }

func (e *portableEndpoint) AddrPort() netip.AddrPort {
	addr, err := netip.ParseAddrPort(e.DstToString())
	if err != nil {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())
}

func (e *portableEndpoint) zone() string {
	addr, err := netip.ParseAddrPort(e.DstToString())
	if err != nil {
		return ""
	}
	return addr.Addr().Zone()
}

func (b *portableBind) ParseEndpoint(s string) (Endpoint, error) {
	ep, err := b.Bind.ParseEndpoint(s)
	return &portableEndpoint{ep}, err
}

func (b *portableBind) Send(packets [][]byte, endpoint Endpoint) error {
	return b.Bind.Send(packets, endpoint.(*portableEndpoint).Endpoint, 0)
}

// link.underlay.bind means nothing on this platform, so Underlay.refuse turns
// down a configuration that sets it by name rather than accepting a setting
// that does nothing.
const takesBind = false

func openPacketBind(port uint16, _ Selection, _ func(string, ...slog.Attr)) (packetBind, []receiveFunc, uint16, error) {
	b := &portableBind{conn.NewStdNetBind()}
	fns, port, err := b.Open(port)
	if err != nil {
		return nil, nil, 0, err
	}
	var receivers []receiveFunc
	for _, fn := range fns {
		size := b.BatchSize()
		// the next read reuses the slab, and the hub copies what it keeps of a read before the next
		slab := make([]byte, readBufferSize*size)
		packets := make([]conn.ReceivedPacket, size)
		receivers = append(receivers, func(bufs [][]byte, sizes []int, endpoints []Endpoint, records []receiveRecord) (int, int, error) {
			n, err := fn(slab, packets)
			for i := range n {
				bufs[i], sizes[i] = packets[i].Bytes(slab), packets[i].Size
				endpoints[i] = &portableEndpoint{packets[i].Endpoint}
				records[i] = receiveRecord{source: packets[i].Endpoint.(*conn.StdNetEndpoint).AddrPort}
			}
			// This bind hands every datagram it reads straight through, so
			// there is nothing it refuses of its own.
			return n, 0, err
		})
	}
	return b, receivers, port, nil
}
