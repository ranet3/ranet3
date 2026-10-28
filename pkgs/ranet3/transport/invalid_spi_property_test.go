// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package transport

import (
	"encoding/binary"
	"net/netip"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/bubble"
	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// invalidSPIPlaces are the endpoints the property's sessions draw theirs from, two of them two ports of one address
var invalidSPIPlaces = []netip.AddrPort{
	netip.MustParseAddrPort("192.0.2.1:4500"),
	netip.MustParseAddrPort("192.0.2.1:4501"),
	netip.MustParseAddrPort("192.0.2.2:4500"),
	netip.MustParseAddrPort("[2001:db8::1]:4500"),
}

// invalidSPIStranger is an address no session is at
var invalidSPIStranger = netip.MustParseAddr("198.51.100.7")

// spiModel is the rule the hub answers unknown SPIs by, kept apart from the hub's code
// a datagram on an SPI no session holds is handed to a session that has not ended when it came from that session's exact endpoint,
// no session let go of the SPI, by letting it go or by ending, within the interval before it, the session was handed none within that interval,
// and the hub looked for no session within it, a look being any such datagram that arrived while the hub had not looked within the interval
type spiModel struct {
	endpoints []netip.AddrPort
	held      []map[uint32]bool
	ended     []bool
	retired   map[uint32]time.Duration
	told      []time.Duration
	looked    time.Duration
	refused   uint64
}

func newSPIModel(endpoints []netip.AddrPort) *spiModel {
	m := &spiModel{endpoints: endpoints, ended: make([]bool, len(endpoints)), retired: map[uint32]time.Duration{}, looked: -invalidSPIInterval}
	for range endpoints {
		m.held = append(m.held, map[uint32]bool{})
		m.told = append(m.told, -invalidSPIInterval)
	}
	return m
}

// letGo has session i let go of spi at now
func (m *spiModel) letGo(i int, spi uint32, now time.Duration) {
	delete(m.held[i], spi)
	m.retired[spi] = now
}

// end has session i end at now, letting go of every SPI it holds, and a session holding none take its place at its endpoint
func (m *spiModel) end(i int, now time.Duration) {
	for spi := range m.held[i] {
		m.letGo(i, spi, now)
	}
	m.ended[i] = true
	m.endpoints = append(m.endpoints, m.endpoints[i])
	m.held = append(m.held, map[uint32]bool{})
	m.ended = append(m.ended, false)
	m.told = append(m.told, -invalidSPIInterval)
}

// arrive answers which sessions are handed spi when it arrives from source at now
func (m *spiModel) arrive(now time.Duration, source netip.AddrPort, spi uint32) []bool {
	handed := make([]bool, len(m.endpoints))
	for _, held := range m.held {
		if held[spi] {
			return handed
		}
	}
	m.refused++
	if now-m.looked < invalidSPIInterval {
		return handed
	}
	m.looked = now
	if at, retired := m.retired[spi]; retired && now-at < invalidSPIInterval {
		return handed
	}
	from := netip.AddrPortFrom(source.Addr().Unmap(), source.Port())
	for i, endpoint := range m.endpoints {
		if !m.ended[i] && endpoint == from && now-m.told[i] >= invalidSPIInterval {
			handed[i], m.told[i] = true, now
		}
	}
	return handed
}

// over drawn arrivals of ESP from sessions' endpoints and from elsewhere, on SPIs held, let go of and never held, at times around the interval, between sessions letting SPIs go, ending with another taking their place, and moving
// the hub hands each session exactly the SPIs the model does, and counts as refused exactly the datagrams on an SPI no session holds
func TestUnknownSPIsAreHandedOnAsTheModelDoes(t *testing.T) {
	bubble.Run(func(t *testing.T) {
		pbt.Check(t, func(ht *hegel.T) {
			hub, arrivals := scriptedHub()
			defer hub.Close()
			defer close(arrivals)
			endpoints := make([]netip.AddrPort, hegel.Draw(ht, pbt.Spanning(1, 3)))
			for i := range endpoints {
				endpoints[i] = hegel.Draw(ht, hegel.SampledFrom(invalidSPIPlaces))
			}
			model := newSPIModel(endpoints)
			muxes := make([]*Mux, len(endpoints))
			for i, endpoint := range model.endpoints {
				mux, err := hub.NewMux(endpoint.Addr().AsSlice(), int(endpoint.Port()))
				if err != nil {
					ht.Fatal(err)
				}
				muxes[i] = mux
				for _, spi := range []uint32{knownSPI + 2*uint32(i), knownSPI + 2*uint32(i) + 1} {
					if err := mux.RegisterESP(spi); err != nil {
						ht.Fatal(err)
					}
					model.held[i][spi] = true
				}
			}
			var now time.Duration
			for step := range hegel.Draw(ht, pbt.Spanning(1, 24)) {
				var pause time.Duration
				switch hegel.Draw(ht, hegel.SampledFrom([]string{"at once", "around the interval", "within it"})) {
				case "around the interval":
					pause = invalidSPIInterval + time.Duration(hegel.Draw(ht, pbt.Spanning(-1, 1)))
				case "within it":
					pause = time.Duration(hegel.Draw(ht, pbt.Spanning(int64(1), int64(invalidSPIInterval-1))))
				}
				time.Sleep(pause)
				now += pause
				session := hegel.Draw(ht, pbt.Spanning(0, len(model.endpoints)-1))
				if hegel.Draw(ht, hegel.WeightedBooleans(1.0/4)) {
					switch hegel.Draw(ht, hegel.SampledFrom([]string{"let go of an SPI", "end", "move"})) {
					case "move":
						place := hegel.Draw(ht, hegel.SampledFrom(invalidSPIPlaces))
						muxes[session].AdoptEndpoint(newMemoryEndpoint(place))
						model.endpoints[session] = place
					case "let go of an SPI":
						if held := heldSPIs(model.held[session]); len(held) > 0 {
							spi := hegel.Draw(ht, hegel.SampledFrom(held))
							muxes[session].UnregisterESP(spi)
							model.letGo(session, spi, now)
						}
					case "end":
						muxes[session].Close()
						model.end(session, now)
						place := model.endpoints[session]
						mux, err := hub.NewMux(place.Addr().AsSlice(), int(place.Port()))
						if err != nil {
							ht.Fatal(err)
						}
						muxes = append(muxes, mux)
					}
					continue
				}
				source := drawSource(ht, model.endpoints[session])
				spi := drawSPI(ht, model)
				want := model.arrive(now, source, spi)
				arrivals <- scriptedArrival{data: binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, spi), 1), source: source}
				synctest.Wait()
				for i, mux := range muxes {
					got, handed := told(mux)
					if handed != want[i] || (handed && got != spi) {
						ht.Fatalf("step %d at %v: ESP on SPI %#x from %s handed session %d at %s %#x (%v), want %v", step, now, spi, source, i, model.endpoints[i], got, handed, want[i])
					}
				}
				if hub.Refused() != model.refused {
					ht.Fatalf("step %d at %v: ESP on SPI %#x from %s left refused at %d, want %d", step, now, spi, source, hub.Refused(), model.refused)
				}
			}
		})
	})(t)
}

// heldSPIs answers the SPIs a session holds, in order
func heldSPIs(held map[uint32]bool) []uint32 {
	var spis []uint32
	for spi := range held {
		spis = append(spis, spi)
	}
	slices.Sort(spis)
	return spis
}

// drawSource draws where a datagram comes from: endpoint itself, its IPv4-mapped form, another port of its address, or another address
func drawSource(ht *hegel.T, endpoint netip.AddrPort) netip.AddrPort {
	switch hegel.Draw(ht, hegel.SampledFrom([]string{"the endpoint", "mapped", "another port", "another address"})) {
	case "mapped":
		return netip.AddrPortFrom(netip.AddrFrom16(endpoint.Addr().As16()), endpoint.Port())
	case "another port":
		return netip.AddrPortFrom(endpoint.Addr(), endpoint.Port()+1)
	case "another address":
		return netip.AddrPortFrom(invalidSPIStranger, endpoint.Port())
	}
	return endpoint
}

// drawSPI draws an SPI a session holds, one a session let go of, or one no session ever held
func drawSPI(ht *hegel.T, model *spiModel) uint32 {
	var held, retired []uint32
	for i := range model.held {
		held = append(held, heldSPIs(model.held[i])...)
	}
	for spi := range model.retired {
		retired = append(retired, spi)
	}
	slices.Sort(retired)
	kinds := []string{"never held"}
	if len(held) > 0 {
		kinds = append(kinds, "held")
	}
	if len(retired) > 0 {
		kinds = append(kinds, "let go of")
	}
	switch hegel.Draw(ht, hegel.SampledFrom(kinds)) {
	case "held":
		return hegel.Draw(ht, hegel.SampledFrom(held))
	case "let go of":
		return hegel.Draw(ht, hegel.SampledFrom(retired))
	}
	return strayedSPI + hegel.Draw(ht, pbt.Spanning(uint32(0), 3))
}
