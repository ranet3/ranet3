// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package userspace

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// echoModel is RFC 5508's NAT as the echo relay must behave: one mapping per
// leaf address and identifier, ended a minute after its last request or
// reply, every source within its share of the flows
type echoModel struct {
	now      time.Duration
	share    int
	mappings map[echoKey]time.Duration
}

// send moves the model as a request from key does, and reports whether a
// mapping takes it
func (m *echoModel) send(key echoKey) bool {
	if _, ok := m.mappings[key]; !ok {
		held := 0
		for other := range m.mappings {
			if other.leaf == key.leaf {
				held++
			}
		}
		if held >= m.share {
			return false
		}
	}
	m.mappings[key] = m.now
	return true
}

func (m *echoModel) advance(d time.Duration) {
	m.now += d
	for key, last := range m.mappings {
		if last <= m.now-time.Minute {
			delete(m.mappings, key)
		}
	}
}

// for any order of echo requests from a few leaf addresses and identifiers
// to a few servers, and time passing, the relay's mappings are the model's:
// the same leaves and identifiers live, no two live mappings on one outside
// identifier, a reply delivered, to its own leaf with its own identifier and
// sequence number, exactly where a mapping took its request, and a request
// past the share answered past the limit. The servers are addresses of the
// loopback's network, whose kernel answers each echo.
func TestEchoIdentifiersAreTheModels(t *testing.T) {
	servers := []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("127.0.0.3")}
	for _, server := range servers {
		_ = loopbackServer(t, server)
	}
	ids := freeIdentifiers(t, false, 2)
	leaves := []netip.Addr{leaf4, other4}
	delays := []time.Duration{time.Second, 30 * time.Second, 59 * time.Second, 61 * time.Second}
	pbt.Check(t, func(ht *hegel.T) {
		share := hegel.Draw(ht, pbt.Spanning(1, 3))
		h := newRelayHarness(t, func(_ *Runtime, cfg *egress.Egress) { cfg.FlowsPerSource = uint32(share) })
		defer closeWithin(t, h.x)
		model := &echoModel{share: share, mappings: map[echoKey]time.Duration{}}
		for step := range hegel.Draw(ht, hegel.Integers(1, 20)) {
			if hegel.Draw(ht, hegel.Integers(0, 2)) == 0 {
				d := delays[hegel.Draw(ht, hegel.Integers(0, len(delays)-1))]
				model.advance(d)
				h.advance(d)
			} else {
				key := echoKey{leaves[hegel.Draw(ht, hegel.Integers(0, len(leaves)-1))], ids[hegel.Draw(ht, hegel.Integers(0, len(ids)-1))]}
				server := servers[hegel.Draw(ht, hegel.Integers(0, len(servers)-1))]
				seq, payload := uint16(step+1), fmt.Appendf(nil, "step %d", step)
				answered := len(h.mesh.answered())
				admitted := model.send(key)
				h.x.echo.take(ipPacket(key.leaf, server, protoICMP, echoRequest(key.leaf, server, key.id, seq, payload)))
				if !admitted {
					if answers := h.mesh.answered(); len(answers) != answered+1 || answers[answered].kind != netstack.ExitPastLimit {
						ht.Fatalf("step %d: %v past its share of %d answered %v, want one past the limit", step, key, share, answers[answered:])
					}
				} else if raw := h.nextLaid(ht, fmt.Sprintf("step %d: reply to %v", step, key)); !isEchoReply(raw, server, key.leaf, key.id, seq, payload) {
					p, _ := parse(raw)
					ht.Fatalf("step %d: laid %s, want the reply from %s to %s identifier %d sequence %d", step, p, server, key.leaf, key.id, seq)
				}
			}
			checkEchoMappings(ht, step, h, model)
		}
	})
}

// checkEchoMappings fails ht where the relay's live mappings are not the
// model's, two hold one outside identifier, or the flows held are not theirs
func checkEchoMappings(ht *hegel.T, step int, h *relayHarness, model *echoModel) {
	h.x.echo.mu.Lock()
	defer h.x.echo.mu.Unlock()
	outside := map[uint16]echoKey{}
	for key, m := range h.x.echo.mappings {
		if _, ok := model.mappings[key]; !ok {
			ht.Fatalf("step %d: %v holds a mapping the model ended or refused", step, key)
		}
		id := boundIdentifier(ht, m.socket)
		if other, taken := outside[id]; taken {
			ht.Fatalf("step %d: %v and %v both hold identifier %d", step, key, other, id)
		}
		outside[id] = key
	}
	if len(h.x.echo.mappings) != len(model.mappings) {
		ht.Fatalf("step %d: %d mappings live, the model %d", step, len(h.x.echo.mappings), len(model.mappings))
	}
	h.x.flows.mu.Lock()
	defer h.x.flows.mu.Unlock()
	if h.x.flows.open != len(model.mappings) {
		ht.Fatalf("step %d: %d flows held, the mappings %d", step, h.x.flows.open, len(model.mappings))
	}
}
