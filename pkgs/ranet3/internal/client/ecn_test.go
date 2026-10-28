// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/esp"
	"ranet3.com/pkgs/ranet3/internal/bubble"
	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/packet"
)

// ecnSession is one session's emit on a node built by hand, with the SA its peer seals with
type ecnSession struct {
	emit   func([]inboundDecrypted, []inboundECN)
	tunnel *tunnel
	remote *esp.OutboundSA
}

// ecnNode is a node built by hand with an event bus, which a status reads whole
func ecnNode(t *testing.T) *Client {
	t.Helper()
	c := writable(t)
	c.events = events.New()
	return c
}

// espCounts is c's ESP counters as ranet3 status reads them, each checked against the metric that carries it
func espCounts(t *testing.T, c *Client) control.ESPCounters {
	t.Helper()
	counts := c.Status().ESP
	var scraped bytes.Buffer
	c.Metrics(&scraped)
	for name, value := range map[string]uint64{
		"ranet3_esp_inbound_packets_total":    counts.InboundPackets,
		"ranet3_esp_inbound_dropped_total":    counts.InboundDropped,
		"ranet3_esp_inbound_ce_total":         counts.InboundCE,
		"ranet3_esp_inbound_ecn_unused_total": counts.InboundECNUnused,
	} {
		if line := fmt.Sprintf("\n%s %d\n", name, value); !strings.Contains(scraped.String(), line) {
			t.Errorf("the scrape does not read %q, which ranet3 status reads", strings.TrimSpace(line))
		}
	}
	return counts
}

// newECNSession opens a session at path on c, whose SA is child's
func newECNSession(t *testing.T, c *Client, path string, child esp.ChildSA) *ecnSession {
	t.Helper()
	peer := netstack.NewPeer(path, func(int) (netstack.BatchSealer, error) { return nil, errors.New("this peer sends nothing") },
		func([][]byte) error { return nil }, nil)
	t.Cleanup(peer.Close)
	session := &ecnSession{emit: c.inboundEmit(path, func() {}, peer), tunnel: &tunnel{replayWindow: 4096}, remote: remoteSA(t, child)}
	if err := session.tunnel.install(child); err != nil {
		t.Fatal(err)
	}
	return session
}

// receive seals each of inner as the peer does, decrypts them as the session does and hands them to its emit beside outer, and returns each inner packet as the emit left it
func (s *ecnSession) receive(t *testing.T, inner [][]byte, outer []inboundECN) [][]byte {
	t.Helper()
	datagrams := make([][]byte, len(inner))
	for i, p := range inner {
		nextHeader := byte(esp.NextHeaderIPv4)
		if p[0]>>4 == 6 {
			nextHeader = esp.NextHeaderIPv6
		}
		var err error
		if datagrams[i], err = s.remote.Seal(p, nextHeader); err != nil {
			t.Fatal(err)
		}
	}
	results := s.tunnel.decryptBatch(datagrams, nil)
	s.emit(results, outer)
	left := make([][]byte, len(results))
	for i := range results {
		if plain, _, err := results[i].Plaintext(); err == nil {
			left[i], _ = packet.Payload(plain)
		}
	}
	return left
}

// ecnPacket is a UDP packet of the IP version given with the ECN field field under the DSCP 0x2e, id telling it apart
// an IPv4 one carries a valid header checksum
func ecnPacket(version int, field packet.ECN, id uint16) []byte {
	if version == 4 {
		p := make([]byte, 20+8+4)
		p[0], p[1], p[8], p[9] = 0x45, 0xb8|byte(field), 64, 17
		binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
		binary.BigEndian.PutUint16(p[4:], id)
		copy(p[12:], []byte{192, 0, 2, 1, 198, 51, 100, 1})
		binary.BigEndian.PutUint16(p[10:], ^uint16(packet.Sum(0, p[:20])))
		binary.BigEndian.PutUint16(p[20:], 40000)
		binary.BigEndian.PutUint16(p[22:], 9)
		binary.BigEndian.PutUint16(p[24:], 12)
		return p
	}
	p := make([]byte, 40+8+4)
	binary.BigEndian.PutUint32(p, 6<<28|uint32(0xb8|field)<<20|uint32(id))
	binary.BigEndian.PutUint16(p[4:], 12)
	p[6], p[7] = 17, 64
	copy(p[8:], []byte{0x20, 0x01, 0x0d, 0xb8, 15: 1})
	copy(p[24:], []byte{0x20, 0x01, 0x0d, 0xb8, 15: 2})
	binary.BigEndian.PutUint16(p[40:], 40000)
	binary.BigEndian.PutUint16(p[42:], 9)
	binary.BigEndian.PutUint16(p[44:], 12)
	return p
}

// fieldOf is the ECN field of p, read from its own bits rather than through packet.ECNOf
func fieldOf(p []byte) packet.ECN {
	if p[0]>>4 == 4 {
		return packet.ECN(p[1] & 0b11)
	}
	return packet.ECN(binary.BigEndian.Uint32(p) >> 20 & 0b11)
}

// an inner ECT(0) packet of each family whose datagram arrived CE leaves the emit CE, the IPv4 one with a valid checksum, and both count as marked
func TestOuterCEMarksAnECTInnerPacket(t *testing.T) {
	bubble.Run(func(t *testing.T) {
		c := ecnNode(t)
		session := newECNSession(t, c, "example/gateway:0@0", tunnelChild(1))
		left := session.receive(t, [][]byte{ecnPacket(4, packet.ECT0, 1), ecnPacket(6, packet.ECT0, 2)}, []inboundECN{packet.CE, packet.CE})
		for i, p := range left {
			if p == nil {
				t.Fatalf("packet %d did not come through", i)
			}
			if got := fieldOf(p); got != packet.CE {
				t.Errorf("an inner ECT(0) IPv%d packet under an outer CE left %s", p[0]>>4, got)
			}
		}
		if left[0] != nil && packet.Sum(0, left[0][:20]) != 0xffff {
			t.Error("the IPv4 packet's header checksum fails once it is marked")
		}
		if counts := espCounts(t, c); counts.InboundCE != 2 || counts.InboundPackets != 2 {
			t.Errorf("%d packets counted marked and %d delivered, want 2 and 2", counts.InboundCE, counts.InboundPackets)
		}
	})(t)
}

// an inner Not-ECT packet whose datagram arrived CE is dropped and counted with the reason, and one beside it under ECT(0) goes on Not-ECT
func TestOuterCEOverNotECTIsDropped(t *testing.T) {
	bubble.Run(func(t *testing.T) {
		written := capturedLog(t)
		c := ecnNode(t)
		session := newECNSession(t, c, "example/gateway:0@0", tunnelChild(1))
		left := session.receive(t, [][]byte{ecnPacket(4, packet.NotECT, 1), ecnPacket(6, packet.NotECT, 2)}, []inboundECN{packet.CE, packet.ECT0})
		if counts := espCounts(t, c); counts.InboundDropped != 1 || counts.InboundPackets != 1 || counts.InboundECNUnused != 2 {
			t.Errorf("%d packets counted dropped, %d delivered and %d with an unused combination, want 1, 1 and 2", counts.InboundDropped, counts.InboundPackets, counts.InboundECNUnused)
		}
		if written.count(errECNDropped.Error()) != 1 {
			t.Errorf("the drop was not reported with its reason %q", errECNDropped)
		}
		if left[1] == nil || fieldOf(left[1]) != packet.NotECT {
			t.Error("an inner Not-ECT packet under an outer ECT(0) did not go on Not-ECT")
		}
	})(t)
}

// an outer ECT(0) over an inner ECT(1), Figure 4's (!) cell, is counted for each packet and recorded with a count, both fields and the first packet's header
// at most once an interval for each session, in an event and in a debug log line
func TestUnusedECNCombinationIsRecordedOncePerInterval(t *testing.T) {
	bubble.Run(func(t *testing.T) {
		written := capturedLog(t)
		level := slog.SetLogLoggerLevel(slog.LevelDebug)
		t.Cleanup(func() { slog.SetLogLoggerLevel(level) })
		c := ecnNode(t)
		gateway := newECNSession(t, c, "example/gateway:0@0", tunnelChild(1))
		relay := newECNSession(t, c, "example/relay:0@0", tunnelChild(2))
		burst := func(session *ecnSession, from uint16, count int) [][]byte {
			inner := make([][]byte, count)
			outer := make([]inboundECN, count)
			for i := range inner {
				inner[i], outer[i] = ecnPacket(4, packet.ECT1, from+uint16(i)), packet.ECT0
			}
			for _, p := range session.receive(t, inner, outer) {
				if p == nil || fieldOf(p) != packet.ECT1 {
					t.Error("an inner ECT(1) packet under an outer ECT(0) did not go on ECT(1)")
				}
			}
			return inner
		}
		type record struct {
			peer, count, header string
		}
		recordsOf := func() []record {
			var out []record
			for _, event := range recorded(c.events, "esp.ecn.unused") {
				if event.Attrs["outer"] != "ECT(0)" || event.Attrs["inner"] != "ECT(1)" {
					t.Errorf("the record names the outer %q and the inner %q, want ECT(0) and ECT(1)", event.Attrs["outer"], event.Attrs["inner"])
				}
				out = append(out, record{event.Peer, event.Attrs["count"], event.Attrs["header"]})
			}
			return out
		}
		header := func(p []byte) string { return hex.EncodeToString(p[:20]) }

		first := burst(gateway, 1, 3)
		second := burst(gateway, 10, 2)
		relayed := burst(relay, 20, 1)
		want := []record{{"example/gateway:0@0", "3", header(first[0])}, {"example/relay:0@0", "1", header(relayed[0])}}
		if got := recordsOf(); !slices.Equal(got, want) {
			t.Fatalf("within one interval the records are %+v, want %+v", got, want)
		}
		time.Sleep(espDropReportInterval)
		burst(gateway, 30, 1)
		want = append(want, record{"example/gateway:0@0", "3", header(second[0])})
		if got := recordsOf(); !slices.Equal(got, want) {
			t.Errorf("an interval later the records are %+v, want %+v", got, want)
		}
		if got := espCounts(t, c).InboundECNUnused; got != 7 {
			t.Errorf("%d packets counted with an unused combination, want 7", got)
		}
		if got := written.count("ecn combination no tunnel sends"); got != 3 {
			t.Errorf("%d debug lines for 3 records", got)
		}
	})(t)
}

// a batch whose datagrams all arrived Not-ECT, handed as nil, leaves every byte of every packet as it was, after a batch that marked
func TestNotECTBatchIsLeftAlone(t *testing.T) {
	bubble.Run(func(t *testing.T) {
		c := ecnNode(t)
		session := newECNSession(t, c, "example/gateway:0@0", tunnelChild(1))
		session.receive(t, [][]byte{ecnPacket(4, packet.ECT0, 1), ecnPacket(6, packet.ECT0, 2)}, []inboundECN{packet.CE, packet.CE})
		sent := [][]byte{ecnPacket(4, packet.ECT0, 3), ecnPacket(6, packet.ECT1, 4)}
		for i, p := range session.receive(t, sent, nil) {
			if !bytes.Equal(p, sent[i]) {
				t.Errorf("packet %d left the emit as % x, sent as % x", i, p, sent[i])
			}
		}
	})(t)
}
