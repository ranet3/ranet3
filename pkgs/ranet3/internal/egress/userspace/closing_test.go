// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package userspace

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"

	"ranet3.com/pkgs/ranet3/internal/egress"
)

func closingResponse(t *testing.T, h *relayHarness, c *leafConn, want []byte) {
	t.Helper()
	h.x.link.deliver(leafSegment(c.leaf, c.server, c.seq, c.ack, tcpACK, 65535, nil))
	var got []byte
	for {
		raw := h.waitLaid(t, "response data or FIN", func(raw []byte) bool {
			p, ok := parse(raw)
			return ok && p.protocol == protoTCP && netip.AddrPortFrom(p.dst, p.dstPort) == c.leaf && (p.payload > 0 || p.flags&(tcpFIN|tcpRST) != 0)
		})
		p, _ := parse(raw)
		if p.flags&tcpRST != 0 {
			t.Fatalf("response reset after %d of %d bytes", len(got), len(want))
		}
		if p.seq == c.ack {
			got = append(got, raw[len(raw)-p.payload:]...)
			c.ack += uint32(p.payload)
			if p.flags&tcpFIN != 0 {
				c.ack++
			}
		}
		h.x.link.deliver(tcpSegment(c.leaf, c.server, c.seq, c.ack, tcpACK, nil))
		if p.flags&tcpFIN != 0 && c.ack == p.seq+uint32(p.payload)+1 {
			break
		}
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("response is %d bytes, want all %d bytes unchanged", len(got), len(want))
	}
}

func closingConnection(t *testing.T, h *relayHarness, state tcp.EndpointState, window uint16, response []byte) (*leafConn, *tcpFlow) {
	t.Helper()
	allowLoopback(t, h.x.stack)
	start, stop := make(chan struct{}), make(chan struct{})
	release := sync.OnceFunc(func() { close(start) })
	end := sync.OnceFunc(func() { close(stop) })
	server := tcpServer(t, netip.MustParseAddr("127.0.0.1"), func(conn *net.TCPConn) {
		_ = conn.SetDeadline(time.Now().Add(exitWait))
		select {
		case <-start:
		case <-stop:
			_ = conn.Close()
			return
		}
		if _, err := conn.Write(response); err != nil {
			_ = conn.Close()
			return
		}
		if state == tcp.StateEstablished {
			<-stop
			_ = conn.Close()
			return
		}
		_ = conn.CloseWrite()
		readsToTheEnd(conn)
	})
	t.Cleanup(end)
	t.Cleanup(release)
	c := h.open(t, netip.AddrPortFrom(leaf4, 41100), server)
	f := listedFlow(t, h)
	t.Cleanup(f.ep.Abort)
	if state == tcp.StateLastAck {
		h.x.link.deliver(leafSegment(c.leaf, c.server, c.seq, c.ack, tcpACK|tcpFIN, window, nil))
		c.seq++
		waitFor(t, "leaf FIN", func() bool { return tcp.EndpointState(f.ep.State()) == tcp.StateCloseWait })
	} else {
		// an acknowledged byte orders the window update before the server writes
		h.x.link.deliver(leafSegment(c.leaf, c.server, c.seq, c.ack, tcpACK, window, []byte{1}))
		c.seq++
		h.waitLaid(t, "window update acknowledgment", func(raw []byte) bool {
			p, ok := parse(raw)
			return ok && p.protocol == protoTCP && p.ack == c.seq
		})
	}
	release()
	if state == tcp.StateClosing {
		waitFor(t, "server FIN", func() bool { return tcp.EndpointState(f.ep.State()) == tcp.StateFinWait1 })
		h.x.link.deliver(leafSegment(c.leaf, c.server, c.seq, c.ack, tcpACK|tcpFIN, window, nil))
		c.seq++
	}
	waitFor(t, state.String(), func() bool { return tcp.EndpointState(f.ep.State()) == state })
	return c, f
}

type closingOrder struct {
	state           tcp.EndpointState
	zeroWindow      bool
	reset           bool
	finishBeforeCap bool
}

func closingSequence(t *testing.T, order closingOrder) {
	t.Helper()
	h := newRelayHarness(t, func(rt *Runtime, _ *egress.Egress) {
		rt.Limits.TimeWait, rt.Limits.Connections = 1, 2
	})
	response := bytes.Repeat([]byte("response"), 750)
	window := uint16(65535)
	if order.zeroWindow {
		window = 0
	}
	a, flow := closingConnection(t, h, order.state, window, response)
	var timeout tcpip.TCPUserTimeoutOption
	waitFor(t, "closing wait after relay end", func() bool {
		return flow.ep.GetSockOpt(&timeout) == nil && timeout != 0
	})
	if aborted := h.x.tcp.closed.add(flow.ep.(*tcp.Endpoint)); aborted != 0 {
		t.Fatalf("closing endpoint aborted %d endpoints for room", aborted)
	}
	if got := h.x.tcp.held(); got != [3]int{0, 1, 1} {
		t.Fatalf("closing endpoint holds %v, want [0 1 1]", got)
	}
	if status := h.x.Status().Flows; status.TCP[0] != 1 || status.TimeWait != 0 || status.Closed != 0 {
		t.Fatalf("closing status: TCP %v, TIME_WAIT %d, closed early %d", status.TCP, status.TimeWait, status.Closed)
	}
	complete := func() {
		if order.reset {
			h.x.link.deliver(tcpSegment(a.leaf, a.server, a.seq, a.ack, tcpRST|tcpACK, nil))
		} else {
			closingResponse(t, h, a, response)
		}
		h.waitConnections(t, 0)
		want := tcp.StateTimeWait
		if order.state == tcp.StateLastAck {
			want = tcp.StateClose
		}
		if order.reset {
			want = tcp.StateError
		}
		if got := tcp.EndpointState(flow.ep.State()); got != want {
			t.Fatalf("completed endpoint is %s, want %s", got, want)
		}
		if want == tcp.StateTimeWait {
			h.x.tcp.closed.mu.Lock()
			queued := len(h.x.tcp.closed.queue) == 1 && h.x.tcp.closed.queue[0] == flow.ep
			h.x.tcp.closed.mu.Unlock()
			if !queued {
				t.Fatal("the completed closing endpoint is absent from the TIME_WAIT queue")
			}
		}
		if h.x.flows.open != 0 {
			t.Fatalf("completed endpoint retains %d flows", h.x.flows.open)
		}
	}
	if order.finishBeforeCap {
		complete()
	}
	other := tcpServer(t, netip.MustParseAddr("127.0.0.1"), func(conn *net.TCPConn) { _ = conn.Close() })
	var oldest *tcp.Endpoint
	for i := range 2 {
		b := h.open(t, netip.AddrPortFrom(other4, uint16(41200+i)), other)
		if !order.finishBeforeCap {
			h.waitConnections(t, 2)
			if reason := h.syn(t, netip.AddrPortFrom(other4, 41300), other); reason != reasonConnections {
				t.Fatalf("third open refused for %q, want connections", reason)
			}
		}
		h.closeAfter(t, b)
		want := 1
		if order.finishBeforeCap {
			want = 0
		}
		h.waitConnections(t, want)
		h.x.tcp.closed.mu.Lock()
		queue := h.x.tcp.closed.queue
		if len(queue) != 1 {
			h.x.tcp.closed.mu.Unlock()
			t.Fatalf("TIME_WAIT queue holds %d endpoints, want 1", len(queue))
		}
		latest := queue[0]
		h.x.tcp.closed.mu.Unlock()
		if i == 0 {
			if order.finishBeforeCap && order.state == tcp.StateClosing && !order.reset && tcp.EndpointState(flow.ep.State()) != tcp.StateError {
				t.Fatal("the cap retained the older endpoint that finished closing")
			}
			oldest = latest
		} else if oldest.EndpointState() == tcp.StateTimeWait || latest.EndpointState() != tcp.StateTimeWait {
			t.Fatal("cap did not retain the newest TIME_WAIT endpoint")
		}
		if !order.finishBeforeCap && tcp.EndpointState(flow.ep.State()) != order.state {
			t.Fatalf("cap changed pending response from %s to %s", order.state, tcp.EndpointState(flow.ep.State()))
		}
	}
	if !order.finishBeforeCap {
		if got := h.x.counts.closed.Load(); got != 1 {
			t.Fatalf("closed early %d, want one TIME_WAIT endpoint", got)
		}
		complete()
	}
}

func TestClosingConnectionOrdersPreserveAdmissionAndDelivery(t *testing.T) {
	for _, state := range []tcp.EndpointState{tcp.StateLastAck, tcp.StateClosing} {
		for _, zeroWindow := range []bool{false, true} {
			for _, reset := range []bool{false, true} {
				for _, finishBeforeCap := range []bool{false, true} {
					order := closingOrder{state: state, zeroWindow: zeroWindow, reset: reset, finishBeforeCap: finishBeforeCap}
					t.Run(fmt.Sprintf("%s/zero_window_%t/reset_%t/finish_before_cap_%t", state, zeroWindow, reset, finishBeforeCap), func(t *testing.T) {
						closingSequence(t, order)
					})
				}
			}
		}
	}
}

func TestLastAckEndsWithoutAcknowledgments(t *testing.T) {
	closingTimeoutCase(t, tcp.StateLastAck, false)
}

func TestClosingEndsWithoutAcknowledgments(t *testing.T) {
	closingTimeoutCase(t, tcp.StateClosing, false)
}

func TestClosingEndsDespiteAcknowledgedProbes(t *testing.T) {
	for _, state := range []tcp.EndpointState{tcp.StateLastAck, tcp.StateClosing} {
		t.Run(state.String(), func(t *testing.T) {
			closingTimeoutCase(t, state, true)
		})
	}
}

func TestOpenZeroWindowHasNoClosingTimeout(t *testing.T) {
	closingTimeoutCase(t, tcp.StateEstablished, true)
}

func closingTimeoutCase(t *testing.T, state tcp.EndpointState, answerProbes bool) {
	t.Helper()
	clock := faketime.NewManualClock()
	clock.Advance(time.Second)
	h := newRelayHarnessOn(t, clock, nil)
	window := uint16(65535)
	if answerProbes {
		window = 0
		if state == tcp.StateEstablished {
			window = 1
		}
	}
	c, f := closingConnection(t, h, state, window, bytes.Repeat([]byte{'x'}, 3000))
	var option tcpip.TCPUserTimeoutOption
	if state == tcp.StateEstablished {
		h.waitLaid(t, "first server byte", func(raw []byte) bool {
			p, ok := parse(raw)
			return ok && p.protocol == protoTCP && p.seq == c.ack && p.payload == 1
		})
		c.ack++
		h.x.link.deliver(leafSegment(c.leaf, c.server, c.seq, c.ack, tcpACK, 0, nil))
		h.x.link.deliver(leafSegment(c.leaf, c.server, c.seq-1, c.ack, tcpACK, 0, []byte{1}))
		h.waitLaid(t, "closed window acknowledgment", func(raw []byte) bool {
			p, ok := parse(raw)
			return ok && p.protocol == protoTCP && p.payload == 0 && p.flags == tcpACK && p.ack == c.seq
		})
	} else {
		waitFor(t, "user timeout after copying", func() bool {
			return f.ep.GetSockOpt(&option) == nil && option != 0
		})
	}
	probes, resets := 0, 0
	began := clock.Now()
	receive := func() {
		for pkt := h.x.link.poll(); pkt != nil; pkt = h.x.link.poll() {
			view := pkt.ToView()
			p, ok := parse(view.AsSlice())
			view.Release()
			h.x.link.release(pkt)
			if !ok || p.protocol != protoTCP {
				continue
			}
			if p.flags&tcpRST != 0 {
				resets++
			}
			if answerProbes && p.payload == 1 && p.seq+1 == c.ack {
				if tcp.EndpointState(f.ep.State()) == tcp.StateError {
					t.Fatal("the endpoint ended before the leaf could answer its probe")
				}
				h.x.link.deliver(leafSegment(c.leaf, c.server, c.seq, c.ack, tcpACK, 0, nil))
				probes++
			}
		}
	}
	receive()
	horizon := tcp.DefaultKeepaliveIdle + tcp.DefaultKeepaliveInterval*tcp.DefaultKeepaliveCount
	until := horizon - time.Nanosecond
	if state == tcp.StateEstablished {
		until = horizon + tcp.MaxRTO
	}
	for elapsed := time.Duration(0); elapsed < until; {
		step := min(tcp.MaxRTO, until-elapsed)
		clock.Advance(step)
		elapsed += step
		got := tcp.EndpointState(f.ep.State())
		if !answerProbes && got == tcp.StateError {
			break
		}
		if got != state {
			t.Fatalf("endpoint ended at %s before %s: %s", elapsed, until, got)
		}
		before := probes
		receive()
		if probes != before {
			// the duplicate segment's ACK follows the queued probe replies
			flags, payload := byte(tcpACK|tcpFIN), []byte(nil)
			if state == tcp.StateEstablished {
				flags, payload = tcpACK, []byte{1}
			}
			h.x.link.deliver(leafSegment(c.leaf, c.server, c.seq-1, c.ack, flags, 0, payload))
			h.waitLaid(t, "probe replies processed", func(raw []byte) bool {
				p, ok := parse(raw)
				return ok && p.protocol == protoTCP && p.payload == 0 && p.flags == tcpACK && p.ack == c.seq
			})
		}
	}
	if state != tcp.StateEstablished {
		if answerProbes {
			if got := h.x.tcp.held(); got != [3]int{0, 1, 1} {
				t.Fatalf("before the user timeout holds %v, want [0 1 1]", got)
			}
			clock.Advance(time.Nanosecond)
		}
		if got := tcp.EndpointState(f.ep.State()); got != tcp.StateError {
			t.Fatalf("at the closing bound endpoint is %s, want ERROR", got)
		}
		receive()
	}
	if answerProbes && probes == 0 {
		t.Fatal("the leaf answered no zero-window probe")
	}
	if resets != 0 {
		t.Fatalf("timeout sent %d resets, want none", resets)
	}
	if state == tcp.StateEstablished {
		if err := f.ep.GetSockOpt(&option); err != nil || option != 0 {
			t.Fatalf("open zero-window connection has user timeout %s: %v", time.Duration(option), err)
		}
		if got := h.x.tcp.held(); got != [3]int{0, 1, 1} {
			t.Fatalf("open connection lost its charge: %v", got)
		}
	} else {
		h.waitConnections(t, 0)
		if got := h.x.tcp.held(); got != [3]int{} {
			t.Fatalf("timed-out connection retains charges: %v", got)
		}
		if n := h.x.stack.Stats().TCP.EstablishedTimedout.Value(); n != 1 {
			t.Fatalf("stack timed out %d connections, want 1", n)
		}
	}
	if got := h.x.counts.closed.Load(); got != 0 {
		t.Fatalf("closing bound counted %d early TIME_WAIT closes", got)
	}
	t.Logf("state %s, probes acknowledged %d, resets %d, stack elapsed %s", state, probes, resets, clock.Now().Sub(began))
}

func TestRelayEndDecidesHostBeforeLeaf(t *testing.T) {
	for _, host := range []struct {
		name     string
		platform *hostSockets
		held     int
	}{
		{"plain", nil, 0},
		{"closed", newFakeHostSockets(hostClosed).platform(), 0},
		{"last_ack", newFakeHostSockets(hostLastAck).platform(), 1},
		{"time_wait", newFakeHostSockets(hostTimeWait).platform(), 1},
	} {
		for _, withdraw := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/withdraw_%t", host.name, withdraw), func(t *testing.T) {
				h := newRelayHarness(t, func(rt *Runtime, _ *egress.Egress) {
					rt.Platform.hostSockets = host.platform
				})
				allowLoopback(t, h.x.stack)
				server := tcpServer(t, netip.MustParseAddr("127.0.0.1"), readsToTheEnd)
				c := h.open(t, netip.AddrPortFrom(leaf4, 41500), server)
				f := listedFlow(t, h)
				t.Cleanup(f.ep.Abort)
				mappings := &h.x.tcp.mappings
				mappings.mu.Lock()
				inside, outside := len(mappings.byInside), len(mappings.byOutside)
				mappings.mu.Unlock()
				if inside != 1 || outside != 1 {
					t.Fatalf("open connection has %d inside and %d outside mappings, want one of each", inside, outside)
				}
				h.x.link.deliver(tcpSegment(c.leaf, c.server, c.seq, c.ack, tcpACK|tcpFIN, nil))
				c.seq++
				c.ack = h.stackFIN(t, c)
				waitFor(t, "host decision before the last leaf ACK", func() bool {
					if host.held == 0 {
						return stillOpen(f.conn) != nil
					}
					status := h.x.Status().Flows.Host
					return status.Held == 1 && status.Ports == 1
				})
				waitFor(t, "host mapping returned while the leaf closes", func() bool {
					mappings.mu.Lock()
					defer mappings.mu.Unlock()
					return len(mappings.byInside) == 0 && len(mappings.byOutside) == 0
				})
				if state := tcp.EndpointState(f.ep.State()); state != tcp.StateLastAck || h.x.tcp.held() != [3]int{0, 1, 1} {
					t.Fatalf("leaf in %s holds %v, want LAST_ACK and [0 1 1]", state, h.x.tcp.held())
				}
				if status := h.x.Status().Flows; status.Host != nil && (status.Host.Held != host.held || status.Host.Ports != host.held) {
					t.Fatalf("host charge is %+v, want held and ports %d", status.Host, host.held)
				}
				if withdraw {
					h.x.tcp.withdraw()
				} else {
					h.x.link.deliver(tcpSegment(c.leaf, c.server, c.seq, c.ack, tcpACK, nil))
				}
				h.waitConnections(t, 0)
				want := tcp.StateClose
				if withdraw {
					want = tcp.StateError
				}
				if state := tcp.EndpointState(f.ep.State()); state != want {
					t.Fatalf("leaf ended in %s, want %s", state, want)
				}
				if open := stillOpen(f.conn) == nil; open != (host.held != 0) {
					t.Fatalf("host socket open: %t, want %t", open, host.held != 0)
				}
				if got := h.x.tcp.held(); got != [3]int{0, 0, host.held} {
					t.Fatalf("after the leaf ends charges are %v, want [0 0 %d]", got, host.held)
				}
			})
		}
	}
}

func TestHostPortAdmissionCountsSharedClosingSocketOnce(t *testing.T) {
	fake := newFakeHostSockets(hostClosed)
	h := newRelayHarness(t, func(rt *Runtime, cfg *egress.Egress) {
		rt.Platform.hostSockets = fake.platform()
		rt.Limits.Flows = 4
		cfg.FlowsPerSource = 4
	})
	allowLoopback(t, h.x.stack)
	server := tcpServer(t, netip.MustParseAddr("127.0.0.1"), readsToTheEnd)
	a := h.open(t, netip.AddrPortFrom(leaf4, 41502), server)
	f := listedFlow(t, h)
	t.Cleanup(f.ep.Abort)
	fake.set(f.conn, hostTimeWait)
	h.x.link.deliver(tcpSegment(a.leaf, a.server, a.seq, a.ack, tcpACK|tcpFIN, nil))
	a.seq++
	h.stackFIN(t, a)
	waitFor(t, "host held while leaf closes", func() bool {
		status := h.x.Status().Flows.Host
		return status != nil && status.Held == 1 && status.Ports == 1
	})

	b := h.open(t, netip.AddrPortFrom(leaf4, 41503), server)
	t.Cleanup(func() {
		h.x.link.deliver(tcpSegment(b.leaf, b.server, b.seq, b.ack, tcpACK|tcpRST, nil))
	})
	if got := h.x.Status().Flows.Host; got == nil || *got != (egress.HostHold{Held: 1, Ports: 2, Bound: 2}) {
		t.Fatalf("one held socket and one new connection count %+v, want 2 host ports of 2", got)
	}
}

func TestHostHoldEndsWhileLeafKeepsItsFlow(t *testing.T) {
	hostHoldEndsWhileLeafCloses(t, newFakeHostSockets(hostTimeWait).platform())
}

func hostHoldEndsWhileLeafCloses(t *testing.T, platform *hostSockets) {
	t.Helper()
	msl, err := platform.msl()
	if err != nil {
		t.Fatal(err)
	}
	h, _, _ := holdHarness(t, platform)
	server := tcpServer(t, netip.MustParseAddr("127.0.0.1"), readsToTheEnd)
	c := h.open(t, netip.AddrPortFrom(leaf4, 41501), server)
	f := listedFlow(t, h)
	t.Cleanup(f.ep.Abort)
	h.x.link.deliver(tcpSegment(c.leaf, c.server, c.seq, c.ack, tcpACK|tcpFIN, nil))
	c.seq++
	c.ack = h.stackFIN(t, c)
	waitFor(t, "the host's hold", func() bool {
		host := h.x.Status().Flows.Host
		return host.Held == 1 && host.Ports == 1
	})
	if state, err := h.x.tcp.holds.state(f.conn); err != nil || state != hostTimeWait {
		t.Fatalf("held host state %v: %v, want TIME_WAIT", state, err)
	}
	h.advance(2*msl - time.Nanosecond)
	if err := stillOpen(f.conn); err != nil {
		t.Fatalf("host closed before its hold ended: %v", err)
	}
	h.advance(time.Nanosecond)
	h.advance(platform.margin - time.Nanosecond)
	if stillOpen(f.conn) == nil || h.x.flows.heldCount() != 1 {
		t.Fatal("host socket did not close with its slot kept through the margin")
	}
	h.advance(time.Nanosecond)
	if host := h.x.Status().Flows.Host; host.Held != 0 || host.Ports != 0 {
		t.Fatalf("host's clock left a charge: %+v", host)
	}
	if got := h.x.tcp.held(); got != [3]int{0, 1, 1} {
		t.Fatalf("host's clock released the leaf's charge: %v", got)
	}
	if state := tcp.EndpointState(f.ep.State()); state != tcp.StateLastAck {
		t.Fatalf("host's clock ended the leaf in %s", state)
	}
	h.x.link.deliver(tcpSegment(c.leaf, c.server, c.seq, c.ack, tcpACK, nil))
	h.waitConnections(t, 0)
	if got := h.x.tcp.held(); got != [3]int{} {
		t.Fatalf("leaf's ACK retained a charge: %v", got)
	}
}
