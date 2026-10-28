// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/netstack"
)

// traceClient is a client of a mesh with no tun, recording its events on its own bus
func traceClient(t *testing.T) (*Client, *events.Bus) {
	t.Helper()
	bus := events.New()
	c := &Client{Mesh: netstack.NewRoutesOnly(), events: bus}
	t.Cleanup(c.Mesh.Close)
	return c, bus
}

// a trace is recorded as it opens, with its filter, rate and payload, and as it closes, with why and what it took and refused
// a trace the daemon's stop closes says so, whatever the stream says ended it
// the mesh holds no tracer once both closed
func TestTraceIsRecordedAsItOpensAndCloses(t *testing.T) {
	c, bus := traceClient(t)
	query := control.TraceQuery{
		Destinations: []netip.Prefix{netip.MustParsePrefix("192.0.2.3/32"), netip.MustParsePrefix("3fff::3/128")},
		Decision:     "forward", Peer: "example/gateway", Rate: control.TraceRateDefault, Payload: 64,
	}
	trace, err := c.openTrace(t.Context(), query)
	if err != nil {
		t.Fatal(err)
	}
	trace.Close("the reader left")
	every, err := c.openTrace(t.Context(), control.TraceQuery{Rate: control.TraceRateMin})
	if err != nil {
		t.Fatal(err)
	}
	if n := c.Mesh.TraceClients(); n != 1 {
		t.Errorf("the mesh holds %d traces with one closed and one open, want the open one", n)
	}
	c.Mesh.Close()
	every.Close("the reader left")
	if n := c.Mesh.TraceClients(); n != 0 {
		t.Errorf("the mesh holds %d traces once both closed", n)
	}

	var out strings.Builder
	var reasons []string
	for _, kind := range []string{"control.trace.started", "control.trace.ended"} {
		for _, event := range recorded(bus, kind) {
			if kind == "control.trace.ended" {
				reasons = append(reasons, event.Attrs["reason"])
			}
			event.Seq, event.At = 0, recordedAt
			control.RenderEvent(&out, event)
		}
	}
	if want := []string{"the reader left", "the daemon is stopping"}; !reflect.DeepEqual(reasons, want) {
		t.Errorf("the traces ended for %q, want %q", reasons, want)
	}
	verbGolden(t, "events-trace.txt", []byte(out.String()))
}

// a record's wire form carries each of its fields under its own name
func TestTracePacketCarriesEveryField(t *testing.T) {
	record := netstack.TraceRecord{
		Arrival: netstack.TraceArrivedSession, From: "example/gateway:0@1", Decision: netstack.TraceAnswer, Reason: "expired", Next: "example/relay:0@1",
		Segment: netip.MustParseAddr("3fff:0:0:b::46"), Source: netip.MustParseAddr("3fff::1"), Destination: netip.MustParseAddr("3fff::3"),
		Protocol: 17, Headers: []string{"hop-by-hop"}, Transport: true, SourcePort: 4000, DestinationPort: 9000, TCPFlags: 2, ICMPType: 3, ICMPCode: 4,
		HopLimit: 1, Length: 1280, Fragments: 2, Answer: "expired", Outcome: netstack.TraceWithheld, Payload: []byte{0x60, 0},
	}
	want := control.TracePacket{
		Arrival: "session", From: "example/gateway:0@1", Decision: "answer", Reason: "expired", Next: "example/relay:0@1",
		Segment: record.Segment, Source: record.Source, Destination: record.Destination,
		Protocol: 17, Headers: []string{"hop-by-hop"}, Transport: true, SourcePort: 4000, DestinationPort: 9000, TCPFlags: 2, ICMPType: 3, ICMPCode: 4,
		HopLimit: 1, Length: 1280, Fragments: 2, Answer: "expired", Outcome: "withheld", Payload: []byte{0x60, 0},
	}
	if got := (*clientTrace)(nil).Packet(record); !reflect.DeepEqual(got, want) {
		t.Errorf("the record reads on the wire as %+v, want %+v", got, want)
	}
	// every field of the record is set above, so a field the wire form leaves out shows as a zero here
	value := reflect.ValueOf(want)
	for i := range value.NumField() {
		if value.Field(i).IsZero() {
			t.Errorf("the wire form's %s is not set from the record", value.Type().Field(i).Name)
		}
	}
	if n, m := reflect.TypeFor[netstack.TraceRecord]().NumField(), reflect.TypeFor[control.TracePacket]().NumField(); n != m {
		t.Errorf("the record has %d fields and its wire form %d", n, m)
	}
}
