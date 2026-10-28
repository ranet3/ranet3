// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package ike

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"ranet3.com/pkgs/ranet3/internal/bubble"
	"ranet3.com/pkgs/ranet3/transport"
)

const (
	// strayedSPI is an SPI no Child SA of the tests' sessions holds
	strayedSPI = 0x2000
	// pastReportInterval outlasts the interval the hub hands a session at most one unknown SPI in
	pastReportInterval = 11 * time.Second
	// reportRetransmit is the first wait before a report goes again, short so its attempts run out within answerBudget
	reportRetransmit = 10 * time.Millisecond
)

// strayESP has peer send the session's hub ESP on spi
func strayESP(t *testing.T, s *Session, peer *transport.MemoryConn, spi uint32) {
	t.Helper()
	datagram := binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, spi), 1)
	if _, err := peer.WriteToUDP(datagram, muxLoopback(s.mux)); err != nil {
		t.Fatal(err)
	}
}

// reportingSession is a probedSession that takes its peer's answers and a local request, run until the test ends
func reportingSession(t *testing.T) (*Session, *transport.MemoryConn, *recorder) {
	t.Helper()
	s, peer, events := probedSession(t)
	s.requests = make(chan *localRequest, 1)
	if err := s.mux.RegisterIKE(s.current.spiI); err != nil {
		t.Fatal(err)
	}
	return s, peer, events
}

// readReport reads the next request s sends peer, checks it is an INFORMATIONAL request telling of spi alone, and answers it and its header
func readReport(t *testing.T, s *Session, peer *transport.MemoryConn, spi uint32) ([]byte, Header) {
	t.Helper()
	raw, header, inner := readOwnRequest(t, s, peer)
	if header.ExchangeType != INFORMATIONAL || len(inner) != 1 || inner[0].Type != PayloadN {
		t.Fatalf("the session sent exchange %d carrying %v, want an INFORMATIONAL request with one Notify payload", header.ExchangeType, inner)
	}
	notify, err := DecodeNotify(inner[0].Body)
	if err != nil {
		t.Fatal(err)
	}
	if notify.Type != N_INVALID_SPI || len(inner[0].Body) != 8 || notify.Protocol != 0 || len(notify.SPI) != 0 || !slices.Equal(notify.Data, binary.BigEndian.AppendUint32(nil, spi)) {
		t.Errorf("the session sent notify %d, Protocol ID %d, SPI %x and data %x, want INVALID_SPI, Protocol ID 0, no SPI and data %08x", notify.Type, notify.Protocol, notify.SPI, notify.Data, spi)
	}
	return raw, header
}

// RFC 7296 section 1.5: "it MAY send an INVALID_SPI notification of the wayward packet over that IKE SA in an INFORMATIONAL exchange. The Notification Data contains the SPI of the invalid packet."
// section 3.10: "If the SPI field is empty, this field MUST be sent as zero and MUST be ignored on receipt."
func TestInvalidSPINotifyCarriesTheSPIAsData(t *testing.T) {
	bubble.Run(func(t *testing.T) {
		s, peer, _ := reportingSession(t)
		runSession(t, s)
		strayESP(t, s, peer, strayedSPI)
		readReport(t, s, peer, strayedSPI)
	})(t)
}

// RFC 7296 section 2.3: "An IKE endpoint MUST wait for a response to each of its messages before sending a subsequent message"
// a report while a liveness check, a Child SA rekey or a Delete is outstanding, or while the IKE SA's rekey holds every other request, sends nothing
// the outstanding request is answered as it would have been, and the hub's next report after its interval sends one request
func TestInvalidSPIReportWaitsForNoRequest(t *testing.T) {
	t.Run("a liveness check outstanding", bubble.Run(func(t *testing.T) {
		s, peer, _ := reportingSession(t)
		runSession(t, s)
		s.Probe()
		check := readRequest(t, s, peer)
		strayESP(t, s, peer, strayedSPI)
		if got := peerReads(t, peer, quietPeriod); len(got) != 0 {
			t.Errorf("ESP on an unknown SPI came while a liveness check was outstanding, yet the session sent %d datagrams", len(got))
		}
		header, err := decodeHeader(check)
		if err != nil {
			t.Fatal(err)
		}
		answerOwnRequest(t, s, peer, *header, nil)
		time.Sleep(pastReportInterval)
		strayESP(t, s, peer, strayedSPI)
		readReport(t, s, peer, strayedSPI)
		if got := peerReads(t, peer, quietPeriod); len(got) != 0 {
			t.Errorf("one report was due, yet the session sent %d datagrams more", len(got))
		}
	}))
	for _, outstanding := range []struct {
		name     string
		exchange ExchangeType
		inner    []RawPayload
	}{
		{"a Child SA rekey outstanding", CREATE_CHILD_SA, nil},
		{"a Delete outstanding", INFORMATIONAL, []RawPayload{{Type: PayloadD, Body: EncodeDelete(Delete{Protocol: ProtoESP, SPIs: [][]byte{{0, 0, 0, 9}}})}}},
	} {
		t.Run(outstanding.name, bubble.Run(func(t *testing.T) {
			s, peer, _ := reportingSession(t)
			runSession(t, s)
			answered := make(chan error, 1)
			go func() {
				_, err := s.request(outstanding.exchange, outstanding.inner)
				answered <- err
			}()
			_, header, _ := readOwnRequest(t, s, peer)
			strayESP(t, s, peer, strayedSPI)
			if got := peerReads(t, peer, quietPeriod); len(got) != 0 {
				t.Errorf("ESP on an unknown SPI came with exchange %d outstanding, yet the session sent %d datagrams", outstanding.exchange, len(got))
			}
			answerOwnRequest(t, s, peer, header, nil)
			select {
			case err := <-answered:
				if err != nil {
					t.Errorf("the outstanding exchange ended with %v, want its answer", err)
				}
			case <-time.After(answerBudget):
				t.Error("the outstanding exchange never took its answer")
			}
		}))
	}
	t.Run("the IKE SA's rekey holding requests", bubble.Run(func(t *testing.T) {
		s, peer, _ := reportingSession(t)
		s.quiet.Store(true)
		runSession(t, s)
		strayESP(t, s, peer, strayedSPI)
		if got := peerReads(t, peer, quietPeriod); len(got) != 0 {
			t.Errorf("ESP on an unknown SPI came while the IKE SA's rekey held every other request, yet the session sent %d datagrams", len(got))
		}
		s.quiet.Store(false)
		time.Sleep(pastReportInterval)
		strayESP(t, s, peer, strayedSPI)
		readReport(t, s, peer, strayedSPI)
	}))
}

// RFC 7296 section 2.1: "A retransmission from the initiator MUST be bitwise identical to the original request."
// the report is the session's outstanding request: unanswered it goes again as it went, and the peer's refusal of it is read as a refused liveness check's and settles it
func TestInvalidSPIReportIsSentAgainUntilAnswered(t *testing.T) {
	bubble.Run(func(t *testing.T) {
		lines := recordLines(t)
		s, peer, _ := reportingSession(t)
		s.retransmitAfter = reportRetransmit
		done := runSession(t, s)
		strayESP(t, s, peer, strayedSPI)
		raw, header := readReport(t, s, peer, strayedSPI)
		if again, _, _ := readOwnRequest(t, s, peer); !bytes.Equal(again, raw) {
			t.Errorf("the unanswered report went again as %x, want %x", again, raw)
		}
		answerOwnRequest(t, s, peer, header, refusingAnswer.inner)
		awaitLine(t, lines, slog.LevelWarn, "ike the peer refused a liveness check")
		if got := peerReads(t, peer, 4*reportRetransmit); len(got) != 0 {
			t.Errorf("the session sent %d datagrams after its report was answered", len(got))
		}
		select {
		case err := <-done:
			t.Errorf("the session ended with %v after its peer refused its report", err)
		default:
		}
	})(t)
}

// RFC 7296 section 2.1: "the initiator MUST retransmit a request until it either receives a corresponding response or deems the IKE SA to have failed."
// a report its peer never answers ends the session after a liveness check's attempts, though the session last heard the peer within its liveness interval
func TestUnansweredInvalidSPIReportEndsTheSession(t *testing.T) {
	bubble.Run(func(t *testing.T) {
		s, peer, _ := reportingSession(t)
		s.retransmitAfter = reportRetransmit
		done := runSession(t, s)
		strayESP(t, s, peer, strayedSPI)
		readReport(t, s, peer, strayedSPI)
		select {
		case err := <-done:
			if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("unresponsive after %d attempts", maxRetransmits)) {
				t.Errorf("the session ended with %v, want the report's attempts spent", err)
			}
		case <-time.After(answerBudget):
			t.Fatal("a session whose peer never answers its report never ended")
		}
	})(t)
}

// RFC 7296 section 2.21.4: "The recipient MUST NOT change the state of any SAs as a result"
// a running session answers a peer's INVALID_SPI empty and starts no exchange of its own for it
func TestInvalidSPIFromThePeerStartsNothing(t *testing.T) {
	bubble.Run(func(t *testing.T) {
		s, peer, events := reportingSession(t)
		runSession(t, s)
		held := s.current
		request, err := EncryptMessage(held.suite, held.sker, Header{SPIInitiator: held.spiI, SPIResponder: held.spiR, ExchangeType: INFORMATIONAL}, nil,
			[]RawPayload{invalidSPINotify(strayedSPI)})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := peer.WriteToUDP(withNonESPMarker(request), muxLoopback(s.mux)); err != nil {
			t.Fatal(err)
		}
		sent := peerReads(t, peer, answerBudget)
		if len(sent) != 1 {
			t.Fatalf("the session sent %d datagrams for its peer's INVALID_SPI, want its answer alone", len(sent))
		}
		answer, err := DecodeMessage(sent[0])
		if err != nil {
			t.Fatal(err)
		}
		if inner, err := DecryptMessage(held.suite, held.skei, sent[0], answer); err != nil || !answer.Header.IsResponse() || answer.Header.MessageID != 0 || len(inner) != 0 {
			t.Errorf("the session sent %v at Message ID %d, a response %v (%v), want an empty answer at 0", inner, answer.Header.MessageID, answer.Header.IsResponse(), err)
		}
		if got := recordedKind(events, "ike.rekey.started"); got != 0 {
			t.Errorf("its peer's INVALID_SPI started %d rekeys", got)
		}
	})(t)
}

// an SPI a mux took between the hub's look and the session's read of it draws no report
func TestInvalidSPIReportSkipsAnSPIHeldSince(t *testing.T) {
	bubble.Run(func(t *testing.T) {
		s, peer, _ := reportingSession(t)
		strayESP(t, s, peer, strayedSPI)
		synctest.Wait()
		if len(s.mux.InvalidSPI()) != 1 {
			t.Fatalf("the hub handed the session no SPI for ESP on SPI %08x", strayedSPI)
		}
		if err := s.mux.RegisterESP(strayedSPI); err != nil {
			t.Fatal(err)
		}
		runSession(t, s)
		if got := peerReads(t, peer, quietPeriod); len(got) != 0 {
			t.Errorf("the session holds SPI %08x, yet it sent %d datagrams", strayedSPI, len(got))
		}
		if got := s.InvalidSPIReports(); got != 0 {
			t.Errorf("the session counts %d reports, want none", got)
		}
	})(t)
}

// each report is recorded with the SPI it told of, in hexadecimal as the other events name SPIs, and counted for the sessions view
func TestInvalidSPIReportIsRecorded(t *testing.T) {
	bubble.Run(func(t *testing.T) {
		s, peer, events := reportingSession(t)
		runSession(t, s)
		strayESP(t, s, peer, strayedSPI)
		readReport(t, s, peer, strayedSPI)
		for deadline := time.Now().Add(answerBudget); recordedKind(events, "ike.notify.invalid_spi") == 0; time.Sleep(recordPoll) {
			if time.Now().After(deadline) {
				t.Fatalf("the report recorded %q", events.recorded())
			}
		}
		if got := events.recorded(); !slices.Contains(got, "ike.notify.invalid_spi > spi=00002000") {
			t.Errorf("the session recorded %q, want the report naming SPI 00002000", got)
		}
		if got := s.InvalidSPIReports(); got != 1 {
			t.Errorf("the session counts %d reports, want 1", got)
		}
	})(t)
}
