// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package babel

import (
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/logtest"
)

// saidCounts is the value of key on each line of said that holds msg
func saidCounts(said, msg, key string) []string {
	var counts []string
	for line := range strings.Lines(said) {
		if strings.Contains(line, msg) {
			_, count, _ := strings.Cut(line, key+"=")
			count, _, _ = strings.Cut(strings.TrimSpace(count), " ")
			counts = append(counts, count)
		}
	}
	return counts
}

// an Update that does not decode is said at most once per refusalLogInterval, however many a neighbor packs into a packet or sends in packets after it
// each line counts the Updates ignored since the one before
func TestBadUpdatesAreSaidOncePerIntervalWithTheirCount(t *testing.T) {
	var said strings.Builder
	logtest.SetDefault(t, slog.New(slog.NewTextHandler(&said, nil)))
	speaker, neighbor, _ := captureSpeaker(t, Config{})
	bad := RawTLV{Type: TLVUpdate, Body: []byte{1}}
	packet := EncodePacket([]RawTLV{bad, bad})
	start := time.Now()
	speaker.mu.Lock()
	for _, at := range []time.Duration{0, 0, refusalLogInterval / 2, refusalLogInterval + time.Second} {
		speaker.handlePacketLocked(neighbor, packet, start.Add(at))
	}
	speaker.mu.Unlock()
	if got, want := saidCounts(said.String(), "babel bad update", "ignored_since_last"), []string{"1", "6"}; !slices.Equal(got, want) {
		t.Fatalf("four packets of two undecodable Updates each, the fourth past the interval, were said with counts %q, want %q, in\n%s", got, want, said.String())
	}
}
