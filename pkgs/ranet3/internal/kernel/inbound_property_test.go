// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package kernel

import (
	"fmt"
	"slices"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// inboundPorts is the ports a drawn entry starts and ends at: a run at the
// bottom, so drawn ranges overlap, touch and fall apart, and the top of the
// port space
var inboundPorts = []uint16{1, 2, 3, 4, 5, 6, 7, 8, 65533, 65534, 65535}

// drawnInbound draws up to five entries, each spelled as a port or as a range,
// a range of one port among them
func drawnInbound(tc hegel.TestCase) []string {
	var out []string
	for range hegel.Draw(tc, pbt.Spanning(0, 5)) {
		protocol := []string{"tcp", "udp"}[hegel.Draw(tc, pbt.Spanning(0, 1))]
		a := inboundPorts[hegel.Draw(tc, pbt.Spanning(0, len(inboundPorts)-1))]
		b := inboundPorts[hegel.Draw(tc, pbt.Spanning(0, len(inboundPorts)-1))]
		first, last := min(a, b), max(a, b)
		if first == last && hegel.Draw(tc, pbt.Spanning(0, 1)) == 1 {
			out = append(out, fmt.Sprintf("%d/%s", first, protocol))
			continue
		}
		out = append(out, fmt.Sprintf("%d-%d/%s", first, last, protocol))
	}
	return out
}

// entryOf reads an entry of either form by the grammar alone
func entryOf(t *hegel.T, entry string) Service {
	var s Service
	if _, err := fmt.Sscanf(entry, "%d-%d/%s", &s.First, &s.Last, &s.Protocol); err == nil {
		return s
	}
	if _, err := fmt.Sscanf(entry, "%d/%s", &s.First, &s.Protocol); err != nil {
		t.Fatalf("inbound entry %q is neither form", entry)
	}
	s.Last = s.First
	return s
}

// covered is each protocol and port an entry of inbound holds
func covered(t *hegel.T, inbound []string) map[string]map[int]bool {
	out := map[string]map[int]bool{"tcp": {}, "udp": {}}
	for _, entry := range inbound {
		s := entryOf(t, entry)
		for port := int(s.First); port <= int(s.Last); port++ {
			out[s.Protocol][port] = true
		}
	}
	return out
}

// Validate refuses a drawn inbound exactly when two entries name the same
// ports of one protocol. Normalized holds the ports and protocols the entries
// hold, tcp before udp, each protocol's ranges ascending with a gap between
// any two, a range of one port spelled as the port. It is the same for the
// entries in reverse order and for its own output, which Validate takes, so a
// reload over the same ports written another way is no change.
func TestInboundNormalizesToTheOneSpellingOfItsPorts(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		inbound := drawnInbound(ht)
		mode := ExitMode{Fallback: FallbackNone, Inbound: inbound}
		seen := map[Service]bool{}
		twice := false
		for _, entry := range inbound {
			s := entryOf(ht, entry)
			twice = twice || seen[s]
			seen[s] = true
		}
		if err := mode.Validate(); (err != nil) != twice {
			ht.Fatalf("inbound %q was refused with %v, and an entry written twice is %v", inbound, err, twice)
		}
		if twice {
			return
		}

		normal := mode.Normalized().Inbound
		want, got := covered(ht, inbound), covered(ht, normal)
		for _, protocol := range []string{"tcp", "udp"} {
			for port := range 1 << 16 {
				if want[protocol][port] != got[protocol][port] {
					ht.Fatalf("inbound %q normalized to %q, which differs at %d/%s", inbound, normal, port, protocol)
				}
			}
		}
		for i, entry := range normal {
			s := entryOf(ht, entry)
			if s.First == s.Last && entry != fmt.Sprintf("%d/%s", s.First, s.Protocol) {
				ht.Fatalf("inbound %q normalized to %q, whose %q is a range of one port", inbound, normal, entry)
			}
			if i == 0 {
				continue
			}
			before := entryOf(ht, normal[i-1])
			if before.Protocol > s.Protocol || before.Protocol == s.Protocol && int(before.Last)+1 >= int(s.First) {
				ht.Fatalf("inbound %q normalized to %q, where %q and %q are out of order, overlap or touch", inbound, normal, normal[i-1], entry)
			}
		}

		reversed := slices.Clone(inbound)
		slices.Reverse(reversed)
		if again := (ExitMode{Fallback: FallbackNone, Inbound: reversed}).Normalized().Inbound; !slices.Equal(again, normal) {
			ht.Fatalf("inbound %q normalized to %q, and in reverse to %q", inbound, normal, again)
		}
		once := ExitMode{Fallback: FallbackNone, Inbound: normal}
		if err := once.Validate(); err != nil {
			ht.Fatalf("inbound %q normalized to %q, which Validate refuses: %v", inbound, normal, err)
		}
		if again := once.Normalized().Inbound; !slices.Equal(again, normal) {
			ht.Fatalf("inbound %q normalized to %q, and that to %q", inbound, normal, again)
		}
	})
}
