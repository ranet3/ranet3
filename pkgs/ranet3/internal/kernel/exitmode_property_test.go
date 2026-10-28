// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package kernel

import (
	"maps"
	"path"
	"slices"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// globNames is the names a drawn host holds its links under, the tun among them
var globNames = []string{"br-1a", "br-3d", "docker0", "docker1", "eth0", "eth1", "lo", "ranet3", "veth9", "wlan0"}

// globEntries is the entries a drawn forward list holds, each a name or a
// pattern that path.Match finds in none, one or several of globNames
var globEntries = []string{"docker*", "br-?", "br-*", "eth[01]", "eth[^0]", "veth9", "ranet*", "lo*", "wlan0", "*", "tun?", `eth\0`}

// drawnSubset draws names of globNames by a mask
func drawnSubset(tc hegel.TestCase) []Link {
	mask := hegel.Draw(tc, pbt.Spanning(0, 1<<len(globNames)-1))
	var out []Link
	for i, name := range globNames {
		if mask&(1<<i) != 0 {
			out = append(out, Link{Name: name})
		}
	}
	return out
}

// drawnDefault draws the link a default leaves by, or none
func drawnDefault(tc hegel.TestCase) string {
	at := hegel.Draw(tc, pbt.Spanning(0, len(globNames)))
	if at == len(globNames) {
		return ""
	}
	return globNames[at]
}

// The expansion writes exactly the links of the host, and the tun, that some
// entry of forward matches as path.Match reads it, sorted and each once, less
// the tun, lo and the link either family's default leaves by, and it reports
// each of those it leaves out with the first entry in forward's order that
// matched it.
func TestForwardExpandsToTheMatchedLinksLessTheTunLoopbackAndUplink(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		var forward []string
		for range hegel.Draw(ht, pbt.Spanning(0, 4)) {
			forward = append(forward, globEntries[hegel.Draw(ht, pbt.Spanning(0, len(globEntries)-1))])
		}
		var network NetworkState
		network.IPv4.Links, network.IPv6.Links = drawnSubset(ht), drawnSubset(ht)
		network.IPv4.Default.Interface, network.IPv6.Default.Interface = drawnDefault(ht), drawnDefault(ht)
		tun := ""
		if hegel.Draw(ht, pbt.Spanning(0, 1)) == 1 {
			tun = "ranet3"
		}

		out, skipped := expandForward(forward, tun, network)
		candidates := map[string]bool{}
		for _, link := range slices.Concat(network.IPv4.Links, network.IPv6.Links) {
			candidates[link.Name] = true
		}
		if tun != "" {
			candidates[tun] = true
		}
		var wantOut []string
		var wantSkipped []ForwardSkip
		for _, name := range slices.Sorted(maps.Keys(candidates)) {
			at := slices.IndexFunc(forward, func(entry string) bool { matched, _ := path.Match(entry, name); return matched })
			if at < 0 {
				continue
			}
			if name == tun || name == "lo" || name == network.IPv4.Default.Interface || name == network.IPv6.Default.Interface {
				wantSkipped = append(wantSkipped, ForwardSkip{Entry: forward[at], Link: name})
				continue
			}
			wantOut = append(wantOut, name)
		}
		if !slices.Equal(out, wantOut) {
			ht.Fatalf("forward %q on links %v and %v, tun %q, defaults %q and %q expanded to %v, want %v",
				forward, network.IPv4.Links, network.IPv6.Links, tun, network.IPv4.Default.Interface, network.IPv6.Default.Interface, out, wantOut)
		}
		if len(skipped) != len(wantSkipped) {
			ht.Fatalf("forward %q skipped %v, want %v", forward, skipped, wantSkipped)
		}
		for i, skip := range skipped {
			if skip.Entry != wantSkipped[i].Entry || skip.Link != wantSkipped[i].Link || skip.Reason == "" {
				ht.Fatalf("forward %q skipped %v, want %v each with a reason", forward, skipped, wantSkipped)
			}
		}
	})
}
