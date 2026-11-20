// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/schema"
)

const unownedWarning = "kernel is leaving an address it does not own whose network reaches a none class outside overlay"

// unownedWarnings is the class each warning of unownedWarning in logs names,
// by the address it names, one entry a warning
func unownedWarnings(t *testing.T, logs *bytes.Buffer) map[netip.Prefix][]string {
	t.Helper()
	out := map[netip.Prefix][]string{}
	for line := range strings.Lines(logs.String()) {
		var record struct {
			Msg     string
			Level   string
			Address netip.Prefix
			Class   string
			Fix     string
		}
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("a log line is not a json record: %q", line)
		}
		if record.Msg != unownedWarning {
			continue
		}
		if record.Level != "WARN" || record.Fix == "" {
			t.Fatalf("the warning lacks its level or fix: %q", line)
		}
		out[record.Address] = append(out[record.Address], record.Class)
	}
	return out
}

func translateClasses(pairs ...string) []egress.Class {
	var out []egress.Class
	for i := 0; i < len(pairs); i += 2 {
		to := egress.Translation{Auto: true}
		if pairs[i+1] == "none" {
			to = egress.Translation{None: true}
		}
		out = append(out, egress.Class{From: schema.PrefixFrom(prefix(pairs[i])), To: to})
	}
	return out
}

// unownedOverlay is the overlay of the tests of the warning, each family's
// half of its network
var unownedOverlay = []schema.Prefix{schema.PrefixFrom(prefix("198.51.100.0/25")), schema.PrefixFrom(prefix("2001:db8::/64"))}

// A pass warns once, while it stays, of each address on the tun it does not
// own held under a shorter length whose network holds an address outside the
// overlay under a none class, naming that class, removes none of them and
// fails nothing
func TestUnownedAddressIsWarnedOnceAndLeft(t *testing.T) {
	none := translateClasses("198.51.100.128/25", "none", "2001:db8:0:1::/64", "none")
	for _, test := range []struct {
		name    string
		classes []egress.Class
		file    []netip.Prefix
		held    []netip.Prefix
		// named is the class the warning of each held prefix names, nil where none is warned of
		named []string
	}{
		{"warned: address at a host the file assigns in full", none, []netip.Prefix{prefix("198.51.100.1/32"), prefix("2001:db8::1/128")}, []netip.Prefix{prefix("198.51.100.1/24"), prefix("2001:db8::1/63")}, []string{"198.51.100.128/25", "2001:db8:0:1::/64"}},
		{"warned: address at a host the file does not name", none, []netip.Prefix{prefix("198.51.100.1/32"), prefix("2001:db8::1/128")}, []netip.Prefix{prefix("198.51.100.9/24"), prefix("2001:db8::9/63")}, []string{"198.51.100.128/25", "2001:db8:0:1::/64"}},
		{"warned: network meeting two none classes names the first", translateClasses("198.51.100.224/28", "none", "198.51.100.144/28", "none", "2001:db8:0:1:e000::/68", "none", "2001:db8:0:1:1000::/68", "none"), nil, []netip.Prefix{prefix("198.51.100.9/24"), prefix("2001:db8::9/63")}, []string{"198.51.100.144/28", "2001:db8:0:1:1000::/68"}},
		{"not warned: foreign address at its full length", none, nil, []netip.Prefix{prefix("198.51.100.200/32"), prefix("2001:db8:0:1::5/128")}, nil},
		{"not warned: network wholly inside overlay under none class", translateClasses("198.51.100.0/24", "none", "2001:db8::/48", "none"), nil, []netip.Prefix{prefix("198.51.100.9/26"), prefix("2001:db8::9/80")}, nil},
		{"not warned: network outside overlay under no class", translateClasses("203.0.113.0/24", "none", "2001:db8:ff::/48", "none"), nil, []netip.Prefix{prefix("198.51.100.9/24"), prefix("2001:db8::9/63")}, nil},
		{"not warned: network outside overlay under class that translates", translateClasses("198.51.100.128/25", "auto", "2001:db8:0:1::/64", "auto"), nil, []netip.Prefix{prefix("198.51.100.9/24"), prefix("2001:db8::9/63")}, nil},
		{"not warned: longer translating class inside none one", translateClasses("198.51.100.0/24", "none", "198.51.100.128/25", "auto", "2001:db8::/48", "none", "2001:db8:0:1::/64", "auto"), nil, []netip.Prefix{prefix("198.51.100.9/24"), prefix("2001:db8::9/63")}, nil},
		{"not warned: link-local address under none class", translateClasses("::/0", "none", "2001:db8::/64", "auto"), nil, []netip.Prefix{prefix("fe80::1/64")}, nil},
		{"not warned: address process owns", none, []netip.Prefix{prefix("198.51.100.9/24"), prefix("2001:db8::9/63")}, nil, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			logs := captureKernelLogs(t)
			// a full-length address of another block where the file names none, so the pass lists the tun
			file := test.file
			if file == nil {
				file = []netip.Prefix{prefix("203.0.113.1/32")}
			}
			r, _, kernel := harness(t, Table{Addresses: prefixes(file...)}, Runtime{Overlay: unownedOverlay, Classes: test.classes})
			for _, held := range test.held {
				kernel.addrs[held] = true
			}
			for pass := range 2 {
				if _, _, err := r.applyAddresses(); err != nil {
					t.Fatalf("pass %d failed: %v", pass, err)
				}
			}
			warned := unownedWarnings(t, logs)
			for i, held := range test.held {
				var want []string
				if test.named != nil {
					want = []string{test.named[i]}
				}
				if got := warned[held]; strings.Join(got, " ") != strings.Join(want, " ") {
					t.Errorf("%s was warned of over two passes naming %q, want %q", held, got, want)
				}
				if !kernel.addrs[held] {
					t.Errorf("%s was removed", held)
				}
			}
			for _, address := range test.file {
				if r.owned[address] && len(warned[address]) != 0 {
					t.Errorf("%s, which the pass assigned, was warned of", address)
				}
			}
			if test.named == nil && len(warned) != 0 {
				t.Errorf("warned of %v", warned)
			}
		})
	}
}

// An address warned of, gone and back, is warned of again, and so is one that
// takes its place at another length or another address of its network
func TestUnownedAddressBackOrReplacedIsWarnedAgain(t *testing.T) {
	logs := captureKernelLogs(t)
	r, _, kernel := harness(t, Table{Addresses: prefixes(prefix("198.51.100.1/32"))}, Runtime{Overlay: unownedOverlay, Classes: translateClasses("198.51.100.128/25", "none", "2001:db8:0:1::/64", "none")})
	steps := [][]netip.Prefix{
		{prefix("198.51.100.9/24"), prefix("2001:db8::9/63")},
		nil,
		{prefix("198.51.100.9/24"), prefix("2001:db8::9/63")},
		{prefix("198.51.100.9/23"), prefix("2001:db8::9/62")},
		{prefix("198.51.100.10/23"), prefix("2001:db8::a/62")},
	}
	var last []netip.Prefix
	for i, step := range steps {
		for _, address := range last {
			delete(kernel.addrs, address)
		}
		for _, address := range step {
			kernel.addrs[address] = true
		}
		last = step
		if _, _, err := r.applyAddresses(); err != nil {
			t.Fatalf("pass %d: %v", i, err)
		}
	}
	warned := unownedWarnings(t, logs)
	want := map[netip.Prefix]int{prefix("198.51.100.9/24"): 2, prefix("2001:db8::9/63"): 2, prefix("198.51.100.9/23"): 1, prefix("2001:db8::9/62"): 1, prefix("198.51.100.10/23"): 1, prefix("2001:db8::a/62"): 1}
	for address, n := range want {
		if len(warned[address]) != n {
			t.Errorf("%s was warned of %d times, want %d", address, len(warned[address]), n)
		}
	}
}
