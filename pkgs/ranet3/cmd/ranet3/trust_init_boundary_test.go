// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ranet3.com/pkgs/ranet3/trust"
)

func TestTrustInitAuthoredByteBound(t *testing.T) {
	keyPath, input, _ := trustSigningFixture(t)
	for _, size := range []int64{trust.MaxJSONBytes, trust.MaxJSONBytes + 1} {
		if err := os.Truncate(input, size); err != nil {
			t.Fatal(err)
		}
		output := filepath.Join(t.TempDir(), "signed.cose")
		out, stderr, err := runTrustCommand("trust", "init", "--key", keyPath, "--out", output, input)
		if err == nil || out != "" || strings.Contains(stderr, "exceeds 256 MiB") != (size > trust.MaxJSONBytes) {
			t.Fatalf("init read %d bytes: stdout %q, stderr %q, error %v", size, out, stderr, err)
		}
		if _, err := os.Lstat(output); !os.IsNotExist(err) {
			t.Fatalf("init published refused authored file: %v", err)
		}
	}
}

func TestTrustInitAuthoredProfiles(t *testing.T) {
	keyPath, input, public := trustSigningFixture(t)
	for _, test := range []struct {
		name, body string
	}{
		{"missing endpoints", `{"nodes":[{"name":"example/gateway"}]}`},
		{"missing name", `{"nodes":[{"endpoints":[]}]}`},
		{"node names under case folding", `{"nodes":[{"endpoints":[],"name":"example/gateway"},{"endpoints":[],"name":"example/GATEWAY"}]}`},
		{"key shared across organizations", `{"nodes":[{"endpoints":[],"key":"` + public + `","name":"example/gateway"},{"endpoints":[],"key":"` + public + `","name":"other/relay"}]}`},
		{"empty endpoint id", `{"nodes":[{"endpoints":[{"family":"ip4","id":"","port":1}],"name":"example/gateway"}]}`},
		{"long endpoint id", `{"nodes":[{"endpoints":[{"family":"ip4","id":"` + strings.Repeat("x", 65) + `","port":1}],"name":"example/gateway"}]}`},
		{"doubled endpoint spaces", `{"nodes":[{"endpoints":[{"family":"ip4","id":"a  b","port":1}],"name":"example/gateway"}]}`},
		{"endpoint id case twin", `{"nodes":[{"endpoints":[{"family":"ip4","id":"Edge","port":1},{"family":"ip4","id":"edge","port":1}],"name":"example/gateway"}]}`},
		{"invalid family", `{"nodes":[{"endpoints":[{"family":"ip5","port":1}],"name":"example/gateway"}]}`},
		{"zero port", `{"nodes":[{"endpoints":[{"family":"ip4","port":0}],"name":"example/gateway"}]}`},
		{"large port", `{"nodes":[{"endpoints":[{"family":"ip4","port":65536}],"name":"example/gateway"}]}`},
		{"empty address", `{"nodes":[{"endpoints":[{"address":"","family":"ip4","port":1}],"name":"example/gateway"}]}`},
		{"zone in address", `{"nodes":[{"endpoints":[{"address":"2001:db8::1%lo","family":"ip6","port":1}],"name":"example/gateway"}]}`},
		{"mapped address", `{"nodes":[{"endpoints":[{"address":"::ffff:192.0.2.1","family":"ip6","port":1}],"name":"example/gateway"}]}`},
		{"noncanonical ip4", `{"nodes":[{"endpoints":[{"address":"192.000.002.001","family":"ip4","port":1}],"name":"example/gateway"}]}`},
		{"numeric hostname", `{"nodes":[{"endpoints":[{"address":"12345","family":"ip4","port":1}],"name":"example/gateway"}]}`},
		{"invalid alabel", `{"nodes":[{"endpoints":[{"address":"xn--","family":"ip4","port":1}],"name":"example/gateway"}]}`},
		{"nonprintable id", `{"nodes":[{"endpoints":[{"family":"ip4","id":"\u00e9","port":1}],"name":"example/gateway"}]}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := os.WriteFile(input, []byte(test.body), 0600); err != nil {
				t.Fatal(err)
			}
			output := filepath.Join(t.TempDir(), "signed.cose")
			out, stderr, err := runTrustCommand("trust", "init", "--key", keyPath, "--out", output, input)
			if err == nil || out != "" || !strings.Contains(stderr, input) {
				t.Fatalf("init accepted %s: stdout %q, stderr %q, error %v", test.name, out, stderr, err)
			}
			if _, err := os.Lstat(output); !os.IsNotExist(err) {
				t.Fatalf("init published %s: %v", test.name, err)
			}
		})
	}
}
