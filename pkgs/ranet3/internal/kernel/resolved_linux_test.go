// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

// DumpDNSConfiguration's reply names each link's servers, the global and
// fallback servers left out, and a reply holding an error or an address of
// another length is refused
func TestLinkServersReadsEachLinksServers(t *testing.T) {
	reply := `{"parameters":{"configuration":[
		{"servers":[{"address":[192,0,2,53],"family":2,"port":53}],"fallbackServers":[{"address":[198,51,100,99],"family":2,"port":53}]},
		{"ifname":"eth0","ifindex":2,"servers":[{"address":[203,0,113,53],"family":2,"port":53,"ifindex":2},
			{"address":[32,1,13,184,0,0,0,0,0,0,0,0,0,0,0,83],"family":10,"port":53,"ifindex":2}]},
		{"ifname":"lo","ifindex":1}]}}`
	got, err := linkServers([]byte(reply))
	if err != nil {
		t.Fatal(err)
	}
	want := []LinkResolver{{Link: "eth0", Address: netip.MustParseAddr("203.0.113.53")}, {Link: "eth0", Address: netip.MustParseAddr("2001:db8::53")}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("the servers read %v, want %v", got, want)
	}
	for name, refused := range map[string]string{
		"an error":          `{"error":"io.systemd.Resolve.NoNameServers"}`,
		"a short address":   `{"parameters":{"configuration":[{"ifname":"eth0","servers":[{"address":[203,0,113]}]}]}}`,
		"an octet past 255": `{"parameters":{"configuration":[{"ifname":"eth0","servers":[{"address":[203,0,113,256]}]}]}}`,
	} {
		if got, err := linkServers([]byte(refused)); err == nil || !strings.HasPrefix(err.Error(), "kernel: ") {
			t.Errorf("%s: read %v (err %v), want a refusal", name, got, err)
		}
	}
}
