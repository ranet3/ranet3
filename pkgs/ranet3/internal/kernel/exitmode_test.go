// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"reflect"
	"testing"
)

// defaultsBy is a host whose IPv4 default leaves by v4 and whose IPv6 default leaves by v6, each holding the links named
func defaultsBy(v4, v6 string, links ...string) NetworkState {
	var state NetworkState
	state.IPv4.Default.Interface, state.IPv6.Default.Interface = v4, v6
	for _, name := range links {
		state.IPv4.Links = append(state.IPv4.Links, Link{Name: name})
		state.IPv6.Links = append(state.IPv6.Links, Link{Name: name})
	}
	return state
}

// a name forward writes is refused where it is the tun or the link either
// family's default leaves by, and a pattern matching one is left to the
// expansion, which skips it
func TestForwardRefusesTheTunAndTheUplinkByName(t *testing.T) {
	host := defaultsBy("eth0", "wlan0", "docker0", "eth0", "wlan0")
	for entry, says := range map[string]string{
		"ranet3": "kernel: cap.exit forward ranet3 is the mesh's own tun, whose traffic never follows the mode: remove it from forward",
		"eth0":   "kernel: cap.exit forward eth0 is the link the IPv4 default leaves by, whose traffic never follows the mode: remove it from forward",
		"wlan0":  "kernel: cap.exit forward wlan0 is the link the IPv6 default leaves by, whose traffic never follows the mode: remove it from forward",
	} {
		err := ExitMode{Forward: []string{"docker0", entry}}.RefuseNamed("ranet3", host)
		if err == nil || err.Error() != says {
			t.Errorf("forward %s was refused with %v, want %q", entry, err, says)
		}
	}
	for _, forward := range [][]string{{"docker0"}, {"eth*"}, {"ranet?"}, {"*"}, {`eth\0`}, {"veth9"}} {
		if err := (ExitMode{Forward: forward}).RefuseNamed("ranet3", host); err != nil {
			t.Errorf("forward %v was refused: %v", forward, err)
		}
	}
	// a host with no default refuses the tun alone
	if err := (ExitMode{Forward: []string{"eth0"}}).RefuseNamed("ranet3", NetworkState{}); err != nil {
		t.Errorf("forward eth0 on a host with no default was refused: %v", err)
	}
}

// the mode reaches the reconciler through the table, and normalizing puts forward in one order with each entry once
func TestTableCarriesTheModeNormalized(t *testing.T) {
	if mode := (Table{}).Normalized().Mode(); mode != nil {
		t.Errorf("a table with no mode normalized to %+v", mode)
	}
	written := &ExitMode{Forward: []string{"eth1", "docker*", "eth1"}}
	table := Table{}.WithMode(written)
	if got, want := table.Normalized().Mode(), (&ExitMode{Forward: []string{"docker*", "eth1"}}); !reflect.DeepEqual(got, want) {
		t.Errorf("the table runs the mode %+v, want %+v", got, want)
	}
	if !reflect.DeepEqual(Table{}.WithMode(&ExitMode{}).Normalized(), Table{}.WithMode(&ExitMode{Forward: []string{}}).Normalized()) {
		t.Error("an empty forward and none normalize apart")
	}
	if reflect.DeepEqual(Table{}.Normalized(), Table{}.WithMode(&ExitMode{}).Normalized()) {
		t.Error("mode off and mode 2 with no forward normalize alike")
	}
	if err := (Table{}.WithMode(&ExitMode{Forward: []string{"lo"}})).Validate(); err == nil {
		t.Error("a table running a mode forward lo was taken")
	}
}
