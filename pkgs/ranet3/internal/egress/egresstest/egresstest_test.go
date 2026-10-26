// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package egresstest

import (
	"context"
	"net/netip"
	"slices"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/netstack"
)

type takenExit struct {
	announce []netip.Prefix
	taken    []byte
}

func (e *takenExit) Run(ctx context.Context) error {
	<-ctx.Done()
	return nil
}

func (e *takenExit) SetEnabled(bool) {}

func (e *takenExit) Egress(frames [][]byte) {
	for _, frame := range frames {
		e.taken = append(e.taken, frame[netstack.TUNHeadroom]>>4)
	}
}

func (e *takenExit) Announce() []netip.Prefix { return e.announce }

func (e *takenExit) Status() egress.Status { return egress.Status{} }

// the hand gives the backend a packet only of a family Ready last held ready
// that Announce's last answer holds a prefix of, as a node's word for an
// advertised prefix holds it, whichever of the two hooks moved last
func TestHandCarriesWhatIsReadyAndAnnounced(t *testing.T) {
	exit := &takenExit{}
	r := &running{Exit: exit}
	packets := [][]byte{
		datagram(netip.MustParseAddrPort("192.0.2.2:40000"), netip.MustParseAddrPort("203.0.113.17:9000"), leafTTL, nil),
		datagram(netip.MustParseAddrPort("[3fff::2]:40000"), netip.MustParseAddrPort("[2001:db8:3::1]:9000"), leafTTL, nil),
	}
	for _, step := range []struct {
		republish bool
		v4, v6    bool
		announce  []netip.Prefix
		want      []byte
	}{
		{v4: true, v6: true},
		{republish: true, announce: defaults, want: []byte{4, 6}},
		{v6: true, announce: defaults, want: []byte{6}},
		{republish: true, announce: defaults[1:], want: []byte{6}},
		{v4: true, v6: true, announce: defaults[1:], want: []byte{6}},
		{republish: true, announce: defaults, want: []byte{4, 6}},
		{v4: true, announce: defaults, want: []byte{4}},
		{announce: defaults},
	} {
		exit.announce, exit.taken = step.announce, nil
		hook := "Ready"
		if step.republish {
			hook = "Republish"
			r.republish()
		} else {
			r.ready(step.v4, step.v6, false)
		}
		r.hand(packets)
		if !slices.Equal(exit.taken, step.want) {
			t.Errorf("after %s with Ready last holding %v %v and Announce answering %v the hand gave the backend IP versions %v, want %v",
				hook, r.ready4, r.ready6, step.announce, exit.taken, step.want)
		}
	}
}

// quotes holds a quote to the addresses, the protocol and the transport header
// RFC 5508 REQ-4 a has a NAT put back, and to nothing a router or the stack an
// error is rebuilt from may change: the TTL or hop limit, the header checksum,
// the IPv4 ID of an atomic datagram and what follows the transport header
func TestQuotesHoldsWhatANATPutsBack(t *testing.T) {
	for _, sent := range [][]byte{
		datagram(netip.MustParseAddrPort("192.0.2.2:40000"), netip.MustParseAddrPort("203.0.113.17:9000"), leafTTL, []byte("a quoted datagram")),
		datagram(netip.MustParseAddrPort("[3fff::2]:40000"), netip.MustParseAddrPort("[2001:db8:3::1]:9000"), leafTTL, []byte("a quoted datagram")),
	} {
		at := headerLength(sent)
		hops, source := 7, 8
		if sent[0]>>4 == 4 {
			hops, source = 8, 12
		}
		changed := func(octets ...int) []byte {
			quote := slices.Clone(sent)
			for _, octet := range octets {
				quote[octet] ^= 1
			}
			return quote
		}
		type quoteCase struct {
			name  string
			quote []byte
			want  bool
		}
		cases := []quoteCase{
			{"as sent", sent, true},
			{"its hops spent", changed(hops), true},
			{"cut after the transport header", sent[:at+8], true},
			{"another payload", changed(at + 8), true},
			{"cut inside the transport header", sent[:at+4], false},
			{"another source", changed(source), false},
			{"another destination port", changed(at + 3), false},
			{"another transport checksum", changed(at + 6), false},
		}
		if sent[0]>>4 == 4 {
			cases = append(cases, quoteCase{"another ID and header checksum", changed(4, 5, 10), true})
		}
		for _, c := range cases {
			if got := quotes(c.quote, sent); got != c.want {
				t.Errorf("a quote %s of the IPv%d datagram quotes it %v, want %v", c.name, sent[0]>>4, got, c.want)
			}
		}
	}
}

// an arm that names no class would have Run run no row, which Run refuses
func TestArmWithNoClassIsRefused(t *testing.T) {
	if err := (Arm{}).check(); err == nil {
		t.Error("an arm with no class was taken")
	}
	if err := (Arm{Classes: []Class{Auto}}).check(); err != nil {
		t.Errorf("an arm with a class was refused: %v", err)
	}
}

// a limit is declared with its reason and its deviations row, or Run refuses the arm
func TestArmDeclaringALimitWithoutItsReasonOrRowIsRefused(t *testing.T) {
	for _, c := range []struct {
		declared Declared
		taken    bool
	}{
		{Declared{}, false},
		{Declared{Reason: "the platform's reason"}, false},
		{Declared{Row: "RFC 4787 section 6"}, false},
		{Declared{Reason: "the platform's reason", Row: "RFC 4787 section 6"}, true},
	} {
		err := (Arm{Classes: []Class{Auto}, Limits: map[Limit]Declared{NoHairpinning: c.declared}}).check()
		if taken := err == nil; taken != c.taken {
			t.Errorf("an arm declaring %s as %+v was taken %v (%v), want %v", NoHairpinning, c.declared, taken, err, c.taken)
		}
	}
}
