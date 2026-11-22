// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package srv6

import (
	"net/netip"
	"testing"

	"ranet3.com/pkgs/ranet3/schema"
)

// ::1 is refused as a block source, a steering entry's own source, a local SID, a segment of an entry and a segment of cap.exit via
// whether or not a packet would ever be sent from or to it, RFC 4291 section 2.5.3, each refusal's message whole, through Validate and the constructors alike
// beside it ff0e::1 as a block source is refused, and an ordinary block source, entry and SID load
func TestSegmentsRefuseLoopbackInEveryRole(t *testing.T) {
	lo, ok := schema.MustAddr("::1"), schema.MustAddr("3fff:1::1")
	to := schema.PrefixFrom(netip.MustParsePrefix("3fff:9::/64"))
	overlay := []schema.Prefix{schema.MustPrefix("3fff::/20")}
	for _, c := range []struct {
		name     string
		segments Segments
		says     string
	}{
		{"a block source no entry uses", Segments{Source: lo}, "srv6: cap.segment source ::1 cannot address a segment routed packet"},
		{"an entry's own source", Segments{Source: ok, Steer: []Steer{{To: to, Via: []schema.Addr{schema.MustAddr("3fff:1::2")}, Source: lo}}}, "srv6: tunnel source ::1 cannot address a segment routed packet"},
		{"a local SID no packet reaches", Segments{Local: []Segment{{SID: lo, Behavior: BehaviorEnd}}}, "srv6: cap.segment local ::1 cannot address a segment routed packet"},
		{"a segment of an entry", Segments{Source: ok, Steer: []Steer{{To: to, Via: []schema.Addr{lo}}}}, "srv6: segment ::1 cannot address a segment routed packet"},
		{"ff0e::1 as a block source", Segments{Source: schema.MustAddr("ff0e::1")}, "srv6: cap.segment source ff0e::1 cannot address a segment routed packet"},
		{"an ordinary block source, entry and SID", Segments{Source: ok, Local: []Segment{{SID: schema.MustAddr("3fff:5::1"), Behavior: BehaviorEnd}}, Steer: []Steer{{To: to, Via: []schema.Addr{schema.MustAddr("3fff:1::2")}}}}, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := c.segments.Validate()
			if got := errorText(err); got != c.says {
				t.Errorf("Validate says %q, want %q", got, c.says)
			}
		})
	}
	if _, err := NewLocalTable([]Segment{{SID: lo, Behavior: BehaviorEnd}}, overlay); errorText(err) != "srv6: cap.segment local ::1 cannot address a segment routed packet" {
		t.Errorf("NewLocalTable says %v for a SID of ::1", err)
	}
	if _, err := NewSteerTable([]Steer{{To: to, Via: []schema.Addr{ok}}}, lo); errorText(err) != "srv6: tunnel source ::1 cannot address a segment routed packet" {
		t.Errorf("NewSteerTable says %v for a source of ::1", err)
	}
	if _, err := (*SteerTable)(nil).WithDefault(ok.Addr, []netip.Addr{lo.Addr}); errorText(err) != "cap.exit via: srv6: segment ::1 cannot address a segment routed packet" {
		t.Errorf("WithDefault says %v for a path through ::1", err)
	}
}

// errorText is err's message, empty for nil
func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
