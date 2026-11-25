// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package config

import (
	"fmt"
	"strings"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/netstack"
)

func TestSourcedCapacityFromAcceptedAnnouncements(t *testing.T) {
	for _, sourcedNinth := range []bool{false, true} {
		announcements := make([]string, 0, 9)
		for i := range 8 {
			announcements = append(announcements, fmt.Sprintf(`"2001:db8:%x::/48"`, 0x100+i))
		}
		ninth := `"2001:db8:108::/48"`
		if sourcedNinth {
			ninth = `{ prefix = "2001:db8:108::/48", from = "3fff:f00::/32" }`
		}
		announcements = append(announcements, ninth)
		cfg, err := loadTOML(t, nodeTOML+
			"[cap.table]\nsourced = { to = [\"2001:db8:fff0::/48\", \"2001:db8:fff1::/48\"] }\n"+
			"[cap.route]\nannounce = ["+strings.Join(announcements, ", ")+"]\n")
		if err != nil {
			t.Fatal(err)
		}
		_, err = kernel.New(*cfg.ReconcilerTable(), kernel.Runtime{Interface: "interface-name-too-long"}, netstack.NewRouteTable())
		if sourcedNinth {
			if err == nil || strings.Contains(err.Error(), "destination-source pairs") {
				t.Fatalf("a source-specific ninth announcement consumed a sourced pair: %v", err)
			}
		} else if err == nil || !strings.Contains(err.Error(), "needs 2 destinations and 18 destination-source pairs, up to 77 IPv6 rules") {
			t.Fatalf("accepted configuration with nine unsourced announcements: %v", err)
		}
	}
}
