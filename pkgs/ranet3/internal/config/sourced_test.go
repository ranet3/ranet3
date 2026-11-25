// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package config

import (
	"fmt"
	"strings"
	"testing"
)

func sourcedDocument(format, id, to, extra string) string {
	switch format {
	case ".toml":
		return nodeTOML + "[cap.table]\n" + extra + "sourced = { to = [" + to + "]" + id + " }\n"
	case ".yaml":
		return nodeYAML + "cap:\n  table:\n" + extra + "    sourced: { to: [" + to + "]" + id + " }\n"
	default:
		return `{"node":"example/laptop","auth":{"key":"key.pem","trust":"trust.json"},"link":{"port":13000,"endpoints":[{"serial":"0","family":"ip4"}]},"dial":{"to":["example/gateway"]},"cap":{"table":{` + extra + `"sourced":{"to":[` + to + `]` + id + `}}}}`
	}
}

func TestSourcedFormatsAndIDs(t *testing.T) {
	for _, format := range []string{".toml", ".yaml", ".json"} {
		for _, tc := range []struct {
			name, id string
			want     uint32
		}{
			{name: "default", want: 201},
			{name: "zero", id: ", id = 0", want: 201},
			{name: "override", id: ", id = 300", want: 300},
		} {
			t.Run(format+"/"+tc.name, func(t *testing.T) {
				id := tc.id
				if format == ".json" {
					id = strings.ReplaceAll(id, ", id = ", `,"id":`)
				} else if format == ".yaml" {
					id = strings.ReplaceAll(id, " = ", ": ")
				}
				cfg, err := load(t, format, sourcedDocument(format, id, `"2001:db8:ffff::/48"`, ""))
				if err != nil {
					t.Fatal(err)
				}
				if cfg.Cap.Table == nil || cfg.Cap.Table.Sourced == nil || len(cfg.Cap.Table.Sourced.To) != 1 || cfg.Cap.Table.Sourced.To[0].String() != "2001:db8:ffff::/48" || uint32(cfg.Cap.Table.Normalized().Sourced.ID) != tc.want {
					t.Fatalf("decoded sourced table: %+v", cfg.Cap.Table)
				}
			})
		}
		cfg, err := load(t, format, sourcedDocument(format, "", `"2001:db8:ffff::/48"`, ""))
		if err != nil || cfg.Cap.Table.Sourced == nil {
			t.Fatalf("%s optional id: %v", format, err)
		}
		var absent string
		switch format {
		case ".toml":
			absent = nodeTOML + "[cap.table]\nid = 200\n"
		case ".yaml":
			absent = nodeYAML + "cap:\n  table:\n    id: 200\n"
		default:
			absent = strings.Replace(sourcedDocument(format, "", `"2001:db8:ffff::/48"`, ""), `"sourced":{"to":["2001:db8:ffff::/48"]}`, `"id":200`, 1)
		}
		cfg, err = load(t, format, absent)
		if err != nil || cfg.Cap.Table == nil || cfg.Cap.Table.Sourced != nil {
			t.Fatalf("%s absent sourced: %v, table %+v", format, err, cfg)
		}
		var extra string
		switch format {
		case ".toml":
			extra = "other = 1\n"
		case ".yaml":
			extra = "    other: 1\n"
		default:
			extra = `"other":1,`
		}
		_, err = load(t, format, sourcedDocument(format, "", `"2001:db8:ffff::/48"`, extra))
		if err == nil || !strings.Contains(err.Error(), "other") {
			t.Fatalf("%s unknown key: %v", format, err)
		}
		cfg, err = load(t, format, sourcedDocument(format, "", `"2001:db8:ffff::/48", "2001:db9::/48"`, ""))
		if err != nil {
			t.Fatalf("%s adjacent destinations: %v", format, err)
		}
		if cfg.Cap.Table == nil || cfg.Cap.Table.Sourced == nil || len(cfg.Cap.Table.Sourced.To) != 2 ||
			cfg.Cap.Table.Sourced.To[0].String() != "2001:db8:ffff::/48" ||
			cfg.Cap.Table.Sourced.To[1].String() != "2001:db9::/48" {
			t.Fatalf("%s adjacent destinations decoded as %+v", format, cfg.Cap.Table)
		}
	}
}

func TestSourcedUnknownMember(t *testing.T) {
	for _, format := range []string{".toml", ".yaml", ".json"} {
		t.Run(format, func(t *testing.T) {
			unknown, want := ", other = 1", `unknown field "cap.table.sourced.other"`
			switch format {
			case ".yaml":
				unknown = ", other: 1"
				want = "field other not found in type kernel.Sourced"
			case ".json":
				unknown = `,"other":1`
				want = "field other not found in type kernel.Sourced"
			}
			_, err := load(t, format, sourcedDocument(format, unknown, `"2001:db8:ffff::/48"`, ""))
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("unknown sourced member: %v; want %q", err, want)
			}
		})
	}
}

func TestSourcedInvalidConfiguration(t *testing.T) {
	for _, tc := range []struct{ name, id, to, table, extra, want string }{
		{"empty", "", "", "", "", "to names no destination"},
		{"ipv4", "", `"192.0.2.0/24"`, "", "", "not an IPv6 destination"},
		{"mapped", "", `"::ffff:192.0.2.0/120"`, "", "", "IPv4 prefix written as IPv6"},
		{"host bits", "", `"2001:db8:ffff::1/48"`, "", "", "bits set below"},
		{"default", "", `"2000::/15"`, "", "", "shorter than /16"},
		{"unroutable", "", `"fe80::/16"`, "", "", "link-local addresses"},
		{"overlap", "", `"2001:db8:ffff::/48", "2001:db8:ffff:1::/64"`, "", "", "name each destination once"},
		{"overlap equal", "", `"2001:db8:ffff::/48", "2001:db8:ffff::/48"`, "", "", "is written twice"},
		{"overlap covering", "", `"2001:db8:ffff:1::/64", "2001:db8:ffff::/48"`, "", "", "name each destination once"},
		{"reserved derived", "", `"2001:db8:ffff::/48"`, "id = 252\n", "", "cannot be derived from cap.table.id 252, write id"},
		{"overflow", "", `"2001:db8:ffff::/48"`, "id = 4294967295\n", "", "cannot be derived from cap.table.id 4294967295, write id"},
		{"reserved explicit", ", id = 253", `"2001:db8:ffff::/48"`, "", "", "id 253 is reserved or equals cap.table.id"},
		{"same table", ", id = 200", `"2001:db8:ffff::/48"`, "", "", "id 200 is reserved or equals cap.table.id"},
		{"overlay", "", `"3fff:f00::/32"`, "", "", "meets overlay"},
		{"overlay covering", "", `"3fff::/16"`, "", "", "meets overlay"},
		{"overlay equal", "", `"3fff::/20"`, "", "", "meets overlay"},
		{"own address", "", `"2001:db8:ffff::/48"`, "addresses = [\"2001:db8:ffff::1/128\"]\n", "", "holds this node's own"},
		{"own announce", "", `"2001:db8:ffff::/48"`, "", "[cap.route]\nannounce = [\"2001:db8:ffff::1/128\"]\n", "holds this node's own"},
		{"sourced announce", "", `"2001:db8:ffff::/48"`, "", "[cap.route]\nannounce = [{ prefix = \"2001:db8:ffff::/48\", from = \"3fff:f00::/32\" }]\n", "with a source"},
		{"steer inside", "", `"2001:db8:ffff::/48"`, "", "[cap.segment]\nsource = \"3fff:b:0:100::1\"\n[[cap.segment.steer]]\nfrom = \"3fff:a::7/128\"\nto = \"2001:db8:ffff:1::/64\"\nvia = [\"3fff:b:0:206::1\"]\n", "meets cap.segment steer"},
		{"steer covering", "", `"2001:db8:ffff::/48"`, "", "[cap.segment]\nsource = \"3fff:b:0:100::1\"\n[[cap.segment.steer]]\nfrom = \"3fff:a::7/128\"\nto = \"2001:db8::/32\"\nvia = [\"3fff:b:0:206::1\"]\n", "meets cap.segment steer"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := "overlay = [\"3fff::/20\"]\n" + nodeTOML + "[cap.table]\n" + tc.table + "sourced = { to = [" + tc.to + "]" + tc.id + " }\n" + tc.extra
			_, err := loadTOML(t, body)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
	for _, id := range []uint32{254, 255} {
		_, err := loadTOML(t, nodeTOML+fmt.Sprintf("[cap.table]\nsourced = { to = [\"2001:db8:ffff::/48\"], id = %d }\n", id))
		if err == nil || !strings.Contains(err.Error(), "is reserved or equals cap.table.id") {
			t.Fatalf("id %d: %v", id, err)
		}
	}
}

func TestSourcedInsideBroaderOwnAnnouncement(t *testing.T) {
	for _, tc := range []struct {
		name, announcement, prefix string
		withSource                 bool
	}{
		{"bare", `["2001:db8::/32"]`, "2001:db8::/32", false},
		{"with source", `[{ prefix = "2001:db8::/32", from = "3fff:f00::/32" }]`, "2001:db8::/32", true},
		{"exit default", `["::/0"]`, "::/0", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := nodeTOML + "[cap.table]\nsourced = { to = [\"2001:db8:ffff::/48\"] }\n[cap.route]\nannounce = " + tc.announcement + "\n"
			cfg, err := loadTOML(t, body)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Cap.Table == nil || cfg.Cap.Table.Sourced == nil ||
				len(cfg.Cap.Table.Sourced.To) != 1 || cfg.Cap.Table.Sourced.To[0].String() != "2001:db8:ffff::/48" ||
				cfg.Cap.Route == nil || len(cfg.Cap.Route.Announce) != 1 ||
				cfg.Cap.Route.Announce[0].Prefix.String() != tc.prefix ||
				cfg.Cap.Route.Announce[0].From.IsValid() != tc.withSource {
				t.Fatalf("decoded table %+v and announcement %+v", cfg.Cap.Table, cfg.Cap.Route)
			}
		})
	}
}

func TestSourcedEgressAdvertise(t *testing.T) {
	for _, tc := range []struct {
		name, advertised string
		refused          bool
	}{
		{"equal", "2001:db8:ffff::/48", true},
		{"inside destination", "2001:db8:ffff:1::/64", true},
		{"broader than destination", "2001:db8::/32", false},
		{"exit default", "::/0", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := nodeTOML + "[cap.table]\nsourced = { to = [\"2001:db8:ffff::/48\"] }\n[cap.egress]\nadvertise = [\"" + tc.advertised + "\"]\n"
			cfg, err := loadTOML(t, body)
			if tc.refused {
				want := "holds cap.egress advertise " + tc.advertised
				if err == nil || !strings.Contains(err.Error(), want) {
					t.Fatalf("got %v, want %q", err, want)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Cap.Table == nil || cfg.Cap.Table.Sourced == nil ||
				len(cfg.Cap.Table.Sourced.To) != 1 || cfg.Cap.Table.Sourced.To[0].String() != "2001:db8:ffff::/48" ||
				cfg.Cap.Egress == nil || len(cfg.Cap.Egress.Advertise) != 1 ||
				cfg.Cap.Egress.Advertise[0].String() != tc.advertised {
				t.Fatalf("decoded table %+v and egress %+v", cfg.Cap.Table, cfg.Cap.Egress)
			}
		})
	}
}

func TestSourcedAssignedAddressAtAnyWrittenLength(t *testing.T) {
	for _, tc := range []struct {
		name, address string
		refused       bool
	}{
		{"broader written length", "2001:db8:ffff::1/32", true},
		{"shorter written length", "2001:db8:ffff::1/47", true},
		{"equal written length", "2001:db8:ffff::1/48", true},
		{"longer written length", "2001:db8:ffff::1/64", true},
		{"full written length", "2001:db8:ffff::1/128", true},
		{"broader network but address outside", "2001:db8::1/32", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := nodeTOML + "[cap.table]\naddresses = [\"" + tc.address + "\"]\nsourced = { to = [\"2001:db8:ffff::/48\"] }\n"
			cfg, err := loadTOML(t, body)
			if tc.refused {
				want := "holds this node's own 2001:db8:ffff::1/128"
				if err == nil || !strings.Contains(err.Error(), want) {
					t.Fatalf("got %v, want %q", err, want)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Cap.Table == nil || cfg.Cap.Table.Sourced == nil ||
				len(cfg.Cap.Table.Sourced.To) != 1 || cfg.Cap.Table.Sourced.To[0].String() != "2001:db8:ffff::/48" ||
				len(cfg.Cap.Table.Addresses) != 1 || cfg.Cap.Table.Addresses[0].String() != tc.address {
				t.Fatalf("decoded table %+v", cfg.Cap.Table)
			}
		})
	}
}

func TestSourcedAssignedAnnouncement(t *testing.T) {
	for _, tc := range []struct {
		name   string
		assign bool
	}{
		{"broader announcement", false},
		{"broader announcement assigned", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := nodeTOML + fmt.Sprintf("[cap.table]\nassign_announced = %t\nsourced = { to = [\"2001:db8:ffff::/48\"] }\n[cap.route]\nannounce = [\"2001:db8:ffff::1/32\"]\n", tc.assign)
			cfg, err := loadTOML(t, body)
			if tc.assign {
				if err == nil || !strings.Contains(err.Error(), "holds this node's own 2001:db8:ffff::1/128") {
					t.Fatalf("assigned announcement: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Cap.Table == nil || cfg.Cap.Table.Sourced == nil ||
				len(cfg.Cap.Table.Sourced.To) != 1 || cfg.Cap.Table.Sourced.To[0].String() != "2001:db8:ffff::/48" ||
				cfg.Cap.Route == nil || len(cfg.Cap.Route.Announce) != 1 ||
				cfg.Cap.Route.Announce[0].Prefix.String() != "2001:db8:ffff::1/32" {
				t.Fatalf("decoded table %+v and announcement %+v", cfg.Cap.Table, cfg.Cap.Route)
			}
		})
	}
}

func TestSourcedExamples(t *testing.T) {
	for _, name := range []string{"toml", "yaml"} {
		cfg, err := load(t, "."+name, readExample(t, name, true))
		if err != nil {
			t.Fatalf("%s with options enabled: %v", name, err)
		}
		if cfg.Cap.Table == nil || cfg.Cap.Table.Sourced == nil ||
			len(cfg.Cap.Table.Sourced.To) != 1 || cfg.Cap.Table.Sourced.To[0].String() != "2001:db8:ffff::/48" ||
			cfg.Cap.Table.Sourced.ID != 300 {
			t.Fatalf("%s: wrong sourced table: %+v", name, cfg.Cap.Table)
		}
	}
}
