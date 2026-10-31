// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

module ranet3.com/pkgs/ranet3

go 1.26.3

require (
	github.com/BurntSushi/toml v1.6.0
	github.com/spf13/cobra v1.10.2
	go.yaml.in/yaml/v3 v3.0.5
	golang.org/x/crypto v0.58.0
	golang.org/x/net v0.62.0
	golang.org/x/sys v0.49.0
	hegel.dev/go/hegel v0.9.28
	ranet3.com/pkgs/wireguard v0.0.0-00010101000000-000000000000
)

require (
	github.com/ebitengine/purego v0.12.0-alpha.1.0.20261017145726-715acd0097ea // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
)

replace ranet3.com/pkgs/wireguard => ../wireguard
