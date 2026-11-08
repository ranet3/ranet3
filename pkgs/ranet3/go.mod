// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

module ranet3.com/pkgs/ranet3

go 1.27.3

require (
	github.com/BurntSushi/toml v1.6.0
	github.com/spf13/cobra v1.10.2
	go.yaml.in/yaml/v3 v3.0.5
	golang.org/x/crypto v0.58.0
	golang.org/x/net v0.62.0
	golang.org/x/sys v0.49.0
	gvisor.dev/gvisor v0.0.0-20261008000517-3b87f090dbda
	hegel.dev/go/hegel v0.9.29
	ranet3.com/pkgs/wireguard v0.0.0-00010101000000-000000000000
)

require (
	github.com/ebitengine/purego v0.12.0-alpha.1.0.20261017145726-715acd0097ea // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	golang.org/x/exp v0.0.0-20261014143641-f0251eb4aa3e // indirect
	golang.org/x/time v0.16.0 // indirect
)

replace ranet3.com/pkgs/wireguard => ../wireguard

replace gvisor.dev/gvisor => github.com/stepbrobd/gvisor v0.0.0-20261108143121-b68f2641a116
