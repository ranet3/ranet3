---
# SPDX-FileCopyrightText: 2026 Nick Cao
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: MIT AND CC-BY-4.0
title: "Getting started"
description: "Building the binary, the binary cache, and running a node by hand."
created: 2026-08-17
updated: 2026-10-21
order: 20
---

## Building

```sh
cd pkgs/ranet3 && go build -o ranet3 ./cmd/ranet3
```

Requires Go 1.26.3 or later.

On Linux the daemon needs `CAP_NET_ADMIN` to create the tun and to write routes.
A `link.port` below 1024 also needs `CAP_NET_BIND_SERVICE`. Root has both. On
macOS, creating a utun and writing routes need root.

A binary run with these capabilities instead of root also needs a state
directory it can write. The daemon refuses to start when it cannot create or
read that directory. It is `/var/lib/ranet3` on Linux and `/var/db/ranet3` on
macOS, unless `--state-dir` names another. Without write access to
`/var/run/ranet3`, the daemon runs with no control socket. A `--control` path
the daemon cannot create stops the start instead.

## Binary cache

- Cache: <https://cache.ysun.co>
- Key: `cache.ysun.co-1:WxPYwT5g3kt9XhUhHPpNLZKI9HIOsVVAuqSHpok8Qt4=`

## Running

With nix, from the flake:

```sh
sudo nix run github:ranet3/ranet3 -- daemon --config /etc/ranet3/config.toml
```

Or with the binary built above:

```sh
sudo ./ranet3 daemon --config /etc/ranet3/config.toml
```

`--config` defaults to `/etc/ranet3/config.toml`. The config file names the
node, its key and trust document, its port and endpoints, and the peers it
dials.
[`examples/config.toml`](https://github.com/ranet3/ranet3/blob/master/pkgs/ranet3/examples/config.toml)
is an annotated example, with the same schema in
[YAML](https://github.com/ranet3/ranet3/blob/master/pkgs/ranet3/examples/config.yaml)
and
[JSON](https://github.com/ranet3/ranet3/blob/master/pkgs/ranet3/examples/config.json).
[The configuration reference](configuration-reference.md) lists every key, and
[command line](cli.md) lists the daemon's flags.

On startup the daemon logs the tun's name. The device is `ranet3` on Linux
unless `link.tun` names another (see [Configuration](configuration.md)). On
macOS it is the utun unit the daemon got, such as `utun6`.

Without a `cap.table` block, the line ends in
`configure its addresses and kernel routes externally`. Traffic won't flow until
you configure them, for example on Linux:

```sh
ip addr add 203.0.113.10/32 dev ranet3
ip route add 203.0.113.0/24 dev ranet3
```

With `cap.table`, the node installs its routes itself. It assigns the addresses
`cap.table.addresses` lists, and with `cap.table.assign_announced` the prefixes
it announces. On Linux the routes go into table `cap.table.id`, 200 unless set.
The host reads that table only through a policy rule, such as a
`cap.table.rules` entry, or through a VRF. The line then names where the node
reconciles, such as `table 200 protocol 155` on Linux or `interface utun6` on
macOS.

`daemon` is the node. Most other subcommands speak to a running daemon over its
control socket, and they ship in the same binary. Most of them ask a question,
while `disable`, `enable`, `redial`, `rekey`, `reload`, `down` and `up` act on
one. `version` without `--daemon`, `licenses`, `completion`, `debug buildinfo`
and `help` run without a daemon. See [Control socket](control-socket.md) and
[command line](cli.md).

`ranet3 completion bash`, `ranet3 completion zsh` or `ranet3 completion fish`
writes that shell's completion script, as
[command line](cli.md#shell-completion) describes. The Nix package does not
install one.
