---
# SPDX-FileCopyrightText: 2026 Nick Cao
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: MIT AND CC-BY-4.0
title: "Getting started"
description: "Building the binary, the binary cache, and running a node by hand."
created: 2026-08-17
updated: 2026-10-06
order: 20
---

## Building

```sh
cd pkgs/ranet3 && go build -o ranet3 ./cmd/ranet3
```

Requires Go 1.26+. Creating the TUN device needs `CAP_NET_ADMIN` (root, or that
capability granted to the binary).

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

On startup it logs the TUN device's name, `ranet3` on linux unless `link.tun`
names another (see [Configuration](configuration.md)). Traffic won't flow until
you configure it yourself, e.g.:

```sh
ip addr add 10.66.0.5/32 dev ranet3
ip route add 10.66.0.0/16 dev ranet3
```

`daemon` is the node; every other subcommand speaks to a running one over its
control socket, so `ranet3 status` and its siblings work alongside a
deployment's own `ranet3 daemon` with no second binary and no second unit. Most
of them ask a question; `disable`, `enable`, `redial`, `rekey` and `reload` act
on one. See [Control socket](control-socket.md).
`ranet3 completion
bash|zsh|fish` writes the shell's completion script,
generated from the command tree so a command added without one is completed
anyway, and a peer or a subsystem an argument takes is completed from the
running node.
