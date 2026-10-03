---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "Running it as a service"
description: "Running ranet3 from the NixOS and nix-darwin modules."
created: 2026-09-22
updated: 2026-10-03
order: 40
---

The nixos module runs the daemon from this flake's package, writes the config
file from `networking.ranet3.settings`, and gives the control socket a
`RuntimeDirectory` and a group:

```nix
{
  imports = [ inputs.ranet3.nixosModules.default ];

  networking.ranet3 = {
    enable = true;
    group = "ranet3";
    settings = {
      node = {
        org = "example";
        name = "gateway";
      };
      auth = {
        key = "/var/lib/ranet3/key.pem";
        trust = "/var/lib/ranet3/trust.json";
      };
      link = {
        port = 13000;
        endpoints = [
          {
            serial = "0";
            family = "ip4";
          }
        ];
      };
    };
  };
}
```

`settings` is written to the store and is world readable there, so the key and
the trust document are named by path rather than carried inline. A config file
that must stay out of the store entirely is named by `configFile` instead.
`systemctl reload ranet3` sends SIGHUP, which reconciles against a rewritten
trust document without dropping an SA. A restart drops every one.

The nix-darwin module is the same options over `launchd.daemons`, with the log
file taking the place of the journal and `admin` as the default group, because
that is a group macOS already has and nothing here creates one. It was evaluated
by hand against nix-darwin, which produced the expected plist, and it has never
been loaded on a Mac. No check covers it: verifying it in CI would mean taking
nix-darwin as an input of this flake, which nothing else here needs.
