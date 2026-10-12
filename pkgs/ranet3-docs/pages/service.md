---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "Running it as a service"
description: "Running ranet3 from the NixOS and nix-darwin modules."
created: 2026-09-22
updated: 2026-10-13
order: 40
---

The nixos module runs the daemon from this flake's package, writes the config
file from `networking.ranet3.settings`, and gives the control socket a
`RuntimeDirectory` and a group:

```nix
{
  imports = [ inputs.ranet3.nixosModules.ranet3 ];

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
      dial.all = true;
    };
  };
}
```

`settings` is written to the store and is world readable there, so the key and
the trust document are named by path rather than carried inline. A config file
that must stay out of the store entirely is named by `configFile` instead.
`systemctl reload ranet3` runs `ranet3 reload`, which reconciles against a
rewritten trust document without dropping an SA and fails when the daemon
refuses what it read. A restart drops every one. An `extraArgs` that moves the
control socket with `--control` moves `ranet3 reload` with it, to the last
`--control` given, as the daemon reads them. One that turns the socket off with
`--control ""` leaves a reload nothing to ask, and the module refuses it at
evaluation while a change to the config file still reloads the unit.

The unit's `StateDirectory` is `/var/lib/ranet3`, at mode 0700, and the module
passes it to the daemon with `--state-dir`. It holds the flag `ranet3 down`
writes, which keeps a node taken off the mesh off it through
`systemctl restart ranet3` and a reboot until `ranet3 up`, as
[taking a node off the mesh](control-socket.md#taking-a-node-off-the-mesh)
describes.

## What a switch does

The unit starts the daemon with `/etc/ranet3/config.toml`, which the module
links to the file it generated from `settings`. A `configFile` is linked in its
place, and the link keeps the file's extension, so a YAML file is at
`/etc/ranet3/config.yaml`. A change to `settings` changes that link and the
unit's reload triggers, so a switch runs `ranet3 reload` where it would
otherwise restart the daemon. A trust document built in the store and named by
its store path in `settings.auth.trust` is one such change, and every session
the new document still names stays. The store is readable by every user of the
host.

A change the daemon refuses to reload, such as a new port or key, fails the
switch with status 4, and the daemon's reason is in the unit's log. The daemon
keeps its old configuration until `systemctl restart ranet3` applies the new
one, which drops every SA. [Reloading](reloading.md) lists what a reload
applies. A new build of the package, or a change to `logLevel` or `extraArgs`,
changes the command line, and the switch restarts the daemon.

## Restarts and the network

The unit starts the daemon again 5 seconds after it fails, and it does not stop
trying. A key that a secrets tool has not installed yet, or a port that another
IKE daemon still holds during a migration, costs 5 seconds a try and nothing
else.

dhcpcd and NetworkManager are told to leave the tun alone. `ranet*` and the name
`link.tun` gives go in `networking.dhcpcd.denyInterfaces` and, as
`interface-name:` entries, in `networking.networkmanager.unmanaged`.

## nix-darwin

The nix-darwin module, `darwinModules.ranet3`, is the same options over
`launchd.daemons`, with the log file taking the place of the journal and `admin`
as the default group, because that is a group macOS already has and nothing here
creates one. It was evaluated by hand against nix-darwin, which produced the
expected plist, and it has never been loaded on a Mac. No check covers it:
verifying it in CI would mean taking nix-darwin as an input of this flake, which
nothing else here needs.

The daemon makes `/var/run/ranet3` in the job's group, whether the control
socket or the record `link.underlay.bind` keeps there makes it first. One an
earlier version made is in `daemon`, the group of `/var/run`, which keeps the
control socket out of the job group's reach until the directory takes the job's
group, `admin` unless `networking.ranet3.group` names another, with the job
stopped:

```sh
sudo launchctl bootout system/org.nixos.ranet3
sudo chgrp admin /var/run/ranet3
sudo launchctl bootstrap system /Library/LaunchDaemons/org.nixos.ranet3.plist
```

A reboot does it as well, since macOS clears `/var/run` as it starts and the
daemon makes the directory afresh. Removing the directory instead takes
`underlay.json` with it, and a scoped default the record still holds, one a
start refused to withdraw, then stays on its interface for good.

The daemon keeps the flag `ranet3 down` writes in `/var/db/ranet3`, its default
state directory on darwin, and makes the directory at mode 0700 the first time,
which leaves the job no `--state-dir` to pass.

launchd has no reload path, so the job names the store path of the config file,
and any change to `settings` restarts the daemon.

nix-darwin loads its launchd jobs before a secrets tool has installed the key
and the trust document. Where the module renders the config file from
`settings`, the job waits up to 60 seconds in all for `auth.key` and
`auth.trust` to exist before it starts the daemon, so the daemon does not exit
once and come back about 10 seconds later through `KeepAlive`. When the 60
seconds are up, the daemon starts anyway and fails with its own message in the
log. A `configFile` set by hand names no file the module can read, and the job
then waits for none.

`openFirewall` lets the binary through the application firewall when the
configuration is activated. Every build is a store path of its own, and
`socketfilterfw --add` never removes an entry, so activation also removes the
entries earlier builds left. An entry it cannot remove, or a listing that fails,
is reported and does not stop the activation.
