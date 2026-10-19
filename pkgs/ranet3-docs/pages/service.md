---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "Running it as a service"
description: "Running ranet3 from the NixOS and nix-darwin modules."
created: 2026-09-22
updated: 2026-10-19
order: 40
---

The NixOS module runs the daemon from this flake's package, writes the config
file from `networking.ranet3.settings`, and gives the control socket a
`RuntimeDirectory` and a group:

```nix
{
  imports = [ inputs.ranet3.nixosModules.ranet3 ];

  networking.ranet3 = {
    enable = true;
    group = "ranet3";
    settings = {
      node = "example/gateway";
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

`systemctl reload ranet3` runs `ranet3 reload`. It re-reads the config file and
the trust document it names without a restart, and it fails when the daemon
refuses what it read. A session closes when the new trust document drops its
peer or holds another key for it. A session this node dialed also closes when
the new file stops dialing that peer. A file that turns `link.listen` off closes
every session this node answered. Every other session stays. A restart drops
every session.

When `extraArgs` moves the control socket with `--control`, `ranet3 reload` asks
the socket the last `--control` names, the one the daemon binds. `--control ""`
turns the socket off and leaves a reload nothing to ask. The module refuses that
at evaluation unless `systemd.services.ranet3.reloadTriggers` is empty.

## Options

Both modules take the same options under `networking.ranet3`. Every option
applies on NixOS and on nix-darwin. The defaults of `group` and `logFile` differ
between the two, and so does what `openFirewall` opens.

| Option               | Type                                       | Default                                                | What it does                                                                                                                                  |
| -------------------- | ------------------------------------------ | ------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `enable`             | bool                                       | `false`                                                | Runs the daemon, as a systemd unit on NixOS and a launchd daemon on nix-darwin.                                                               |
| `package`            | package                                    | the `ranet3` package of this flake                     | The build the host runs. The module adds it to `environment.systemPackages`, which puts `ranet3` on every user's path.                        |
| `settings`           | TOML attribute set                         | `{ }`                                                  | The config file, in the schema of `examples/config.toml`. The module writes it to the store.                                                  |
| `settings.link.port` | port                                       | none, required with `settings`                         | The UDP port IKE and ESP share.                                                                                                               |
| `settings.auth.key`  | absolute path outside the store            | none, required with `settings`                         | The private key. A store path fails evaluation.                                                                                               |
| `configFile`         | path                                       | the file written from `settings`                       | A config file to run in place of `settings`.                                                                                                  |
| `logLevel`           | `"debug"`, `"info"`, `"warn"` or `"error"` | `"info"`                                               | The daemon's `--log-level`.                                                                                                                   |
| `extraArgs`          | list of strings                            | `[ ]`                                                  | Further arguments to `ranet3 daemon`, such as `[ "--metrics" "127.0.0.1:9669" ]`.                                                             |
| `openFirewall`       | bool                                       | `false`                                                | On NixOS, opens `settings.link.port` in `networking.firewall`. On nix-darwin, lets the binary through the application firewall.               |
| `group`              | string                                     | `"ranet3"` on NixOS, `"admin"` on nix-darwin           | The group that may use the control socket. NixOS creates it. nix-darwin creates none, and its default, `admin`, is a group macOS already has. |
| `logFile`            | absolute path outside the store, or `null` | `null` on NixOS, `"/var/log/ranet3.log"` on nix-darwin | Where the daemon's output goes. `null` keeps it in the journal on NixOS and discards it on nix-darwin.                                        |

Members of `group` may run every subcommand and the read paths of the
`ranet3 debug` tree. The other debug paths take root or the daemon's own user,
unless `extraArgs` passes `--debug-access group`.

## The NixOS unit

| Setting                                        | Value                                                                                                                        |
| ---------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `ExecStart`                                    | `ranet3 daemon --config /etc/ranet3/config.<extension> --log-level <logLevel> --state-dir /var/lib/ranet3`, then `extraArgs` |
| `ExecReload`                                   | `ranet3 reload`, with the last `--control` that `extraArgs` gives                                                            |
| `Restart`, `RestartSec`                        | `on-failure`, `5s`                                                                                                           |
| `TimeoutStopSec`                               | `15s`, the time a shutdown has to close every session and withdraw its routes                                                |
| `RuntimeDirectory`                             | `ranet3` at mode 0750, the control socket's directory                                                                        |
| `StateDirectory`                               | `ranet3` at mode 0700                                                                                                        |
| `Group`                                        | `group`                                                                                                                      |
| `AmbientCapabilities`, `CapabilityBoundingSet` | `CAP_NET_ADMIN`, and `CAP_NET_BIND_SERVICE` when `settings` renders the file and `link.port` is below 1024                   |
| `wantedBy`                                     | `multi-user.target`                                                                                                          |
| `wants`, `after`                               | `network-online.target`                                                                                                      |
| `reloadTriggers`                               | `configFile`                                                                                                                 |
| `stopIfChanged`                                | `false`                                                                                                                      |
| `StandardOutput`, `StandardError`              | `append:<logFile>`, when `logFile` is set                                                                                    |

The unit sets no `User`, so the daemon runs as root with only those
capabilities. A `configFile` set by hand gets no `CAP_NET_BIND_SERVICE`, so its
`link.port` has to be 1024 or above.

The module refuses 3 configurations at evaluation:

- `openFirewall` with a `configFile` set by hand, because the module reads the
  port from `settings`.
- A `configFile` that names `/etc/ranet3/config.<extension>`, the path the
  module links it to.
- `--control ""` in `extraArgs` while a change to the config file still reloads
  the unit.

## The state directory

The unit's `StateDirectory` is `/var/lib/ranet3`, at mode 0700, and the module
passes it to the daemon with `--state-dir`. It holds the flag `ranet3 down`
writes, which keeps a node taken off the mesh off it through
`systemctl restart ranet3` and a reboot until `ranet3 up`, as
[taking a node off the mesh](control-socket.md#taking-a-node-off-the-mesh)
describes.

It also holds `babel.json`, which keeps the node's Babel router id through
restarts, crashes and reboots. A restarted node is then the speaker it was to
the rest of the mesh, and its routes carry a seqno past every one it sent
before, which makes them feasible at once wherever its old routes are still
held. The file names the node it belongs to beside the router id and a seqno
limit, at mode 0600:

```json
{
  "node": { "org": "example", "name": "gateway" },
  "router_id": "7201020304050607",
  "seqno_limit": 523
}
```

The limit stays ahead of every seqno the node has sent. Before the speaker uses
a seqno past the limit, it saves a new limit 256 past that seqno. The save
writes the whole file beside its name, syncs it, renames it into place and then
syncs the directory. A start resumes one past the limit the file holds. A crash
at any point of a write leaves the old limit or the new one, and either is ahead
of every seqno sent.

A file that is missing, names another node or cannot be read costs the router id
and nothing else. A disk image or a backup taken from another node holds such a
file. The node then starts under a new router id at seqno 1, and its first write
replaces the file. The start's `babel.seqno.raised` event says why the router id
is new, and the log gives the reason too where the file names another node or
cannot be read. An unreadable file also records a `babel.state.unreadable`
event.

A write that fails is logged and recorded as a `babel.state.unsaved` event, and
the node still raises its seqno when a neighbor asks for a newer one. A crash
before a later write succeeds can then resume at a seqno the node has already
sent. A node that holds this node's routes at a newer seqno finds the new routes
unfeasible. They stay unfeasible until seqno requests raise this node's seqno
past it, or until the source entry there expires, 3 minutes after its last
update.

A start from an older copy of the node's own state directory, such as a snapshot
rollback or a backup restore, can resume at seqnos the node has already sent as
well. Its routes are then unfeasible for up to 3 minutes wherever a far node
holds a newer source entry. Removing `babel.json` before such a start costs the
router id alone, as a missing file does.

`ranet3 debug updown` shows the router id, the seqno and the limit the file
holds, as [debugging](development/debug.md#commands) describes.

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
one, which drops every session. [Reloading](reloading.md) lists what a reload
applies.

A new build, or a change to `package`, `logLevel`, `extraArgs`, `group` or
`logFile`, changes the unit itself. So does a `settings.link.port` that moves
across 1024, a switch between `settings` with a port below 1024 and a
`configFile` set by hand, or a `configFile` with another extension. The switch
then restarts the daemon. With `stopIfChanged` off, the restart comes once the
switch is done. A node switched over its own mesh then keeps the mesh while the
switch runs.

## Restarts and the network

The unit starts the daemon again 5 seconds after it fails, and it does not stop
trying. A key that a secrets tool has not installed yet, or a port another IKE
daemon still holds, costs 5 seconds a try and nothing else.

A tun that goes away under a running node, such as one an operator deleted, is a
failure the daemon cannot repair. It logs `netstack tun failed` with the
interface and the error, records a `netstack.tun.failed` event, and stops as it
does on SIGTERM: it closes every session with its grace period and withdraws its
routes and its translation rules. It then exits 1, and the unit starts it again
5 seconds later, which opens the tun anew. On macOS launchd starts it again
through `KeepAlive`. A single frame the tun hands over that cannot be read as
packets costs that frame alone, as [metrics](metrics.md#tun-reads) describes.

dhcpcd and NetworkManager are told to leave the tun alone. The module adds
`ranet*` to `networking.dhcpcd.denyInterfaces`, and as an `interface-name:`
entry to `networking.networkmanager.unmanaged`. Where the module renders the
config file from `settings`, it adds the name `link.tun` gives to both as well.

## nix-darwin

The nix-darwin module, `darwinModules.ranet3`, takes the same options and runs
the daemon from `launchd.daemons.ranet3`. The log file takes the place of the
journal. No check covers the module. A check would need nix-darwin as an input
of this flake, and nothing else here needs one.

| Key                                    | Value                                                                                                             |
| -------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| `RunAtLoad`                            | `true`                                                                                                            |
| `KeepAlive`                            | `true`, so launchd starts the daemon again whenever it exits                                                      |
| `UserName`                             | `root`                                                                                                            |
| `GroupName`                            | `group`                                                                                                           |
| `StandardOutPath`, `StandardErrorPath` | `logFile`                                                                                                         |
| `ExitTimeOut`                          | `20`, the seconds launchd gives a shutdown to close every session and withdraw its routes before it sends SIGKILL |

The job runs `ranet3 daemon --config <store path> --log-level <logLevel>`, then
`extraArgs`.

The daemon creates `/var/run/ranet3` in the job's group at mode 0750. The
control socket and the `link.underlay.bind` record share the directory, and
whichever comes first creates it. The daemon leaves a directory that already
exists as it is. A directory in another group keeps the control socket out of
the job group's reach until it takes the job's group. Change its group with the
job stopped. The commands below use the default group, `admin`:

```sh
sudo launchctl bootout system/org.nixos.ranet3
sudo chgrp admin /var/run/ranet3
sudo launchctl bootstrap system /Library/LaunchDaemons/org.nixos.ranet3.plist
```

A reboot does it as well, since macOS clears `/var/run` as it starts and the
daemon makes the directory afresh. Do not remove the directory instead. It holds
`underlay.json`, the record of the scoped defaults `link.underlay.bind` writes.
A stop withdraws the defaults it wrote. A start withdraws the ones a killed or
failed run left in the record. Without the record, a default an earlier run left
behind stays on its interface.

The daemon keeps the flag `ranet3 down` writes and `babel.json` in
`/var/db/ranet3`, its default state directory on macOS, and makes the directory
at mode 0700 the first time, which leaves the job no `--state-dir` to pass.

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
