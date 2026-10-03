---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "Reloading"
description: "What a reload applies without dropping a session, and what needs a restart."
created: 2026-09-12
updated: 2026-10-03
order: 70
---

`SIGHUP` re-reads the config file and the registry and reconciles rather than
restarting. It applies the registry itself, the peers dialed, and the prefixes
originated, so a node joining or leaving the mesh costs one dialer instead of
dropping every SA this node is carrying. ranet's own `ExecReload` works the same
way, and it matters because the registry is rewritten every time any node joins.

A reload also decides which sessions stay. The registry is the trust root a
handshake is checked against, so a node taken out of it stops being carried:
every session whose authenticated peer the new registry no longer names is
closed, and the line naming it says so. A registry read mid-write fails to parse
rather than arriving empty, so the sweep never runs against half a file.

A session this node dialed also ends when its dialer does, and taking the peer
out of `peers:` stops that dialer. One the peer opened against this node's
`responder` survives, because nothing was dialing it.

Revocation tests whether the organization still names the node and its key still
parses, not which endpoint the peer asserted. Renumbering a serial is a registry
edit rather than a revocation, and a node whose own endpoints were renumbered
has done nothing to lose the session it is carrying.

Everything else is refused rather than applied, because a reload cannot reach
it. Identity, port, TUN device and local endpoints each change what peers have
already authenticated or what the dataplane is attached to. So does the private
key. It is read once at startup and the responder holds its own copy, so a
reload re-reads the file only to compare: a rotation is refused by name whether
it moved the path or rewrote the file in place, rather than reported as applied
while the node keeps signing with the key it started on. The `babel` block is
built into the speaker once, apart from the prefixes it originates, which a
reload does apply. The `kernel` block, including the addresses
`assign_originated` expands into, is read once at startup, and so is the
`cap.egress`: the capability owns the tables it created under the families the
old block named, and a new one applied here would leave the host holding rules
from a configuration nothing is running. The rekey and replay settings are
captured by a session when it is created, so applying them to new sessions alone
would leave the node running two policies at once. And `responder` decides
whether the node answers at all, which is wired up before the reload path
exists. A restart is the honest way to change any of them, and a reload that
fails validation changes nothing.
