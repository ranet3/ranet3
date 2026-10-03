---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: Repository layout
description: Where everything lives in the repository.
created: 2026-10-03
updated: 2026-10-03
order: 10
---

ranet3 is one repository holding every package it ships, each under `pkgs/`,
with the nix that builds and deploys them beside it.

```
flake.nix               the flake, loaded by directory through autopilot
licenses/               the license texts every file names
lib/                    nix helpers
modules/flake/          checks, packages, overlays, the shell and the formatter
modules/nixos/          the NixOS module, networking.ranet3
modules/darwin/         the nix-darwin module, networking.ranet3
integration/            NixOS VM tests and the namespace benchmark
pkgs/ranet3/            the go module, ranet3.com/pkgs/ranet3
pkgs/ranet3-docs/       these pages
pkgs/iperf3-benchmark/  the iperf3 build the benchmarks use
```

The go module is one module with one dependency set. Its packages at the top of
`pkgs/ranet3` are the ones another program can import: `control`, `esp`, `ike`,
`sadr`, `schema`, `srv6` and `transport`. Everything under `internal/` is this
program's own. Go commands run from `pkgs/ranet3`.

Every directory under `pkgs/` with a `default.nix` is a package of the flake,
named after the directory, so `pkgs/ranet3` builds as `packages.<system>.ranet3`
and the default package.

Every file names its license in SPDX lines at its top, or in a `REUSE.toml` in
its own directory or one above it when it cannot carry a comment. `license.txt`
at the root says which license covers what.
