---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "Repository layout"
description: "Where everything lives in the repository."
created: 2026-10-03
updated: 2026-10-25
order: 10
---

ranet3 is 1 repository holding every package it ships, each under `pkgs/`, with
the Nix that builds and deploys them beside it.

```text
flake.nix               the flake, loaded by directory through autopilot
flake.lock              the pinned flake inputs
atelier.toml            the systems and outputs CI builds, and the ones it skips
license.txt             which license covers what
REUSE.toml              the licenses of flake.lock and the test keys, which carry no comment
readme.md               the front page of the repository
.envrc                  direnv's entry to the flake's default dev shell
.gitattributes          line endings and diff drivers by file type
.gitignore              build results, test binaries, local keys and registries
.github/workflows/      ci.yaml runs the flake through atelier, merge.yaml merges bot
                        pull requests whose checks pass, pages.yaml deploys raweb3
.github/dependabot.yaml weekly updates of the actions and the flake inputs
.github/codeowners      the owner of every path
licenses/               the license texts every file names
lib/                    Nix helpers
modules/flake/          the formatter, the overlay, the package and check outputs,
                        the module loader under modules/flake/modules/, and the shells
modules/nixos/          the NixOS module, networking.ranet3
modules/darwin/         the nix-darwin module, networking.ranet3
modules/common/         the options both modules import
checks/                 checks, the VM tests among them, and the profiling runs
checks/fixtures/        the synthetic organization key pair the tests use
pkgs/ranet3/            the Go module, ranet3.com/pkgs/ranet3
pkgs/raweb3/            ranet3.com with these pages, and the generator that builds it
pkgs/iperf3-benchmark/  the iperf3 build the benchmarks use
pkgs/wireguard/         wireguard-go's tun, conn and rwcancel, ranet3.com/pkgs/wireguard
```

## The Go module

The Go module has 1 dependency set. Its packages at the top of `pkgs/ranet3` are
the ones another program can import: `control`, `esp`, `identity`, `ike`,
`sadr`, `schema`, `srv6` and `transport`. Everything under `internal/` is this
program's own. Go commands run from `pkgs/ranet3`.

| Directory                    | What it holds                                                                                                                          |
| ---------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| `cmd/ranet3`                 | the `ranet3` binary: `ranet3 daemon` and every command that asks a running node                                                        |
| `control`                    | the control socket's wire format, its client and server, the text renderers and the debug views, with golden files in `testdata/debug` |
| `esp`                        | userspace ESP (RFC 4303) in tunnel mode, carried in UDP (RFC 3948)                                                                     |
| `identity`                   | the name of a node and of each of its endpoints                                                                                        |
| `ike`                        | an IKEv2 initiator and responder in the minimal shape of RFC 7815                                                                      |
| `sadr`                       | source address dependent routing tables                                                                                                |
| `schema`                     | the scalar spellings a config file is written in, and which routes count as a default                                                  |
| `srv6`                       | SRv6 in userspace: the routing header (RFC 8754), H.Encaps, End and End.DT46 (RFC 8986)                                                |
| `transport`                  | the UDP sockets on 1 port for both IKE and ESP                                                                                         |
| `examples`                   | `config.toml`, `config.json` and `config.yaml`, which the `internal/config` tests parse                                                |
| `internal/babel`             | the Babel speaker (RFC 8966)                                                                                                           |
| `internal/client`            | the mesh runtime: peers, sessions, reload, path MTU, up and down, metrics and the daemon's side of the debug views                     |
| `internal/cmd/notices`       | writes `internal/notices/third_party.md`                                                                                               |
| `internal/cmd/babeltest`     | test tool: runs the client stack against a strongSwan responder and a Babel peer such as BIRD, and reports the routes it learns        |
| `internal/cmd/esptest`       | test tool: sends 1 ICMP echo sealed in ESP to a strongSwan responder's kernel, to check the ESP framing                                |
| `internal/cmd/gendn`         | test tool: prints the strongSwan `asn1dn:#hex` identity for an organization, common name and serial number                             |
| `internal/cmd/iketest`       | test tool: runs 1 IKEv2 initiator handshake against a strongSwan responder and prints the negotiated Child SA                          |
| `internal/config`            | reads the config file                                                                                                                  |
| `internal/egress`            | the `cap.egress` and `cap.border` capabilities, the `Exit` every exit backend sits behind, and the border filter's reports             |
| `internal/egress/kernel`     | the kernel exit, which translates the source of what exit nodes and subnet routers carry with nftables, and the border filter          |
| `internal/egress/egresstest` | the exit behavior suite every exit backend passes, imported by test files alone                                                        |
| `internal/events`            | the event recorder behind `debug events`                                                                                               |
| `internal/goldentest`        | holds a test's output to its golden file, which `-update` rewrites, imported by test files alone                                       |
| `internal/kernel`            | the route reconciler, the host network watch, and on macOS the scoped default route a bound underlay socket can need                   |
| `internal/logtest`           | swaps the default logger for 1 test, imported by test files alone                                                                      |
| `internal/netnstest`         | the network namespaces, links, addresses and routes of the Linux root tests, imported by test files and `internal/egress/egresstest`   |
| `internal/netstack`          | moves packets between the tun and the sessions, and decides each packet a session delivers, forwarding transit between sessions        |
| `internal/nftables`          | writes, reads back and watches the translator's and the border filter's nf_tables tables, chains and rules over netlink                |
| `internal/notices`           | the third-party notice the binary embeds and `ranet3 licenses` prints                                                                  |
| `internal/packet`            | checks the IP envelope of packets, and what a router does with an IPv4 header it forwards: its checks, TTL, options and ICMPv4 errors  |
| `internal/pbt`               | the settings every property test runs under                                                                                            |
| `internal/registry`          | reads ranet's `registry.json` and Ed25519 key files, with a fixture in `testdata`                                                      |
| `internal/version`           | the build's version and revision                                                                                                       |

Beside the packages, `pkgs/ranet3` holds `go.mod` and `go.sum`, `gomod2nix.toml`
for the Nix build, `version.txt` with the release version, a `license.txt` and a
`REUSE.toml` of its own, `default.nix`, `shell.nix`, and an `.envrc` that enters
the `ranet3` dev shell. `default.nix` lists every top-level directory the build
takes. A new top-level package has to be added to that list.

`pkgs/wireguard` is a second Go module, `ranet3.com/pkgs/wireguard`, with a
`go.mod`, `go.sum` and `gomod2nix.toml` of its own. It keeps upstream's style
and license, and its `readme.md` says which upstream and tailscale commits it is
built from and how it follows upstream.

## The site and these pages

`pkgs/raweb3` builds ranet3.com, these pages among it, with a generator of its
own, the Go module `ranet3.com/pkgs/raweb3`. Each page is a Markdown file with
YAML frontmatter, rendered into templ components and styled with Tailwind.

| Path             | What it holds                                                                                                                                   |
| ---------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| `pages/`         | the pages by the path they serve at: `index.md` is the front page, and `docs/` holds these pages, with `design/` and `development/` beneath     |
| `site.yaml`      | the site's title and address, the `go-import` and `go-source` metas, the analytics, the header links, the call to action and the footer's facts |
| `static/`        | files the site serves as they are, `favicon.svg` among them                                                                                     |
| `cmd/raweb3`     | the `raweb3` binary: `raweb3 build` writes the site to a directory, `raweb3 serve` renders each page as it is asked for                         |
| `internal/site`  | loads `site.yaml` and the pages, checks them, and renders, highlights and minifies every page                                                   |
| `internal/pages` | the layouts: the frame every page shares, with its header, theme switch and notice, and the docs, page and 404 layouts                          |
| `ui/`            | what another site in the repository can take: the head, the logo mark drawn in SVG and in text, and `style.css`, the colors and components      |
| `default.nix`    | the generator's build, and the site's, which runs `raweb3 build` with Tailwind                                                                  |
| `shell.nix`      | the `raweb3` dev shell                                                                                                                          |
| `.envrc`         | direnv's entry to that shell                                                                                                                    |

Beside them are `go.mod`, `go.sum`, `gomod2nix.toml` and a `REUSE.toml` of its
own. A file `a.md` serves at `/a/`, and so does `a/index.md`. Both in one
directory fail the build.

Every page's frontmatter carries `title`, `description`, `created` and
`updated`, and a page under `docs/` also an `order`, its place in the sidebar.
`layout` is optional: under `docs/` a page takes the docs layout, elsewhere
`page`, and `bare` leaves the whole width to the Markdown, as the front page
does. `vetted: <date>` is optional too. Only the maintainer sets it, by hand, on
the day they last read the page in full. A page without it, or with a `vetted`
older than its `updated`, shows a notice that it may contain unreviewed machine
generated text.

A page places a component of `ui/` with an empty element named after it, such as
`<ui-ascii-mark></ui-ascii-mark>` for the logo mark drawn in text, and sets its
size and where it shows on an element around it.

A fenced code block names its language after the opening fence, and chroma
splits it into tokens, each colored as Nord's syntax guide colors its kind. A
block that names no language shows as plain text.

The build fails on a missing field, an `updated` before `created`, a relative
link to a page that does not exist, a link to a heading the page does not have,
a code block in a language chroma has no lexer for, and a `ui-` element that
names no component or holds content. A relative link to a `.md` file serves as
the path of that page.

`.github/workflows/pages.yaml` deploys `raweb3` to GitHub Pages when a push to
`master` changes `pkgs/raweb3`, the workflow or `flake.lock`.

## Flake outputs

Every directory under `pkgs/` with a `default.nix` is a package of the flake,
named after the directory, so `pkgs/ranet3` builds as
`legacyPackages.<system>.ranet3`. `packages.<system>.default` is the same build,
for `nix run` with no attribute. A directory under `pkgs/` with a `shell.nix` is
also a dev shell of the same name.

`<system>` is `x86_64-linux`, `aarch64-linux` or `aarch64-darwin`.

| Output                                                              | What it is                                                                                                                                                                                  |
| ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `packages.<system>.default`                                         | `ranet3`, for `nix run` with no attribute                                                                                                                                                   |
| `legacyPackages.<system>.ranet3`                                    | the `ranet3` binary                                                                                                                                                                         |
| `legacyPackages.<system>.raweb3`                                    | ranet3.com with these pages, checked as it builds                                                                                                                                           |
| `legacyPackages.<system>.iperf3-benchmark`                          | the iperf3 build the benchmarks use                                                                                                                                                         |
| `legacyPackages.<system>.wireguard`                                 | the Go module in `pkgs/wireguard`, built without its tests                                                                                                                                  |
| `legacyPackages.<system>.profile.integration`, `.profile.namespace` | the profiling runs [testing](testing.md) describes, which build only on Linux                                                                                                               |
| `checks.<system>.go-test`, `.go-lint`, `.tree`                      | the Go tests, the linters, and the format and licenses of the tree with its `atelier.toml` exclusions, on every system                                                                      |
| `checks.<system>.wireguard`                                         | the vet and the tests of `pkgs/wireguard`, on every system                                                                                                                                  |
| `checks.<system>.raweb3`                                            | the vet and the tests of the generator in `pkgs/raweb3`, on every system                                                                                                                    |
| `checks.<system>.netlink`, `.integration-*`                         | the VM tests, on Linux                                                                                                                                                                      |
| `devShells.<system>.default`                                        | deno, git, nixfmt-tree and taplo                                                                                                                                                            |
| `devShells.<system>.ranet3`                                         | the default shell, the build inputs of `ranet3`, go-tools, gomod2nix, gopls, pprof and Python, and on Linux BIRD, strongSwan, iproute2, iputils, ethtool, util-linux and `iperf3-benchmark` |
| `devShells.<system>.raweb3`                                         | the default shell, the build inputs of the generator, go-tools, gomod2nix, gopls and Tailwind                                                                                               |
| `formatter.<system>`                                                | what `nix fmt` runs, which [testing](testing.md) lists                                                                                                                                      |
| `overlays.default`                                                  | every package under `pkgs/`                                                                                                                                                                 |
| `nixosModules.ranet3`                                               | the NixOS module                                                                                                                                                                            |
| `darwinModules.ranet3`                                              | the nix-darwin module                                                                                                                                                                       |

## Licenses

Every file names its license in SPDX lines at its top, or in a `REUSE.toml` in
its own directory or one above it. A `REUSE.toml` names a file that cannot carry
a comment, and in `pkgs/wireguard` also a copied file that came without a
header, which stays as it was written. `license.txt` at the root says which
license covers what.
