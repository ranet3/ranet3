---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "Repository layout"
description: "Where everything lives in the repository."
created: 2026-10-03
updated: 2026-11-10
order: 10
---

The project is 1 repository holding every package it ships, each under `pkgs/`,
with the Nix that builds and deploys them beside it.

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
modules/common/         the options both modules import, the paths and the reload
                        command both derive, and the nix-darwin activation steps
checks/                 checks, the VM tests among them, and the profiling runs
checks/fixtures/        the synthetic organization key pair the tests use
pkgs/ranet3/            the Go module, ranet3.com/pkgs/ranet3
pkgs/raweb3/            ranet3.com with these pages, and the generator that builds it
pkgs/iperf3-benchmark/  the iperf3 build the benchmarks use
pkgs/wireguard/         wireguard-go's tun, conn and rwcancel, ranet3.com/pkgs/wireguard
pkgs/go-tools/          go-tools, built with go_latest
pkgs/gomod2nix/         gomod2nix, built with go_latest
pkgs/templ/             templ, built with go_latest
```

## The Go module

The Go module has 1 dependency set. Its packages at the top of `pkgs/ranet3` are
the ones another program can import: `control`, `esp`, `identity`, `ike`,
`sadr`, `schema`, `srv6` and `transport`. Everything under `internal/` is this
program's own. Go commands run from `pkgs/ranet3`.

| Directory                    | What it holds                                                                                                                                                                                                 |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cmd/ranet3`                 | the `ranet3` binary: `ranet3 daemon` and every command that asks a running node                                                                                                                               |
| `control`                    | the control socket's wire format, its client and server, the text renderers and the debug views, with golden files in `testdata/debug`                                                                        |
| `esp`                        | userspace ESP (RFC 4303) in tunnel mode, carried in UDP (RFC 3948)                                                                                                                                            |
| `identity`                   | the name of a node and of each of its endpoints                                                                                                                                                               |
| `ike`                        | an IKEv2 initiator and responder in the minimal shape of RFC 7815                                                                                                                                             |
| `sadr`                       | source address dependent routing tables                                                                                                                                                                       |
| `schema`                     | the scalar spellings a config file is written in, and which routes count as a default                                                                                                                         |
| `srv6`                       | SRv6 in userspace: the routing header (RFC 8754), H.Encaps, End and End.DT46 (RFC 8986)                                                                                                                       |
| `transport`                  | the UDP sockets on 1 port for both IKE and ESP                                                                                                                                                                |
| `examples`                   | `config.toml`, `config.json` and `config.yaml`, which the `internal/config` tests parse                                                                                                                       |
| `internal/babel`             | the Babel speaker (RFC 8966)                                                                                                                                                                                  |
| `internal/bubble`            | runs a test in a `testing/synctest` bubble bounded in real time, imported by test files alone                                                                                                                 |
| `internal/client`            | the mesh runtime: peers, sessions, reload, path MTU, up and down, metrics and the daemon's side of the debug views                                                                                            |
| `internal/cmd/notices`       | writes `internal/notices/third_party.md`                                                                                                                                                                      |
| `internal/codel`             | the controlled delay of RFC 8289 a peer's sender and the userspace exit's pump run over their queues                                                                                                          |
| `internal/config`            | reads the config file                                                                                                                                                                                         |
| `internal/dnstest`           | a nameserver on lo recording each query's mark, behind a resolv.conf of the test's own, imported by test files alone                                                                                          |
| `internal/egress`            | the `cap.egress` and `cap.antispoof` capabilities, the `Exit` every exit backend sits behind, and the antispoof filter's reports                                                                              |
| `internal/egress/egresstest` | the exit behavior suite every exit backend passes, imported by test files alone                                                                                                                               |
| `internal/egress/kernel`     | the kernel exit, which translates the source of what exit nodes and subnet routers carry with nftables, and the antispoof filter                                                                              |
| `internal/egress/userspace`  | the userspace exit macOS carries, ending each TCP connection in gVisor's stack and relaying UDP and echo through the host's sockets, with its raw sockets in `raw`                                            |
| `internal/events`            | the event recorder behind `debug events`                                                                                                                                                                      |
| `internal/goldentest`        | holds a test's output to its golden file, which `-update` rewrites, imported by test files alone                                                                                                              |
| `internal/kernel`            | the route reconciler, the host network watch, and on macOS the selection that names each underlay datagram's interface                                                                                        |
| `internal/logtest`           | swaps the default logger for 1 test, imported by test files alone                                                                                                                                             |
| `internal/netnstest`         | the network namespaces, links, addresses and routes of the Linux root tests, imported by test files, `internal/egress/egresstest` and `internal/dnstest`                                                      |
| `internal/netstack`          | moves packets between the tun and the sessions, and decides each packet a session delivers, forwarding transit between sessions                                                                               |
| `internal/nftables`          | writes, reads back and watches the translator's, the antispoof filter's and the kill switch's chains, rules, sets and timeout objects in the nftables table `inet ranet3` over netlink                        |
| `internal/notices`           | the third-party notice the binary embeds and `ranet3 licenses` prints                                                                                                                                         |
| `internal/packet`            | checks and edits the IP packets the dataplane forwards: the IP envelope, an IPv4 header's checks, TTL and options, ECN fields, fragments of either family, ICMPv4 errors and the addresses no router forwards |
| `internal/pbt`               | the settings every property test runs under                                                                                                                                                                   |
| `internal/pf`                | writes and reads back, through `pfctl`, the antispoof filter's rules and table in a pf anchor on macOS, and holds the reference that keeps pf on                                                              |
| `internal/registry`          | reads ranet's `registry.json` and Ed25519 key files, with a fixture in `testdata`                                                                                                                             |
| `internal/statefile`         | the file lock and the whole-file write of the daemon's state files: the record of the pf reference, the control socket's lock, the down flag and the Babel state                                              |
| `internal/underlay`          | the one way each platform keeps a socket out of the mesh, the `Prepare` the transport, the resolver and the userspace exit take from their caller                                                             |
| `internal/version`           | the build's version and revision                                                                                                                                                                              |

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

| Path             | What it holds                                                                                                                                                               |
| ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pages/`         | the pages by the path they serve at: `index.md` is the front page, `docs/` holds these pages, with `design/` and `development/` beneath, and `news/` the news and its posts |
| `site.yaml`      | the site's title and address, the `go-import` and `go-source` metas, the analytics, the header links, the call to action and the footer's facts                             |
| `static/`        | files the site serves as they are, `favicon.svg` among them                                                                                                                 |
| `cmd/raweb3`     | the `raweb3` binary: `raweb3 build` writes the site to a directory, `raweb3 serve` renders each page as it is asked for                                                     |
| `internal/site`  | loads `site.yaml` and the pages, checks them, and renders, highlights and minifies every page                                                                               |
| `internal/pages` | the layouts: the frame every page shares, with its header, theme switch and notice, and the docs, page, bare, news, post and 404 layouts                                    |
| `ui/`            | what the site's pages take: the head, `style.css` with the colors and components, and the logo mark, drawn in SVG on every page and in text where a page places it          |
| `default.nix`    | the generator's build, and the site's, which runs `raweb3 build` with Tailwind                                                                                              |
| `shell.nix`      | the `raweb3` dev shell                                                                                                                                                      |
| `.envrc`         | direnv's entry to that shell                                                                                                                                                |

Beside them are `go.mod`, `go.sum`, `gomod2nix.toml` and a `REUSE.toml` of its
own. A file `a.md` serves at `/a/`, and so does `a/index.md`. Both in one
directory fail the build.

Every page's frontmatter carries `title`, `description`, `created` and
`updated`, a page in the docs layout also an `order`, its place in the sidebar,
and a news post also `authors`, naming at least one. `layout` is optional: under
`docs/` a page takes the docs layout, elsewhere `page`, and `bare` leaves the
whole width to the Markdown, as the front page does. Under `news/` the place of
a page decides its layout, and the build fails on a page there that names one:
`news/index.md` takes the news layout, which lists the posts, and every other
page there is a post. Once the news holds a post, the build also writes its Atom
feed, `news/atom.xml`. `vetted: <date>` is optional too. Only the maintainer
sets it, by hand, on the day they last read the page in full. A page without it,
or with a `vetted` older than its `updated`, shows a notice that it may contain
unreviewed machine generated text.

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
`master` of `ranet3/ranet3` changes `pkgs/raweb3`, the workflow, `flake.nix`,
`flake.lock`, `lib` or `modules/flake`, and on a manual run of the workflow in
`ranet3/ranet3`. In a fork the workflow builds the site and deploys nothing.

## Flake outputs

Every directory under `pkgs/` with a `default.nix` is a package of the flake,
named after the directory, so `pkgs/ranet3` builds as
`legacyPackages.<system>.ranet3`. `packages.<system>.default` is the same build,
for `nix run` with no attribute. A directory under `pkgs/` with a `shell.nix` is
also a dev shell of the same name.

`<system>` is `x86_64-linux`, `aarch64-linux` or `aarch64-darwin`.

| Output                                                              | What it is                                                                                                                                                                                              |
| ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `packages.<system>.default`                                         | `ranet3`, for `nix run` with no attribute                                                                                                                                                               |
| `legacyPackages.<system>.ranet3`                                    | the `ranet3` binary                                                                                                                                                                                     |
| `legacyPackages.<system>.raweb3`                                    | ranet3.com with these pages, checked as it builds                                                                                                                                                       |
| `legacyPackages.<system>.iperf3-benchmark`                          | the iperf3 build the benchmarks use                                                                                                                                                                     |
| `legacyPackages.<system>.wireguard`                                 | the Go module in `pkgs/wireguard`, built without its tests                                                                                                                                              |
| `legacyPackages.<system>.go-tools`, `.gomod2nix`, `.templ`          | the tools the checks, the formatter and the dev shells take                                                                                                                                             |
| `legacyPackages.<system>.profile.integration`, `.profile.namespace` | the profiling runs [testing](testing.md) describes, which build only on Linux                                                                                                                           |
| `checks.<system>.go-test`, `.go-lint`, `.tree`                      | the Go tests, the linters, and the format and licenses of the tree with its `atelier.toml` exclusions, on every system                                                                                  |
| `checks.<system>.wireguard`                                         | the vet and the tests of `pkgs/wireguard`, on every system                                                                                                                                              |
| `checks.<system>.raweb3`                                            | the vet and the tests of the generator in `pkgs/raweb3`, on every system                                                                                                                                |
| `checks.<system>.modules`                                           | an evaluation of the NixOS module's networkd default and of the nix-darwin module with its activation steps, on Linux                                                                                   |
| `checks.<system>.netlink`, `.integration-*`                         | the VM tests, on Linux                                                                                                                                                                                  |
| `devShells.<system>.default`                                        | deno, git, nixfmt-tree and taplo                                                                                                                                                                        |
| `devShells.<system>.ranet3`                                         | the default shell, the build inputs of `ranet3`, go-tools, gomod2nix, gopls, pprof, Python and shellcheck, and on Linux BIRD, strongSwan, iproute2, iputils, ethtool, util-linux and `iperf3-benchmark` |
| `devShells.<system>.raweb3`                                         | the default shell, the build inputs of the generator, go-tools, gomod2nix, gopls and Tailwind                                                                                                           |
| `formatter.<system>`                                                | what `nix fmt` runs, which [testing](testing.md) lists                                                                                                                                                  |
| `overlays.default`                                                  | every package under `pkgs/`                                                                                                                                                                             |
| `nixosModules.ranet3`                                               | the NixOS module                                                                                                                                                                                        |
| `darwinModules.ranet3`                                              | the nix-darwin module                                                                                                                                                                                   |

## Licenses

Every file names its license in SPDX lines at its top, or in a `REUSE.toml` in
its own directory or one above it. A `REUSE.toml` names a file that cannot carry
a comment, and in `pkgs/wireguard` also a copied file that came without a
header, which stays as it was written. `license.txt` at the root says which
license covers what.
