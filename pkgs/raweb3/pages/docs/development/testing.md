---
# SPDX-FileCopyrightText: 2026 Nick Cao
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: MIT AND CC-BY-4.0
title: "Testing"
description: "The unit and property tests, the root-only tests, the Nix checks and CI, the VM tests and the benchmarks."
created: 2026-08-17
updated: 2026-11-07
order: 20
---

The `go test` commands run from `pkgs/ranet3`, where the Go module is, and
everything else from the root of the repository.

```sh
go test ./... -race
```

## Tests on a fake clock

Most of `ike`'s tests open their hubs and sockets on `transport`'s network in
memory rather than on the host's loopback, and run in a
[`testing/synctest`](https://pkg.go.dev/testing/synctest) bubble, so a
retransmission timer, a lifetime or a read deadline costs no real time. A bubble
still running past a bound in real time fails its test by name, so a test that
never blocks ends there rather than at `go test`'s timeout. The network delivers
a datagram to what holds the port it is sent to, whole, copied and in order,
keeps it until it is read, and answers a send to port 0 as the host's loopback
answers the same socket, which Linux decides in
[`ipv4/udp.c`](https://github.com/torvalds/linux/blob/940de590b839f71d6dc846160534bf202401b8b7/net/ipv4/udp.c#L1296)
and
[`ipv6/udp.c`](https://github.com/torvalds/linux/blob/940de590b839f71d6dc846160534bf202401b8b7/net/ipv6/udp.c#L1562)
and macOS in
[`udp_usrreq.c`](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/netinet/udp_usrreq.c#L1884),
[`in_pcb.c`](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/netinet/in_pcb.c#L1556)
and
[`udp6_output.c`](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/netinet6/udp6_output.c#L287).
A mux on it reads a path MTU of 65535 for IPv4 and 65536 for IPv6 with DF set,
what a mux reads over Linux's
[loopback](https://github.com/torvalds/linux/blob/940de590b839f71d6dc846160534bf202401b8b7/drivers/net/loopback.c#L202)
once IPv4's is
[capped](https://github.com/torvalds/linux/blob/940de590b839f71d6dc846160534bf202401b8b7/include/net/ip.h#L500),
and no send is refused for its size. A property test in `transport` runs drawn
scripts on the network and on loopback and compares what each hub and socket
received. GRO and GSO, ICMP errors, the path MTU of a real route, the source an
endpoint is pinned to, the socket mark and connected sockets stay with
`transport`'s tests over real sockets, the root tests below and the VM tests. A
test joins every goroutine it starts at cleanup. A test stays on the real clock
where a goroutine of its session waits for a lock another holds across a timer,
or where its subtests share their parent's hub, and on loopback where it reads
the host's path MTU or the source address the kernel picks. The daemon links
none of the network, which `go-lint` checks.

## Root tests on Linux

The unit tests need no privileges, except for the root tests, which skip unless
run as root. Most of them move a thread of their own into a network namespace
they unshare, and refuse to continue unless it is empty. The
[`netlink` check](#nix-checks) runs them.

`internal/client`'s `TestSetEgressReadyMovesTheMeshBeforeTheAnnouncement`,
`TestAdvertisedEgressWaitsOnReadyAndTheAnnouncement` and
`TestModeTwoEgressFollowsTheAnnouncementWithNoEgressSegment` build the mesh with
`netstack.NewOnDevice` over a device of the test's own, and judge what it
egresses by the packets that device received, so they need no root.
`TestTUNExitEgressesBothModesThroughItsOneTun`, the lab of both egress modes
through the exit's tun, makes a real tun and is a root test.

The `internal/client` tests the command below runs reach the kernel from
whatever thread a goroutine runs on. No single thread can be moved into a
namespace for them, so they take the namespace the test process started in. They
skip without root, and they fail in a namespace that holds a link that is up, an
address or a route. Run them in an empty namespace:

```sh
unshare -rn go test ./internal/client -run '^TestNode(GoingDown|RestartedWhileDown)|^TestSession(MovedUnderTheFloorHandsItsFragmentingOver|LowersItsBudgetAtTheRefusalOfItsOwnData)|^TestDialerTheHostHasNoRouteForDialsAtOnceWhenWoken$'
```

The `cmd/ranet3` tests whose names start with `TestDaemon` and that need root
start the daemon as `ranet3 daemon` does, so they take the namespace the same
way:

```sh
unshare -rn go test ./cmd/ranet3 -run '^TestDaemon'
```

`internal/registry`'s `TestResolverQueryFollowsTheOverlayResolveRemoteIsHanded`
and `internal/client`'s `TestEndpointQueryFollowsTheOverlayInForceAcrossReloads`
look a name up through Go's resolver as the daemon does, and check the mark of
each query by the overlay the lookup is handed. Each starts a nameserver on lo
through `internal/dnstest` and binds a resolv.conf naming it over the
`/etc/resolv.conf` Go's resolver
[reads](https://github.com/golang/go/blob/go1.27.3/src/net/dnsclient_unix.go#L369),
in a mount namespace the whole process runs in. They skip without root and
refuse to start in init's network or mount namespace. Run them in namespaces of
their own:

```sh
unshare -rmn go test ./internal/registry -run '^TestResolver'
unshare -rmn go test ./internal/client -run '^TestEndpointQueryFollowsTheOverlayInForceAcrossReloads$'
```

## The exit behavior suite

`internal/egress/egresstest` holds what every exit backend owes a leaf, whatever
platform carries it. It drives a backend through `egress.Exit` as the dataplane
does for a prefix `cap.egress` advertises: it hands the leaf's packets to
`Egress` while their family is ready and announced, reads what comes back toward
the leaf, and plays the server beyond the exit's uplink. A backend's tests run
it with an arm, which builds the backend, names the source classes it carries,
declares the NAT behaviors it lacks by its nature, each with its reason and the
row of [protocol deviations](../design/protocol-deviations.md) that records it,
and says whether it ends the leaf's TCP. Each class runs on a network of its
own, and each of the suite's rows in both families. The `raweb3` check fails
unless each row the kernel exit's arm declares a limit under is the first cell
of exactly 1 row of that page.

On Linux the suite builds 4 network namespaces, each new and empty and held by a
thread of its own:

- the leaf, behind a tun of its own whose packets the suite hands the exit, with
  a second address in each family for each source's share of the flows and
  hairpinning, which no unbound socket takes as its source
- the exit, with the mesh's tun, a peer the mesh routes the leaf's addresses to,
  which writes what it carries into the leaf's tun, and an uplink with an MTU of
  1340 to the router
- the router, routing the exit's addresses, the leaf's overlay prefix back to
  the exit for `none`, and the server's addresses, and nothing else, with 2
  links to the server, one with an MTU of 1280
- the server, whose side drops each SYN without ACK to the simultaneous open's
  port

It skips without root. Run it in a namespace of its own:

```sh
unshare -rn go test ./internal/egress/kernel -run '^TestKernelExitPassesTheExitBehaviorSuite$'
unshare -rn go test ./internal/egress/egresstest
```

## Root tests on macOS

On macOS the root tests of `internal/kernel`, `internal/netstack`,
`internal/client`, `transport`, `control`, `internal/pf` and
`internal/egress/kernel` run as root, and only with `RANET3_DARWIN_NETTEST=1`
set. They run against the real routing socket, utuns, feth pairs, directories
given a group only root may give, and pf, and the Mac that runs them may be on a
live mesh. The pf tests write only `com.apple/ranet3` and children of
`com.apple` named `ranet3-` and a suffix, skip where `com.apple/ranet3` holds
anything already or the main ruleset calls no child of `com.apple`, leave pf
running as they found it, and fail one that leaves the anchor holding anything
or a reference of its own held. They send datagrams up utuns of their own, from
overlay and outside sources of the documentation ranges to each utun's own
address, and count each on the anchor's rule that took it: a forged overlay
source up an outside utun, an overlay source up the mesh utun and through `lo0`,
a carve-out and the gateway example of
[exemptions](../antispoof.md#a-gateways-site) through the daemon's own sets, a
pass of a later anchor, a reply to a flow from the outside utun's own address
that a later anchor's stateful `pass out` on the mesh utun lets in ahead of the
drop, and its drop where that state is if-bound, and an exemption under `utun*`
over a utun that comes after the first pass, whose exempt source is dropped
until a pass writes the exemption's rule for it. One sends the same reply to a
flow from the mesh utun's own address, which pf passes on the state and XNU's
check of the interface then drops, read in `netstat -s -p ip`. One sets pf's
skip flag on utuns of its own and clears it before it ends, and one loads filter
rules into the main ruleset and puts back the ones it found.

## Property tests

The packages that read bytes a peer or a file chooses also carry property tests,
in files ending in `_property_test.go`: `esp`, `ike`, `identity`, `transport`,
`sadr`, `srv6`, `internal/babel`, `internal/packet`, `internal/netstack`,
`schema`, `internal/config`, `internal/registry`, `internal/client`,
`internal/kernel`, `internal/egress`, `internal/egress/kernel`,
`internal/nftables` and `control`. They run with the rest of `go test`, under
Hegel for Go through `internal/pbt`, whose `Check` gives every property the same
terms: 200 cases, or 10 under `go test -short`, where Hegel replaces the count
`Check` sets, no example database, and a derandomized engine. Hegel seeds the
labels of nested generators per process, so two runs need not draw the same
sample, and a boundary the code branches on is drawn outright, with
`pbt.Spanning` or by name, rather than left to the sample. A failing property
prints the smallest input it found. Hegel is a test dependency only:
`internal/notices` fails when a non-test file outside `internal/pbt` imports it,
or when a non-test file imports `internal/pbt`, so it never reaches the binary
or its notices.

Hegel runs on a library of its own. The `go-test` check sets
`HEGEL_LIBHEGEL_PATH` to the library in the vendored Hegel module, and fails if
a test wrote Hegel's cache, `~/.cache/hegel-go` or `~/Library/Caches/hegel-go`,
under the check's home directory anyway.

Property tests build on Linux and macOS alone. `internal/pbt` and every property
test carry a build constraint that names them. The `transport` properties of its
sends and of the source a socket connected to 1 peer binds, the
`internal/kernel` netlink and rule message properties, the
`internal/egress/kernel` nftables and antispoof chain properties and the
`internal/nftables` properties build on Linux alone, and the `transport`
property of the address an answer leaves from builds on macOS alone. The
`go-lint` check vets the tree for FreeBSD, which fails on a property test
without the constraint.

## Nix checks

Every check builds from the root of the repository:

```sh
nix flake check -L
nix build .#checks.x86_64-linux.go-test -L
nix build .#checks.x86_64-linux.go-lint -L
nix build .#checks.x86_64-linux.tree -L
nix build .#checks.x86_64-linux.wireguard -L
nix build .#checks.x86_64-linux.netlink -L
nix build .#checks.x86_64-linux.modules -L
```

`nix flake check -L` builds every check of the host's system. The VM tests below
have commands of their own.

| Check           | Systems | CI runs it on                    | What it runs                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| --------------- | ------- | -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `go-test`       | all 3   | all 3                            | `go test -race ./...` on the vendored libhegel, then a check that no test wrote Hegel's cache                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `go-lint`       | all 3   | `x86_64-linux`, `aarch64-darwin` | `go vet ./...`, the same vet with `GOOS=freebsd`, `staticcheck ./...`, a build of `cmd/ranet3` for Android with cgo off, and a build of `cmd/ranet3` that keeps its symbols, which fails where the daemon links `transport`'s network in memory, `internal/bubble` or `testing`, or a non-test file, outside the network's own files, that names `NewMemoryNetwork`                                                                                                                                                                                                                                                                                     |
| `tree`          | all 3   | `x86_64-linux`                   | `gofmt -l`, `deno fmt --check`, `templ fmt -fail`, `nixfmt --check` on every Nix file, `taplo format --check`, a comparison of the module versions the 3 `go.mod` files require, a check of the `aarch64-linux` exclusions in `atelier.toml`, a check of the VM tests' absent and counted log lines, and `reuse lint`                                                                                                                                                                                                                                                                                                                                   |
| `wireguard`     | all 3   | all 3                            | `go vet ./...` and `go test -race ./...` in `pkgs/wireguard`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `raweb3`        | all 3   | all 3                            | a check of the kernel exit's rows of protocol deviations, as [the exit behavior suite](#the-exit-behavior-suite) says, then `go vet ./...` and `go test ./...` in `pkgs/raweb3`                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `modules`       | Linux   | `x86_64-linux`, `aarch64-linux`  | an evaluation of the NixOS module with networkd on, on with `ManageForeignRoutingPolicyRules` set by the host, and off, and of the `networkd.conf` it writes with networkd on, and of the nix-darwin module beside a stand-in for the nix-darwin options it reads and sets, which declares each `serviceConfig` key the module sets with nix-darwin's type: its job's command line and its `/etc` entry for a TOML and a YAML file, its `serviceConfig` rendered as a plist, its 2 assertions, its reload past a secrets step at `mkAfter` in 3 module orders, and its activation steps against stand-ins for `ranet3` and `launchctl` in 9 activations |
| `netlink`       | Linux   | `x86_64-linux`                   | the Linux root tests, as root in a VM                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `integration-*` | Linux   | `x86_64-linux`                   | the VM tests below                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |

The 3 systems are `x86_64-linux`, `aarch64-linux` and `aarch64-darwin`. CI
builds through atelier, and `atelier.toml` sets what it skips. The
`aarch64-linux` runner has no KVM, so CI runs the VM tests on `x86_64-linux`
alone. CI also builds every package, every dev shell and the formatter on all 3
systems, and never builds `legacyPackages.*.profile`.

The `tree` check fails when an `aarch64-linux` check whose derivation requires
the `kvm` system feature has no `checks.aarch64-linux.<name>` line in the
`exclude` list of `atelier.toml`, when such a line names a check that does not
exist, and when it finds no `aarch64-linux` check that requires `kvm` at all. It
also fails when a fixed string that a VM test's script greps ranet3's journal
for and expects absent, or counts through a command that must succeed, is no
longer in a string literal of a non-test Go file under `pkgs`, since a renamed
log line would leave that grep passing on nothing and that count at 0. A count
is a `grep` with `-c` among its flags or `--count`, or a pipe into `wc -l`. The
check reads every argument of such a call but a `timeout=`, past Python's
comments, as string literals, a name the file binds to one or to a journal, or a
call of a function of the file that returns one. It fails on an argument of any
other form, `command=` among them. A call that must succeed with such an
argument fails only where its string literals hold a count, and is otherwise
skipped whole, with the count of a bound name in it unread. A name bound to a
literal is read only as a whole argument, and a count built from one inside an
expression goes unread. It fails as well on a command a script expects to fail,
or one that must succeed and counts, that is neither ranet3's journal piped into
`grep -F` stages of quoted fixed strings, which a count may follow with
`|| true`, nor a command that reads no journal of ranet3's.

The `netlink` check runs the test binary of each package that holds Linux root
tests, whole, as root, in its package's directory of the source it was built
from.
[`checks/netlink/default.nix`](https://github.com/ranet3/ranet3/blob/master/checks/netlink/default.nix)
lists the binaries and the tests it names. `cmd/ranet3`'s binary runs under
`unshare -n`, and so do the `internal/client` tests above that take the
process's namespace. The resolver tests run under `unshare -mn`, and the rest of
each binary in the VM's own namespace. The check fails when a test skips and the
check does not name it, when a named test passed in a run or is not in its
binary's `-test.list`, when a subtest the check lists passed in no run, and when
a top-level test a binary's `-test.list` names passed in none of the binary's
runs and is not named. Each name carries the reason its test passes in no run.
It also checks that no rule, link or nftables table of theirs is left on the
host, and that the host's own tables and its `/etc/resolv.conf` are as they
were.

A real kernel takes the `nf_tables` encoding in the `netlink` check and in every
integration check that sets `cap.egress` or `overlay`. Elsewhere the encoding
meets only the decoder written beside it.
`internal/egress/kernel/testdata/messages.golden` holds the kind, flags and body
of every request in the transactions the translator and the antispoof filter
write, in the order each transaction sends them. It holds neither the dumps the
translator and the antispoof filter read with, nor the netlink header, sequence
numbers, batch markers and acknowledgment flag that sending adds.
`go test ./internal/egress/kernel -update` rewrites it on Linux.

`nix fmt` rewrites the tree in place. It runs `deno fmt` on the Markdown, the
example JSON and the site, then `nixfmt-tree`, then `go fmt`, `go vet`,
`staticcheck`, `gomod2nix` and `go run ./internal/cmd/notices` in `pkgs/ranet3`,
then `gomod2nix` in `pkgs/wireguard`, then `templ fmt`, `go fmt` and `gomod2nix`
in `pkgs/raweb3`, then `taplo format` on every TOML file. The notices command
regenerates `internal/notices/third_party.md`.
`TestEveryDirectRequirementIsNoticed` fails when a direct requirement in
`go.mod` has no section there.

## VM tests

Protocol-level interoperability is covered by the NixOS VM tests in
`checks/integration`. Except `integration-reload`, each boots separate client
and gateway VMs. The client runs the packaged, user-facing `ranet3` binary with
a real TUN device, while the gateway runs `charon-systemd`/`swanctl`, BIRD, and
iperf3. Each builds on its own:

```sh
nix build .#checks.x86_64-linux.integration-initiator -L
nix build .#checks.x86_64-linux.integration-responder -L
nix build .#checks.x86_64-linux.integration-initiator-fqdn -L
nix build .#checks.x86_64-linux.integration-responder-fqdn -L
nix build .#checks.x86_64-linux.integration-kernel -L
nix build .#checks.x86_64-linux.integration-segments -L
nix build .#checks.x86_64-linux.integration-egress -L
nix build .#checks.x86_64-linux.integration-egress-segment -L
nix build .#checks.x86_64-linux.integration-suites-meet -L
nix build .#checks.x86_64-linux.integration-suites-meet-responder -L
nix build .#checks.x86_64-linux.integration-suites-apart -L
nix build .#checks.x86_64-linux.integration-suites-apart-responder -L
nix build .#checks.x86_64-linux.integration-mlkem-meet -L
nix build .#checks.x86_64-linux.integration-mlkem-meet-responder -L
nix build .#checks.x86_64-linux.integration-mlkem-apart -L
nix build .#checks.x86_64-linux.integration-mlkem-apart-responder -L
nix build .#checks.x86_64-linux.integration-mlkem-fallback -L
nix build .#checks.x86_64-linux.integration-mlkem-optional -L
nix build .#checks.x86_64-linux.integration-mlkem-none -L
nix build .#checks.x86_64-linux.integration-mlkem-fragment -L
nix build .#checks.x86_64-linux.integration-docker -L
nix build .#checks.x86_64-linux.integration-tailscale -L
nix build .#checks.x86_64-linux.integration-k3s -L
nix build .#checks.x86_64-linux.integration-reload -L
```

The checks give the Child SA a lifetime of 24 seconds and the IKE SA one of 34
seconds, with a margin of 22 seconds and no jitter, so each SA rekeys soon after
it is made. The 2 `mlkem-meet` checks give the Child SA 32 seconds. The
ML-KEM-768 Child SA of strongSwan's rekey thereby lasts until ranet3's own rekey
10 seconds after it is made, past the check of its key exchanges. The margin
covers the unanswered Delete of a replaced IKE SA, which holds the session's
next request, and then a rekey's 3 lost sends. The script of
`integration-initiator`, `integration-initiator-fqdn` and `integration-kernel`
also has the gateway drop the client's IKE for 5 seconds while iperf3 runs,
which outlasts a rekey's first send, and counts the IKE the client sends from
the moment the drop is in place to its end. When the drop took none of the
client's sends, the script fails if the client sent none in those 5 seconds. If
the client sent some, they were lost before the gateway, and the script holds
the drop up to 6 seconds longer until the drop takes one, and fails if the drop
takes none. The script also asserts that a Child SA rekey completed and that no
Child SA reached its lifetime. The scripts of the initiator, responder and
`suites-meet` checks, and of the `mlkem-*` checks except the 2 `mlkem-apart`
ones, fail whenever ranet3 logs that it stopped ESP on a Child SA past its
lifetime, whenever its scrape counts an ESP datagram a session dropped or one of
an SPI no session holds, and whenever strongSwan's journal shows an
`N(INVAL_SPI)`, an `INVALID_SPI` notify from ranet3, across the rekeys. They
read the first in `ranet3_esp_inbound_dropped_total` and the second in
`ranet3_receive_refused_total{cause="unknown_esp"}`, which
[metrics](../metrics.md#series) and its
[refused datagrams](../metrics.md#refused-datagrams) define. They read neither
`ranet3_receive_dropped_total` nor the other causes of
`ranet3_receive_refused_total`. The two they read start at 0 with each start of
the daemon, so a script that restarts it reads them before each restart.

The VM console, systemd, strongSwan, BIRD, ranet3, and iperf3 output is streamed
by the Nix test driver. The test also prints strongSwan SA state and BIRD
neighbors and routes on exit, including after a failed check.

## Profiles

`checks/integration/harness` also accepts `profile = true` when imported from
Nix to capture Go and kernel CPU profiles during longer throughput runs,
including simultaneous traffic in both directions:

```sh
nix build .#profile.integration --no-link -L
```

The kernel profiler runs as root inside the disposable VM. It does not require
host root or changes to the host's profiling permissions. Profiles are copied
into the test result.

`nix build .#profile.namespace --no-link -L` runs the namespace harness below
inside one six-core VM and captures a system-wide kernel profile. This keeps the
veth topology used by host measurements and avoids the virtual switch between
integration-test VMs. The guest's CPU and clock still affect results.

## Measurements in namespaces

For measurements without VM overhead, use the namespace harness:

```sh
nix develop .#ranet3 -c go build -C pkgs/ranet3 -o /tmp/ranet-bench ./cmd/ranet3
nix develop .#ranet3 -c unshare --user --map-root-user --mount --net \
  python3 checks/profile/namespace/performance.py --client /tmp/ranet-bench \
  --output /tmp/ranet-perf-6 --cores 6 --affinity 0-5 \
  --directions outbound,inbound,bidir
```

Run as an ordinary user with unprivileged user namespaces available. With the
default `--peer strongswan`, `performance.py` creates private client and gateway
network namespaces, a private `/run`, strongSwan, BIRD, and a real TUN and XFRM
tunnel using the synthetic test keys in `checks/fixtures`. `--peer ranet3`
answers with a second ranet3 instead. It records binary identity, CPU affinity,
iperf3 JSON, CPU profiles, socket drops, and key-free XFRM counters in a new
output directory. All processes and interfaces are removed when the namespaces
exit.

`--cores` sets GOMAXPROCS. `--affinity` restricts the client to actual CPUs. Use
`--cores 1 --affinity 0` for a pinned single-core comparison. Keep flow ports,
stream counts, affinity, MTU, and replay windows identical between versions.
`--replay-window` sets it for every instance in the run, on both sides, and
defaults to 4096 rather than strongSwan's own 32 so replay drops are
distinguishable from processing limits. `--protocol udp --rate 10` offers an
aggregate 10 Gbit/s per direction with UDP GSO/GRO and 4 MiB iperf socket
buffers. Inspect received throughput and loss, not just the offered rate. The
`.#ranet3` development shell uses the `iperf3-benchmark` package, which changes
[iperf 3.21's GRO receive call](https://github.com/esnet/iperf/blob/3.21/src/net.c#L521-L595)
to block instead of busy-polling. With the upstream receive loop, eight
bidirectional streams can occupy every CPU even when waiting for packets,
starving the tunnel on a shared host. The harness records the exact iperf
executable and version along with the client binary identity. TCP behavior is
unchanged.

`performance.py` takes these flags:

| Flag              | Default           | What it sets                                                |
| ----------------- | ----------------- | ----------------------------------------------------------- |
| `--client`        | required          | the `ranet3` binary under test                              |
| `--output`        | required          | the results directory, which must not exist yet             |
| `--fixtures`      | `checks/fixtures` | the synthetic keys                                          |
| `--cores`         | 6                 | GOMAXPROCS of the client                                    |
| `--affinity`      | none              | the CPUs the client runs on                                 |
| `--duration`      | 15                | the seconds of each iperf3 run and CPU profile              |
| `--streams`       | 8                 | the parallel iperf3 streams                                 |
| `--directions`    | `bidir`           | a comma-separated list of `outbound`, `inbound` and `bidir` |
| `--protocol`      | `tcp`             | `tcp` or `udp`                                              |
| `--rate`          | 10                | the aggregate UDP Gbit/s per direction                      |
| `--replay-window` | 4096              | the anti-replay window of every instance                    |
| `--gro`           | unchanged         | `on` or `off` for GRO on both ends of the veth pair         |
| `--delay`         | none              | a netem delay on both ends of the veth pair                 |
| `--peer`          | `strongswan`      | `strongswan` or `ranet3`                                    |
| `--peer-cores`    | `--cores`         | GOMAXPROCS of a ranet3 peer                                 |
| `--peer-affinity` | none              | the CPUs a ranet3 peer runs on                              |
| `--load-affinity` | none              | the CPUs both iperf3 processes run on                       |
| `--client-port`   | 20000             | the base of the iperf3 client ports                         |

## Benchmarks

Raw ESP encryption and decryption have separate benchmarks:

```sh
nix develop .#ranet3 -c go test ./esp -run '^$' -bench 'BenchmarkESP' \
  -benchmem -cpu=1,2,4,8 -count=5
```

These include ESP framing, AEAD, sequence reservation or replay commits, and
reusable batch buffers. Decryption also includes copying the input ciphertext
into reusable buffers. They exclude UDP, TUN, and the client queues. Cipher
throughput cannot establish full-duplex tunnel throughput. Namespace
measurements share CPU resources with the Linux gateway and traffic generators
and do not establish performance on a physical NIC.

To compare routing and packet classification across CPU counts:

```sh
go test ./sadr ./internal/babel -run '^$' \
  -bench 'BenchmarkLookup|BenchmarkRouteChange|BenchmarkReceiveData' \
  -benchmem -cpu=1,2,4,8 -count=5
```

Compare runs on the same idle host. Lookup throughput, route-update cost, and
full-tunnel TCP bandwidth measure different work. VM throughput also includes
the gateway's kernel IPsec and virtual networking overhead.

Immutable snapshots favor packet lookups over route-write latency. Each changed
route allocates the copied trie path. This costs more than an in-place update,
but readers never contend with other readers or wait for a route writer.

The commands above do not name these benchmarks. The `sadr` ones other than
`BenchmarkFillOneDestination` still match the `-bench` pattern of the previous
command.

| Package             | Benchmarks                                                                                                                                                                                       | What they measure                                                                                                                                |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `esp`               | `BenchmarkReplayCommitJumpDistances`                                                                                                                                                             | a replay window commit across growing jumps of the sequence number                                                                               |
| `sadr`              | `BenchmarkLookupBySourceCount`, `BenchmarkLookupByDistinctLengths`, `BenchmarkLookupDownADestinationChain`, `BenchmarkRouteChangeOnOneDestination`, `BenchmarkFillOneDestination`                | lookups and edits with many sources on one destination, or spread over many prefix lengths                                                       |
| `internal/babel`    | `BenchmarkRunLoopPass`, `BenchmarkRunLoopDeadline`, `BenchmarkEmitDump`, `BenchmarkReceiveHello`, `BenchmarkCoalesceOneTarget`                                                                   | the speaker's run loop, a full table dump, a hello against a full table and send coalescing                                                      |
| `internal/netstack` | `BenchmarkPeerEnqueueSerialSinglePacket`, `BenchmarkPeerEnqueueSerialBatched`, `BenchmarkPeerEnqueueParallelSinglePacket`, `BenchmarkPeerEnqueueParallelBatched`, `BenchmarkPeerSenderRoundTrip` | a peer's send queue with 1 packet or batches of 128, and the round trip through its sender                                                       |
| `internal/netstack` | `BenchmarkResolve`, `BenchmarkDecide`, `BenchmarkDecideWithheld`, `BenchmarkOptionStage`                                                                                                         | the route lookup with its matched length, the forwarding decision per packet, the decision with every answer withheld, and the IPv4 option stage |
| `internal/packet`   | `BenchmarkMartianChecks`                                                                                                                                                                         | the checks of a source and a destination no router forwards                                                                                      |
| `transport`         | `BenchmarkUDPReceiveVector`                                                                                                                                                                      | batched UDP receive through the real syscalls, on Linux                                                                                          |
