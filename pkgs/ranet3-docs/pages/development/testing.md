---
# SPDX-FileCopyrightText: 2026 Nick Cao
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: MIT AND CC-BY-4.0
title: "Testing"
description: "The unit and property tests, the root-only tests, the Nix checks and CI, the VM tests and the benchmarks."
created: 2026-08-17
updated: 2026-10-16
order: 20
---

The `go test` commands run from `pkgs/ranet3`, where the Go module is, and
everything else from the root of the repository.

```sh
go test ./... -race
```

## Root tests on Linux

The unit tests need no privileges, except for the ones below. Each of these
unshares a network namespace, refuses to continue unless it is empty, and skips
unless run as root.

- `internal/kernel` has tests that write to a real routing table.
- `internal/egress` has 1 that writes into a real packet filter.
- `transport` has 2 that send through a veth pair to a peer in a second
  namespace, behind a route with a locked path MTU. They check that the kernel
  refuses what the path cannot carry, segmented or single, and reports the path
  MTU. They also check that it fragments past the path only while the family
  asks. A third checks on loopback that IPv4 leaves without DF while the socket
  fragments.
- `internal/netstack` has tests whose names start with `TestTUN` that create and
  attach to a real TUN device. They read its `gso_max_segs` back, open several
  queues as 1 device and no more than the kernel attaches, and refuse a mesh
  under the default name where a device of that name exists. They warn at a new
  mesh's first cut read, move the MTU of an open device, steer a read as large
  as the device and clamp the MSS of a SYN. They answer a packet larger than its
  session, at the headend and at a waypoint, until the kernel that sent it holds
  the smaller path MTU.
- `internal/client` has tests under the same prefix that run a node on a real
  TUN device:
  - A SYN arriving through a session between 2 nodes on loopback reaches the tun
    with its MSS lowered.
  - A reload moves the tun's MTU.
  - `New` opens read buffers that hold a steered packet of `link.mtu`.
  - A TCP stream keeps flowing through a session whose path drops IPv4 packets
    past 1400 bytes, and later past 1360, without an answer, as the search finds
    each.
  - A Babel packet sent in fragments reaches the speaker whole, and the tun
    never sees it. A fragment of ordinary traffic on the same session reaches
    the tun as sent.

The `internal/client` tests `TestNodeGoingDownLeavesItsPeerAndItsKernelAtOnce`,
`TestNodeRestartedWhileDownInstallsNothingUntilUp`,
`TestSessionMovedUnderTheFloorHandsItsFragmentingOver` and
`TestSessionLowersItsBudgetAtTheRefusalOfItsOwnData` reach the kernel from
whatever thread a goroutine runs on. No single thread can be moved into a
namespace for them, so they take the namespace the test process started in. They
skip without root, and they fail in a namespace that holds a link that is up, an
address or a route. Run them in an empty namespace:

```sh
unshare -rn go test ./internal/client -run '^TestNode(GoingDown|RestartedWhileDown)|^TestSession(MovedUnderTheFloorHandsItsFragmentingOver|LowersItsBudgetAtTheRefusalOfItsOwnData)'
```

## Root tests on macOS

On macOS the tests below run as root, and only with `RANET3_DARWIN_NETTEST=1`
set. The Mac that runs them may be on a live mesh.

- `internal/kernel` has tests against the real routing socket.
- `internal/netstack` has arms that create a utun.
- `internal/client` has arms that put a node on a real utun.
- `transport` has 1 that sends through a feth pair whose MTU is 1400. A datagram
  past that MTU is refused, or fragmented while a session asks.
- `control` has 1 that checks that the control socket and the directories the
  daemon makes for it get the daemon's group, under a parent directory that
  hands down another group, as `/var/run` does on macOS.
- `internal/kernel` has 1 that checks the same for the directory the underlay
  record shares with the control socket, whichever of the 2 creates it.

The last 2 give a directory a group of any number, which only root may do. Each
has an unprivileged twin that uses a second group of the running user, and skips
where the user has no second group it can give a directory. The `control` twin
runs on Linux as well, where a setgid directory hands its group down. It skips
in the Linux Nix sandbox and under `unshare -rn`.

`internal/kernel` names the machine it reads and writes, `kernel.Host`, so the
macOS backend can be driven without either. `internal/client`'s
`daemon_darwin_test.go` uses that to run a configuration file all the way to a
daemon against a recorded routing table: the transport binds, the underlay
writes the default its bound socket depends on, and the reconciler holds an
announced default out of the kernel until a session is live, all asserted on the
routes that arrive rather than on the calls that made them. It needs no
privilege, and the one thing it leaves with the running kernel is `IP_BOUND_IF`
on the transport's own UDP socket.

## Property tests

The packages that read bytes a peer or a file chooses also carry property tests,
in files ending in `_property_test.go`: `esp`, `ike`, `identity`, `transport`,
`sadr`, `srv6`, `internal/babel`, `internal/packet`, `internal/netstack`,
`schema`, `internal/config`, `internal/registry`, `internal/client`,
`internal/kernel` and `control`. They run with the rest of `go test`, under
hegel-go through `internal/pbt`, whose `Check` gives every property the same
terms: 200 cases, or 10 under `go test -short`, where hegel replaces the count
`Check` sets, no example database, and a derandomized engine. hegel seeds the
labels of nested generators per process, so two runs need not draw the same
sample, and a boundary the code branches on is drawn outright, with
`pbt.Spanning` or by name, rather than left to the sample. A failing property
prints the smallest input it found. hegel is a test dependency only:
`internal/notices` fails when a non-test file outside `internal/pbt` imports it,
or when a non-test file imports `internal/pbt`, so it never reaches the binary
or its notices.

Property tests build on Linux and macOS alone. `internal/pbt` and every property
test carry a build constraint that names them. The `transport` property and the
`internal/kernel` netlink property build on Linux alone. The `go-lint` check
vets the tree for FreeBSD, which fails on a property test without the
constraint.

## Nix checks

Every check builds from the root of the repository:

```sh
nix flake check -L
nix build .#checks.x86_64-linux.go-test -L
nix build .#checks.x86_64-linux.go-lint -L
nix build .#checks.x86_64-linux.tree -L
nix build .#checks.x86_64-linux.netlink -L
```

`nix flake check -L` builds every check of the host's system. The VM tests below
have commands of their own.

| Check           | Systems | CI runs it on                    | What it runs                                                                                                |
| --------------- | ------- | -------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `go-test`       | all 3   | all 3                            | `go test -race ./...`                                                                                       |
| `go-lint`       | all 3   | `x86_64-linux`, `aarch64-darwin` | `go vet ./...`, the same vet with `GOOS=freebsd`, and `staticcheck ./...`                                   |
| `tree`          | all 3   | `x86_64-linux`                   | `gofmt -l`, `deno fmt --check`, `nixfmt --check` on every Nix file, `taplo format --check` and `reuse lint` |
| `netlink`       | Linux   | `x86_64-linux`                   | the Linux root tests listed below, as root in a VM                                                          |
| `integration-*` | Linux   | `x86_64-linux`                   | the VM tests below                                                                                          |

The 3 systems are `x86_64-linux`, `aarch64-linux` and `aarch64-darwin`. CI
builds through atelier, and `atelier.toml` sets what it skips. The
`aarch64-linux` runner has no KVM, so CI runs the VM tests on `x86_64-linux`
alone. CI also builds every package, every dev shell and the formatter on all 3
systems, and never builds `legacyPackages.*.profile`.

The `netlink` check runs these root tests: the `internal/kernel` tests whose
names start with `TestNetlink`, the `internal/egress` round trip, the `TestTUN`
tests of `internal/netstack` and `internal/client`, the 3 `transport` sends, and
the 4 `internal/client` tests above under `unshare -n`. It fails if any of them
skips. It then checks that no rule, link or nftables table of theirs is left on
the host. The `internal/kernel` tests `TestNetworkWatchInNetworkNamespace` and
`TestNetworkWatchReadsNothingForMainRoutesThatAreNoDefault` need root and run in
no check.

The `netlink` check and `integration-egress` are the only places where a real
kernel takes the `nf_tables` encoding. Elsewhere the encoding meets only the
decoder written beside it.

`nix fmt` rewrites the tree in place. It runs `deno fmt` on the Markdown, the
example JSON and the site, then `nixfmt-tree`, then `go fmt`, `go vet`,
`staticcheck`, `gomod2nix` and `go run ./internal/cmd/notices` in `pkgs/ranet3`,
then `taplo format` on every TOML file. The notices command regenerates
`internal/notices/third_party.md`. `TestEveryDirectRequirementIsNoticed` fails
when a direct requirement in `go.mod` has no section there.

## VM tests

Protocol-level interoperability is covered by the NixOS VM tests in
`checks/integration`. Except `integration-reload`, each boots separate client
and gateway VMs. The client runs the packaged, user-facing `ranet3` binary with
a real TUN device, while the gateway runs `charon-systemd`/`swanctl`, BIRD, and
iperf3. `integration-initiator` verifies an Ed25519-authenticated IKEv2 and
Child SA negotiation across asymmetric local and remote UDP ports, checks Babel
route exchange in both directions, and measures TCP bandwidth through the
negotiated ESP tunnel:

```sh
nix build .#checks.x86_64-linux.integration-initiator -L
nix build .#checks.x86_64-linux.integration-responder -L
nix build .#checks.x86_64-linux.integration-kernel -L
nix build .#checks.x86_64-linux.integration-segments -L
nix build .#checks.x86_64-linux.integration-egress -L
```

`integration-responder` inverts the exchange: strongSwan dials and ranet3
answers, and the check asserts that ranet3 never dials. After a restart of
ranet3, strongSwan dials again and ranet3 answers without dialing.
`integration-kernel` exercises the route reconciler against a real table. In
every one of these checks the client runs ranet3 through the NixOS module, which
writes its settings as the TOML a deployed node runs, and the check reads back
the unit's runtime directory and group.

`integration-egress` makes the client an exit node and boots a third machine
behind it, holding prefixes the gateway can reach through the mesh and no other
way. It asserts that the announcement reaches BIRD on the far side, that the
machine behind the exit sees the exit's own address on both families and never
the mesh address the packet started with, that the sweep recognizes its own
rules rather than rewriting them, that turning `net.ipv4.ip_forward` off
withdraws the IPv4 advertisement and leaves the IPv6 one alone, and that a stop
leaves no nftables table behind. A start after the stop installs the tables
again.

`integration-segments` steers 1 destination through a segment routing header
(RFC 8754). The gateway's own kernel removes the header with End.DT6, and a
capture on the gateway shows the bare inner packet. `ranet3 status --json`
counts steered packets and no unsteered ones. With the gateway's SID removed,
the steered packets still arrive and nothing removes the header. In the other
direction the gateway's kernel builds the header, and the client's End.DT46
delivers the packet, which its `delivered` counter records.

`integration-reload` boots one machine and no gateway. It runs ranet3 through
the NixOS module with a trust document that names only itself. The machine has 4
entries under `specialisation`, and the test script switches to each the way a
deployment does:

```sh
nix build .#checks.x86_64-linux.integration-reload -L
```

The first changes an announced prefix and the trust document, which a reload
applies. The switch exits with status 0, the daemon keeps its process and so its
sessions, and the control socket reports the new prefix and document. The second
changes the port, which a reload refuses. The switch exits with status 4, the
daemon's reason is in the journal, and the old configuration keeps running until
a restart applies the new file. No other check switches a configuration, so this
one holds the unit's reload triggers and the stable path its command line names.

The third moves the control socket through `extraArgs`, and the switch restarts
the daemon on the new socket. The fourth applies the first change through that
socket, which the unit's reload command names with `--control`. Last, the script
runs `ranet3 down`. Its flag is in `/var/lib/ranet3`, a directory of mode 0700.
After a restart the node is still down, and the `Down` line of `ranet3 status`
gives the moment the flag records. `ranet3 up` removes the flag, and the next
restart comes up on the mesh.

`integration-initiator`, with a 4-core client, and `integration-kernel`, with a
1-core client, run the same script. It covers IPv4 and IPv6 routes, locally
scheduled and peer-initiated rekeys, BIRD withdrawal and recovery, and a clean
stop and restart with an idle tun read. `integration-responder` drives both
rekeys from the peer.

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

| Package             | Benchmarks                                                                                                                                                                                                                         | What they measure                                                                                                           |
| ------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `esp`               | `BenchmarkReplayCommitJumpDistances`                                                                                                                                                                                               | a replay window commit across growing jumps of the sequence number                                                          |
| `sadr`              | `BenchmarkLookupBySourceCount`, `BenchmarkLookupByDistinctLengths`, `BenchmarkLookupDownADestinationChain`, `BenchmarkRouteChangeOnOneDestination`, `BenchmarkFillOneDestination`                                                  | lookups and edits with many sources on one destination, or spread over many prefix lengths                                  |
| `internal/babel`    | `BenchmarkRunLoopPass`, `BenchmarkRunLoopDeadline`, `BenchmarkEmitDump`, `BenchmarkReceiveHello`, `BenchmarkCoalesceOneTarget`                                                                                                     | the speaker's run loop, a full table dump, a hello against a full table and send coalescing                                 |
| `internal/netstack` | `BenchmarkPeerEnqueueSerialSinglePacket`, `BenchmarkPeerEnqueueSerialBatched`, `BenchmarkPeerEnqueueParallelSinglePacket`, `BenchmarkPeerEnqueueParallelBatched`, `BenchmarkPeerSenderRoundTrip`, `BenchmarkInboundCopyAndRelease` | a peer's send queue with 1 packet or batches of 128, the round trip through its sender, and the copy of each inbound packet |
| `transport`         | `BenchmarkUDPReceiveVector`                                                                                                                                                                                                        | batched UDP receive through the real syscalls, on Linux                                                                     |
