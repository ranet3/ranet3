---
# SPDX-FileCopyrightText: 2026 Nick Cao
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: MIT AND CC-BY-4.0
title: "Testing"
description: "The unit and property tests, the VM tests, the root-only tests and the benchmarks."
created: 2026-08-17
updated: 2026-10-08
order: 20
---

The `go test` commands run from `pkgs/ranet3`, where the go module is, and
everything else from the root of the repository.

```sh
go test ./... -race
```

The unit tests need no privileges, with four exceptions: `internal/kernel` has
tests that write to a real routing table, `internal/egress` one that writes into
a real packet filter, `internal/netstack` four that create and attach to a real
TUN on linux, read its `gso_max_segs` back, open several lanes as one device,
refuse a mesh under the default name where a device of that name exists and warn
at a new mesh's first cut read, and `transport` one that sends through a veth
pair to a peer in a second namespace, behind a route with a locked path MTU. On
linux all four unshare a network namespace, refuse to continue unless it is
empty, and skip unless run as root. On darwin the `internal/kernel` tests
against the real routing socket and the `internal/netstack` arms that create a
utun run as root only with `RANET3_DARWIN_NETTEST=1` set, because that machine
is on a live mesh.

`internal/kernel` names the machine it reads and writes, `kernel.Host`, so the
darwin backend can be driven without either. `internal/client`'s
`daemon_darwin_test.go` uses that to run a configuration file all the way to a
daemon against a recorded routing table: the transport binds, the underlay
writes the default its bound socket depends on, and the reconciler holds an
announced default out of the kernel until a session is live, all asserted on the
routes that arrive rather than on the calls that made them. It needs no
privilege, and the one thing it leaves with the running kernel is `IP_BOUND_IF`
on the transport's own UDP socket. The `netlink` VM check runs the four binaries
as root against a real kernel, which is the only place the `nf_tables` encoding
is checked against something other than the decoder it was written beside.

The packages that read bytes a peer or a file chooses also carry property tests,
in files ending in `_property_test.go`: `esp`, `ike`, `transport`, `sadr`,
`srv6`, `internal/babel`, `internal/packet`, `schema`, `internal/config`,
`internal/kernel` and `control`. They run with the rest of `go test`, under
hegel-go through `internal/pbt`, whose `Check` gives every property the same
terms: 200 cases, or 10 under `go test -short`, where hegel v0.9.19 replaces the
count `Check` sets, no example database, and a derandomized engine. hegel
v0.9.19 still seeds the labels of nested generators per process, so two runs
need not draw the same sample, and a boundary the code branches on is drawn
outright, with `pbt.Spanning` or by name, rather than left to the sample. A
failing property prints the smallest input it found. hegel is a test dependency
only: `internal/notices` refuses a non-test file that imports it, so it never
reaches the binary or its notices.

Protocol-level interoperability is covered by the NixOS VM tests in
`checks/integration`. Except `integration-reload`, each boots separate client
and gateway VMs. The client runs the packaged, user-facing `ranet3` binary with
a real TUN device, while the gateway runs `charon-systemd`/`swanctl`, BIRD, and
iperf3. The default test verifies an Ed25519-authenticated IKEv2 and Child SA
negotiation across asymmetric local and remote UDP ports, checks Babel route
exchange in both directions, and measures TCP bandwidth through the negotiated
ESP tunnel:

```sh
nix build .#checks.x86_64-linux.integration-initiator -L
nix build .#checks.x86_64-linux.integration-responder -L
nix build .#checks.x86_64-linux.integration-kernel -L
nix build .#checks.x86_64-linux.integration-segments -L
nix build .#checks.x86_64-linux.integration-egress -L
```

`integration-responder` inverts the exchange: strongSwan dials and ranet3
answers, which upstream could not do at all, and the check asserts that ranet3
never dials. `integration-kernel` exercises the route reconciler against a real
table. In every one of these checks the client runs ranet3 through the nixos
module, which writes its settings as the TOML a deployed node runs, and the
check reads back the unit's runtime directory and group.

`integration-egress` makes the client an exit node and boots a third machine
behind it, holding prefixes the gateway can reach through the mesh and no other
way. It asserts that the announcement reaches BIRD on the far side, that the
machine behind the exit sees the exit's own address on both families and never
the mesh address the packet started with, that the sweep recognizes its own
rules rather than rewriting them, that turning `net.ipv4.ip_forward` off
withdraws the IPv4 advertisement and leaves the IPv6 one alone, and that a stop
leaves no nftables table behind.

`integration-reload` boots one machine and no gateway. It runs ranet3 through
the nixos module with a trust document that names only itself, and the machine
has two specialisations that the test script switches to the way a deployment
does:

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

The checks with a gateway exercise one-core and four-core clients, IPv4 and IPv6
routes, locally scheduled and peer-initiated rekeys, BIRD withdrawal/recovery,
and a clean stop/restart with an idle TUN read. The integration test also
accepts `profile = true` when imported from Nix to capture Go and kernel CPU
profiles during longer throughput runs, including simultaneous traffic in both
directions:

```sh
nix build .#profile.integration --no-link -L
```

The kernel profiler runs as root inside the disposable VM. It does not require
host root or changes to the host's profiling permissions. Profiles are copied
into the test result.

`nix build .#profile.namespace --no-link -L` runs the namespace harness below
inside one six-core VM and captures a system-wide kernel profile. This keeps the
veth topology used by host measurements and avoids the virtual switch between
integration-test VMs; the guest's CPU and clock still affect results.

For measurements without VM overhead, use the namespace harness:

```sh
nix develop .#ranet3 -c go build -C pkgs/ranet3 -o /tmp/ranet-bench ./cmd/ranet3
nix develop .#ranet3 -c unshare --user --map-root-user --mount --net \
  python3 checks/profile/namespace/performance.py --client /tmp/ranet-bench \
  --output /tmp/ranet-perf-6 --cores 6 --affinity 0-5 \
  --directions outbound,inbound,bidir
```

Run as an ordinary user with unprivileged user namespaces available. The harness
creates private client/gateway network namespaces, a private `/run`, strongSwan,
BIRD, and a real TUN/XFRM tunnel using the synthetic test keys. It records
binary identity, CPU affinity, iperf3 JSON, CPU profiles, socket drops, and
key-free XFRM counters in a new output directory. All processes and interfaces
are removed when the namespaces exit.

`--cores` sets GOMAXPROCS; `--affinity` restricts the client to actual CPUs. Use
`--cores 1 --affinity 0` for a pinned single-core comparison. Keep flow ports,
stream counts, affinity, MTU, and replay windows identical between versions.
`--replay-window` sets it for every instance in the run, on both sides, and
defaults to 4096 rather than strongSwan's own 32 so replay drops are
distinguishable from processing limits. `--protocol udp --rate 10` offers an
aggregate 10 Gbit/s per direction with UDP GSO/GRO and 4 MiB iperf socket
buffers; inspect received throughput and loss, not just the offered rate. The
`.#ranet3` development shell uses the `iperf3-benchmark` package, which changes
[iperf 3.21's GRO receive call](https://github.com/esnet/iperf/blob/3.21/src/net.c#L521-L595)
to block instead of busy-polling. With the upstream receive loop, eight
bidirectional streams can occupy every CPU even when waiting for packets,
starving the tunnel on a shared host. The harness records the exact iperf
executable and version along with the client binary identity. TCP behavior is
unchanged.

Raw ESP encryption and decryption have separate benchmarks:

```sh
nix develop .#ranet3 -c go test ./esp -run '^$' -bench 'BenchmarkESP' \
  -benchmem -cpu=1,2,4,8 -count=5
```

These include ESP framing, AEAD, sequence reservation or replay commits, and
reusable batch buffers. Decryption also includes copying the input ciphertext
into reusable buffers. They exclude UDP, TUN, and the client queues; cipher
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
full-tunnel TCP bandwidth measure different work; VM throughput also includes
the gateway's kernel IPsec and virtual networking overhead.

Immutable snapshots favor packet lookups over route-write latency. Each changed
route allocates the copied trie path; this costs more than an in-place update,
but readers never contend with other readers or wait for a route writer.

The VM console, systemd, strongSwan, BIRD, ranet3, and iperf3 output is streamed
by the Nix test driver. The test also prints strongSwan SA state and BIRD
neighbors and routes on exit, including after a failed check.
