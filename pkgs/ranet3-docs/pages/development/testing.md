---
# SPDX-FileCopyrightText: 2026 Nick Cao
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: MIT AND CC-BY-4.0
title: "Testing"
description: "The unit tests, the VM tests, the root-only tests and the benchmarks."
created: 2026-08-17
updated: 2026-10-03
order: 20
---

The `go test` commands run from `pkgs/ranet3`, where the go module is, and
everything else from the root of the repository.

```sh
go test ./... -race
```

The unit tests need no privileges, with two exceptions: `internal/kernel` has
tests that write to a real routing table, and `internal/egress` one that writes
into a real packet filter. Both unshare a network namespace and refuse to
continue unless it is empty, and both skip unless run as root, on darwin unless
`RANET3_DARWIN_NETTEST=1` is also set, because that machine is on a live mesh.

`internal/kernel` names the machine it reads and writes, `kernel.Host`, so the
darwin backend can be driven without either. `internal/client`'s
`daemon_darwin_test.go` uses that to run a configuration file all the way to a
daemon against a recorded routing table: the transport binds, the underlay
writes the default its bound socket depends on, and the reconciler holds an
announced default out of the kernel until a session is live, all asserted on the
routes that arrive rather than on the calls that made them. It needs no
privilege, and the one thing it leaves with the running kernel is `IP_BOUND_IF`
on the transport's own UDP socket. The `netlink` VM check runs both binaries as
root against a real kernel, which is the only place the `nf_tables` encoding is
checked against something other than the decoder it was written beside.
Protocol-level interoperability is covered by the NixOS VM tests in
`modules/flake/checks.nix`. Each boots separate client and gateway VMs; the
client runs the packaged, user-facing `ranet3` binary with a real TUN device,
while the gateway runs `charon-systemd`/`swanctl`, BIRD, and iperf3. The default
test verifies an Ed25519-authenticated IKEv2 and Child SA negotiation across
asymmetric local and remote UDP ports, checks Babel route exchange in both
directions, and measures TCP bandwidth through the negotiated ESP tunnel:

```sh
nix build .#checks.x86_64-linux.integration -L
nix build .#checks.x86_64-linux.integration-multicore -L
nix build .#checks.x86_64-linux.responder -L
nix build .#checks.x86_64-linux.kernel -L
nix build .#checks.x86_64-linux.segments -L
nix build .#checks.x86_64-linux.egress -L
```

`responder` inverts the exchange: strongSwan dials and ranet3 answers, which
upstream could not do at all, and the check asserts that ranet3 never dials.
`kernel` exercises the route reconciler against a real table. `nixos-module`
boots nothing: it evaluates the nixos module into the unit systemd would run and
reads back the binary, the runtime directory and the group, since otherwise a
wrong option name in it is found by the first machine that imports it.

`egress` makes the client an exit node and boots a third machine behind it,
holding prefixes the gateway can reach through the mesh and no other way. It
asserts that the announcement reaches BIRD on the far side, that the machine
behind the exit sees the exit's own address on both families and never the mesh
address the packet started with, that the sweep recognizes its own rules rather
than rewriting them, that turning `net.ipv4.ip_forward` off withdraws the IPv4
advertisement and leaves the IPv6 one alone, and that a stop leaves no nftables
table behind.

These checks exercise one-core and four-core clients, IPv4 and IPv6 routes,
locally scheduled and peer-initiated rekeys, BIRD withdrawal/recovery, and a
clean stop/restart with an idle TUN read. The integration test also accepts
`profile = true` when imported from Nix to capture Go and kernel CPU profiles
during longer throughput runs, including simultaneous traffic in both
directions:

```sh
nix build .#integration-profile --no-link -L
```

The kernel profiler runs as root inside the disposable VM. It does not require
host root or changes to the host's profiling permissions. Profiles are copied
into the test result.

`nix build .#namespace-profile --no-link -L` runs the namespace harness below
inside one six-core VM and captures a system-wide kernel profile. This keeps the
veth topology used by host measurements and avoids the virtual switch between
integration-test VMs; the guest's CPU and clock still affect results.

For measurements without VM overhead, use the namespace harness:

```sh
nix develop -c go build -C pkgs/ranet3 -o /tmp/ranet-bench ./cmd/ranet3
nix develop -c unshare --user --map-root-user --mount --net \
  python3 integration/performance.py --client /tmp/ranet-bench \
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
Nix development shell uses the `iperf3-benchmark` package, which changes
[iperf 3.21's GRO receive call](https://github.com/esnet/iperf/blob/3.21/src/net.c#L521-L595)
to block instead of busy-polling. With the upstream receive loop, eight
bidirectional streams can occupy every CPU even when waiting for packets,
starving the tunnel on a shared host. The harness records the exact iperf
executable and version along with the client binary identity. TCP behavior is
unchanged.

Raw ESP encryption and decryption have separate benchmarks:

```sh
nix develop -c go test ./esp -run '^$' -bench 'BenchmarkESP' \
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
