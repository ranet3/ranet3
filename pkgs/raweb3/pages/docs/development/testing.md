---
# SPDX-FileCopyrightText: 2026 Nick Cao
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: MIT AND CC-BY-4.0
title: "Testing"
description: "The unit and property tests, the root-only tests, the Nix checks and CI, the VM tests and the benchmarks."
created: 2026-08-17
updated: 2026-10-25
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
- `internal/egress` has 7 that write into a real packet filter. One round trips
  the translator's rules, another checks that the kernel tells the backend when
  another writer adds a rule to its chain, sets its table dormant or deletes it,
  and that its own writes tell it nothing, and a third checks that another
  writer's transactions overflowing the notification socket reach the backend as
  lost notifications. The fourth checks that another writer's uncommented rule
  at the head of the translator's chain is read back, and that the next pass
  leaves only the translator's rules. The fifth runs the translator while
  another writer sets a table dormant or makes a chain again at another priority
  or as a regular chain, and checks that each holds both families not ready
  until the pass it wakes writes the table back and reads them ready. The other
  2 round trip the border filter's chain. One puts it back on the pass another
  writer wakes by deleting the table, adding a rule or setting the table
  dormant, and leaves no table behind. The other writes it back after another
  writer adds a rule to it, sets its table dormant, turns its policy to drop,
  makes the chain again at another priority or as a regular chain, or makes the
  table again with a flag nf_tables will not clear in place, the last 3 by
  deleting and making the table again.
- `transport` has 2 that send through a veth pair to a peer in a second
  namespace, behind a route with a locked path MTU. They check that the kernel
  refuses what the path cannot carry, segmented or single, and reports the path
  MTU. They also check that it fragments past the path only while the family
  asks. A third checks on loopback that IPv4 leaves without DF while the socket
  fragments. 7 more, in `pair_namespace_linux_test.go`, check the sockets
  connected to 1 peer. Such a socket gets its peer's datagrams while the
  listener keeps the rest, connects only in its listener's namespace and stops
  carrying a pair from an address the host lost. It follows its family's path
  MTU discovery across a locked path, keeps its pair past a hop's report of a
  smaller path, leaves by the interface its peer's datagram arrived on, and for
  a dialed pair binds the source of the route the underlay mark selects. 3 more,
  in `unpin_namespace_linux_test.go`, check that an answer from an address with
  no route to the peer leaves from the kernel's choice, and that the session
  returns to its address once the host holds it again, or 1 minute after a
  fallback for want of a route, once it routes again.
- `internal/netstack` has tests whose names start with `TestTUN` that create and
  attach to a real TUN device. They read its `gso_max_segs` back, open several
  queues as 1 device and no more than the kernel attaches, and refuse a mesh
  under the default name where a device of that name exists. They warn at a new
  mesh's first cut read, keep a lane reading past a frame of 1 byte and past a
  frame with a virtio-net header the read refuses, report a link deleted under a
  running mesh once and stop every lane's reader, and check that the device
  queues no link event and leaves no route listener running after the mesh
  closes. They hold the MTU a device was created or attached at and move it,
  carry a read of 65535 bytes through a device opened at the default MTU, steer
  a read as large as the device and clamp the MSS of a SYN. They answer a packet
  larger than its session, at the headend and at a waypoint, until the kernel
  that sent it holds the smaller path MTU, and
  `TestTUNAnswerToThisHostPassesAReversePathCheck` checks that a session's
  packet from this host, answered by the forwarding decision, reaches the
  sending socket under a strict and a loose reverse path chain in both families.
  Another writes a TCP stream into a kernel socket as frames lying in 1 buffer,
  as a session's datagrams do, and checks that the tun's GRO coalesces them and
  that the socket reads back the bytes sent. 2 more check that a lane's write
  into the tun allocates nothing and keeps no reference to the frames it wrote,
  whether its packets go alone or coalesce.
- `internal/client` has tests under the same prefix that run a node on a real
  TUN device:
  - A SYN arriving through a session between 2 nodes on loopback reaches the tun
    with its MSS lowered.
  - A reload moves the tun's MTU.
  - A TCP stream keeps flowing through a session whose path drops IPv4 packets
    past 1400 bytes, and later past 1360, without an answer, as the search finds
    each.
  - A Babel packet sent in fragments reaches the speaker whole, and the tun
    never sees it. A fragment of ordinary traffic on the same session reaches
    the tun as sent.
  - `TestTUNExitEgressesBothModesThroughItsOneTun` runs an exit node with an
    egress segment and a default of each family, in a namespace holding only its
    tun, its uplink to a far host and the loopback. A leaf's IPv4 and IPv6,
    steered through the SID and sent through the default, leave the uplink under
    its address and the replies come back through the mesh tun, while a source
    outside the allow list is refused. A route sending a lookup back into the
    tun, a rule sending the leaf's address out of the uplink, and IPv4
    `forwarding` off on the tun each hold their family not ready with a reason
    naming it, retract the default and the SID's /128, and let nothing reach the
    far host, until the change goes. With strict reverse path filtering on the
    tun, the rule holds IPv4 by its forward lookup instead, and the reason names
    the filter. An inner packet for the leaf at the SID is refused and counted.
    With no IPv6 prefix of the leaf's inside the overlay, the IPv6 lookups are
    skipped and say so, and IPv6 still egresses. The node puts back an nftables
    table another writer deleted, and the border drops a packet from the far
    host to the SID.
  - `TestTUNSetEgressReadyMovesTheMeshBeforeTheAnnouncement` reads what the mesh
    egresses into a real tun while the announcement is rebuilt, and checks that
    it already follows the readiness just given.
  - `TestTUNBorderDropsAForgedSourceAtTheUplink` runs an exit node with
    `cap.border` and a far host behind a veth pair, in the host's own tables and
    in a VRF. A packet from beyond the uplink with a source outside the overlay
    crosses the mesh tun, while one with a source inside it, a type 4 routing
    header alone or behind one of type 0 or 2, or the local SID never crosses it
    and is counted. A packet to another node's SID from outside the overlay
    crosses the tun and is refused at that SID. The mesh's own packets leave
    through the tun, nothing crosses once the border is withdrawn and forwarding
    is off, and no table is left behind.
  - `TestTUNEgressCarriesNothingWhileTheBorderIsNotReady` and
    `TestTUNEgressFollowsTheTranslatorOnlyWhileTheBorderReadsBack` read what the
    mesh egresses into a real tun, and check that an egress segment carries a
    family only while the translator holds it ready and the border's chain reads
    back.
  - `TestTUNLineCarriesTransitThroughItsMiddleNodeAndAnswersAsARouter` runs 3
    nodes in a line, each in a namespace of its own, with transit on at the
    middle one, whose kernel forwards neither family and whose tun holds no
    address. Datagrams of both families cross it, and it answers from its
    router-id: Time Exceeded at a hop limit of 1, Packet Too Big and
    Fragmentation Needed with its next session's size, which the sender caches,
    and Destination Unreachable inside a prefix it holds unreachable. An IPv6
    datagram from a link-local source draws a beyond scope answer back on its
    session. With no address of either family it answers IPv4 from `192.0.0.8`,
    a Packet Too Big from the packet's destination and IPv6's Time Exceeded not
    at all. Its kernel forwards nothing and reads nothing from its tun
    throughout.
  - `TestTUNLineRefusesTransitWhileItIsOffButNotThroughAnEndDT46SID` runs the
    line with transit off at the middle node, which answers administratively
    prohibited, and still carries what the sender steers through its End.DT46
    SID.
  - `TestTUNExitCarriesTransitInProcessAndNothingOutOfItsUplink` runs an exit
    that announces a default of each family, with forwarding on and a default
    route out of an uplink to a fourth namespace. Transit between its 2
    neighbors crosses it in the mesh, its kernel forwards none of it, and
    nothing of it reaches the uplink.
  - `TestTUNExitEgressesEachShapeOfTheInternetTranslated` runs the same exit
    advertising each family through `cap.egress` as a default, a pair of `/1`
    halves and four `/2`s, with the translator running. A neighbor's datagrams
    of both families reach the fourth namespace from the exit's uplink address,
    and a datagram from a source the mesh routes no reply to is counted at the
    exit and never reaches the uplink.
  - `TestTUNModeTwoEgressFollowsTheAnnouncementWithNoEgressSegment` gives a node
    with `cap.egress` and no egress segment a real tun, and checks that its
    egress through a default reaches the tun for each family it announces and is
    counted not ready for the others, whatever the border's chain reads back.

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
- `internal/netstack` has arms that create a utun. 2 of its tests carry a packet
  each way through a utun addressed in `198.18.0.0/15`: a datagram sent out of
  it reaches a recording peer whole, and a frame delivered inbound reaches a
  socket behind it. They take the address and its route off again and check that
  no route on another interface changed. Another checks that the mesh's utun
  runs no route listener and queues no link event while its MTU moves more times
  than the device's event channel holds, and that closing the mesh closes that
  channel.
- `internal/client` has arms that put a node on a real utun.
- `transport` has 1 that sends through a feth pair whose MTU is 1400. A datagram
  past that MTU is refused, or fragmented while a session asks. A second checks
  that a socket connected to 1 peer from a hub bound to 1 feth binds that feth's
  address, where the host's own route leaves by the other. 6 more check where
  answers leave from. An answer leaves from the address its request reached, by
  the interface holding that address. The session's path MTU reads the MTU of
  that interface. The datagrams of a send that fit still leave from the address
  after one is refused for its size. Once the address is gone or has no route to
  the peer, sends leave from the kernel's choice and return to the address as
  [moving hosts](../platforms.md#moving-hosts) describes. A send refused from
  the address and again without it keeps the address.
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
writes the default its bound socket depends on only while a capture holds a zero
address, and the reconciler holds an announced default out of the kernel until a
session is live, all asserted on the routes that arrive rather than on the calls
that made them. It needs no privilege, and the one thing it leaves with the
running kernel is `IP_BOUND_IF` on the transport's own UDP socket.

## Property tests

The packages that read bytes a peer or a file chooses also carry property tests,
in files ending in `_property_test.go`: `esp`, `ike`, `identity`, `transport`,
`sadr`, `srv6`, `internal/babel`, `internal/packet`, `internal/netstack`,
`schema`, `internal/config`, `internal/registry`, `internal/client`,
`internal/kernel`, `internal/egress`, `internal/nftables` and `control`. They
run with the rest of `go test`, under hegel-go through `internal/pbt`, whose
`Check` gives every property the same terms: 200 cases, or 10 under
`go test -short`, where hegel replaces the count `Check` sets, no example
database, and a derandomized engine. hegel seeds the labels of nested generators
per process, so two runs need not draw the same sample, and a boundary the code
branches on is drawn outright, with `pbt.Spanning` or by name, rather than left
to the sample. A failing property prints the smallest input it found. hegel is a
test dependency only: `internal/notices` fails when a non-test file outside
`internal/pbt` imports it, or when a non-test file imports `internal/pbt`, so it
never reaches the binary or its notices.

hegel-go runs on a library of its own. With `HEGEL_LIBHEGEL_PATH` set it loads
that file and no other. Otherwise it writes the copy it embeds into the user
cache, `~/.cache/hegel-go` on Linux and `~/Library/Caches/hegel-go` on macOS,
and loads it from there. Test binaries that start before a copy exists each
write their own and rename it into place, and the macOS loader refuses a file
replaced between its check and its open. The first `go test ./...` on a Mac
after a hegel update can therefore fail in libhegel's load with "file inode
changed", and the next run, which finds the copy, passes. The `go-test` check
sets `HEGEL_LIBHEGEL_PATH` to the library in the vendored hegel module, and
fails if a test wrote hegel's cache under the check's home directory anyway.

Property tests build on Linux and macOS alone. `internal/pbt` and every property
test carry a build constraint that names them. The `transport` properties of its
sends and of the source a socket connected to 1 peer binds, the
`internal/kernel` netlink and rule message properties, the `internal/egress`
nftables and border chain properties and the `internal/nftables` properties
build on Linux alone, and the `transport` property of the address an answer
leaves from builds on macOS alone. The `go-lint` check vets the tree for
FreeBSD, which fails on a property test without the constraint.

## Nix checks

Every check builds from the root of the repository:

```sh
nix flake check -L
nix build .#checks.x86_64-linux.go-test -L
nix build .#checks.x86_64-linux.go-lint -L
nix build .#checks.x86_64-linux.tree -L
nix build .#checks.x86_64-linux.wireguard -L
nix build .#checks.x86_64-linux.netlink -L
```

`nix flake check -L` builds every check of the host's system. The VM tests below
have commands of their own.

| Check           | Systems | CI runs it on                    | What it runs                                                                                                                                                                                                                                                   |
| --------------- | ------- | -------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `go-test`       | all 3   | all 3                            | `go test -race ./...` on the vendored libhegel, then a check that no test wrote hegel's cache                                                                                                                                                                  |
| `go-lint`       | all 3   | `x86_64-linux`, `aarch64-darwin` | `go vet ./...`, the same vet with `GOOS=freebsd`, and `staticcheck ./...`                                                                                                                                                                                      |
| `tree`          | all 3   | `x86_64-linux`                   | `gofmt -l`, `deno fmt --check`, `templ fmt -fail`, `nixfmt --check` on every Nix file, `taplo format --check`, a comparison of the module versions the 3 `go.mod` files require, a check of the `aarch64-linux` exclusions in `atelier.toml`, and `reuse lint` |
| `wireguard`     | all 3   | all 3                            | `go vet ./...` and `go test -race ./...` in `pkgs/wireguard`                                                                                                                                                                                                   |
| `raweb3`        | all 3   | all 3                            | `go vet ./...` and `go test ./...` in `pkgs/raweb3`                                                                                                                                                                                                            |
| `netlink`       | Linux   | `x86_64-linux`                   | the Linux root tests listed below, as root in a VM                                                                                                                                                                                                             |
| `integration-*` | Linux   | `x86_64-linux`                   | the VM tests below                                                                                                                                                                                                                                             |

The 3 systems are `x86_64-linux`, `aarch64-linux` and `aarch64-darwin`. CI
builds through atelier, and `atelier.toml` sets what it skips. The
`aarch64-linux` runner has no KVM, so CI runs the VM tests on `x86_64-linux`
alone. CI also builds every package, every dev shell and the formatter on all 3
systems, and never builds `legacyPackages.*.profile`.

The `tree` check fails when an `aarch64-linux` check whose derivation requires
the `kvm` system feature has no `checks.aarch64-linux.<name>` line in the
`exclude` list of `atelier.toml`, when such a line names a check that does not
exist, and when it finds no `aarch64-linux` check that requires `kvm` at all.

The `netlink` check runs these root tests: the `internal/kernel` tests whose
names start with `TestNetlink`, the 7 `internal/egress` tests, the `TestTUN`
tests of `internal/netstack` and `internal/client`, the 3 `transport` sends, and
the 4 `internal/client` tests above under `unshare -n`, and every test of the
`tun` and `conn` packages of `pkgs/wireguard`. It fails if any of them skips. It
then checks that no rule, link, xfrm state or policy, or nftables table of
theirs is left on the host. The `internal/kernel` tests
`TestNetworkWatchInNetworkNamespace` and
`TestNetworkWatchReadsNothingForMainRoutesThatAreNoDefault` need root and run in
no check, and so do the 7 `transport` tests of the sockets connected to 1 peer
and the 3 of a session's fallback from its address.

The `netlink` check, `integration-egress` and `integration-egress-segment` are
the only places where a real kernel takes the `nf_tables` encoding. Elsewhere
the encoding meets only the decoder written beside it.
`internal/egress/testdata/messages.golden` holds the kind, flags and body of
every request in the transactions the translator and the border filter write, in
the order each transaction sends them. It holds neither the dumps the translator
and the border filter read with, nor the netlink header, sequence numbers, batch
markers and acknowledgment flag that sending adds.
`go test ./internal/egress -update` rewrites it on Linux.

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
iperf3. `integration-initiator` verifies an Ed25519-authenticated IKEv2 and
Child SA negotiation across asymmetric local and remote UDP ports, checks Babel
route exchange in both directions, and measures TCP bandwidth through the
negotiated ESP tunnel:

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
```

`integration-responder` inverts the exchange: strongSwan dials and ranet3
answers, and the check asserts that ranet3 never dials. After a restart of
ranet3, strongSwan dials again and ranet3 answers without dialing.
`integration-initiator-fqdn` and `integration-responder-fqdn` run the same 2
exchanges with each side named by an FQDN in place of a DN, strongSwan by its
own `id` and ranet3 through `auth.aliases`. Each asserts that strongSwan
established the SA between the 2 FQDNs and that ranet3 recorded an
`ike.id.resolved` with `type=fqdn` for the gateway. The initiator variant also
asserts that ranet3 asked for the gateway's FQDN in IDr. `integration-kernel`
exercises the route reconciler against a real table. In every one of these
checks the client runs ranet3 through the NixOS module, which writes its
settings as the TOML a deployed node runs, and the check reads back the unit's
runtime directory and group.

`integration-suites-meet` and `integration-suites-apart` set ranet3's
`cap.crypto` lists against strongSwan's proposals, with ranet3 dialing, and
their `-responder` variants with strongSwan dialing. In `suites-meet` the 2 ends
share AES-GCM with a 128-bit key, HMAC-SHA2-256 and P-256 alone. Each check
asserts that `ranet3 sessions --json` and `swanctl --list-sas` both report that
suite, rekeys each SA from strongSwan's side and from ranet3's, and asserts the
same suite after. In `suites-apart` the 2 ends share no IKE cipher, and the
answering end refuses the handshake with `NO_PROPOSAL_CHOSEN` whichever end
dials.

The `integration-mlkem-*` checks set ranet3's `cap.crypto.ike.kex` against
strongSwan's proposals. In `mlkem-meet` both ends run `x25519+mlkem768` with
ranet3 dialing, and in `mlkem-meet-responder` with strongSwan dialing. Each
asserts from strongSwan's log the `IKE_INTERMEDIATE` exchange at Message ID 1
and `IKE_AUTH` at 2, and that `ranet3 sessions --json` names `x25519+mlkem768`
and `swanctl --list-sas` `KE1_ML_KEM_768`. Each then waits for ranet3's own
scheduled rekey of the IKE SA. After it the check asks strongSwan for a rekey of
the IKE SA and then of the Child SA, each right after strongSwan answers
ranet3's Delete of a Child SA ranet3 rekeyed, which puts each between 2 of
ranet3's Child SA rekeys. It asks again the same way after strongSwan's request
drew `TEMPORARY_FAILURE` or strongSwan logs that it lost an IKE SA rekey
collision, and waits for strongSwan's own exchange by the name strongSwan gives
the new SA. Each asserts from strongSwan's log that ranet3's rekey of the IKE
SA, strongSwan's of the IKE SA and strongSwan's of the Child SA each run
ML-KEM-768 in an `IKE_FOLLOWUP_KE` exchange whose request echoes the link of the
`CREATE_CHILD_SA` response, that a ping crosses each, and that
`ranet3 sessions --json` names no kex entry for the Child SA of `IKE_AUTH` and
`x25519+mlkem768` for the Child SA of strongSwan's rekey. It also asserts that
ranet3 closed no IKE SA and completed 1 handshake, and that strongSwan never
dialed again. In `mlkem-apart` and `mlkem-apart-responder` ranet3 lists
`x25519+mlkem768` alone against strongSwan's default proposals, which hold no
ML-KEM, and the answering end refuses the handshake with `NO_PROPOSAL_CHOSEN`
whichever end dials. In `mlkem-fallback` ranet3 dials listing `x25519+mlkem768`
and then `x25519` against those defaults. strongSwan takes `x25519`, no
`IKE_INTERMEDIATE` runs, and ranet3's rekey of the IKE SA, which offers both
entries again, completes in `x25519`. In `mlkem-optional` and `mlkem-none`
strongSwan dials with ML-KEM-768 or `NONE` for its additional key exchange.
ranet3 lists `x25519+mlkem768` first in `mlkem-optional` and takes ML-KEM-768,
and its own rekey of the IKE SA runs ML-KEM-768 again in an `IKE_FOLLOWUP_KE`
exchange. It lists `x25519` alone in `mlkem-none`, answers with `NONE` written
out, runs no `IKE_INTERMEDIATE` and rekeys its IKE SA in `x25519`. strongSwan
logs at level 2 for its `cfg` group in these checks, so its journal shows the
proposals it received from ranet3, a `NONE` among them.

`integration-mlkem-fragment` has ranet3 dial over links too narrow for its
ML-KEM messages, and each end cuts them into the fragments of RFC 7383. Vlan 1
has an MTU of 1280 and carries IPv6. Vlan 2 carries IPv4 with a route MTU of 576
at each end, since Linux takes IPv6 off a device under 1280, and the gateway's
kernel then builds no route for IPv6 in an SA over it. strongSwan cuts its own
messages at its `fragment_size` of 1280 on both, and on vlan 2 the kernel splits
those fragments into IP fragments. The check runs 4 phases: `x25519+mlkem768`
over IPv6, `p384+mlkem1024` over IPv6, `x25519+mlkem768` over IPv4 and
`p384+mlkem1024` over IPv4, each later one entered through a `specialisation` of
the client. Where a phase keeps the family, the switch reloads the `kex` list,
which rekeys the IKE SA to the new entry through `IKE_FOLLOWUP_KE` cut both ways
with the session kept, and a restart then dials with it. Each phase asserts that
`ranet3 sessions --json` names the entry and the remote, `ike_fragments` true
and `ike_fragment_threshold` at the phase's threshold, 1280 or 576, and that
`swanctl --list-sas` names the entry. For each `IKE_INTERMEDIATE` and
`IKE_FOLLOWUP_KE` it asserts ranet3's `ike sending a message in fragments` line
and `ike.message.fragmented` event at that threshold and strongSwan's
`reassembled fragmented IKE message`. For ML-KEM-1024, whose answers pass
strongSwan's `fragment_size`, it also asserts strongSwan's
`splitting IKE message (... bytes) into N fragments` and ranet3's
`ike reassembled a message from fragments`. A ping crosses each phase in both
families. At the end it asserts that each log holds none of these lines:

- ranet3's: `no matching inbound ESP SA`,
  `ike stopping ESP on a Child SA past its lifetime` and
  `ike dropped the fragments of a message the peer left incomplete`
- strongSwan's: `integrity check failed`, `no CHILD_SA built` and
  `AUTHENTICATION_FAILED`

The checks that write no `kex` list, all but `suites-meet` and the `mlkem-*`
ones, run its default: ranet3 offers `x25519+mlkem768` first, and a strongSwan
whose proposals hold no ML-KEM takes a classical entry.

`integration-egress` makes the client an exit node and boots a third machine
behind it, holding prefixes the gateway can reach through the mesh and no other
way. It asserts that the announcement reaches BIRD on the far side, that the
machine behind the exit sees the exit's own address on both families and never
the mesh address the packet started with, that the sweep recognizes its own
rules rather than rewriting them, that turning `net.ipv4.ip_forward` off
withdraws the IPv4 advertisement and leaves the IPv6 one alone, and that a stop
leaves no nftables table behind. A start after the stop installs the tables
again.

`integration-egress-segment` gives the exit node an egress segment instead of an
advertisement. It asserts that the exit is ready for both families and that the
gateway holds the SID's /128, that the exit holds its mesh tun as its only tun,
no routing rule keyed on an arrival device and a translation rule keyed on the
tun in both families, and that its lookups ran rather than being skipped. The
gateway then steers its IPv6 traffic to the SID, and the machine behind the exit
sees the exit's own address. A source outside the allow list is refused, and so
is an inner packet for a destination the mesh routes, which the gateway never
gets back through the mesh. Turning IPv6 forwarding off keeps the SID, since a
family the host does not forward is not waited for. A stop removes the tables.

`integration-segments` steers 1 destination through a segment routing header
(RFC 8754). The gateway's own kernel removes the header with End.DT6, and a
capture on the gateway shows the bare inner packet. `ranet3 status --json`
counts steered packets and no unsteered ones. With the gateway's SID removed,
the steered packets still arrive and nothing removes the header. In the other
direction the gateway's kernel builds the header, and the client's End.DT46
delivers the packet, which its `delivered` counter records with no segment
dropped. The address it delivers to is one the client holds on loopback and
announces, since the forwarding decision delivers only to an address the client
routes. A rule on the gateway ahead of its main table sends that address through
the segment rather than the route it learns.

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

The checks give the Child SA a lifetime of 24 seconds and the IKE SA one of 34
seconds, with a margin of 22 seconds and no jitter, so each SA rekeys soon after
it is made. The 2 `mlkem-meet` checks give the Child SA 32 seconds. The
ML-KEM-768 Child SA of strongSwan's rekey thereby lasts until ranet3's own rekey
10 seconds after it is made, past the check of its key exchanges. The margin
covers the unanswered Delete of a replaced IKE SA, which holds the session's
next request, and then a rekey's 3 lost sends. The script of
`integration-initiator` and `integration-kernel` also has the gateway drop the
client's IKE for 5 seconds while iperf3 runs, which outlasts a rekey's first
send, and asserts that a Child SA rekey completed and that no Child SA reached
its lifetime. The scripts of the initiator, responder and `suites-meet` checks,
and of the `mlkem-*` checks except the 2 `mlkem-apart` ones, fail whenever
ranet3 logs that it stopped ESP on a Child SA past its lifetime.

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
