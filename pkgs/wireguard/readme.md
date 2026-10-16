<!-- SPDX-FileCopyrightText: 2026 Yifei Sun -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# wireguard

A copy of the `tun`, `conn` and `rwcancel` packages of
[wireguard-go](https://git.zx2c4.com/wireguard-go), with the changes from
[tailscale's fork](https://github.com/tailscale/wireguard-go) that ranet3's tun
uses, as the module `ranet3.com/pkgs/wireguard`.

The code keeps upstream's style and license (MIT, in `LICENSE`), so a change
made here can be offered upstream as it is.

## Provenance

The copy is built in a clone of upstream in four steps:

1. Upstream's tip `2631ce99a06f27120d581611cf125d68bc6aa565` (2026-10-06, Jason
   A. Donenfeld, "device: noise: reject response consumption after intermediate
   initiation").
2. The 15 commits of tailscale's `tailscale` branch below, cherry-picked in
   their order with `git cherry-pick -x`, authorship kept. Their imports of
   `github.com/tailscale/wireguard-go/...` are rewritten to
   `golang.zx2c4.com/wireguard/...` in the pick. tailscale never merges or
   rebases upstream: its branch leaves upstream at `469159ecf7d1` (2023-07-04)
   and takes upstream's later commits one by one, so the picks land on code that
   both sides changed since.
3. One commit renaming the module to `ranet3.com/pkgs/wireguard`: the `module`
   line of `go.mod` and every import of the module's own packages, nothing else.
4. The trim: the files of `tun`, `conn` and `rwcancel` that some build of linux,
   darwin, freebsd or openbsd on amd64 or arm64 compiles, their tests,
   `tun/generate_amd64.go` (the source of `tun/checksum_generated_amd64.s`),
   `LICENSE`, and `go.mod` and `go.sum` tidied to what is left. The trim drops
   `x/crypto` and `wintun` from `go.mod`. `gvisor` stays, for tests of `tun`.

The first commit of this directory is the result of these steps. The changes
made here since are the later commits that `git log` shows for this directory.

### The tailscale commits

| tailscale commit | Subject                                                              | Author           | Where the pick conflicted                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ---------------- | -------------------------------------------------------------------- | ---------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ec6f23b33e03`   | tun: checksum tests and benchmarks                                   | Adrian Dewhurst  | `tun/checksum_test.go`, against upstream's reference tests from `b82c016`. Both sets are kept, and tailscale's table test `TestChecksum` is renamed `TestChecksumVectors`, since upstream has a `TestChecksum` of its own.                                                                                                                                                                                                                                                                                                                                                    |
| `88b11b4a0dde`   | tun: AMD64 optimized checksum                                        | Adrian Dewhurst  | `tun/checksum.go` takes tailscale's rewrite whole, which replaces upstream's add-with-carry `checksumNoFold` from `b82c016`. Upstream renamed `tun/tcp_offload_linux.go` to `tun/offload_linux.go` in `d0bc03c`, so the pick's edits to the old file are made in the new one: `pseudoHeaderChecksum` with a folded `uint16` in `checksumValid`, both coalesce accountings, `gsoSplit` and `gsoNoneChecksum`. Upstream's `TestPseudoHeaderChecksum` calls `pseudoHeaderChecksum`.                                                                                              |
| `03c5a0ccf754`   | tun: implement API for disabling UDP GRO on Linux                    | Jordan Whited    | Clean. ranet3 does not call it, but `799c197`, `07ca723` and `cbffc0a` build on its `groDisablementFlags`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `60eeedfd624b`   | tun: export GSOSplit() for external Device implementers              | Jordan Whited    | Clean, imports rewritten in `tun/offload_test.go`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `6c039a188c2d`   | tun: export optimized IP checksum funcs                              | Jordan Whited    | Clean. Upstream's reference tests call the exported `Checksum` and `PseudoHeaderChecksum`, since the unexported names no longer exist off amd64.                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `71393c576b98`   | tun: fix checksum test failures on non-4KiB page sizes               | Adrian Dewhurst  | Clean.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `799c1978fafc`   | tun: add method for disabling TCP GRO on Linux                       | Jordan Whited    | Clean. Upstream's test from `ecfc5a8` passed `false` for `canUDPGRO` to `handleGRO` and now passes `udpGRODisabled`, which means the same.                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `4e883d38c8d3`   | tun: use x/sys/unix IoctlIfreq/NewIfreq to set MTU on Linux          | Brad Fitzpatrick | Clean.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `65cd6eed7d7f`   | conn,device: provide 8 free bytes at packet head to conn.Bind.Send() | Jordan Whited    | Clean.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `cd4feb8708a9`   | conn: coalesce via scatter-gather writes                             | Alex Valiushko   | `putMessages` in `conn/bind_std.go`: upstream's `OOB[:0]` reset is kept beside tailscale's `Buffers[:1]`. The retry without GSO in `Send` first trims each message back to `Buffers[:1]`, as tailscale does only in its later `f4ef62e`. Without it the retry sends the datagrams coalesced into a message again behind its first one. The pick's message carries a note saying so, and the pick adds `TestStdNetBindSendRetryWithoutGSO` to `conn/sticky_linux_test.go`, a root test that draws the kernel's EIO with an xfrm policy on loopback and fails without the trim. |
| `07ca723923d8`   | tun: coalesce via scatter-gather writes (#52)                        | Alex Valiushko   | `Test_handleGRO_invalidItemCsumClearsVirtioNetHdr`, upstream's test from `ecfc5a8` against tailscale's rewrite of it: tailscale's body, calling `handleGRO` with `udpGRODisabled`.                                                                                                                                                                                                                                                                                                                                                                                            |
| `24b5b6917431`   | conn,device,tun: use single ~128KiB packet buf for batched i/o       | Jordan Whited    | `tun/tun_plan9.go` is dropped, since upstream has no plan9 port. `conn/bind_std.go` takes tailscale's `putMessages(msgs, used)` with upstream's `OOB[:0]` reset, and tailscale's slab path in `receiveIP` with upstream's `linux \|\| android` checks from `24ea133`. The `device`, `tun/netstack` and windows changes are resolved in the full stack and are not part of this copy.                                                                                                                                                                                          |
| `7658b3f64aff`   | tun: remove extra read buf/mutex on Linux                            | Jordan Whited    | Clean.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `cbffc0a83ffa`   | device,tun: shard the tun side of the dataplane across queues (#96)  | Alex Valiushko   | The `tun` files merge without a conflict. The `device` half is ported by hand onto upstream's `device` and is not part of this copy.                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `e61b6b78110b`   | device: serialize nonce stamping with the outbound enqueue (#103)    | Alex Valiushko   | `device` only, not part of this copy: the hunk in tailscale's `SendPriorityMessage` and its registry change are dropped, and the lock goes into upstream's `SendStagedPackets`.                                                                                                                                                                                                                                                                                                                                                                                               |

### What was left out

The commits of tailscale's branch since the merge base that touch `tun`, `conn`
or `rwcancel` and are not picked:

- In upstream already, patch for patch: `915962d` (tun: unwind summing loop in
  checksumNoFold()), `ceb9a09` (tun: reduce redundant checksumming in tcpGRO()),
  `2f6748d` (tun: fix crash when ForceMTU is called after close).
- In upstream already, as upstream's own version of the same change: `e06231b`
  (conn, device: use UDP GSO and GRO on Linux) as upstream's `6a84778`,
  `24f8d7c` and `db7604d` (tun: implement UDP GSO/GRO for Linux, tun: don't
  assume UDP GRO is supported) as upstream's `d0bc03c`, `e26adb8`
  (go.mod,tun/netstack: bump gvisor) as upstream's `42ec952`, and `92a4d28`
  (tun: clear virtioNetHdr when deleting item from tcpGROTable) as upstream's
  `ecfc5a8`.
- tailscale's module path: `bd7e9d3` (all: rename module), replaced here by the
  rename to `ranet3.com/pkgs/wireguard`.
- Platforms ranet3 does not build for: `6cd5922` (all: adjust build tags for
  plan9), `202a340` (adjust build tags for tamago), `91a0587` (tun: add plan9
  support).
- tailscale's peer-aware endpoints, which ranet3 does not use: `2f5d148`
  (conn,device: enable cryptorouting via PeerAwareEndpoint), `24483d7`
  (conn,device: always perform PeerAwareEndpoint check), `1f398ae` (conn,device:
  implement InitiationAwareEndpoint), `1d0488a` (conn,device: eval
  conn.PeerAwareEndpoint per-packet).
- `f4ef62e` (device,conn: shard the UDP side of the dataplane across queues), a
  `device` change ranet3 does not use. Its reset of a message's buffers before
  the retry without GSO is carried in the pick of `cd4feb8`.

## Syncing with upstream

A later upstream applies as upstream's own diff, limited to the packages kept
here, onto this directory. Fetch upstream into this repository first so that
`-3` finds the blobs the diff names, which lets the import rewrite merge with
upstream's changes:

```sh
git fetch https://git.zx2c4.com/wireguard-go master
git diff 2631ce99a06f27120d581611cf125d68bc6aa565 FETCH_HEAD -- tun conn rwcancel go.mod go.sum \
  | git apply --directory=pkgs/wireguard -3
```

Then rewrite new imports of `golang.zx2c4.com/wireguard/` to
`ranet3.com/pkgs/wireguard/`, remove any new file that the trim above would not
keep, tidy `go.mod`, regenerate `gomod2nix.toml` with `nix fmt`, and update the
hash in this file and the date in the `version` of `default.nix`.

`go.mod` requires each module that `pkgs/ranet3/go.mod` also requires, such as
`golang.org/x/net` and `golang.org/x/sys`, at the version ranet3 links into
these packages, so that the tests here build what ranet3 ships. `checks/tree`
fails when the two files require a module at different versions, and names both
versions. A sync keeps the higher of upstream's version and this one, and a bump
of such a module goes into both files in the same commit.

## Offering a fix

A fix made here is exported relative to this directory, with the imports
rewritten back to the upstream module path:

```sh
git format-patch --relative=pkgs/wireguard <base>..<tip> -- pkgs/wireguard
sed -i 's|"ranet3.com/pkgs/wireguard/|"golang.zx2c4.com/wireguard/|g' 0*.patch
```

The scatter-gather write path is tailscale's (`07ca723`), not upstream's, so a
fix to it goes to tailscale/wireguard-go, with the imports rewritten to
`github.com/tailscale/wireguard-go/` instead.

The rename sorted the module's imports anew: they sort after `gvisor.dev` here
and before it upstream, and after `golang.org` here and before it in tailscale's
tree. A hunk whose context holds such an import block does not apply after the
rewrite, so it is made again by hand in a checkout of the target, and `gofmt`
runs on every file the fix touches there.
