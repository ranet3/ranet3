<!-- SPDX-FileCopyrightText: 2026 Yifei Sun -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# ranet3

A mesh network in one Go binary: IKEv2 and userspace ESP between nodes, Babel
routing with source-specific routes, segment routing, exit nodes and subnet
routers.

```sh
sudo nix run github:ranet3/ranet3 -- daemon --config /etc/ranet3/config.toml
```

The documentation is at <https://ranet3.com>, and its sources in
[pkgs/ranet3-docs/pages](pkgs/ranet3-docs/pages).

## License

ranet3's own work is under the Functional Source License, FSL-1.1-ALv2, and each
version becomes Apache-2.0 two years after it is published. ranet3 began as a
fork of [NickCao/ranet-lite](https://github.com/NickCao/ranet-lite), and the
portions that come from it stay under the MIT license. The documentation is
under CC-BY-4.0. [license.txt](license.txt) says which license covers what, and
`ranet3 licenses` prints the notices that travel with a binary.
