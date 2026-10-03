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

MIT, see [license.txt](license.txt). ranet3 began as a fork of
[NickCao/ranet-lite](https://github.com/NickCao/ranet-lite).
