# SPDX-FileCopyrightText: 2026 Nick Cao
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

{
  lib,
  inputs,
  pkgs,
  testers,
  ...
}:

{
  cores ? 1,
  profile ? false,
  # responder inverts the exchange: strongSwan dials and ranet3 answers,
  # which is the direction upstream could not do at all.
  responder ? false,
  # kernel turns on the route reconciler, so the routes babel learns from BIRD
  # have to reach a real kernel table rather than only the in-process trie.
  kernel ? false,
  # segments steers one destination through a segment routing header that the
  # gateway's own kernel decapsulates, so this tree's encapsulation is checked
  # against the implementation it has to interoperate with rather than against
  # its own decoder.
  segments ? false,
  # egress makes the client an exit node for a network the gateway can reach no
  # other way, so the translation, the forwarding and the advertisement are
  # measured against a third machine rather than against this tree's own idea
  # of what it installed.
  egress ? false,
  # egressSegment makes the client's exit an egress segment the gateway's own
  # kernel steers into with seg6 encap, rather than a prefix it advertises, so
  # a kernel leaf's bytes are checked against the exit that has to act on them.
  # It goes with egress and segments, and only the SID is announced.
  egressSegment ? false,
  # fqdn names both ends by an FQDN in place of a DN, strongSwan by its own id
  # and ranet3 by auth.aliases, so an ID of another type than a DN is checked
  # against the implementation it has to interoperate with.
  fqdn ? false,
  # suites gives ranet3 the cap.crypto lists suiteLists names under it and strongSwan the proposals of swanProposals
  # "meet" shares one suite between the two ends
  # "apart" shares none
  suites ? null,
  # mlkem gives ranet3 the kex list mlkemLists names under it and strongSwan the proposals of mlkemSwan
  # "meet" shares x25519+mlkem768 between the two ends
  # "apart" lists x25519+mlkem768 alone against strongSwan's defaults, which hold no ML-KEM
  # "fallback" lists x25519 after it against those defaults
  # "optional" and "none" answer a strongSwan that dials with ML-KEM-768 optional, listing x25519+mlkem768 first or x25519 alone
  mlkem ? null,
}:

assert suites == null || mlkem == null;
# strongSwan dials in "optional" and "none" and ranet3 in "fallback"
assert
  lib.elem mlkem [
    "optional"
    "none"
  ]
  -> responder;
assert mlkem == "fallback" -> !responder;

let
  gatewayTunnel = "fd00:99::1";
  clientTunnel = "fd00:88::2";
  gatewayTunnelV4 = "10.99.0.1";
  kernelTable = 200;
  kernelProtocol = 155;
  clientTunnelV4 = "10.88.0.2";
  # networkd makes the client's tun under a name of its own
  # and link.tun names it for ranet3 to attach to
  # the default name, ranet3, is only ever created
  clientDevice = "ranet0";
  # Inside the /64 BIRD already announces, so the segment is reachable over
  # the mesh without a second announcement to keep in step with this one.
  gatewaySID = "fd00:99::6:1";
  gatewayBehind = "fd00:99::9";
  # The mirror image, for the direction where the gateway's kernel builds the
  # header and this tree acts on it. The SID is announced so the gateway can
  # route to it, and clientBehind is not, so the only way a packet reaches it
  # is the segment.
  clientSID = "fd00:88::6:1";
  # On loopback rather than on the tun: an address on the tun is one the kernel
  # can pick as the source for the mesh traffic that leaves through it, and
  # nothing announces this one, so the replies would have nowhere to go.
  clientBehind = "fd00:88::9";
  # The egress segment's SID, announced by the client only while its egress
  # device is ready, and the device named after the client's tun. The
  # gateway's outside address is in neither prefix the allow list names.
  clientEgressSID = "fd00:88::6:3";
  clientEgressDevice = "${clientDevice}e";
  gatewayOutside = "fd00:77::1";
  # Mesh sources behind forges from the client's link, inside the border's
  # overlay and owned by nobody on the mesh.
  borderForged4 = "10.99.0.77";
  borderForged6 = "fd00:99::77";
  # A segment behind's routing header names, in the prefix it routes through
  # the exit.
  borderSegment = "fd00:99::2";
  # The network behind the exit node, on the same link as the underlay but in
  # prefixes neither the gateway nor the test harness assigns, so the gateway
  # reaches it through the mesh or not at all. behind answers there and has no
  # route back to the tunnel prefixes, so a reply proves the source was
  # translated as surely as the capture does.
  exitNetV4 = "198.51.100.0/24";
  exitNetV6 = "fd00:aa::/64";
  behindV4 = "198.51.100.1";
  behindV6 = "fd00:aa::1";
  exitV4 = "198.51.100.2";
  exitV6 = "fd00:aa::2";
  gatewayFQDN = "server.testorg.example";
  clientFQDN = "client.testorg.example";
  publicKey = builtins.readFile ../../fixtures/org-pub.pem;
  # strongSwan proposes the stronger of each pair first
  # so a choice ranet3's lists did not narrow comes out as the stronger one
  swanProposals = [ "aes256gcm16-aes128gcm16-prfsha384-prfsha256-ecp384-ecp256" ];
  swanESPProposals = [ "aes256gcm16-aes128gcm16" ];
  # meet leaves ranet3 aes128gcm, sha256 and p256 of what strongSwan proposes
  # apart leaves it no IKE cipher strongSwan proposes
  suiteLists = {
    meet = {
      ike = {
        cipher = [
          "chacha20poly1305"
          "aes128gcm"
        ];
        prf = [ "sha256" ];
        kex = [
          "x25519"
          "p256"
        ];
      };
      esp.cipher = [
        "chacha20poly1305"
        "aes128gcm"
      ];
    };
    apart.ike.cipher = [ "chacha20poly1305" ];
  };
  mlkemLists = {
    meet = [ "x25519+mlkem768" ];
    apart = [ "x25519+mlkem768" ];
    fallback = [
      "x25519+mlkem768"
      "x25519"
    ];
    optional = [
      "x25519+mlkem768"
      "x25519"
    ];
    none = [ "x25519" ];
  };
  # strongSwan prefixes an additional key exchange's keyword with ke1_ for ADDKE1, and ke1_none makes it optional
  # "meet" esp_proposals take an ESP rekey with no key exchange at all, which is the one ranet3 sends, and strongSwan's own runs x25519 and ML-KEM-768
  # a variant missing here leaves strongSwan its defaults
  mlkemSwan = {
    meet = {
      ike = [ "aes256gcm16-prfsha384-x25519-ke1_mlkem768" ];
      esp = [ "aes256gcm16-x25519-none-ke1_mlkem768-ke1_none" ];
    };
    optional.ike = [ "aes256gcm16-prfsha384-x25519-ke1_mlkem768-ke1_none" ];
    none.ike = [ "aes256gcm16-prfsha384-x25519-ke1_mlkem768-ke1_none" ];
  };
  swan =
    if suites != null then
      {
        ike = swanProposals;
        esp = swanESPProposals;
      }
    else if mlkem != null then
      mlkemSwan.${mlkem} or { }
    else
      { };

  common = {
    virtualisation.vlans = [ 1 ];
    virtualisation.cores = cores;
    networking = {
      useNetworkd = true;
      useDHCP = false;
      firewall.enable = false;
    };
  };
in
testers.runNixOSTest {
  name =
    if suites != null then
      "ranet3-suites-${suites}${lib.optionalString responder "-responder"}"
    else if mlkem != null then
      "ranet3-mlkem-${mlkem}${lib.optionalString responder "-responder"}"
    else if responder then
      "ranet3-responder${lib.optionalString fqdn "-fqdn"}"
    else if egressSegment then
      "ranet3-egress-segment"
    else if kernel then
      "ranet3-kernel"
    else if segments then
      "ranet3-segments"
    else if egress then
      "ranet3-egress"
    else
      "ranet3-integration${lib.optionalString fqdn "-fqdn"}";

  meta.platforms = lib.platforms.linux;

  nodes = {
    gateway =
      { config, nodes, ... }:
      {
        imports = [ common ];

        boot.kernelModules = [ "xfrm_interface" ];

        # The gateway is the peer this tree has to interoperate with, so the
        # segment it answers for is the kernel's own End behavior rather than
        # anything from this repository. default covers swan0, which
        # strongSwan creates once the SA is up and after any boot-time sysctl
        # would have run.
        boot.kernel.sysctl = pkgs.lib.mkIf segments {
          "net.ipv6.conf.all.seg6_enabled" = 1;
          "net.ipv6.conf.default.seg6_enabled" = 1;
          # A node answering for a segment is a router for it, and a kernel
          # with forwarding off drops the packet in ip6_forward and counts
          # Ip6InAddrErrors, which reads as an address problem rather than as
          # a policy one. The fleet's own nodes set this too.
          "net.ipv6.conf.all.forwarding" = 1;
        };

        environment.systemPackages =
          with pkgs;
          [
            bird2
            iperf3
            iproute2
            # drops the client's IKE for a while to show a rekey outlasts lost sends
            nftables
            config.services.strongswan-swanctl.package
          ]
          # A capture is the only thing that tells a packet that never arrived
          # from one the far end refused.
          ++ pkgs.lib.optionals segments [ tcpdump ];

        environment.etc = {
          "swanctl/private/org-key.pem".source = ../../fixtures/org-key.pem;
          "swanctl/pubkey/org-pub.pem".source = ../../fixtures/org-pub.pem;
        };

        systemd.network = {
          netdevs."20-swan0" = {
            netdevConfig = {
              Name = "swan0";
              Kind = "xfrm";
            };
            xfrmConfig.InterfaceId = 1;
          };
          networks = {
            # The test network module already defines 40-eth1. Extend it to
            # create swan0 with eth1 as its underlying device.
            "40-eth1".networkConfig.Xfrm = "swan0";
            "40-swan0" = {
              matchConfig.Name = "swan0";
              linkConfig = {
                Multicast = true;
                RequiredForOnline = false;
              };
              networkConfig.ConfigureWithoutCarrier = true;
              addresses = [
                { Address = "fe80::1/64"; }
                { Address = "${gatewayTunnel}/64"; }
                { Address = "${gatewayTunnelV4}/24"; }
              ]
              # The steered destination goes here rather than on lo, because
              # the tunnel prefix is a connected /64 on this link: an address
              # inside it that is not assigned locally is one the gateway
              # sends straight back to the client.
              ++ pkgs.lib.optionals segments [ { Address = "${gatewayBehind}/128"; } ]
              ++ pkgs.lib.optionals egressSegment [ { Address = "${gatewayOutside}/128"; } ];
            };
          };
        };

        services.strongswan-swanctl = {
          enable = true;
          # cfg at level 2 logs the proposals strongSwan received where it found one acceptable
          # so the log shows each transform of ranet3's answer, a NONE among them
          strongswan.extraConfig = ''
            charon-systemd {
              interfaces_use = eth1
              port = 0
              port_nat_t = 13000
            }
          ''
          + lib.optionalString (mlkem != null) ''
            charon-systemd {
              journal {
                cfg = 2
              }
            }
          '';
          swanctl = {
            connections.ranet = {
              version = 2;
              local_addrs = [ "0.0.0.0/0" ];
              # A wildcard remote can only answer. Naming the client lets
              # swanctl --initiate dial it.
              remote_addrs = if responder then [ nodes.client.networking.primaryIPAddress ] else [ "0.0.0.0/0" ];
              local_port = 13000;
              remote_port = 14000;
              encap = true;
              mobike = false;
              proposals = pkgs.lib.mkIf (swan ? ike) swan.ike;
              dpd_delay = "10s";
              keyingtries = 0;
              unique = "replace";
              if_id_in = "1";
              if_id_out = "1";
              local.main = {
                auth = "pubkey";
                pubkeys = [ "org-pub.pem" ];
                id = if fqdn then gatewayFQDN else "O=testorg, CN=server, serialNumber=1";
              };
              remote.main = {
                auth = "pubkey";
                pubkeys = [ "org-pub.pem" ];
                id = if fqdn then clientFQDN else "O=testorg, CN=client, serialNumber=2";
              };
              children.default = {
                local_ts = [
                  "0.0.0.0/0"
                  "::/0"
                ];
                remote_ts = [
                  "0.0.0.0/0"
                  "::/0"
                ];
                mode = "tunnel";
                esp_proposals = pkgs.lib.mkIf (swan ? esp) swan.esp;
                dpd_action = "restart";
                start_action = "none";
                close_action = "none";
              };
            };
          };
        };

        systemd.services.strongswan-swanctl = {
          requires = [ "network-online.target" ];
          after = [ "network-online.target" ];
        };

        services.bird = {
          enable = true;
          package = pkgs.bird3;
          config = ''
            ipv6 sadr table sadr6;

            protocol device {
              scan time 1;
            }

            protocol kernel {
              ipv6 sadr {
                export all;
                import none;
              };
            }

            protocol static {
              ipv6 sadr ;
              route fd00:99::/64 from ::/0 unreachable;
            }

            protocol kernel kernel4 {
              ipv4 {
                export all;
                import none;
              };
            }

            protocol static static4 {
              ipv4;
              route 10.99.0.0/24 unreachable;
            }

            protocol babel {
              ipv4 {
                export all;
                import all;
              };
              ipv6 sadr {
                export all;
                import all;
              };
              randomize router id;
              interface "swan0" {
                type tunnel;
                rxcost 96;
                hello interval 500 ms;
                update interval 1 s;
                rtt cost 1024;
                rtt max 1024 ms;
                rx buffer 1500;
              };
            }
          '';
        };

        systemd.services.bird = {
          requires = [ "network-online.target" ];
          after = [ "network-online.target" ];
        };

        services.iperf3 = {
          enable = true;
          bind = gatewayTunnel;
        };
      };

    client =
      { nodes, ... }:
      {
        imports = [
          common
          inputs.self.nixosModules.ranet3
        ];

        boot.kernelModules = [ "tun" ];

        # An exit node forwards for its peers, and a node that advertises a
        # prefix it will not forward attracts traffic and drops it. The
        # capability withholds the advertisement while these are off, which the
        # script turns one of them off to measure.
        boot.kernel.sysctl = pkgs.lib.mkIf egress {
          "net.ipv4.ip_forward" = 1;
          "net.ipv6.conf.all.forwarding" = 1;
        };

        # The far side of the exit is on the same link as the underlay, under
        # prefixes the harness assigns to nobody, so the gateway has a route to
        # it through the mesh alone.
        networking.interfaces.eth1 = pkgs.lib.mkIf egress {
          ipv4.addresses = [
            {
              address = exitV4;
              prefixLength = 24;
            }
          ];
          ipv6.addresses = [
            {
              address = exitV6;
              prefixLength = 64;
            }
          ];
        };

        environment.systemPackages =
          with pkgs;
          [
            curl
            iperf3
            iproute2
          ]
          # nft reads back what this tree wrote through netlink, and jq asks
          # the control socket a question the shell cannot.
          ++ pkgs.lib.optionals egress [
            jq
            nftables
          ]
          ++ lib.optionals profile [
            pprof
            perf
          ];

        systemd.network = {
          netdevs."20-${clientDevice}" = {
            netdevConfig = {
              Name = clientDevice;
              Kind = "tun";
            };
            tunConfig = {
              MultiQueue = true;
              PacketInfo = false;
              VNetHeader = true;
            };
          };
          networks."05-lo" = pkgs.lib.mkIf segments {
            matchConfig.Name = "lo";
            networkConfig.ConfigureWithoutCarrier = true;
            # What an End.DT46 on this node delivers to, reachable through the
            # segment and nothing else, because nothing announces it.
            addresses = [ { Address = "${clientBehind}/128"; } ];
          };
          networks."40-${clientDevice}" = {
            matchConfig.Name = clientDevice;
            linkConfig = {
              MTUBytes = 1400;
              RequiredForOnline = false;
            };
            networkConfig.ConfigureWithoutCarrier = true;
            addresses = [
              { Address = "${clientTunnel}/128"; }
              { Address = "${clientTunnelV4}/32"; }
            ];
            routes = [
              { Destination = "fd00:99::/64"; }
              { Destination = "10.99.0.0/24"; }
            ];
          };
        };

        environment.etc = {
          "ranet3/key.pem".source = ../../fixtures/org-key.pem;
          "ranet3/registry.json".text = builtins.toJSON [
            {
              public_key = publicKey;
              organization = "testorg";
              nodes = [
                {
                  common_name = "client";
                  endpoints = [
                    {
                      serial_number = "2";
                      address_family = "ip4";
                      address = nodes.client.networking.primaryIPAddress;
                      port = 14000;
                    }
                  ];
                  remarks = { };
                }
                {
                  common_name = "server";
                  endpoints = [
                    {
                      serial_number = "1";
                      address_family = "ip4";
                      address = nodes.gateway.networking.primaryIPAddress;
                      port = 13000;
                    }
                  ];
                  remarks = { };
                }
              ];
            }
          ];
        };

        networking.ranet3 = {
          enable = true;
          logLevel = "debug";
          extraArgs = [
            "--metrics"
            "127.0.0.1:9669"
          ]
          ++ pkgs.lib.optionals profile [
            "--pprof"
            "127.0.0.1:6060"
          ];
          settings = {
            node = "testorg/client";
            auth = {
              key = "/etc/ranet3/key.pem";
              trust = "/etc/ranet3/registry.json";
            }
            # the gateway names itself by the FQDN of its own id and this node
            # by the FQDN of its remote id
            // pkgs.lib.optionalAttrs fqdn {
              aliases = {
                remote.fqdn.${gatewayFQDN} = "testorg/server:1";
                local."testorg/server".fqdn = clientFQDN;
              };
            };
            link = {
              port = 14000;
              endpoints = [
                {
                  serial = "2";
                  family = "ip4";
                }
              ];
              tun = clientDevice;
              listen = pkgs.lib.mkIf responder true;
            };
            dial = pkgs.lib.mkIf (!responder) {
              to = [ "testorg/server:1" ];
            };
            cap = {
              route.announce = [
                "${clientTunnel}/128"
                "${clientTunnelV4}/32"
              ]
              ++ pkgs.lib.optional segments "${clientSID}/128";
              babel = {
                hello = "500ms";
                update = "1s";
              };
              crypto = {
                rekey = {
                  # each rekey starts the margin before the lifetime stops its SA
                  # and the margin covers a Delete of a replaced IKE SA on the teardown budget, then a rekey's three lost sends
                  child = if profile then 0 else "24s";
                  ike = if profile then 0 else "34s";
                  margin = "22s";
                  jitter = 0;
                };
              }
              // pkgs.lib.optionalAttrs (suites != null) suiteLists.${suites}
              // pkgs.lib.optionalAttrs (mlkem != null) { ike.kex = mlkemLists.${mlkem}; };
              segment = pkgs.lib.mkIf segments {
                source = clientTunnel;
                local = [
                  {
                    sid = clientSID;
                    behavior = "End.DT46";
                  }
                ]
                ++ pkgs.lib.optional egressSegment {
                  sid = clientEgressSID;
                  behavior = "End.DT46";
                  deliver = "egress";
                  allow = [
                    "fd00:99::/64"
                    "10.99.0.0/24"
                  ];
                };
                steer = [
                  {
                    from = "${clientTunnel}/128";
                    to = "${gatewayBehind}/128";
                    via = [ gatewaySID ];
                  }
                ];
              };
              # a local segment needs the border, whose overlay covers both
              # tunnel prefixes, so every outer source the gateway sends from
              # and the egress segment's allow list
              border = pkgs.lib.mkIf segments {
                overlay = [
                  "fd00:88::/32"
                  "fd00:99::/32"
                  "10.88.0.0/16"
                  "10.99.0.0/16"
                ];
              };
              # an exit for an egress segment alone advertises nothing, so the
              # gateway reaches the far side through the segment or not at all
              egress = pkgs.lib.mkIf egress {
                advertise = pkgs.lib.optionals (!egressSegment) [
                  exitNetV4
                  exitNetV6
                ];
                sweep = "2s";
              };
              table = pkgs.lib.mkIf (kernel || egress) (
                {
                  id = kernelTable;
                  proto = kernelProtocol;
                  metric = 32;
                  prefsrc4 = clientTunnelV4;
                  reconcile = "2s";
                }
                # A reply to a translated flow has its destination put back
                # before the forwarding lookup runs, so the route to the peer
                # has to be in a table that lookup consults. The mesh's routes
                # are in a table of the reconciler's own, and a rule is how
                # anything else reaches them.
                // pkgs.lib.optionalAttrs egress {
                  rules = [
                    {
                      to = "10.99.0.0/24";
                      table = kernelTable;
                      priority = 100;
                    }
                    {
                      to = "fd00:99::/64";
                      table = kernelTable;
                      priority = 100;
                    }
                  ]
                  # what leaves the egress device follows main, after the to
                  # rules so a mesh destination still goes to the mesh
                  ++ pkgs.lib.optional egressSegment {
                    iif = clientEgressDevice;
                    table = "main";
                    priority = 120;
                    family = "both";
                  };
                }
              );
            };
          };
        };
      };
  }
  // pkgs.lib.optionalAttrs egress {
    # The network the exit node carries. It has no route to either tunnel
    # prefix, so it can answer the exit's own address and nothing else: a reply
    # that arrives at the gateway is a source that was translated, and the
    # capture says which address it was translated to.
    behind = {
      imports = [ common ];
      environment.systemPackages = [ pkgs.tcpdump ];
      networking.interfaces.eth1 = {
        ipv4.addresses = [
          {
            address = behindV4;
            prefixLength = 24;
          }
        ];
        ipv6.addresses = [
          {
            address = behindV6;
            prefixLength = 64;
          }
        ];
      };
    };
  };

  testScript =
    let
      preamble = ''
        import datetime as dt

        timeout = dt.timedelta(seconds=30)
        # how long an iperf3 client retries a server that refused it between tests
        iperf_timeout = dt.timedelta(seconds=120)

        kernel_enabled = ${if kernel then "True" else "False"}
        fqdn_enabled = ${if fqdn then "True" else "False"}
        kernel_table = "${toString kernelTable}"
        kernel_protocol = "${toString kernelProtocol}"
        client_tunnel_v4 = "${clientTunnelV4}"
        client_device = "${clientDevice}"

        def journal_after(machine, unit):
            output = machine.succeed(f"journalctl -u {unit} -n 1 --show-cursor --no-pager")
            cursor = output.rsplit("-- cursor: ", 1)[1].strip()
            return f"journalctl -u {unit} --after-cursor='{cursor}' --no-pager"

        def named_by_fqdn():
            """strongSwan established the SA under the two FQDNs, and ranet3 resolved the gateway's to its endpoint."""
            gateway.succeed(
                "journalctl -u strongswan-swanctl.service --no-pager | grep -F 'established between'"
                " | grep -F '[${gatewayFQDN}]...' | grep -F '[${clientFQDN}]'"
            )
            print(client.succeed(
                "ranet3 debug wait ike.id.resolved --past 10m --attr type=fqdn --attr id=${gatewayFQDN} --attr sent=fqdn"
            ))

        start_all()

        # The runtime directory is where the control socket is bound and the
        # group is who may then use it, so a typo in either leaves a node nobody
        # can ask anything or one anybody can.
        for key, want in [("RuntimeDirectory", "ranet3"), ("Group", "ranet3")]:
            got = client.succeed(f"systemctl show -p {key} --value ranet3.service").strip()
            assert got == want, f"ranet3.service has {key}={got}, want {want}"

      '';

      # The gateway's own kernel decapsulates what this tree encapsulated, so
      # the header is checked against the implementation it interoperates with
      # rather than against its own decoder.
      #
      # The assertion is on the capture rather than on a round trip, because
      # what is being tested is whether the kernel accepts this tree's header
      # and takes it off. Where the inner packet goes afterward is the test
      # topology's business: End.DT6 looks the decapsulated destination up in
      # the table it is given, and a local address of the gateway's is not in
      # main.
      segmentRouted = ''
        import json

        gateway.wait_for_unit("systemd-networkd-wait-online.service")
        gateway.wait_for_unit("strongswan-swanctl.service")
        gateway.wait_for_unit("bird.service")
        client.wait_for_unit("ranet3.service")

        # The unsteered path first, so a failure below is the segment rather
        # than the mesh.
        client.wait_until_succeeds("ping -c 1 ${gatewayTunnel}", timeout=timeout)

        # The local SID is the kernel's own behavior, added here rather than
        # in the module so a rejection is a failing command. The device is the
        # one the packet arrives on: an input lookup landing on a route out of
        # lo answers ICMP unreachable, which reads exactly like a segment the
        # kernel never had.
        gateway.succeed(
            "ip -6 route replace ${gatewaySID}/128 encap seg6local action End.DT6 table 254 dev swan0"
        )
        print(gateway.succeed("ip -6 route show ${gatewaySID}/128"))

        def steer_and_capture(machine, name):
            """Three steered packets, and what the gateway made of them."""
            machine.succeed(f"rm -f /tmp/{name}.pcap")
            machine.execute(f"tcpdump -ni swan0 -w /tmp/{name}.pcap ip6 >/dev/null 2>&1 &")
            machine.wait_until_succeeds("pgrep -x tcpdump", timeout=timeout)
            client.execute("ping -c 3 -i 0.3 -W 1 -I ${clientTunnel} ${gatewayBehind}")
            machine.succeed("pkill -x tcpdump")
            machine.wait_until_fails("pgrep -x tcpdump", timeout=timeout)
            return machine.succeed(f"tcpdump -nr /tmp/{name}.pcap 'not port 6696'")

        def bare_inner(capture):
            """The inner packet on its own, with no routing header left.

            The encapsulated line carries the inner addresses too, since
            tcpdump prints what is inside, so the routing header is the only
            thing telling the two apart. The ICMP error the gateway sends when it has no
            segment runs the other way and matches neither.
            """
            return [
                line for line in capture.splitlines()
                if "${clientTunnel} > ${gatewayBehind}:" in line and "RT6" not in line
            ]

        carried = steer_and_capture(gateway, "carried")
        print(carried)
        # The encapsulated packet arrived, addressed to the segment.
        assert "${gatewaySID}" in carried, "the steered packet never reached the gateway"
        # And the kernel took the header off.
        assert bare_inner(carried), f"the kernel did not decapsulate this tree's header:\n{carried}"

        status = json.loads(client.succeed("ranet3 status --json"))
        print(json.dumps(status["segment_counters"], indent=2))
        assert status["segment_counters"]["steered"] > 0, "nothing was steered"
        assert status["segment_counters"]["unsteered"] == 0, "a packet could not be steered"
        assert status["steering"], "the steering policy is not reported"

        # Taking the segment away leaves the encapsulated packet arriving and
        # nothing coming out of it, which is the proof that the line above was
        # the kernel acting on the header rather than anything else.
        gateway.succeed("ip -6 route del ${gatewaySID}/128")
        refused = steer_and_capture(gateway, "refused")
        print(refused)
        assert "${gatewaySID}" in refused, "the steered packet stopped arriving for another reason"
        assert not bare_inner(refused), f"something still decapsulated the header:\n{refused}"

        # The other direction: the gateway's kernel builds the header and this
        # tree acts on it. Nothing announces the address behind the client, so
        # the gateway reaches it through the segment or not at all, and the
        # client's own counter says which of the two carried the packet.
        gateway.wait_until_succeeds("ip -6 route get ${clientSID}", timeout=timeout)
        gateway.succeed(
            "ip -6 route replace ${clientBehind}/128 encap seg6 mode encap segs ${clientSID} dev swan0"
        )
        print(gateway.succeed("ip -6 route show ${clientBehind}/128"))

        before = json.loads(client.succeed("ranet3 status --json"))["segment_counters"]
        gateway.wait_until_succeeds(
            "ping -c 1 -W 2 -I ${gatewayTunnel} ${clientBehind}", timeout=timeout
        )
        gateway.succeed("ping -c 3 -i 0.3 -W 2 -I ${gatewayTunnel} ${clientBehind}")
        status = json.loads(client.succeed("ranet3 status --json"))
        after = status["segment_counters"]
        print(json.dumps(after, indent=2))
        assert after["delivered"] > before["delivered"], (
            f"the ping arrived without this tree's exit delivering it: {before} then {after}"
        )
        assert after["dropped"] == before["dropped"], f"a segment was refused: {after}"
        assert status["segments"], "the local segment is not reported"
      '';

      # The client is the exit node and the gateway is the peer using it. What
      # is measured is a third machine's view: it answers in prefixes only the
      # exit can reach, and it sees the exit's own address rather than the mesh
      # address the packet started with. The rules go away at shutdown, which
      # is the ownership claim and not a guess.
      exitNode = ''
        import json

        try:
            gateway.wait_for_unit("systemd-networkd-wait-online.service")
            gateway.wait_for_unit("strongswan-swanctl.service")
            gateway.wait_for_unit("bird.service")
            # The addresses rather than the unit: networkd's wait-online is
            # WantedBy network-online.target, a passive target nothing on this
            # node pulls in, so it never becomes active here however configured
            # the link is. This arm needs the far side answering instead, so it
            # waits for the addresses themselves.
            for address in ["${behindV4}", "${behindV6}"]:
                behind.wait_until_succeeds(f"ip addr show dev eth1 | grep -qF {address}", timeout=timeout)
            client.wait_for_unit("ranet3.service")

            # The mesh first, so a failure below is the exit rather than the tunnel.
            client.wait_until_succeeds("ping -c 1 ${gatewayTunnel}", timeout=timeout)

            # Only this tree's own tables exist, and only in the families it was
            # asked for. Anything else here would be a rule written outside what
            # the ownership rules allow.
            client.wait_until_succeeds("nft list table ip ranet3", timeout=timeout)
            tables = sorted(t for t in client.succeed("nft list tables").splitlines() if t.strip())
            assert tables == ["table ip ranet3", "table ip6 ranet3"], tables
            ruleset = client.succeed("nft list ruleset")
            print(ruleset)
            for want in ["chain postrouting", "type nat hook postrouting", "masquerade",
                         f'iifname "{client_device}"', f'oifname != "{client_device}"']:
                assert want in ruleset, f"the ruleset does not carry {want}:\n{ruleset}"

            # The announcement reaches a peer that has never heard of this
            # capability, through ordinary babel and the BIRD on the far side.
            gateway.wait_until_succeeds("ip -4 route show ${exitNetV4} | grep -q swan0", timeout=timeout)
            gateway.wait_until_succeeds("ip -6 route show ${exitNetV6} | grep -q swan0", timeout=timeout)

            def carried(name, filter, source, destination):
                """What the far side saw of three pings through the exit.

                tcpdump counts the three it wants and exits on its own, rather
                than being killed once the pings are done: a kill races the
                write, and measured here it lost, reporting six packets past
                the filter and none written. The filter is the echo request
                alone, so neighbor discovery cannot make up the count.
                """
                behind.succeed(f"rm -f /tmp/{name}.pcap /tmp/{name}.log")
                behind.execute(
                    f"tcpdump -Uni eth1 -c 3 -w /tmp/{name}.pcap '{filter}' >/tmp/{name}.log 2>&1 &")
                behind.wait_until_succeeds(f"grep -q 'listening on' /tmp/{name}.log", timeout=timeout)
                print(gateway.succeed(f"ping -c 3 -i 0.3 -W 2 -I {source} {destination}"))
                behind.wait_until_fails("pgrep -x tcpdump", timeout=timeout)
                print(behind.succeed(f"cat /tmp/{name}.log"))
                return behind.succeed(f"tcpdump -nr /tmp/{name}.pcap")

            for name, filter, source, destination, translated in [
                ("v4", "icmp[icmptype] = icmp-echo", "${gatewayTunnelV4}", "${behindV4}", "${exitV4}"),
                ("v6", "icmp6 and ip6[40] = 128", "${gatewayTunnel}", "${behindV6}", "${exitV6}"),
            ]:
                # The round trip first: behind has no route to the tunnel
                # prefixes, so a reply that comes back at all is one the exit
                # translated and then put back.
                gateway.wait_until_succeeds(
                    f"ping -c 1 -W 2 -I {source} {destination}", timeout=timeout)
                capture = carried(name, filter, source, destination)
                print(capture)
                assert f"{translated} > {destination}" in capture, (
                    f"the far side did not see the exit's own address:\n{capture}")
                assert source not in capture, (
                    f"the mesh address reached the far side untranslated:\n{capture}")

            status = json.loads(client.succeed("ranet3 status --json"))["egress"]
            print(json.dumps(status, indent=2))
            assert status["enabled"], status
            assert status["installed"] == 2, status
            assert sorted(status["announced"]) == sorted(status["advertise"]), status
            assert status["flows"] > 0, status
            assert not status.get("err"), status
            metrics = client.succeed("curl -sf http://127.0.0.1:9669/metrics")
            for want in [
                'ranet3_egress_prefixes{state="advertised"} 2',
                'ranet3_egress_prefixes{state="announced"} 2',
                "ranet3_egress_pass_failed 0",
            ]:
                assert want in metrics, f"the scrape does not carry {want}:\n{metrics}"

            # A rule is recognized on every sweep rather than rewritten, which
            # is the proof that the spelling the host hands back is the one this
            # node wrote. Many sweeps have run by now.
            installs = client.succeed(
                "journalctl -u ranet3.service --no-pager | grep -c 'egress rules installed'").strip()
            assert installs == "1", f"the ruleset was rewritten {installs} times, so a pass does not recognize its own rules"

            # An exit that cannot forward must stop advertising rather than
            # attract traffic it would drop, and babel gives a peer no other way
            # to learn that. The IPv6 half keeps working, because a host can
            # forward one family and not the other.
            client.succeed("sysctl -w net.ipv4.ip_forward=0")
            client.wait_until_succeeds(
                "ranet3 status --json | jq -e '.egress.announced == [\"${exitNetV6}\"]'", timeout=timeout)
            gateway.wait_until_fails("ip -4 route show ${exitNetV4} | grep -q swan0", timeout=timeout)
            client.succeed("sysctl -w net.ipv4.ip_forward=1")
            client.wait_until_succeeds(
                "ranet3 status --json | jq -e '.egress.announced | length == 2'", timeout=timeout)
            gateway.wait_until_succeeds("ip -4 route show ${exitNetV4} | grep -q swan0", timeout=timeout)

            # Shutdown takes the tables with it. A rule left behind would go on
            # translating for a process that is no longer running.
            client.succeed("systemctl stop ranet3.service")
            assert client.succeed("systemctl show -p Result --value ranet3.service").strip() == "success"
            left = client.succeed("nft list tables").strip()
            assert left == "", f"shutdown left tables behind: {left}"

            # And a restart installs them again, so the withdrawal above was a
            # shutdown rather than a failure to write.
            client.succeed("systemctl start ranet3.service")
            client.wait_until_succeeds("nft list table ip ranet3", timeout=timeout)
        finally:
            print(client.execute("nft list ruleset")[1])
            print(client.execute("ip -4 rule show")[1])
            print(client.execute(f"ip -4 route show table {kernel_table}")[1])
            print(gateway.execute("birdc show route")[1])
      '';

      # The gateway is a kernel leaf: its own seg6 encap steers a ping into the
      # client's egress segment, and the far side sees the exit's address. The
      # IPv6 arm only, since the root test in internal/client carries IPv4
      # with synthetic frames. The SID's /128 is the exit's liveness on the
      # gateway's own table.
      egressSegmentScript = ''
        import json

        def status():
            return json.loads(client.succeed("ranet3 status --json"))

        def counters():
            return status()["segment_counters"]

        try:
            gateway.wait_for_unit("systemd-networkd-wait-online.service")
            gateway.wait_for_unit("strongswan-swanctl.service")
            gateway.wait_for_unit("bird.service")
            behind.wait_until_succeeds("ip addr show dev eth1 | grep -qF ${behindV6}", timeout=timeout)
            client.wait_for_unit("ranet3.service")
            client.wait_until_succeeds("ping -c 1 ${gatewayTunnel}", timeout=timeout)

            # the device exists with no address, and the SID reaches the gateway once both families are ready
            client.wait_until_succeeds(
                "ranet3 status --json | jq -e '.egress.ready == [\"ipv4\", \"ipv6\"]'", timeout=timeout)
            device = client.succeed("ip -d addr show dev ${clientEgressDevice}")
            print(device)
            assert "inet" not in device, f"the egress device carries an address:\n{device}"
            gateway.wait_until_succeeds("ip -6 route show ${clientEgressSID} | grep -q swan0", timeout=timeout)
            print(client.execute("journalctl -u ranet3.service --no-pager | grep -F 'egress device'")[1])

            # the kernel builds the header from the address the tunnel source names, which the allow list covers
            gateway.succeed("ip sr tunsrc set ${gatewayTunnel}")
            gateway.succeed(
                "ip -6 route replace ${behindV6}/128 encap seg6 mode encap segs ${clientEgressSID} dev swan0")
            print(gateway.succeed("ip -6 route show ${behindV6}/128"))

            # behind has no route to the tunnel prefixes, so a reply is a source the exit translated and put back
            before = counters()
            gateway.wait_until_succeeds("ping -c 1 -W 2 -I ${gatewayTunnel} ${behindV6}", timeout=timeout)
            behind.succeed("rm -f /tmp/segment.pcap /tmp/segment.log")
            behind.execute("tcpdump -Uni eth1 -c 3 -w /tmp/segment.pcap 'icmp6 and ip6[40] = 128' >/tmp/segment.log 2>&1 &")
            behind.wait_until_succeeds("grep -q 'listening on' /tmp/segment.log", timeout=timeout)
            print(gateway.succeed("ping -c 3 -i 0.3 -W 2 -I ${gatewayTunnel} ${behindV6}"))
            behind.wait_until_fails("pgrep -x tcpdump", timeout=timeout)
            capture = behind.succeed("tcpdump -nr /tmp/segment.pcap")
            print(capture)
            assert "${exitV6} > ${behindV6}" in capture, f"the far side did not see the exit's own address:\n{capture}"
            assert "${gatewayTunnel}" not in capture, f"the gateway's address reached the far side untranslated:\n{capture}"
            after = counters()
            print(json.dumps(after, indent=2))
            assert after["egressed"] >= before["egressed"] + 4, f"the steered pings were not egressed: {before} then {after}"
            assert after["refused"] == before["refused"], f"an allowed source was refused: {after}"

            # an inner source outside the allow list is refused and answered with nothing
            before = counters()
            gateway.fail("ping -c 3 -i 0.3 -W 1 -I ${gatewayOutside} ${behindV6}")
            after = counters()
            assert after["refused"] >= before["refused"] + 3, f"a source outside the list was not refused: {before} then {after}"
            assert after["egressed"] == before["egressed"], f"a source outside the list was egressed: {after}"

            metrics = client.succeed("curl -sf http://127.0.0.1:9669/metrics")
            for want in ['ranet3_egress_device_ready{family="ipv4"} 1', 'ranet3_egress_device_ready{family="ipv6"} 1', "ranet3_border_ready 1"]:
                assert want in metrics, f"the scrape does not carry {want}:\n{metrics}"

            # behind is on the client's link and outside the mesh, so a mesh source, a type 4 routing
            # header and the client's own SID arriving from it are dropped at the client's border:
            # each is counted, none reaches the gateway, and nothing is egressed or refused
            behind.succeed(
                "ip -6 addr add ${borderForged6}/128 dev eth1 nodad",
                "ip addr add ${borderForged4}/32 dev eth1",
                "ip -6 route add fd00:99::/64 via ${exitV6}",
                "ip route add 10.99.0.0/24 via ${exitV4}",
                "ip -6 route add ${clientEgressSID}/128 via ${exitV6}",
                # the outer header leaves from an address outside the overlay, so the header alone drops it
                "ip sr tunsrc set ${behindV6}",
            )
            before = counters()
            gateway.succeed("rm -f /tmp/border.pcap /tmp/border.log")
            gateway.execute(
                "tcpdump -Uni swan0 -Q in -w /tmp/border.pcap"
                " 'src ${borderForged4} or src ${borderForged6} or src ${behindV6} or src ${behindV4}' >/tmp/border.log 2>&1 &")
            gateway.wait_until_succeeds("grep -q 'listening on' /tmp/border.log", timeout=timeout)
            behind.fail("ping -c 3 -i 0.3 -W 1 -I ${borderForged6} ${gatewayTunnel}")
            behind.fail("ping -c 3 -i 0.3 -W 1 -I ${borderForged4} ${gatewayTunnelV4}")
            behind.fail("ping -c 3 -i 0.3 -W 1 -I ${behindV6} ${clientEgressSID}")
            # the segment lies outside the encap route, which would otherwise take its own outer header again
            behind.succeed("ip -6 route add ${gatewayTunnel}/128 encap seg6 mode encap segs ${borderSegment} via ${exitV6} dev eth1")
            behind.fail("ping -c 3 -i 0.3 -W 1 -I ${behindV6} ${gatewayTunnel}")
            # the counters reach the scrape at the border's next pass, one sweep at most
            for reason, family in [("overlay_source", "ipv6"), ("overlay_source", "ipv4"), ("sid_destination", "ipv6"), ("routing_header", "ipv6")]:
                series = 'ranet3_border_dropped_packets_total{reason="' + reason + '",family="' + family + '"}'
                client.wait_until_succeeds(
                    "curl -sf http://127.0.0.1:9669/metrics | awk -v want='" + series + "' '$1 == want && $2 >= 3 { found = 1 } END { exit !found }'",
                    timeout=dt.timedelta(seconds=90))
            gateway.succeed("pkill -x tcpdump")
            gateway.wait_until_fails("pgrep -x tcpdump", timeout=timeout)
            capture = gateway.succeed("tcpdump -nr /tmp/border.pcap 2>/dev/null").strip()
            assert capture == "", f"a packet the border drops reached the gateway:\n{capture}"
            after = counters()
            assert after["egressed"] == before["egressed"] and after["refused"] == before["refused"], f"a dropped packet reached the egress segment: {before} then {after}"
            print(client.succeed("ranet3 debug rules"))
            rules = json.loads(client.succeed("ranet3 debug rules --json"))
            assert rules["border"]["ready"], f"the border reads not ready: {rules['border']}"
            assert status()["border"]["ready"], "the status reports the border not ready"
            behind.succeed(
                "ip -6 route del ${gatewayTunnel}/128",
                "ip -6 route del ${clientEgressSID}/128",
                "ip route del 10.99.0.0/24",
                "ip -6 route del fd00:99::/64",
                "ip addr del ${borderForged4}/32 dev eth1",
                "ip -6 addr del ${borderForged6}/128 dev eth1",
                "ip sr tunsrc set ::",
            )

            # a host forwarding one family serves it, so IPv6 forwarding off leaves the SID announced
            client.succeed("sysctl -w net.ipv6.conf.all.forwarding=0")
            client.wait_until_succeeds("ranet3 status --json | jq -e '.egress.ready == [\"ipv4\"]'", timeout=timeout)
            gateway.succeed("ip -6 route show ${clientEgressSID} | grep -q swan0")
            client.succeed("sysctl -w net.ipv6.conf.all.forwarding=1")
            client.wait_until_succeeds("ranet3 status --json | jq -e '.egress.ready | length == 2'", timeout=timeout)

            # a family the host forwards and the device cannot pass withdraws the SID, and putting it right brings it back
            client.succeed("sysctl -w net.ipv4.conf.all.rp_filter=2")
            client.wait_until_succeeds("ranet3 status --json | jq -e '.egress.ready == [\"ipv6\"]'", timeout=timeout)
            print(status()["egress"])
            gateway.wait_until_fails("ip -6 route show ${clientEgressSID} | grep -q swan0", timeout=timeout)
            client.succeed("sysctl -w net.ipv4.conf.all.rp_filter=0")
            gateway.wait_until_succeeds("ip -6 route show ${clientEgressSID} | grep -q swan0", timeout=timeout)
            gateway.wait_until_succeeds("ping -c 1 -W 2 -I ${gatewayTunnel} ${behindV6}", timeout=timeout)

            # shutdown takes the device and the tables with it
            client.succeed("systemctl stop ranet3.service")
            assert client.succeed("systemctl show -p Result --value ranet3.service").strip() == "success"
            client.fail("ip link show ${clientEgressDevice}")
            left = client.succeed("nft list tables").strip()
            assert left == "", f"shutdown left tables behind: {left}"
            client.succeed("journalctl -u ranet3.service --no-pager | grep -F 'egress device withdrawn'")
        finally:
            print(client.execute("ranet3 status")[1])
            print(client.execute("nft list ruleset")[1])
            print(client.execute("ip -6 rule show; ip -4 rule show")[1])
            print(gateway.execute("birdc show route")[1])
      '';

      # strongSwan answers, ranet3 dials: upstream's original exchange.
      initiator = ''
        try:
            gateway.wait_for_unit("systemd-networkd-wait-online.service")
            gateway.wait_for_unit("strongswan-swanctl.service")
            gateway.wait_for_unit("bird.service")
            gateway.wait_for_unit("iperf3.service")
            client.wait_for_unit("ranet3.service")

            client.wait_until_succeeds("ping -c 1 ${gatewayTunnel}", timeout=timeout)
            client.wait_until_succeeds("ping -c 1 ${gatewayTunnelV4}", timeout=timeout)
            if fqdn_enabled:
                named_by_fqdn()
                gateway.succeed(
                    "journalctl -u strongswan-swanctl.service --no-pager | grep -F 'parsed IKE_AUTH request 1 [ IDi IDr '"
                )
                gateway.succeed(
                    "journalctl -u strongswan-swanctl.service --no-pager | grep -F 'looking for peer configs matching'"
                    " | grep -F '[${gatewayFQDN}]...'"
                )
            peer_rekey = journal_after(gateway, "strongswan-swanctl.service")
            print(gateway.succeed("swanctl --rekey --child default"))
            gateway.wait_until_succeeds(f"{peer_rekey} | grep -E 'parsed CREATE_CHILD_SA response.*SA No KE TSi TSr'", timeout=timeout)
            client.wait_until_succeeds("ping -c 1 ${gatewayTunnel}", timeout=timeout)
            peer_rekey = journal_after(gateway, "strongswan-swanctl.service")
            print(gateway.succeed("swanctl --rekey --ike ranet"))
            gateway.wait_until_succeeds(f"{peer_rekey} | grep -E 'IKE_SA ranet.* rekeyed between'", timeout=timeout)
            local_rekeys = journal_after(client, "ranet3.service")
            client.wait_until_succeeds("ping -c 1 ${gatewayTunnel}", timeout=timeout)

            profile = ${if profile then "True" else "False"}
            if profile:
                # NixOS tests force acpi_pm for deterministic timekeeping. Its
                # virtual I/O reads dominate CPU profiles, so use the KVM clock
                # in this performance-only variant on both sides of the tunnel.
                for machine in [client, gateway]:
                    machine.succeed("echo kvm-clock > /sys/devices/system/clocksource/clocksource0/current_clocksource")
                    assert machine.succeed("cat /sys/devices/system/clocksource/clocksource0/current_clocksource").strip() == "kvm-clock"
            duration = 25 if profile else 5
            for direction, flags in [("outbound", ""), ("inbound", "--reverse"), ("bidir", "--bidir")]:
                if profile:
                    client.succeed(f"systemd-run --unit=ranet-{direction}-profile --collect curl --silent --show-error 'http://127.0.0.1:6060/debug/pprof/profile?seconds=20' --output /tmp/{direction}.pprof")
                    pid = client.succeed("systemctl show -p MainPID --value ranet3.service").strip()
                    client.succeed(f"systemd-run --unit=ranet-{direction}-kernel-profile --collect perf record -e cpu-clock:k -F 199 -g -p {pid} -o /tmp/{direction}.perf -- sleep 20")
                # iperf3's server closes and reopens its listening socket between
                # tests, so a client that connects in that window is refused.
                # Retrying keeps a harness race out of the result, while a peer
                # that is genuinely unreachable still fails once they run out.
                print(client.wait_until_succeeds(
                    f"iperf3 --client ${gatewayTunnel} --parallel 8 --time {duration} {flags}",
                    timeout=iperf_timeout,
                ))
                if profile:
                    client.wait_until_succeeds(f"test -s /tmp/{direction}.pprof")
                    print(client.succeed(f"pprof -top -nodecount=50 /tmp/{direction}.pprof"))
                    print(client.succeed(f"perf report --stdio --no-children --percent-limit 1 -g none -i /tmp/{direction}.perf"))
                    client.copy_from_machine(f"/tmp/{direction}.pprof")
                    client.copy_from_machine(f"/tmp/{direction}.perf")

            # ranet3 attached to the tun networkd made
            # and set its gso_max_segs to the read batch of 128 packets
            segments = client.succeed(f"ip -d link show {client_device}").split("gso_max_segs ")[1].split()[0]
            assert segments == "128", f"{client_device} holds gso_max_segs {segments}, want the read batch of 128"

            # at this segment size one gso frame can carry more packets than a tun read holds
            # which may cost the tail of that frame, and neither refuses a frame nor loses the device
            tun_lines = journal_after(client, "ranet3.service")
            print(client.wait_until_succeeds(
                "iperf3 --client ${gatewayTunnel} --parallel 8 --time 5 --set-mss 400",
                timeout=iperf_timeout,
            ))
            client.fail(f"{tun_lines} | grep -F -e 'netstack tun failed' -e 'netstack tun refused a frame'")
            client.wait_until_succeeds("ping -c 1 ${gatewayTunnel}", timeout=timeout)
            # the kernel splits such a frame before the tun
            # and no read came back cut short or refused
            metrics = client.succeed("curl -sf http://127.0.0.1:9669/metrics")
            assert "ranet3_tun_reads_truncated_total 0" in metrics.splitlines(), metrics
            assert "ranet3_tun_frames_refused_total 0" in metrics.splitlines(), metrics

            if not profile:
                # a rekey lost under load still replaces its SA before the lifetime: the gateway drops the client's IKE for 5 s while iperf runs
                # IKE and ESP share UDP 13000, and the four zero octets after the UDP header, the non-ESP marker, pick out the IKE, so ESP passes
                # the drop outlasts a rekey's first send, so a rekey starting in it lives on its resends, and only the margin decides whether the SA lives that long
                lost = journal_after(client, "ranet3.service")
                client.succeed("systemd-run --unit=iperf-under-ike-loss iperf3 --client ${gatewayTunnel} --parallel 8 --time 10")
                gateway.succeed(
                    "nft add table inet ike_loss",
                    "nft add chain inet ike_loss input '{ type filter hook input priority 0; }'",
                    "nft add rule inet ike_loss input udp dport 13000 @th,64,32 0 counter drop",
                    "sleep 5",
                )
                dropped = gateway.succeed("nft list table inet ike_loss")
                gateway.succeed("nft delete table inet ike_loss")
                print(dropped)
                # the drop outlasts the time between Child SA rekeys, so it took at least one of their sends
                assert "counter packets 0 " not in dropped, dropped
                client.wait_until_fails("systemctl is-active iperf-under-ike-loss.service", timeout=iperf_timeout)
                client.wait_until_succeeds(f"{lost} | grep -F 'ike rekey completed' | grep -F 'sa=\"Child SA\"'", timeout=timeout)
                client.fail(f"{lost} | grep -F 'ike stopping ESP on a Child SA past its lifetime'")
                client.wait_until_succeeds("ping -c 1 ${gatewayTunnel}", timeout=timeout)

                # Verify both new IKE keys and subsequent ESP keys are usable.
                # swanctl's exit status alone does not prove a rekey succeeded.
                for sa in ["Child SA", "IKE SA"]:
                    client.wait_until_succeeds(f"{local_rekeys} | grep -F 'ike rekey completed' | grep -F 'sa=\"{sa}\"'", timeout=timeout)
                client.wait_until_succeeds("ping -c 1 ${gatewayTunnel}", timeout=timeout)

            # A graceful BIRD stop retracts routes, then fresh announcements restore
            # them without reconnecting IKE. Check the client publication as well as IP.
            withdrawal = journal_after(client, "ranet3.service")
            gateway.succeed("systemctl stop bird.service")
            client.wait_until_succeeds(f"{withdrawal} | grep -F 'babel route retracted'", timeout=timeout)
            gateway.succeed("systemctl start bird.service")
            client.wait_until_succeeds("ping -c 1 ${gatewayTunnel}", timeout=timeout)
            client.wait_until_succeeds("ping -c 1 ${gatewayTunnelV4}", timeout=timeout)
            if kernel_enabled:
                # What replaces kbabel4 and kbabel6 on a fleet node: a route babel
                # learned has to be in the kernel table the policy rules look up,
                # carrying this reconciler's protocol and the configured prefsrc.
                client.wait_until_succeeds(f"ip -4 route show table {kernel_table} | grep -q '10.99.0.0/24'", timeout=timeout)
                client.wait_until_succeeds(f"ip -6 route show table {kernel_table} | grep -q 'fd00:99::/64'", timeout=timeout)
                v4 = client.succeed(f"ip -4 route show table {kernel_table}")
                v6 = client.succeed(f"ip -6 route show table {kernel_table}")
                print(v4)
                print(v6)
                assert f"proto {kernel_protocol}" in v4, v4
                assert f"src {client_tunnel_v4}" in v4, v4
                assert f"dev {client_device}" in v4, v4
                # The main table is not this reconciler's to write.
                leaked = client.succeed(f"ip -4 route show proto {kernel_protocol}")
                assert "10.99.0.0/24" not in leaked, leaked
            # The endpoint that replaces prometheus-bird-exporter has to report a
            # live neighbor and a selected route, not just answer.
            client.wait_until_succeeds("curl -sf http://127.0.0.1:9669/metrics | grep -q '^ranet3_babel_neighbor_up{.*} 1$'", timeout=timeout)
            metrics = client.succeed("curl -sf http://127.0.0.1:9669/metrics")
            print(metrics)
            assert "ranet3_sessions 1" in metrics, metrics
            assert "ranet3_babel_routes_originated 2" in metrics, metrics
            selected = [line for line in metrics.splitlines() if line.startswith("ranet3_babel_routes_selected ")]
            assert selected and int(selected[0].split()[1]) > 0, metrics

            assert client.succeed("journalctl -u ranet3.service --no-pager | grep -c ': connected (SPI'").strip() == "1"
            client.fail("journalctl -u ranet3.service --no-pager | grep -F 'no matching inbound ESP SA'")
            # an SA that reached its lifetime before a rekey replaced it drops what the peer still sends on it, and this names that cause
            client.fail("journalctl -u ranet3.service --no-pager | grep -F 'ike stopping ESP on a Child SA past its lifetime'")
            gateway.fail("journalctl -u strongswan-swanctl.service --no-pager | grep -E 'integrity check failed|no CHILD_SA built'")

            # Closing an idle TUN read must stop promptly without SIGKILL.
            client.succeed("systemctl stop ranet3.service")
            assert client.succeed("systemctl show -p Result --value ranet3.service").strip() == "success"
            if kernel_enabled:
                # Shutdown withdraws what it installed rather than leaving it behind.
                assert client.succeed(f"ip -4 route show table {kernel_table}").strip() == "", "ipv4 routes survived shutdown"
                assert client.succeed(f"ip -6 route show table {kernel_table}").strip() == "", "ipv6 routes survived shutdown"
            client.succeed("systemctl start ranet3.service")
            client.wait_until_succeeds("ping -c 1 ${gatewayTunnel}", timeout=timeout)
        finally:
            for command in ["swanctl --list-sas", "birdc show babel neighbors", "birdc show babel routes"]:
                print(gateway.execute(command)[1])
      '';

      # strongSwan dials, ranet3 answers.
      responderScript = ''
        try:
            gateway.wait_for_unit("systemd-networkd-wait-online.service")
            gateway.wait_for_unit("strongswan-swanctl.service")
            gateway.wait_for_unit("bird.service")
            client.wait_for_unit("ranet3.service")

            # ranet3 has no peers configured here, so it never dials. A tunnel
            # exists only if it answered strongSwan's IKE_SA_INIT.
            client.fail("journalctl -u ranet3.service --no-pager | grep -F ': dialing '")
            gateway.succeed("swanctl --initiate --child default")
            client.wait_until_succeeds("journalctl -u ranet3.service --no-pager | grep -F ': connected (SPI'", timeout=timeout)
            client.wait_until_succeeds("ping -c 1 ${gatewayTunnel}", timeout=timeout)
            client.wait_until_succeeds("ping -c 1 ${gatewayTunnelV4}", timeout=timeout)
            if fqdn_enabled:
                named_by_fqdn()

            # The peer drives both rekeys. An answered session has to service them
            # exactly as a dialed one does, from the opposite role.
            peer_rekey = journal_after(gateway, "strongswan-swanctl.service")
            print(gateway.succeed("swanctl --rekey --child default"))
            gateway.wait_until_succeeds(f"{peer_rekey} | grep -E 'parsed CREATE_CHILD_SA response.*SA No KE TSi TSr'", timeout=timeout)
            client.wait_until_succeeds("ping -c 1 ${gatewayTunnel}", timeout=timeout)
            peer_rekey = journal_after(gateway, "strongswan-swanctl.service")
            print(gateway.succeed("swanctl --rekey --ike ranet"))
            gateway.wait_until_succeeds(f"{peer_rekey} | grep -E 'IKE_SA ranet.* rekeyed between'", timeout=timeout)
            client.wait_until_succeeds("ping -c 1 ${gatewayTunnel}", timeout=timeout)

            client.fail("journalctl -u ranet3.service --no-pager | grep -F 'no matching inbound ESP SA'")
            # an SA that reached its lifetime before a rekey replaced it drops what the peer still sends on it, and this names that cause
            client.fail("journalctl -u ranet3.service --no-pager | grep -F 'ike stopping ESP on a Child SA past its lifetime'")
            gateway.fail("journalctl -u strongswan-swanctl.service --no-pager | grep -E 'integrity check failed|no CHILD_SA built'")

            # Losing the answered SA has to be recoverable without ranet3 ever
            # dialing, so the responder accepts a second SA for a peer it already
            # knew. Drive the peer rather than waiting out its DPD timers: what is
            # under test is the responder, not how long charon takes to notice.
            client.succeed("systemctl restart ranet3.service")
            gateway.execute("swanctl --terminate --ike ranet")
            gateway.wait_until_succeeds("swanctl --initiate --child default", timeout=timeout)
            client.wait_until_succeeds("ping -c 1 ${gatewayTunnel}", timeout=timeout)
            client.fail("journalctl -u ranet3.service --no-pager | grep -F ': dialing '")
        finally:
            for command in [
                "swanctl --list-sas",
                "birdc show babel neighbors",
                "birdc show babel routes",
                "ip xfrm state",
                "ip xfrm policy",
                "grep -v ' 0$' /proc/net/xfrm_stat",
                "ip -s link show swan0",
            ]:
                print(gateway.execute(command)[1])
            print(client.execute(f"ip -s link show {client_device}")[1])
      '';

      # with responder strongSwan dials and ranet3 answers
      # without it ranet3 dials
      # the two ends share aes128gcm, sha256 and p256 alone
      # and each reports that suite as the one its SAs run
      suitesMeet = ''
        import json

        try:
            gateway.wait_for_unit("systemd-networkd-wait-online.service")
            gateway.wait_for_unit("strongswan-swanctl.service")
            gateway.wait_for_unit("bird.service")
            client.wait_for_unit("ranet3.service")

            if ${if responder then "True" else "False"}:
                gateway.succeed("swanctl --initiate --child default")
            client.wait_until_succeeds("journalctl -u ranet3.service --no-pager | grep -F ': connected (SPI'", timeout=timeout)
            client.wait_until_succeeds("ping -c 1 ${gatewayTunnel}", timeout=timeout)

            def both_ends_run_the_shared_suite():
                sessions = json.loads(client.succeed("ranet3 sessions --json"))
                print(json.dumps(sessions, indent=2))
                running = [(s.get("ike_cipher"), s.get("ike_prf"), s.get("ike_kex"), s.get("esp_cipher")) for s in sessions]
                assert running == [("aes128gcm", "sha256", "p256", "aes128gcm")], f"ranet3 runs {running}"
                sas = gateway.succeed("swanctl --list-sas")
                print(sas)
                for want in ["AES_GCM_16-128/PRF_HMAC_SHA2_256/ECP_256", "ESP:AES_GCM_16-128"]:
                    assert want in sas, f"strongSwan's SAs do not run {want}"

            both_ends_run_the_shared_suite()

            # strongSwan's rekeys offer its whole proposals
            # and ranet3 answers them within its lists
            for sa, done in [("--child default", "parsed CREATE_CHILD_SA response.*SA No TSi TSr"), ("--ike ranet", "IKE_SA ranet.* rekeyed between")]:
                peer_rekey = journal_after(gateway, "strongswan-swanctl.service")
                print(gateway.succeed(f"swanctl --rekey {sa}"))
                gateway.wait_until_succeeds(f"{peer_rekey} | grep -E '{done}'", timeout=timeout)
                client.wait_until_succeeds("ping -c 1 ${gatewayTunnel}", timeout=timeout)

            # ranet3's own rekeys keep the cipher and the PRF
            # and offer its lists for the rest
            for sa, suite in [("child", "aes128gcm"), ("ike", "aes128gcm/sha256/p256")]:
                print(client.succeed(f"ranet3 debug wait ike.rekey.completed --attr sa={sa} --attr suite={suite} --timeout 60s"))
            client.wait_until_succeeds("ping -c 1 ${gatewayTunnel}", timeout=timeout)
            both_ends_run_the_shared_suite()

            client.fail("journalctl -u ranet3.service --no-pager | grep -F 'no matching inbound ESP SA'")
            # an SA that reached its lifetime before a rekey replaced it drops what the peer still sends on it, and this names that cause
            client.fail("journalctl -u ranet3.service --no-pager | grep -F 'ike stopping ESP on a Child SA past its lifetime'")
            gateway.fail("journalctl -u strongswan-swanctl.service --no-pager | grep -E 'integrity check failed|no CHILD_SA built'")
        finally:
            print(gateway.execute("swanctl --list-sas")[1])
            print(client.execute("ranet3 sessions")[1])
      '';

      # the two ends share no IKE cipher
      # so the end answering refuses with NO_PROPOSAL_CHOSEN whichever end dials
      suitesApart = ''
        # ranet3 waits out its retransmissions before it gives up on a refusal no key authenticates
        refusal_timeout = dt.timedelta(seconds=120)
        swan_log = "journalctl -u strongswan-swanctl.service --no-pager"

        try:
            gateway.wait_for_unit("systemd-networkd-wait-online.service")
            gateway.wait_for_unit("strongswan-swanctl.service")
            client.wait_for_unit("ranet3.service")

            if ${if responder then "True" else "False"}:
                gateway.execute("swanctl --initiate --child default --timeout 10")
                gateway.wait_until_succeeds(f"{swan_log} | grep -F 'parsed IKE_SA_INIT response 0 [ N(NO_PROP) ]'", timeout=timeout)
                client.succeed("ranet3 debug wait ike.handshake.failed --attr 'err=ike: no acceptable IKE SA proposal' --past 10m --timeout 30s")
            else:
                gateway.wait_until_succeeds(f"{swan_log} | grep -F 'generating IKE_SA_INIT response 0 [ N(NO_PROP) ]'", timeout=timeout)
                client.wait_until_succeeds("journalctl -u ranet3.service --no-pager | grep -F 'the responder answered NO_PROPOSAL_CHOSEN'", timeout=refusal_timeout)

            client.fail("journalctl -u ranet3.service --no-pager | grep -F ': connected (SPI'")
            gateway.fail("swanctl --list-sas | grep -F ESTABLISHED")
        finally:
            print(gateway.execute("swanctl --list-sas")[1])
      '';

      # what each mlkem script asks of the two ends
      mlkemCommon = ''
        import json

        swan_log = "journalctl -u strongswan-swanctl.service --no-pager"
        ranet3_log = "journalctl -u ranet3.service --no-pager"
        # each wait for a rekey outlasts the ike lifetime, by which ranet3's own IKE SA rekey, due the margin before it, has replaced the SA, and strongSwan's retry of a rekey ranet3 answered TEMPORARY_FAILURE
        rekey_timeout = dt.timedelta(seconds=60)
        # the IKE SA both ends run where they meet on ML-KEM-768
        hybrid_suite = "aes256gcm/sha384/x25519+mlkem768"
        # strongSwan's lines of the exchanges of one handshake and of what it chose and dropped
        swan_lines = "IKE_SA_INIT|IKE_INTERMEDIATE|IKE_AUTH|CREATE_CHILD_SA|INFORMATIONAL|proposal|DELETE|restarting|initiating|established|rekeyed"

        def swan_count(line):
            return int(gateway.succeed(f"{swan_log} | grep -cF '{line}' || true").strip())

        def connected():
            """ranet3 has completed a handshake, within the wait the other scripts give theirs"""
            client.wait_until_succeeds(f"{ranet3_log} | grep -F ': connected (SPI'", timeout=timeout)

        def connected_once():
            """ranet3 has completed one handshake and no other, every rekey keeping the session it made"""
            handshakes = int(client.succeed(f"{ranet3_log} | grep -cF ': connected (SPI' || true").strip())
            assert handshakes == 1, f"ranet3 completed {handshakes} handshakes, want 1"

        def session_runs(want):
            """ranet3's one session holds each field of want, read again while an SA is being replaced"""
            seen = []

            def holds(last_try):
                sessions = json.loads(client.succeed("ranet3 sessions --json")) or []
                seen[:] = [{key: s.get(key) for key in want} for s in sessions]
                return seen == [want]

            try:
                retry(holds, timeout=timeout)
            except Exception:
                raise AssertionError(f"ranet3 runs {seen}, want [{want}]")
            print(json.dumps(seen))

        def ike_sas_closed():
            """the reason of each IKE SA ranet3 closed"""
            lines = client.succeed("ranet3 debug events --kind ike.sa.closed --json").splitlines()
            return [e["attrs"].get("reason") for e in map(json.loads, lines) if e.get("attrs", {}).get("sa") == "ike"]

        gateway.wait_for_unit("systemd-networkd-wait-online.service")
        gateway.wait_for_unit("strongswan-swanctl.service")
        gateway.wait_for_unit("bird.service")
        client.wait_for_unit("ranet3.service")
      '';

      # the two ends share aes256gcm, sha384 and x25519+mlkem768, ML-KEM-768 in an IKE_INTERMEDIATE exchange
      # with responder strongSwan dials, and without it ranet3 dials
      # each rekey of the IKE SA, ranet3's and strongSwan's, and strongSwan's rekey of the Child SA run ML-KEM-768 in an IKE_FOLLOWUP_KE exchange after their CREATE_CHILD_SA, and pings go on across each
      mlkemMeet = ''
        responder_enabled = ${if responder then "True" else "False"}
        # strongSwan's side of the handshake, whose IKE_AUTH takes Message ID 2 after the one IKE_INTERMEDIATE
        if responder_enabled:
            exchanges = [
                "generating IKE_INTERMEDIATE request 1 [ KE ]",
                "parsed IKE_INTERMEDIATE response 1 [ KE ]",
                "generating IKE_AUTH request 2 [",
                "parsed IKE_AUTH response 2 [",
            ]
        else:
            exchanges = [
                "parsed IKE_INTERMEDIATE request 1 [ KE ]",
                "generating IKE_INTERMEDIATE response 1 [ KE ]",
                "parsed IKE_AUTH request 2 [",
                "generating IKE_AUTH response 2 [",
            ]

        def chained(journal, side):
            """strongSwan's lines of one rekey through IKE_FOLLOWUP_KE, whose CREATE_CHILD_SA response carries the link in N(ADD_KE) and whose IKE_FOLLOWUP_KE request echoes it"""
            create, followup = ("parsed", "generating") if side == "request" else ("generating", "parsed")
            for line in [
                f"{create} CREATE_CHILD_SA response",
                f"{followup} IKE_FOLLOWUP_KE request",
            ]:
                gateway.wait_until_succeeds(f"{journal} | grep -F '{line}' | grep -F 'N(ADD_KE)'", timeout=timeout)
            gateway.wait_until_succeeds(f"{journal} | grep -F '{create} IKE_FOLLOWUP_KE response' | grep -F '[ KE ]'", timeout=timeout)

        try:
            # strongSwan's journal from before the handshake, which ranet3's own IKE SA rekey reaches before any rekey of strongSwan's
            own_rekey = journal_after(gateway, "strongswan-swanctl.service")
            if responder_enabled:
                gateway.succeed("swanctl --initiate --child default")
            connected()
            client.wait_until_succeeds("ping -c 1 ${gatewayTunnel}", timeout=timeout)
            for line in exchanges:
                gateway.succeed(f"{swan_log} | grep -F '{line}'")
            # the Child SA of IKE_AUTH has no key exchange of its own
            session_runs({"ike_cipher": "aes256gcm", "ike_prf": "sha384", "ike_kex": "x25519+mlkem768", "esp_cipher": "aes256gcm", "esp_kex": None})
            gateway.wait_until_succeeds(
                "swanctl --list-sas | grep -F 'AES_GCM_16-256/PRF_HMAC_SHA2_384/CURVE_25519/KE1_ML_KEM_768'", timeout=timeout)

            # ranet3's own scheduled rekey of the IKE SA first, strongSwan answering it with a link and taking the next IKE_FOLLOWUP_KE
            print(client.succeed(f"ranet3 debug wait ike.rekey.completed --attr sa=ike --attr suite={hybrid_suite} --past 10m --timeout {rekey_timeout.seconds}s"))
            chained(own_rekey, "response")
            client.wait_until_succeeds("ping -c 1 ${gatewayTunnel}", timeout=timeout)

            # strongSwan's rekeys of the IKE SA and of the Child SA right after it and before ranet3's next, ranet3 answering each with a link and the next IKE_FOLLOWUP_KE
            # two CREATE_CHILD_SA requests in flight at once would be settled on the nonces, and strongSwan's, where it lost, would send no IKE_FOLLOWUP_KE
            for sa, done in [("--ike ranet", "IKE_SA ranet.* rekeyed between"), ("--child default", "rekeyed CHILD_SA default")]:
                peer_rekey = journal_after(gateway, "strongswan-swanctl.service")
                print(gateway.succeed(f"swanctl --rekey {sa}"))
                gateway.wait_until_succeeds(f"{peer_rekey} | grep -E '{done}'", timeout=rekey_timeout)
                chained(peer_rekey, "request")
                client.wait_until_succeeds("ping -c 1 ${gatewayTunnel}", timeout=timeout)
            # the Child SA of strongSwan's rekey shows the entry of its key exchanges until ranet3's own rekey replaces it a rekey interval later
            session_runs({"ike_cipher": "aes256gcm", "ike_prf": "sha384", "ike_kex": "x25519+mlkem768", "esp_cipher": "aes256gcm", "esp_kex": "x25519+mlkem768"})

            assert ike_sas_closed() == [], f"ranet3 closed IKE SAs for {ike_sas_closed()}"
            connected_once()
            restarts = swan_count("restarting CHILD_SA default")
            assert restarts == 0, f"strongSwan dialed again {restarts} times"
            if responder_enabled:
                client.fail(f"{ranet3_log} | grep -F ': dialing '")

            client.fail(f"{ranet3_log} | grep -F 'no matching inbound ESP SA'")
            # an SA that reached its lifetime before a rekey replaced it drops what the peer still sends on it, and this names that cause
            client.fail(f"{ranet3_log} | grep -F 'ike stopping ESP on a Child SA past its lifetime'")
            gateway.fail(f"{swan_log} | grep -E 'integrity check failed|no CHILD_SA built|AUTHENTICATION_FAILED'")
        finally:
            print(gateway.execute("swanctl --list-sas")[1])
            print(gateway.execute(f"{swan_log} | grep -E '{swan_lines}'")[1])
            print(client.execute("ranet3 sessions")[1])
            print(client.execute("ranet3 debug events --kind ike")[1])
      '';

      # ranet3 lists x25519+mlkem768 alone and strongSwan proposes no ML-KEM
      # so the end answering refuses with NO_PROPOSAL_CHOSEN whichever end dials
      mlkemApart = ''
        # ranet3 waits out its retransmissions before it gives up on a refusal no key authenticates
        refusal_timeout = dt.timedelta(seconds=120)

        try:
            if ${if responder then "True" else "False"}:
                gateway.execute("swanctl --initiate --child default --timeout 10")
                gateway.wait_until_succeeds(f"{swan_log} | grep -F 'parsed IKE_SA_INIT response 0 [ N(NO_PROP) ]'", timeout=timeout)
                client.succeed("ranet3 debug wait ike.handshake.failed --attr 'err=ike: no acceptable IKE SA proposal' --past 10m --timeout 30s")
            else:
                # strongSwan read ranet3's ML-KEM-768 as an ADDKE1 transform and the request's IKE_INT_SUP
                gateway.wait_until_succeeds(
                    f"{swan_log} | grep -F 'received proposals: ' | grep -F '/CURVE_25519/KE1_ML_KEM_768'", timeout=timeout)
                gateway.succeed(f"{swan_log} | grep -F 'parsed IKE_SA_INIT request 0 [' | grep -F 'N(IKE_INT_SUP)'")
                gateway.wait_until_succeeds(f"{swan_log} | grep -F 'generating IKE_SA_INIT response 0 [ N(NO_PROP) ]'", timeout=timeout)
                client.wait_until_succeeds(f"{ranet3_log} | grep -F 'the responder answered NO_PROPOSAL_CHOSEN'", timeout=refusal_timeout)

            client.fail(f"{ranet3_log} | grep -F ': connected (SPI'")
            gateway.fail("swanctl --list-sas | grep -F ESTABLISHED")
            gateway.fail(f"{swan_log} | grep -F IKE_INTERMEDIATE")
        finally:
            print(gateway.execute("swanctl --list-sas")[1])
            print(gateway.execute(f"{swan_log} | grep -E '{swan_lines}'")[1])
      '';

      # ranet3 dials listing x25519+mlkem768 then x25519, and strongSwan proposes no ML-KEM
      # so strongSwan takes x25519 alone, no IKE_INTERMEDIATE runs, and ranet3's IKE SA rekeys are CREATE_CHILD_SA exchanges of x25519
      mlkemFallback = ''
        try:
            connected()
            client.wait_until_succeeds("ping -c 1 ${gatewayTunnel}", timeout=timeout)
            session_runs({"ike_kex": "x25519"})
            gateway.succeed(f"{swan_log} | grep -F 'received proposals: ' | grep -F '/CURVE_25519/KE1_ML_KEM_768'")
            gateway.succeed(f"{swan_log} | grep -F 'selected proposal: IKE:' | grep -F '/CURVE_25519'")
            gateway.fail(f"{swan_log} | grep -F 'selected proposal: IKE:' | grep -F 'KE1_'")
            gateway.fail(f"{swan_log} | grep -F 'generating IKE_SA_INIT response 0 [' | grep -F 'N(IKE_INT_SUP)'")
            gateway.succeed(f"{swan_log} | grep -F 'parsed IKE_AUTH request 1 ['")
            gateway.fail(f"{swan_log} | grep -F IKE_INTERMEDIATE")
            sas = gateway.succeed("swanctl --list-sas")
            print(sas)
            assert "/CURVE_25519" in sas and "KE1_" not in sas, "strongSwan's IKE SA does not run x25519 alone"

            # each rekey of the IKE SA keeps the cipher and the PRF, and strongSwan takes the entry of x25519 alone from its offer
            session = json.loads(client.succeed("ranet3 sessions --json"))[0]
            suite = f"{session['ike_cipher']}/{session['ike_prf']}/x25519"
            print(client.succeed(
                f"ranet3 debug wait ike.rekey.completed --attr sa=ike --attr suite={suite} --past 10m --timeout {rekey_timeout.seconds}s"))
            client.wait_until_succeeds("ping -c 1 ${gatewayTunnel}", timeout=timeout)
            assert ike_sas_closed() == [], f"ranet3 closed IKE SAs for {ike_sas_closed()}"
            connected_once()

            client.fail(f"{ranet3_log} | grep -F 'no matching inbound ESP SA'")
            client.fail(f"{ranet3_log} | grep -F 'ike stopping ESP on a Child SA past its lifetime'")
            gateway.fail(f"{swan_log} | grep -E 'integrity check failed|no CHILD_SA built'")
        finally:
            print(gateway.execute(f"{swan_log} | grep -E '{swan_lines}'")[1])
            print(client.execute("ranet3 sessions")[1])
      '';

      # strongSwan dials with ML-KEM-768 optional in ADDKE1
      # "optional" lists x25519+mlkem768 first, and ranet3 answers ADDKE1 with ML-KEM-768
      # "none" lists x25519 alone, and ranet3 answers ADDKE1 with NONE written out and no IKE_INTERMEDIATE follows
      mlkemAnswered = ''
        joined = ${if mlkem == "optional" then "True" else "False"}

        try:
            gateway.succeed("swanctl --initiate --child default")
            connected()
            client.wait_until_succeeds("ping -c 1 ${gatewayTunnel}", timeout=timeout)
            gateway.succeed(f"{swan_log} | grep -F 'parsed IKE_SA_INIT response 0 [' | grep -F 'N(IKE_INT_SUP)'")
            if joined:
                session_runs({"ike_cipher": "aes256gcm", "ike_prf": "sha384", "ike_kex": "x25519+mlkem768"})
                for line in [
                    "received proposals: IKE:AES_GCM_16_256/PRF_HMAC_SHA2_384/CURVE_25519/KE1_ML_KEM_768",
                    "selected proposal: IKE:AES_GCM_16_256/PRF_HMAC_SHA2_384/CURVE_25519/KE1_ML_KEM_768",
                    "generating IKE_INTERMEDIATE request 1 [ KE ]",
                    "parsed IKE_INTERMEDIATE response 1 [ KE ]",
                    "parsed IKE_AUTH response 2 [",
                ]:
                    gateway.succeed(f"{swan_log} | grep -F '{line}'")
                # strongSwan's ke1_none would take a CREATE_CHILD_SA rekey without ML-KEM-768
                # and ranet3's own rekey keeps it, in an IKE_FOLLOWUP_KE exchange
                print(client.succeed(
                    f"ranet3 debug wait ike.rekey.completed --attr sa=ike --attr suite={hybrid_suite} --past 10m --timeout {rekey_timeout.seconds}s"))
                gateway.succeed(f"{swan_log} | grep -F 'parsed IKE_FOLLOWUP_KE request' | grep -F 'N(ADD_KE)'")
                client.wait_until_succeeds("ping -c 1 ${gatewayTunnel}", timeout=timeout)
                assert ike_sas_closed() == [], f"ranet3 closed IKE SAs for {ike_sas_closed()}"
            else:
                session_runs({"ike_cipher": "aes256gcm", "ike_prf": "sha384", "ike_kex": "x25519"})
                for line in [
                    "received proposals: IKE:AES_GCM_16_256/PRF_HMAC_SHA2_384/CURVE_25519/KE1_KE_NONE",
                    "parsed IKE_AUTH response 1 [",
                ]:
                    gateway.succeed(f"{swan_log} | grep -F '{line}'")
                gateway.fail(f"{swan_log} | grep -F IKE_INTERMEDIATE")
                # the IKE SA rekeys as any SA of one key exchange does, strongSwan taking NONE for an ADDKE1 the offer leaves out
                print(client.succeed(
                    f"ranet3 debug wait ike.rekey.completed --attr sa=ike --attr suite=aes256gcm/sha384/x25519 --past 10m --timeout {rekey_timeout.seconds}s"))
                client.wait_until_succeeds("ping -c 1 ${gatewayTunnel}", timeout=timeout)
                assert ike_sas_closed() == [], f"ranet3 closed IKE SAs for {ike_sas_closed()}"

            client.fail(f"{ranet3_log} | grep -F ': dialing '")
            client.fail(f"{ranet3_log} | grep -F 'no matching inbound ESP SA'")
            client.fail(f"{ranet3_log} | grep -F 'ike stopping ESP on a Child SA past its lifetime'")
            gateway.fail(f"{swan_log} | grep -E 'integrity check failed|no CHILD_SA built|AUTHENTICATION_FAILED'")
        finally:
            print(gateway.execute("swanctl --list-sas")[1])
            print(gateway.execute(f"{swan_log} | grep -E '{swan_lines}'")[1])
            print(client.execute("ranet3 debug events --kind ike")[1])
      '';
    in
    preamble
    + (
      if suites == "meet" then
        suitesMeet
      else if suites == "apart" then
        suitesApart
      else if mlkem == "meet" then
        mlkemCommon + mlkemMeet
      else if mlkem == "apart" then
        mlkemCommon + mlkemApart
      else if mlkem == "fallback" then
        mlkemCommon + mlkemFallback
      else if mlkem != null then
        mlkemCommon + mlkemAnswered
      else if responder then
        responderScript
      else if egressSegment then
        egressSegmentScript
      else if segments then
        segmentRouted
      else if egress then
        exitNode
      else
        initiator
    );
}
