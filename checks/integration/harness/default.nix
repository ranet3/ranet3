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
  # "fragment" dials x25519+mlkem768 and then p384+mlkem1024, over IPv6 on a link of MTU 1280 and then over IPv4 on one of 576
  mlkem ? null,
  # beside runs another program's own daemon on the client at the version nixpkgs pins, "docker", "tailscale" or "k3s"
  # with cap.table and cap.border.overlay, so ranet3's rules and its lookups of them meet that program's rules
  beside ? null,
}:

assert suites == null || mlkem == null;
assert lib.elem beside [
  null
  "docker"
  "tailscale"
  "k3s"
];
# a program beside ranet3 meets the plain dialing client, and Docker the exit
assert beside != null -> suites == null && mlkem == null && !segments && !responder && !fqdn;
assert beside != null -> egress == (beside == "docker");
# strongSwan dials in "optional" and "none" and ranet3 in "fallback" and "fragment"
assert
  lib.elem mlkem [
    "optional"
    "none"
  ]
  -> responder;
assert
  lib.elem mlkem [
    "fallback"
    "fragment"
  ]
  -> !responder;

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
  # route to it. clientBehind is the client's own and announced too, since the
  # forwarding decision delivers an End.DT46's inner packet only to an address
  # the client routes, and the gateway sends it through the segment by a rule
  # ahead of the route it learns.
  clientSID = "fd00:88::6:1";
  # On loopback rather than on the tun: an address on the tun is one the kernel
  # can pick as the source for the mesh traffic that leaves through it.
  clientBehind = "fd00:88::9";
  # The gateway's table for the segment's route to clientBehind, and its rule's
  # priority, ahead of main's.
  segmentTable = 88;
  # The egress segment's SID, announced by the client only while its egress
  # segments are ready. The gateway's outside address is in neither prefix
  # the allow list names.
  clientEgressSID = "fd00:88::6:3";
  gatewayOutside = "fd00:77::1";
  # Inside the gateway's tunnel prefix and held by nobody, so the client's mesh
  # routes it to the gateway and the egress segment refuses it.
  meshDestination = "fd00:99::5";
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
    fragment = [ "x25519+mlkem768" ];
  };
  # "fragment" runs on vlan 1 at the IPv6 minimum MTU and on vlan 2 at the IPv4 floor of RFC 7383 section 2.5.1
  # ranet3 cuts its messages at the path MTU, 1280 and then 576, and strongSwan at its fragment_size of 1280 on both
  # so on vlan 2 the kernel splits strongSwan's fragments into IP fragments, which the client's kernel puts back together
  fragment = mlkem == "fragment";
  fragmentMTU = {
    ip6 = 1280;
    ip4 = 576;
  };
  # the specialisations "fragment" switches the client into after its first handshakes, in order, each with the family of its endpoint and its kex entry
  fragmentPhases = [
    {
      name = "mlkem1024";
      family = "ip6";
      kex = "p384+mlkem1024";
    }
    {
      name = "ipv4";
      family = "ip4";
      kex = "x25519+mlkem768";
    }
    {
      name = "ipv4-mlkem1024";
      family = "ip4";
      kex = "p384+mlkem1024";
    }
  ];
  # the family of the endpoints ranet3 starts on
  underlay = if fragment then "ip6" else "ip4";
  # a node's endpoint in family, on vlan 1 but for "fragment" over IPv4, which takes vlan 2
  underlayAddress =
    node: family:
    if family == "ip6" then
      node.networking.primaryIPv6Address
    else if fragment then
      (lib.head node.networking.interfaces.eth2.ipv4.addresses).address
    else
      node.networking.primaryIPAddress;
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
    # strongSwan answers the one entry ranet3 offers, ke1_mlkem768 and then ke1_mlkem1024
    fragment = {
      ike = [
        "aes256gcm16-prfsha384-x25519-ke1_mlkem768"
        "aes256gcm16-prfsha384-ecp384-ke1_mlkem1024"
      ];
      esp = [ "aes256gcm16-x25519-none-ke1_mlkem768-ke1_none" ];
    };
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
    virtualisation.vlans = [ 1 ] ++ lib.optional fragment 2;
    virtualisation.cores = cores;
    networking = {
      useNetworkd = true;
      useDHCP = false;
      firewall.enable = false;
      interfaces = lib.mkIf fragment {
        eth1.mtu = fragmentMTU.ip6;
      };
    };
  };
  # vlan 2's MTU is that of each end's route to the other, since linux takes IPv6 off a device under 1280
  # and the gateway's kernel builds no route for IPv6 in an SA over a device without IPv6
  fragmentRoute = peer: {
    Destination = "${underlayAddress peer "ip4"}/32";
    MTUBytes = fragmentMTU.ip4;
  };
  # the address Tailscale's exit node holds and nothing else answers
  exitOnlyV4 = "203.0.113.1";
  exitArm = lib.elem beside [
    "docker"
    "tailscale"
  ];
  # the gateway answers these on lo as the far side of the mesh's exit, and the client sends them nothing over the mesh otherwise
  meshExitV4 = "203.0.113.2";
  meshExitV6 = "2001:db8:ff00::2";
  # k3s pulls nothing: its pods and its pause container run this image from the store
  podImageName = "example.org/pod:local";
  podImage = pkgs.dockerTools.buildLayeredImage {
    name = "example.org/pod";
    tag = "local";
    contents = [
      pkgs.busybox
      pkgs.tini
    ];
    config.Entrypoint = [
      "/bin/tini"
      "--"
      "/bin/sleep"
      "inf"
    ];
  };
  podContainer = name: command: {
    inherit name command;
    image = podImageName;
    imagePullPolicy = "Never";
  };
  # tailscaled closes its connection to the control server on every link change while the host has no default route,
  # and then dials it only over HTTPS for as long as it keeps retrying, which headscale here does not serve
  uplinkDefault =
    { nodes, ... }:
    {
      networking.defaultGateway = {
        address = nodes.gateway.networking.primaryIPAddress;
        interface = "eth1";
      };
      networking.defaultGateway6 = {
        address = nodes.gateway.networking.primaryIPv6Address;
        interface = "eth1";
      };
    };
  # what each program beside ranet3 adds to the client, at its defaults
  besideClient = {
    docker = {
      # main's default, which the catch-all under cap.exit has to come ahead of, as on a deployed host
      imports = [ uplinkDefault ];
      virtualisation.docker.enable = true;
      virtualisation.memorySize = 1536;
      specialisation.exit.configuration.networking.ranet3.settings.cap.exit.forward = [ "docker0" ];
    };
    tailscale = {
      imports = [ uplinkDefault ];
      services.tailscale = {
        enable = true;
        useRoutingFeatures = "client";
      };
      specialisation.exit.configuration.networking.ranet3.settings.cap.exit = { };
    };
    k3s =
      { config, ... }:
      {
        virtualisation = {
          memorySize = 2048;
          diskSize = 4096;
        };
        environment.sessionVariables.KUBECONFIG = "/etc/rancher/k3s/k3s.yaml";
        services.k3s = {
          enable = true;
          role = "server";
          disable = [
            "coredns"
            "local-storage"
            "metrics-server"
            "servicelb"
            "traefik"
          ];
          images = [ podImage ];
          # a server behind a ClusterIP service and a client that reaches it through the service's address
          manifests.pods.content = [
            {
              apiVersion = "v1";
              kind = "Pod";
              metadata = {
                name = "server";
                labels.app = "server";
              };
              spec.containers = [
                (podContainer "server" [
                  "sh"
                  "-c"
                  "mkdir -p /www && echo beside > /www/index.html && exec httpd -f -p 8080 -h /www"
                ])
              ];
            }
            {
              apiVersion = "v1";
              kind = "Service";
              metadata.name = "server";
              spec = {
                selector.app = "server";
                ports = [
                  {
                    port = 80;
                    targetPort = 8080;
                  }
                ];
              };
            }
            {
              apiVersion = "v1";
              kind = "Pod";
              metadata.name = "client";
              spec.containers = [
                (podContainer "client" [
                  "sleep"
                  "inf"
                ])
              ];
            }
          ];
          nodeIP = config.networking.primaryIPAddress;
          extraFlags = [
            "--flannel-iface eth1"
            "--pause-image ${podImageName}"
          ];
        };
        # the kernel keeps the translation a flow's first packet met, so the script starts ranet3 once kube-proxy's
        # masquerade exists, and a session dialed before it would pass the port check under any mark
        systemd.services.ranet3.wantedBy = lib.mkForce [ ];
      };
  };
in
testers.runNixOSTest {
  name =
    if beside != null then
      "ranet3-beside-${beside}"
    else if suites != null then
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
          ++ pkgs.lib.optionals (segments || exitArm) [ tcpdump ];

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
            # the kernel routes what an xfrm interface encapsulates out of its underlying device alone
            # and "fragment" carries the SA over eth1 and then over eth2, so its swan0 has none
            xfrmConfig = {
              InterfaceId = 1;
            }
            // lib.optionalAttrs fragment { Independent = true; };
          };
          networks = {
            # The test network module already defines 40-eth1. Extend it to
            # create swan0 with eth1 as its underlying device.
            "40-eth1".networkConfig.Xfrm = lib.mkIf (!fragment) "swan0";
            "40-eth2" = lib.mkIf fragment { routes = [ (fragmentRoute nodes.client) ]; };
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
            "05-lo" = lib.mkIf exitArm {
              matchConfig.Name = "lo";
              networkConfig.ConfigureWithoutCarrier = true;
              addresses = [
                { Address = "${meshExitV4}/32"; }
                { Address = "${meshExitV6}/128"; }
              ];
            };
          };
        };

        services.strongswan-swanctl = {
          enable = true;
          # cfg at level 2 logs the proposals strongSwan received where it found one acceptable
          # so the log shows each transform of ranet3's answer, a NONE among them
          strongswan.extraConfig = ''
            charon-systemd {
              interfaces_use = ${if fragment then "eth1,eth2" else "eth1"}
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
          ''
          # its default, written out since each end's fragments are cut to a size of its own
          + lib.optionalString fragment ''
            charon-systemd {
              fragment_size = 1280
            }
          '';
          swanctl = {
            connections.ranet = {
              version = 2;
              local_addrs = [ "0.0.0.0/0" ] ++ lib.optional fragment "::/0";
              # A wildcard remote can only answer. Naming the client lets
              # swanctl --initiate dial it.
              remote_addrs =
                if responder then
                  [ nodes.client.networking.primaryIPAddress ]
                else
                  [ "0.0.0.0/0" ] ++ lib.optional fragment "::/0";
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

            # after ranet3 restarts under cap.exit, the kernel keeps this BIRD's unreachable for a network the client
            # announces until a kernel protocol's next scan, 60 s apart by default, while BIRD's table routes it by the client
            protocol kernel {
              scan time 1;
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
              scan time 1;
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
          ''
          # the mesh's default, which the arm under cap.exit enables
          + lib.optionalString exitArm ''
            protocol static exit4 {
              disabled;
              ipv4;
              route 0.0.0.0/0 unreachable;
            }

            protocol static exit6 {
              disabled;
              ipv6 sadr;
              route ::/0 from ::/0 unreachable;
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
      let
        # the registry this node trusts, with each end's endpoint in family
        registry =
          family:
          builtins.toJSON [
            {
              public_key = publicKey;
              organization = "testorg";
              nodes = [
                {
                  common_name = "client";
                  endpoints = [
                    {
                      serial_number = "2";
                      address_family = family;
                      address = underlayAddress nodes.client family;
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
                      address_family = family;
                      address = underlayAddress nodes.gateway family;
                      port = 13000;
                    }
                  ];
                  remarks = { };
                }
              ];
            }
          ];
      in
      {
        imports = [
          common
          inputs.self.nixosModules.ranet3
        ]
        ++ lib.optional (beside != null) besideClient.${beside};

        boot.kernelModules = [ "tun" ];

        # what "fragment" switches the client into after its first handshakes, p384+mlkem1024 and then IPv4
        specialisation = pkgs.lib.mkIf fragment (
          lib.listToAttrs (
            map (
              phase:
              lib.nameValuePair phase.name {
                configuration = {
                  environment.etc."ranet3/registry.json".text = lib.mkForce (registry phase.family);
                  networking.ranet3.settings = {
                    link.endpoints = lib.mkForce [
                      {
                        serial = "2";
                        inherit (phase) family;
                      }
                    ];
                    cap.crypto.ike.kex = lib.mkForce [ phase.kex ];
                  };
                };
              }
            ) fragmentPhases
          )
        );

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
          # An exit routes every other destination out of its uplink. An exit
          # for an egress segment alone advertises nothing, so the translator
          # judges each family by the kernel's lookup of a translated packet to
          # an address of the family's default, which needs this route to be
          # ready.
          ipv4.routes = pkgs.lib.optionals egressSegment [
            {
              address = "0.0.0.0";
              prefixLength = 0;
              via = behindV4;
            }
          ];
          ipv6.routes = pkgs.lib.optionals egressSegment [
            {
              address = "::";
              prefixLength = 0;
              via = behindV6;
            }
          ];
        };

        environment.systemPackages =
          with pkgs;
          [
            curl
            iperf3
            iproute2
            tcpdump
          ]
          # nft reads back what this tree wrote through netlink, and jq asks
          # the control socket a question the shell cannot.
          ++ pkgs.lib.optionals (egress || beside != null) [
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
          networks."40-eth2" = lib.mkIf fragment { routes = [ (fragmentRoute nodes.gateway) ]; };
          networks."05-lo" = pkgs.lib.mkIf segments {
            matchConfig.Name = "lo";
            networkConfig.ConfigureWithoutCarrier = true;
            # What an End.DT46 on this node delivers to, which the gateway
            # reaches through the segment alone, by its rule.
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
          "ranet3/registry.json".text = registry underlay;
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
                  family = underlay;
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
              ++ pkgs.lib.optionals segments [
                "${clientSID}/128"
                "${clientBehind}/128"
              ];
              babel = {
                hello = "500ms";
                update = "1s";
              };
              crypto = {
                rekey = {
                  # each rekey starts the margin before the lifetime stops its SA
                  # and the margin covers a Delete of a replaced IKE SA on the teardown budget, then a rekey's three lost sends
                  # in meet the ML-KEM-768 Child SA of strongSwan's rekey lasts until ranet3's own rekey, child less margin after it, and the check of its key exchanges must come first
                  child =
                    if profile then
                      0
                    else if mlkem == "meet" then
                      "32s"
                    else
                      "24s";
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
              # and beside another program the reconciler holds each overlay prefix and looks up an address of it
              border = pkgs.lib.mkIf (segments || beside != null) {
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
              table = pkgs.lib.mkIf (kernel || egress || beside != null) {
                id = kernelTable;
                proto = kernelProtocol;
                metric = 32;
                reconcile = "2s";
              };
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
  }
  // lib.optionalAttrs (beside == "tailscale") {
    # Tailscale's other node and its exit, and headscale, the control server it registers with
    peer = {
      imports = [
        common
        uplinkDefault
      ];
      services.tailscale = {
        enable = true;
        useRoutingFeatures = "server";
      };
      services.headscale = {
        enable = true;
        address = "0.0.0.0";
        settings = {
          server_url = "http://peer:8080";
          # the default fetches Tailscale's own DERP map
          derp = {
            server = {
              enabled = true;
              region_id = 999;
              stun_listen_addr = "0.0.0.0:3478";
            };
            urls = [ ];
          };
          dns = {
            magic_dns = false;
            override_local_dns = false;
          };
        };
      };
      systemd.network.networks."05-lo" = {
        matchConfig.Name = "lo";
        networkConfig.ConfigureWithoutCarrier = true;
        addresses = [ { Address = "${exitOnlyV4}/32"; } ];
      };
    };
  };

  testScript =
    { nodes, ... }:
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
            machine.succeed(f"rm -f /tmp/{name}.pcap /tmp/{name}.log")
            # an answered ping ends inside libpcap's block timeout, and the kill would lose the block it holds
            machine.execute(f"tcpdump --immediate-mode -ni swan0 -w /tmp/{name}.pcap ip6 >/tmp/{name}.log 2>&1 &")
            machine.wait_until_succeeds(f"grep -q 'listening on' /tmp/{name}.log", timeout=timeout)
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
        # tree acts on it. The client announces the address behind it, and the
        # gateway's rule ahead of main sends it through the segment rather than
        # the route it learned, so the client's own counter says which of the
        # two carried the packet.
        gateway.wait_until_succeeds("ip -6 route get ${clientSID}", timeout=timeout)
        gateway.succeed(
            "ip -6 route replace ${clientBehind}/128 encap seg6 mode encap segs ${clientSID} dev swan0 table ${toString segmentTable}",
            "ip -6 rule add to ${clientBehind}/128 table ${toString segmentTable} priority ${toString segmentTable}",
        )
        print(gateway.succeed("ip -6 route show table ${toString segmentTable}"))

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

      captureWhile = ''
        def capture_while(machine, interface, name, filter, count, act):
            """What machine saw on interface of count packets the filter matches while act ran.

            tcpdump counts the packets it wants and exits on its own, rather
            than being killed once act is done: a kill races the write. A
            filter of the echo request alone keeps neighbor discovery from
            making up the count.
            """
            machine.succeed(f"rm -f /tmp/{name}.pcap /tmp/{name}.log")
            machine.execute(
                f"tcpdump -Uni {interface} -c {count} -w /tmp/{name}.pcap '{filter}' >/tmp/{name}.log 2>&1 &")
            machine.wait_until_succeeds(f"grep -q 'listening on' /tmp/{name}.log", timeout=timeout)
            act()
            machine.wait_until_fails("pgrep -x tcpdump", timeout=timeout)
            print(machine.succeed(f"cat /tmp/{name}.log"))
            return machine.succeed(f"tcpdump -nr /tmp/{name}.pcap")
      '';

      exitTranslates = captureWhile + ''
        def carried(name, filter, source, destination):
            """what the far side saw of three pings through the exit"""
            return capture_while(
                behind, "eth1", name, filter, 3,
                lambda: print(gateway.succeed(f"ping -c 3 -i 0.3 -W 2 -I {source} {destination}")))

        def exit_translates():
            """the gateway reaches behind through the exit in both families, and behind sees the exit's own address"""
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

            exit_translates()

            status = json.loads(client.succeed("ranet3 status --json"))["egress"]
            print(json.dumps(status, indent=2))
            assert status["enabled"], status
            # the rules the translator writes for this configuration, which
            # advertises without return: in ipv4 the 4 drops of source quench
            # and information messages, then in each family the drop of what no
            # flow is tracked for, the limit rule and the refusals of dccp and
            # udp-lite, then 3 timeout rules and a masquerade for the catch-all
            # auto class, and 3 timeout rules and a masquerade for the local rule
            # of the client's one mesh address, so a stale or doubled rule shows
            assert status["installed"] == 28, status
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

            # the SID reaches the gateway once both families are ready
            client.wait_until_succeeds(
                "ranet3 status --json | jq -e '.egress.ready == [\"ipv4\", \"ipv6\"]'", timeout=timeout)
            gateway.wait_until_succeeds("ip -6 route show ${clientEgressSID} | grep -q swan0", timeout=timeout)

            # the translator reads the mesh's members at each pass, and its passes run on the sweep rather than when a
            # route comes in, so the lookups read from a member of each family once a sweep after the gateway's routes has run
            client.wait_until_succeeds(
                "ranet3 status --json | jq -e '.egress.skipped == null and .egress.ready == [\"ipv4\", \"ipv6\"]'", timeout=timeout)

            # the exit egresses through its one tun: no other tun, no rule keyed on an arrival device,
            # and the translator's rule keyed on the tun in both families
            tuns = client.succeed("ip -o link show type tun")
            print(tuns)
            assert [line.split(": ")[1] for line in tuns.splitlines()] == [client_device], f"the exit holds another tun:\n{tuns}"
            for family in ["-4", "-6"]:
                rules = client.succeed(f"ip {family} rule show")
                print(rules)
                assert " iif " not in rules, f"the exit holds a rule keyed on an arrival device:\n{rules}"
            for family in ["ip", "ip6"]:
                table = client.succeed(f"nft list table {family} ranet3")
                print(table)
                for want in ["masquerade", f'iifname "{client_device}"', f'oifname != "{client_device}"']:
                    assert want in table, f"the {family} table does not carry {want}:\n{table}"

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

            # an inner packet for a destination the mesh routes is refused at the SID, answered with nothing
            # and never handed back to the gateway through the mesh
            gateway.succeed("ip -6 route replace ${meshDestination}/128 encap seg6 mode encap segs ${clientEgressSID} dev swan0")
            gateway.succeed("rm -f /tmp/mesh.pcap /tmp/mesh.log")
            # the kill would lose the block libpcap holds, and a packet handed back with it
            gateway.execute("tcpdump --immediate-mode -ni swan0 -Q in -w /tmp/mesh.pcap 'ip6 dst ${meshDestination}' >/tmp/mesh.log 2>&1 &")
            gateway.wait_until_succeeds("grep -q 'listening on' /tmp/mesh.log", timeout=timeout)
            before = counters()
            gateway.fail("ping -c 3 -i 0.3 -W 1 -I ${gatewayTunnel} ${meshDestination}")
            after = counters()
            gateway.succeed("pkill -x tcpdump")
            gateway.wait_until_fails("pgrep -x tcpdump", timeout=timeout)
            capture = gateway.succeed("tcpdump -nr /tmp/mesh.pcap 2>/dev/null").strip()
            gateway.succeed("ip -6 route del ${meshDestination}/128")
            assert capture == "", f"the exit handed the gateway back a packet it took at its egress SID:\n{capture}"
            assert after["refused"] >= before["refused"] + 3, f"an inner packet for the mesh was not refused: {before} then {after}"
            assert after["egressed"] == before["egressed"], f"an inner packet for the mesh was egressed: {after}"

            metrics = client.succeed("curl -sf http://127.0.0.1:9669/metrics")
            for want in ['ranet3_egress_ready{family="ipv4"} 1', 'ranet3_egress_ready{family="ipv6"} 1', "ranet3_border_ready 1"]:
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
            gateway.wait_until_succeeds("ping -c 1 -W 2 -I ${gatewayTunnel} ${behindV6}", timeout=timeout)

            # shutdown takes the tables with it
            client.succeed("systemctl stop ranet3.service")
            assert client.succeed("systemctl show -p Result --value ranet3.service").strip() == "success"
            left = client.succeed("nft list tables").strip()
            assert left == "", f"shutdown left tables behind: {left}"
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

            # a hop that marks the gateway's ESP CE reaches the inner flow's receiver as CE, RFC 6040 section 4.2's decapsulation
            # strongSwan's kernel copies the inner ECT(0) to the outer header, and fq_codel behind a 1 mbit shaper on the gateway's eth1 marks it CE past its ce_threshold
            # the inner flow goes at twice the shaper's rate, so its datagrams queue there, and a capture on the client's tun reads what ranet3 delivers
            client.succeed("systemd-run --unit=iperf-ecn iperf3 --server --bind ${clientTunnelV4} --one-off")
            client.wait_until_succeeds("ss -ltn | grep -qF '${clientTunnelV4}:5201'", timeout=timeout)
            client.execute(f"timeout 120 tcpdump --immediate-mode -lnv -i {client_device} 'udp and dst port 5201' >/tmp/ecn.log 2>&1 &")
            client.wait_until_succeeds("grep -q 'listening on' /tmp/ecn.log", timeout=timeout)
            try:
                gateway.succeed(
                    "tc qdisc replace dev eth1 root handle 1: htb default 1",
                    "tc class add dev eth1 parent 1: classid 1:1 htb rate 1mbit",
                    "tc qdisc add dev eth1 parent 1:1 fq_codel ce_threshold 1ms",
                )
                # ECT(0) under the DSCP 0x2e
                print(gateway.execute("iperf3 --client ${clientTunnelV4} --udp --bitrate 2M --length 1200 --time 2 --tos 0xba")[1])
                client.wait_until_succeeds("grep -qF 'tos 0xbb,CE' /tmp/ecn.log", timeout=timeout)
                print(gateway.succeed("tc -s qdisc show dev eth1"))
            finally:
                gateway.succeed("tc qdisc del dev eth1 root")
                client.execute("pkill tcpdump; systemctl stop iperf-ecn.service")
            # tcpdump prints a header's TOS whatever its checksum, so a CE written without the checksum's update would pass the wait above
            client.fail("grep -F 'bad cksum' /tmp/ecn.log")
            metrics = client.succeed("curl -sf http://127.0.0.1:9669/metrics")
            marked = [line for line in metrics.splitlines() if line.startswith("ranet3_esp_inbound_ce_total ")]
            assert marked and int(marked[0].split()[1]) > 0, metrics
            assert "ranet3_esp_inbound_ecn_unused_total 0" in metrics.splitlines(), metrics

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
                # carrying this reconciler's protocol.
                client.wait_until_succeeds(f"ip -4 route show table {kernel_table} | grep -q '10.99.0.0/24'", timeout=timeout)
                client.wait_until_succeeds(f"ip -6 route show table {kernel_table} | grep -q 'fd00:99::/64'", timeout=timeout)
                v4 = client.succeed(f"ip -4 route show table {kernel_table}")
                v6 = client.succeed(f"ip -6 route show table {kernel_table}")
                print(v4)
                print(v6)
                assert f"proto {kernel_protocol}" in v4, v4
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
            gateway.fail("journalctl -u strongswan-swanctl.service --no-pager | grep -E 'integrity check failed|no CHILD_SA built|N[(]INVAL_SPI[)]'")

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
            gateway.fail("journalctl -u strongswan-swanctl.service --no-pager | grep -E 'integrity check failed|no CHILD_SA built|N[(]INVAL_SPI[)]'")

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
            gateway.fail("journalctl -u strongswan-swanctl.service --no-pager | grep -E 'integrity check failed|no CHILD_SA built|N[(]INVAL_SPI[)]'")
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
        # each wait for a rekey outlasts the ike lifetime, within which ranet3's own IKE SA rekey, due the margin before it, replaces the SA through its retries
        # and it covers a rekey asked of strongSwan with each ask again after a TEMPORARY_FAILURE or an IKE SA rekey crossing that strongSwan lost, every ask made once the next of ranet3's Child SA rekeys has ended, so it ends on strongSwan's own rekey
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
        import re

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

        def peer_rekey(sa, made, done):
            """strongSwan's journal from its own rekey of sa, asked for right after strongSwan answers ranet3's Delete of a Child SA ranet3 rekeyed, and asked for again that way after a TEMPORARY_FAILURE or a crossing it lost, until the rekey ends
            made finds the name strongSwan gives the SA its own rekey makes, and done, given that name, the line that ends the rekey, which no rekey of ranet3's logs"""
            journal = ""

            def ask():
                nonlocal journal
                # ranet3's next Child SA rekey waits the child interval less the margin, so a rekey asked now runs before it
                since = journal_after(gateway, "strongswan-swanctl.service")
                gateway.wait_until_succeeds(f"{since} | grep -F 'generating INFORMATIONAL response' | grep -F '[ D ]'", timeout=timeout)
                journal = journal_after(gateway, "strongswan-swanctl.service")
                print(gateway.succeed(f"swanctl --rekey {sa}"))

            def rekeyed(last_try):
                lines = gateway.succeed(journal)
                names = re.findall(made, lines)
                if names and done.format(names[-1]) in lines:
                    return True
                # RFC 7296 section 2.25: "When a peer receives a TEMPORARY_FAILURE notification, it MUST NOT immediately retry the operation" and "it MUST wait so that the sender may complete whatever operation caused the temporary condition."
                # so the rekey is asked again once ranet3's Child SA rekey has ended, as strongSwan's own retry may come after a rekey of ranet3's has replaced the SA it was for
                # RFC 9370 section 2.2.4: "because there is nothing to delete yet, the initiator of this exchange just stops the rekeying process, and it MUST NOT initiate the IKE_FOLLOWUP_KE exchange."
                # so an IKE SA rekey of strongSwan's that crossed one of ranet3's and lost on the nonces, the collision strongSwan logs as lost, makes no SA of its own and is asked again too
                if any("parsed " in line and " response " in line and "N(TEMP_FAIL)" in line for line in lines.splitlines()) or "IKE_SA rekey collision lost" in lines:
                    ask()
                return False

            ask()
            retry(rekeyed, timeout=rekey_timeout)
            return journal

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

            # strongSwan's rekeys of the IKE SA and of the Child SA, each between two of ranet3's Child SA rekeys, ranet3 answering each with a link and the next IKE_FOLLOWUP_KE
            for sa, made, done in [
                ("--ike ranet", r"initiating IKE_SA (ranet\[\d+\]) to ", "IKE_SA {} rekeyed between"),
                ("--child default", r"establishing CHILD_SA (default\{\d+\})", "with {} with SPIs"),
            ]:
                chained(peer_rekey(sa, made, done), "request")
                client.wait_until_succeeds("ping -c 1 ${gatewayTunnel}", timeout=timeout)
            # the Child SA of strongSwan's rekey shows the entry of its key exchanges until ranet3's own rekey replaces it, child less margin after strongSwan made it
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
            gateway.fail(f"{swan_log} | grep -E 'integrity check failed|no CHILD_SA built|AUTHENTICATION_FAILED|N[(]INVAL_SPI[)]'")
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
            gateway.fail(f"{swan_log} | grep -E 'integrity check failed|no CHILD_SA built|N[(]INVAL_SPI[)]'")
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
            gateway.fail(f"{swan_log} | grep -E 'integrity check failed|no CHILD_SA built|AUTHENTICATION_FAILED|N[(]INVAL_SPI[)]'")
        finally:
            print(gateway.execute("swanctl --list-sas")[1])
            print(gateway.execute(f"{swan_log} | grep -E '{swan_lines}'")[1])
            print(client.execute("ranet3 debug events --kind ike")[1])
      '';

      # ranet3 dials x25519+mlkem768 and then p384+mlkem1024, over IPv6 on vlan 1 and then over IPv4 on vlan 2
      # the reload to p384+mlkem1024 first rekeys the IKE SA, ML-KEM-1024 in an IKE_FOLLOWUP_KE exchange after the CREATE_CHILD_SA, and a restart then dials with it
      # each IKE_INTERMEDIATE and IKE_FOLLOWUP_KE request passes the path MTU, so ranet3 cuts it to the path and strongSwan reassembles it
      # each ML-KEM-1024 response passes strongSwan's fragment_size, so strongSwan splits it and ranet3 reassembles it
      # the ML-KEM-768 response fits 1280 octets, and on vlan 2 the kernel carries it in IP fragments
      mlkemFragment = ''
        # the client's first configuration and then each specialisation, with the family of its endpoint and its kex entry
        phases = json.loads('${
          builtins.toJSON (
            [
              {
                name = null;
                family = underlay;
                kex = lib.head mlkemLists.fragment;
              }
            ]
            ++ fragmentPhases
          )
        }')
        # the address ranet3 reaches strongSwan at and the threshold ranet3 cuts at, in each family
        remotes = {"ip6": "[${underlayAddress nodes.gateway "ip6"}]:13000", "ip4": "${underlayAddress nodes.gateway "ip4"}:13000"}
        thresholds = json.loads('${builtins.toJSON fragmentMTU}')
        # strongSwan's name of each kex entry
        swan_suites = {"x25519+mlkem768": "CURVE_25519/KE1_ML_KEM_768", "p384+mlkem1024": "ECP_384/KE1_ML_KEM_1024"}

        def cut_both_ways(exchange, threshold, swan_since, ranet3_since, swan_splits):
            """ranet3 cut its request of exchange to the path and strongSwan reassembled it, and where swan_splits holds strongSwan split its response and ranet3 reassembled it"""
            client.wait_until_succeeds(
                f"{ranet3_since} | grep -F 'ike sending a message in fragments' | grep -F 'exchange={exchange}' | grep -F 'threshold={threshold}'",
                timeout=timeout)
            print(client.succeed(
                f"ranet3 debug wait ike.message.fragmented --attr exchange={exchange} --attr threshold={threshold} --past 10m --timeout 1s"))
            gateway.wait_until_succeeds(f"{swan_since} | grep -F 'reassembled fragmented IKE message'", timeout=timeout)
            if swan_splits:
                gateway.wait_until_succeeds(
                    f"{swan_since} | grep -E 'splitting IKE message \\([0-9]+ bytes\\) into [0-9]+ fragments'", timeout=timeout)
                client.wait_until_succeeds(
                    f"{ranet3_since} | grep -F 'ike reassembled a message from fragments' | grep -F 'exchange={exchange}'",
                    timeout=timeout)

        try:
            for machine, peer in [(client, "${underlayAddress nodes.gateway "ip4"}"), (gateway, "${underlayAddress nodes.client "ip4"}")]:
                machine.succeed("ip link show eth1 | grep -F 'mtu ${toString fragmentMTU.ip6} '")
                machine.succeed(f"ip -4 route show {peer}/32 | grep -E 'mtu (lock )?${toString fragmentMTU.ip4}'")

            family = "${underlay}"
            for phase in phases:
                name, phase_family, kex = phase["name"], phase["family"], phase["kex"]
                suite, remote, threshold = swan_suites[kex], remotes[phase_family], thresholds[phase_family]
                # each ML-KEM-1024 response passes strongSwan's fragment_size of 1280
                swan_splits = kex.endswith("+mlkem1024")
                if name is None:
                    swan_since, ranet3_since = swan_log, ranet3_log
                else:
                    swan_since = journal_after(gateway, "strongswan-swanctl.service")
                    ranet3_since = journal_after(client, "ranet3.service")
                    status, output = client.execute(
                        f"${nodes.client.system.build.toplevel}/specialisation/{name}/bin/switch-to-configuration test 2>&1")
                    print(output)
                    if phase_family == family:
                        # a reload applies the kex list and rekeys the IKE SA whose entry it removed, keeping the session
                        assert status == 0, f"the switch into {name} exited with {status}"
                        session_runs({"ike_kex": kex, "remote": remote, "ike_fragments": True, "ike_fragment_threshold": threshold})
                        session = json.loads(client.succeed("ranet3 sessions --json"))[0]
                        print(client.succeed(
                            f"ranet3 debug wait ike.rekey.completed --attr sa=ike --attr suite={session['ike_cipher']}/{session['ike_prf']}/{kex} --past 10m --timeout {rekey_timeout.seconds}s"))
                        cut_both_ways("IKE_FOLLOWUP_KE", threshold, swan_since, ranet3_since, swan_splits)
                        client.fail(f"{ranet3_since} | grep -F ': connected (SPI'")
                        swan_since = journal_after(gateway, "strongswan-swanctl.service")
                        ranet3_since = journal_after(client, "ranet3.service")
                    # the endpoints are read at the start, and a restart dials with the phase's entry
                    client.succeed("systemctl restart ranet3.service")
                    client.wait_until_succeeds("ranet3 sessions --json", timeout=timeout)
                    family = phase_family

                # the session view says both ends support RFC 7383 fragmentation and the threshold ranet3 cuts at
                session_runs({"ike_kex": kex, "remote": remote, "ike_fragments": True, "ike_fragment_threshold": threshold})
                gateway.wait_until_succeeds(f"swanctl --list-sas | grep -F '{suite}'", timeout=timeout)
                # the handshake runs ML-KEM in IKE_INTERMEDIATE
                cut_both_ways("IKE_INTERMEDIATE", threshold, swan_since, ranet3_since, swan_splits)
                for address in ["${gatewayTunnel}", "${gatewayTunnelV4}"]:
                    client.wait_until_succeeds(f"ping -c 1 {address}", timeout=timeout)

            client.fail(f"{ranet3_log} | grep -F 'no matching inbound ESP SA'")
            client.fail(f"{ranet3_log} | grep -F 'ike stopping ESP on a Child SA past its lifetime'")
            client.fail(f"{ranet3_log} | grep -F 'ike dropped the fragments of a message the peer left incomplete'")
            gateway.fail(f"{swan_log} | grep -E 'integrity check failed|no CHILD_SA built|AUTHENTICATION_FAILED|N[(]INVAL_SPI[)]'")
        finally:
            print(gateway.execute("swanctl --list-sas")[1])
            print(gateway.execute(f"{swan_log} | grep -E '{swan_lines}|fragment|splitting'")[1])
            print(client.execute("ranet3 sessions")[1])
            print(client.execute("ranet3 debug events --kind ike")[1])
      '';

      # what ranet3 holds beside another program, read after the program is up and after each disturbance
      besideCommon = ''
        import json

        def last_pass(capability):
            """when the last pass of capability's status ended, or None while the control socket does not answer"""
            code, output = client.execute("ranet3 status --json")
            return json.loads(output)[capability].get("pass_at") if code == 0 else None

        def two_passes(capability="kernel"):
            """two passes of capability that ended after the call, the second begun after it, its period apart at most"""
            seen = [last_pass(capability)]

            def moved(last_try):
                at = last_pass(capability)
                if at is not None and at != seen[-1]:
                    seen.append(at)
                return len(seen) == 3

            retry(moved, timeout=timeout)

        def untaken():
            """the rules view, the status and the gauges read no lookup taken, and what the rules view and the status hold"""
            rules = json.loads(client.succeed("ranet3 debug rules --json"))
            lookups = rules.get("lookups") or []
            print(json.dumps(lookups, indent=2))
            taken = [l for l in lookups if l["taken"]]
            assert not taken, f"another program's rule takes {taken}:\n{client.execute('ranet3 status')[1]}"

            kernel = json.loads(client.succeed("ranet3 status --json"))["kernel"]
            assert not kernel.get("taken"), f"the status reads taken {kernel['taken']}:\n{client.execute('ranet3 status')[1]}"
            text = client.succeed("ranet3 status")
            assert "taken" not in text, text

            asked = {kind: sorted({l["family"] for l in lookups if l["lookup"] == kind}) for kind in ["overlay", "underlay"]}
            metrics = client.succeed("curl -sf http://127.0.0.1:9669/metrics").splitlines()
            for kind, families in asked.items():
                for family in families:
                    want = f'ranet3_kernel_{kind}_taken{{family="{family}"}} 0'
                    assert want in metrics, f"the scrape does not carry {want}"
            return rules, kernel, asked

        def holds_beside():
            """the mesh reaches the gateway, and no lookup of the reconciler's finds another program's rule ahead of ranet3's"""
            for address in ["${gatewayTunnel}", "${gatewayTunnelV4}"]:
                try:
                    client.wait_until_succeeds(f"ping -c 1 -W 2 {address}", timeout=timeout)
                except Exception:
                    untaken()
                    raise AssertionError(f"the mesh does not reach {address}:\n{client.execute('ranet3 status')[1]}")
            two_passes()

            rules, kernel, asked = untaken()
            assert not rules.get("policy_err"), f"the policy rules read back with {rules['policy_err']}"
            assert not rules.get("missing"), f"the kernel lacks derived rules: {rules['missing']}"
            assert asked["overlay"] == ["ipv4", "ipv6"], f"the overlay was looked up in {asked['overlay']}"
            assert asked["underlay"], "no live session's endpoint was looked up"
            assert kernel["enabled"], kernel
            assert not kernel.get("err"), kernel

            # a pass whose lookups fail keeps the last answers and logs the failure once, until one succeeds again
            invocation = client.succeed("systemctl show -P InvocationID ranet3.service").strip()
            journal = client.succeed(f"journalctl _SYSTEMD_INVOCATION_ID={invocation} -o cat --no-pager").splitlines()
            assert journal, f"the journal holds nothing of ranet3's invocation {invocation}"
            failed = [i for i, line in enumerate(journal) if "could not ask where its overlay and underlay lookups end" in line]
            again = [i for i, line in enumerate(journal) if "can ask where its overlay and underlay lookups end again" in line]
            assert not failed or (again and again[-1] > failed[-1]), (
                f"the lookups read are kept from before a pass that could not ask them:\n{journal[failed[-1]]}")
            return rules["lookups"]

        def policy_rules(mine):
            """the policy rules of both families that are ranet3's, or that are not"""
            return [
                line
                for family in ["-4", "-6"]
                for line in client.succeed(f"ip {family} rule show").splitlines()
                if (f"proto {kernel_protocol}" in line) == mine
            ]

        def their_rules():
            """the policy rules and netfilter tables that are not ranet3's, without counters and set elements"""
            rules = policy_rules(False)
            tables, theirs = [], True
            for line in client.succeed("nft -s -t list ruleset").splitlines():
                if line.startswith("table "):
                    theirs = line.split()[2] != "ranet3"
                if theirs:
                    tables.append(line)
            return rules, tables

        def restart_ranet3():
            """ranet3 restarted changes nothing of the other program's, and holds beside it again"""
            before = their_rules()
            client.succeed("systemctl restart ranet3.service")
            holds_beside()
            after = their_rules()
            assert after == before, f"ranet3's restart changed another program's rules:\n{before}\nthen\n{after}"
      '';

      exitMode = ''
        def exit_mode():
            """the client holds the gateway's default in both families and runs cap.exit's rules"""
            gateway.succeed("birdc enable exit4", "birdc enable exit6")
            for family in ["-4", "-6"]:
                client.wait_until_succeeds(f"ip {family} route show table {kernel_table} | grep -q '^default '", timeout=timeout)
            client.succeed("${nodes.client.system.build.toplevel}/specialisation/exit/bin/switch-to-configuration test")
            for family in ["-4", "-6"]:
                client.wait_until_succeeds(f"ip {family} rule show | grep -q 'from all iif lo lookup {kernel_table} '", timeout=timeout)

        def leaves_by_mesh_exit(name, ping, families=("ipv4", "ipv6"), lookup=""):
            """the lookup of the far side of the mesh's exit takes the catch-all at 5440 into the mesh's table ahead of
            main's default, and what ping sends there enters the mesh from the tun's own address"""
            for family in families:
                flag, filter, source, destination = {
                    "ipv4": ("-4", "icmp[icmptype] = icmp-echo", "${clientTunnelV4}", "${meshExitV4}"),
                    "ipv6": ("-6", "icmp6 and ip6[40] = 128", "${clientTunnel}", "${meshExitV6}"),
                }[family]
                rules = client.succeed(f"ip {flag} rule show")
                route = client.succeed(f"ip route get {destination}{lookup}")
                assert f"dev ${clientDevice} table {kernel_table} " in route, (
                    f"the {name}'s lookup of {destination} does not take the catch-all at 5440 into table {kernel_table}:\n{route}\n{rules}")
                try:
                    client.wait_until_succeeds(f"{ping} -c 1 -W 2 {destination}", timeout=timeout)
                except Exception:
                    raise AssertionError(f"the {name}'s traffic does not reach {destination} beyond the mesh's exit:\n{rules}")
                try:
                    capture = capture_while(
                        gateway, "swan0", f"{name}-{family}", f"{filter} and dst host {destination}", 1,
                        lambda: client.succeed(f"{ping} -c 1 -W 2 {destination}"))
                except Exception:
                    gateway.execute("pkill -x tcpdump")
                    raise AssertionError(f"the {name}'s traffic to {destination} did not enter the mesh:\n{rules}")
                print(capture)
                assert f"{source} > {destination}" in capture, f"the {name}'s traffic did not enter the mesh from {source}:\n{capture}"
      '';

      besideScript = {
        # Docker beside an exit: a container reaches outside the mesh by main's route and inside it through the tun
        # under Docker's own masquerade, and the exit's translation at 99 runs ahead of Docker's nat POSTROUTING at 100
        docker = exitTranslates + ''
          ${exitMode}
          # an empty image, and the VM's own store and programs in the container
          docker_run = "docker run --rm -v /nix/store:/nix/store -v /run/current-system/sw/bin:/bin scratch"
          ranet3_tables = ["inet", "ip", "ip6"]

          def behind_reached():
              """the gateway routes behind's network by the client's announcement and reaches behind through the exit,
              with what the gateway and the client hold printed at each try that does not"""
              def reached(_):
                  route = gateway.succeed("ip -4 route show ${exitNetV4}")
                  code, _ = gateway.execute("ping -c 1 -W 1 -I ${gatewayTunnelV4} ${behindV4}")
                  if code != 0:
                      print(gateway.execute("date +%T.%N; ip -4 route show ${exitNetV4}; birdc show route for ${behindV4} all")[1])
                      print(client.execute("date +%T.%N; ip -4 route get ${gatewayTunnelV4} from ${behindV4} iif eth1; ip -4 route show table 200")[1])
                  return "dev swan0" in route and code == 0

              try:
                  retry(reached, timeout=timeout)
              except Exception:
                  route = gateway.execute("ip -4 route show ${exitNetV4}")[1]
                  if "dev swan0" not in route:
                      raise AssertionError(f"the gateway holds no route to ${exitNetV4} by the client:\n{gateway.execute('birdc show route all')[1]}")
                  raise AssertionError(f"the gateway routes ${exitNetV4} by the client and does not reach ${behindV4}:\n{route}")

          def exit_holds():
              """the exit translates for the mesh beside Docker's chains, and finds no other translation that runs ahead of its own"""
              behind_reached()
              exit_translates()
              two_passes("egress")
              egress = json.loads(client.succeed("ranet3 status --json"))["egress"]
              print(json.dumps(egress, indent=2))
              assert egress["ready"] == ["ipv4", "ipv6"], egress
              assert not egress.get("conflicts"), f"another program's source translation runs at or ahead of the exit's: {egress['conflicts']}"
              metrics = client.succeed("curl -sf http://127.0.0.1:9669/metrics").splitlines()
              assert "ranet3_egress_conflicts 0" in metrics, "the scrape does not carry ranet3_egress_conflicts 0"
              tables = client.succeed("nft list tables").splitlines()
              for want in [f"table {family} ranet3" for family in ranet3_tables] + ["table ip nat", "table ip filter"]:
                  assert want in tables, f"{want} is not among {tables}"

          def docker_works():
              """a container reaches behind outside the mesh, and the gateway's tunnel address as the client's own tun address,
              and the gateway reaches the container through its published port"""
              try:
                  client.wait_until_succeeds(f"{docker_run} ping -c 1 -W 2 ${behindV4}", timeout=timeout)
              except Exception:
                  raise AssertionError(f"a container does not reach ${behindV4} outside the mesh:\n{client.execute('ip -4 rule show')[1]}")
              try:
                  capture = capture_while(
                      gateway, "swan0", "docker", "icmp[icmptype] = icmp-echo", 1,
                      lambda: client.wait_until_succeeds(f"{docker_run} ping -c 1 -W 2 ${gatewayTunnelV4}", timeout=timeout))
              except Exception:
                  gateway.execute("pkill -x tcpdump")
                  raise AssertionError(f"a container does not reach ${gatewayTunnelV4} through the mesh:\n{client.execute('ip -4 rule show')[1]}")
              print(capture)
              assert "${clientTunnelV4} > ${gatewayTunnelV4}" in capture, f"the gateway did not see the client's tun address:\n{capture}"
              try:
                  gateway.wait_until_succeeds(
                      "curl -sf -m 2 http://${nodes.client.networking.primaryIPAddress}:8080/ | grep -qx beside", timeout=timeout)
              except Exception:
                  raise AssertionError(f"the gateway does not reach the container through its published port 8080:\n{client.execute('ip -4 rule show')[1]}")

          def mode_off():
              """the exit and a container hold beside Docker's chains with no cap.exit"""
              exit_holds()
              docker_works()

          def exit_arm():
              """under cap.exit the host's own traffic and a container's leave through the mesh's exit, beside Docker's chains"""
              exit_holds()
              docker_works()
              leaves_by_mesh_exit("host", "ping")
              web = client.succeed("docker inspect -f '{{.NetworkSettings.Networks.bridge.IPAddress}}' web").strip()
              leaves_by_mesh_exit("container", f"{docker_run} ping", ["ipv4"], f" from {web} iif docker0")

          def ranet3_rules():
              return [client.succeed(f"nft -s -t list table {family} ranet3") for family in ranet3_tables]

          def disturbed(reading):
              """reading holds after Docker's restart, which leaves ranet3's tables as they were, and after ranet3's"""
              tables = ranet3_rules()
              client.succeed("systemctl restart docker.service")
              holds_beside()
              reading()
              assert ranet3_rules() == tables, "Docker's restart changed ranet3's tables"
              restart_ranet3()
              reading()

          try:
              gateway.wait_for_unit("systemd-networkd-wait-online.service")
              gateway.wait_for_unit("strongswan-swanctl.service")
              gateway.wait_for_unit("bird.service")
              for address in ["${behindV4}", "${behindV6}"]:
                  behind.wait_until_succeeds(f"ip addr show dev eth1 | grep -qF {address}", timeout=timeout)
              client.wait_for_unit("docker.service")
              client.wait_for_unit("ranet3.service")
              client.succeed("tar c --files-from /dev/null | docker import - scratch")
              client.succeed(
                  "docker run -d --name web --restart always -p 8080:80 -v /nix/store:/nix/store scratch"
                  " ${pkgs.busybox}/bin/busybox httpd -f -p 80 -h ${pkgs.writeTextDir "index.html" "beside\n"}")

              holds_beside()
              mode_off()
              disturbed(mode_off)

              exit_mode()
              holds_beside()
              exit_arm()
              disturbed(exit_arm)
          finally:
              print(client.execute("ranet3 status")[1])
              print(client.execute("nft list ruleset")[1])
              print(client.execute("ip -4 rule show")[1])
        '';

        # Tailscale at its default base, its rules at 5210 to 5270 between ranet3's two blocks, first with no exit node
        # and then with peer as its exit node, whose default in table 52 meets an overlay address only after 5110 answered it
        tailscale = captureWhile + ''
          ${exitMode}
          login = "--login-server http://peer:8080 --accept-dns=false"
          renames = iter(range(1, 100))
          tailscale_priorities = ["5210", "5230", "5250", "5270"]

          def tailscale_rules():
              """tailscaled has put back none of its rules another program deleted, and its 4 rules sit beside ranet3's in both families"""
              restored = client.execute(f"{tailscaled_journal} | grep 'deleted ip rules; restoring'")[1]
              assert not restored, f"another program deleted Tailscale's rules:\n{restored}"
              for family in ["-4", "-6"]:
                  rules = client.succeed(f"ip {family} rule show")
                  for priority in tailscale_priorities:
                      assert f"\n{priority}:" in rules, f"Tailscale's rule at {priority} is missing:\n{rules}"

          def through_tailscale(address):
              """the host's own lookup of address ends in Tailscale's table 52 by tailscale0"""
              route = client.succeed(f"ip route get {address}")
              assert "dev tailscale0 table 52 " in route, f"Tailscale's table 52 does not route the host's own traffic to {address}:\n{route}"

          def tailscale_works(exit_node):
              """each node reaches the other through Tailscale, and with the exit node the client reaches the address only peer answers"""
              for machine, other in [(client, peer_ips), (peer, client_ips)]:
                  machine.wait_until_succeeds(f"tailscale ping -c 1 {other[0]}", timeout=timeout)
                  for address in other:
                      machine.wait_until_succeeds(f"ping -c 1 -W 2 {address}", timeout=timeout)
              if exit_node:
                  client.wait_until_succeeds("ping -c 1 -W 2 ${exitOnlyV4}", timeout=timeout)
                  through_tailscale("${exitOnlyV4}")

          def exit_default():
              """Tailscale's table 52 holds the exit node's default in both families"""
              for family in ["-4", "-6"]:
                  client.wait_until_succeeds(f"ip {family} route show table 52 | grep -q '^default dev tailscale0'", timeout=timeout)

          def underlay_in_main(lookups):
              """the underlay's marked lookups go on past 5270 and end in main, not through Tailscale's exit"""
              underlay = [l for l in lookups if l["lookup"] == "underlay"]
              assert all(l["answer"].startswith("table main ") and "dev tailscale0" not in l["answer"] for l in underlay), (
                  f"the underlay's lookups do not end in main: {underlay}")

          def controlled():
              """the client still takes the control server's updates: a name headscale gives peer reaches it"""
              name = f"r{next(renames)}peer"
              peer.succeed(f"headscale nodes rename --identifier {peer_node} {name}")
              try:
                  client.wait_until_succeeds(
                      f"tailscale status --json | jq -e 'any(.Peer[]; .DNSName | split(\".\")[0] == \"{name}\")'", timeout=timeout)
              except Exception:
                  raise AssertionError(
                      f"the client no longer takes the control server's updates:\n{client.execute(f'{tailscaled_journal} | tail -n 20')[1]}")

          try:
              peer.wait_for_unit("headscale.service")
              peer.wait_for_open_port(8080)
              for machine in [client, peer]:
                  machine.wait_for_unit("tailscaled.service")
              # networkd deletes every rule it did not ask for, Tailscale's among them, as it configures a link, and
              # tailscaled logs that it restores them before it adds them again, so the journal is read from once
              # networkd has configured the uplink and the tun and Tailscale's IPv4 rules are all in place, and once
              # journald has written what it was sent, since the cursor is the last entry it has written
              try:
                  client.wait_until_succeeds(
                      "networkctl list --no-legend > /tmp/links"
                      " && [ \"$(grep -Ew 'eth1|${clientDevice}' /tmp/links | grep -cw configured)\" -eq 2 ]"
                      " && ! grep -Eqw 'pending|initialized|configuring' /tmp/links", timeout=timeout)
              except Exception:
                  raise AssertionError(f"networkd has not configured eth1 and ${clientDevice}:\n{client.execute('networkctl list')[1]}")
              try:
                  client.wait_until_succeeds(
                      f"[ \"$(ip -4 rule show | grep -cE '^({'|'.join(tailscale_priorities)}):')\" -eq {len(tailscale_priorities)} ]",
                      timeout=timeout)
              except Exception:
                  raise AssertionError(f"Tailscale's IPv4 rules are not all in place:\n{client.execute('ip -4 rule show')[1]}")
              client.succeed("journalctl --sync")
              tailscaled_journal = journal_after(client, "tailscaled.service")
              client.wait_for_unit("ranet3.service")

              peer.succeed("headscale users create example")
              user = json.loads(peer.succeed("headscale users list -o json"))[0]["id"]
              key = json.loads(peer.succeed(f"headscale preauthkeys create --user {user} --reusable -o json"))["key"]
              peer.succeed(f"tailscale up {login} --auth-key {key} --advertise-exit-node")
              client.succeed(f"tailscale up {login} --auth-key {key}")
              peer_ips = peer.succeed("tailscale ip").split()
              client_ips = client.succeed("tailscale ip").split()
              peer_node = [n["id"] for n in json.loads(peer.succeed("headscale nodes list -o json")) if n["name"] == "peer"][0]

              # (a) no exit node: table 52 holds Tailscale's own addresses alone
              tailscale_works(False)
              holds_beside()
              tailscale_rules()
              controlled()

              # (b) peer as the exit node, with the LAN left to main, so the underlay's marked lookup goes on past 5270
              peer.succeed(f"headscale nodes approve-routes --identifier {peer_node} --routes 0.0.0.0/0,::/0")
              client.wait_until_succeeds(f"tailscale set --exit-node={peer_ips[0]} --exit-node-allow-lan-access", timeout=timeout)
              exit_default()
              underlay_in_main(holds_beside())
              tailscale_works(True)
              controlled()

              client.succeed("systemctl restart tailscaled.service")
              exit_default()
              underlay_in_main(holds_beside())
              tailscale_works(True)
              tailscale_rules()
              controlled()

              restart_ranet3()
              tailscale_works(True)
              tailscale_rules()
              controlled()

              # (c) cap.exit, first with Tailscale's exit node in use: its table at 5270 takes the host's own traffic ahead of 5440
              theirs = their_rules()
              exit_mode()
              exit_default()
              for address in peer_ips + ["${meshExitV4}", "${meshExitV6}"]:
                  through_tailscale(address)
              underlay_in_main(holds_beside())
              tailscale_works(True)
              tailscale_rules()
              assert their_rules() == theirs, f"cap.exit changed another program's rules:\n{theirs}\nthen\n{their_rules()}"
              controlled()

              # then with no exit node of Tailscale's: the host's own traffic leaves through the mesh's exit by 5440,
              # and Tailscale's own addresses through its table at 5270
              client.succeed("tailscale set --exit-node=")
              for family in ["-4", "-6"]:
                  client.wait_until_fails(f"ip {family} route show table 52 | grep -q '^default '", timeout=timeout)
              underlay_in_main(holds_beside())
              tailscale_works(False)
              leaves_by_mesh_exit("host", "ping")
              tailscale_rules()
              controlled()

              # sorted, since ranet3 takes its rules for tailscale0's addresses down and back with the link, and a rule
              # put back is listed after the others at its priority
              before = sorted(policy_rules(True))
              client.succeed("systemctl restart tailscaled.service")
              tailscale_works(False)
              underlay_in_main(holds_beside())
              after = sorted(policy_rules(True))
              assert after == before, f"ranet3's rules are not as they were once Tailscale is back:\n{before}\nthen\n{after}"
              leaves_by_mesh_exit("host", "ping")
              tailscale_rules()
              controlled()

              restart_ranet3()
              tailscale_works(False)
              leaves_by_mesh_exit("host", "ping")
              tailscale_rules()
              controlled()
          finally:
              print(client.execute("ranet3 status")[1])
              print(client.execute("tailscale status")[1])
              for family in ["-4", "-6"]:
                  print(client.execute(f"ip {family} route show table main")[1])
              for family in ["-4", "-6"]:
                  print(client.execute(f"ip {family} rule show")[1])
                  print(client.execute(f"ip {family} route show table 52")[1])
        '';

        # k3s with kube-proxy in iptables mode and flannel: kube-proxy masquerades a packet whose mark holds its masqueradeBit 0x4000,
        # with --random-fully, so the gateway reading the client at its own port 14000 shows the underlay's mark left that bit clear
        k3s = ''
          k3s_timeout = dt.timedelta(minutes=5)

          def underlay_port():
              """the gateway reads ranet3's underlay at the port it sends from, untranslated by kube-proxy"""
              gateway.wait_until_succeeds("swanctl --list-sas | grep -q ESTABLISHED", timeout=timeout)
              sas = gateway.succeed("swanctl --list-sas")
              remotes = [line.strip() for line in sas.splitlines() if line.strip().startswith("remote '")]
              assert remotes and all(line.endswith("@ ${nodes.client.networking.primaryIPAddress}[14000]") for line in remotes), (
                  f"the gateway reads the client at another port than 14000: {remotes}")

          def k3s_works():
              """flannel's masquerade is in place, a pod reaches another through its service's address and the gateway through the tun, and the host reaches a pod by main's route"""
              client.wait_until_succeeds("nft list chain ip nat FLANNEL-POSTRTG | grep -qi masquerade", timeout=k3s_timeout)
              client.wait_until_succeeds("kubectl wait --for condition=Ready node --all --timeout=10s", timeout=k3s_timeout)
              client.wait_until_succeeds("kubectl wait --for condition=Ready pod/server pod/client --timeout=10s", timeout=k3s_timeout)
              service = client.succeed("kubectl get service server -o jsonpath='{.spec.clusterIP}'").strip()
              client.wait_until_succeeds(f"kubectl exec client -- wget -qO- -T 2 http://{service} | grep -qx beside", timeout=timeout)
              client.wait_until_succeeds("kubectl exec client -- ping -c 1 -W 2 ${gatewayTunnelV4}", timeout=timeout)
              pod = client.succeed("kubectl get pod server -o jsonpath='{.status.podIP}'").strip()
              route = client.succeed(f"ip route get {pod}")
              assert "table" not in route and "${clientDevice}" not in route, f"the host does not reach a pod by main's route:\n{route}"
              client.succeed(f"ping -c 1 -W 2 {pod}")

          try:
              gateway.wait_for_unit("systemd-networkd-wait-online.service")
              gateway.wait_for_unit("strongswan-swanctl.service")
              gateway.wait_for_unit("bird.service")
              client.wait_for_unit("k3s.service")
              client.wait_until_succeeds("nft list chain ip nat KUBE-POSTROUTING | grep -qi masquerade", timeout=k3s_timeout)
              client.succeed("systemctl start ranet3.service")
              k3s_works()
              holds_beside()
              underlay_port()

              k3s_journal = journal_after(client, "k3s.service")
              client.succeed("systemctl restart k3s.service")
              client.wait_until_succeeds(f"[ \"$({k3s_journal} | grep -c 'bootstrap done')\" -ge 2 ]", timeout=k3s_timeout)
              k3s_works()
              holds_beside()
              underlay_port()

              restart_ranet3()
              underlay_port()
              k3s_works()
          finally:
              print(client.execute("ranet3 status")[1])
              print(gateway.execute("swanctl --list-sas")[1])
              print(client.execute("nft list table ip nat")[1])
              print(client.execute("kubectl get pods -o wide")[1])
        '';
      };
    in
    preamble
    + (
      if beside != null then
        besideCommon + besideScript.${beside}
      else if suites == "meet" then
        suitesMeet
      else if suites == "apart" then
        suitesApart
      else if mlkem == "meet" then
        mlkemCommon + mlkemMeet
      else if mlkem == "apart" then
        mlkemCommon + mlkemApart
      else if mlkem == "fallback" then
        mlkemCommon + mlkemFallback
      else if fragment then
        mlkemCommon + mlkemFragment
      else if mlkem != null then
        mlkemCommon + mlkemAnswered
      else if responder then
        responderScript
      else if egressSegment then
        egressSegmentScript
      else if segments then
        segmentRouted
      else if egress then
        exitTranslates + exitNode
      else
        initiator
    );
}
