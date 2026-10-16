# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: FSL-1.1-ALv2

# The netlink round trips in internal/kernel and internal/egress need root and
# a network namespace to make a mess in, so they skip themselves under the go
# check, which builds as an unprivileged user. That left every rule and VRF
# write, the FRA_PROTOCOL ownership they rest on, and every byte of the
# nf_tables encoding asserted nowhere any check ran. These are the same test
# binaries, run as root against a real kernel.
# internal/netstack's tun round trips run here for the same reason
# and so does transport's send through a path whose mtu is locked
# and the tun and conn packages of pkgs/wireguard
{
  lib,
  iproute2,
  nftables,
  ranet3,
  testers,
  wireguard,
  writableTmpDirAsHomeHook,
}:

let
  netlinkTests = ranet3.overrideAttrs (prev: {
    pname = "ranet3-netlink-tests";
    nativeBuildInputs = prev.nativeBuildInputs ++ [ writableTmpDirAsHomeHook ];
    buildPhase = ''
      go test -c -o netlink-tests ./internal/kernel/
      go test -c -o egress-tests ./internal/egress/
      go test -c -o netstack-tests ./internal/netstack/
      go test -c -o client-tests ./internal/client/
      go test -c -o transport-tests ./transport/
    '';
    installPhase = ''
      install -Dm755 netlink-tests "$out/bin/netlink-tests"
      install -Dm755 egress-tests "$out/bin/egress-tests"
      install -Dm755 netstack-tests "$out/bin/netstack-tests"
      install -Dm755 client-tests "$out/bin/client-tests"
      install -Dm755 transport-tests "$out/bin/transport-tests"
    '';
  });
  wireguardTests = wireguard.overrideAttrs (prev: {
    pname = "wireguard-root-tests";
    nativeBuildInputs = prev.nativeBuildInputs ++ [ writableTmpDirAsHomeHook ];
    buildPhase = ''
      go test -c -o tun-tests ./tun/
      go test -c -o conn-tests ./conn/
    '';
    installPhase = ''
      install -Dm755 tun-tests "$out/bin/tun-tests"
      install -Dm755 conn-tests "$out/bin/conn-tests"
    '';
  });
in
testers.runNixOSTest {
  name = "ranet3-netlink";

  meta.platforms = lib.platforms.linux;

  # The tests build their own namespaces, links, rules and tables, so the
  # machine needs nothing but a kernel, root, and iproute2 and nft to read the
  # result back with.
  nodes.machine.environment.systemPackages = [
    iproute2
    nftables
  ];

  testScript = ''
    machine.wait_for_unit("multi-user.target")

    # The host's own nftables tables, whatever they are. This machine runs the
    # NixOS firewall through iptables-nft, so four of them are here before
    # anything under test has run, and the assertion below has to be about this
    # tool's own name rather than about the ruleset being empty.
    def foreign():
        return [t for t in machine.succeed("nft list tables").splitlines() if "ranet3" not in t]

    before = foreign()
    print("the host's own tables:", before)

    # -test.v so a failure names the round trip rather than the package, and
    # the count so a pass here means the binary ran them rather than skipping
    # them for the same reason the go check does.
    out = machine.succeed(
        "${netlinkTests}/bin/netlink-tests -test.v -test.run 'TestNetlink' 2>&1"
    )
    print(out)
    assert "SKIP" not in out, f"the tests skipped themselves under root:\n{out}"
    ran = out.count("--- PASS")
    assert ran >= 4, f"only {ran} netlink round trips ran:\n{out}"

    # The nf_tables half. A fake backend can only ever agree with the encoder
    # it was written beside, so what the kernel accepts, and the spelling it
    # hands back for a diff to compare against, is checked here and nowhere
    # else short of the full exit node arm.
    out = machine.succeed(
        "${netlinkTests}/bin/egress-tests -test.v -test.run 'TestNftablesRoundTrip' 2>&1"
    )
    print(out)
    assert "SKIP" not in out, f"the nftables round trip skipped itself under root:\n{out}"
    assert "--- PASS" in out, f"the nftables round trip did not run:\n{out}"

    # the tun round trips create a device, attach to one and read its gso limit back
    # refuse a mesh under the default name where a device of that name is there
    # and open several lanes as one device
    out = machine.succeed(
        "${netlinkTests}/bin/netstack-tests -test.v -test.run 'TestTUN' 2>&1"
    )
    print(out)
    assert "SKIP" not in out, f"the tun round trips skipped themselves under root:\n{out}"
    ran = out.count("--- PASS")
    assert ran >= 28, f"only {ran} tun round trips ran:\n{out}"

    # the client's tun round trips
    # among them a TCP stream through a black hole a session's search finds
    # a veth pair to a second namespace whose far end drops what it cannot take and answers nothing
    out = machine.succeed(
        "${netlinkTests}/bin/client-tests -test.v -test.run 'TestTUN' 2>&1"
    )
    print(out)
    assert "SKIP" not in out, f"the client's tun round trips skipped themselves under root:\n{out}"
    ran = out.count("--- PASS")
    assert ran >= 10, f"only {ran} of the client's tun round trips ran:\n{out}"

    # every datagram sent with DF and the path mtu a refused one reports, against linux itself
    # and a family's socket fragmenting past the path only while a session of the family asks
    # a veth pair to a second namespace behind routes whose path mtu is locked below the datagram size
    # and an IPv4 datagram its route carries leaving without DF while the family fragments, read off loopback
    out = machine.succeed(
        "${netlinkTests}/bin/transport-tests -test.v -test.run 'TestKernel(RefusesWhatALockedPathCannotCarry|FragmentsPastALockedPathOnlyWhileTheFamilyAsks|SendsWithoutDFWhatTheRouteCarriesWhileIPv4Fragments)' 2>&1"
    )
    print(out)
    assert "SKIP" not in out, f"the kernel send tests skipped themselves under root:\n{out}"
    ran = out.count("--- PASS")
    assert ran >= 3, f"only {ran} of the kernel send tests ran:\n{out}"

    # two nodes taken down and put back up against linux itself
    # a session moved under the floor handing its fragmenting to the new endpoint's family
    # the refusal of a session's own data past a narrower loopback lowering its budget
    # the transit warning against the forwarding sysctls a namespace of its own is given
    # every goroutine of a node opens sockets and tuns, so the whole process runs in a namespace of its own
    out = machine.succeed(
        "unshare -n ${netlinkTests}/bin/client-tests -test.v -test.run '^TestNode(GoingDown|RestartedWhileDown)|^TestSession(MovedUnderTheFloorHandsItsFragmentingOver|LowersItsBudgetAtTheRefusalOfItsOwnData)|^TestTransitWarnsOnlyWhereTheHostCannotForwardIt' 2>&1"
    )
    print(out)
    assert "SKIP" not in out, f"the client's round trips in a namespace of their own skipped themselves under root:\n{out}"
    ran = out.count("--- PASS")
    assert ran >= 5, f"only {ran} of the client's round trips in a namespace of their own ran:\n{out}"

    out = machine.succeed(
        "${wireguardTests}/bin/tun-tests -test.v 2>&1"
    )
    print(out)
    assert "SKIP" not in out, f"the wireguard tun tests skipped themselves under root:\n{out}"
    ran = sum(1 for line in out.splitlines() if line.startswith("--- PASS"))
    assert ran >= 27, f"only {ran} of the wireguard tun tests ran:\n{out}"
    assert "--- PASS: TestWriteAllocs" in out, f"the write allocation test did not pass:\n{out}"

    out = machine.succeed(
        "${wireguardTests}/bin/conn-tests -test.v 2>&1"
    )
    print(out)
    assert "SKIP" not in out, f"the wireguard conn tests skipped themselves under root:\n{out}"
    ran = sum(1 for line in out.splitlines() if line.startswith("--- PASS"))
    assert ran >= 8, f"only {ran} of the wireguard conn tests ran:\n{out}"
    assert "--- PASS: TestStdNetBindSendRetryWithoutGSO" in out, f"the send retry without GSO did not pass:\n{out}"

    # Nothing the tests wrote may outlive them: they run against the host's own
    # kernel here rather than against a fake, so a rule, a VRF or a table left
    # behind is a leak this check is the only thing positioned to see.
    assert "proto 155" not in machine.succeed("ip rule show; ip -6 rule show")
    machine.fail("ip link show mesh")
    machine.fail("ip link show gsocap0")
    machine.fail("ip link show ranet3")
    links = machine.succeed("ip -br link")
    assert "wgt" not in links, f"a wireguard test tun outlived its test:\n{links}"
    xfrm = machine.succeed("ip xfrm state; ip xfrm policy")
    assert xfrm.strip() == "", f"an xfrm state or policy outlived the namespace it was written in:\n{xfrm}"
    tables = machine.succeed("nft list tables")
    assert "ranet3" not in tables, f"a table outlived the namespace it was written in:\n{tables}"
    # And nothing of the host's went with it: the tests write into a namespace
    # of their own, so the four tables the firewall had are still here.
    assert foreign() == before, f"the host's own tables changed under the tests: {before} then {foreign()}"
  '';
}
