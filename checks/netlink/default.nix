# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: FSL-1.1-ALv2

# The Linux root tests need root and a network namespace to make a mess in, so
# they skip themselves under the go-test and wireguard checks, which build as an
# unprivileged user. These are the same test binaries, each run whole as root
# against a real kernel, and every test each lists passes in one of its runs or
# is named with the reason it passes in none.
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
      go test -c -o egress-tests ./internal/egress/kernel/
      go test -c -o nftables-tests ./internal/nftables/
      go test -c -o suite-tests ./internal/egress/egresstest/
      go test -c -o netstack-tests ./internal/netstack/
      go test -c -o client-tests ./internal/client/
      go test -c -o transport-tests ./transport/
      go test -c -o registry-tests ./internal/registry/
      go test -c -o daemon-tests ./cmd/ranet3/
      go test -c -o netnstest-tests ./internal/netnstest/
      go test -c -o socket-tests ./internal/netlink/
    '';
    installPhase = ''
      install -Dm755 netlink-tests "$out/bin/netlink-tests"
      install -Dm755 egress-tests "$out/bin/egress-tests"
      install -Dm755 nftables-tests "$out/bin/nftables-tests"
      install -Dm755 suite-tests "$out/bin/suite-tests"
      install -Dm755 netstack-tests "$out/bin/netstack-tests"
      install -Dm755 client-tests "$out/bin/client-tests"
      install -Dm755 transport-tests "$out/bin/transport-tests"
      install -Dm755 registry-tests "$out/bin/registry-tests"
      install -Dm755 daemon-tests "$out/bin/daemon-tests"
      install -Dm755 netnstest-tests "$out/bin/netnstest-tests"
      install -Dm755 socket-tests "$out/bin/socket-tests"
    '';
  });
  wireguardTests = wireguard.overrideAttrs (prev: {
    pname = "wireguard-root-tests";
    nativeBuildInputs = prev.nativeBuildInputs ++ [ writableTmpDirAsHomeHook ];
    buildPhase = ''
      go test -c -o tun-tests ./tun/
    '';
    installPhase = ''
      install -Dm755 tun-tests "$out/bin/tun-tests"
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

  nodes.machine.virtualisation.memorySize = 2048;
  # the binaries run whole, so their tests whose senders and readers run at once get several CPUs, as under the go-test
  # check, and veth's GRO coalesces only what a sender on another CPU queues while the near end polls
  nodes.machine.virtualisation.cores = 4;
  # no DHCP client, so nothing but the tests writes the machine's links and routes, and resolv.conf names no nameserver
  # the machine cannot reach, so a name a test looks up fails at once, as in the go-test check's sandbox
  nodes.machine.networking.useDHCP = false;

  # the kill switch's tunnel lab writes a GRE and a WireGuard tunnel, whose modules nothing else here loads
  nodes.machine.boot.kernelModules = [
    "ip_gre"
    "wireguard"
  ];
  # ip_gre would add its fallback devices gre0, gretap0 and erspan0 to every namespace, where the labs read each link
  nodes.machine.boot.kernel.sysctl."net.core.fb_tunnels_only_for_init_net" = 2;

  testScript = ''
    import re

    machine.wait_for_unit("multi-user.target")

    # The host's own nftables tables, whatever they are. This machine runs the
    # NixOS firewall through iptables-nft, so four of them are here before
    # anything under test has run, and the assertion below has to be about this
    # tool's own name rather than about the ruleset being empty.
    def foreign():
        return [t for t in machine.succeed("nft list tables").splitlines() if "ranet3" not in t]

    before = foreign()
    print("the host's own tables:", before)

    # each test binary and its package's directory of the source it was built
    # from, where it runs, so its tests read their testdata as they do there
    binaries = {
        "netlink-tests": ("${netlinkTests}/bin/netlink-tests", "${ranet3.src}/internal/kernel"),
        "egress-tests": ("${netlinkTests}/bin/egress-tests", "${ranet3.src}/internal/egress/kernel"),
        "nftables-tests": ("${netlinkTests}/bin/nftables-tests", "${ranet3.src}/internal/nftables"),
        "suite-tests": ("${netlinkTests}/bin/suite-tests", "${ranet3.src}/internal/egress/egresstest"),
        "netstack-tests": ("${netlinkTests}/bin/netstack-tests", "${ranet3.src}/internal/netstack"),
        "client-tests": ("${netlinkTests}/bin/client-tests", "${ranet3.src}/internal/client"),
        "transport-tests": ("${netlinkTests}/bin/transport-tests", "${ranet3.src}/transport"),
        "registry-tests": ("${netlinkTests}/bin/registry-tests", "${ranet3.src}/internal/registry"),
        "daemon-tests": ("${netlinkTests}/bin/daemon-tests", "${ranet3.src}/cmd/ranet3"),
        "netnstest-tests": ("${netlinkTests}/bin/netnstest-tests", "${ranet3.src}/internal/netnstest"),
        "socket-tests": ("${netlinkTests}/bin/socket-tests", "${ranet3.src}/internal/netlink"),
        "tun-tests": ("${wireguardTests}/bin/tun-tests", "${wireguard.src}/tun"),
    }
    # the tests that pass in no run here, each with the reason, by binary
    crash = "a lab's crash helper, which runs in the process its lab starts and kills, and skips anywhere else"
    named: dict[str, dict[str, str]] = {
        "egress-tests": {"TestBorderCrashHelper": crash},
        "client-tests": {
            "TestEntryLabCrashHelper": crash,
            "TestExitLabCrashHelper": crash,
            "TestKillSwitchLabCrashHelper": crash,
            "TestSaveFailsWhereTheStateDirectoryWillNotSync": "root reads a directory whatever its mode, so the sync the test needs refused succeeds, and the test skips",
        },
    }
    # the subtests a step of these binaries stands on, which the cover of top-level tests leaves out
    subtests = {
        "egress-tests": ["TestKernelExitPassesTheExitBehaviorSuite/a_share_the_capability_names"],
        "client-tests": ["TestTUNKillSwitchHoldsInModeThree/the_antispoof_filter's_chains_the_stop_for_the_mesh's_failure_leaves"],
        "daemon-tests": [
            "TestDaemonStoppedWhileItBuildsStartsNothing/SIGTERM",
            "TestDaemonStoppedWhileItBuildsStartsNothing/SIGINT",
            "TestDaemonForcedOutOfItsBuildByASecondSignal/in_the_build",
            "TestDaemonForcedOutOfItsBuildByASecondSignal/in_the_undo",
            "TestDaemonEndedInItsBuildLeavesTheChainsItFound/refused_at_the_reconciler",
            "TestDaemonEndedInItsBuildLeavesTheChainsItFound/stopped_while_it_builds",
        ],
    }
    passed: dict[str, set[str]] = {binary: set() for binary in binaries}

    def ran(command):
        """runs command, a binary named as in binaries with its flags and maybe a namespace of its own, under -test.v in the binary's directory,
        keeps each test and subtest it passed, and fails on a test it skipped that named does not hold"""
        binary = next(name for name in binaries if re.search(rf"(^| ){name}( |$)", command))
        path, directory = binaries[binary]
        out = machine.succeed(f"cd {directory} && {command.replace(binary, path + ' -test.v', 1)} 2>&1")
        print(out)
        passed[binary].update(re.findall(r"^\s*--- PASS: (\S+)", out, re.M))
        for name in re.findall(r"^\s*--- SKIP: (\S+)", out, re.M):
            assert name.split("/")[0] in named.get(binary, {}), f"{binary} skipped {name} under root:\n{out}"

    def pattern(command):
        """the -test.run pattern of command"""
        return re.findall(r"-test\.run '([^']*)'", command)[0]

    for binary in ["netlink-tests", "egress-tests", "nftables-tests", "suite-tests", "netstack-tests", "transport-tests", "netnstest-tests", "socket-tests", "tun-tests"]:
        ran(binary)

    # every goroutine of a node of these opens sockets and tuns, so the whole process runs in a namespace of its own
    claims = "unshare -n client-tests -test.run '^TestNode(GoingDown|RestartedWhileDown)|^TestSession(MovedUnderTheFloorHandsItsFragmentingOver|LowersItsBudgetAtTheRefusalOfItsOwnData)|^TestDialerTheHostHasNoRouteForDialsAtOnceWhenWoken$'"
    # Go's resolver reads /etc/resolv.conf from whatever thread looks a name up, so each resolver test binds its own over it
    # in a mount namespace the whole process runs in, beside a network namespace for its nameserver on lo, and refuses init's
    resolvers = ["unshare -mn registry-tests -test.run '^TestResolver'", "unshare -mn client-tests -test.run '^TestEndpointQueryFollowsTheOverlayInForceAcrossReloads$'"]
    ran(f"client-tests -test.skip '{pattern(claims)}|{pattern(resolvers[1])}'")
    ran(claims)
    # the daemon claims the process's namespace too
    ran("unshare -n daemon-tests")
    resolv = machine.succeed("cat /etc/resolv.conf")
    ran(f"registry-tests -test.skip '{pattern(resolvers[0])}'")
    for command in resolvers:
        ran(command)
    assert machine.succeed("cat /etc/resolv.conf") == resolv, "a resolver test's resolv.conf reached the host's mount namespace"

    # a test renamed out of every run above, or skipped by a pattern no run takes up, fails here rather than running nowhere
    # and a named test that passed in a run here has lost the reason it is named for
    for binary, (path, _) in binaries.items():
        listed = [name for name in machine.succeed(f"{path} -test.list '.'").split() if not name.startswith("Benchmark")]
        reasons = named.get(binary, {})
        unpassed = [name for name in listed if name not in passed[binary] and name not in reasons]
        assert not unpassed, f"{binary} lists tests that passed in no run here: {unpassed}, and names {reasons}"
        stale = {name: reason for name, reason in reasons.items() if name not in listed or name in passed[binary]}
        assert not stale, f"{binary} names tests it does not list or that passed in a run here, against these reasons: {stale}"
        missing = [name for name in subtests.get(binary, []) if name not in passed[binary]]
        assert not missing, f"{binary} passed none of these subtests: {missing}"

    # Nothing the tests wrote may outlive them: they run against the host's own
    # kernel here rather than against a fake, so a rule, a link or a table left
    # behind is a leak this check is the only thing positioned to see.
    assert "proto 155" not in machine.succeed("ip rule show; ip -6 rule show")
    machine.fail("ip link show gsocap0")
    machine.fail("ip link show ranet3")
    links = machine.succeed("ip -br link")
    assert "wgt" not in links, f"a wireguard test tun outlived its test:\n{links}"
    tables = machine.succeed("nft list tables")
    assert "ranet3" not in tables, f"a table outlived the namespace it was written in:\n{tables}"
    # And nothing of the host's went with it: the tests write into a namespace
    # of their own, so the four tables the firewall had are still here.
    assert foreign() == before, f"the host's own tables changed under the tests: {before} then {foreign()}"
  '';
}
