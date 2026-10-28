# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: FSL-1.1-ALv2

# The netlink round trips in internal/kernel and internal/egress/kernel need root and
# a network namespace to make a mess in, so they skip themselves under the go
# check, which builds as an unprivileged user. That left every rule write, the
# FRA_PROTOCOL ownership it rests on, and every byte of the nf_tables encoding
# asserted nowhere any check ran. These are the same test binaries, run as root
# against a real kernel.
# internal/netstack's tun round trips run here for the same reason
# and internal/nftables's sets and expressions beside nft's own encoding
# and so does transport's send through a path whose mtu is locked
# and the tun and conn packages of pkgs/wireguard
# and internal/registry's and internal/client's tests of the endpoint resolver's mark, through a resolv.conf of their own
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

  nodes.machine.virtualisation.memorySize = 2048;

  # the kill switch's tunnel lab writes a GRE and a WireGuard tunnel, whose modules nothing else here loads
  nodes.machine.boot.kernelModules = [
    "ip_gre"
    "wireguard"
  ];
  # ip_gre would add its fallback devices gre0, gretap0 and erspan0 to every namespace, where the labs read each link
  nodes.machine.boot.kernel.sysctl."net.core.fb_tunnels_only_for_init_net" = 2;

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
    assert "--- PASS: TestNetlinkDumpRulesReadsEveryOwner" in out, f"the rule dump's round trip did not run:\n{out}"
    assert "--- PASS: TestNetlinkRouteGetNamesTheMatchedRouteAndTable" in out, f"the route lookup did not run:\n{out}"
    assert "--- PASS: TestNetlinkRouteGetNamesTheRuleTheLookupTook" in out, f"the rule a lookup took was not named:\n{out}"
    assert "--- PASS: TestNetlinkRouteGetNamesACandidateForAnErrnoRaisedOutsideTheWalk" in out, f"a rule an errno raised outside the walk answers was not named a candidate:\n{out}"
    assert "--- PASS: TestNetlinkRouteGetWalksAnInvertedRuleOfASelectorItDoesNotRead" in out, f"an inverted rule of an unread selector was not walked:\n{out}"
    assert "--- PASS: TestNetlinkRouteGetNamesTheRuleAnExceptionTook" in out, f"the rule an exception took was not named:\n{out}"
    assert "--- PASS: TestNetlinkRouteGetNamesLocalForALocalRouteOfOneTrie" in out, f"the local route of one trie was not named the lookup of local:\n{out}"
    assert "--- PASS: TestNetlinkRouteGetAnswersARouteOfNoTableEntryAsTheKernelsOwn" in out, f"a route of no table entry was not answered as the kernel's own:\n{out}"
    assert "--- PASS: TestNetlinkLookupsReportAnotherProgramsRuleAhead" in out, f"the reconciler's lookups did not run:\n{out}"
    assert "--- PASS: TestNetlinkFollowsAnotherWritersAddressOnTheTun" in out, f"the reconciler's wake on the tun's addresses did not run:\n{out}"
    assert "--- PASS: TestNetlinkFallbackNoneEndsTheWalkAsTheRulesSay" in out, f"fallback = \"none\"'s rules did not run:\n{out}"
    assert "--- PASS: TestNetlinkFallbackTableListsAsNftsOwnAndOutlivesItsWriter" in out, f"the fallback table did not run:\n{out}"
    assert "--- PASS: TestNetlinkFallbackTableAnswersAnotherWritersChangeWithinAPass" in out, f"the fallback table's wake did not run:\n{out}"
    ran = out.count("--- PASS")
    assert ran >= 6, f"only {ran} netlink round trips ran:\n{out}"

    # The nf_tables half. A fake backend can only ever agree with the encoder
    # it was written beside, so what the kernel accepts, and the spelling it
    # hands back for a diff to compare against, is checked here and nowhere
    # else short of the full exit node arm.
    out = machine.succeed(
        "${netlinkTests}/bin/egress-tests -test.v -test.run '^TestNftables(RoundTrip|NotifiesAnotherWritersChange|RewritesAnotherWritersRuleInItsChain|RemakesATableHoldingAStaleTimeout|KeepsTheSetsCountsAcrossARewrite|RemakesATableWhoseSetCountsAnotherLimit|WakesMissedOnAnOverflow|PutsBackAnotherWritersChangeToItsTable|ReportsTheNatChainsAtItsPriorityOrBelow)|^TestBorderRoundTrip(PutsBackWhatAnotherWriterChanged)?$' 2>&1"
    )
    print(out)
    assert "SKIP" not in out, f"the nftables round trips skipped themselves under root:\n{out}"
    assert "--- PASS: TestBorderRoundTrip" in out, f"the border filter's round trip did not run:\n{out}"
    assert "--- PASS: TestNftablesRemakesATableHoldingAStaleTimeout" in out, f"the stale timeout's remake did not run:\n{out}"
    assert "--- PASS: TestNftablesKeepsTheSetsCountsAcrossARewrite" in out, f"the sets' counts across a rewrite did not run:\n{out}"
    assert "--- PASS: TestNftablesRemakesATableWhoseSetCountsAnotherLimit" in out, f"the remake of a set counting another limit did not run:\n{out}"
    assert "--- PASS: TestNftablesReportsTheNatChainsAtItsPriorityOrBelow" in out, f"the report of other nat chains did not run:\n{out}"
    ran = out.count("--- PASS")
    assert ran >= 11, f"only {ran} nftables round trips ran:\n{out}"

    # the encoder's sets, their elements, the lookup, ct with a direction and the set messages of the monitor, each
    # acting on loopback's datagrams, and woken by another writer
    out = machine.succeed(
        "${netlinkTests}/bin/nftables-tests -test.v -test.run '^TestNftables(FilterExpressionsActOnPackets|SetElementsReadBackAndWakeOnAnothersChange)$' 2>&1"
    )
    print(out)
    assert "SKIP" not in out, f"the encoder's round trips skipped themselves under root:\n{out}"
    assert "--- PASS: TestNftablesFilterExpressionsActOnPackets" in out, f"the expressions on packets did not run:\n{out}"
    assert "--- PASS: TestNftablesSetElementsReadBackAndWakeOnAnothersChange" in out, f"the set elements' readback and wake did not run:\n{out}"

    # the exit behavior suite against the kernel exit under each class: rows 1 to 5, Egress from several sessions, the
    # packets no flow is tracked for out of the mesh and into it, the idle timers read from conntrack's listing, the
    # return direction's and an answered flow's among them,
    # filtering and hairpinning as it declares them under the classes that translate, and row 6's limit on a source's
    # flows in both families, the withdrawal and restore, another writer's change, another writer's translation at
    # srcnat made after the exit's and one ahead of it, and the stop, a leaf, the exit, a router and a server in
    # namespaces of their own
    out = machine.succeed(
        "${netlinkTests}/bin/egress-tests -test.v -test.run '^TestKernelExitPassesTheExitBehaviorSuite$' 2>&1"
    )
    print(out)
    assert "SKIP" not in out, f"the exit behavior suite skipped itself under root:\n{out}"
    assert "--- PASS: TestKernelExitPassesTheExitBehaviorSuite" in out, f"the exit behavior suite did not pass:\n{out}"
    assert "--- PASS: TestKernelExitPassesTheExitBehaviorSuite/a_share_the_capability_names" in out, f"row 6 at a share the capability names did not pass:\n{out}"
    ran = out.count("--- PASS")
    assert ran >= 343, f"only {ran} of the exit behavior suite's tests ran:\n{out}"

    # the kernel exit held not ready while the host does not hold an address its classes translate to, in a namespace of
    # its own, each family's taken off lo and put back
    # and its debug read of a rule's counter, from two readers beside passes following one another, and across its stop
    out = machine.succeed(
        "${netlinkTests}/bin/egress-tests -test.v -test.run '^(TestClassAddressTakenOffLoopbackHoldsItsFamilyNotReady|TestDebugReadsARulesCounterWithoutAPass|TestDebugReadsBesidePassesAndAnotherReader|TestDebugReadsAcrossTheExitsStop)$' 2>&1"
    )
    print(out)
    assert "SKIP" not in out, f"the class address's readiness skipped itself under root:\n{out}"
    assert "--- PASS: TestClassAddressTakenOffLoopbackHoldsItsFamilyNotReady" in out, f"the class address's readiness did not pass:\n{out}"
    assert "--- PASS: TestDebugReadsARulesCounterWithoutAPass" in out, f"the debug read of a rule's counter did not pass:\n{out}"
    assert "--- PASS: TestDebugReadsBesidePassesAndAnotherReader" in out, f"the debug reads beside passes and each other did not pass:\n{out}"
    assert "--- PASS: TestDebugReadsAcrossTheExitsStop" in out, f"the debug reads across the exit's stop did not pass:\n{out}"

    # the suite's own fakes of the backends no real one stands for yet, one mapping the leaf's ports and one ending its TCP
    out = machine.succeed(
        "${netlinkTests}/bin/suite-tests -test.v -test.run '^Test(PortMappingBackendMeetsTheRowsThatReadTheMapping|TerminatingBackendMeetsThePathMTURow)$' 2>&1"
    )
    print(out)
    assert "SKIP" not in out, f"the suite's fakes skipped themselves under root:\n{out}"
    assert "--- PASS: TestPortMappingBackendMeetsTheRowsThatReadTheMapping" in out, f"the port mapping fake did not pass:\n{out}"
    assert "--- PASS: TestTerminatingBackendMeetsThePathMTURow" in out, f"the terminating fake did not pass:\n{out}"
    ran = out.count("--- PASS")
    assert ran >= 52, f"only {ran} of the suite's fake tests ran:\n{out}"

    # the tun round trips create a device, attach to one and read its gso limit back
    # refuse a mesh under the default name where a device of that name is there
    # and open several lanes as one device
    out = machine.succeed(
        "${netlinkTests}/bin/netstack-tests -test.v -test.run 'TestTUN' 2>&1"
    )
    print(out)
    assert "SKIP" not in out, f"the tun round trips skipped themselves under root:\n{out}"
    ran = out.count("--- PASS")
    assert ran >= 34, f"only {ran} tun round trips ran:\n{out}"

    # the client's tun round trips
    # among them a TCP stream through a black hole a session's search finds
    # a veth pair to a second namespace whose far end drops what it cannot take and answers nothing
    # and three nodes in a line whose middle one forwards and answers in process, with its kernel forwarding nothing
    # and an exit carrying transit in process, with nothing out of its uplink
    # and the same exit egressing each shape of the internet it advertises translated, a stranger's source refused
    # and an exit egressing both modes through its one tun, held not ready by each kernel lookup that fails and refusing a mesh destination at its SID
    # and an exit carrying a class of none, a class of an address, return from its LAN and its own traffic under the derived rules
    # and a leaf's sockets of every kind sent where the derived rules and the mirror send them, beside another program's table, as an exit, and nothing left after a stop
    # and the same leaf in exit mode beside a masqueraded bridge and a routed LAN, under each reverse path check
    # and in exit mode beside Tailscale, a conntrack mark restore, kube-proxy and Cilium, and Docker, live, retracted and after kill -9
    # and an IPv6 arrival the route view says the kernel drops exactly where the kernel counts it dropped, not forwarded
    # and each kind of destination, own and arriving, the route view naming the path the kernel takes for it
    # and the same leaf under fallback = "none", with its defaults present and retracted: each socket, other programs' chains and rules,
    # NAT at output, a destination changed after the tun, loopback, each CPU, the listed services, each reverse path check, neighbor
    # discovery and the host's ICMP errors, and a GRE and a WireGuard tunnel's outer packets
    # and the line's middle node traced by uid 0 over its control socket, a record for each forward and answer
    out = machine.succeed(
        "${netlinkTests}/bin/client-tests -test.v -test.run 'TestTUN' 2>&1"
    )
    print(out)
    assert "SKIP" not in out, f"the client's tun round trips skipped themselves under root:\n{out}"
    assert "--- PASS: TestTUNBorderDropsAForgedSourceAtTheUplink" in out, f"the border's lab did not run:\n{out}"
    assert "--- PASS: TestTUNLineCarriesTransitThroughItsMiddleNodeAndAnswersAsARouter" in out, f"the line's lab did not run:\n{out}"
    assert "--- PASS: TestTUNLineRefusesTransitWhileItIsOffButNotThroughAnEndDT46SID" in out, f"the line's lab with transit off did not run:\n{out}"
    assert "--- PASS: TestTUNExitCarriesTransitInProcessAndNothingOutOfItsUplink" in out, f"the exit's lab did not run:\n{out}"
    assert "--- PASS: TestTUNExitEgressesEachShapeOfTheInternetTranslated" in out, f"the exit's egress lab did not run:\n{out}"
    assert "--- PASS: TestTUNModeTwoEgressFollowsTheAnnouncementWithNoEgressSegment" in out, f"mode 2 egress at a node with no egress segment did not run:\n{out}"
    assert "--- PASS: TestTUNExitEgressesBothModesThroughItsOneTun" in out, f"the egress lab did not run:\n{out}"
    assert "--- PASS: TestTUNExitTranslatesEachClassUnderTheDerivedRules" in out, f"the classes' lab did not run:\n{out}"
    assert "--- PASS: TestTUNDerivedRulesSendEachSocketWhereModeOffSays" in out, f"the derived rules' socket lab did not run:\n{out}"
    assert "--- PASS: TestTUNExitModeSendsEachSocketWhereModeTwoSays" in out, f"the exit mode's socket lab did not run:\n{out}"
    assert "--- PASS: TestTUNExitModeBesideTailscale" in out, f"the exit mode beside Tailscale did not run:\n{out}"
    assert "--- PASS: TestTUNExitModeBesideAConntrackMarkRestore" in out, f"the exit mode beside a conntrack mark restore did not run:\n{out}"
    assert "--- PASS: TestTUNExitModeBesideKubeProxyAndCilium" in out, f"the exit mode beside kube-proxy and Cilium did not run:\n{out}"
    assert "--- PASS: TestTUNExitModeBesideDocker" in out, f"the exit mode beside Docker did not run:\n{out}"
    assert "--- PASS: TestTUNDebugRouteNamesTheIPv6DropWhereTheKernelMakesIt" in out, f"the route view's IPv6 forwarding against the kernel's did not run:\n{out}"
    assert "--- PASS: TestTUNDebugRouteNamesThePathTheKernelTakesForEachDestinationKind" in out, f"the route view against the kernel's path for each kind of destination did not run:\n{out}"
    for name in [
        "TestTUNKillSwitchKeepsEachSocketOffTheUplink",
        "TestTUNKillSwitchAnswersOnlyTheListedServices",
        "TestTUNKillSwitchHoldsUnderOtherProgramsChains",
        "TestTUNKillSwitchHoldsUnderNATAtOutput",
        "TestTUNKillSwitchHoldsWhenADestinationChangesAfterTheTun",
        "TestTUNKillSwitchKeepsTheHostsOwnTrafficOnLoopback",
        "TestTUNKillSwitchIsTheSameOnEveryCPU",
        "TestTUNKillSwitchKeepsReversePathChecksPassing",
        "TestTUNKillSwitchPassesDiscoveryAndTheHostsErrors",
        "TestTUNKillSwitchKeepsKernelTunnelsOffTheUplink",
    ]:
        assert f"--- PASS: {name}" in out, f"the kill switch's lab {name} did not run:\n{out}"
    assert "--- PASS: TestTUNTraceShowsTheMiddleNodesDecisions" in out, f"the trace's lab did not run:\n{out}"
    ran = out.count("--- PASS")
    assert ran >= 17, f"only {ran} of the client's tun round trips ran:\n{out}"

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
    # every goroutine of a node opens sockets and tuns, so the whole process runs in a namespace of its own
    out = machine.succeed(
        "unshare -n ${netlinkTests}/bin/client-tests -test.v -test.run '^TestNode(GoingDown|RestartedWhileDown)|^TestSession(MovedUnderTheFloorHandsItsFragmentingOver|LowersItsBudgetAtTheRefusalOfItsOwnData)' 2>&1"
    )
    print(out)
    assert "SKIP" not in out, f"the client's round trips in a namespace of their own skipped themselves under root:\n{out}"
    ran = out.count("--- PASS")
    assert ran >= 4, f"only {ran} of the client's round trips in a namespace of their own ran:\n{out}"

    # the endpoint resolver's sockets carrying the underlay's mark, and its query marked by the overlay a lookup is handed
    # and a dial's query following the overlay of the config in force across reloads
    # Go's resolver reads /etc/resolv.conf from whatever thread looks a name up, so each test binds its own over it in a
    # mount namespace the whole process runs in, beside a network namespace for its nameserver on lo, and refuses init's
    resolv = machine.succeed("cat /etc/resolv.conf")
    out = machine.succeed(
        "unshare -mn ${netlinkTests}/bin/registry-tests -test.v -test.run '^TestResolver' 2>&1"
    )
    print(out)
    assert "SKIP" not in out, f"the registry's resolver tests skipped themselves under root:\n{out}"
    assert "--- PASS: TestResolverSocketsCarryTheUnderlayMark" in out, f"the resolver's socket marks did not pass:\n{out}"
    assert "--- PASS: TestResolverQueryFollowsTheOverlayResolveRemoteIsHanded" in out, f"the registry's hand-over did not pass:\n{out}"
    out = machine.succeed(
        "unshare -mn ${netlinkTests}/bin/client-tests -test.v -test.run '^TestEndpointQueryFollowsTheOverlayInForceAcrossReloads$' 2>&1"
    )
    print(out)
    assert "--- PASS: TestEndpointQueryFollowsTheOverlayInForceAcrossReloads" in out, f"the client's hand-over did not pass:\n{out}"
    assert machine.succeed("cat /etc/resolv.conf") == resolv, "a resolver test's resolv.conf reached the host's mount namespace"

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
    # kernel here rather than against a fake, so a rule, a link or a table left
    # behind is a leak this check is the only thing positioned to see.
    assert "proto 155" not in machine.succeed("ip rule show; ip -6 rule show")
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
