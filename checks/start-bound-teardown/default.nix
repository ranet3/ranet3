# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: FSL-1.1-ALv2

# the driver's end that a fired bound arms ends a run that goes on past it
{
  coreutils,
  lib,
  python3,
  runCommand,
  testers,
  writeShellScriptBin,
}:

let
  stubs = import ../start-bound/stubs.nix { inherit coreutils python3 writeShellScriptBin; };
  test = testers.runNixOSTest {
    name = "ranet3-start-bound-teardown";

    meta.platforms = lib.platforms.linux;

    # the whole timeout holds the bounds and the wait after them with room to spare
    globalTimeout = 120;

    nodes.stuck.system.build.vm = lib.mkForce stubs.runStuck;

    testScript = builtins.readFile ../start-bound/start.py + ''
      # both bounds stand short to keep the check short
      stall_bound = dt.timedelta(seconds=5)
      teardown_bound = dt.timedelta(seconds=2)
      # the script goes on this long after the bound, far past the teardown bound
      goes_on = dt.timedelta(seconds=20)

      try:
          start_machines(stall_bound, teardown_bound)
      except MachineError:
          time.sleep(goes_on.total_seconds())
      raise AssertionError("the driver outlived its end")
    '';
  };
  failed = testers.testBuildFailure test.config.rawTestDerivation;
in
runCommand "ranet3-start-bound-teardown"
  {
    # the run it reads needs kvm, and the tree check reads the script of every check that does
    requiredSystemFeatures = [ "kvm" ];
    passthru = { inherit (test) config; };
    meta.platforms = lib.platforms.linux;
  }
  ''
    log=${failed}/testBuildFailure.log
    fail() {
      echo "start-bound-teardown: $1" >&2
      exit 1
    }
    grep -F "start bound: the driver still ran 2 s after the bound's kill and ends itself with every thread's stack" "$log" >&2 || fail "the driver's end never fired"
    grep -F '(most recent call first):' "$log" >&2 || fail "the driver's end dumped no stack"
    if grep -F 'AssertionError: the driver outlived its end' "$log" >&2; then
      fail "the driver outlived its end"
    fi
    test "$(cat ${failed}/testBuildFailure.exit)" = 1 || fail "the run ended with $(cat ${failed}/testBuildFailure.exit), not 1"
    touch "$out"
  ''
