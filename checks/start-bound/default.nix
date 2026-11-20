# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: FSL-1.1-ALv2

{
  coreutils,
  lib,
  python3,
  testers,
  writeShellScriptBin,
}:

let
  stubs = import ./stubs.nix { inherit coreutils python3 writeShellScriptBin; };
in
testers.runNixOSTest {
  name = "ranet3-start-bound";

  meta.platforms = lib.platforms.linux;

  # the whole timeout holds the stall bound and every wait after it with room to spare
  # it ends a check whose bound never fires in minutes and not in an hour
  globalTimeout = 300;

  nodes = {
    live = { };
    mute.system.build.vm = lib.mkForce stubs.runMute;
    stuck.system.build.vm = lib.mkForce stubs.runStuck;
    # named after live and on no vlan, which leaves live's number and hosts file as they were
    unbootable = {
      virtualisation.vlans = [ ];
      system.build.vm = lib.mkForce stubs.runUnbootable;
    };
  };

  testScript = builtins.readFile ./start.py + ''
    # the stall bound stands below START_BOUND to keep the check short
    # it stands far above a healthy start, which keeps live clear of it
    stall_bound = dt.timedelta(seconds=30)
    # the kill comes after the bound, within this
    stall_slack = dt.timedelta(seconds=10)
    # how long the check waits for a killed process to leave /proc or turn a zombie
    ended_wait = dt.timedelta(seconds=10)


    def ended(pid: int) -> bool:
        stat = proc_stat(pid)
        return stat is None or stat.state == "Z"


    def mute_ended(_: bool) -> bool:
        assert mute.process is not None
        return mute.process.poll() is not None


    # a process of another session that works in stuck's state directory, which the kill spares
    foreign = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(3600)"], cwd=stuck.state_dir, start_new_session=True)

    began = time.monotonic()
    try:
        start_machines(stall_bound)
    except MachineError as e:
        armed = teardown_timer is not None and teardown_timer.is_alive()
        disarm_teardown_bound()
        lines = str(e).splitlines()
    else:
        raise AssertionError("start_machines returned where the starts of mute and stuck should still have run at the bound")
    took = time.monotonic() - began

    want = "start bound: mute, stuck never ran after 30 s (ran: live) (failed: unbootable)"
    assert lines[0] == want, f"start_machines failed with {lines[0]!r}, want {want!r}"
    assert stall_bound.total_seconds() <= took < (stall_bound + stall_slack).total_seconds(), f"start_machines failed after {took:.2f} s"
    assert armed, "the bound did not arm the driver's end for a teardown past 60 s"
    assert teardown_timer is not None and not teardown_timer.is_alive(), "the driver's end still runs after its script disarmed it"

    assert live.process is not None and mute.process is not None and stuck.process is not None
    for name, frame, state in [
        ("mute", " at machine/qmp.py:", f" while its process {mute.process.pid} runs"),
        ("stuck", "accept_or_fail at machine/__init__.py:", f" while its process {stuck.process.pid} has exited with code 1"),
    ]:
        line = next((line for line in lines if line.startswith(f"start bound: {name} is blocked in ")), "")
        assert frame in line and line.endswith(state), f"no line of {name} names {frame.strip()!r} and ends with {state.strip()!r}:\n" + "\n".join(lines)
    failed_line = "start bound: unbootable failed to start with unbootable: QEMU process exited with code 1 before connecting to monitor socket."
    assert failed_line in lines, f"no line is {failed_line!r}:\n" + "\n".join(lines)

    sleeper = int((stuck.state_dir / "sleeper").read_text())
    retry(lambda _: ended(sleeper), timeout=ended_wait)
    retry(mute_ended, timeout=ended_wait)
    assert live.process.poll() is None, "live's process has ended"
    assert foreign.poll() is None, "a process of another session in stuck's state directory has ended"
    session = int((mute.state_dir / "session").read_text())
    assert not ended(session), "a child mute's start put in a session of its own has ended"
    foreign.kill()
    foreign.wait()
    os.kill(session, signal.SIGKILL)

    # a driver marked interactive arms nothing to end itself when the bound's failure runs
    # it names mute, whose processes have ended, with a thread never started, so the kill finds nothing
    driver.interactive = True
    teardown_timer = None
    with log.nested("a probe of a driver marked interactive, whose start bound lines describe no start of this run"):
        try:
            fail_stalled([(mute, threading.Thread())], [], {}, stall_bound, TEARDOWN_BOUND)
        except MachineError:
            pass
    # a driver marked interactive logs the machines started before start_machines() and goes on
    try:
        named = report_started()
    except MachineError:
        raise AssertionError("report_started() raised in a driver marked interactive, where it only logs")
    assert named == ["live"], f"report_started() in a driver marked interactive named {named!r}, want ['live']"
    driver.interactive = False
    assert teardown_timer is None, "the bound armed the driver's end in an interactive driver"

    # with live running, a second start_machines() refuses at once and names live, as it does a machine that a command of the script started before the call
    try:
        start_machines(stall_bound)
    except MachineError as e:
        second = str(e)
    else:
        raise AssertionError("start_machines() returned with live running, where it refuses a machine started before it")
    want_second = "start bound: live started before start_machines(), outside the bound"
    assert second == want_second, f"start_machines() with live running failed with {second!r}, want {want_second!r}"
  '';
}
