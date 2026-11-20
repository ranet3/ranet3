# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: FSL-1.1-ALv2

# every test script of a check with machines begins with this file
# its script calls start_machines() once, before its first use of a machine
# the driver's start_all() and a machine's first command wait on a start with no limit but the whole test's timeout

import datetime as dt
import faulthandler
import os
import signal
import subprocess
import sys
import threading
import time
from types import FrameType
from typing import NamedTuple, NoReturn

from test_driver.errors import MachineError

# the bound covers the driver's start of the machines, from the spawn of their processes to the last monitor prompt
# the boot to a root shell comes after that span, where the driver waits at most 300 s for the shell's first output and then without a limit for its root shell
# the bound stands some fifty times above the longest healthy start on CI
# a slow runner stays clear of it
# a hung start costs minutes in place of the whole test's timeout
START_BOUND = dt.timedelta(seconds=120)

# the longest a driver that runs neither interactively nor under a script that disarms it goes on after a fired bound's kill before it ends itself
TEARDOWN_BOUND = dt.timedelta(seconds=60)

teardown_timer: threading.Timer | None = None


class ProcStat(NamedTuple):
    state: str
    parent: int
    group: int


def start_machines(bound: dt.timedelta = START_BOUND, teardown: dt.timedelta = TEARDOWN_BOUND) -> None:
    """Start every machine as start_all() does, and fail when bound has passed with any start still running, naming each machine."""
    report_started()
    with log.nested("start all VMs"):
        failed: dict[str, Exception] = {}

        def run_start(machine: BaseMachine) -> None:
            try:
                machine.start()
            except Exception as e:
                failed[machine.name] = e

        # the main thread never enters a start and holds the bound wherever a start blocks
        # a start left blocked in a daemon thread does not hold the driver's exit
        threads = [
            (machine, threading.Thread(target=run_start, args=(machine,), name=f"start-{machine.name}", daemon=True))
            for machine in machines
        ]
        for _, thread in threads:
            thread.start()
        deadline = time.monotonic() + bound.total_seconds()
        for _, thread in threads:
            thread.join(max(0.0, deadline - time.monotonic()))

        # one reading decides who never ran, who failed and who ran
        alive = {machine.name: thread.is_alive() for machine, thread in threads}
        ended_failed = {name: e for name, e in failed.items() if not alive[name]}
        stalled = [(machine, thread) for machine, thread in threads if alive[machine.name]]
        if stalled:
            ran = [machine.name for machine, _ in threads if not alive[machine.name] and machine.name not in ended_failed]
            fail_stalled(stalled, ran, ended_failed, bound, teardown)
        if ended_failed:
            raise MachineError("Failed to start the following machines:\n" + "\n".join(f"{name}: {e}" for name, e in ended_failed.items()))


def fail_stalled(
    stalled: list[tuple[BaseMachine, threading.Thread]],
    ran: list[str],
    failed: dict[str, Exception],
    bound: dt.timedelta,
    teardown: dt.timedelta,
) -> NoReturn:
    global teardown_timer
    frames = sys._current_frames()
    names = ", ".join(machine.name for machine, _ in stalled)
    lines = [
        f"start bound: {names} never ran after {bound.total_seconds():.0f} s (ran: {', '.join(ran) or 'none'}) (failed: {', '.join(failed) or 'none'})"
    ]
    for machine, thread in stalled:
        frame = frames.get(thread.ident) if thread.ident is not None else None
        if frame is None:
            lines.append(f"start bound: {machine.name} ended its start just after the bound while {process_state(machine)}")
        else:
            lines.append(f"start bound: {machine.name} is blocked in {blocked_in(frame)} while {process_state(machine)}")
    for name, e in failed.items():
        # the driver's error may hold the machine's output on lines of its own, which this joins into the one line
        lines.append(f"start bound: {name} failed to start with {' '.join(str(e).split())}")
    # log.error exits the driver before the processes are ended
    for line in lines:
        log.warning(line)

    kill_stalled(stalled)

    # an interactive driver keeps its session after the error
    # a teardown that hangs there is its user's to end
    if not driver.interactive:
        teardown_timer = threading.Timer(teardown.total_seconds(), end_driver, args=(teardown,))
        teardown_timer.daemon = True
        teardown_timer.start()
        lines.append(f"start bound: the driver ends itself {teardown.total_seconds():.0f} s from now unless its script disarms this")
        log.warning(lines[-1])
    raise MachineError("\n".join(lines))


def disarm_teardown_bound() -> None:
    """Cancel the end of the driver that a fired bound armed, for a script that catches the bound's error and goes on."""
    if teardown_timer is not None and teardown_timer.is_alive():
        teardown_timer.cancel()
        teardown_timer.join()


def end_driver(teardown: dt.timedelta) -> None:
    # straight to the descriptor, since a main thread blocked in a write to sys.stderr holds that stream's lock
    os.write(2, f"start bound: the driver still ran {teardown.total_seconds():.0f} s after the bound's kill and ends itself with every thread's stack\n".encode())
    faulthandler.dump_traceback(all_threads=True)
    os._exit(1)


def kill_stalled(stalled: list[tuple[BaseMachine, threading.Thread]]) -> None:
    """Kill the processes of each stalled machine."""
    for machine, _ in stalled:
        for pid in sorted(stalled_pids(machine)):
            try:
                os.kill(pid, signal.SIGKILL)
            # the process ended since the listing
            except ProcessLookupError:
                continue


def driver_process(machine: BaseMachine) -> subprocess.Popen | None:
    if isinstance(machine, (QemuMachine, NspawnMachine)):
        return machine.process
    return None


def started(machine: BaseMachine) -> bool:
    """Whether the machine is in the state where the driver's own start of it returns at once."""
    if isinstance(machine, QemuMachine):
        return machine.booted
    if isinstance(machine, NspawnMachine):
        return machine.process is not None
    return False


def report_started() -> list[str]:
    """Name each machine the driver started before start_machines() in a logged line, raise MachineError for them where the driver is not marked interactive, and return their names otherwise."""
    # the driver's start of a machine it started and has not shut down returns at once, so such a machine was started before start_machines(), outside the bound
    begun = [machine.name for machine in machines if started(machine)]
    if begun:
        line = f"start bound: {', '.join(begun)} started before start_machines(), outside the bound"
        log.warning(line)
        # a user of an interactive driver may run test_script() again over the machines its last run left
        if not driver.interactive:
            raise MachineError(line)
    return begun


def process_state(machine: BaseMachine) -> str:
    process = driver_process(machine)
    if process is None:
        return "it has no process"
    code = process.poll()
    if code is None:
        return f"its process {process.pid} runs"
    return f"its process {process.pid} has exited with code {code}"


def blocked_in(innermost: FrameType) -> str:
    """The innermost frame of the driver's own code in the stack, or the innermost frame where the driver has none."""
    frame: FrameType | None = innermost
    while frame is not None:
        if "/test_driver/" in frame.f_code.co_filename:
            path = frame.f_code.co_filename.split("/test_driver/", 1)[1]
            return f"{frame.f_code.co_name} at {path}:{frame.f_lineno}"
        frame = frame.f_back
    return f"{innermost.f_code.co_name} at {os.path.basename(innermost.f_code.co_filename)}:{innermost.f_lineno}"


def proc_stat(pid: int) -> ProcStat | None:
    """The state, parent and process group of a process, or None once it has left /proc."""
    try:
        with open(f"/proc/{pid}/stat") as stat:
            text = stat.read()
    except (FileNotFoundError, ProcessLookupError):
        return None
    # the command name may hold spaces and parentheses, and the fields begin after its last parenthesis
    fields = text.rsplit(")", 1)[1].split()
    return ProcStat(fields[0], int(fields[1]), int(fields[2]))


def stalled_pids(machine: BaseMachine) -> set[int]:
    """The pids to kill for a stalled machine.

    They are the machine's start process while it lives, every process whose working directory is the machine's state directory, and every descendant of those.
    Only processes of the driver's own process group are listed, roots and descendants alike, and no zombie is.
    That group holds the processes the driver starts, and outside a build also what the shell put in the driver's job, such as the other commands of its pipeline.
    A process whose working directory the driver may not read is taken only as a descendant.
    A process of another session or group is spared even where it works in that directory.
    A process that calls setsid or setpgid leaves the group, so neither it nor any process it forks after is taken.
    No start script of the pinned nixpkgs leaves the group, and the child that the start-bound check's mute stub forks does.
    The listing is read once before the kill, so a process forked after it is not taken either.
    A process that is not taken runs on until a sandboxed build ends, and past the driver otherwise.
    Where it holds the machine's output open, the stalled start's thread stays blocked, which the driver's exit does not wait for, and a teardown that reads that output runs until the driver's end.
    """
    group = os.getpgrp()
    children: dict[int, list[int]] = {}
    roots = []
    seen = set()
    for entry in os.listdir("/proc"):
        if not entry.isdigit() or int(entry) == os.getpid():
            continue
        pid = int(entry)
        stat = proc_stat(pid)
        if stat is None or stat.state == "Z" or stat.group != group:
            continue
        seen.add(pid)
        children.setdefault(stat.parent, []).append(pid)
        try:
            cwd = os.readlink(f"/proc/{pid}/cwd")
        # the process left /proc after its stat was read, or the driver may not trace it
        # one the driver may not trace is killed only as a descendant
        except (FileNotFoundError, PermissionError):
            continue
        if cwd == str(machine.state_dir):
            roots.append(pid)
    process = driver_process(machine)
    if process is not None and process.pid in seen and process.poll() is None:
        roots.append(process.pid)
    found: set[int] = set()
    while roots:
        pid = roots.pop()
        if pid not in found:
            found.add(pid)
            roots.extend(children.get(pid, []))
    return found
