# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: FSL-1.1-ALv2

# machines' starts that stand in for QEMU in the checks of checks/start-bound/start.py
{
  coreutils,
  python3,
  writeShellScriptBin,
}:

{
  # a start that leaves a child holding the machine's output open and exits
  # the driver reads that output to its end and never returns
  runStuck = writeShellScriptBin "run-stuck-vm" ''
    ${coreutils}/bin/sleep infinity &
    echo "$!" > "$TMPDIR/sleeper"
    exit 1
  '';
  # a start whose process lives and never greets on QMP
  runMute = writeShellScriptBin "run-mute-vm" ''
    exec ${python3}/bin/python3 -I ${./mute.py} "$@"
  '';
  # a start that exits at once with nothing left behind, which the driver reports as failed
  runUnbootable = writeShellScriptBin "run-unbootable-vm" ''
    exit 1
  '';
}
