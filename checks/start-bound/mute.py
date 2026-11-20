# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: FSL-1.1-ALv2

# a machine's start that does what QEMU does for the driver up to the QMP greeting and never greets
# it forks a child into a session of its own, listens on the QMP socket, connects the monitor and the shell, and sleeps outside the machine's state directory, while the child sleeps in it

import os
import socket
import sys
import time

args = sys.argv[1:]

# a child in a session of its own, which the kill spares though it descends from this start
child = os.fork()
if child == 0:
    os.setsid()
    os.closerange(0, 1024)
    while True:
        time.sleep(3600)
with open(os.path.join(os.environ["TMPDIR"], "session"), "w") as pid:
    pid.write(str(child))


def after(flag: str) -> str:
    return args[args.index(flag) + 1]


qmp = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
qmp.bind(after("-qmp").removeprefix("unix:").split(",")[0])
qmp.listen(1)
monitor = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
monitor.connect(after("-monitor").removeprefix("unix:"))
shell = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
shell.connect(next(arg for arg in args if arg.startswith("socket,id=shell,")).split("path=", 1)[1])
# only the start process's own pid, not the working directory, leads the kill here
os.chdir("/")
conn, _ = qmp.accept()
while True:
    time.sleep(3600)
