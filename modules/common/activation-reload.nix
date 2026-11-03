# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: FSL-1.1-ALv2

# the two steps nix-darwin's activation runs for the daemon: one ahead of the launchd step, which says whether that step
# leaves the job loaded as it is, and one after it, which then reloads the daemon onto the files the activation installed
{
  diffutils,
  lib,
  writeShellScriptBin,
}:

writeShellScriptBin "ranet3-activation-reload" ''
  # ranet3-activation-reload kept <plist> <installed plist>
  # ranet3-activation-reload reload <kept> <job label> <reload command...>
  set -eu
  PATH=${lib.makeBinPath [ diffutils ]}:$PATH
  case $1 in
    kept)
      # it answers on its output and exits 0, since a status of 1 would end the activation under its set -e
      if cmp -s "$2" "$3"; then echo yes; else echo no; fi
      ;;
    reload)
      [ "$2" = yes ] || exit 0
      launchctl print "system/$3" > /dev/null 2>&1 || exit 0
      shift 3
      exec "$@"
      ;;
    *)
      echo "ranet3-activation-reload: no step $1" >&2
      exit 64
      ;;
  esac
''
