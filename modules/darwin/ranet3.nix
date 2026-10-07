# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: FSL-1.1-ALv2

{ inputs, ... }:

{
  config,
  lib,
  options,
  ...
}:

let
  cfg = config.networking.ranet3;
  ranet3 = lib.getExe cfg.package;
  socketfilterfw = "/usr/libexec/ApplicationFirewall/socketfilterfw";
  # read from priorities alone, so a configFile set by hand never forces the settings it replaces
  generated = options.networking.ranet3.configFile.highestPrio == (lib.mkOptionDefault null).priority;
in
{
  key = toString ./ranet3.nix;

  imports = [ (lib.modules.importApply ../common/options.nix { inherit inputs; }) ];

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [ cfg.package ];

    launchd.daemons.ranet3 = {
      # creating a utun and writing the route table both need root, and the
      # group leaves the control socket usable without it. The daemon
      # creates /var/run/ranet3 itself, at a mode that group can enter,
      # which is why nothing here makes the directory. configFile is
      # interpolated before it is quoted, since escapeShellArg leaves a path
      # literal naming the source tree rather than the store
      script =
        lib.optionalString generated ''
          key=${lib.escapeShellArg cfg.settings.auth.key}
          # a key that never comes ends the wait after 60 seconds and the daemon fails with its own message
          seconds_to_wait=60
          [ -e "$key" ] || echo "ranet3: waiting for $key" >&2
          until [ -e "$key" ] || [ "$SECONDS" -ge "$seconds_to_wait" ]; do
            sleep 1
          done
        ''
        + ''
          exec ${
            lib.escapeShellArgs (
              [
                ranet3
                "daemon"
                "--config"
                "${cfg.configFile}"
                "--log-level"
                cfg.logLevel
              ]
              ++ cfg.extraArgs
            )
          }
        '';
      serviceConfig = {
        RunAtLoad = true;
        KeepAlive = true;
        StandardOutPath = cfg.logFile;
        StandardErrorPath = cfg.logFile;
        GroupName = cfg.group;
        UserName = "root";
        # shutdown closes every session with a grace period and withdraws the
        # routes it installed. launchd sends SIGTERM and then SIGKILL after
        # this, so a machine that takes longer leaves routes behind.
        ExitTimeOut = 20;
      };
    };

    system.activationScripts.extraActivation.text = lib.mkIf cfg.openFirewall ''
      ${socketfilterfw} --add ${lib.escapeShellArg ranet3}
      ${socketfilterfw} --unblockapp ${lib.escapeShellArg ranet3}
      ranet3_entries=$(${socketfilterfw} --listapps | sed -n 's|^.*\(${builtins.storeDir}/[^/ ]*/bin/${baseNameOf ranet3}\).*$|\1|p') || echo "ranet3: could not list the firewall entries" >&2
      for ranet3_entry in $ranet3_entries; do
        if [ "$ranet3_entry" != ${lib.escapeShellArg ranet3} ]; then
          ${socketfilterfw} --remove "$ranet3_entry" || echo "ranet3: could not remove the firewall entry $ranet3_entry" >&2
        fi
      done
    '';
  };
}
