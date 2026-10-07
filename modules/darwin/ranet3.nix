# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: FSL-1.1-ALv2

{ inputs, ... }:

{ config, lib, ... }:

let
  cfg = config.networking.ranet3;
  ranet3 = lib.getExe cfg.package;
  socketfilterfw = "/usr/libexec/ApplicationFirewall/socketfilterfw";
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
      script = ''
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
    '';
  };
}
