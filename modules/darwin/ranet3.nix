# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: FSL-1.1-ALv2

{ inputs, ... }:

{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.networking.ranet3;
  ranet3 = lib.getExe cfg.package;
  socketfilterfw = "/usr/libexec/ApplicationFirewall/socketfilterfw";
  inherit (import ../common/daemon.nix { inherit lib cfg; })
    etcName
    configPath
    controlSocket
    reload
    ;
  activationReload = pkgs.callPackage ../common/activation-reload.nix { };
  label = config.launchd.daemons.ranet3.serviceConfig.Label;
  # the name nix-darwin gives the job's plist
  plist = "${label}.plist";
in
{
  key = toString ./ranet3.nix;

  imports = [ (lib.modules.importApply ../common/options.nix { inherit inputs; }) ];

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = toString cfg.configFile != configPath;
        message = "networking.ranet3.configFile names ${configPath}, the path the module installs it at, so the link would point at itself.";
      }
      {
        assertion = controlSocket != "";
        message = "networking.ranet3.extraArgs turns the control socket off, which the activation's ranet3 reload asks the daemon through.";
      }
    ];

    environment.systemPackages = [ cfg.package ];

    environment.etc.${etcName}.source = cfg.configFile;

    launchd.daemons.ranet3 = {
      # creating a utun and writing the route table both need root, and the
      # group leaves the control socket usable without it. The daemon
      # creates /var/run/ranet3 itself, in that group and at a mode the
      # group can enter, which is why nothing here makes the directory.
      script = ''
        exec ${
          lib.escapeShellArgs (
            [
              ranet3
              "daemon"
              "--config"
              configPath
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

    # The launchd step loads the job anew wherever its plist differs from the copy installed before, which it then replaces,
    # so the two are compared ahead of it. The reload below runs only where that step left the job as it was.
    system.activationScripts.preActivation.text = ''
      ranet3_job_kept=$(${lib.getExe activationReload} kept "$systemConfig"/${
        lib.escapeShellArgs [
          "Library/LaunchDaemons/${plist}"
          "/Library/LaunchDaemons/${plist}"
        ]
      })
    '';

    # Past mkAfter, so a key or trust document that a tool such as sops-nix or agenix installs in this step at mkAfter is
    # there before the reload. A reload the daemon refuses ends the activation before nix-darwin links /run/current-system.
    system.activationScripts.postActivation.text = lib.mkOrder 2000 ''
      ${lib.getExe activationReload} reload "$ranet3_job_kept" ${
        lib.escapeShellArgs ([ label ] ++ reload)
      }
    '';

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
