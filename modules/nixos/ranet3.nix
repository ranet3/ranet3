# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: FSL-1.1-ALv2

{ inputs, ... }:

{
  config,
  lib,
  options,
  utils,
  ...
}:

let
  cfg = config.networking.ranet3;
  ranet3 = lib.getExe cfg.package;
  # whether the daemon runs the file rendered from settings, the one case in
  # which the module can read the port. Read from priorities alone, so a
  # configFile set by hand never forces the settings it replaces
  generated = options.networking.ranet3.configFile.highestPrio == (lib.mkOptionDefault null).priority;
  # creating the tun, and the routes, rules and addresses cap.table owns.
  # cap.egress additionally writes an nftables table of its own, which is why
  # the set is not narrower than this
  capabilities = [
    "CAP_NET_ADMIN"
  ]
  ++ lib.optional (generated && cfg.settings.link.port < 1024) "CAP_NET_BIND_SERVICE";
in
{
  key = toString ./ranet3.nix;

  imports = [ (lib.modules.importApply ../common/options.nix { inherit inputs; }) ];

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.openFirewall -> generated;
        message = "networking.ranet3.openFirewall reads the port from settings, which a configFile set by hand replaces.";
      }
    ];

    users.groups.${cfg.group} = { };

    environment.systemPackages = [ cfg.package ];

    # the daemon names its tun ranet3 unless link.tun says otherwise
    # ranet* also covers a ranet%d template and a ranet0 that a hand-written configFile names
    networking.dhcpcd.denyInterfaces = [
      "ranet*"
    ]
    ++ lib.optional (generated && cfg.settings.link ? tun) cfg.settings.link.tun;

    networking.firewall.allowedUDPPorts = lib.mkIf cfg.openFirewall [ cfg.settings.link.port ];

    systemd.services.ranet3 = {
      description = "ranet3 mesh daemon";
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];
      # one restart once a switch is done rather than a stop before it, so a
      # node switched over its own mesh is not cut off while the switch runs
      stopIfChanged = false;

      serviceConfig = {
        ExecStart = utils.escapeSystemdExecArgs (
          [
            ranet3
            "daemon"
            "--config"
            cfg.configFile
            "--log-level"
            cfg.logLevel
          ]
          ++ cfg.extraArgs
        );
        # the trust document is rewritten every time a node joins the mesh,
        # and a restart to pick that up would drop every SA this node is
        # carrying. The socket verb rather than SIGHUP, so a reload the
        # daemon refuses fails here instead of only reaching the log
        ExecReload = utils.escapeSystemdExecArgs [
          ranet3
          "reload"
        ];
        Restart = "on-failure";
        # shutdown closes every session with a grace period and withdraws the
        # routes it installed, and a kill partway through leaves them behind
        TimeoutStopSec = "15s";
        # control.DefaultSocket is /var/run/ranet3/control.sock, which
        # linux resolves to /run, so this is the directory it is bound in
        RuntimeDirectory = "ranet3";
        RuntimeDirectoryMode = "0750";
        Group = cfg.group;
        AmbientCapabilities = capabilities;
        CapabilityBoundingSet = capabilities;
      }
      // lib.optionalAttrs (cfg.logFile != null) {
        StandardOutput = "append:${cfg.logFile}";
        StandardError = "append:${cfg.logFile}";
      };
    };
  };
}
