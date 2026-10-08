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
  # the daemon names its tun ranet3 unless link.tun says otherwise
  # ranet* also covers a ranet%d template and a ranet0 that a hand-written configFile names
  tunNames = [
    "ranet*"
  ]
  ++ lib.optional (generated && cfg.settings.link ? tun) cfg.settings.link.tun;
  # creating the tun, and the routes, rules and addresses cap.table owns.
  # cap.egress additionally writes an nftables table of its own, which is why
  # the set is not narrower than this
  capabilities = [
    "CAP_NET_ADMIN"
  ]
  ++ lib.optional (generated && cfg.settings.link.port < 1024) "CAP_NET_BIND_SERVICE";
  configExtension = lib.last (
    lib.splitString "." (baseNameOf (builtins.unsafeDiscardStringContext (toString cfg.configFile)))
  );
  etcName = "ranet3/config.${configExtension}";
  configPath = "/etc/${etcName}";
  # every --control extraArgs hands the daemon, in either spelling the flag parser reads
  controlArgs =
    args:
    if args == [ ] then
      [ ]
    else if lib.head args == "--control" && lib.tail args != [ ] then
      [ (lib.elemAt args 1) ] ++ controlArgs (lib.drop 2 args)
    else if lib.hasPrefix "--control=" (lib.head args) then
      [ (lib.removePrefix "--control=" (lib.head args)) ] ++ controlArgs (lib.tail args)
    else
      controlArgs (lib.tail args);
  # the socket the daemon serves when extraArgs moves it, the last one given as with the flag parser
  # empty turns the socket off, and null leaves it where ranet3 reload looks by itself
  controlSocket =
    let
      sockets = controlArgs cfg.extraArgs;
    in
    if sockets == [ ] then null else lib.last sockets;
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
      {
        assertion = toString cfg.configFile != configPath;
        message = "networking.ranet3.configFile names ${configPath}, the path the module installs it at, so the link would point at itself.";
      }
      {
        assertion = controlSocket == "" -> config.systemd.services.ranet3.reloadTriggers == [ ];
        message = "networking.ranet3.extraArgs turns the control socket off, which ranet3 reload asks the daemon through, while a change to the config file still reloads the service.";
      }
    ];

    users.groups.${cfg.group} = { };

    environment.systemPackages = [ cfg.package ];

    networking.dhcpcd.denyInterfaces = tunNames;
    networking.networkmanager.unmanaged = map (name: "interface-name:${name}") tunNames;

    networking.firewall.allowedUDPPorts = lib.mkIf cfg.openFirewall [ cfg.settings.link.port ];

    environment.etc.${etcName}.source = cfg.configFile;

    systemd.services.ranet3 = {
      description = "ranet3 mesh daemon";
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];
      reloadTriggers = [ cfg.configFile ];
      # one restart once a switch is done rather than a stop before it, so a
      # node switched over its own mesh is not cut off while the switch runs
      stopIfChanged = false;

      serviceConfig = {
        ExecStart = utils.escapeSystemdExecArgs (
          [
            ranet3
            "daemon"
            "--config"
            configPath
            "--log-level"
            cfg.logLevel
          ]
          ++ cfg.extraArgs
        );
        # the trust document is rewritten every time a node joins the mesh,
        # and a restart to pick that up would drop every SA this node is
        # carrying. The socket verb rather than SIGHUP, so a reload the
        # daemon refuses fails here instead of only reaching the log
        ExecReload = utils.escapeSystemdExecArgs (
          [
            ranet3
            "reload"
          ]
          ++ lib.optionals (controlSocket != null) [
            "--control"
            controlSocket
          ]
        );
        Restart = "on-failure";
        # a delay of 5 seconds keeps a failing daemon under systemd's limit of 5 starts in 10 seconds
        RestartSec = "5s";
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
