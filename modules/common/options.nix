# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: FSL-1.1-ALv2

{ inputs }:

{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.networking.ranet3;
  format = pkgs.formats.toml { };
in
{
  options.networking.ranet3 = {
    enable = lib.mkEnableOption "the ranet3 mesh daemon";

    package = lib.mkOption {
      type = lib.types.package;
      default = inputs.self.legacyPackages.${pkgs.stdenv.hostPlatform.system}.ranet3;
      defaultText = lib.literalMD "the ranet3 package of the flake this module came from";
      description = "The build this machine runs.";
    };

    settings = lib.mkOption {
      type = lib.types.submodule {
        freeformType = format.type;
        options.link.port = lib.mkOption {
          type = lib.types.port;
          description = "The UDP port IKE and ESP share.";
        };
        options.auth.key = lib.mkOption {
          type = lib.types.externalPath;
          description = "The private key, by an absolute path outside the store.";
        };
      };
      default = { };
      example = lib.literalExpression ''
        {
          node = { org = "example"; name = "gateway"; };
          auth = {
            key = "/var/lib/ranet3/key.pem";
            trust = "/var/lib/ranet3/trust.json";
          };
          link = {
            port = 13000;
            endpoints = [ { serial = "0"; family = "ip4"; } ];
          };
          dial.all = true;
        }
      '';
      description = "The config file, in the schema pkgs/ranet3/examples/config.toml documents.";
    };

    configFile = lib.mkOption {
      type = lib.types.path;
      default = format.generate "ranet3.toml" cfg.settings;
      defaultText = lib.literalMD "the file generated from networking.ranet3.settings";
      description = "The config file to run, in place of settings.";
    };

    logLevel = lib.mkOption {
      type = lib.types.enum [
        "debug"
        "info"
        "warn"
        "error"
      ];
      default = "info";
      description = "The daemon's --log-level.";
    };

    extraArgs = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [
        "--metrics"
        "127.0.0.1:9669"
      ];
      description = "Further arguments to `ranet3 daemon`.";
    };

    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Whether to let the mesh's UDP port in: the firewall on NixOS, the application firewall on darwin.";
    };

    group = lib.mkOption {
      type = lib.types.str;
      default = if pkgs.stdenv.hostPlatform.isDarwin then "admin" else "ranet3";
      defaultText = lib.literalExpression ''if darwin then "admin" else "ranet3"'';
      description = "The group that may use the control socket, every subcommand included.";
    };

    logFile = lib.mkOption {
      type = lib.types.nullOr lib.types.externalPath;
      default = if pkgs.stdenv.hostPlatform.isDarwin then "/var/log/ranet3.log" else null;
      defaultText = lib.literalExpression ''if darwin then "/var/log/ranet3.log" else null'';
      description = "Where the daemon's output goes, or null to keep it in the journal on NixOS and discard it on darwin.";
    };
  };
}
