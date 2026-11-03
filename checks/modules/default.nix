# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: FSL-1.1-ALv2

{
  inputs,
  lib,
  pkgs,
  runCommand,
  stdenv,
  writeShellScript,
  writeShellScriptBin,
  writeText,
}:

let
  settings = {
    node = "example/gateway";
    auth = {
      key = "/var/lib/ranet3/key.pem";
      trust = "/var/lib/ranet3/trust.json";
    };
    link = {
      port = 13000;
      endpoints = [
        {
          serial = "0";
          family = "ip4";
        }
      ];
    };
    dial.all = true;
  };

  # a launchd key nix-darwin declares, unset by default
  launchdKey =
    type:
    lib.mkOption {
      type = lib.types.nullOr type;
      default = null;
    };
  # the nix-darwin options the darwin module reads and writes, so the module is evaluated without nix-darwin. The job's
  # serviceConfig declares Label, which the module reads, and the keys the module sets, and no others, each with the type
  # nix-darwin ff0e21a4 declares in modules/launchd/launchd.nix, Label at line 11, UserName 39, GroupName 48, KeepAlive 166,
  # RunAtLoad 242, ExitTimeOut 294, StandardOutPath 389 and StandardErrorPath 397, and Label's default from
  # modules/launchd/default.nix:89
  darwinOptions = {
    options = {
      assertions = lib.mkOption {
        type = lib.types.listOf lib.types.attrs;
        default = [ ];
      };
      environment.etc = lib.mkOption {
        type = lib.types.attrsOf (
          lib.types.submodule { options.source = lib.mkOption { type = lib.types.path; }; }
        );
        default = { };
      };
      environment.systemPackages = lib.mkOption {
        type = lib.types.listOf lib.types.package;
        default = [ ];
      };
      launchd.daemons = lib.mkOption {
        type = lib.types.attrsOf (
          lib.types.submodule (
            { name, ... }:
            {
              options.script = lib.mkOption { type = lib.types.lines; };
              options.serviceConfig = lib.mkOption {
                type = lib.types.submodule {
                  options = {
                    Label = lib.mkOption {
                      type = lib.types.str;
                      default = "org.nixos.${name}";
                    };
                    UserName = launchdKey lib.types.str;
                    GroupName = launchdKey lib.types.str;
                    KeepAlive = launchdKey (
                      lib.types.either lib.types.bool (
                        lib.types.submodule {
                          options = lib.mapAttrs (_: launchdKey) {
                            SuccessfulExit = lib.types.bool;
                            NetworkState = lib.types.bool;
                            PathState = lib.types.attrsOf lib.types.bool;
                            OtherJobEnabled = lib.types.attrsOf lib.types.bool;
                            Crashed = lib.types.bool;
                            AfterInitialDemand = lib.types.bool;
                          };
                        }
                      )
                    );
                    RunAtLoad = launchdKey lib.types.bool;
                    ExitTimeOut = launchdKey lib.types.int;
                    StandardOutPath = launchdKey lib.types.path;
                    StandardErrorPath = launchdKey lib.types.path;
                  };
                };
                default = { };
              };
            }
          )
        );
        default = { };
      };
      system.activationScripts = lib.mkOption {
        type = lib.types.attrsOf (
          lib.types.submodule {
            options.text = lib.mkOption {
              type = lib.types.lines;
              default = "";
            };
          }
        );
        default = { };
      };
    };
    config._module.args.pkgs = pkgs;
  };
  # the daemon's reload, which records its call, refuses while RANET3_REFUSED is yes, and otherwise runs the file the
  # activation linked
  daemon = writeShellScriptBin "ranet3" ''
    echo "ranet3 $*" >> "$RANET3_ROOT/calls"
    [ "$RANET3_REFUSED" = no ] || exit 3
    readlink -e "$RANET3_ROOT/etc/ranet3/config.toml" > "$RANET3_ROOT/running"
  '';
  # launchd, which answers a print of the module's job in the system domain alone, the job loaded while RANET3_LOADED is
  # yes, and records any other question as unasked
  launchctl = writeShellScriptBin "launchctl" ''
    if [ "$*" != "print system/org.nixos.ranet3" ]; then
      echo "unasked launchctl $*" >> "$RANET3_ROOT/calls"
      exit 64
    fi
    [ "$RANET3_LOADED" = yes ]
  '';
  # a darwin host running the module beside the modules before it and extra after it
  darwinWith =
    before: extra:
    (lib.evalModules {
      modules = before ++ [
        inputs.self.darwinModules.ranet3
        darwinOptions
        {
          networking.ranet3 = {
            enable = true;
            package = daemon;
            inherit settings;
          };
        }
        extra
      ];
    }).config;
  darwin = darwinWith [ ];
  darwinDefault = darwin { };
  darwinMoved = darwin { networking.ranet3.extraArgs = [ "--control=/var/run/ranet3/moved.sock" ]; };
  darwinYaml = darwin {
    networking.ranet3.configFile = writeText "ranet3.yaml" "node: example/gateway\n";
  };
  # a tool that installs secrets at mkAfter in the step the reload runs in, as sops-nix does
  secrets = {
    system.activationScripts.postActivation.text = lib.mkAfter "secrets installed";
  };
  failed =
    config:
    lib.concatMapStringsSep "\n" (a: a.message) (lib.filter (a: !a.assertion) config.assertions);
  etcNames = config: lib.concatStringsSep " " (lib.attrNames config.environment.etc);
  # the module's steps of an activation of the system $1 in nix-darwin's order, with nix-darwin's etc and launchd steps
  # between them as nix-darwin runs them, and the files it installs under $RANET3_ROOT in place of /
  activation =
    config:
    let
      step =
        name:
        lib.replaceStrings [ " /Library/" ] [ " \"$RANET3_ROOT\"/Library/" ]
          (config.system.activationScripts.${name} or { text = ""; }).text;
    in
    writeShellScript "activate" ''
      set -e
      systemConfig=$1
      ${step "preActivation"}
      mkdir -p "$RANET3_ROOT/etc/ranet3" "$RANET3_ROOT/Library/LaunchDaemons"
      ln -sfn "$systemConfig/etc/ranet3/config.toml" "$RANET3_ROOT/etc/ranet3/config.toml"
      plist=Library/LaunchDaemons/org.nixos.ranet3.plist
      if ! cmp -s "$systemConfig/$plist" "$RANET3_ROOT/$plist"; then
        cp -f "$systemConfig/$plist" "$RANET3_ROOT/$plist"
        echo "launchd loads the job" >> "$RANET3_ROOT/calls"
        readlink -e "$RANET3_ROOT/etc/ranet3/config.toml" > "$RANET3_ROOT/running"
      fi
      ${step "postActivation"}
    '';

  # a NixOS host running the module, with networkd on or off and what extra sets
  host =
    networkd: extra:
    (inputs.nixpkgs.lib.nixosSystem {
      modules = [
        inputs.self.nixosModules.ranet3
        {
          nixpkgs.hostPlatform = stdenv.hostPlatform.system;
          system.stateVersion = lib.trivial.release;
          systemd.network.enable = networkd;
          networking.ranet3 = {
            enable = true;
            inherit settings;
          };
        }
        extra
      ];
    }).config;
  # the networkd settings for foreign rules and routes a host ends with, which the build compares
  foreign =
    config:
    builtins.toJSON (
      lib.filterAttrs (
        name: _: lib.hasPrefix "ManageForeign" name
      ) config.systemd.network.config.networkConfig
    );
  withNetworkd = host true { };
in
runCommand "ranet3-modules"
  {
    nativeBuildInputs = [ launchctl ];
    darwinScript = darwinDefault.launchd.daemons.ranet3.script;
    # the job's serviceConfig rendered with toPlist as nix-darwin's launchd module renders it (modules/launchd/default.nix:12),
    # which reads each value
    darwinPlist = lib.generators.toPlist {
      escape = true;
    } darwinDefault.launchd.daemons.ranet3.serviceConfig;
    darwinYamlScript = darwinYaml.launchd.daemons.ranet3.script;
    darwinEtc = etcNames darwinDefault;
    darwinYamlEtc = etcNames darwinYaml;
    darwinEtcSource = toString darwinDefault.environment.etc."ranet3/config.toml".source;
    darwinConfigFile = toString darwinDefault.networking.ranet3.configFile;
    darwinFailed = failed darwinDefault;
    darwinOffFailed = failed (darwin {
      networking.ranet3.extraArgs = [
        "--control"
        ""
      ];
    });
    darwinSelfFailed = failed (darwin {
      networking.ranet3.configFile = "/etc/ranet3/config.toml";
    });
    secretsAfter = (darwin secrets).system.activationScripts.postActivation.text;
    secretsFirst = (darwinWith [ secrets ] { }).system.activationScripts.postActivation.text;
    secretsImportedAfter =
      (darwin { imports = [ secrets ]; }).system.activationScripts.postActivation.text;
    networkdOn = foreign withNetworkd;
    networkdOverridden = foreign (
      host true {
        systemd.network.config.networkConfig.ManageForeignRoutingPolicyRules = true;
      }
    );
    networkdOff = foreign (host false { });
    networkdConf = withNetworkd.environment.etc."systemd/networkd.conf".text;
    meta.platforms = lib.platforms.linux;
  }
  ''
    failed=0
    # same <case> <got> <want>
    same() {
      if [ "$2" != "$3" ]; then
        echo "$1 is '$2', want '$3'" >&2
        failed=1
      fi
    }
    # holds <case> <text> <part>
    holds() {
      if ! grep -q -F -e "$3" <<< "$2"; then
        echo "$1 reads '$2', want it to hold '$3'" >&2
        failed=1
      fi
    }
    holds "the darwin job's script" "$darwinScript" " daemon --config /etc/ranet3/config.toml "
    holds "the darwin job's script for a YAML file" "$darwinYamlScript" " daemon --config /etc/ranet3/config.yaml "
    holds "the darwin job's serviceConfig rendered as a plist" "$darwinPlist" "<string>org.nixos.ranet3</string>"
    same "the darwin etc entries" "$darwinEtc" "ranet3/config.toml"
    same "the darwin etc entries for a YAML file" "$darwinYamlEtc" "ranet3/config.yaml"
    same "the darwin etc entry's source" "$darwinEtcSource" "$darwinConfigFile"
    same "the darwin assertions that fail" "$darwinFailed" ""
    holds "the darwin assertions that fail with the socket off" "$darwinOffFailed" "turns the control socket off"
    holds "the darwin assertions that fail with the file at the link" "$darwinSelfFailed" "the link would point at itself"
    # last <case> <postActivation text>: the reload after the secrets
    last() {
      secrets=$(grep -n -x 'secrets installed' <<< "$2" | cut -d: -f1)
      step=$(grep -n 'ranet3-activation-reload reload ' <<< "$2" | cut -d: -f1)
      if [ -z "$secrets" ] || [ -z "$step" ] || [ "$step" -le "$secrets" ]; then
        echo "$1: the reload is line '$step' of postActivation and the secrets line '$secrets', want the reload after:" >&2
        echo "$2" >&2
        failed=1
      fi
    }
    last "the secrets module listed after" "$secretsAfter"
    last "the secrets module listed first" "$secretsFirst"
    last "the secrets module imported by a module listed after" "$secretsImportedAfter"

    for file in config-a config-b plist-a plist-b; do
      echo "$file" > "$file"
    done
    # system <dir> <config file> <plist file>: a system's links as nix-darwin builds them
    system() {
      mkdir -p "$1/etc/ranet3" "$1/Library/LaunchDaemons"
      ln -s "$PWD/$2" "$1/etc/ranet3/config.toml"
      ln -s "$PWD/$3" "$1/Library/LaunchDaemons/org.nixos.ranet3.plist"
    }
    system A config-a plist-a
    system B config-b plist-a
    system C config-b plist-b
    export RANET3_ROOT=$PWD/root
    # root <system or empty>: a host where that system's activation ran, its job running the file it linked
    root() {
      rm -rf root
      mkdir -p root/etc/ranet3 root/Library/LaunchDaemons
      touch root/calls root/running
      if [ -n "$1" ]; then
        ln -s "$PWD/$1/etc/ranet3/config.toml" root/etc/ranet3/config.toml
        cp "$1/Library/LaunchDaemons/org.nixos.ranet3.plist" root/Library/LaunchDaemons/
        readlink -e root/etc/ranet3/config.toml > root/running
      fi
    }
    # activate <case> <activation> <system> <loaded> <refused> <status> <reloads> <running>: an activation of the system on
    # the root, the job loaded or not and the daemon refusing a reload or not, against its status, the reloads the root has
    # seen and the file the daemon runs
    activate() {
      status=0
      RANET3_LOADED=$4 RANET3_REFUSED=$5 "$2" "$PWD/$3" || status=$?
      reloads=$(grep -c '^ranet3 reload' root/calls || true)
      unasked=$(grep -c '^unasked' root/calls || true)
      running=$(basename "$(cat root/running)")
      if [ "$status" != "$6" ] || [ "$reloads" != "$7" ] || [ "$running" != "$8" ] || [ "$unasked" != 0 ]; then
        echo "$1: the activation exited $status after $reloads reloads with the daemon running $running, want $6 after $7 running $8:" >&2
        cat root/calls >&2
        failed=1
      fi
    }
    root A
    activate "the files unchanged" ${activation darwinDefault} A yes no 0 1 config-a
    root A
    activate "the config changed with the job kept" ${activation darwinDefault} B yes no 0 1 config-b
    root A
    activate "a reload the daemon refuses" ${activation darwinDefault} B yes yes 3 1 config-a
    root A
    activate "the job not loaded" ${activation darwinDefault} B no no 0 0 config-a
    root A
    activate "the job's plist changed" ${activation darwinDefault} C yes no 0 0 config-b
    root ""
    activate "the job installed first" ${activation darwinDefault} B yes no 0 0 config-b
    root A
    activate "a refused reload" ${activation darwinDefault} B yes yes 3 1 config-a
    readlink -e root/etc/ranet3/config.toml > root/running
    same "the job restarted after a refused reload" "$(basename "$(cat root/running)")" config-b
    activate "the rollback after the refusal and the restart" ${activation darwinDefault} A yes no 0 2 config-a
    root A
    activate "the control socket moved" ${activation darwinMoved} B yes no 0 1 config-b
    holds "the reload with the control socket moved" "$(cat root/calls)" "ranet3 reload --control /var/run/ranet3/moved.sock"

    # networkd <case> <settings> <want>
    networkd() {
      if [ "$2" != "$3" ]; then
        echo "$1: networkd's foreign settings are $2, want $3" >&2
        failed=1
      fi
    }
    networkd "a host with networkd" "$networkdOn" '{"ManageForeignRoutingPolicyRules":false}'
    networkd "a host that sets the rules true" "$networkdOverridden" '{"ManageForeignRoutingPolicyRules":true}'
    networkd "a host without networkd" "$networkdOff" '{}'
    if ! grep -q -x 'ManageForeignRoutingPolicyRules=false' <<< "$networkdConf"; then
      echo "networkd.conf of a host with networkd reads:" >&2
      echo "$networkdConf" >&2
      failed=1
    fi
    [ "$failed" = 0 ]
    touch "$out"
  ''
