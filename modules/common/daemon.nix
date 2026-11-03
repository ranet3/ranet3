# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: FSL-1.1-ALv2

# what both modules derive from networking.ranet3 for the daemon's command lines
{ lib, cfg }:

let
  configExtension = lib.last (
    lib.splitString "." (baseNameOf (builtins.unsafeDiscardStringContext (toString cfg.configFile)))
  );
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
  sockets = controlArgs cfg.extraArgs;
in
rec {
  # the daemon reads the file's format by its extension, which the link keeps
  etcName = "ranet3/config.${configExtension}";
  configPath = "/etc/${etcName}";
  # the socket the daemon serves when extraArgs moves it, the last one given as with the flag parser
  # empty turns the socket off, and null leaves it where ranet3 reload looks by itself
  controlSocket = if sockets == [ ] then null else lib.last sockets;
  reload = [
    (lib.getExe cfg.package)
    "reload"
  ]
  ++ lib.optionals (controlSocket != null) [
    "--control"
    controlSocket
  ];
}
