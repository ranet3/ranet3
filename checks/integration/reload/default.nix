# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: FSL-1.1-ALv2

{
  lib,
  inputs,
  pkgs,
  testers,
  ...
}:

let
  organization = "testorg";
  publicKey = builtins.readFile ../../fixtures/org-pub.pem;

  # a documentation address, since nothing dials this node
  member = serial: name: {
    common_name = name;
    endpoints = [
      {
        serial_number = serial;
        address_family = "ip4";
        address = "192.0.2.${serial}";
        port = 14000;
      }
    ];
    remarks = { };
  };

  # built in the store and named by its store path in the settings, so a new
  # document is a new path and a change the module has to notice
  trust =
    members:
    pkgs.writeText "trust.json" (
      builtins.toJSON [
        {
          public_key = publicKey;
          inherit organization;
          nodes = members;
        }
      ]
    );

  settings = {
    node = {
      org = organization;
      name = "machine";
    };
    auth = {
      key = "/etc/ranet3/key.pem";
      trust = "${trust [ (member "1" "machine") ]}";
    };
    link = {
      port = 14000;
      endpoints = [
        {
          serial = "1";
          family = "ip4";
        }
      ];
      # the daemon refuses to start with nobody to dial and nothing to answer
      listen = true;
    };
    cap.route.announce = [ "fd00:1::/64" ];
  };
in
testers.runNixOSTest {
  name = "ranet3-reload";

  meta.platforms = lib.platforms.linux;

  nodes.machine = {
    imports = [ inputs.self.nixosModules.ranet3 ];

    boot.kernelModules = [ "tun" ];

    environment.etc."ranet3/key.pem".source = ../../fixtures/org-key.pem;

    networking.ranet3 = {
      enable = true;
      inherit settings;
    };

    specialisation = {
      # what a reload applies, an announced prefix and a trust document that
      # names a second node
      applied.configuration.networking.ranet3.settings = lib.mkForce (
        lib.recursiveUpdate settings {
          auth.trust = "${trust [
            (member "1" "machine")
            (member "2" "other")
          ]}";
          cap.route.announce = [ "fd00:2::/64" ];
        }
      );
      # what a reload refuses, since the socket is bound once
      refused.configuration.networking.ranet3.settings = lib.mkForce (
        lib.recursiveUpdate settings { link.port = 14001; }
      );
    };
  };

  testScript =
    { nodes, ... }:
    ''
      import datetime as dt
      import json

      timeout = dt.timedelta(seconds=30)
      toplevel = "${nodes.machine.system.build.toplevel}"

      def switch(name):
          return machine.execute(f"{toplevel}/specialisation/{name}/bin/switch-to-configuration test 2>&1")

      def main_pid():
          return machine.succeed("systemctl show --property MainPID --value ranet3.service").strip()

      def status():
          return json.loads(machine.succeed("ranet3 status --json"))

      def announced(state):
          return [route["prefix"] for route in state["originate"]]

      def listening(port):
          return f"ss --numeric --listening --udp | grep -F ':{port}'"

      def reloaded(output):
          for line in output.splitlines():
              if line.startswith("reloading the following units: "):
                  return line.removeprefix("reloading the following units: ").split(", ")
          return []

      machine.wait_for_unit("multi-user.target")
      machine.wait_for_unit("ranet3.service")
      machine.wait_until_succeeds("ranet3 status", timeout=timeout)
      pid = main_pid()
      state = status()
      assert announced(state) == ["fd00:1::/64"], state["originate"]
      assert state["registry"]["nodes"] == 1, state["registry"]
      assert state["port"] == 14000, state["port"]
      machine.wait_until_succeeds(listening(14000), timeout=timeout)

      # a change a reload applies reaches the running daemon, which keeps its
      # process and so every SA it carries
      status_code, output = switch("applied")
      print(output)
      assert status_code == 0, f"the switch exited with {status_code}"
      assert "ranet3.service" in reloaded(output), output
      assert "restarting the following units" not in output, output
      assert main_pid() == pid, "the switch restarted the daemon"
      state = status()
      assert announced(state) == ["fd00:2::/64"], state["originate"]
      assert state["registry"]["nodes"] == 2, state["registry"]

      # a change it refuses fails the switch with the daemon's reason, and
      # nothing of the new file is applied
      status_code, output = switch("refused")
      print(output)
      assert status_code == 4, f"the switch exited with {status_code}, want 4"
      assert "ranet3.service" in reloaded(output), output
      machine.wait_until_succeeds("journalctl --unit ranet3.service --no-pager | grep -F 'link.port changed, restart to apply'", timeout=timeout)
      assert main_pid() == pid, "the refused switch replaced the daemon"
      state = status()
      assert state["port"] == 14000, state["port"]
      assert announced(state) == ["fd00:2::/64"], state["originate"]
      assert state["registry"]["nodes"] == 2, state["registry"]
      machine.succeed(listening(14000))
      machine.fail(listening(14001))

      # the old configuration runs until a restart applies the new file
      machine.succeed("systemctl restart ranet3.service")
      machine.wait_until_succeeds("ranet3 status", timeout=timeout)
      assert main_pid() != pid, "the restart kept the old process"
      state = status()
      assert state["port"] == 14001, state["port"]
      assert announced(state) == ["fd00:1::/64"], state["originate"]
      assert state["registry"]["nodes"] == 1, state["registry"]
      machine.wait_until_succeeds(listening(14001), timeout=timeout)
    '';
}
