{
  inputs,
  lib,
  buildGoApplication,
}:

let
  # the commit this build came from, which tells two nodes apart between
  # releases: version.txt moves once per release and a fleet converts one node
  # at a time in between. A dirty tree has no revision to report.
  revision = inputs.self.shortRev or inputs.self.dirtyShortRev or null;
in
buildGoApplication (
  lib.fix (finalAttrs: {
    meta.mainProgram = finalAttrs.pname;
    pname = "ranet3";
    version = lib.fileContents ./version.txt;

    src =
      with lib.fileset;
      toSource {
        root = ./.;
        fileset = unions [
          # code. This is an allow list, so a package promoted out of internal
          # has to be named here in the same commit that moves it, or the
          # sandbox builds a tree that cannot compile.
          ./cmd
          ./control
          ./esp
          ./ike
          ./internal
          ./sadr
          ./schema
          ./srv6
          ./transport
          # the example is parsed by a test, so it has to be in the source the
          # checks see or that test passes only outside the sandbox
          ./examples
          # meta
          ./go.mod
          ./go.sum
          ./version.txt
        ];
      };

    modules = ./gomod2nix.toml;

    subPackages = [ "cmd/ranet3" ];

    ldflags = [
      "-s"
      "-w"
      "-X ranet3.com/pkgs/ranet3/internal/version.Value=${finalAttrs.version}"
    ]
    ++ lib.optional (
      revision != null
    ) "-X ranet3.com/pkgs/ranet3/internal/version.Revision=${revision}";

    # the test suite runs as a flake check, never inside the package build
    doCheck = false;
  })
)
