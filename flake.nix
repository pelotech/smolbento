{
  description = "smolbento dev shell";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-parts = {
      url = "github:hercules-ci/flake-parts";
      inputs.nixpkgs-lib.follows = "nixpkgs";
    };
    treefmt-nix = {
      url = "github:numtide/treefmt-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      imports = [ inputs.treefmt-nix.flakeModule ];
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];
      perSystem =
        { pkgs, ... }:
        {
          devShells.default = pkgs.mkShell {
            packages = with pkgs; [
              # rust
              cargo
              rustc
              clippy
              rustfmt
              rust-analyzer
              cargo-nextest
              cargo-insta
              cargo-deny

              # release
              rcodesign

              # tasks
              just

              # pre-commit
              prek
              yamllint
              actionlint
              zizmor

              # scanning
              trivy
            ];
            env.RUST_SRC_PATH = "${pkgs.rustPlatform.rustLibSrc}";
          };

          packages.default = pkgs.rustPlatform.buildRustPackage {
            pname = "smolbento";
            version = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).package.version;
            src = ./.;
            cargoLock.lockFile = ./Cargo.lock;
            # Some unit tests read host facts (memory, free ports) the build sandbox hides; CI runs them.
            doCheck = false;
            postInstall = ''
              for n in sbt sbx bento; do ln -s smolbento $out/bin/$n; done
            '';
            meta.mainProgram = "sbt";
          };

          treefmt = {
            projectRootFile = "flake.nix";
            programs.nixfmt.enable = true;
          };
        };
    };
}
