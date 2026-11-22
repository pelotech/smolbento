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

              # kit signing (`bento kit sign/verify`, e2e)
              cosign

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
            cargoLock = {
              lockFile = ./Cargo.lock;
              # Temporary: russh from git until a release pins ssh-key 0.7.0-rc.12+; then drop this.
              outputHashes = {
                "russh-0.65.1" = "sha256-4972RiU0ayW6snBUsJ2ju3yR9dwsGBeaKwOWsJrmprA=";
                "russh-cryptovec-0.62.0" = "sha256-4972RiU0ayW6snBUsJ2ju3yR9dwsGBeaKwOWsJrmprA=";
                "russh-util-0.52.0" = "sha256-4972RiU0ayW6snBUsJ2ju3yR9dwsGBeaKwOWsJrmprA=";
                "pageant-0.2.5" = "sha256-4972RiU0ayW6snBUsJ2ju3yR9dwsGBeaKwOWsJrmprA=";
                # Temporary: smolvm from git until smolvm-credentials is on crates.io.
                # FIXME placeholder: smolvm's .gitmodules use ssh URLs, so a sandboxed fetch fails; replace once smolvm-credentials is fetchable without ssh (crates.io or https submodules).
                "smolvm-credentials-1.36.1" = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
                "smolvm-protocol-1.36.1" = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
              };
            };
            # Some unit tests read host facts (memory, free ports) the build sandbox hides; CI runs them.
            doCheck = false;
            postInstall = ''
              for n in bento sbx; do ln -s smolbento $out/bin/$n; done
            '';
            meta.mainProgram = "bento";
          };

          treefmt = {
            projectRootFile = "flake.nix";
            programs.nixfmt.enable = true;
          };
        };
    };
}
