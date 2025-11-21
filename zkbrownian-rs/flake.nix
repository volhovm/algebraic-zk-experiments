{
  description = "zkbrownian-rs development environment";

  inputs = {
    naersk.url = "github:nix-community/naersk/master";
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, utils, naersk }:
    utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        naersk-lib = pkgs.callPackage naersk { };
      in
      {
        defaultPackage = naersk-lib.buildPackage ./.;

        devShell = with pkgs; mkShell {
          buildInputs = [
            # Rust toolchain
            cargo
            rustc
            rustfmt
            rust-analyzer
            clippy

            # Build tools
            pkg-config
            openssl

            # macOS compatibility
            libiconv
          ];

          shellHook = ''
            export RUST_SRC_PATH="${rustPlatform.rustLibSrc}"
            echo "zkbrownian-rs development environment"
            echo "Rust version: $(rustc --version)"
            echo "Cargo version: $(cargo --version)"
          '';
        };
      }
    );
}
