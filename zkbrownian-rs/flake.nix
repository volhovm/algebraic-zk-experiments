{
  description = "zkbrownian-rs development environment";

  inputs = {
    naersk.url = "github:nix-community/naersk/master";
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    utils.url = "github:numtide/flake-utils";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = { self, nixpkgs, utils, naersk, rust-overlay }:
    utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
          config.allowUnfree = true;
        };

        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "rust-analyzer" ];
          targets = [ "aarch64-linux-android" ];
        };

        naersk-lib = pkgs.callPackage naersk {
          cargo = rustToolchain;
          rustc = rustToolchain;
        };

        androidNdk = pkgs.androidenv.androidPkgs.ndk-bundle;
        ndkToolchain = "${androidNdk}/libexec/android-sdk/ndk-bundle/toolchains/llvm/prebuilt/linux-x86_64";
      in
      {
        defaultPackage = naersk-lib.buildPackage ./.;

        devShell = pkgs.mkShell {
          buildInputs = [
            # Rust toolchain (with Android target)
            rustToolchain

            # Build tools
            pkgs.pkg-config
            pkgs.openssl

            # macOS compatibility
            pkgs.libiconv

            # Android
            androidNdk
          ];

          shellHook = ''
            echo "zkbrownian-rs development environment"
            echo "Rust version: $(rustc --version)"
            echo "Cargo version: $(cargo --version)"
          '';

          CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER = "${ndkToolchain}/bin/aarch64-linux-android33-clang";
          CARGO_TARGET_AARCH64_LINUX_ANDROID_AR = "${ndkToolchain}/bin/llvm-ar";
        };
      }
    );
}
