{ pkgs ? import <nixpkgs> {} }:
let
  succinct-toolchain = pkgs.callPackage ./succinct-toolchain.nix {};
in
pkgs.mkShell {
  buildInputs = with pkgs; [
    # SP1 build deps
    clang
    llvmPackages.libclang
    pkg-config
    openssl
    protobuf
    # For patching prebuilt toolchain binaries
    patchelf
    # Standard build tools
    gcc
    gnumake
  ];
  shellHook = ''
    export LIBCLANG_PATH="${pkgs.llvmPackages.libclang.lib}/lib"
    export PKG_CONFIG_PATH="${pkgs.openssl.dev}/lib/pkgconfig"
    export LD_LIBRARY_PATH="${pkgs.lib.makeLibraryPath [ pkgs.openssl pkgs.zlib pkgs.stdenv.cc.cc.lib ]}"
    export SP1_TOOLCHAIN_DIR="${succinct-toolchain}"
  '';
}
