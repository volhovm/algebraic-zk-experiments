{ stdenv, fetchurl, autoPatchelfHook, zlib }:

stdenv.mkDerivation {
  pname = "succinct-rust-toolchain";
  version = "1.93.0-64bit";

  src = fetchurl {
    url = "https://github.com/succinctlabs/rust/releases/download/succinct-1.93.0-64bit/rust-toolchain-x86_64-unknown-linux-gnu.tar.gz";
    sha256 = "sha256-meaN2GTdfulogzM0a0KEUscF2CoRCY5RFGOJQX4MgsY=";
  };

  sourceRoot = ".";

  nativeBuildInputs = [ autoPatchelfHook ];
  buildInputs = [ stdenv.cc.cc.lib zlib ];

  installPhase = ''
    mkdir -p $out
    cp -r bin lib $out/
  '';
}
