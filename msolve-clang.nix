{ pkgs ? import <nixpkgs> {} }:

let
  clangStdenv = pkgs.clangStdenv;
in
pkgs.msolve.override {
  stdenv = clangStdenv;
}

