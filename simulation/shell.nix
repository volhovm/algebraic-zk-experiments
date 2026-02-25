{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  packages = [
    (pkgs.python3.withPackages (ps: [
      ps.jupyter
      ps.networkx
      ps.matplotlib
      ps.numpy
      ps.tqdm
    ]))
  ];
}
