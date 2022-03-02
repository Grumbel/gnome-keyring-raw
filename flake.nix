{
  description = "Dump Gnome's binary keyrings into text format";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-21.11";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in rec {
        packages = flake-utils.lib.flattenTree {
          gnome-keyring-raw = pkgs.python3Packages.buildPythonPackage rec {
            pname = "gnome-keyring-raw";
            version = "0.1.0";
            src = nixpkgs.lib.cleanSource ./.;
            nativeBuildInputs = with pkgs.python3.pkgs; [
              flake8
            ];
            propagatedBuildInputs = with pkgs.python3.pkgs; [
              pyyaml
              pycrypto
            ];
           };
        };
        defaultPackage = packages.gnome-keyring-raw;
      });
}
