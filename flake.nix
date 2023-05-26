{
  description = "Dump Gnome's binary keyrings into text format";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-23.05";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        pythonPackages = pkgs.python3Packages;
      in {
        packages = rec {
          default = gnome-keyring-raw;

          gnome-keyring-raw = pythonPackages.buildPythonPackage rec {
            pname = "gnome-keyring-raw";
            version = "0.1.0";

            src = nixpkgs.lib.cleanSource ./.;

            nativeCheckInputs = with pythonPackages; [
              flake8
            ];

            propagatedBuildInputs = with pythonPackages; [
              pyyaml
              pycrypto
            ];
           };
        };
      }
    );
}
