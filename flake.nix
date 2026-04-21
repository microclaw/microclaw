{
  description = "MicroClaw - Multi-channel agent runtime";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
        };
        webAssets = pkgs.buildNpmPackage {
          pname = "microclaw-web-assets";
          version = "0.1.0";
          src = ./web;
          npmBuildScript = "build";
          npmDeps = pkgs.importNpmLock {
            npmRoot = ./web;
          };
          npmConfigHook = pkgs.importNpmLock.npmConfigHook;

          installPhase = ''
            runHook preInstall
            mkdir -p $out
            cp -r dist $out/dist
            runHook postInstall
          '';
        };
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            pkg-config
            openssl
            sqlite
            libsodium
          ] ++ pkgs.lib.optionals pkgs.stdenv.isLinux [
            udev
          ];

          LD_LIBRARY_PATH = "${pkgs.openssl}/lib:${pkgs.sqlite}/lib:${pkgs.libsodium}/lib";

          shellHook = ''
            export OPENSSL_DIR=${pkgs.openssl.dev}
            export OPENSSL_LIB_DIR=${pkgs.openssl.out}/lib
            export OPENSSL_INCLUDE_DIR=${pkgs.openssl.dev}/include
            export PKG_CONFIG_PATH=${pkgs.openssl.out}/lib/pkgconfig:$PKG_CONFIG_PATH
          '';
        };

        packages = {
          microclaw = pkgs.rustPlatform.buildRustPackage {
            pname = "microclaw";
            version = "0.0.163";
            src = ./.;
            cargoLock.lockFile = ./Cargo.lock;
            buildFeatures = pkgs.lib.optionals pkgs.stdenv.isLinux [ "journald" "sqlite-vec" ];
            nativeBuildInputs = with pkgs; [
              pkg-config
            ];
            buildInputs = with pkgs; [
              openssl.out
              sqlite
              libsodium
            ] ++ pkgs.lib.optionals pkgs.stdenv.isLinux [
              udev
            ];
            OPENSSL_DIR = "${pkgs.openssl.dev}";
            OPENSSL_LIB_DIR = "${pkgs.openssl.out}/lib";
            OPENSSL_INCLUDE_DIR = "${pkgs.openssl.dev}/include";
            LD_LIBRARY_PATH = "${pkgs.openssl.out}/lib:${pkgs.sqlite}/lib:${pkgs.libsodium}/lib";
            preBuild = ''
              rm -rf web/dist
              cp -r ${webAssets}/dist web/dist
            '';
            doCheck = false;
          };
          default = self.packages.${system}.microclaw;
        };
      }
    );
}
