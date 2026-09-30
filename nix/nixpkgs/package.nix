# Template for pkgs/by-name/mi/microclaw/package.nix in NixOS/nixpkgs.
#
# scripts/update-nixpkgs.sh copies this file into a nixpkgs checkout when the
# package does not exist there yet (the "init" case), then resolves the three
# placeholder hashes from nix-build output. Keep it buildable against
# nixos-unstable / master; nixpkgs has no network access at build time, so the
# web UI bundle is produced from a pre-fetched npm cache and the Rust build is
# told not to invoke npm itself.
{
  lib,
  stdenv,
  rustPlatform,
  fetchFromGitHub,
  fetchNpmDeps,
  npmHooks,
  nodejs,
  pkg-config,
  openssl,
  versionCheckHook,
}:

rustPlatform.buildRustPackage (finalAttrs: {
  pname = "microclaw";
  version = "0.7.0";

  src = fetchFromGitHub {
    owner = "microclaw";
    repo = "microclaw";
    tag = "v${finalAttrs.version}";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };

  # The workspace lockfile pins Git revisions of GPUI/Zed crates used by the
  # optional desktop app. fetchCargoVendor vendors them behind this one hash.
  cargoHash = "sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=";

  # Only the server binary is packaged; skip the GPUI desktop crates.
  cargoBuildFlags = [
    "--package"
    "microclaw"
  ];

  npmDeps = fetchNpmDeps {
    name = "${finalAttrs.pname}-${finalAttrs.version}-npm-deps";
    src = "${finalAttrs.src}/web";
    hash = "sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=";
  };
  npmRoot = "web";

  nativeBuildInputs = [
    pkg-config
    nodejs
    npmHooks.npmConfigHook
  ];

  # rusqlite and sqlite-vec compile their bundled SQLite; native-tls links
  # OpenSSL on Linux (Security.framework on Darwin).
  buildInputs = lib.optionals stdenv.hostPlatform.isLinux [ openssl ];

  buildFeatures = lib.optionals stdenv.hostPlatform.isLinux [
    "journald"
    "sqlite-vec"
  ];

  # build.rs embeds web/dist into the binary. Build the bundle from the
  # offline npm cache first and stop build.rs from running npm on its own.
  preBuild = ''
    npm --prefix web run build
  '';
  env.MICROCLAW_SKIP_WEB_BUILD = "1";

  # The test suite needs a writable data dir and live provider endpoints.
  doCheck = false;

  nativeInstallCheckInputs = [ versionCheckHook ];
  doInstallCheck = true;

  meta = {
    description = "Multi-channel agent runtime for Telegram, Discord, Slack, Feishu, and Web";
    homepage = "https://github.com/microclaw/microclaw";
    changelog = "https://github.com/microclaw/microclaw/releases/tag/v${finalAttrs.version}";
    license = lib.licenses.mit;
    mainProgram = "microclaw";
    platforms = lib.platforms.linux ++ lib.platforms.darwin;
    maintainers = with lib.maintainers; [ everettjf ];
  };
})
