#!/usr/bin/env python3
"""Write the ACP Registry entry for a released MicroClaw Code version.

Usage: scripts/acp_registry_entry.py VERSION OUT_DIR

Reads the release's SHA256SUMS.txt and writes OUT_DIR/agent.json plus
OUT_DIR/icon.svg, ready to copy into a fork of
https://github.com/agentclientprotocol/registry as `mccode/`.
"""
import json
import shutil
import sys
import urllib.request
from pathlib import Path

REPO = "https://github.com/microclaw/microclaw"
TARGETS = {
    "darwin-aarch64": ("aarch64-apple-darwin", "tar.gz", "./mccode"),
    "darwin-x86_64": ("x86_64-apple-darwin", "tar.gz", "./mccode"),
    "linux-aarch64": ("aarch64-linux-gnu", "tar.gz", "./mccode"),
    "linux-x86_64": ("x86_64-linux-gnu", "tar.gz", "./mccode"),
    "windows-x86_64": ("x86_64-windows-msvc", "zip", "mccode.exe"),
}


def main() -> None:
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    version, out = sys.argv[1].lstrip("v"), Path(sys.argv[2])
    base = f"{REPO}/releases/download/v{version}"
    with urllib.request.urlopen(f"{base}/SHA256SUMS.txt") as response:
        sums = {
            name: digest
            for digest, name in (
                line.split() for line in response.read().decode().splitlines() if line.strip()
            )
        }
    binary = {}
    for platform, (triple, ext, cmd) in TARGETS.items():
        asset = f"mccode-{version}-{triple}.{ext}"
        if asset not in sums:
            sys.exit(f"{asset} is not in the v{version} release")
        binary[platform] = {
            "archive": f"{base}/{asset}",
            "sha256": sums[asset],
            "cmd": cmd,
            "args": ["acp"],
        }
    entry = {
        "id": "mccode",
        "name": "MicroClaw Code",
        "version": version,
        "description": "Coding agent with checks, fix rounds, an OS sandbox and any model provider",
        "repository": REPO,
        "website": f"{REPO}/tree/main/apps/microclaw-code",
        "authors": ["MicroClaw contributors"],
        "license": "MIT",
        "license_url": f"{REPO}/blob/main/LICENSE",
        "icon": "./icon.svg",
        "distribution": {"binary": binary},
    }
    out.mkdir(parents=True, exist_ok=True)
    (out / "agent.json").write_text(json.dumps(entry, indent=2) + "\n")
    shutil.copy(Path(__file__).resolve().parent.parent / "packaging/acp-registry/icon.svg", out)
    print(f"wrote {out / 'agent.json'} and icon.svg for v{version}")


if __name__ == "__main__":
    main()
