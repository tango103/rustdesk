#!/usr/bin/env python3
"""Prepare a Windows Sciter release folder with inline UI and sciter.dll."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.request import urlretrieve

SCITER_DLL_URL_X64 = "https://github.com/c-smile/sciter-sdk/raw/master/bin.win/x64/sciter.dll"
SCITER_DLL_URL_X86 = "https://github.com/c-smile/sciter-sdk/raw/master/bin.win/x32/sciter.dll"



def run(cmd: list[str], cwd: Path) -> None:
    print("+", " ".join(cmd))
    subprocess.run(cmd, cwd=cwd, check=True)



def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build rustdesk.exe (Sciter inline UI) and stage Release folder with sciter.dll"
    )
    parser.add_argument(
        "--target",
        default="",
        help="Optional cargo target (for example i686-pc-windows-msvc or x86_64-pc-windows-msvc)",
    )
    parser.add_argument(
        "--release-dir",
        default="Release",
        help="Output folder for rustdesk.exe + sciter.dll",
    )
    return parser.parse_args()



def cargo_release_exe(repo: Path, target: str) -> Path:
    if target:
        return repo / "target" / target / "release" / "rustdesk.exe"
    return repo / "target" / "release" / "rustdesk.exe"



def sciter_url_for_target(target: str) -> str:
    target_lower = target.lower()
    if "i686" in target_lower or "x86" in target_lower:
        return SCITER_DLL_URL_X86
    return SCITER_DLL_URL_X64



def main() -> int:
    args = parse_args()
    repo = Path(__file__).resolve().parents[2]
    release_dir = (repo / args.release_dir).resolve()
    release_dir.mkdir(parents=True, exist_ok=True)

    # 1) Inline UI so runtime no longer needs src/ui files.
    run([sys.executable, "res/inline-sciter.py"], repo)

    # 2) Build Sciter binary with inline feature.
    cargo_cmd = ["cargo", "build", "--features", "inline,vram,hwcodec", "--release", "--bins"]
    if args.target:
        cargo_cmd.extend(["--target", args.target])
    run(cargo_cmd, repo)

    rustdesk_exe = cargo_release_exe(repo, args.target)
    if not rustdesk_exe.exists():
        raise FileNotFoundError(f"RustDesk executable not found: {rustdesk_exe}")

    # 3) Stage release folder.
    out_exe = release_dir / "rustdesk.exe"
    shutil.copy2(rustdesk_exe, out_exe)
    print(f"Copied: {out_exe}")

    sciter_url = sciter_url_for_target(args.target)
    out_dll = release_dir / "sciter.dll"
    urlretrieve(sciter_url, out_dll)
    print(f"Downloaded: {out_dll} ({sciter_url})")

    print("Done. Release folder ready.")
    return 0



if __name__ == "__main__":
    raise SystemExit(main())
