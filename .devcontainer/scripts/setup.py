#!/usr/bin/env python3
"""Download Ghidra, install pyghidra (offline) and ghidrecomp, extract firmware."""

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path
from urllib.request import urlretrieve

GHIDRA_VERSION = "12.1.2"
GHIDRA_TAG = "Ghidra_12.1.2_build"
GHIDRA_FILENAME = "ghidra_12.1.2_PUBLIC_20260605.zip"
GHIDRA_URL = f"https://github.com/NationalSecurityAgency/ghidra/releases/download/{GHIDRA_TAG}/{GHIDRA_FILENAME}"
GHIDRA_SHA256 = "b62e81a0390618466c019c60d8c2f796ced2509c4c1aea4a37644a77272cf99d"

GHIDRA_INSTALL_DIR = "/opt/ghidra"
FIRMWARE_ZIP = "firmware/realtek_rtl9210B_fw1.34.39(station-drivers.com).zip"
JAVA_VERSION = "21"
POLL_INTERVAL = 5
MAX_WAIT = 300


def run(cmd, **kwargs):
    print(f"  $ {' '.join(cmd)}")
    return subprocess.run(cmd, check=True, **kwargs)


def download_ghidra():
    print(f"\n=== Downloading Ghidra {GHIDRA_VERSION} ===")
    dest = Path("/tmp") / GHIDRA_FILENAME
    if dest.exists():
        print(f"  Already downloaded: {dest}")
    else:
        print(f"  Downloading from {GHIDRA_URL} ...")
        urlretrieve(GHIDRA_URL, dest)
    size_mb = dest.stat().st_size / (1024 * 1024)
    print(f"  Downloaded: {size_mb:.0f} MB")

    print("  Verifying SHA256 ...")
    sha = hashlib.sha256(dest.read_bytes()).hexdigest()
    if sha != GHIDRA_SHA256:
        sys.exit(f"SHA256 mismatch:\n  expected: {GHIDRA_SHA256}\n  got:      {sha}")
    print("  SHA256 OK")
    return dest


def extract_ghidra(zip_path):
    print("\n=== Extracting Ghidra ===")
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall("/opt")
    zip_path.unlink()

    dirs = sorted(Path("/opt").glob("ghidra_*_PUBLIC*"))
    if not dirs:
        sys.exit("No Ghidra directory found under /opt/")
    src = dirs[0]
    print(f"  Extracted: {src}")

    symlink = Path(GHIDRA_INSTALL_DIR)
    if symlink.is_symlink() or symlink.exists():
        symlink.unlink()
    symlink.symlink_to(src)
    print(f"  Symlinked: {GHIDRA_INSTALL_DIR} -> {src}")


def wait_for_java():
    print(f"\n=== Waiting for Java {JAVA_VERSION} ===")
    java_home = os.environ.get("JAVA_HOME", "/usr/local/sdkman/candidates/java/current")
    bin_dir = Path(java_home) / "bin"
    java_bin = shutil.which("java", path=str(bin_dir)) or "java"

    elapsed = 0
    while elapsed < MAX_WAIT:
        try:
            result = subprocess.run(
                [java_bin, "-version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            stderr = result.stderr or result.stdout
            if JAVA_VERSION in stderr:
                print(f"  Java: {stderr.splitlines()[0]}")
                return
        except Exception:
            pass
        print(f"  waiting for JDK {JAVA_VERSION} ... ({elapsed}s)")
        time.sleep(POLL_INTERVAL)
        elapsed += POLL_INTERVAL

    sys.exit(f"Java {JAVA_VERSION} not found after {MAX_WAIT}s")


def install_pyghidra():
    print("\n=== Installing pyghidra (offline from Ghidra bundle) ===")
    pypkg = Path(GHIDRA_INSTALL_DIR) / "Ghidra/Features/PyGhidra/pypkg/dist"
    if not pypkg.exists():
        sys.exit(f"pyghidra dist not found at {pypkg}")

    env = {**os.environ, "GHIDRA_INSTALL_DIR": GHIDRA_INSTALL_DIR}
    run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--user",
            "--no-index",
            "-f",
            str(pypkg),
            "pyghidra",
        ],
        env=env,
    )

    result = subprocess.run(
        [sys.executable, "-c", "import pyghidra; print(pyghidra.__version__)"],
        capture_output=True,
        text=True,
        env=env,
    )
    if result.returncode == 0:
        print(f"  pyghidra version: {result.stdout.strip()}")
    else:
        print(f"  WARNING: pyghidra import test failed:\n{result.stderr}")


def install_ghidrecomp():
    print("\n=== Installing ghidrecomp ===")
    env = {**os.environ, "GHIDRA_INSTALL_DIR": GHIDRA_INSTALL_DIR}
    run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--user",
            "--no-deps",
            "ghidrecomp",
        ],
        env=env,
    )

    result = subprocess.run(
        [sys.executable, "-m", "ghidrecomp", "--version"],
        capture_output=True,
        text=True,
        env=env,
    )
    if result.returncode == 0:
        print(f"  ghidrecomp: {result.stdout.strip()}")
    else:
        print(f"  ghidrecomp: {result.stderr.strip() or result.stdout.strip()}")


def extract_firmware(workspace):
    print("\n=== Extracting UTHSB_MPtool_Lite.exe from firmware zip ===")
    zip_path = Path(workspace) / FIRMWARE_ZIP
    if not zip_path.exists():
        sys.exit(f"Firmware zip not found: {zip_path}")

    dest = Path.home() / "binaries"
    dest.mkdir(exist_ok=True)

    with zipfile.ZipFile(zip_path, "r") as zf:
        members = [
            "Windows/UTHSB_MPtool_Lite.exe",
            "Windows/UTHSB_MPtool_Lite.ini",
            "Windows/RTL9210B_v1.34.39.032625.bin",
            "Windows/gdfw/RTL9210B_gd_v4.30.23.071922.bin",
        ]
        for m in members:
            if m in zf.namelist():
                zf.extract(m, dest)
                print(f"  Extracted: {dest / m}")
            else:
                print(f"  WARNING: not found in zip: {m}")

    exe_path = dest / "Windows/UTHSB_MPtool_Lite.exe"
    fw_path = dest / "Windows/RTL9210B_v1.34.39.032625.bin"
    gd_path = dest / "Windows/gdfw/RTL9210B_gd_v4.30.23.071922.bin"

    for label, p in [("binary", exe_path), ("firmware", fw_path), ("gdfw", gd_path)]:
        if p.exists():
            print(f"  {label}: {p} ({p.stat().st_size} bytes)")
        else:
            print(f"  {label}: NOT FOUND")


def main():
    workspace = os.environ.get("GITHUB_WORKSPACE", "/workspaces/rtl9210")
    os.environ["GHIDRA_INSTALL_DIR"] = GHIDRA_INSTALL_DIR

    zip_path = download_ghidra()
    extract_ghidra(zip_path)
    wait_for_java()
    install_pyghidra()
    install_ghidrecomp()
    extract_firmware(workspace)

    print()
    print("=== Setup complete ===")
    print()
    print("Run the decompilation:")
    print(f"  python3 {Path(workspace) / '.devcontainer' / 'scripts' / 'decompile.py'}")


if __name__ == "__main__":
    main()
