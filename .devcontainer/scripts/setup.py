#!/usr/bin/env python3
"""Download Ghidra, install pyghidra (offline) and ghidrecomp, extract firmware."""

import hashlib
import os
import subprocess
import sys
import time
import zipfile
from pathlib import Path
from urllib.request import urlretrieve

GHIDRA_VERSION = "12.1"
GHIDRA_TAG = "Ghidra_12.1_build"
GHIDRA_FILENAME = "ghidra_12.1_PUBLIC_20260513.zip"
GHIDRA_URL = f"https://github.com/NationalSecurityAgency/ghidra/releases/download/{GHIDRA_TAG}/{GHIDRA_FILENAME}"
GHIDRA_SHA256 = "aa5cbcbbf48f41ca185fce900e19592f1ade4cd5994eb6e0ede468dac8a6f302"

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


def switch_to_jdk_21():
    """Switch to JDK 21 via SDKMAN; devcontainer features install 21+25, pick 21."""
    print(f"\n=== Switching to Java 21 ===")
    sdkman_dir = Path("/usr/local/sdkman")
    sdkman_init = sdkman_dir / "bin" / "sdkman-init.sh"
    sdk_bin = sdkman_dir / "bin" / "sdkman-init.sh"
    candidates = sdkman_dir / "candidates" / "java"

    elapsed = 0
    while elapsed < MAX_WAIT:
        if sdkman_init.exists() and candidates.exists():
            break
        print(f"  waiting for SDKMAN ... ({elapsed}s)")
        time.sleep(POLL_INTERVAL)
        elapsed += POLL_INTERVAL
    else:
        sys.exit(f"SDKMAN not available after {MAX_WAIT}s")

    java_candidates = sorted(
        [d for d in candidates.iterdir() if d.is_dir() and d.name != "current"],
        reverse=True,
    )
    jdk21 = next(
        (d for d in java_candidates if d.name.startswith("21.") or d.name == "21"), None
    )

    if not jdk21:
        jdk21s = [d.name for d in java_candidates if "21" in d.name]
        if jdk21s:
            sys.exit(f"JDK 21 not found under {candidates}. Available: {jdk21s}")

    if jdk21:
        java_home = jdk21
    else:
        java_home = candidates / "current"

    os.environ["JAVA_HOME"] = str(java_home)
    os.environ["PATH"] = f"{java_home / 'bin'}:{os.environ.get('PATH', '')}"

    result = subprocess.run(
        [str(java_home / "bin" / "java"), "-version"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    ver_line = (
        (result.stderr or result.stdout).splitlines()[0]
        if (result.stderr or result.stdout)
        else "unknown"
    )
    print(f"  Java home: {java_home}")
    print(f"  {ver_line}")

    if "21" not in ver_line and not jdk21:
        print("  WARNING: failed to confirm JDK 21")


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
    switch_to_jdk_21()
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
