#!/usr/bin/env python3
"""Run the full 5-step decompilation pipeline."""

import argparse
import json
import os
import subprocess
import sys
import tarfile
import time
from pathlib import Path


def run(cmd, check=True, log_file=None, **kwargs):
    label = " ".join(str(c) for c in cmd)
    print(f"  $ {label}")
    start = time.monotonic()

    if log_file:
        with open(log_file, "w") as lf:
            result = subprocess.run(cmd, stdout=lf, stderr=subprocess.STDOUT, **kwargs)
    else:
        result = subprocess.run(cmd, capture_output=True, text=True, **kwargs)
        if result.stdout:
            for line in result.stdout.strip().splitlines():
                print(f"    {line}")

    elapsed = time.monotonic() - start
    status = "OK" if result.returncode == 0 else f"FAILED (exit {result.returncode})"
    print(f"  [{status}] {elapsed:.1f}s")

    if check and result.returncode != 0:
        if result.stderr:
            print(f"  stderr: {result.stderr[:500]}", file=sys.stderr)
        raise subprocess.CalledProcessError(result.returncode, cmd)
    return result


def ensure_decomp_corpus(output_dir, workspace):
    corpus_dir = output_dir / "decomp_all"
    if corpus_dir.exists() and any(corpus_dir.iterdir()):
        count = len(list(corpus_dir.glob("*.c")))
        print(f"\n=== Step 1: SKIPPED (corpus exists: {count} functions) ===")
        return count

    tarball = workspace / "decompile-output" / "decomp_all.tar.gz"
    if tarball.exists():
        print(f"\n=== Step 1: Extracting corpus from {tarball.name} ===")
        output_dir.mkdir(parents=True, exist_ok=True)
        with tarfile.open(tarball, "r:gz") as tf:
            tf.extractall(output_dir)
        count = len(list(corpus_dir.glob("*.c")))
        print(f"  Extracted {count} functions")
        return count

    return None


def step_ghidrecomp(binary_path, output_dir):
    print("\n=== Step 1: ghidrecomp — batch decompile all functions ===")
    size_mb = Path(binary_path).stat().st_size / (1024 * 1024)
    print(f"  Binary: {binary_path} ({size_mb:.1f} MB)")
    print("  Estimated time: 45-90 minutes")

    log_path = output_dir / "ghidrecomp.log"
    output_path = output_dir / "decomp_all"
    output_path.mkdir(parents=True, exist_ok=True)

    env = {
        **os.environ,
        "GHIDRA_INSTALL_DIR": os.environ.get("GHIDRA_INSTALL_DIR", "/opt/ghidra"),
    }
    env["PATH"] = (
        f"{Path.home()}/.local/bin:{env['GHIDRA_INSTALL_DIR']}/support:{env.get('PATH', '')}"
    )

    run(
        [
            "ghidrecomp",
            "--va",
            "--output-path",
            str(output_path),
            "--thread-count",
            "4",
            "--max-ram-percent",
            "60",
            str(binary_path),
        ],
        check=False,
        log_file=log_path,
        env=env,
    )

    count = len(list(output_path.glob("*.c")))
    print(f"  Decompiled {count} functions")
    return count


def step_scan_patterns(output_dir, scripts_dir):
    print("\n=== Step 2: scan_patterns — grep .c corpus for USB/SCSI/IO patterns ===")
    output_file = output_dir / "pattern_matches.txt"

    run(
        [
            sys.executable,
            str(scripts_dir / "scan_patterns.py"),
            "--input",
            str(output_dir / "decomp_all"),
            "--output",
            str(output_file),
        ]
    )

    match_count = 0
    if output_file.exists():
        match_count = sum(1 for _ in open(output_file))
    print(f"  Pattern matches: {match_count} lines")
    return match_count


def step_filter_decomp(output_dir, scripts_dir):
    print("\n=== Step 3: filter_decomp — copy relevant .c files ===")
    output_path = output_dir / "relevant_decomp"

    run(
        [
            sys.executable,
            str(scripts_dir / "filter_decomp.py"),
            "--input",
            str(output_dir / "decomp_all"),
            "--output",
            str(output_path),
        ]
    )

    count = len(list(output_path.glob("*.c"))) if output_path.exists() else 0
    print(f"  Relevant functions copied: {count}")
    return count


def step_trace_scsi(binary_path, output_dir):
    print("\n=== Step 4: trace_scsi — pyghidra targeted SCSI extraction ===")
    json_path = output_dir / "scsi_cdb_sequence.json"
    scripts_dir = (
        Path(os.environ.get("GITHUB_WORKSPACE", "/workspaces/rtl9210")) / "scripts"
    )
    log_path = output_dir / "trace_scsi.log"

    env = {
        **os.environ,
        "GHIDRA_INSTALL_DIR": os.environ.get("GHIDRA_INSTALL_DIR", "/opt/ghidra"),
    }

    try:
        result = subprocess.run(
            [
                sys.executable,
                str(scripts_dir / "trace_scsi.py"),
                "--binary",
                str(binary_path),
                "--project-dir",
                "/tmp/ghidra-project",
                "--output",
                str(json_path),
            ],
            capture_output=True,
            text=True,
            env=env,
            timeout=1800,
        )
        with open(log_path, "w") as lf:
            lf.write(result.stdout)
            if result.stderr:
                lf.write("\n--- stderr ---\n")
                lf.write(result.stderr)

        if json_path.exists():
            data = json.loads(json_path.read_text())
            status = data.get("status", "completed")
            print(f"  SCSI trace status: {status}")
            if status == "skipped":
                print(f"  Reason: {data.get('reason', 'unknown')}")
            else:
                print(f"  SCSI functions: {len(data.get('scsi_functions', []))}")
                print(f"  CDB extractions: {len(data.get('cdb_extractions', []))}")
                print(f"  Device paths: {len(data.get('device_paths', []))}")
        else:
            print("  WARNING: scsi_cdb_sequence.json not produced")
    except subprocess.TimeoutExpired:
        print("  WARNING: trace_scsi timed out after 30 minutes")
    except Exception as e:
        print(f"  WARNING: trace_scsi failed: {e}")


def step_manifest(binary_path, output_dir, decomp_count, relevant_count, match_count):
    print("\n=== Step 5: manifest ===")
    fw_bin = Path.home() / "binaries/Windows/RTL9210B_v1.34.39.032625.bin"
    gd_bin = Path.home() / "binaries/Windows/gdfw/RTL9210B_gd_v4.30.23.071922.bin"

    manifest = {
        "binary": {
            "file": "UTHSB_MPtool_Lite.exe",
            "size": Path(binary_path).stat().st_size,
            "type": "Windows PE (x86)",
            "version": "2.0.2.30818",
        },
        "firmware": {
            "version": "1.34.39.032625",
            "bin": "RTL9210B_v1.34.39.032625.bin",
            "size": fw_bin.stat().st_size if fw_bin.exists() else 0,
        },
        "gd_firmware": {
            "version": "4.30.23.071922",
            "bin": "RTL9210B_gd_v4.30.23.071922.bin",
            "size": gd_bin.stat().st_size if gd_bin.exists() else 0,
        },
        "decompilation": {
            "total_functions": decomp_count,
            "relevant_functions": relevant_count,
            "pattern_matches": match_count,
        },
    }

    manifest_path = output_dir / "v1.34.39_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2))
    print(f"  Manifest written: {manifest_path}")


def main():
    parser = argparse.ArgumentParser(description="Run the decompilation pipeline")
    parser.add_argument(
        "--skip-ghidrecomp",
        action="store_true",
        help="Skip ghidrecomp; use existing corpus or extract from tarball",
    )
    args = parser.parse_args()

    workspace = Path(os.environ.get("GITHUB_WORKSPACE", "/workspaces/rtl9210"))
    binary_path = Path.home() / "binaries/Windows/UTHSB_MPtool_Lite.exe"
    output_dir = Path.home() / "decompile-output"
    scripts_dir = workspace / "scripts"

    if not binary_path.exists():
        sys.exit(f"Binary not found: {binary_path}\nRun setup.py first.")

    output_dir.mkdir(parents=True, exist_ok=True)

    pipeline_start = time.monotonic()

    if args.skip_ghidrecomp:
        decomp_count = ensure_decomp_corpus(output_dir, workspace)
        if decomp_count is None:
            sys.exit(
                "Corpus not found. Either:\n"
                "  - Run without --skip-ghidrecomp (45-90 min)\n"
                f"  - Place tarball at {workspace / 'decompile-output' / 'decomp_all.tar.gz'}"
            )
    else:
        decomp_count = step_ghidrecomp(binary_path, output_dir)

    match_count = step_scan_patterns(output_dir, scripts_dir)
    relevant_count = step_filter_decomp(output_dir, scripts_dir)
    step_trace_scsi(binary_path, output_dir)
    step_manifest(binary_path, output_dir, decomp_count, relevant_count, match_count)

    pipeline_elapsed = time.monotonic() - pipeline_start

    print()
    print("=== Decompilation complete ===")
    total_size = sum(f.stat().st_size for f in output_dir.rglob("*") if f.is_file())
    print(f"  Output: {output_dir} ({total_size / (1024 * 1024):.0f} MB)")
    print(f"  Pipeline time: {pipeline_elapsed / 60:.1f} minutes")
    print()
    print("=== Download instructions ===")
    print("  Locally, run:")
    print("    gh codespace cp -r -c CODESPACE_NAME 'remote:decompile-output/' .")


if __name__ == "__main__":
    main()
