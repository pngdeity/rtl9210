#!/usr/bin/env python3
"""Trace SCSI and USB firmware-update logic in UTHSB_MPtool_Lite.exe using pyghidra.

Requires: pyghidra, jpype (installed by setup.sh)
Outputs: scsi_cdb_sequence.json — structured SCSI command sequence
"""

import argparse
import json
import os
import re
import sys


def _launch_ghidra(install_dir):
    ghidra_install = install_dir or os.environ.get("GHIDRA_INSTALL_DIR")
    if not ghidra_install:
        sys.exit("GHIDRA_INSTALL_DIR not set")
    os.environ["GHIDRA_INSTALL_DIR"] = str(ghidra_install)

    import pyghidra
    from pyghidra import HeadlessPyGhidraLauncher

    launcher = HeadlessPyGhidraLauncher(verbose=False)
    launcher.start()
    return pyghidra


def extract_scsi_info(binary_path, project_dir, output_path):
    try:
        import pyghidra as _check  # noqa: F401
    except ImportError:
        print("pyghidra not available — skipping targeted SCSI trace", file=sys.stderr)
        with open(output_path, "w") as f:
            json.dump(
                {"status": "skipped", "reason": "pyghidra not available"},
                f,
                indent=2,
            )
        return

    results = {
        "binary": os.path.basename(binary_path),
        "device_paths": [],
        "scsi_functions": [],
        "cdb_extractions": [],
        "strings_of_interest": [],
        "file_references": [],
        "error": None,
    }

    try:
        project_path = project_dir
        os.makedirs(project_path, exist_ok=True)

        print(f"Opening binary with pyghidra: {binary_path}")
        print(f"Project path: {project_path}")

        ghidra = _launch_ghidra(os.environ.get("GHIDRA_INSTALL_DIR"))

        with ghidra.open_program(
            binary_path,
            project_location=project_path,
            analyze=True,
        ) as flat_api:
            program = flat_api.getCurrentProgram()
            fm = program.getFunctionManager()
            listing = program.getListing()

            print("Setting up decompiler ...")
            from ghidra.app.decompiler import DecompInterface
            from ghidra.util.task import ConsoleTaskMonitor

            decompiler = DecompInterface()
            decompiler.openProgram(program)
            monitor = ConsoleTaskMonitor()

            print("Collecting strings ...")
            string_count = 0
            for data in listing.getDefinedData(True):
                if data and data.hasStringValue():
                    s = str(data)
                    string_count += 1
                    if _is_interesting_string(s):
                        addr = data.getAddress()
                        results["strings_of_interest"].append(
                            {
                                "address": str(addr),
                                "value": s,
                            }
                        )

            print(
                f"  {string_count} strings, {len(results['strings_of_interest'])} interesting"
            )

            functions = list(fm.getFunctions(True))
            print(f"Enumerating {len(functions)} functions ...")

            scsi_keywords = re.compile(
                r"DeviceIoControl|CreateFile[AW]|SCSI|CDB|WRITE.BUFFER|"
                r"IOCTL_SCSI|PhysicalDrive|SetupDi|WinUSB|"
                r"firmware|gdfw|\.bin|\.cfg",
                re.IGNORECASE,
            )

            for i, func in enumerate(functions):
                if (i + 1) % 5000 == 0:
                    print(f"  processed {i + 1}/{len(functions)} ...")

                name = func.getName() or "(unnamed)"
                addr = func.getEntryPoint()

                try:
                    result = decompiler.decompileFunction(func, 30, monitor)
                    if result and result.decompileCompleted():
                        decomp = result.getDecompiledFunction().getC()
                    else:
                        decomp = None
                except Exception:
                    decomp = None

                if not decomp:
                    continue

                if not scsi_keywords.search(decomp):
                    continue

                results["scsi_functions"].append(
                    {
                        "name": name,
                        "address": str(addr),
                        "code": decomp,
                    }
                )

                for match in re.finditer(
                    r'\\\\\.\\(?:PhysicalDrive\d+|USB#[^"]+|SCSI\d+)', decomp
                ):
                    results["device_paths"].append(match.group(0))

                for match in re.finditer(
                    r'["\']([^"\']+\.(?:bin|cfg|gdfw)[^"\']*)["\']',
                    decomp,
                    re.IGNORECASE,
                ):
                    results["file_references"].append(match.group(1))

                if _has_cdb_pattern(decomp):
                    extraction = _extract_cdb_info(decomp, name, addr)
                    if extraction:
                        results["cdb_extractions"].append(extraction)

            results["device_paths"] = sorted(set(results["device_paths"]))
            results["file_references"] = sorted(set(results["file_references"]))

            print(f"  SCSI-related functions: {len(results['scsi_functions'])}")
            print(f"  Device paths: {len(results['device_paths'])}")
            print(f"  CDB extractions: {len(results['cdb_extractions'])}")
            print(f"  File references: {len(results['file_references'])}")

    except Exception as e:
        results["error"] = str(e)
        print(f"Error during pyghidra analysis: {e}", file=sys.stderr)
        import traceback

        results["traceback"] = traceback.format_exc()

    with open(output_path, "w") as f:
        json.dump(results, f, indent=2, default=str)

    print(f"Wrote SCSI trace to {output_path}")


def _is_interesting_string(s):
    keywords = [
        "PhysicalDrive",
        "USB#",
        "SCSI",
        "\\\\",
        "VID_",
        "PID_",
        "RTL9210",
        "Sabrent",
        "Realtek",
        "0x0bda",
        "0bda",
        "9210",
        "gdfw",
        "firmware",
        "UTNVME",
        "UTHSB",
        "MPtool",
        "NVME",
        "WRITE_BUFFER",
        "IOCTL_SCSI",
        "SCSIOP_",
        "SEND_DIAGNOSTIC",
        "DeviceIoControl",
        "CreateFile",
        ".bin",
        ".cfg",
        "GD_",
        "golden",
        "Signed",
        "signed",
    ]
    slow = s.lower()
    return any(kw.lower() in slow for kw in keywords)


def _has_cdb_pattern(decomp):
    """Check if decompiled function constructs a SCSI CDB."""
    cdb_indicators = [
        r"\.Cdb\s*\[",  # Array indexing: sptd.Cdb[i]
        r"cdb\s*\[",  # Direct array: cdb[i]
        r"(?:0x|\\x)3[bB]\b",  # WRITE_BUFFER opcode
        r"(?:0x|\\x)3[cC]\b",  # READ_BUFFER opcode
        r"WRITE_BUFFER",  # Named constant
        r"WRITE_DATA_BUFF",  # Alternative
        r"SCSI_PASS_THROUGH",  # SPT structure
        r"CmdBlock\b",  # CDB block
        r"CommandDescriptor",  # CDB full name
        r"scsiCommand\b|scsi_cmd\b",  # Variable naming
        r"BUFFER_FFU_MODE",  # FFU mode constant (0x0E)
        r"download_microcode",  # Microcode download
    ]
    return any(re.search(p, decomp, re.IGNORECASE) for p in cdb_indicators)


def _extract_cdb_info(decomp, func_name, func_addr):
    """Try to extract CDB byte sequence from decompiled function."""
    info = {
        "function": func_name,
        "address": str(func_addr),
        "suspected_opcode": None,
        "suspected_mode": None,
        "cdb_assignments": [],
    }

    # Look for CDB[i] = 0xNN assignments (Ghidra decompiler output format)
    for match in re.finditer(
        r"(?:Cdb|cdb)\s*\[(\d+)\]\s*=\s*(0x[0-9a-fA-F]+|\d+)", decomp
    ):
        info["cdb_assignments"].append(
            {
                "index": int(match.group(1)),
                "value": match.group(2),
            }
        )

    # Detect opcode from byte pattern
    for match in re.finditer(r"(?:0[xX])?3[bB]\b", decomp):
        info["suspected_opcode"] = "0x3B (WRITE BUFFER)"

    for match in re.finditer(r"(?:0[xX])?3[cC]\b", decomp):
        if not info["suspected_opcode"]:
            info["suspected_opcode"] = "0x3C (READ BUFFER)"

    # Detect mode byte
    mode_patterns = [
        (
            r"BUFFER_FFU_MODE|0x0[Ee]\b|mode.*=\s*0xe|0x0E\b",
            "0x0E (download microcode with offsets, save)",
        ),
        (
            r"0x0[Ff]\b|mode.*=\s*0xf",
            "0x0F (download microcode with offsets, deferred)",
        ),
        (r"0x0[45]\b|mode.*=\s*0x[45]", "0x04/0x05 (download microcode, no offsets)"),
        (r"0x1[cCdD]\b", "0x1C/0x1D (echo buffer / enable expander)"),
    ]
    for pattern, desc in mode_patterns:
        if re.search(pattern, decomp, re.IGNORECASE):
            info["suspected_mode"] = desc
            break

    # Only return if we found something useful
    if info["cdb_assignments"] or info["suspected_opcode"]:
        return info
    return None


def main():
    parser = argparse.ArgumentParser(
        description="Trace SCSI firmware update logic via pyghidra"
    )
    parser.add_argument("--binary", required=True, help="Path to UTHSB_MPtool_Lite.exe")
    parser.add_argument("--project-dir", required=True, help="Ghidra project directory")
    parser.add_argument("--output", required=True, help="Output JSON file")
    args = parser.parse_args()

    extract_scsi_info(args.binary, args.project_dir, args.output)


if __name__ == "__main__":
    main()
