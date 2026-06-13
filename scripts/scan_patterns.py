#!/usr/bin/env python3
"""Scan decompiled .c files for USB/SCSI/IO patterns and produce structured matches."""

import argparse
import os
import re
import sys

_RAW_PATTERNS = {
    "device_open": [
        r"CreateFile[AW]?\s*\(",
        r"\\\\\.\\PhysicalDrive",
        r"\\\\\.\\USB#",
        r"\\\\\.\\SCSI",
    ],
    "scsi_passthrough": [
        r"DeviceIoControl\s*\(",
        r"IOCTL_SCSI_PASS_THROUGH",
        r"SCSI_PASS_THROUGH",
        r"SCSI_PASS_THROUGH_DIRECT",
        r"CDB\b",
        r"cdb\b",
    ],
    "scsi_commands": [
        r"(?:0x|\\x)3b\b",  # WRITE BUFFER opcode
        r"(?:0x|\\x)3c\b",  # READ BUFFER opcode
        r"(?:0x|\\x)12\b",  # INQUIRY
        r"WRITE_BUFFER",
        r"WRITE_DATA_BUFF",
        r"SEND_DIAGNOSTIC",
    ],
    "firmware_io": [
        r"\.bin\b",
        r"gdfw\b",
        r"\.cfg\b",
        r"fileSize|file_size|filelen|file_len",
        r"firmware\b",
        r"ReadFile\s*\(",
        r"WriteFile\s*\(",
        r"fopen\b|fread\b|fwrite\b",
    ],
    "device_detection": [
        r"VID_0BDA|vid.*0bda|0x0bda",
        r"PID_9210|pid.*9210|0x9210\b",
        r"RTL9210\b",
        r"Sabrent\b",
        r"SetupDi\w+",
        r"CM_Get_Device_ID",
        r"USB\\.*VID",
    ],
    "usb_transport": [
        r"Bulk\s*(?:In|Out|IN|OUT)",
        r"ControlTransfer",
        r"WinUSB\b",
        r"libusb\b",
        r"Interface\s*=\s*0",
        r"Endpoint\b",
    ],
}

PATTERNS = {
    cat: [re.compile(p, re.IGNORECASE) for p in regexes]
    for cat, regexes in _RAW_PATTERNS.items()
}


def scan_file(filepath):
    """Scan a single .c file for patterns and return matches."""
    matches = []
    try:
        with open(filepath, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except Exception as e:
        print(f"Warning: could not read {filepath}: {e}", file=sys.stderr)
        return matches

    for line_num, line in enumerate(lines, start=1):
        for category, regexes in PATTERNS.items():
            for regex in regexes:
                if regex.search(line):
                    matches.append(
                        {
                            "file": os.path.basename(filepath),
                            "path": filepath,
                            "line": line_num,
                            "category": category,
                            "content": line.strip(),
                        }
                    )
                    break
    return matches


def scan_corpus(input_dir, output_file):
    """Scan all .c files in input_dir."""
    c_files = []
    for root, _, files in os.walk(input_dir):
        for f in files:
            if f.endswith(".c"):
                c_files.append(os.path.join(root, f))

    print(f"Scanning {len(c_files)} .c files for {len(PATTERNS)} pattern categories...")

    all_matches = []
    for i, fpath in enumerate(c_files):
        matches = scan_file(fpath)
        all_matches.extend(matches)
        if (i + 1) % 500 == 0:
            print(
                f"  scanned {i + 1}/{len(c_files)} files, {len(all_matches)} matches so far"
            )

    # Summary
    by_category = {}
    for m in all_matches:
        by_category[m["category"]] = by_category.get(m["category"], 0) + 1

    by_file = {}
    for m in all_matches:
        by_file[m["file"]] = by_file.get(m["file"], 0) + 1

    top_files = sorted(by_file.items(), key=lambda x: x[1], reverse=True)[:20]

    with open(output_file, "w") as out:
        for m in all_matches:
            out.write(f"{m['file']}:{m['line']}: [{m['category']}] {m['content']}\n")
        out.write(f"\n=== Summary ===\n")
        out.write(f"Total matches: {len(all_matches)}\n\n")
        out.write("By category:\n")
        for cat, count in sorted(by_category.items()):
            out.write(f"  {cat}: {count}\n")
        out.write(f"\nTop files:\n")
        for fname, count in top_files:
            out.write(f"  {fname}: {count} matches\n")

    print(f"Wrote {len(all_matches)} matches to {output_file}")
    return all_matches


def main():
    parser = argparse.ArgumentParser(
        description="Scan decompiled .c files for SCSI/USB patterns"
    )
    parser.add_argument("--input", required=True, help="Directory containing .c files")
    parser.add_argument(
        "--output", required=True, help="Output file for pattern matches"
    )
    args = parser.parse_args()

    scan_corpus(args.input, args.output)


if __name__ == "__main__":
    main()
