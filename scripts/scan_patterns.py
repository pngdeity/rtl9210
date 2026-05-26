#!/usr/bin/env python3
"""Scan decompiled .c files for USB/SCSI/IO patterns and produce structured matches."""

import argparse
import os
import re
import sys

PATTERNS = {
    "device_open": [
        r'CreateFile[AW]?\s*\(',           # Windows file open
        r'\\\\\.\\PhysicalDrive',           # SCSI passthrough device
        r'\\\\\.\\USB#',                     # Raw USB device path
        r'\\\\\.\\SCSI',                     # SCSI device
    ],
    "scsi_passthrough": [
        r'DeviceIoControl\s*\(',            # Windows IOCTL dispatch
        r'IOCTL_SCSI_PASS_THROUGH',         # SCSI passthrough IOCTL
        r'SCSI_PASS_THROUGH',               # SCSI_PASS_THROUGH struct
        r'SCSI_PASS_THROUGH_DIRECT',        # Direct variant
        r'CDB\b',                            # CDB construction
        r'cdb\b',                            # lowercase variant
    ],
    "scsi_commands": [
        r'(?:0x|\\x)3[bB]\b',              # WRITE BUFFER opcode (0x3B)
        r'(?:0x|\\x)3[cC]\b',              # READ BUFFER opcode (0x3C)
        r'(?:0x|\\x)00\b',                  # TEST UNIT READY (0x00)
        r'(?:0x|\\x)12\b',                  # INQUIRY (0x12)
        r'WRITE_BUFFER',                     # Named constant
        r'WRITE_DATA_BUFF',                  # Alternative name
        r'SEND_DIAGNOSTIC',                  # Self-test/firmware mode switch
    ],
    "firmware_io": [
        r'\.bin\b',                          # Firmware binary file
        r'gdfw\b',                           # GD firmware reference
        r'\.cfg\b',                          # Config file
        r'fileSize|file_size|filelen|file_len',  # File size tracking
        r'firmware\b',                       # Firmware references
        r'ReadFile\s*\(',                    # File read
        r'WriteFile\s*\(',                   # File write (to device)
        r'fopen\b|fread\b|fwrite\b',        # C file I/O
    ],
    "device_detection": [
        r'VID_0BDA|vid.*0bda|0x0bda',       # Realtek vendor ID
        r'PID_9210|pid.*9210|0x9210',        # RTL9210 product ID
        r'RTL9210\b',                        # Chip name
        r'Sabrent\b',                        # Enclosure brand
        r'SetupDi\w+',                       # Setup API enumeration
        r'CM_Get_Device_ID',                 # Device manager API
        r'USB\\.*VID',                       # USB hardware ID
    ],
    "usb_transport": [
        r'Bulk\s*(?:In|Out|IN|OUT)',        # USB bulk endpoint
        r'ControlTransfer',                  # USB control transfer
        r'WinUSB\b',                         # WinUSB API
        r'libusb\b',                         # libusb (unlikely in PE but check)
        r'Interface\s*=\s*0',                # USB interface selection
        r'Endpoint\b',                       # USB endpoint
    ],
}


def scan_file(filepath):
    """Scan a single .c file for patterns and return matches."""
    matches = []
    try:
        with open(filepath, 'r', errors='replace') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"Warning: could not read {filepath}: {e}", file=sys.stderr)
        return matches

    for line_num, line in enumerate(lines, start=1):
        for category, regexes in PATTERNS.items():
            for regex in regexes:
                if re.search(regex, line, re.IGNORECASE):
                    matches.append({
                        'file': os.path.basename(filepath),
                        'path': filepath,
                        'line': line_num,
                        'category': category,
                        'content': line.strip(),
                    })
    return matches


def scan_corpus(input_dir, output_file):
    """Scan all .c files in input_dir."""
    c_files = []
    for root, _, files in os.walk(input_dir):
        for f in files:
            if f.endswith('.c'):
                c_files.append(os.path.join(root, f))

    print(f"Scanning {len(c_files)} .c files for {len(PATTERNS)} pattern categories...")

    all_matches = []
    for i, fpath in enumerate(sorted(c_files)):
        matches = scan_file(fpath)
        all_matches.extend(matches)
        if (i + 1) % 500 == 0:
            print(f"  scanned {i + 1}/{len(c_files)} files, {len(all_matches)} matches so far")

    # Write as grep-style output
    with open(output_file, 'w') as out:
        for m in all_matches:
            out.write(f"{m['file']}:{m['line']}: [{m['category']}] {m['content']}\n")

    # Summary
    by_category = {}
    for m in all_matches:
        by_category[m['category']] = by_category.get(m['category'], 0) + 1

    by_file = {}
    for m in all_matches:
        by_file[m['file']] = by_file.get(m['file'], 0) + 1

    top_files = sorted(by_file.items(), key=lambda x: x[1], reverse=True)[:20]

    with open(output_file, 'a') as out:
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
    parser = argparse.ArgumentParser(description="Scan decompiled .c files for SCSI/USB patterns")
    parser.add_argument('--input', required=True, help="Directory containing .c files")
    parser.add_argument('--output', required=True, help="Output file for pattern matches")
    args = parser.parse_args()

    scan_corpus(args.input, args.output)


if __name__ == '__main__':
    main()
