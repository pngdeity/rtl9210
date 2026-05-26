#!/usr/bin/env python3
"""Copy .c files containing USB/SCSI/IO patterns to a filtered output directory."""

import argparse
import os
import re
import shutil
import sys

RELEVANT_PATTERNS = [
    r'CreateFile[AW]?\s*\(',
    r'DeviceIoControl\s*\(',
    r'SCSI_PASS_THROUGH',
    r'IOCTL_SCSI',
    r'WRITE_BUFFER',
    r'(?:0x|\\x)3[bB]\b',
    r'PhysicalDrive',
    r'\\\\\.\\USB#',
    r'SetupDi\w+',
    r'gdfw\b',
    r'\.bin\b',
    r'\.cfg\b',
    r'VID_0BDA|vid.*0bda|0x0bda',
    r'PID_9210|pid.*9210|0x9210',
    r'RTL9210\b',
    r'WinUSB\b',
    r'Bulk\s*(?:In|Out|IN|OUT)',
    r'ControlTransfer',
    r'Sabrent\b',
    r'firmware\b',
    r'ReadFile\s*\(',
    r'WriteFile\s*\(',
]

def is_relevant(filepath):
    try:
        with open(filepath, 'r', errors='replace') as f:
            content = f.read()
    except Exception:
        return False

    for pattern in RELEVANT_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE):
            return True
    return False


def filter_corpus(input_dir, output_dir):
    c_files = []
    for root, _, files in os.walk(input_dir):
        for f in files:
            if f.endswith('.c'):
                c_files.append(os.path.join(root, f))

    print(f"Filtering {len(c_files)} .c files for {len(RELEVANT_PATTERNS)} relevance patterns...")

    os.makedirs(output_dir, exist_ok=True)
    copied = 0

    for i, fpath in enumerate(sorted(c_files)):
        if is_relevant(fpath):
            fname = os.path.basename(fpath)
            dest = os.path.join(output_dir, fname)
            shutil.copy2(fpath, dest)
            copied += 1

        if (i + 1) % 500 == 0:
            print(f"  scanned {i + 1}/{len(c_files)}, {copied} relevant so far")

    print(f"Copied {copied}/{len(c_files)} relevant .c files to {output_dir}")


def main():
    parser = argparse.ArgumentParser(description="Filter decompiled .c files for relevance")
    parser.add_argument('--input', required=True, help="Directory containing .c files")
    parser.add_argument('--output', required=True, help="Directory for filtered .c files")
    args = parser.parse_args()

    filter_corpus(args.input, args.output)


if __name__ == '__main__':
    main()
