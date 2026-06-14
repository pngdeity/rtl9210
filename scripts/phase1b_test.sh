#!/usr/bin/env bash
# Phase 1b: Correct 0xE2 CDBs — transfer length properly encoded
# Usage: doas bash scripts/phase1b_test.sh

DEV=${DEV:-/dev/sdb}
: >/tmp/phase1b_output.txt

sg() {
	echo "=== $1 ===" >>/tmp/phase1b_output.txt
	doas python scripts/sg_raw.py "$2" -d "$DEV" -D from -l "$3" >>/tmp/phase1b_output.txt 2>&1 || true
	echo >>/tmp/phase1b_output.txt
}

# Status query — mode 0x13, CDB len 0x48, SG_IO alloc 0x48 (72)
sg "E2 mode=0x13 len=0x48 (status query)" E2000000A81300000000000048000000 72

# Generic read — mode 0x01, CDB len 0x24, SG_IO alloc 0x24 (36)
sg "E2 mode=0x01 len=0x24 (generic read)" E2000000A80100000000000024000000 36

# For comparison: length=0 CDB with non-zero SG_IO alloc
sg "E2 mode=0x13 len=0 alloc=72" E2000000A81300000000000000000000 72
sg "E2 mode=0x01 len=0 alloc=36" E2000000A80100000000000000000000 36

cat /tmp/phase1b_output.txt
