#!/usr/bin/env bash
# Phase 1: CDB variant testing — opcode 0xE2/0xE3 field isolation
# Usage: doas bash scripts/phase1_test.sh

DEV=/dev/sdb
OUT=${1:-/tmp/phase1_output.txt}

sg() {
	echo "=== $1 ===" >>"$OUT"
	doas python scripts/sg_raw.py "$2" -d "$DEV" -D from -l 0 >>"$OUT" 2>&1 || true
	echo >>"$OUT"
}

: >"$OUT"

echo "Phase 1 CDB variant tests" >>"$OUT"
echo "Device: $DEV" >>"$OUT"
echo >>"$OUT"

# --- Baseline: standard INQUIRY (6-byte, known-good) ---
doas python scripts/sg_raw.py 120000002400 -d "$DEV" -D from -l 36 >>"$OUT" 2>&1 || true
echo >>"$OUT"

# --- 0xE2 READ: vary magic byte (mode=0, len=0) ---
sg "E2 magic=0x00 mode=0" E2000000000000000000000000000000
sg "E2 magic=0xA8 mode=0" E2000000A80000000000000000000000
sg "E2 magic=0x27 mode=0" E2000000270000000000000000000000

# --- 0xE2 READ: vary magic at different offset ---
sg "E2 magic@1=0xA8 mode=0" E2A80000000000000000000000000000
sg "E2 magic@2=0xA8 mode=0" E200A800000000000000000000000000
sg "E2 magic@3=0xA8 mode=0" E20000A8000000000000000000000000

# --- 0xE2 READ: vary mode (magic=0xA8 at byte 4, len=0) ---
sg "E2 magic=0xA8 mode=0x00" E2000000A80000000000000000000000
sg "E2 magic=0xA8 mode=0x01" E2000000A80100000000000000000000
sg "E2 magic=0xA8 mode=0x13" E2000000A81300000000000000000000
sg "E2 magic=0xA8 mode=0xFF" E2000000A8FF00000000000000000000

# --- 0xE3 WRITE: vary magic/mode (len=0) ---
sg "E3 magic=0x00 mode=0" E3000000000000000000000000000000
sg "E3 magic=0x27 mode=0" E3000000270000000000000000000000
sg "E3 magic=0x27 mode=0x03" E3000000270300000000000000000000
sg "E3 magic=0x27 mode=0x13" E3000000271300000000000000000000

# --- Standard opcodes for context ---
doas python scripts/sg_raw.py 000000000000 -d "$DEV" -D from -l 0 >>"$OUT" 2>&1 || true
echo >>"$OUT"
doas python scripts/sg_raw.py 1A0000000024000000 -d "$DEV" -D from -l 36 >>"$OUT" 2>&1 || true
echo >>"$OUT"

echo "Done. Output in $OUT"
