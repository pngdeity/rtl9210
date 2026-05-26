#!/usr/bin/env bash
set -euo pipefail

BINARY="$HOME/binaries/Windows/UTHSB_MPtool_Lite.exe"
OUTDIR="$HOME/decompile-output"
export GHIDRA_INSTALL_DIR="${GHIDRA_INSTALL_DIR:-/opt/ghidra}"
export PATH="$HOME/.local/bin:$GHIDRA_INSTALL_DIR/support:$PATH"

WORKSPACE="/workspaces/rtl9210"
SCRIPTS="$WORKSPACE/scripts"

mkdir -p "$OUTDIR"

echo "=== Step 1: ghidrecomp — batch decompile all functions ==="
echo "Binary: $BINARY ($(stat -c%s "$BINARY") bytes)"
echo "This decompiles every function to individual .c files (~5,000+ functions)"
echo "Estimated time: 45–90 minutes"

ghidrecomp \
	--va \
	--output-path "$OUTDIR/decomp_all" \
	--thread-count 4 \
	--max-ram-percent 60 \
	"$BINARY" 2>&1 | tee "$OUTDIR/ghidrecomp.log"

DECOMP_COUNT=$(find "$OUTDIR/decomp_all" -name '*.c' | wc -l)
echo "Decompiled $DECOMP_COUNT functions"

echo ""
echo "=== Step 2: scan_patterns — grep .c corpus for USB/SCSI/IO patterns ==="
python3 "$SCRIPTS/scan_patterns.py" \
	--input "$OUTDIR/decomp_all" \
	--output "$OUTDIR/pattern_matches.txt"

MATCH_COUNT=$(wc -l <"$OUTDIR/pattern_matches.txt")
echo "Pattern matches: $MATCH_COUNT lines"

echo ""
echo "=== Step 3: filter_decomp — copy relevant .c files ==="
python3 "$SCRIPTS/filter_decomp.py" \
	--input "$OUTDIR/decomp_all" \
	--output "$OUTDIR/relevant_decomp"

RELEVANT_COUNT=$(find "$OUTDIR/relevant_decomp" -name '*.c' 2>/dev/null | wc -l)
echo "Relevant functions copied: $RELEVANT_COUNT"

echo ""
echo "=== Step 4: trace_scsi — pyghidra targeted SCSI extraction ==="
python3 "$SCRIPTS/trace_scsi.py" \
	--binary "$BINARY" \
	--project-dir /tmp/ghidra-project \
	--output "$OUTDIR/scsi_cdb_sequence.json" 2>&1 | tee "$OUTDIR/trace_scsi.log" || true

echo ""
echo "=== Step 5: manifest ==="
cat >"$OUTDIR/v1.34.39_manifest.json" <<EOF
{
  "binary": {
    "file": "UTHSB_MPtool_Lite.exe",
    "size": $(stat -c%s "$BINARY"),
    "type": "Windows PE (x86)",
    "version": "2.0.2.30818"
  },
  "firmware": {
    "version": "1.34.39.032625",
    "bin": "RTL9210B_v1.34.39.032625.bin",
    "size": $(stat -c%s "$HOME/binaries/Windows/RTL9210B_v1.34.39.032625.bin")
  },
  "gd_firmware": {
    "version": "4.30.23.071922",
    "bin": "RTL9210B_gd_v4.30.23.071922.bin",
    "size": $(stat -c%s "$HOME/binaries/Windows/gdfw/RTL9210B_gd_v4.30.23.071922.bin")
  },
  "decompilation": {
    "total_functions": $DECOMP_COUNT,
    "relevant_functions": $RELEVANT_COUNT,
    "pattern_matches": $(wc -l <"$OUTDIR/pattern_matches.txt")
  }
}
EOF

echo ""
echo "=== Decompilation complete ==="
du -sh "$OUTDIR"
echo ""
echo "=== Download instructions ==="
echo "Locally, run:"
echo "  gh codespace cp -r -c CODESPACE_NAME 'remote:decompile-output/' ."
