#!/usr/bin/env bash
set -euo pipefail

echo "=== Downloading Ghidra 12.1 (headless decompiler) ==="
GHIDRA_URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1_build/ghidra_12.1_PUBLIC_20260513.zip"
GHIDRA_SHA256="aa5cbcbbf48f41ca185fce900e19592f1ade4cd5994eb6e0ede468dac8a6f302"

curl -fsSL -o /tmp/ghidra.zip "$GHIDRA_URL"
echo "$GHIDRA_SHA256  /tmp/ghidra.zip" | sha256sum -c -
unzip -q /tmp/ghidra.zip -d /opt/
rm /tmp/ghidra.zip
ln -sf /opt/ghidra_12.1_PUBLIC_20260513 /opt/ghidra

echo "=== Waiting for Java 21 ==="
export JAVA_HOME="${JAVA_HOME:-/usr/local/sdkman/candidates/java/current}"
export PATH="$JAVA_HOME/bin:$PATH"
until java -version 2>&1 | grep -q "21"; do
	echo "  waiting for JDK 21..."
	sleep 5
done
echo "Java: $(java -version 2>&1 | head -1)"

echo "=== Installing Python dependencies ==="
export GHIDRA_INSTALL_DIR=/opt/ghidra
python3 -m pip install --user pyghidra ghidrecomp 2>&1
echo "pyghidra: $(python3 -c 'import pyghidra; print(pyghidra.__version__)' 2>&1)"
echo "ghidrecomp: $(python3 -m ghidrecomp --version 2>&1)"

echo "=== Extracting UTHSB_MPtool_Lite.exe from firmware zip ==="
FIRMWARE_ZIP="firmware/realtek_rtl9210B_fw1.34.39(station-drivers.com).zip"
mkdir -p "$HOME/binaries"

unzip -o "$FIRMWARE_ZIP" \
	Windows/UTHSB_MPtool_Lite.exe \
	Windows/UTHSB_MPtool_Lite.ini \
	Windows/RTL9210B_v1.34.39.032625.bin \
	Windows/gdfw/RTL9210B_gd_v4.30.23.071922.bin \
	-d "$HOME/binaries/"

echo "binary: UTHSB_MPtool_Lite.exe ($(stat -c%s "$HOME/binaries/Windows/UTHSB_MPtool_Lite.exe") bytes)"
echo "firmware: $(ls "$HOME/binaries/Windows/RTL9210B_v1.34.39.032625.bin")"
echo "gdfw: $(ls "$HOME/binaries/Windows/gdfw/RTL9210B_gd_v4.30.23.071922.bin")"

echo "=== Setup complete ==="
echo ""
echo "Run the decompilation:"
echo "  bash .devcontainer/scripts/decompile.sh"
