#!/usr/bin/env bash
set -euo pipefail

PLUGIN_NAME="sharkai.so"
WIRESHARK_PLUGIN_DIR="/usr/local/lib/wireshark/plugins/4.6/epan"

echo "[*] SharkAI build starting..."

# Ensure we are in the project root (where CMakeLists.txt lives)
if [[ ! -f CMakeLists.txt ]]; then
    echo "[!] CMakeLists.txt not found. Run this script from the project root."
    exit 1
fi

# Remove existing build directory if present
if [[ -d build ]]; then
    echo "[*] Removing existing build directory"
    rm -rf build
fi

# Create and enter build directory
echo "[*] Creating build directory"
mkdir build
cd build

# Configure
echo "[*] Running cmake"
cmake ../

# Build
echo "[*] Running make"
make -j$(nproc)

# Install plugin
if [[ ! -f "${PLUGIN_NAME}" ]]; then
    echo "[!] Build succeeded but ${PLUGIN_NAME} not found"
    exit 1
fi

echo "[*] Installing plugin to ${WIRESHARK_PLUGIN_DIR}"
sudo cp "${PLUGIN_NAME}" "${WIRESHARK_PLUGIN_DIR}/"

echo "[✓] SharkAI build and install complete"

