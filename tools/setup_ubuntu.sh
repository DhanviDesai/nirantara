#!/usr/bin/env bash
# Install Nirantara build and local development dependencies on Ubuntu/Debian.

set -Eeuo pipefail

if ! command -v apt-get >/dev/null 2>&1; then
    echo "error: this setup script requires apt-get (Ubuntu/Debian)." >&2
    exit 1
fi

if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    SUDO=()
else
    if ! command -v sudo >/dev/null 2>&1; then
        echo "error: run as root or install sudo." >&2
        exit 1
    fi
    SUDO=(sudo)
fi

export DEBIAN_FRONTEND="${DEBIAN_FRONTEND:-noninteractive}"

required_packages=(
    build-essential
    gcc
    make
    cmake
    pkg-config
    libssl-dev
    libmosquitto-dev
    libsqlite3-dev
    libpq-dev
    libcurl4-openssl-dev
    mosquitto
    mosquitto-clients
    openssl
    ca-certificates
    curl
    valgrind
    clang-format
    gdb
)

echo "[setup] Updating apt package index..."
"${SUDO[@]}" apt-get update

optional_packages=()
for clang_rt in \
    libclang-rt-18-dev \
    libclang-rt-17-dev \
    libclang-rt-16-dev \
    libclang-rt-15-dev \
    libclang-rt-14-dev; do
    if apt-cache show "$clang_rt" >/dev/null 2>&1; then
        optional_packages+=("$clang_rt")
        break
    fi
done

if ((${#optional_packages[@]} > 0)); then
    echo "[setup] Installing optional sanitizer runtime: ${optional_packages[*]}"
else
    echo "[setup] No libclang sanitizer runtime package found in apt; continuing."
fi

echo "[setup] Installing Nirantara dependencies..."
"${SUDO[@]}" apt-get install -y \
    "${required_packages[@]}" \
    "${optional_packages[@]}"

echo "[setup] Done."
echo "[setup] Next steps:"
echo "        make build"
echo "        sudo tools/ca/gen_ca.sh"
