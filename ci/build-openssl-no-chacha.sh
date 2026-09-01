#!/usr/bin/env bash
set -euo pipefail

# Build OpenSSL without ChaCha20-Poly1305

ROOT_DIR=$(pwd)
BUILD_DIR=$(mktemp -d)
INSTALL_DIR="$ROOT_DIR/ci/openssl-no-chacha"
mkdir -p "$INSTALL_DIR"

OPENSSL_VERSION="${OPENSSL_VERSION:-3.2.0}"
OPENSSL_TARBALL="openssl-${OPENSSL_VERSION}.tar.gz"
OPENSSL_URL="https://www.openssl.org/source/${OPENSSL_TARBALL}"

echo "Building OpenSSL ${OPENSSL_VERSION} in ${BUILD_DIR}"
cd "$BUILD_DIR"

if [ ! -f "$OPENSSL_TARBALL" ]; then
    curl -fsSL "$OPENSSL_URL" -o "$OPENSSL_TARBALL"
fi

tar xzf "$OPENSSL_TARBALL"
cd "openssl-${OPENSSL_VERSION}"

echo "Configuring OpenSSL ${OPENSSL_VERSION} (no-chacha)"
./config no-chacha --prefix="$INSTALL_DIR"

echo "Building OpenSSL"
make -j"$(nproc)"
make install_sw
