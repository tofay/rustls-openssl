#!/usr/bin/env bash
set -euo pipefail

# Build OpenSSL

ROOT_DIR=$(pwd)
BUILD_DIR=$(mktemp -d)
INSTALL_DIR="$ROOT_DIR/ci/openssl-custom"
mkdir -p "$INSTALL_DIR"

OPENSSL_CONFIG_FLAGS="${OPENSSL_CONFIG_FLAGS:-no-chacha}"
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

echo "Configuring OpenSSL ${OPENSSL_VERSION} ${OPENSSL_CONFIG_FLAGS}"
./config $OPENSSL_CONFIG_FLAGS --prefix="$INSTALL_DIR"

echo "Building OpenSSL"
make -j"$(nproc)"
make install_sw
