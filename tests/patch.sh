#!/bin/bash
rm -rf rustls/src/crypto/openssl
cp -r ../rustls-openssl/src rustls/src/crypto/openssl
mv rustls/src/crypto/openssl/lib.rs rustls/src/crypto/openssl/mod.rs
find rustls/src/crypto/openssl/ -type f -exec sed -i 's/rustls::/crate::/g' {} \;
git apply ../rustls_openssl/tests/0001-Patch-openssl-into-rustls.patch
