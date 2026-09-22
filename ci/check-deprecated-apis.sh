#!/usr/bin/env bash
set -euo pipefail

# Fail if the crate declares or calls an OpenSSL C function that is deprecated in OpenSSL 3.0.
#
# `clippy.toml` already bans the rust-openssl APIs that wrap these, and `cargo clippy -D
# warnings` enforces that. But clippy only sees calls that resolve through those paths: a
# hand-written `unsafe extern "C"` block in src/openssl_internal/, or a direct
# `openssl_sys::` call, is invisible to it. That is exactly where a deprecated function is
# most likely to be reintroduced, so check the source text too.
#
# Why this matters: a deprecated low-level function is implemented inside libcrypto and is
# never dispatched through OpenSSL's provider layer. The FIPS module *is* a provider, so such
# a call computes outside the validated module while still returning an answer -- and while
# `fips()` still reports true. Nothing fails, so no functional test catches it.

cd "$(dirname "$0")/.."

# Deprecated in OpenSSL 3.0. Spelled out in full rather than by prefix: several neighbours
# are NOT deprecated and are used deliberately (EVP_PKEY_set1_encoded_public_key,
# EVP_PKEY_get_octet_string_param, EVP_PKEY_get_utf8_string_param).
PATTERNS=(
    # low-level digests
    'SHA1_(Init|Update|Final)' 'SHA224_(Init|Update|Final)' 'SHA256_(Init|Update|Final)'
    'SHA384_(Init|Update|Final)' 'SHA512_(Init|Update|Final)' 'MD5_(Init|Update|Final)'
    # low-level HMAC
    'HMAC_(Init|Init_ex|Update|Final|CTX_new|CTX_free)'
    # low-level EC
    'EC_KEY_(new|new_by_curve_name|generate_key|set_public_key|set_private_key|check_key)'
    # low-level RSA
    'RSA_(new|generate_key_ex|public_encrypt|private_decrypt|public_decrypt|private_encrypt|sign|verify)'
    # low-level DH / DSA
    'DH_(new|generate_key|compute_key)' 'DSA_(new|generate_key|do_sign|do_verify)'
    # legacy ASN.1 key encodings
    'd2i_(RSAPublicKey|RSAPrivateKey|ECPrivateKey|DSAPrivateKey)'
    'i2d_(RSAPublicKey|RSAPrivateKey|ECPrivateKey|DSAPrivateKey)'
    # legacy key bridging
    'EVP_PKEY_assign(_RSA|_EC_KEY|_DH|_DSA)?'
    'EVP_PKEY_get1_(RSA|EC_KEY|DH|DSA)'
    'EVP_PKEY_set1_(RSA|EC_KEY|DH|DSA)'
    # ENGINE framework
    'ENGINE_(new|by_id|init|set_default)'
)

joined=$(IFS='|'; echo "${PATTERNS[*]}")

# Strip line comments before matching: the code deliberately names these functions in prose,
# explaining what it uses instead.
violations=""
while IFS= read -r file; do
    stripped=$(sed 's|//.*||' "$file")
    while IFS= read -r hit; do
        [ -n "$hit" ] && violations+="  $file:$hit"$'\n'
    done < <(echo "$stripped" | grep -nE "\b(${joined})\b" || true)
done < <(find src -name '*.rs')

if [ -n "$violations" ]; then
    echo "error: deprecated OpenSSL 3.0 API used in src/" >&2
    echo >&2
    echo "$violations" >&2
    echo "These functions are implemented in libcrypto and are never dispatched through" >&2
    echo "OpenSSL's provider layer, so they do not reach the FIPS module. Use the EVP" >&2
    echo "equivalents: EVP_MD/EVP_MD_CTX for digests, EVP_PKEY_keygen for key generation," >&2
    echo "and d2i_PUBKEY (crate::spki + PKey::public_key_from_der) for public key import." >&2
    exit 1
fi

echo "ok: no deprecated OpenSSL 3.0 APIs in src/"
