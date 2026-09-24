#!/usr/bin/env bash
# Collect FIPS evidence on a genuinely FIPS-enabled host.
#
# Everything verified so far used a hand-written OPENSSL_CONF to force the fips+base
# providers inside a container. This script deliberately sets *no* OpenSSL configuration:
# the point is to observe what a real FIPS-mode system does on its own.
#
# Usage, from the top of the copied repo:
#
#     ./ci/fips-vm-report.sh
#
# Writes two files beside itself:
#     fips-vm-report-<host>-<stamp>.txt   scannable summary, one RESULT per line
#     fips-vm-report-<host>-<stamp>.log   full output for anything that needs reading
#
# Needs: gcc, openssl-devel, git, cargo (rustup or packaged), and network for crates.
# Every check either produces a RESULT line or a VOID line saying why not. A check that
# could not run is never reported as a pass.

set -uo pipefail

cd "$(dirname "$0")/.." || exit 1
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
HOST=$(hostname -s 2>/dev/null || echo unknown)
SUM="fips-vm-report-${HOST}-${STAMP}.txt"
LOG="fips-vm-report-${HOST}-${STAMP}.log"

# Keep out of any target/ copied from another machine.
export CARGO_TARGET_DIR="${PWD}/target-vm"

: > "$SUM"; : > "$LOG"
say()  { printf '%s\n' "$*" >> "$SUM"; printf '%s\n' "$*" >&2; }
log()  { printf '%s\n' "$*" >> "$LOG"; }
fact() { printf 'FACT\t%s\t%s\n' "$1" "$2" >> "$SUM"; }
res()  { printf 'RESULT\t%s\t%s\t%s\n' "$1" "$2" "${3:-}" >> "$SUM"; }
void() { printf 'VOID\t%s\t%s\n' "$1" "$2" >> "$SUM"; }

say "# FIPS VM report"
fact stamp "$STAMP"
fact host "$HOST"

# ---------------------------------------------------------------- preconditions
# A precondition that fails makes every later result meaningless, so stop.
die() { void preconditions "$1"; say "# ABORTED: $1"; exit 1; }

command -v openssl >/dev/null || die "openssl CLI not installed"
command -v cargo   >/dev/null || die "cargo not on PATH (install rustup, then re-run)"
command -v gcc     >/dev/null || die "gcc not installed (needed to build openssl-sys)"
[ -f Cargo.toml ] || die "not at the top of the repo (no Cargo.toml)"

KERNEL_FIPS=$(cat /proc/sys/crypto/fips_enabled 2>/dev/null || echo "absent")
fact kernel_fips_enabled "$KERNEL_FIPS"
[ "$KERNEL_FIPS" = "1" ] || die "kernel FIPS flag is '$KERNEL_FIPS', not 1 -- this host is not in FIPS mode"

# No OPENSSL_CONF anywhere: if one is inherited, the run is not measuring the system.
if [ -n "${OPENSSL_CONF:-}" ]; then die "OPENSSL_CONF is set ($OPENSSL_CONF); unset it so the system config is what is measured"; fi

# ---------------------------------------------------------------- environment
say "# environment"
fact os_release "$(sed -n 's/^PRETTY_NAME="\(.*\)"/\1/p' /etc/os-release 2>/dev/null || echo unknown)"
fact openssl_version "$(openssl version 2>&1)"
if command -v fips-mode-setup >/dev/null 2>&1; then
    fact fips_mode_setup "$(fips-mode-setup --check 2>/dev/null | head -1)"
else
    fact fips_mode_setup "command-not-available"
fi
fact crypto_policy "$(update-crypto-policies --show 2>/dev/null || echo unknown)"
fact rustc "$(rustc --version 2>&1)"
fact git_head "$(git rev-parse --short HEAD 2>/dev/null || echo 'not a git checkout')"

{ echo "### openssl list -providers"; openssl list -providers 2>&1
  echo "### openssl list -providers -verbose"; openssl list -providers -verbose 2>&1; } >> "$LOG"
# The distro version does not imply the module: RHEL 10.2 loads a 3.0.7 provider, Rocky 10.2
# a 3.5.8 one, on the same libcrypto. Record the identity, not just the number.
PROVIDER_NAME=$(openssl list -providers 2>/dev/null | awk '/fips/{f=1} f&&/name:/{sub(/^ *name: */,"");print;exit}')
fact fips_provider_name "${PROVIDER_NAME:-NOT-LOADED}"
for so in /usr/lib64/ossl-modules/fips.so /usr/lib/ossl-modules/fips.so; do
    [ -f "$so" ] && fact fips_module_path "$so ($(rpm -qf "$so" 2>/dev/null || echo 'no owning package'))"
done
FIPS_MODULE=$(openssl list -providers 2>/dev/null | awk '/fips/{f=1} f&&/version:/{gsub(/ /,"");sub(/version:/,"");print;exit}')
fact fips_module_version "${FIPS_MODULE:-NOT-LOADED}"
if [ -z "$FIPS_MODULE" ]; then
    res system_fips_provider_active fail "kernel says FIPS but openssl does not list a fips provider"
else
    res system_fips_provider_active pass "module $FIPS_MODULE, no OPENSSL_CONF set"
fi

# ---------------------------------------------------------------- capabilities
say "# platform capabilities under system FIPS"
cap() { # name, command...
    local n="$1"; shift
    if "$@" >/dev/null 2>&1; then res "cap_$n" available; else res "cap_$n" refused; fi
}
cap x25519_keygen   openssl genpkey -algorithm X25519 -out /dev/null
cap ed25519_keygen  openssl genpkey -algorithm ED25519 -out /dev/null
cap rsa2048_keygen  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out /dev/null
cap rsa1024_keygen  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:1024 -out /dev/null
printf 'test\n' > /tmp/_fipsvm.in
K=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
IV=00000000000000000000000000000000
cap chacha20_encrypt openssl enc -chacha20   -K "$K" -iv "$IV" -in /tmp/_fipsvm.in -out /dev/null
cap aes256cbc_encrypt openssl enc -aes-256-cbc -K "$K" -iv "$IV" -in /tmp/_fipsvm.in -out /dev/null
rm -f /tmp/_fipsvm.in

MLKEM=$(openssl list -kem-algorithms 2>/dev/null | grep -ci mlkem)
fact mlkem_kem_entries "${MLKEM:-0}"
fact kdfs "$(openssl list -kdf-algorithms 2>/dev/null | grep -oiE 'HKDF|TLS13-KDF|TLS1-PRF' | sort -u | tr '\n' ' ')"
{ echo "### kem-algorithms"; openssl list -kem-algorithms 2>&1
  echo "### kdf-algorithms"; openssl list -kdf-algorithms 2>&1
  echo "### signature-algorithms"; openssl list -signature-algorithms 2>&1; } >> "$LOG"

# ---------------------------------------------------------------- build
say "# build"
if ! cargo test --no-run >>"$LOG" 2>&1; then
    void build "cargo test --no-run failed; see the .log -- no crate results follow"
    say "# ABORTED after build failure"
    exit 1
fi
res build pass
LIB=$(ls -t "$CARGO_TARGET_DIR"/debug/deps/rustls_openssl-* 2>/dev/null | grep -v '\.d$' | head -1)
[ -x "${LIB:-}" ] || { void lib_binary "could not locate the lib test binary"; say "# ABORTED"; exit 1; }
fact lib_test_binary "$LIB"

# Parse a libtest run. Treats "0 passed" as VOID, never as a pass -- a filter that
# matches nothing otherwise reports ok and looks like success. Counts are summed across every
# "test result:" line, so a test that spawns a child test process (hash.rs does) inflates the
# total by that child's own result line; the pass/fail verdict is unaffected.
run_tests() { # label, expect_nonzero(yes|no), command...
    local label="$1" expect="$2"; shift 2
    local out passed failed
    out=$("$@" 2>&1); printf '### %s\n%s\n' "$label" "$out" >> "$LOG"
    passed=$(printf '%s' "$out" | awk '/^test result:/{for(i=1;i<=NF;i++)if($(i+1) ~ /^passed/)s+=$i}END{print s+0}')
    failed=$(printf '%s' "$out" | awk '/^test result:/{for(i=1;i<=NF;i++)if($(i+1) ~ /^failed/)s+=$i}END{print s+0}')
    if printf '%s' "$out" | grep -q '^test result: FAILED'; then
        res "$label" fail "passed=$passed failed=$failed"
        printf '%s' "$out" | grep -E 'panicked|^failures:' -A3 | head -20 >> "$LOG"
    elif [ "$expect" = yes ] && [ "$passed" -eq 0 ]; then
        void "$label" "nothing ran (0 passed) -- filter or build problem, not a pass"
    else
        res "$label" pass "passed=$passed failed=$failed"
    fi
}

# ------------------------------------------- 1. the headline: no forcing at all
# --no-fail-fast matters: cargo stops at the first failing target, so a single failing lib
# test otherwise means tests/it.rs and tests/server.rs never run and nothing says so.
say "# crate tests, system FIPS, no features, no OPENSSL_CONF"
run_tests default_suite yes cargo test --no-fail-fast
run_tests default_suite_single_threaded yes cargo test --no-fail-fast -- --test-threads=1

# ------------------------------------------- 2. the fips feature (CI's method)
say "# crate tests with --features fips"
run_tests features_fips yes cargo test --tests --features fips --no-fail-fast -- --test-threads=1

# ------------------------------------------- 3. FIPS reporting, full test paths
say "# fips() reporting, targeted"
for t in tests::aead_trait_impls_report_fips_directly \
         tests::every_suite_reports_fips_consistently \
         tests::chacha_is_never_fips_approved \
         tests::aes_gcm_tracks_openssl_fips_state \
         quic::test::header_protection_fips_reporting \
         quic::test::quic_key_builder_reports_fips_directly ; do
    run_tests "fips_report_${t##*::}" yes "$LIB" "$t" --exact --test-threads=1
done

# ------------------------------------------- 3b. was the routing control real or void?
# This test proves digests reach the provider layer, but it can only do so where a
# provider-free environment can be built. A kernel-FIPS host activates the FIPS provider
# whatever OPENSSL_CONF says, so the test skips there -- and a skip looks identical to a pass
# in the counts above. Record which happened, or the report cannot tell them apart.
say "# digest provider-routing control"
ROUTE=$("$LIB" --exact hash::tests::digests_are_dispatched_through_the_provider_layer \
        --nocapture 2>&1)
printf '### provider_routing_control\n%s\n' "$ROUTE" >> "$LOG"
if printf '%s' "$ROUTE" | grep -q 'PREMISE-BROKEN'; then
    res provider_routing_control skipped "host activates a provider regardless of OPENSSL_CONF; base-only control is void here, so routing is NOT verified on this host"
elif printf '%s' "$ROUTE" | grep -q '^test result: ok. 1 passed'; then
    res provider_routing_control pass "base-only control held; digest refused when no provider could supply it"
elif printf '%s' "$ROUTE" | grep -q '^test result: ok. 0 passed'; then
    void provider_routing_control "test not present in this build (expected below OpenSSL 3.0)"
else
    res provider_routing_control fail "see .log"
fi

# ------------------------------------------- 4. the HKDF first-use race
# Reproduced deterministically on ubi9 under a forced fips+base config; six standalone
# reproducers failed. Does a real FIPS host show it? Repeat, because it is timing-sensitive.
say "# HKDF first-use race probe"
for threads in 1 2 4 8; do
    fails=0; runs=8; void_runs=0
    for _ in $(seq 1 $runs); do
        out=$("$LIB" hkdf --test-threads=$threads 2>&1)
        printf '%s' "$out" | grep -q '^test result:' || { void_runs=$((void_runs+1)); continue; }
        printf '%s' "$out" | grep -q '^test result: FAILED' && fails=$((fails+1))
    done
    if [ "$void_runs" -gt 0 ]; then
        void "hkdf_race_threads_${threads}" "$void_runs/$runs runs produced no result line"
    elif [ "$fails" -gt 0 ]; then
        res "hkdf_race_threads_${threads}" fail "$fails/$runs runs failed -- RACE REPRODUCED"
        "$LIB" hkdf --test-threads=$threads >> "$LOG" 2>&1
    else
        res "hkdf_race_threads_${threads}" pass "0/$runs failed"
    fi
done

# Whole suite in parallel, which is how the race first surfaced. Attribute the failures:
# a suite run "fails" for any failing test, so count HKDF failures separately from the rest.
hkdf_runs=0; other_runs=0; other_names=""
for _ in 1 2 3 4 5; do
    out=$("$LIB" 2>&1)
    printf '%s' "$out" | grep -q '^test result: FAILED' || continue
    # Field-exact: libtest prints "test <name> ... FAILED". Matching /FAILED/ loosely also
    # catches the "test result: FAILED." summary line and yields a bogus name of "result:".
    names=$(printf '%s' "$out" | awk '$1=="test" && $3=="..." && $4=="FAILED"{print $2}' | sort -u)
    if printf '%s\n' "$names" | grep -qi hkdf; then hkdf_runs=$((hkdf_runs+1)); fi
    rest=$(printf '%s\n' "$names" | grep -vi hkdf)
    if [ -n "$rest" ]; then other_runs=$((other_runs+1)); other_names="$other_names $rest"; fi
    printf '### full_suite_parallel failures\n%s\n' "$names" >> "$LOG"
done
if [ "$hkdf_runs" -eq 0 ]; then
    res hkdf_race_full_suite_parallel pass "0/5 runs had an HKDF failure"
else
    res hkdf_race_full_suite_parallel fail "$hkdf_runs/5 runs had an HKDF failure -- RACE REPRODUCED"
fi
if [ "$other_runs" -gt 0 ]; then
    res unrelated_suite_failures fail "$other_runs/5 runs, not HKDF:$(printf '%s' "$other_names" | tr ' ' '\n' | sort -u | tr '\n' ' ')"
fi

# ------------------------------------------- 5. lints
say "# lints"
if cargo clippy --all-targets -- -D warnings >>"$LOG" 2>&1; then res clippy pass; else
    res clippy fail "see .log"
    cargo clippy --all-targets --message-format=short 2>&1 \
        | grep -E '^[^ ]+\.rs:[0-9]+:[0-9]+: (warning|error)' | sort -u >> "$LOG"
fi
cargo fmt --check >/dev/null 2>&1 && res fmt pass || res fmt fail
if [ -x ci/check-deprecated-apis.sh ]; then
    ./ci/check-deprecated-apis.sh >>"$LOG" 2>&1 && res deprecated_apis pass || res deprecated_apis fail
fi

say "# done"
printf '\nSummary: %s\nFull log: %s\n' "$SUM" "$LOG"
grep -cE '^RESULT' "$SUM" | sed 's/^/RESULT lines: /'
grep -E '^(VOID|RESULT[^\t]*\t[^\t]*\tfail)' "$SUM" | sed 's/^/  ATTENTION: /' || true
