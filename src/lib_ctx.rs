//! The global OpenSSL library context.
//!
//! OpenSSL 3.0 is the first version to have library contexts; before that every operation
//! happens in the single default one, and there is nothing to set.
//!
//! An application that supplies a context gets the providers it chose, and this crate's
//! `fips()` reporting follows the same context. Two things follow from that, and both are about
//! *when* a context can be set:
//!
//! - The digests, ciphers, MAC and Ed25519 availability are fetched once and kept in
//!   process-wide caches. The first fetch captures whichever context is current at that moment,
//!   so a context set afterwards would leave those caches using the default context's providers
//!   while [`crate::fips::enabled`] read the one supplied. [`set_global_lib_ctx`] refuses that.
//! - [`crate::fips::enable`] loads the FIPS provider into whichever context is current, so
//!   calling it before [`set_global_lib_ctx`] would leave the provider in the default context
//!   while this crate works in the one supplied. [`set_global_lib_ctx`] refuses that too.
//! - Reading the context is not the same as using it. [`get_global_lib_ctx`] has no effect and
//!   does not prevent a context being set; only the caches do, which is why the code that caches
//!   a fetched algorithm calls [`primed_lib_ctx`] instead.

use std::fmt;
use std::sync::{Mutex, OnceLock};

// Re-exported so that an application can name the types `set_global_lib_ctx` takes and returns
// without having to resolve a matching version of `openssl` itself.
pub use openssl::lib_ctx::{LibCtx, LibCtxRef};

static GLOBAL_LIB_CTX: OnceLock<LibCtx> = OnceLock::new();

/// Whether a process-wide cache has already captured the global library context.
static LIB_CTX_PRIMED: OnceLock<()> = OnceLock::new();

/// Serialises `set_global_lib_ctx` and `fips::enable` against `primed_lib_ctx`.
///
/// The check-then-act in those two functions is only safe if no cache can prime the context
/// between the check and the act; this lock closes that window.
static LIB_CTX_LOCK: Mutex<()> = Mutex::new(());

/// Acquires the library context lock and checks whether it has been primed.
///
/// Returns `Some(guard)` if the context has not been primed, or `None` if it has.
/// The lock is held until the returned guard is dropped.
pub(crate) fn acquire_lib_ctx_lock() -> Option<std::sync::MutexGuard<'static, ()>> {
    let guard = LIB_CTX_LOCK.lock().unwrap();
    if LIB_CTX_PRIMED.get().is_some() {
        None
    } else {
        Some(guard)
    }
}

/// Sets the global OpenSSL library context for this crate.
///
/// Must be called before anything in this crate fetches an algorithm; see the module
/// documentation for why, and for what this refuses to do.
///
/// Supplying a context also means OpenSSL's own external FIPS configuration no longer applies:
/// `openssl.cnf` and `OPENSSL_FORCE_FIPS_MODE` set the default properties of the *default*
/// context, not of one you create. With a context set, call [`crate::fips::enable`].
pub fn set_global_lib_ctx(ctx: LibCtx) -> Result<(), LibCtxError> {
    let _guard = acquire_lib_ctx_lock().ok_or(LibCtxError::AlreadyUsed)?;
    if crate::fips::fips_already_enabled() {
        return Err(LibCtxError::FipsAlreadyEnabled);
    }
    GLOBAL_LIB_CTX.set(ctx).map_err(|_| LibCtxError::AlreadySet)
}

/// The global library context, recording that a process-wide cache has taken it.
///
/// This is for the code that caches a fetched algorithm: the digest and cipher caches in
/// [`crate::hash`] and [`crate::cipher`], the MAC in [`crate::hmac`], and the Ed25519
/// availability probe in [`crate::verify`]. Everything else reads the context per operation with
/// [`get_global_lib_ctx`], which follows whatever it currently is.
pub(crate) fn primed_lib_ctx() -> Option<&'static LibCtxRef> {
    let _guard = LIB_CTX_LOCK.lock().unwrap();
    let _ = LIB_CTX_PRIMED.set(());
    GLOBAL_LIB_CTX.get().map(|ctx| ctx.as_ref())
}

/// Retrieves a reference to the global `LibCtxRef`, or `None` if unset.
///
/// A plain read: it has no effect on anything, and in particular it does not stop
/// [`set_global_lib_ctx`] being called afterwards. Only the caches do that.
///
/// `#[doc(hidden)]` because it exists so that the test support modules can name the context
/// from a separate crate, not because an application has a use for it.
#[doc(hidden)]
pub fn get_global_lib_ctx() -> Option<&'static LibCtxRef> {
    GLOBAL_LIB_CTX.get().map(|ctx| ctx.as_ref())
}

/// Why [`set_global_lib_ctx`] refused to set the global library context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LibCtxError {
    /// A library context has already been set.
    ///
    /// [`set_global_lib_ctx`] takes the context by value, so a second call has nothing to take:
    /// there is one context per process, and an application that wants a different one has to
    /// have chosen it first.
    AlreadySet,

    /// A process-wide cache has already fetched an algorithm from a library context.
    ///
    /// By the time anything in this crate fetches a digest, a cipher, the MAC, or probes
    /// Ed25519, one of the caches above has taken whichever context was current. Setting a
    /// different one now would leave this crate computing with the cached context's providers
    /// while [`crate::fips::enabled`] reported the status of the one set here -- either a
    /// configuration that is not in FIPS mode attesting that it is, or the reverse. Both are
    /// worse than an error, so this is one.
    ///
    /// The fix is to call [`set_global_lib_ctx`] first, before anything else in this crate runs.
    AlreadyUsed,

    /// FIPS mode has already been enabled.
    ///
    /// [`crate::fips::enable`] loads the FIPS provider into whichever context is current, so
    /// calling it before [`set_global_lib_ctx`] would leave the provider in the default context
    /// while this crate works in the one supplied. [`set_global_lib_ctx`] refuses to set a context
    /// after FIPS has been enabled.
    FipsAlreadyEnabled,
}

impl fmt::Display for LibCtxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadySet => write!(f, "the global library context has already been set"),
            Self::AlreadyUsed => write!(
                f,
                "the library context has already been used by a process-wide cache; \
                 set_global_lib_ctx() must be called before any other function in this crate"
            ),
            Self::FipsAlreadyEnabled => write!(
                f,
                "FIPS mode has already been enabled; \
                 set_global_lib_ctx() must be called before fips::enable()"
            ),
        }
    }
}

impl std::error::Error for LibCtxError {}

#[cfg(all(test, not(feature = "ossl-context")))]
mod tests {
    use super::*;

    /// Markers exchanged with the child processes below.
    const CHILD_STARTED: &str = "set-lib-ctx-child-started";
    const CHILD_SET_AFTER_READ: &str = "set-lib-ctx-after-a-plain-read-succeeded";
    const CHILD_SET_AFTER_PRIME_REFUSED: &str = "set-lib-ctx-after-a-cache-was-primed-refused";

    /// Setting the context is allowed after a plain read: reading is not using it.
    ///
    /// Runs as a subprocess because setting the context changes process-wide state that
    /// cannot be undone. Gated on the absence of the `ossl-context` feature, because that
    /// installs a constructor which would set the context before this test got to choose when
    /// to.
    ///
    /// The other half of this property -- that setting is refused once a cache has primed
    /// the context -- is tested in the crypto wiring PR, where the caches start calling
    /// `primed_lib_ctx()`.
    #[test]
    fn set_global_lib_ctx_succeeds_after_a_plain_read() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "lib_ctx::tests::set_the_context_after_a_plain_read",
                "--ignored",
                "--nocapture",
            ])
            .output()
            .expect("failed to run child process");

        let out = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            out.contains(CHILD_STARTED),
            "child never reported; this test proved nothing.\n{out}"
        );
        assert!(
            out.contains(CHILD_SET_AFTER_READ),
            "child did not report {CHILD_SET_AFTER_READ}.\n{out}"
        );
    }

    /// The child half of the above. Reading the context is not using it: an application that
    /// only ever asks which context is in play can still set one afterwards.
    #[test]
    #[ignore]
    fn set_the_context_after_a_plain_read() {
        println!("{CHILD_STARTED}");

        assert!(
            get_global_lib_ctx().is_none(),
            "no context should be set in this configuration"
        );
        let ctx = LibCtx::new().expect("failed to create a library context");
        assert_eq!(
            set_global_lib_ctx(ctx),
            Ok(()),
            "reading the context must not stop it being set"
        );
        println!("{CHILD_SET_AFTER_READ}");
    }

    /// The child half of the above. A cache has taken the context, so setting a different one
    /// afterwards would leave the crate computing with one set of providers and reporting FIPS
    /// status from another.
    ///
    /// Ignored until the crypto wiring PR: the caches don't call `primed_lib_ctx()` yet, so
    /// priming them has no effect and the assertion would fail. Enabled in that PR.
    #[test]
    #[ignore]
    fn set_the_context_after_a_cache_was_primed() {
        println!("{CHILD_STARTED}");

        // Fetching a digest primes the per-digest cache, which keeps the `EVP_MD` it fetched
        // for the life of the process. `output_len` would not: that is a constant.
        let _ = crate::hash::Algorithm::SHA256.mdref();
        let _ = crate::cipher::CipherKind::Aes128Gcm.is_available();

        let ctx = LibCtx::new().expect("failed to create a library context");
        assert_eq!(
            set_global_lib_ctx(ctx),
            Err(LibCtxError::AlreadyUsed),
            "a primed cache must stop the context being set, and say why"
        );
        println!("{CHILD_SET_AFTER_PRIME_REFUSED}");
    }
}
