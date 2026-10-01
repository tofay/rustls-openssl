//! # FIPS support
//!
//! To use rustls with OpenSSL in FIPS mode, perform the following actions.
//!
//! ## 1. Specify `require_ems` when constructing [rustls::ClientConfig] or [rustls::ServerConfig]
//!
//! See [rustls documentation](https://docs.rs/rustls/latest/rustls/client/struct.ClientConfig.html#structfield.require_ems) for rationale.
//!
//! ## 2. Enable FIPS mode for OpenSSL
//!
//! FIPS mode can be enabled with [enable()]. On OpenSSL 3.0 and later that is optional if
//! OpenSSL is already configured for FIPS externally (e.g. via `openssl.cnf`, system
//! environment variables, or system-wide cryptographic policies); on OpenSSL 1.1.1 it is the
//! only way to turn it on in-process.
//!
//! ## 3. Validate the FIPS status of your ClientConfig or ServerConfig at runtime
//! See [rustls documenation on FIPS](https://docs.rs/rustls/latest/rustls/manual/_06_fips/index.html#3-validate-the-fips-status-of-your-clientconfigserverconfig-at-run-time).

/// Returns `true` if OpenSSL is running in FIPS mode.
#[cfg(fips_module)]
pub(crate) fn enabled() -> bool {
    openssl::fips::enabled()
}

#[cfg(not(fips_module))]
pub(crate) fn enabled() -> bool {
    crate::openssl_internal::fips_enabled(crate::get_global_lib_ctx())
}

/// Whether FIPS mode has already been enabled.
///
/// Used by [`crate::set_global_lib_ctx`] to refuse setting a context after FIPS has been
/// enabled, since [`enable`] loads the FIPS provider into whichever context is current.
static FIPS_ENABLED: std::sync::OnceLock<()> = std::sync::OnceLock::new();

pub(crate) fn fips_already_enabled() -> bool {
    FIPS_ENABLED.get().is_some()
}

/// Enable FIPS mode for OpenSSL.
///
/// This should be called on application startup before the provider is used.
///
/// On OpenSSL 1.1.1 this calls [FIPS_mode_set](https://wiki.openssl.org/index.php/FIPS_mode_set()).
/// On OpenSSL 3 this loads a FIPS provider, which must be available.
///
/// Panics if FIPS cannot be enabled.
#[cfg(fips_module)]
pub fn enable() {
    let _guard = crate::lib_ctx::acquire_lib_ctx_lock().expect(
        "fips::enable() called after a process-wide cache has already captured the \
         global library context; call fips::enable() before any other function in this crate"
    );
    let _ = FIPS_ENABLED.set(());
    openssl::fips::enable(true).expect("Failed to enable FIPS mode.");
}

/// Enable FIPS mode for OpenSSL.
///
/// This function is a convenience helper to programmatically enforce FIPS mode
/// on OpenSSL 3.x. Calling this is optional if OpenSSL is already configured
/// for FIPS externally (e.g., via `openssl.cnf`, system environment variables,
/// or system-wide cryptographic policies).
///
/// On OpenSSL 3.x, this loads the `fips`, and `base` providers, and sets default
/// properties to strictly require `fips=yes`.
/// On OpenSSL 1.1.1 this calls [FIPS_mode_set](https://wiki.openssl.org/index.php/FIPS_mode_set()).
///
/// If the application has supplied a library context with
/// [crate::set_global_lib_ctx()], that is the context FIPS mode is enabled in, since it
/// is the one this crate signs, verifies and encrypts in. Call this *after* setting the
/// context: enabling FIPS first would put the FIPS provider in the default context,
/// where nothing in this crate would then use it.
///
/// Panics if FIPS cannot be enabled.
///
/// Must be called after [`crate::set_global_lib_ctx`]: enabling FIPS first would put the FIPS
/// provider in the default context, where nothing in this crate would then use it.
#[cfg(not(fips_module))]
pub fn enable() {
    #[cfg(ossl300)]
    let _guard = crate::lib_ctx::acquire_lib_ctx_lock().expect(
        "fips::enable() called after a process-wide cache has already captured the \
         global library context; call fips::enable() before any other function in this crate"
    );

    use once_cell::sync::OnceCell;
    use openssl::provider::Provider;

    use crate::openssl_internal;

    /// The providers this loaded.
    ///
    /// The `Provider` handles have to be kept for the life of the process: an
    /// `OSSL_PROVIDER` unloads its provider when it is dropped, so a `Provider` that
    /// nothing holds is gone by the time this function returns. That leaves `fips=yes`
    /// naming no provider, and every fetch in the context failing -- which, in a context
    /// of this crate's own, means every operation.
    static LOADED: OnceCell<(Provider, Provider)> = OnceCell::new();

    let _ = FIPS_ENABLED.set(());

    LOADED.get_or_init(|| {
        let ctx = crate::get_global_lib_ctx();
        let fips = Provider::load(ctx, "fips").expect("Failed to load FIPS provider.");
        let base = Provider::load(ctx, "base").expect("Failed to load Base provider.");
        openssl_internal::set_default_properties(ctx, "fips=yes")
            .expect("Failed to set 'fips=yes'.");

        (fips, base)
    });
}

#[cfg(all(test, ossl300, feature = "ossl-context"))]
mod tests {
    /// Markers exchanged with the child process below. Gated with the tests that use them: on
    /// OpenSSL 1.1.1 there is no library context, and without the `ossl-context` feature there
    /// is no context whose FIPS status differs from the default one's.
    const CHILD_STARTED: &str = "fips-status-child-started";
    const CHILD_REPORTED_FIPS: &str = "fips-status-child-sees-FIPS-enabled";

    /// `fips::enabled()` must ask about the context this crate works in.
    ///
    /// An application that supplies its own library context also enables FIPS mode *there*
    /// (see [`crate::fips::enable`]), so the status has to be read back from that context.
    /// Reading the default one instead reports `false` for a process whose every operation
    /// is inside the validated module -- and that is the answer rustls uses to decide
    /// whether a configuration may be trusted, so it has to be the right one.
    ///
    /// No FIPS module is needed to observe this: the status is a property of the default
    /// properties, and setting `fips=yes` is what `enable()` does. Implemented as a
    /// subprocess because the properties cannot be un-set once written, so setting them in
    /// this process would break every other test running alongside it.
    ///
    /// Only meaningful once a global context has been set, which is what the `ossl-context`
    /// feature does. Without it there is nothing to distinguish -- the crate and the default
    /// context are the same context -- so the test is absent rather than silently passing.
    #[test]
    fn fips_status_follows_the_global_context() {
        assert!(
            crate::get_global_lib_ctx().is_some(),
            "the `ossl-context` feature is on but no global context was set"
        );

        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "fips::tests::fips_status_of_the_global_context",
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

        // Guard against a vacuous pass: the child must have got as far as asking.
        assert!(
            out.contains(CHILD_STARTED),
            "child never reported; this test proved nothing.\n{out}"
        );

        assert!(
            out.contains(CHILD_REPORTED_FIPS),
            "`fips::enabled()` reported FIPS mode off for a library context whose default \
             properties require `fips=yes`. It is reading the default library context rather \
             than the one this crate does its work in, so everything built on it -- every \
             `fips()` in this crate, and so rustls' FIPS validation -- would report a \
             FIPS-mode process as not being one.\n{out}"
        );
    }

    /// The child half of [`fips_status_follows_the_global_context`]. Ignored so it only ever
    /// runs when that test invokes it.
    #[test]
    #[ignore]
    fn fips_status_of_the_global_context() {
        println!("{CHILD_STARTED}");

        // The test-suite constructor runs in the child too, so under `--features fips` the
        // properties have already been set on this context, and OpenSSL refuses to overwrite
        // them. Either way the context is in FIPS mode, which is all this child is asserting.
        if super::enabled() {
            println!("{CHILD_REPORTED_FIPS}");
            return;
        }
        crate::openssl_internal::set_default_properties(crate::get_global_lib_ctx(), "fips=yes")
            .expect("failed to set 'fips=yes'");
        if super::enabled() {
            println!("{CHILD_REPORTED_FIPS}");
        }
    }
}
