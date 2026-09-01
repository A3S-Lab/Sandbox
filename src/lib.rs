//! Cross-platform native command isolation for A3S.
//!
//! Platform backends are implemented with Seatbelt on macOS, namespaces and
//! seccomp on Linux, and AppContainer plus Job Objects on Windows. Unsupported
//! targets fail closed.

/// Native backend selected for the current target.
pub const NATIVE_SANDBOX_BACKEND: &str = if cfg!(target_os = "macos") {
    "macos-seatbelt"
} else if cfg!(target_os = "linux") {
    "linux-namespace-seccomp"
} else if cfg!(windows) {
    "windows-appcontainer"
} else {
    "unsupported"
};
