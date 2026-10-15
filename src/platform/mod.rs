//! Operating-system isolation backends.

/// Candidate bwrap executable paths, most-specific first:
/// the `A3S_SANDBOX_BWRAP_PATH` override (an explicit override is
/// authoritative — it is not PATH-fallen-back), else the distribution
/// default `/usr/bin/bwrap`, else a bare `bwrap` for a PATH lookup
/// (NixOS, Homebrew-Linux, custom prefixes). The last candidate is a
/// bare NAME: `resolve_executable` PATH-searches single-component
/// binaries.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn bwrap_candidates() -> Vec<std::path::PathBuf> {
    if let Some(override_path) = std::env::var_os("A3S_SANDBOX_BWRAP_PATH") {
        let override_path = std::path::PathBuf::from(override_path);
        if !override_path.as_os_str().is_empty() {
            return vec![override_path];
        }
    }
    vec![
        std::path::PathBuf::from("/usr/bin/bwrap"),
        std::path::PathBuf::from("bwrap"),
    ]
}

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
mod unsupported;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
mod windows_security;
#[cfg(windows)]
mod windows_shell;

#[cfg(target_os = "linux")]
pub(crate) use linux::PlatformSandbox;
#[cfg(target_os = "macos")]
pub(crate) use macos::PlatformSandbox;
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub(crate) use unsupported::PlatformSandbox;
#[cfg(windows)]
pub(crate) use windows::resolve_powershell;
#[cfg(windows)]
pub(crate) use windows::PlatformSandbox;

#[cfg(test)]
mod bwrap_candidate_tests {
    use super::bwrap_candidates;

    #[test]
    fn defaults_then_an_authoritative_override() {
        // One test: both shapes touch the same env var, and parallel tests
        // would race on it.
        std::env::remove_var("A3S_SANDBOX_BWRAP_PATH");
        let candidates = bwrap_candidates();
        assert_eq!(candidates[0], std::path::PathBuf::from("/usr/bin/bwrap"));
        assert_eq!(
            candidates[1],
            std::path::PathBuf::from("bwrap"),
            "the bare name is the PATH-lookup fallback"
        );

        std::env::set_var("A3S_SANDBOX_BWRAP_PATH", "/opt/custom/bwrap");
        let candidates = bwrap_candidates();
        assert_eq!(candidates.len(), 1, "no PATH fallback past an override");
        assert_eq!(candidates[0], std::path::PathBuf::from("/opt/custom/bwrap"));
        std::env::remove_var("A3S_SANDBOX_BWRAP_PATH");
    }
}
