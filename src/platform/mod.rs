//! Operating-system isolation backends.

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
pub(crate) use windows::PlatformSandbox;
