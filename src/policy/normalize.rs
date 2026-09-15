//! Path normalization for policy matching and digests.

use anyhow::{bail, Result};
use std::path::{Component, Path};

/// A path in policy-canonical form: `/` separators, no `.` or `..`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NormalizedPath(String);

impl NormalizedPath {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl AsRef<str> for NormalizedPath {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Normalize a path for policy comparison.
///
/// Relative and absolute inputs are accepted. Absolute Windows prefixes keep a
/// single drive letter form (`C:/...`). The result never contains `.` or `..`
/// components; unresolved `..` that would escape the root is rejected.
pub fn normalize_policy_path(path: impl AsRef<Path>) -> Result<NormalizedPath> {
    let raw = path.as_ref();
    if raw.as_os_str().is_empty() {
        bail!("cannot normalize an empty path");
    }

    let mut parts: Vec<String> = Vec::new();
    let mut absolute = false;
    let mut drive: Option<String> = None;

    for component in raw.components() {
        match component {
            Component::Prefix(prefix) => {
                let text = prefix.as_os_str().to_string_lossy().replace('\\', "/");
                let trimmed = text.trim_end_matches('/').to_string();
                if trimmed.is_empty() {
                    bail!("invalid path prefix in {}", raw.display());
                }
                drive = Some(trimmed);
                absolute = true;
                parts.clear();
            }
            Component::RootDir => {
                absolute = true;
                if drive.is_none() {
                    parts.clear();
                }
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if parts.pop().is_none() {
                    bail!(
                        "path escapes its root during normalization: {}",
                        raw.display()
                    );
                }
            }
            Component::Normal(part) => {
                let text = part.to_string_lossy();
                if text.contains('\0') {
                    bail!("path contains NUL: {}", raw.display());
                }
                parts.push(text.into_owned());
            }
        }
    }

    let body = parts.join("/");
    let normalized = if let Some(drive) = drive {
        if body.is_empty() {
            format!("{drive}/")
        } else {
            format!("{drive}/{body}")
        }
    } else if absolute {
        format!("/{body}")
    } else {
        if body.is_empty() {
            bail!("normalized relative path is empty: {}", raw.display());
        }
        body
    };

    Ok(NormalizedPath(normalized))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn collapses_dot_and_rejects_escape() {
        let normalized = normalize_policy_path("a/./b/../c").unwrap();
        assert_eq!(normalized.as_str(), "a/c");
        assert!(normalize_policy_path("../outside").is_err());
        assert!(normalize_policy_path("a/../../outside").is_err());
    }

    #[test]
    fn normalizes_separators() {
        let mixed = PathBuf::from("src").join("main.rs");
        let normalized = normalize_policy_path(&mixed).unwrap();
        assert_eq!(normalized.as_str(), "src/main.rs");
    }

    #[test]
    fn absolute_unix_style_paths_keep_root() {
        let normalized = normalize_policy_path("/tmp/scratch/./file").unwrap();
        assert_eq!(normalized.as_str(), "/tmp/scratch/file");
    }

    #[test]
    fn identical_relative_shapes_compare_equal() {
        let left = normalize_policy_path("workspace/src/lib.rs").unwrap();
        let right = normalize_policy_path("./workspace/./src/lib.rs").unwrap();
        assert_eq!(left, right);
    }
}
