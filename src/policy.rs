//! Platform-neutral A3S sandbox policy construction.

use anyhow::{bail, Context, Result};
use std::collections::{BTreeMap, HashMap};
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

const MAX_WORKSPACE_SCAN_ENTRIES: usize = 1_000_000;
const MAX_WORKSPACE_SCAN_DEPTH: usize = 64;

/// Workspace-relative directories that can alter the agent, repository, or
/// surrounding tool control plane.
pub const PROTECTED_WORKSPACE_DIRECTORIES: &[&str] = &[
    ".git", ".a3s", ".agents", ".codex", ".claude", ".vscode", ".idea",
];

/// Workspace-relative files that can alter command discovery or repository
/// behavior without living in a protected directory.
pub const PROTECTED_WORKSPACE_FILES: &[&str] = &[
    ".gitmodules",
    ".mcp.json",
    ".ripgreprc",
    ".bashrc",
    ".bash_profile",
    ".zshrc",
    ".zprofile",
    ".profile",
];

/// Return whether a normalized workspace-relative path targets protected
/// control metadata.
pub fn is_protected_workspace_path(path: &str) -> bool {
    let normalized = path.replace('\\', "/");
    let mut components = normalized
        .split('/')
        .filter(|component| !component.is_empty() && *component != ".");
    let Some(first) = components.next() else {
        return false;
    };
    if first == ".." || components.clone().any(|component| component == "..") {
        return false;
    }

    PROTECTED_WORKSPACE_DIRECTORIES
        .iter()
        .any(|protected| first.eq_ignore_ascii_case(protected))
        || PROTECTED_WORKSPACE_FILES
            .iter()
            .any(|protected| first.eq_ignore_ascii_case(protected))
}

#[derive(Debug)]
pub(super) struct SandboxPolicy {
    pub(super) workspace: PathBuf,
    pub(super) scratch: PathBuf,
    pub(super) allow_read: Vec<PathBuf>,
    pub(super) deny_read: Vec<PathBuf>,
    pub(super) allow_write: Vec<PathBuf>,
    pub(super) deny_write: Vec<PathBuf>,
}

impl SandboxPolicy {
    pub(super) fn for_execution(workspace: &Path, scratch: &Path) -> Result<Self> {
        let workspace = workspace
            .canonicalize()
            .context("failed to resolve the native sandbox workspace")?;
        let scratch = scratch
            .canonicalize()
            .context("failed to resolve the native sandbox scratch directory")?;

        let mut protected = protected_workspace_paths(&workspace);
        if let Some(git_dir) = resolved_git_dir(&workspace) {
            protected.push(git_dir);
        }
        expand_existing_canonical_paths(&mut protected);

        let mut sensitive = sensitive_paths();
        sensitive.extend(workspace_sensitive_paths(&workspace)?);
        sensitive.extend(workspace_hardlink_paths(&workspace)?);
        expand_existing_canonical_paths(&mut sensitive);

        let mut deny_read = sensitive.clone();
        deny_read.extend(read_denied_roots());
        let mut allow_read = readable_tool_paths(&workspace, &scratch);
        let allow_write = vec![workspace.clone(), scratch.clone()];
        let mut deny_write = protected;
        deny_write.extend(sensitive);
        validate_denied_workspace_entries(&workspace, &deny_write)?;

        deduplicate_paths(&mut allow_read);
        deduplicate_paths(&mut deny_read);
        remove_redundant_descendants(&mut deny_write);

        Ok(Self {
            workspace,
            scratch,
            allow_read,
            deny_read,
            allow_write,
            deny_write,
        })
    }

    pub(super) fn child_environment(
        &self,
        explicit: Option<&HashMap<String, String>>,
    ) -> Result<BTreeMap<OsString, OsString>> {
        compose_child_env(explicit, &self.scratch)
    }
}

fn validate_denied_workspace_entries(workspace: &Path, paths: &[PathBuf]) -> Result<()> {
    for path in paths.iter().filter(|path| path.starts_with(workspace)) {
        match std::fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                bail!(
                    "native sandbox refuses a symbolic link at protected workspace path {}",
                    path.display()
                );
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to inspect protected workspace path {}",
                        path.display()
                    )
                });
            }
        }
    }
    Ok(())
}

fn compose_child_env(
    explicit: Option<&HashMap<String, String>>,
    scratch: &Path,
) -> Result<BTreeMap<OsString, OsString>> {
    const SAFE_KEYS: &[&str] = &[
        "PATH",
        "USER",
        "USERNAME",
        "LOGNAME",
        "SHELL",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "TZ",
        "TERM",
        "COLORTERM",
        "NO_COLOR",
        "CI",
        "CARGO_HOME",
        "RUSTUP_HOME",
        "RUSTC_WRAPPER",
        "GOPATH",
        "GOROOT",
        "GOMODCACHE",
        "NVM_DIR",
        "FNM_DIR",
        "VOLTA_HOME",
        "BUN_INSTALL",
        "DENO_DIR",
        "PNPM_HOME",
        "JAVA_HOME",
        "GRADLE_USER_HOME",
        "MAVEN_HOME",
        "SDKROOT",
        "DEVELOPER_DIR",
        "PKG_CONFIG_PATH",
        "LIBRARY_PATH",
        "CPATH",
        "CC",
        "CXX",
        "AR",
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "PATHEXT",
    ];

    let mut environment = BTreeMap::new();
    for key in SAFE_KEYS {
        if let Some(value) = std::env::var_os(key) {
            environment.insert(OsString::from(key), value);
        }
    }
    for (key, value) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("LC_") {
            environment.insert(key, value);
        }
    }
    if let Some(explicit) = explicit {
        for (key, value) in explicit {
            if key.is_empty() || key.contains('=') || key.contains('\0') || value.contains('\0') {
                bail!("invalid explicit command environment entry: {key:?}");
            }
            environment.insert(OsString::from(key), OsString::from(value));
        }
    }
    remove_bootstrap_injection_variables(&mut environment);

    let scratch = scratch.as_os_str().to_os_string();
    for key in [
        "HOME",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "TMPDIR",
        "TMP",
        "TEMP",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_STATE_HOME",
    ] {
        environment.insert(OsString::from(key), scratch.clone());
    }
    Ok(environment)
}

fn remove_bootstrap_injection_variables(environment: &mut BTreeMap<OsString, OsString>) {
    const BLOCKED: &[&str] = &[
        "BASH_ENV",
        "ENV",
        "NODE_OPTIONS",
        "NODE_PATH",
        "PYTHONHOME",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "PYTHONINSPECT",
        "RUBYOPT",
        "RUBYLIB",
        "PERL5OPT",
        "PERL5LIB",
        "LUA_INIT",
        "JAVA_TOOL_OPTIONS",
        "JDK_JAVA_OPTIONS",
        "_JAVA_OPTIONS",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
    ];
    environment.retain(|key, _| {
        let key = key.to_string_lossy();
        !BLOCKED
            .iter()
            .any(|blocked| key.eq_ignore_ascii_case(blocked))
            && !key.to_ascii_uppercase().starts_with("LUA_INIT_")
    });
}

pub(super) fn resolve_executable(
    binary: impl Into<PathBuf>,
    excluded_root: &Path,
) -> Result<PathBuf> {
    let binary = binary.into();
    let candidate = if binary.components().count() == 1 {
        find_executable_on_path(&binary, excluded_root).ok_or_else(|| {
            anyhow::anyhow!(
                "required native sandbox executable was not found on PATH: {}",
                binary.display()
            )
        })?
    } else {
        binary
    };
    let candidate = candidate
        .canonicalize()
        .with_context(|| format!("failed to resolve executable {}", candidate.display()))?;
    if !candidate.is_file() || !is_executable(&candidate) {
        bail!(
            "native sandbox executable is not executable: {}",
            candidate.display()
        );
    }
    if candidate.starts_with(excluded_root) {
        bail!(
            "refusing native sandbox executable from inside the active workspace: {}",
            candidate.display()
        );
    }
    Ok(candidate)
}

fn find_executable_on_path(binary: &Path, excluded_root: &Path) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for directory in std::env::split_paths(&path) {
        if !directory.is_absolute() {
            continue;
        }
        let candidate = directory.join(binary);
        if executable_is_trusted(&candidate, excluded_root) {
            return candidate.canonicalize().ok();
        }
        #[cfg(windows)]
        for extension in executable_extensions() {
            let mut name = binary.as_os_str().to_os_string();
            name.push(extension);
            let candidate = directory.join(name);
            if executable_is_trusted(&candidate, excluded_root) {
                return candidate.canonicalize().ok();
            }
        }
    }
    None
}

fn executable_is_trusted(candidate: &Path, excluded_root: &Path) -> bool {
    if !candidate.is_file() || !is_executable(candidate) {
        return false;
    }
    candidate
        .canonicalize()
        .is_ok_and(|resolved| !resolved.starts_with(excluded_root))
}

#[cfg(windows)]
fn executable_extensions() -> Vec<OsString> {
    std::env::var_os("PATHEXT")
        .map(|value| {
            value
                .to_string_lossy()
                .split(';')
                .filter(|value| !value.is_empty())
                .map(OsString::from)
                .collect()
        })
        .unwrap_or_else(|| {
            [".COM", ".EXE", ".BAT", ".CMD"]
                .into_iter()
                .map(OsString::from)
                .collect()
        })
}

fn is_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        path.metadata()
            .map(|metadata| metadata.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        path.is_file()
    }
}

pub(crate) fn sensitive_paths() -> Vec<PathBuf> {
    let mut paths = dirs::home_dir()
        .map(|home| default_sensitive_paths(&home))
        .unwrap_or_default();

    extend_configured_secret(&mut paths, "CODEX_HOME", Some("auth.json"));
    extend_configured_secret(&mut paths, "CLAUDE_CONFIG_DIR", Some(".credentials.json"));
    extend_configured_secret(&mut paths, "CARGO_HOME", Some("credentials"));
    extend_configured_secret(&mut paths, "CARGO_HOME", Some("credentials.toml"));
    for variable in ["A3S_KIMI_HOME", "KIMI_CODE_HOME", "KIMI_SHARE_DIR"] {
        extend_configured_secret(&mut paths, variable, Some("credentials/kimi-code.json"));
    }
    for variable in [
        "A3S_KIMI_DESKTOP_HOME",
        "KIMI_DESKTOP_HOME",
        "WORKBUDDY_CONFIG_DIR",
        "CODEBUDDY_CONFIG_DIR",
    ] {
        extend_configured_secret(&mut paths, variable, None);
    }
    paths
}

fn read_denied_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(home) = dirs::home_dir() {
        roots.push(home.canonicalize().unwrap_or(home));
    }
    let temp = std::env::temp_dir();
    roots.push(temp.canonicalize().unwrap_or(temp));
    roots
}

fn readable_tool_paths(workspace: &Path, scratch: &Path) -> Vec<PathBuf> {
    const TOOLCHAIN_ROOTS: &[&str] = &[
        "CARGO_HOME",
        "RUSTUP_HOME",
        "GOPATH",
        "GOROOT",
        "GOMODCACHE",
        "NVM_DIR",
        "FNM_DIR",
        "VOLTA_HOME",
        "BUN_INSTALL",
        "DENO_DIR",
        "PNPM_HOME",
        "JAVA_HOME",
        "GRADLE_USER_HOME",
        "MAVEN_HOME",
        "SDKROOT",
        "DEVELOPER_DIR",
    ];

    let mut paths = vec![workspace.to_path_buf(), scratch.to_path_buf()];
    for variable in TOOLCHAIN_ROOTS {
        let Some(path) = std::env::var_os(variable).filter(|value| !value.is_empty()) else {
            continue;
        };
        let path = PathBuf::from(path);
        if path.is_absolute() && path.exists() {
            paths.push(path.canonicalize().unwrap_or(path));
        }
    }
    if let Some(path) = std::env::var_os("PATH") {
        paths.extend(std::env::split_paths(&path).filter_map(|path| {
            if !path.is_absolute() || !path.exists() {
                return None;
            }
            path.canonicalize().ok()
        }));
    }
    paths
}

fn default_sensitive_paths(home: &Path) -> Vec<PathBuf> {
    [
        ".ssh",
        ".gnupg",
        ".aws",
        ".azure",
        ".kube",
        ".docker",
        ".config/gcloud",
        ".config/gh",
        ".netrc",
        ".npmrc",
        ".pypirc",
        ".cargo/credentials",
        ".cargo/credentials.toml",
        ".codex/auth.json",
        ".claude/.credentials.json",
        ".claude.json",
        ".git-credentials",
        ".config/git/credentials",
        ".workbuddy",
        "credentials/kimi-code.json",
        ".kimi-code/credentials/kimi-code.json",
        ".kimi/credentials/kimi-code.json",
        ".config/kimi-desktop/daimon-share",
        "Library/Application Support/kimi-desktop/daimon-share",
        ".config/opencode/auth.json",
        ".local/share/opencode/auth.json",
        ".gemini/oauth_creds.json",
        ".terraform.d/credentials.tfrc.json",
        ".local/share/keyrings",
        ".password-store",
        ".a3s/os-auth.json",
        "Library/Keychains",
    ]
    .into_iter()
    .map(|path| home.join(path))
    .collect()
}

pub(crate) fn workspace_sensitive_paths(workspace: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = [
        ".env",
        ".env.local",
        ".env.development",
        ".env.production",
        ".env.test",
        ".netrc",
        ".npmrc",
        ".pypirc",
        ".git-credentials",
        ".a3s/os-auth.json",
        ".codex/auth.json",
        ".claude/.credentials.json",
        ".claude.json",
    ]
    .into_iter()
    .map(|path| workspace.join(path))
    .collect::<Vec<_>>();
    paths.extend(workspace_nested_env_paths(workspace)?);
    Ok(paths)
}

fn workspace_nested_env_paths(workspace: &Path) -> Result<Vec<PathBuf>> {
    let mut pending = vec![(workspace.to_path_buf(), 0usize)];
    let mut scanned = 0usize;
    let mut paths = Vec::new();

    while let Some((directory, depth)) = pending.pop() {
        let Some(entries) = workspace_scan_result(std::fs::read_dir(&directory), || {
            format!(
                "failed to scan native sandbox workspace {}",
                directory.display()
            )
        })?
        else {
            continue;
        };
        for entry in entries {
            let Some(entry) = workspace_scan_result(entry, || {
                format!(
                    "failed to enumerate native sandbox workspace {}",
                    directory.display()
                )
            })?
            else {
                continue;
            };
            scanned = next_workspace_scan_entry(scanned)?;
            let path = entry.path();
            let Some(file_type) = workspace_scan_result(entry.file_type(), || {
                format!(
                    "failed to inspect native sandbox workspace path {}",
                    path.display()
                )
            })?
            else {
                continue;
            };
            if entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with(".env"))
            {
                paths.push(path);
            } else if file_type.is_dir() {
                if should_skip_workspace_scan_directory(&entry.file_name()) {
                    continue;
                }
                ensure_workspace_scan_depth(depth, &path)?;
                pending.push((path, depth + 1));
            }
        }
    }
    Ok(paths)
}

pub(crate) fn workspace_hardlink_paths(workspace: &Path) -> Result<Vec<PathBuf>> {
    let mut pending = vec![(workspace.to_path_buf(), 0usize)];
    let mut scanned = 0usize;
    let mut hardlinks = Vec::new();

    while let Some((directory, depth)) = pending.pop() {
        let Some(entries) = workspace_scan_result(std::fs::read_dir(&directory), || {
            format!(
                "failed to scan native sandbox workspace {}",
                directory.display()
            )
        })?
        else {
            continue;
        };
        for entry in entries {
            let Some(entry) = workspace_scan_result(entry, || {
                format!(
                    "failed to enumerate native sandbox workspace {}",
                    directory.display()
                )
            })?
            else {
                continue;
            };
            scanned = next_workspace_scan_entry(scanned)?;
            let path = entry.path();
            let Some(metadata) = workspace_scan_result(std::fs::symlink_metadata(&path), || {
                format!(
                    "failed to inspect native sandbox workspace path {}",
                    path.display()
                )
            })?
            else {
                continue;
            };
            if metadata.file_type().is_symlink() {
                continue;
            }
            if metadata.is_dir() {
                if should_skip_workspace_scan_directory(&entry.file_name()) {
                    continue;
                }
                ensure_workspace_scan_depth(depth, &path)?;
                pending.push((path, depth + 1));
            } else if metadata.is_file() && hard_link_count(&path, &metadata) > 1 {
                hardlinks.push(path);
            }
        }
    }
    deduplicate_paths(&mut hardlinks);
    Ok(hardlinks)
}

fn workspace_scan_result<T>(
    result: std::io::Result<T>,
    context: impl FnOnce() -> String,
) -> Result<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(context),
    }
}

fn next_workspace_scan_entry(scanned: usize) -> Result<usize> {
    let scanned = scanned
        .checked_add(1)
        .context("native sandbox workspace scan entry count overflowed")?;
    if scanned > MAX_WORKSPACE_SCAN_ENTRIES {
        bail!("native sandbox workspace exceeds the {MAX_WORKSPACE_SCAN_ENTRIES} entry scan limit");
    }
    Ok(scanned)
}

fn ensure_workspace_scan_depth(depth: usize, path: &Path) -> Result<()> {
    if depth >= MAX_WORKSPACE_SCAN_DEPTH {
        bail!(
            "native sandbox workspace exceeds the {MAX_WORKSPACE_SCAN_DEPTH}-level scan depth at {}",
            path.display()
        );
    }
    Ok(())
}

pub(crate) fn should_skip_workspace_scan_directory(name: &OsStr) -> bool {
    matches!(name.to_str(), Some(".git" | "node_modules" | "target"))
}

#[cfg(unix)]
fn hard_link_count(_path: &Path, metadata: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    metadata.nlink()
}

#[cfg(windows)]
fn hard_link_count(path: &Path, metadata: &std::fs::Metadata) -> u64 {
    let Ok(file) = std::fs::File::open(path) else {
        return u64::MAX;
    };
    hard_link_count_for_open_file(&file, metadata)
}

#[cfg(windows)]
fn hard_link_count_for_open_file<T>(file: &T, _metadata: &std::fs::Metadata) -> u64
where
    T: std::os::windows::io::AsRawHandle,
{
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };

    let mut information = unsafe { std::mem::zeroed::<BY_HANDLE_FILE_INFORMATION>() };
    // SAFETY: `file` owns a valid handle and `information` is writable.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } == 0 {
        return u64::MAX;
    }
    u64::from(information.nNumberOfLinks.max(1))
}

#[cfg(not(any(unix, windows)))]
fn hard_link_count(_path: &Path, _metadata: &std::fs::Metadata) -> u64 {
    1
}

fn extend_configured_secret(paths: &mut Vec<PathBuf>, variable: &str, suffix: Option<&str>) {
    let Some(root) = std::env::var_os(variable).filter(|value| !value.is_empty()) else {
        return;
    };
    let root = PathBuf::from(root);
    if !root.is_absolute() {
        return;
    }
    paths.push(match suffix {
        Some(suffix) => root.join(suffix),
        None => root,
    });
}

fn protected_workspace_paths(workspace: &Path) -> Vec<PathBuf> {
    PROTECTED_WORKSPACE_DIRECTORIES
        .iter()
        .chain(PROTECTED_WORKSPACE_FILES)
        .copied()
        .map(|path| workspace.join(path))
        .collect()
}

fn resolved_git_dir(workspace: &Path) -> Option<PathBuf> {
    let dot_git = workspace.join(".git");
    if dot_git.is_dir() {
        return dot_git.canonicalize().ok();
    }
    let source = std::fs::read_to_string(dot_git).ok()?;
    let relative = source.trim().strip_prefix("gitdir:")?.trim();
    let path = Path::new(relative);
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        workspace.join(path)
    };
    path.canonicalize().ok()
}

fn expand_existing_canonical_paths(paths: &mut Vec<PathBuf>) {
    let resolved = paths
        .iter()
        .filter_map(|path| path.canonicalize().ok())
        .collect::<Vec<_>>();
    paths.extend(resolved);
    deduplicate_paths(paths);
}

pub(super) fn deduplicate_paths(paths: &mut Vec<PathBuf>) {
    paths.sort();
    paths.dedup();
}

fn remove_redundant_descendants(paths: &mut Vec<PathBuf>) {
    deduplicate_paths(paths);
    let candidates = paths.clone();
    paths.retain(|path| {
        !candidates
            .iter()
            .any(|ancestor| ancestor != path && path.starts_with(ancestor))
    });
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn path_ancestors(path: &Path) -> Vec<PathBuf> {
    let mut ancestors = path
        .parent()
        .into_iter()
        .flat_map(Path::ancestors)
        .take_while(|ancestor| ancestor.parent().is_some())
        .map(Path::to_path_buf)
        .collect::<Vec<_>>();
    ancestors.reverse();
    ancestors
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn child_environment_removes_runtime_injection_and_rehomes_state() {
        let scratch = tempfile::tempdir().unwrap();
        let explicit = HashMap::from([
            ("SAFE_VALUE".to_string(), "visible".to_string()),
            ("BASH_ENV".to_string(), "/tmp/attack".to_string()),
            ("LD_PRELOAD".to_string(), "/tmp/attack.so".to_string()),
        ]);
        let environment = compose_child_env(Some(&explicit), scratch.path()).unwrap();

        assert_eq!(
            environment.get(OsStr::new("SAFE_VALUE")),
            Some(&OsString::from("visible"))
        );
        assert!(!environment.contains_key(OsStr::new("BASH_ENV")));
        assert!(!environment.contains_key(OsStr::new("LD_PRELOAD")));
        assert_eq!(
            environment.get(OsStr::new("HOME")),
            Some(&scratch.path().as_os_str().to_os_string())
        );
    }

    #[test]
    fn nested_environment_files_and_hardlinks_enter_the_deny_set() {
        let workspace = tempfile::tempdir().unwrap();
        let scratch = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(workspace.path().join("nested")).unwrap();
        std::fs::write(workspace.path().join("nested/.env.secret"), "secret").unwrap();
        let outside = scratch.path().join("outside-secret");
        std::fs::write(&outside, "outside").unwrap();
        std::fs::hard_link(&outside, workspace.path().join("hardlink-secret")).unwrap();

        let policy = SandboxPolicy::for_execution(workspace.path(), scratch.path()).unwrap();
        let workspace = workspace.path().canonicalize().unwrap();

        assert!(policy
            .deny_read
            .contains(&workspace.join("nested/.env.secret")));
        assert!(policy
            .deny_read
            .contains(&workspace.join("hardlink-secret")));
        assert!(policy
            .deny_write
            .contains(&workspace.join("hardlink-secret")));
    }

    #[cfg(unix)]
    #[test]
    fn protected_workspace_symlinks_fail_closed() {
        use std::os::unix::fs::symlink;

        let workspace = tempfile::tempdir().unwrap();
        let scratch = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        symlink(outside.path(), workspace.path().join(".git")).unwrap();

        let error = SandboxPolicy::for_execution(workspace.path(), scratch.path()).unwrap_err();
        assert!(error.to_string().contains("symbolic link"), "{error:#}");
    }
}
