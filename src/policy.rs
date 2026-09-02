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

        let mut protected = protected_workspace_paths(&workspace)?;
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

#[cfg(any(target_os = "linux", windows))]
pub(super) fn requires_directory_placeholder(workspace: &Path, path: &Path) -> bool {
    let Ok(relative) = path.strip_prefix(workspace) else {
        return false;
    };
    let mut components = relative.components();
    let Some(component) = components.next() else {
        return false;
    };
    if components.next().is_some() {
        return false;
    }
    let name = component.as_os_str().to_string_lossy();
    PROTECTED_WORKSPACE_DIRECTORIES
        .iter()
        .any(|protected| name.eq_ignore_ascii_case(protected))
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
        "SYSTEMDRIVE",
        "WINDIR",
        "COMSPEC",
        "PATHEXT",
        "PSMODULEPATH",
        "PROGRAMDATA",
        "PROGRAMFILES",
        "PROGRAMFILES(X86)",
        "PROGRAMW6432",
        "COMMONPROGRAMFILES",
        "COMMONPROGRAMFILES(X86)",
        "COMMONPROGRAMW6432",
        "PROCESSOR_ARCHITECTURE",
        "NUMBER_OF_PROCESSORS",
        "OS",
        "HOMEDRIVE",
        "HOMEPATH",
        "PUBLIC",
        "ALLUSERSPROFILE",
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
    // Normalize the excluded root before comparing it with the canonical
    // executable path.  Temporary directories and user-provided workspaces
    // can be reached through aliases such as `/var` -> `/private/var` on
    // macOS; comparing unlike representations would otherwise allow a tool
    // that physically lives inside the workspace.
    let excluded_root = excluded_root.canonicalize().with_context(|| {
        format!(
            "failed to resolve native sandbox workspace while validating executable: {}",
            excluded_root.display()
        )
    })?;
    let binary = binary.into();
    let candidate = if binary.components().count() == 1 {
        find_executable_on_path(&binary, &excluded_root).ok_or_else(|| {
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
    if candidate.starts_with(&excluded_root) {
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

/// Resolve known host credential and authentication paths.
pub fn sensitive_paths() -> Vec<PathBuf> {
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

/// Discover credential-like files inside a workspace.
pub fn workspace_sensitive_paths(workspace: &Path) -> Result<Vec<PathBuf>> {
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
            if entry.file_name().to_str().is_some_and(|name| {
                name.get(..4)
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case(".env"))
            }) {
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

/// Discover workspace files with multiple hard-link aliases.
pub fn workspace_hardlink_paths(workspace: &Path) -> Result<Vec<PathBuf>> {
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
                if should_skip_hardlink_scan_directory(&entry.file_name()) {
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

/// Return whether recursive security scans should treat a directory as a
/// package/build store rather than source content.
pub fn should_skip_workspace_scan_directory(name: &OsStr) -> bool {
    name.to_str().is_some_and(|name| {
        [".git", "node_modules", "target"]
            .iter()
            .any(|skipped| name.eq_ignore_ascii_case(skipped))
    })
}

fn should_skip_hardlink_scan_directory(name: &OsStr) -> bool {
    name.to_str().is_some_and(|name| {
        PROTECTED_WORKSPACE_DIRECTORIES
            .iter()
            .any(|protected| name.eq_ignore_ascii_case(protected))
    })
}

#[cfg(unix)]
/// Return a file's hard-link count, failing conservatively on platforms where
/// querying it requires reopening the path.
pub fn hard_link_count(_path: &Path, metadata: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    metadata.nlink()
}

#[cfg(windows)]
/// Return a file's hard-link count, failing conservatively on platforms where
/// querying it requires reopening the path.
pub fn hard_link_count(path: &Path, metadata: &std::fs::Metadata) -> u64 {
    let Ok(file) = std::fs::File::open(path) else {
        return u64::MAX;
    };
    hard_link_count_for_open_file(&file, metadata)
}

#[cfg(windows)]
/// Return the hard-link count for an already-open file handle.
pub fn hard_link_count_for_open_file<T>(file: &T, _metadata: &std::fs::Metadata) -> u64
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

/// Return the hard-link count for an already-open file handle.
#[cfg(unix)]
pub fn hard_link_count_for_open_file<T>(_file: &T, metadata: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    metadata.nlink()
}

#[cfg(not(any(unix, windows)))]
/// Return a conservative hard-link count on unsupported filesystems.
pub fn hard_link_count(_path: &Path, _metadata: &std::fs::Metadata) -> u64 {
    1
}

#[cfg(not(any(unix, windows)))]
/// Return a conservative hard-link count on unsupported filesystems.
pub fn hard_link_count_for_open_file<T>(_file: &T, _metadata: &std::fs::Metadata) -> u64 {
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

fn protected_workspace_paths(workspace: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = PROTECTED_WORKSPACE_DIRECTORIES
        .iter()
        .chain(PROTECTED_WORKSPACE_FILES)
        .copied()
        .map(|path| workspace.join(path))
        .collect::<Vec<_>>();

    // Linux permits names that differ only by case even when the host's
    // default filesystem does not. Discover those aliases explicitly so the
    // policy remains consistent across platforms instead of protecting only
    // the lowercase spelling of control metadata.
    let entries = std::fs::read_dir(workspace).with_context(|| {
        format!(
            "failed to scan protected workspace roots {}",
            workspace.display()
        )
    })?;
    for entry in entries {
        let entry = entry.with_context(|| {
            format!(
                "failed to enumerate protected workspace roots {}",
                workspace.display()
            )
        })?;
        let name = entry.file_name();
        if PROTECTED_WORKSPACE_DIRECTORIES
            .iter()
            .chain(PROTECTED_WORKSPACE_FILES)
            .any(|protected| {
                name.to_str()
                    .is_some_and(|name| name.eq_ignore_ascii_case(protected))
            })
        {
            paths.push(entry.path());
        }
    }
    Ok(paths)
}

fn resolved_git_dir(workspace: &Path) -> Option<PathBuf> {
    let dot_git = workspace.join(".git");
    let dot_git = if dot_git.exists() {
        dot_git
    } else {
        std::fs::read_dir(workspace)
            .ok()?
            .filter_map(Result::ok)
            .find(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.eq_ignore_ascii_case(".git"))
            })
            .map(|entry| entry.path())?
    };
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
    fn child_environment_removes_case_insensitive_bootstrap_variables() {
        let scratch = tempfile::tempdir().unwrap();
        let explicit = HashMap::from([
            ("bash_env".to_string(), "attack".to_string()),
            ("Ld_PreLoad".to_string(), "attack.so".to_string()),
            ("LUA_INIT_script".to_string(), "attack.lua".to_string()),
            ("SAFE_VALUE".to_string(), "visible".to_string()),
        ]);
        let environment = compose_child_env(Some(&explicit), scratch.path()).unwrap();

        assert!(!environment.keys().any(|key| {
            matches!(
                key.to_string_lossy().to_ascii_uppercase().as_str(),
                "BASH_ENV" | "LD_PRELOAD"
            ) || key
                .to_string_lossy()
                .to_ascii_uppercase()
                .starts_with("LUA_INIT_")
        }));
        assert_eq!(
            environment.get(OsStr::new("SAFE_VALUE")),
            Some(&OsString::from("visible"))
        );
    }

    #[test]
    fn protected_path_matching_is_case_insensitive_and_traversal_safe() {
        for path in [
            ".git/config",
            ".GIT/HEAD",
            r".a3s\policy.acl",
            ".mcp.json",
            ".zshrc",
        ] {
            assert!(is_protected_workspace_path(path), "{path}");
        }
        for path in [
            "src/.git/config",
            "../.git/config",
            ".gitignore",
            "src/main.rs",
        ] {
            assert!(!is_protected_workspace_path(path), "{path}");
        }
    }

    #[test]
    fn policy_discovers_case_variant_control_metadata() {
        let workspace = tempfile::tempdir().unwrap();
        let scratch = tempfile::tempdir().unwrap();
        std::fs::create_dir(workspace.path().join(".GIT")).unwrap();
        std::fs::write(workspace.path().join(".MCP.JSON"), "control").unwrap();

        let policy = SandboxPolicy::for_execution(workspace.path(), scratch.path()).unwrap();
        let workspace = workspace.path().canonicalize().unwrap();
        assert!(policy.deny_write.contains(&workspace.join(".GIT")));
        assert!(policy.deny_write.contains(&workspace.join(".MCP.JSON")));
    }

    #[test]
    fn git_worktree_pointer_is_resolved_for_case_variant_gitfiles() {
        let parent = tempfile::tempdir().unwrap();
        let workspace = parent.path().join("workspace");
        let git_dir = parent.path().join("git-dir");
        std::fs::create_dir(&workspace).unwrap();
        std::fs::create_dir(&git_dir).unwrap();
        std::fs::write(workspace.join(".GIT"), "gitdir: ../git-dir\n").unwrap();
        let scratch = tempfile::tempdir().unwrap();

        let policy = SandboxPolicy::for_execution(&workspace, scratch.path()).unwrap();
        assert!(policy.deny_write.contains(&git_dir.canonicalize().unwrap()));
    }

    #[test]
    fn nested_secret_scan_matches_case_variant_environment_files() {
        let workspace = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(workspace.path().join("src/config")).unwrap();
        std::fs::write(workspace.path().join("src/config/.ENV.local"), "secret").unwrap();

        let paths = workspace_sensitive_paths(workspace.path()).unwrap();
        assert!(paths.contains(&workspace.path().join("src/config/.ENV.local")));
    }

    #[test]
    fn scan_directory_filter_handles_case_variants() {
        for name in [".git", ".GIT", "Node_Modules", "TARGET"] {
            assert!(should_skip_workspace_scan_directory(OsStr::new(name)));
        }
        assert!(!should_skip_workspace_scan_directory(OsStr::new("src")));
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

    #[cfg(any(unix, windows))]
    #[test]
    fn hardlink_scan_does_not_skip_writable_dependency_trees() {
        let workspace = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let source = outside.path().join("source");
        std::fs::write(&source, "outside").unwrap();
        for directory in ["node_modules", "target"] {
            let directory = workspace.path().join(directory);
            std::fs::create_dir_all(&directory).unwrap();
            std::fs::hard_link(&source, directory.join("linked")).unwrap();
        }

        let hardlinks = workspace_hardlink_paths(workspace.path()).unwrap();
        assert_eq!(hardlinks.len(), 2);
        assert!(hardlinks
            .iter()
            .any(|path| path.ends_with("node_modules/linked")));
        assert!(hardlinks.iter().any(|path| path.ends_with("target/linked")));
    }

    #[test]
    fn nested_secret_scan_skips_control_and_build_stores() {
        let workspace = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(workspace.path().join("src/config")).unwrap();
        std::fs::create_dir_all(workspace.path().join("node_modules/package")).unwrap();
        std::fs::create_dir_all(workspace.path().join("target/debug")).unwrap();
        std::fs::create_dir_all(workspace.path().join(".git")).unwrap();
        for path in [
            "src/config/.env.secret",
            "node_modules/package/.env.secret",
            "target/debug/.env.secret",
            ".git/.env.secret",
        ] {
            std::fs::write(workspace.path().join(path), "secret").unwrap();
        }

        let paths = workspace_sensitive_paths(workspace.path()).unwrap();
        assert!(paths.contains(&workspace.path().join("src/config/.env.secret")));
        assert!(!paths.contains(&workspace.path().join("node_modules/package/.env.secret")));
        assert!(!paths.contains(&workspace.path().join("target/debug/.env.secret")));
        assert!(!paths.contains(&workspace.path().join(".git/.env.secret")));
    }

    #[cfg(unix)]
    #[test]
    fn nested_secret_scan_fails_closed_at_depth_limit() {
        let workspace = tempfile::tempdir().unwrap();
        let mut current = workspace.path().to_path_buf();
        for index in 0..=MAX_WORKSPACE_SCAN_DEPTH {
            current.push(format!("level-{index}"));
            std::fs::create_dir(&current).unwrap();
        }

        let error = workspace_sensitive_paths(workspace.path()).unwrap_err();
        assert!(error.to_string().contains("depth"), "{error:#}");
    }

    #[test]
    fn executable_resolution_rejects_workspace_tools() {
        let workspace = tempfile::tempdir().unwrap();
        let candidate = workspace.path().join("untrusted-tool");
        std::fs::write(&candidate, "#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&candidate, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let error = resolve_executable(&candidate, workspace.path()).unwrap_err();
        assert!(error.to_string().contains("inside the active workspace"));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn path_ancestors_exclude_the_filesystem_root() {
        let ancestors = path_ancestors(Path::new("/a/b/c"));
        assert_eq!(ancestors, vec![PathBuf::from("/a"), PathBuf::from("/a/b")]);
    }

    #[cfg(any(target_os = "linux", windows))]
    #[test]
    fn only_protected_workspace_roots_require_directory_placeholders() {
        let workspace = Path::new("/workspace");
        assert!(requires_directory_placeholder(
            workspace,
            &workspace.join(".a3s")
        ));
        assert!(requires_directory_placeholder(
            workspace,
            &workspace.join(".GIT")
        ));
        assert!(!requires_directory_placeholder(
            workspace,
            &workspace.join(".gitmodules")
        ));
        assert!(!requires_directory_placeholder(
            workspace,
            &workspace.join(".a3s/os-auth.json")
        ));
        assert!(!requires_directory_placeholder(
            workspace,
            Path::new("/outside/.a3s")
        ));
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
