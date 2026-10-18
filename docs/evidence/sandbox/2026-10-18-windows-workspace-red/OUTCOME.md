# Windows workspace ownership regression preparation

## Result

The two new contracts exercise the existing process-local ownership gate.
This is an isolated development-branch test preparation, not a production fix.
Native Windows execution is pending. Expected failures have not yet been
observed on Windows and are not claimed as evidence.

Base: `b57773944555e96f91f2072b17b921e2d69608db` (Sandbox public main).
Toolchain: Rust 1.97.1. Preparation host: macOS ARM64.

## Contract

- While the parent owns a workspace, a second real test process must time out
  attempting to own it. Only after the parent releases ownership can the child
  acquire it and write its completion marker. The child runs the same test with
  a parent-supplied role; a normal test invocation always executes the complete
  parent contract. Acquisition timeouts are protocol ordering controls, not SLOs.
- A differently cased path resolving to the same directory must not acquire a
  second owner. The fixture explicitly verifies the alias resolves on the host.

Both contracts use the production gate. They assert ownership outcomes and real
filesystem state, not mutex addresses or mock invocation counts. The old gate
keys a process-local map by `PathBuf`, so both contracts are expected to expose
missing physical cross-host coordination. The following Windows-native campaign
will establish whether those expected failures actually occur.

## Local checks

- macOS full `cargo test --all-targets --locked`: 228 passed / 0 failed / 0 ignored; [output](macos-suite.log). Windows-only fixtures do not run on this host.
- Windows `cargo check --target x86_64-pc-windows-msvc --all-targets --locked`: succeeds; [output](cross-check.log). This is compilation checking, not native execution or linking.
- Full Rust formatting and strict all-target Clippy pass; [Clippy output](clippy.log).
- `git diff --check` passes. Native Windows expected-red results will be retained by the subsequent implementation certificate.

## Explicitly not claimed

- No observed native Windows red result yet, no passing native lease, and no
  production change or performance measurement.
- No durable ACL, DOS-device or profile crash recovery; no S4 completion or
  change to `host_exit_cleanup=false`.
- No merge into public main, new version, package publication, or Code/installed
  application deployment. The 0.3.0 release/tag remains unchanged.
