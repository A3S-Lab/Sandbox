# Windows physical-workspace lease

## Result

The process-local path-keyed mutex is replaced by an operating-system directory
handle lease. The Windows implementation compiles with strict Clippy, and the
local macOS full suite passes. Native Windows qualification of the fix and its
mutation oracle is pending on the isolated S4 branch. This is one S4 slice;
`host_exit_cleanup` remains false.

Base regression source: `d93b64f3b02880ea618e585729355a118d2e4e34`.
Toolchain: Rust 1.97.1. Local host: macOS ARM64.

## Observed failure before the fix

[Native CI 39095066851](https://github.com/A3S-Lab/Sandbox/actions/runs/39095066851)
ran the exact regression source on Windows, macOS 14 and Linux. Linux and macOS
jobs passed. The Windows library suite recorded 201 passed / 2 failed / 0 ignored.
Both new contracts failed again when run individually:

- A second real host process acquired the workspace while the first owned it.
- A differently cased path acquired an independent owner for the same directory.

The [complete Windows job log](native-red-windows.log) retains the full suite and
the two solo failures. This is an observed native red result, rather than a
cross-target inference. The earlier [preparation certificate](../2026-10-18-windows-workspace-red/OUTCOME.md)
records the historical state before that CI run.

Retained text logs remove trailing whitespace and extra EOF blank lines; test
results, diagnostics and source identities are unchanged. The linked CI retains
the original logs and artifacts.

## Change and contracts

- Capture the bound directory's volume and 128-bit file identity while retaining
  a metadata handle. Reject a reparse-point root rather than follow it.
- Before scratch creation or policy initialization, acquire a directory handle
  with add-file access and read-only sharing. Windows share-mode checks serialize
  hosts against the physical object, without path-string keys. The lease also
  denies deletion/rename of the root. Attribute-only access would not exclude a
  peer requesting the same access.
- Compare the acquired identity to the bound identity; a replaced root refuses
  execution before `.a3s/loops` initialization or the requested command.
- Move the RAII lease into the existing execution owner. It lasts through Job
  settlement, ACL restoration, placeholder cleanup and scratch disposal. A
  directory handle can be closed on another thread. Contention waits are
  asynchronous and cancellable; no detached lock-wait thread is introduced.
- The six real-filesystem contracts cover cross-host exclusion and reacquisition,
  case aliases, independent workspaces, cross-thread release, root rename denial
  while allowing child-file writes, and pre-policy refusal after root replacement.
- CI removes add-file access and requires both original regression assertions to
  fail. Compilation failure alone cannot satisfy that negative oracle. Source is
  restored in `finally` and checked for an empty diff.

The host must have add-file access to the workspace directory. A read-only host
root is refused; support for that host permission shape is not claimed. Only a
Windows sharing violation is retried. Other filesystem or identity errors fail
closed. Acquisition deadlines and task-wide quota accounting remain S5 work.

## Local checks

- Full macOS `cargo test --all-targets --locked`: 228 passed / 0 failed / 0 ignored;
  [output](macos-suite.log). These results do not execute Windows-only tests.
- Strict Windows all-target cross-compilation Clippy succeeds;
  [output](windows-clippy.log). This does not prove native linking or behavior.
- Strict local all-target Clippy and full formatting pass;
  [Clippy output](macos-clippy.log). `git diff --check` passes.
- The new module and sibling test file are wired into the existing platform
  modules. Three direct platform-test callers pass the lease through the same
  execution path; no SDK or public wire contract changes.

## Explicitly not claimed

- No passing native Windows lease or negative-oracle result yet, no benchmark,
  and no universal filesystem/alias qualification beyond the named contracts.
- No durable ACL, DOS-device or AppContainer profile crash recovery. Existing
  process-local DOS-device allocation is not promoted to cross-host safety.
- No S4 completion, `host_exit_cleanup` promotion, or runtime-abort qualification.
- No resolution of the intermittent macOS CONNECT `EPERM`; the baseline CI passed
  on macOS again, but prior same-source failures remain unresolved.
- No public-main merge, new version, package publication, or Code/installed-app
  deployment. The 0.3.0 release/tag and Code's immutable dependency stay unchanged.
