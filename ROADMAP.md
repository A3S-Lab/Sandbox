# A3S Sandbox Roadmap

This document is the authoritative development plan for `a3s-sandbox`.
It is derived from first principles, not from cloning Anthropic Sandbox
Runtime (SRT) APIs or importing a virtual-shell product such as
`vercel-labs/just-bash`.

Status anchor: Gate 0 (`0.1.x`) is shipped. Later gates are opt-in behind
explicit capability and policy flags. Softening required isolation to ship
features is forbidden.

## First principles

Before any gate is scheduled, a change must pass this filter:

1. **Mission fit.** Does it strengthen a fail-closed host command boundary for
   untrusted agent/tool process trees?
2. **Enforcement locus.** Is the guarantee enforced by the OS (or a
   host-supervised mediator the OS can fence), not by an in-process interpreter
   pretending to be bash?
3. **Real demand.** Is the pain felt by A3S Bash, Code, Box, or Cloud substrate
   consumers today—not a hypothetical parity checkbox?
4. **Dependency order.** Does it introduce a single source of truth (policy)
   before platform forks, and observability before expanding blast radius?
5. **Minimal surface.** Is there a simpler alternative that preserves the same
   security outcome?

If a proposal fails the filter, it is refused or deferred—not “parked politely”
inside this roadmap.

## Mission

`a3s-sandbox` is the **native Gate 0 command boundary** for A3S products:

- take an untrusted command string and its descendants;
- run them only after a workspace / credential / environment / network /
  lifecycle policy can be established;
- enforce that policy with macOS Seatbelt, Linux Bubblewrap+seccomp, or Windows
  AppContainer+Job Object;
- return bounded output and tear down the process tree;
- **fail closed** when the host cannot provide the requested guarantee.

Public contract: Rust-first, platform-neutral, embeddable by Code, CLI, agents,
and future SDKs. Node/npm/SRT are not runtime dependencies.

Cloud obligation: Wave 1 `BX0.3` host command boundary for Box/Code. See
[cloud-substrate-dependency-roadmap.md](../../docs/cloud-substrate-dependency-roadmap.md).

## Non-goals (refuse)

These are adjacent products or anti-patterns. They must not land in this crate:

| Non-goal | Why | Belongs elsewhere |
| --- | --- | --- |
| Reimplemented bash / builtin catalog | Compatibility and escape complexity explode; OS boundary already wraps real shells | Optional upper layer, never this crate |
| In-process WASM Python / QuickJS / sql.js as the sandbox | Same-realm or weak WASM memory bounds are not OS isolation | Agent runtime / tool plugins |
| MicroVM / container orchestration | Different trust and lifecycle model | `a3s-box` and Cloud node |
| Desktop UI policy authoring / fleet control | Product surfaces, not boundary library | Host apps consuming the audit protocol |
| Silent degradation to unsandboxed exec | Violates Cloud substrate and SECURITY.md | Never |
| Line-for-line SRT TypeScript API or settings clone | Couples A3S to foreign module graph | Capability outcomes only |
| TLS interception as a default path | Private CA, plaintext, pinning exclusions | Later opt-in with separate security review |

SRT and `just-bash` remain **reference inputs**: useful behaviours and agent UX
patterns may be adapted when they strengthen the mission; their implementation
shape is not a requirement.

## Adjacent product lines (do not collapse)

```text
a3s-sandbox   → OS process-tree boundary around real bash/pwsh
a3s-box       → hardware-isolated microVM execution
just-bash-like virtual shell (if ever) → in-memory FS + simulated commands
```

Agents may compose them. This roadmap only owns the middle-left box.

## Gate 0 — Baseline delivered

Current `0.1.x` is the minimum A3S Bash boundary. Evidence lives in
`src/tests.rs`, platform backends, and three-OS CI.

| Capability | Behaviour |
| --- | --- |
| Lifecycle | Async exec, deadlines, process-group / Job Object kill, descendant cleanup, stream observers |
| macOS | Seatbelt + process group |
| Linux | bwrap user/mount/PID/IPC/UTS + seccomp; network via socket denial, not netns |
| Windows | PowerShell 7 AppContainer, ACL snapshot/restore, temp drive, kill-on-close Job; per-process serialization |
| Network / IPC | IPv4/IPv6 and host Unix sockets denied |
| Filesystem | Workspace + ephemeral scratch writes; credentials and control metadata protected; symlink/hardlink escape resistance with documented package-store residual risk |
| Environment | Allowlisted env; HOME/TMP redirected; injection vars stripped |
| Failure | Missing launcher / probe failure → error, never host fallback |

Local gates that must stay green:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

Known Gate 0 debts (tracked, not ignored):

- Residual pre-planted package-store hardlinks to non-credential outside files.
- Resource limits: policy timeout + output ceilings everywhere; Windows Job
  process/memory; Linux memory via `RLIMIT_AS`; unenforceable quotas fail closed.
- Network is deny-all only (correct default; insufficient for opt-in tool fetch).

Closed (do not re-open without evidence):

- Windows ancestor ACL hangs on `%TEMP%` / profile parents: fixed by
  `SetKernelObjectSecurity` for non-inheriting grants (see CHANGELOG Unreleased).
- Windows per-workspace serialization: narrowed to per-workspace ACL gate + short
  DOS-drive allocation lock (Gate 6).
- Structured denial telemetry: Gate 2 `AuditEvent` / `AuditLog`.

## Capability backlog (ranked)

Rank = product leverage × architectural necessity ÷ blast-radius cost.

| Rank | Capability | Serves | Depends on | Notes |
| --- | --- | --- | --- | --- |
| 1 | Versioned typed policy + digest | Every later gate | — | Single decision authority; backends only enforce |
| 2 | Structured allow/deny events | Operators, Code UX, Cloud | Policy digests | Needed **before** opening network |
| 3 | OS resource quotas (CPU/mem/pids/output profiles) | Agent DoS, Cloud density | Policy | cgroup / Job / rlimit—not JS counters |
| 4 | Richer FS policy + session write modes | Agent DX, safer monorepos | Policy | RO binds, multi-root allowlists, optional ephemeral overlay/tmpfs where OS allows |
| 5 | Mediated HTTP(S) allowlist + credential transforms | Real tool fetch without secret leakage | Policy + events + FS mounts for proxy socket | Highest agent-value network slice |
| 6 | Unix-socket allowlists / Linux mediator bridge | Local IPC without host socket free-for-all | Policy + events | Required before trusting loopback mediators |
| 7 | SOCKS5 / non-HTTP TCP mediation | SSH and odd protocols | HTTP mediator lessons | Second network slice; do not block HTTP on this |
| 8 | Dynamic policy snapshots + nested/`weaker` probe | Long sessions, containers | Policy + events | Never implicit degrade |
| 9 | CLI + Code/CLI adapters | Diagnostics, migration off SRT paths | Stable library | A3S-native first; SRT translation is lossy helper only |
| 10 | Assurance release (fuzz, soak, external review) | Production trust | Gates that expand surface | Especially before defaulting any network mediation |

Deliberately **not** ranked into the trunk: virtual bash, in-process language VMs,
TLS MITM as default, fleet UI.

## Development and test discipline

Every gate follows this order. Skipping a step to “look done” is forbidden.

1. **State the exit criterion** in falsifiable tests (unit and integration).
2. **Run tests** and confirm new coverage fails or the gap is otherwise proven.
3. **Implement the minimal enforcement** that makes those tests pass.
4. **Re-run the full local gates** (`fmt`, `clippy -D warnings`, `test --all-targets`).
5. **Only then** move to the next gate.

### Mandatory test classes per gate

| Class | Required | Purpose |
| --- | --- | --- |
| Unit / property | Yes | Policy normalization, precedence, digests, malformed rejection—no OS launcher required |
| Integration | Yes | Real backend (or multi-fixture decision replay) proves the gate exit on this host |
| Negative security | Yes when the gate expands surface | Denied path must not reach host via descendant, FD, env, link, or network bypass |
| Platform matrix | Accumulate | Do not claim cross-OS parity from a single-host green run |

Integration tests may be `#[cfg(target_os = "...")]` where the backend only exists there, but the **decision fixtures** for Gate 1+ must be platform-neutral and identical across OSes.

### Refuse overfitting

Do not land optimizations or special cases that only exist to green a local lab condition, a single CI image quirk, or a transient environment bug. Examples of forbidden overfitting:

- DNS / fake-IP / proxy-environment workarounds that are not part of the typed network policy;
- “allow this path because the monorepo scan is slow” without a general rule and residual-risk note;
- silent weaker isolation so a test host can run without `bwrap` / Seatbelt / AppContainer;
- golden tests that assert incidental string formatting instead of security decisions;
- feature flags that broaden the default A3S Bash profile without an explicit policy opt-in.

If a host cannot provide a required capability, **fail closed** or expose an explicit weaker mode via probe—never paper over it in product code.

## Delivery plan

### Gate 1 — Policy spine (must ship first)

**Status:** Complete for the Gate 1 exit — typed `SandboxPolicy`,
normalization, decisions, digests, `BackendCapabilities`, and
`EnforcedPolicy::compile` (baseline materialization + Exact overlays).
`NativeSandbox::with_policy` / `execute` only run through compile; globs and
outside allow overlays fail closed. Evidence: `policy::gate1_integration` plus
full `cargo test --all-targets` (71 tests).

**Why first:** Without one typed policy model, every platform invents rules and
“parity” becomes three divergent sandboxes.

- Define `SandboxPolicy`: filesystem, network, socket, resource limits, feature
  flags as versioned Rust values.
- Normalize paths once (absolute, relative, home, drive-letter, UNC, case-fold).
- Document precedence and globs: deny-read / allow-read, allow-write /
  deny-write, deny-network / allow-network.
- Emit a canonical redacted policy digest for audit and replay.
- Property tests for path equivalence, symlink components, hard links,
  wildcards, ports, IPv6 literals, malformed rules.
- Backends declare enforceable capabilities; unsupported rules fail closed.

**Exit:** Identical decisions on macOS / Linux / Windows fixtures; no silent
broadening; Gate 0 tests remain green.

### Gate 2 — Explainability and hard resource bounds

**Status:** Complete for the Gate 2 exit on enforceable primitives —
`AuditEvent` / `AuditLog`, session/command attribution on `execute`, policy
timeout and output ceilings on all backends, Windows Job process/memory quotas,
Linux `RLIMIT_AS` memory quotas. Unenforceable requests fail closed (Unix
`max_processes` without cgroup; macOS `max_memory_bytes` because address-space
rlimits cannot be lowered). Evidence: `observability::gate2_integration`,
`observability::gate2_resources`, `policy::resources`, plus
`cargo fmt` / `clippy -D warnings` / `test --all-targets` (85 tests on macOS).

**Residual (do not claim):** Linux/macOS process-tree PID quotas need cgroup (or
equivalent). macOS memory quotas need a non-rlimit enforcement path. Neither is
silently approximated.

**Why before network:** Gate 0 already denies. Expanding egress without
attribution and quotas multiplies blind incidents.

- Common audit event schema for filesystem, process, network, and IPC decisions:
  session/command IDs, policy digest, backend, reason code, timestamp, redacted
  target metadata.
- Bounded in-memory store, optional export, live subscribers; monitoring failure
  never grants access.
- Resource profiles mapped to OS primitives that actually enforce (Windows Job
  Object limits, Linux `RLIMIT_AS`, portable timeout/output ceilings). Profiles
  are policy fields, not ad-hoc constants. Missing OS support fails closed.
- Rate-limit denial storms so telemetry cannot DoS the host.

**Exit:** Concurrent commands attribute correctly; secrets redacted; digest
replay reproduces decisions; quota exhaustion (where claimed) kills or bounds
the tree; unclaimable quotas refuse at policy compile.

### Gate 3 — Filesystem policy depth and session write modes

**Status:** Complete for the Gate 3 exit on claimed capabilities — typed
`FilesystemMount` / `MountMode` / `SessionWriteMode`; RO mounts outside
workspace compile and enforce (live read + write-deny on macOS); RW mounts
outside workspace fail closed; ephemeral session writes use Linux bwrap
`--tmpfs` on scratch and fail closed on macOS/Windows (no in-process FS).
Evidence: `policy::gate3_integration`, Linux `ephemeral_scratch_is_mounted_as_tmpfs_not_host_bind`,
plus `cargo fmt` / `clippy -D warnings` / `test --all-targets` (92 tests on macOS).

**Residual:** Windows ephemeral session mode; further hardlink residual
tightening remains documented Gate 0 debt, not silently claimed fixed.

**Why here:** Agents need controlled visibility and optional non-persistent
writes without leaving the OS boundary model.

- Typed multi-root mounts: RO knowledge trees, RW workspace, private scratch.
- Optional ephemeral write mode where the platform can provide overlay/tmpfs
  semantics; where it cannot, capability negotiation fails closed—no fake
  in-memory FS.
- Tighten residual hardlink story where cheap; document remaining residual risk
  honestly.
- Keep symlink/TOCTOU adversarial coverage as exit evidence.

**Exit:** Mount fixtures decide identically across backends that claim the
capability; unsupported session modes are visible via probe/capabilities,
never silently emulated in-process.

### Gate 4 — Mediated HTTP(S) (primary network)

**Status:** Complete for the claimed macOS CONNECT slice and the Linux netns
bridge — host-loopback / Unix CONNECT mediator, `decide_mediated_connect`,
macOS Seatbelt `localhost:<port>` fence, Linux `--unshare-net` + TCP→Unix
relay (`a3s-sandbox-relay`) with live guest allow/deny evidence
(`gate4_macos_sandbox_mediator_tunnels_allowed_connect`,
`gate4_linux_sandbox_mediator_tunnels_allowed_connect`,
`linux_bridge_wire_*`). `mediated_http` is true on macOS, Linux, and Windows
(Windows: inherited named-pipe CONNECT).
Evidence: `network::connect`, `policy::gate4_integration`, `policy::mediate`,
`platform::linux` bridge tests.

**Residual:** absolute-form HTTP path-prefix proxying (non-CONNECT); redirect
revalidation; credential header transforms; fuller proxy-bypass suites.

**Why split from SOCKS:** Most agent/tool traffic is HTTP(S). Shipping allowlisted
fetch with credential transforms unlocks product value without waiting on WFP/
SOCKS completeness.

- Host-supervised HTTP/HTTPS CONNECT mediator; guest has no raw sockets to the
  internet (macOS: Seatbelt loopback-to-mediator only).
- Origin allowlists for CONNECT; path-prefix rules are reserved for future
  absolute-form HTTP and do not silently authorize TLS tunnels.
- Platform fences: macOS Seatbelt loopback to mediator; Linux Unix-bridge
  staging into scratch; Windows inherited AppContainer named-pipe handle.
- Scrub proxy env bypasses; inject mediator proxy only when mediation is on.
- Default profile remains network deny-all until an explicit policy enables this
  gate’s capabilities.

**Exit (current claim):** Denied CONNECT never reaches upstream; allowed
CONNECT is host-mediated and session-attributable on macOS, Linux, and Windows;
platforms without live fences refuse `mediated_network` at compile. Full matrix
bypass suites remain Gate 4 residual / Gate 7 assurance.

### Gate 5 — Local IPC and non-HTTP mediation

**Status:** In progress — macOS Exact Unix-socket allowlists compile into
Seatbelt `path-literal` outbound rules with live allow/deny evidence
(`gate5_macos_allows_listed_unix_socket_and_denies_others`). Host-supervised
SOCKS5 CONNECT mediator reuses Gate 4 origin allowlists (`decide_mediated_socks`)
with macOS Seatbelt loopback fencing and live guest tunnel evidence
(`gate5_macos_sandbox_socks_tunnels_allowed_connect`).
`unix_socket_allowlist` and `mediated_socks` are true only on macOS;
Linux/Windows fail closed. Evidence: `policy::gate5_integration`,
`network::socks`, plus full `cargo test --all-targets` (137 lib tests on macOS
plus CLI suite).

**Residual:** Linux and Windows host-supervised HTTP CONNECT bridges are
**claimed** (`mediated_http`) after live guest proof. SOCKS and Unix-socket
allowlists remain fail-closed on Linux/Windows. Windows guest contract is
`A3S_SANDBOX_MEDIATOR_PIPE_HANDLE` (inherited connected pipe; not `HTTP_PROXY`).
Unix-socket allowlists on non-macOS remain fail-closed.

- Unix-socket path allowlists (macOS Exact Seatbelt; other platforms pending).
- SOCKS5 mediator for non-HTTP TCP (including SSH) reusing Gate 4 fencing
  (macOS claimed; other platforms pending).
- Keep TLS interception **out** unless a separate security review opts in.

**Exit (partial):** Listed Unix sockets connect; unlisted sockets fail closed on
macOS; SOCKS5 allow tunnels and deny never reach upstream on macOS; unclaimed
platforms refuse allowlists / `mediated_socks` at compile.

### Gate 6 — Session controls, nesting, and host integration

**Status:** In progress — monotonic `replace_policy` refuses silent broadening
unless `PolicyUpdateOptions::allow_broadening`; `capability_report` lists
unavailable surfaces explicitly for nested/container negotiation; `a3s-sandbox`
CLI ships `probe` / `digest` / `capabilities` / `exec`. Evidence:
`policy::gate6_integration`, `policy::update`, `tests/cli_gate6.rs`.

**Residual:** none for the library/CLI/Code adapter path. An SRT-settings
translator is **refused** until a concrete Code migration consumer exists;
shipping a lossy clone without demand would couple the API to a non-goal.

- Authenticated monotonic policy updates; running commands do not broaden unless
  explicitly opted in. ✅ (`replace_policy` + execute policy snapshot)
- Nested/container hosts use explicit `weaker` capability negotiation; refuse
  startup when the requested guarantee is unavailable. ✅ (report surfaces;
  constructor still fail-closed on unenforceable policy)
- Stabilize `NativeSandbox` and ship a small `a3s-sandbox` CLI for probe,
  policy digest, and reproduction. ✅
- Code/CLI adapters consume the Rust contract; optional lossy SRT-settings
  translator is a migration aid, not the API. ✅ (Code adapter consumes Rust
  contract; SRT translator refused for now—see residual)
- Reduce Windows serialization where safe (per-workspace identity or lock
  scope), without weakening ACL restore correctness. ✅ (per-workspace ACL
  gate + short DOS-drive allocation lock)

**Exit (partial):** Code, CLI, and library consumers share one artifact; weaker
modes are explicit in probes; no packaging path invokes SRT. Upgrade/rollback
notes remain a packaging residual.

### Gate 7 — Security release

**Status:** In progress — adversarial negatives, between-execute and in-command
TOCTOU/symlink races, overlapping same-workspace isolation, soak
(`GATE7_SOAK_ROUNDS`) + baseline/exec and CONNECT mediator p50 starters,
CONNECT protocol fuzz corpus, release-checklist invariant tests
(`gate7_release_invariants`), per-OS threat model, CycloneDX SBOM,
signing/provenance + `scripts/collect-release-evidence.sh`,
`docs/RELEASE_CHECKLIST.md`, and `docs/INDEPENDENT_REVIEW.md` are in tree.

**Residual:** signed release artifacts on a real tag, **independent security
review** before any profile makes mediated network the default. Extended soak
evidence (≥256 rounds) has been collected locally on Windows and WSL2 (see
`docs/WINDOWS_WSL_GA.md`); attach the `release-out/` bundle when cutting the
tag. Windows `mediated_http` is claimed after live AppContainer pipe proof;
Linux HTTP CONNECT is claimed; Linux/Windows SOCKS and unix allowlists remain
fail-closed.

- Adversarial suites: race/TOCTOU, symlink/hardlink, namespace, environment,
  descriptor, proxy bypass, DNS rebinding, process-tree orphans.
  (proxy bypass / host-literal non-alias / protocol abuse / TOCTOU between
  executes + in-command symlink swap + overlapping executes: ✅ starter)
- Policy/protocol fuzzing, soak, resource exhaustion.
  (validate malformed-host / zero-ceiling rejects: ✅;
   CONNECT malformed corpus + size bounds: ✅;
   repeated soak 64× + concurrent same-workspace: ✅; multi-hour residual)
- Benchmarks: startup/exec p50 + CONNECT mediator allow p50 starters ✅;
  fuller throughput residual.
- Per-OS threat-model review; independent security review before any profile
  makes mediated network the default. ✅ threat model + checklist + review
  package; external sign-off residual
- Signed artifacts, SBOM/provenance, vulnerability reporting process.
  ✅ SBOM + sign-release + collect-release-evidence; attach-to-tag residual

**Release gate:** Mandatory evidence recorded per architecture; unsupported
capabilities visible to callers; default A3S Bash profile remains fail-closed.
Follow `docs/RELEASE_CHECKLIST.md` and `docs/INDEPENDENT_REVIEW.md`.
Run `./scripts/collect-release-evidence.sh` before cutting a tag.

### Gate 8 — Credential containment (secrets never land)

**Status:** In progress — slice 1 complete: host-held secret environment
entries via `NativeSandbox::execute_with_secrets`. Secret values never reach
the child: each entry is delivered as an `a3s:secret:<NAME>` sentinel
(`SECRET_ENV_SENTINEL_PREFIX`), and because a sentinel nothing re-injects
would silently strand the secret, entries refuse before spawn unless
`features.mediated_network` is on. Reserved names (re-homed, proxy-scrubbed,
toolchain, mediator, and injection keys), collisions with explicit env
entries, and malformed entries all fail closed. Injection and refusal are
auditable (`AuditSurface::Environment`, `ReasonCode::SecretRequiresMediation`);
secret bytes never reach the child environment, captured output, audit log,
or policy digest. Evidence: `policy::gate8_integration` plus full local gates.

**Residual:** egress re-injection at the mediation point (Gate 4 CONNECT
first, absolute-form HTTP only — TLS interception stays a non-goal);
cross-OS CI evidence for the new matrix; box `secret_environment`
macOS/Windows execution parity is a `crates/box` follow-up.

**Why:** the field's strongest credential pattern (mask + egress-side
injection) keeps secrets out of the boundary entirely; path deny-lists alone
leave plaintext secrets inside the sandbox for the lifetime of the process
tree.

- Host-held secret store contract (typed `SecretRef`, never bytes in
  policy/config/state). Slice 1 passes the per-request map; a store trait
  waits for a real consumer.
- Mediator re-injection for allowlisted egress only; unlisted egress carries
  sentinels only. **Exit:** falsifiable negative tests prove secret bytes
  never appear in guest env/filesystem when `SecretRef`s are used, and the
  per-platform capability matrix is updated.

## Target architecture

```text
src/
├── config/          # versioned typed policy and migration
├── policy/          # normalization, matching, precedence, digests
├── filesystem/      # path decisions, mounts, protected trees
├── network/         # HTTP mediator, later SOCKS/DNS/bypass checks
├── process/         # quotas, descendants, signals, handles, cleanup
├── observability/   # audit events, attribution, redaction, subscribers
└── platform/
    ├── macos/
    ├── linux/
    ├── windows/
    └── unsupported/
```

Platform modules **enforce**; they do not invent precedence. The policy engine
is the single source of truth.

## Test and release matrix

Each gate extends one conformance suite on:

- macOS arm64 and x86_64;
- Linux x86_64 and aarch64 (ordinary hosts and representative containers);
- Windows x64, then arm64 when the fencing toolchain is available.

Required classes: unit/property, backend integration, cross-process/descendant,
network protocol (from Gate 4), negative security, fuzz/soak (Gate 7),
packaging/upgrade (Gate 6+). CI exercises the strict default and every
advertised weaker mode.

## Risks and decisions

- **Windows egress fencing** may need a privileged broker. Ship a scoped broker
  or fail closed—never an undocumented firewall hint.
- **Unprivileged Linux userns/seccomp** vary by distro and container. Probe +
  explicit weaker mode; no hidden fallback.
- **Seatbelt / violation logs** are OS-dependent. Missing telemetry is a
  monitoring limit, never permission.
- **HTTP before SOCKS** is intentional. Do not hold agent fetch behind SSH
  mediation.
- **No virtual shell in-tree.** If A3S later wants a just-bash-like layer, it is
  a separate crate that *calls* sandbox/box—never a substitute for them.
- **Package-store hardlink residual** remains documented until a cheap complete
  mitigation exists; do not claim it is closed.

## Estimate

With one experienced cross-platform engineer and shared review:

| Gate | Focus | Rough effort after Gate 0 |
| --- | --- | --- |
| 1 | Policy spine | 2–3 weeks |
| 2 | Events + resource quotas | 2–3 weeks |
| 3 | FS mounts / session modes | 2–3 weeks |
| 4 | Mediated HTTP(S) | 3–5 weeks |
| 5 | Unix sockets + SOCKS | 2–4 weeks |
| 6 | Session controls + CLI/adapters | 3–4 weeks |
| 7 | Security release | 2–4 weeks |

Total roughly **16–26 engineering weeks**, excluding external audit scheduling
and Windows signing/privilege surprises. Gate 0 remains the supported deny-all
baseline for A3S Bash today.

## Acceptance of this roadmap

This plan is complete when:

1. Mission, non-goals, and adjacent product boundaries are explicit.
2. Gates are ordered by policy → observability/quotas → FS depth → HTTP →
   broader IPC/network → integration → assurance.
3. just-bash-like and SRT-clone work is explicitly refused or demoted.
4. Each gate has a falsifiable exit condition.
5. Cloud `BX0.3` fail-closed obligation is preserved.
