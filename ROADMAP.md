# A3S Sandbox Roadmap

This roadmap defines the path from the A3S Bash safety boundary to a
production-grade, Rust-native alternative to the feature set exposed by
Anthropic's Sandbox Runtime (SRT). It is intentionally an A3S product plan,
not a promise to copy SRT's internal TypeScript APIs.

## Product decision

`a3s-sandbox` is the single native sandbox library used by A3S products. The
public contract is Rust-first and platform-neutral; A3S Code, the CLI, and
future SDKs adapt to that contract. Node.js, npm, and SRT are not runtime
dependencies.

Compatibility is defined at the capability and security level:

- preserve the useful SRT behaviours (filesystem policy, mediated network,
  Unix sockets, process-tree lifecycle, violation reporting, and CLI/library
  embedding);
- use A3S policy types, error codes, audit events, and configuration rather
  than reproducing SRT's private module graph or settings-file quirks;
- fail closed whenever a platform cannot provide the requested boundary;
- keep a strict baseline mode for A3S Bash even when an operator opts into
  broader, explicitly configured capabilities.

The upstream reference for the feature comparison is the
[Anthropic Sandbox Runtime README](https://github.com/anthropics/sandbox-runtime/blob/main/README.md).

## Baseline delivered (Gate 0)

The current `0.1.x` baseline is complete and is the minimum boundary required
by A3S Bash:

| Capability | Current behaviour | Evidence |
| --- | --- | --- |
| Command lifecycle | Async command execution, bounded output, deadlines, process-group/process-tree termination, descendant cleanup, and stream observers | Unit and integration tests in `src/tests.rs` |
| macOS boundary | Seatbelt profile plus process-group lifecycle | Native macOS test job |
| Linux boundary | Bubblewrap user, mount, PID, IPC, and UTS namespaces with seccomp | Native Linux test job |
| Windows boundary | PowerShell 7 in an AppContainer, restricted ACLs, temporary workspace drive, and kill-on-close Job Object | Native Windows test job |
| Network and IPC | IPv4/IPv6 sockets and host Unix sockets denied by default | Negative network and socket tests |
| Filesystem safety | Credential and secret-file protection, A3S/Git metadata protection, normalized path checks, and symlink/hard-link escape tests | Filesystem adversarial tests |
| Environment safety | Sanitized environment and redirected state/temp variables; injection variables are rejected | Environment tests |
| Failure mode | Missing launcher, unavailable namespace, or failed probe returns an error; no host execution fallback | Fail-closed tests |
| Embedding | Small `NativeSandbox` Rust API suitable for A3S Code and child-session inheritance | Public API and Code integration tests |

The three-platform CI baseline is green at
[Sandbox CI run 33575883293](https://github.com/A3S-Lab/Sandbox/actions/runs/33575883293).
Every change must keep the local gates green:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

The baseline deliberately has no selective network allowlist, HTTP/SOCKS
proxy, TLS interception, dynamic policy reload, or cross-platform violation
store yet. Network is deny-all at the native boundary until Gate 2 is shipped.

## Capability delta to full SRT parity

“Full parity” means equivalent security outcomes and user-visible controls,
not identical implementation details. The following items are the remaining
work, in dependency order.

| Area | Required capability | Design outcome |
| --- | --- | --- |
| Policy model | Typed filesystem/network/socket policy, path normalization, glob semantics, precedence, port-aware host rules, and a canonical policy digest | One versioned policy model shared by all backends |
| Filesystem | Deny-read/allow-read and allow-write/deny-write rules, protected metadata, symlink/hard-link and TOCTOU resistance, and per-session scratch mounts | Deterministic decisions with no path-based bypass |
| Network | HTTP/HTTPS CONNECT proxy, SOCKS5 proxy, domain and port allow/deny rules, DNS handling, IPv4/IPv6 coverage, redirect handling, and proxy-auth support | All permitted traffic is observable and routed through an explicit host mediator |
| Unix sockets | Path allowlists on macOS/Windows and an explicit Linux bridge policy | No accidental local IPC bypass; unsupported path filtering fails closed |
| Runtime controls | Immutable session snapshots, authenticated policy updates, capability probing, nested/weaker mode negotiation, and cancellation | Policy changes are explicit, auditable, and race-free |
| Observability | Structured allow/deny events, reason codes, command attribution, counters, bounded/redacted logs, and optional live subscribers | Operators can explain every denial without leaking secrets |
| Host integration | Stable CLI, Rust library, A3S Code/CLI/SDK adapters, lifecycle inheritance, packaging, and SRT migration tooling | One implementation is consumed consistently across A3S |
| Assurance | Cross-architecture matrix, adversarial tests, property/fuzz tests, benchmarks, threat-model review, and external security audit | Release evidence is repeatable rather than platform anecdote |

## Delivery plan

### Gate 1 — Versioned policy engine (2–3 weeks)

Build the policy layer before adding network exceptions.

- Define `SandboxPolicy`, filesystem rules, network rules, socket rules,
  resource limits, and feature flags as typed Rust values.
- Normalize absolute, relative, home-relative, drive-letter, UNC, and
  case-folded paths once at the policy boundary.
- Specify rule precedence and glob behaviour in a versioned document:
  deny-read/allow-read, allow-write/deny-write, and deny-network/allow-network.
- Produce a canonical, redacted policy digest for audit and replay.
- Add property tests for path equivalence, symlink components, hard links,
  wildcard matching, ports, IPv6 literals, and malformed rules.

**Exit gate:** the same policy fixtures produce identical decisions on all
three platforms; malformed or ambiguous rules are rejected; no backend can
silently broaden a decision; existing Gate 0 tests remain green.

### Gate 2 — Mediated network and Unix sockets (4–6 weeks)

Introduce opt-in network access without weakening the deny-all baseline.

- Implement an in-process or supervised HTTP proxy for HTTP and HTTPS CONNECT.
- Implement a SOCKS5 mediator for non-HTTP TCP protocols (including SSH).
- Enforce domain patterns, explicit ports, deny precedence, DNS rebinding
  resistance, IPv4/IPv6 consistency, redirects, CONNECT tunnelling, and
  proxy authentication.
- Linux: remove direct network interfaces and expose only a private Unix
  socket bridge to the host mediator.
- macOS: allow only the mediator's loopback port in Seatbelt.
- Windows: use a narrowly scoped Windows Filtering Platform egress fence
  keyed to the sandbox identity; permit loopback only to the mediator range.
- Scrub proxy variables and reject alternate proxy, resolver, and raw-socket
  bypasses. A proxy crash must terminate or quarantine the session.

**Exit gate:** allow/deny, DNS, redirect, TLS, SOCKS, local-bind, and bypass
tests pass on macOS arm64/x86_64, Linux x86_64/aarch64, and Windows x64 (with
Windows arm64 where the host toolchain is available). A denied request never
reaches the upstream; an allowed request is attributable to a session.

### Gate 3 — Dynamic policy and violation monitoring (2–3 weeks)

- Add an authenticated, monotonic policy-update API with atomic session
  snapshots; updates cannot retroactively broaden an already running command
  unless the caller explicitly opts in.
- Add capability probes and a typed explanation of degraded/unsupported
  features. Degraded mode is never implicit.
- Emit a common audit event schema for filesystem, process, network, and IPC
  decisions with command/session IDs, policy digest, backend, reason code,
  timestamp, and redacted target metadata.
- Add bounded in-memory storage, optional durable export, live subscribers,
  and stderr annotation compatible with A3S tool diagnostics.
- Add rate limits and back-pressure so a denial storm cannot exhaust the host.

**Exit gate:** events are complete and correctly attributed under concurrent
commands; secrets and credentials are redacted; replaying an event with its
policy digest reproduces the decision; monitoring failure cannot grant access.

### Gate 4 — Cross-platform parity and host migration (3–4 weeks)

- Finish Windows WFP service lifecycle, privilege/error UX, and arm64
  packaging; document the required signed components if a kernel-mode path is
  unavoidable.
- Support nested/container hosts through an explicit `weaker` capability
  negotiation. Refuse startup when the requested guarantee is unavailable.
- Align process, file-descriptor/handle, signal, timeout, and cleanup
  semantics across all backends.
- Stabilize the `NativeSandbox` library and a small `a3s-sandbox` CLI for
  diagnostics and reproducing policy decisions.
- Add A3S Code and CLI migration helpers that translate supported SRT settings
  into the typed policy model, report lossy options, and remove old Node/npm
  resources only after the new path is verified.

**Exit gate:** A3S Code, CLI, and direct library consumers use the same
  release artifact; upgrade and rollback are documented; no active dependency
  or packaging path invokes SRT.

### Gate 5 — Security release (2–4 weeks)

- Run race/TOCTOU, symlink/hard-link, namespace, environment, descriptor,
  proxy-bypass, DNS-rebinding, and process-tree adversarial suites.
- Add policy-parser and protocol fuzzing, long-running soak tests, and
  resource-exhaustion tests.
- Benchmark startup latency, command throughput, proxy overhead, memory, and
  cleanup under large process trees.
- Review the threat model per OS and obtain an independent security review
  before enabling network mediation by default.
- Publish signed, reproducible artifacts, SBOM/provenance, compatibility
  notes, and a documented vulnerability-reporting process.

**Release gate:** all mandatory tests and audits are recorded for each target
  architecture; any unsupported capability is visible to the caller; the
  default A3S Bash profile remains fail-closed.

## Target architecture

The implementation can remain a small public facade while the internals are
split by responsibility as the feature set grows:

```text
src/
├── config/          # versioned typed policy and migration
├── policy/          # normalization, matching, precedence, digests
├── filesystem/      # path decisions and protected-tree handling
├── network/         # HTTP, SOCKS5, DNS, mediation, and bypass checks
├── process/         # limits, descendants, signals, handles, cleanup
├── observability/   # audit events, attribution, redaction, subscribers
└── platform/
    ├── macos/       # Seatbelt and loopback mediation
    ├── linux/       # Bubblewrap, namespaces, seccomp, socket bridge
    ├── windows/     # AppContainer, ACLs, Job Object, WFP fence
    └── unsupported/ # explicit fail-closed errors
```

Platform modules enforce decisions; they do not parse user configuration or
implement their own rule precedence. The policy engine is the single source
of truth, and each backend declares the capabilities it can enforce.

## Test and release matrix

Each gate must add fixtures to the same conformance suite and run them on:

- macOS arm64 and x86_64;
- Linux x86_64 and aarch64, both ordinary hosts and representative containers;
- Windows x64, then arm64 when the WFP/AppContainer toolchain is available.

Required test classes are unit/property tests, backend integration tests,
cross-process and descendant tests, network protocol tests, negative
security tests, fuzz/soak tests, and packaging/upgrade tests. CI must exercise
both the strict default profile and every explicitly advertised weaker mode.

## Risks and decisions

- Windows WFP may require a privileged service or signed driver. The product
  must ship a clearly scoped broker or fail closed; it must never replace WFP
  with an undocumented firewall hint.
- Unprivileged Linux namespaces and seccomp vary by distribution and container
  policy. Capability probing and explicit weaker-mode negotiation are part of
  the API, not hidden fallbacks.
- macOS Seatbelt and system violation-log interfaces are OS-dependent. Keep a
  conservative profile generator and treat missing telemetry as a monitoring
  limitation, never as permission.
- TLS interception introduces a private CA, certificate handling, and
  sensitive plaintext. It requires opt-in configuration, secret-safe logs,
  mTLS/certificate-pinning exclusions, and a separate security review.
- DNS, IPv6, redirects, proxy environment variables, inherited descriptors,
  and nested sandboxes are common bypass surfaces; every one needs a negative
  regression test before a feature is called complete.

Remote container orchestration, desktop UI policy authoring, and fleet-level
control are outside this crate's scope. They may consume the stable library
and audit protocol after Gate 4.

## Estimate

With one experienced cross-platform engineer and shared review capacity, the
full feature set is approximately **12–18 engineering weeks after Gate 0**.
The estimate excludes external security-audit scheduling and can expand for
Windows WFP signing/privilege requirements or hosts that do not permit
unprivileged Linux namespaces. Gate 0 is usable today for A3S Bash with
network deny-all; later gates should be enabled incrementally behind explicit
capability and policy flags.
