# Threat model (Gate 7)

This document records what `a3s-sandbox` claims to enforce today, by
operating system, and what remains residual. Claims require OS-backed
evidence in tests; residuals must stay fail-closed or explicitly probed.

## Assets

- Host secrets and credentials reachable from the workspace tree
- Host network egress and local IPC (Unix sockets)
- Integrity of A3S / Git / editor control metadata
- Availability of the host (process-tree DoS)

## Adversary

The command string, its descendants, workspace contents, and explicit
environment values are untrusted. The host process, OS launcher, and crate
binary are trusted.

## Shared baseline (all supported OS)

| Control | Claim | Evidence |
| --- | --- | --- |
| Network deny-all (no mediation) | IPv4/IPv6/Unix outbound denied | `native_backend_blocks_ip_and_host_unix_socket_communication` |
| Credential / control-metadata write deny | Protected paths not writable | Gate 0 / Gate 3 integration |
| Symlink / hardlink escape resistance | Outside secrets not leaked via planted links | Gate 0 + Gate 7 TOCTOU tests |
| Env scrub + scratch re-home | Injection vars removed; HOME/TMP redirected | `child_environment_*` |
| Bounded output + tree kill | Deadline and capture ceilings | Gate 2 resources |
| Policy spine | Unsupported features fail closed | Gate 1–6 validate/compile tests |

Default A3S Bash profile never enables mediation.

## macOS (Seatbelt)

| Control | Claim | Evidence |
| --- | --- | --- |
| Mediated HTTP CONNECT | Guest only reaches host mediator `localhost:<port>` | Gate 4 live tunnel + Seatbelt profile |
| Mediated SOCKS5 | Same loopback fence | Gate 5 live tunnel |
| Exact Unix-socket allowlist | Listed path-literal only | Gate 5 live allow/deny |
| Proxy bypass resistance | Explicit `NO_PROXY=*` cannot skip mediator | Gate 7 live |

Residuals: Seatbelt violation telemetry quality; package-store hardlink bulk scan
limits (see SECURITY.md).

## Linux (bwrap + seccomp)

| Control | Claim | Evidence |
| --- | --- | --- |
| Socket creation deny | `socket` / `socketpair` → EPERM | seccomp unit + Gate 0 network test |
| Ephemeral scratch | `--tmpfs` on scratch when requested | Gate 3 |
| Mediated HTTP / SOCKS | HTTP **claimed**; SOCKS not | Live netns bridge tests; SOCKS fail-closed |
| Unix-socket allowlist | **Not claimed** | `unix_socket_allowlist` false |

### Why mediation is not claimed

Classic seccomp cBPF cannot dereference `connect(2)` sockaddr pointers, so it
cannot allow only `127.0.0.1:<mediator>`. Sharing the host net and allowing
`AF_INET` would grant full egress—an overfit. A guest netns isolates host
loopback, so the host mediator is unreachable without an explicit bridge.

**Foundation (claimed for HTTP):** bind-mounted Unix CONNECT mediator +
in-guest TCP→Unix relay (`a3s-sandbox-relay`) + `--unshare-net` + socket-allow
seccomp mode. Live guest tests prove allow tunnels, denied CONNECT, and raw
egress failure. `mediated_socks` / `unix_socket_allowlist` stay false.

**Residual Gate 5 work:** Linux SOCKS relay path; Windows named-pipe broker
ACL + live proof — see `policy/gate5_windows_bridge.rs`.

## Windows (AppContainer + Job)

| Control | Claim | Evidence |
| --- | --- | --- |
| No network capability | Guest cannot open network | Gate 0 network test |
| Job process/memory limits | Enforceable quotas | Gate 2 |
| Same-workspace ACL serialization | Per-workspace gate; drive alloc short lock | unit + concurrent isolation tests |
| Mediated HTTP / SOCKS | **Not claimed** | capabilities false; fail-closed |

**Foundation (unclaimed):** `ConnectMediator::bind_named_pipe_acl` plus
`PlatformSandbox::mediator_named_pipe_factory` create every pipe instance with
an AppContainer-only DACL (`create_appcontainer_named_pipe`; host client open
denied). Guest contract is `A3S_SANDBOX_MEDIATOR_PIPE` — not `HTTP_PROXY` —
because zero-net AppContainers cannot reach loopback TCP. Live guest tunnel
proof is still required before any claim.

**Residual:** live AppContainer guest CONNECT allow/deny/egress evidence from
`windows_appcontainer_named_pipe_connect_allow_deny_and_blocks_raw_egress` on
Windows CI/hardware (test is in-tree, unclaimed until green); guest-side
clients that speak CONNECT over the named pipe for real tools; WFP ALE remains
an alternative with higher privilege cost. Further parallelism only if ACL
ancestor updates are proven race-free.

## Mediator protocol (host-supervised)

When mediation is enabled on a claiming OS:

- Denied CONNECT / SOCKS never reaches upstream
- Path-prefixed allow rules never authorize opaque tunnels
- Non-CONNECT HTTP and SOCKS BIND/UDP are rejected
- Host/port string allowlists do not alias `localhost` ↔ `127.0.0.1` or
  hostname ↔ literal IP

## Non-goals (refuse)

- TLS interception by default
- Silent weaker isolation when `bwrap` / Seatbelt / AppContainer is missing
- SRT TypeScript settings clone as a product API
- Virtual bash / in-process language VMs as the sandbox

## Review checklist (before defaulting mediation)

1. Live bypass suite on each claiming OS (proxy env, DNS literal swap, FD leak)
2. Soak under concurrent workspaces
3. SBOM + vulnerability scan of release artifacts
4. Independent review of mediator and platform fences
