# a3s-sandbox-bridge protocol v1

`a3s-sandbox-bridge` is the machine boundary for non-Rust hosts (Go, and any
language that can drive a subprocess). The host spawns the bridge, speaks
newline-delimited JSON over its stdin/stdout, and the bridge owns the native
sandbox. Everything the crate guarantees — fail-closed probing, process-group
supervision, bounded output — is preserved across the boundary.

## Framing

One JSON object per line. Requests arrive on the bridge's stdin; responses and
events leave on stdout, one `write` + flush per line. The bridge's stderr is
diagnostics only and is never part of the protocol.

## Requests and responses

| Method | Params | Result | Notes |
| --- | --- | --- | --- |
| `initialize` | `{"workspace": "/abs/path"}` (absolute, required) | capability report (below) | Creates the sandbox with the A3S Bash baseline policy. Required before anything except `ping`. |
| `probe` | — | capability report with `runtime_probed=true` | Checks launcher availability; lifetime guarantees remain separate. |
| `capabilities` | — | capability report | Same shape as the `initialize` result. |
| `exec` | `{"command": "...", "timeout_ms": 120000?, "env": {...}?}` | `{"stdout", "stderr", "exit_code", "timed_out"}` | Streams `output` / `output_complete` events first. The backend terminates its reported process boundary at the deadline. |
| `ping` | — | `{"alive": true}` | Liveness check. |
| `shutdown` | — | `{"bye": true}` | Replies, cancels active requests and exits. Host-exit guarantees depend on the report. |

Capability report shape:

```json
{
  "backend": "macos-seatbelt",
  "session_id": "…",
  "policy_digest": "…",
  "runtime_probed": false,
  "unavailable": ["filesystem_ephemeral_writes", "resource_memory_limit", "resource_process_limit", "resource_cpu_limit", "process_tree_cleanup", "host_exit_cleanup"],
  "capabilities": {
    "filesystem_path_policy": true,
    "filesystem_readonly_mounts": true,
    "filesystem_ephemeral_writes": false,
    "network_deny_all": true,
    "mediated_http": true,
    "mediated_socks": true,
    "unix_socket_allowlist": true,
    "resource_timeout": true,
    "resource_output_limit": true,
    "resource_memory_limit": false,
    "resource_process_limit": false,
    "resource_cpu_limit": false,
    "process_tree_cleanup": false,
    "host_exit_cleanup": false
  }
}
```

Events (only between an `exec` request and its response):

```json
{"event": "output", "id": 2, "delta": "…"}
{"event": "output_complete", "id": 2, "summary": {"total_bytes": 0, "captured_bytes": 0, "truncated": false, "timed_out": false}}
```

Deltas are interleaved in the order the backend observed them; the protocol
does not split them by stream. Captured output stays bounded at 100 KiB as in
the crate.

## Errors

```json
{"id": 1, "ok": false, "error": {"code": "probe_failed", "message": "…"}}
```

Codes: `initialize_failed`, `probe_failed`, `exec_failed`, `not_initialized`,
`bad_request`, `unknown_method`. A malformed JSON line is a protocol
violation: the bridge emits one `bad_request` error and exits non-zero. Hosts
must treat a bridge exit as fail-closed — never fall back to unsandboxed
execution.

## Supervision

Initialize and `capabilities` describe a static snapshot with
`runtime_probed=false`. Only a successful `probe` returns a runtime-probed
report. A successful launcher probe does not imply either lifetime guarantee.

The bridge owns sandbox executions. Stdin EOF requests graceful shutdown, and
retained execution owners perform cancellation cleanup. The backend's reported
`process_tree_cleanup` and `host_exit_cleanup` determine whether detached
descendants and bridge death are contained. macOS native lifetime and Windows
cross-host crash recovery remain unqualified. Hosts that require complete
lifetime containment must refuse reports missing either guarantee.
