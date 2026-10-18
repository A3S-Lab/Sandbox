# Security model

## Boundary

The sandbox treats the command string, descendants, workspace contents, and
explicit environment values as untrusted. The host process, selected operating
system launcher, and crate binary are trusted.

Every supported backend applies the same baseline policy:

- deny IPv4, IPv6, and host Unix-domain socket communication;
- deny reads of known credential locations and workspace secret files;
- deny writes to A3S, agent, editor, shell, and Git control metadata;
- deny symbolic-link and hard-link escape paths;
- expose only a sanitized environment with state and temporary paths redirected
  into a private scratch directory;
- bound captured output and terminate the original process group or platform
  isolation boundary at its deadline;
- protect case-variant control metadata on case-sensitive filesystems;
- deny source-tree multi-link files and any package/build-store hardlink that
  aliases a discovered credential inode, without bulk-enumerating ordinary
  dependency or build hardlinks into the native profile;
- clean up the original process group when the root shell exits successfully.

macOS lifetime containment is unqualified: descendants can use `setsid` or
`setpgid` to escape process-group cleanup. Seatbelt still enforces the selected
filesystem and network policy, but it does not establish when all descendants
have stopped. Host-exit cleanup is not guaranteed either. A launcher probe
does not qualify either property. A host requiring complete workload cleanup
must refuse this backend and select a separately qualified boundary.

Hard-link policy detail: `node_modules` and `target` routinely contain tens of
thousands of legitimate multi-link artifacts. Naming each path in a Seatbelt
profile exceeds macOS compilation limits and trips the workspace entry scan
ceiling on large monorepos. The sandbox therefore skips those trees for bulk
hardlink denial, keeps a full source-tree hardlink scan, and separately recovers
workspace aliases of already-discovered credential identities. Creating new
hardlinks at runtime remains denied. Residual risk: a pre-planted package-store
hardlink to an arbitrary non-credential outside file is not bulk-denied.

Platform enforcement is native: Seatbelt on macOS, Bubblewrap namespaces plus
seccomp on Linux, and AppContainer plus a kill-on-close Job Object on Windows.
Initialization or capability-probe failures are returned to the caller. The
crate never falls back to executing the command without isolation.

Windows 10 / Server 2016 or newer is required for atomic Job assignment during
process creation. The launcher is PowerShell 7 from system Program Files.
Windows PowerShell 5.1 is not used because its .NET Framework initialization is
not AppContainer-safe under the baseline policy.

On Linux, the baseline (no mediation) keeps socket creation denied by seccomp:
`socket`, `socketpair`, `io_uring`, `unshare`, and `setns` are rejected before
Bash starts. `clone3` and namespace flags on `clone` are rejected while ordinary
child-process creation remains available. Bubblewrap starts Bash with an empty
capability set and closes unexpected inherited file descriptors. The baseline
does **not** take a network namespace, so unprivileged hosts that cannot set up
loopback still get a fail-closed deny-all via seccomp.

When `mediated_network` is active on Linux, the guest instead runs with
`--unshare-net` (loopback only), a socket-allowing seccomp mode for the
in-guest TCP→Unix CONNECT relay, and a bind-mounted host Unix mediator. That
path is claimed only with live guest allow/deny/egress evidence.

On Windows, each sandbox instance has an independent AppContainer identity.
Protected paths temporarily stop inheriting permissions and replace this
identity's grants with the policy's allowed rights; package-SID deny entries
did not enforce the real filesystem contracts. Declared write exceptions add
explicit grants below write-denied parents. Cleanup removes the sandbox SID
from the current DACL and restores the recorded inheritance flag, retaining
other trustees' current entries. Failed revocations stay in the guard for
retry. A host-global named mutex covers each read/modify/write operation, including
Drop. Authenticated hosts receive synchronize/modify rights; AppContainer and
restricted-AppContainer groups are explicitly denied. Handles are not
inherited, and the guard remains on the acquiring OS thread.

Writable trees grant inheritable DELETE on ordinary objects, without granting
FILE_DELETE_CHILD on parents. Parent delete-child authority would bypass a
protected child's own delete restriction.

Workspace and scratch ancestors receive only a non-inheriting `FILE_TRAVERSE`
entry; the volume root is excluded. A temporary local DOS drive exposes the
workspace and is removed during command cleanup. Executions against the same
workspace are serialized inside one host; distinct workspaces may run
concurrently. Cross-host mutex exclusion and abandoned ownership have native
evidence; cross-host ownership of inheritance changes remains unqualified.
Durable ACL, pin/device and profile recovery after host death
remain unqualified. DOS-device letter allocation uses a
separate short critical section. Profiles remain inert after their grants are
revoked; profile lifecycle reclamation remains part of the pending recovery
work. System tool trees are left unchanged. User-owned PATH binaries receive
non-inheritable read/execute entries for this SID, revoked on cleanup. System tools retain their
host-provided AppContainer grants, workspace-local tools are covered by the
workspace grant, and inaccessible user-private tools fail closed. Mediated HTTP
CONNECT is claimed via an AppContainer-ACL'd connected named-pipe pair: the
guest inherits the client handle as `A3S_SANDBOX_MEDIATOR_PIPE_HANDLE` (not
`HTTP_PROXY`; name-open alone stays Access Denied under AppContainer).

## Non-goals

This crate does not provide remote container orchestration, TLS interception by
default, or a virtual shell. Network access remains deny-all for the A3S Bash
baseline. Opt-in host-supervised HTTP CONNECT / SOCKS5 mediation (Gates 4–5)
is available only where the OS can fence the guest to the mediator and the
policy enablement is explicit; unsupported platforms fail closed. Mediated
network must not become the default profile without independent review
(see `docs/INDEPENDENT_REVIEW.md`).

## Reporting

Please report security issues privately to the A3S Lab maintainers rather than
opening a public issue with exploit details. Include the crate version, OS,
backend (`a3s-sandbox capabilities`), and a minimal reproduction. Related
threat-model notes live in `THREAT_MODEL.md`.
