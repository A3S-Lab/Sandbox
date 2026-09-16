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
- bound captured output and terminate the command process tree at its deadline;
- protect case-variant control metadata on case-sensitive filesystems;
- deny source-tree multi-link files and any package/build-store hardlink that
  aliases a discovered credential inode, without bulk-enumerating ordinary
  dependency or build hardlinks into the native profile;
- tear down detached descendants even when the root shell exits successfully.

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

The Windows launcher is PowerShell 7 from the system Program Files directory.
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

On Windows, AppContainer identity is process-scoped. Workspace ACL entries for
that identity are installed only for the command lifetime and then restored from
exact snapshots. Protected paths replace the package SID's inherited permission
mask while their DACL inheritance is disabled; cleanup restores both the ACL and
its original protected or inheriting state. Workspace and scratch ancestors
receive only a non-inheriting `FILE_TRAVERSE` entry for that identity; the volume
root is excluded, directory listing and data access are not granted, and every
ancestor DACL is restored. A temporary local DOS drive exposes only the selected
workspace to the child and is removed during child cleanup. Executions against
the **same workspace** are serialized inside one host process so ACL
apply/use/restore cannot race; **distinct workspaces may run concurrently**.
DOS-device letter allocation uses a separate short critical section. The profile
remains inert after ACL restoration and is reused only by the same sandbox
process, avoiding unsafe profile deletion while container brokers may still hold
profile resources. The backend does not modify the system-drive root, PATH,
Cargo, Rustup, or other user toolchain trees. System tools retain their
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
