# Security model

## Boundary

The sandbox treats the command string, descendants, workspace contents, and
explicit environment values as untrusted. The host process, selected operating
system launcher, and crate binary are trusted.

Every supported backend applies the same baseline policy:

- deny IPv4, IPv6, and Unix-domain socket creation;
- deny reads of known credential locations and workspace secret files;
- deny writes to A3S, agent, editor, shell, and Git control metadata;
- deny symbolic-link and hard-link escape paths;
- expose only a sanitized environment with state and temporary paths redirected
  into a private scratch directory;
- bound captured output and terminate the command process tree at its deadline.

Platform enforcement is native: Seatbelt on macOS, Bubblewrap namespaces plus
seccomp on Linux, and AppContainer plus a kill-on-close Job Object on Windows.
Initialization or capability-probe failures are returned to the caller. The
crate never falls back to executing the command without isolation.

The Windows launcher is PowerShell 7 from the system Program Files directory.
Windows PowerShell 5.1 is not used because its .NET Framework initialization is
not AppContainer-safe under the baseline policy.

On Linux, seccomp rejects `socket`, `socketpair`, `io_uring`, `unshare`, and
`setns` entry points before Bash starts. Bubblewrap creates a nested user
namespace with further user-namespace creation disabled, and Bash starts with
an empty capability set, so namespace flags passed to `clone` or `clone3`
cannot create another isolation boundary. Bubblewrap also closes unexpected
inherited file descriptors, so a command cannot bypass socket creation denial
through an ambient host connection. The backend deliberately avoids a network
namespace: the seccomp boundary already denies socket creation, while loopback
setup is not available under every unprivileged Linux host policy.

On Windows, all workspaces in one host process share one process-scoped
AppContainer identity with no network capabilities. Workspace ACL entries for
that identity are installed only for the command lifetime and then revoked.
Executions are serialized inside one host process because workspace DACL updates
are shared mutable state. The profile remains inert after ACL revocation and is
reused only by the same sandbox process, avoiding unsafe profile deletion while
container brokers may still hold profile resources. The backend does not modify
the system-drive root or add inheritable ACEs to arbitrary PATH, Cargo, Rustup,
or other user toolchain roots. System tools retain their host-provided
AppContainer grants, workspace-local tools are covered by the workspace grant,
and inaccessible user-private tools fail closed.

## Non-goals

This crate does not provide an HTTP proxy, selective network allow-list, remote
container orchestration, or compatibility with Anthropic SRT's internal API.
Those features are intentionally outside the A3S baseline policy.

## Reporting

Please report security issues privately to the A3S Lab maintainers rather than
opening a public issue with exploit details.
