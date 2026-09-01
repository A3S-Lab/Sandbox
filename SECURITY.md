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

On Linux, seccomp rejects `socket`, `socketpair`, `io_uring`, `unshare`, and
`setns` entry points before Bash starts. Bubblewrap creates a nested user
namespace with further user-namespace creation disabled, and Bash starts with
an empty capability set, so namespace flags passed to `clone` or `clone3`
cannot create another isolation boundary. Bubblewrap also closes unexpected
inherited file descriptors, so a command cannot bypass socket creation denial
through an ambient host connection. The backend deliberately avoids a network
namespace: the seccomp boundary already denies socket creation, while loopback
setup is not available under every unprivileged Linux host policy.

On Windows, every command receives a fresh AppContainer identity. Workspace
ACL entries for that identity are installed only for the command lifetime and
revoked before its profile is deleted. Executions are serialized inside one
host process because system DACL updates are shared mutable state. This prevents
concurrent or later commands from inheriting another execution's grants or
denials.

## Non-goals

This crate does not provide an HTTP proxy, selective network allow-list, remote
container orchestration, or compatibility with Anthropic SRT's internal API.
Those features are intentionally outside the A3S baseline policy.

## Reporting

Please report security issues privately to the A3S Lab maintainers rather than
opening a public issue with exploit details.
