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

## Non-goals

This crate does not provide an HTTP proxy, selective network allow-list, remote
container orchestration, or compatibility with Anthropic SRT's internal API.
Those features are intentionally outside the A3S baseline policy.

## Reporting

Please report security issues privately to the A3S Lab maintainers rather than
opening a public issue with exploit details.
