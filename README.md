# A3S Sandbox

`a3s-sandbox` is the A3S-owned, fail-closed native command isolation boundary.
It is intentionally independent of the A3S Code runtime and exposes a small
library contract that other A3S products can embed.

## Platform boundaries

| Platform | Isolation boundary |
| --- | --- |
| macOS | Seatbelt profile and process-group lifecycle |
| Linux | User, mount, PID, IPC, UTS, and network namespaces with seccomp |
| Windows | AppContainer, restricted ACLs, and kill-on-close Job Object |

The baseline policy denies network access, protects credentials and A3S control
metadata, allows workspace writes only outside protected paths, and uses a
private temporary directory. Unsupported platforms return an error instead of
executing on the host.

## Status

The crate is under active extraction from A3S Code. Its public API remains
small until the cross-platform policy and conformance suite are stabilized.

## License

MIT

