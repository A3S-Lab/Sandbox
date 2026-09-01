# A3S Sandbox

`a3s-sandbox` is the A3S-owned, fail-closed native command isolation boundary.
It is intentionally independent of the A3S Code runtime and exposes a small
Rust library contract that other A3S products can embed without Node.js or a
third-party runtime wrapper.

## Platform boundaries

| Platform | Isolation boundary |
| --- | --- |
| macOS | Seatbelt profile and process-group lifecycle |
| Linux | User, mount, PID, IPC, and UTS namespaces with seccomp |
| Windows | AppContainer, restricted ACLs, and kill-on-close Job Object |

The baseline policy denies network access, protects credentials and A3S control
metadata, allows workspace writes only outside protected paths, and uses a
private temporary directory. Unsupported platforms return an error instead of
executing on the host.

## Usage

```rust,no_run
use a3s_sandbox::NativeSandbox;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let sandbox = NativeSandbox::new("/path/to/workspace")?;
    sandbox.probe().await?;

    let output = sandbox.exec_command("cargo test").await?;
    println!("{}", output.stdout);
    Ok(())
}
```

Linux hosts must provide Bubblewrap at `/usr/bin/bwrap` and permit Bubblewrap to
create an unprivileged user namespace; initialization fails closed when the host
policy forbids that boundary. macOS uses the system `/usr/bin/sandbox-exec`.
Windows requires PowerShell 7 in the system Program Files directory and runs it
inside an AppContainer token. One process-scoped profile identity is reused
across all workspace sandboxes in the host process. Temporary workspace access
ACL entries are restored after every command. Protected workspace paths replace
that identity's inherited access mask under a protected DACL, then restore both
the exact DACL and its original inheritance state. The launcher grants only
non-inheriting traverse access to workspace and scratch ancestors, excluding the
volume root, and exposes the workspace through a temporary local DOS drive that
is removed during child cleanup. Tools and system paths use only their existing
AppContainer access. A tool stored in a private user directory must be copied
into the workspace or pre-authorized for AppContainer access by the host; the
sandbox never grants parent-directory listing or data access and never rewrites
the system-drive root, PATH, or toolchain trees.

See [SECURITY.md](SECURITY.md) for the threat model and fail-closed guarantees.

## Development

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

## License

MIT
