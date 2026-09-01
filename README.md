# A3S Sandbox

`a3s-sandbox` is the A3S-owned, fail-closed native command isolation boundary.
It is intentionally independent of the A3S Code runtime and exposes a small
library contract that other A3S products can embed without Node.js or the
Anthropic Sandbox Runtime package.

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

Linux hosts must provide Bubblewrap at `/usr/bin/bwrap` and util-linux
`setpriv` at `/usr/bin/setpriv`. macOS uses the system `/usr/bin/sandbox-exec`.
Windows uses the system Windows PowerShell executable inside a per-execution
AppContainer whose temporary workspace ACL entries are revoked during cleanup.

See [SECURITY.md](SECURITY.md) for the threat model and fail-closed guarantees.

## Development

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

## License

MIT
