# a3s-sandbox Go SDK

Go bindings for [a3s-sandbox](../../), the fail-closed native command sandbox.
The SDK spawns the `a3s-sandbox-bridge` process and speaks the protocol in
[docs/bridge-protocol.md](../../docs/bridge-protocol.md); enforcement and
reported lifecycle guarantees stay in Rust.

## Build the bridge

```bash
cargo build --bin a3s-sandbox-bridge
```

## Usage

```go
package main

import (
	"context"
	"fmt"
	"time"

	sandbox "github.com/A3S-Lab/Sandbox/sdk/go"
)

func main() {
	ctx := context.Background()
	client, err := sandbox.New(ctx,
		sandbox.WithBridgePath("../../target/debug/a3s-sandbox-bridge"),
		sandbox.WithWorkspace("/absolute/path/to/workspace"),
	)
	if err != nil {
		panic(err) // fail closed: no boundary, no execution
	}
	defer client.Close()

	if err := client.Probe(ctx); err != nil {
		panic(err)
	}

	output, err := client.Exec(ctx, "echo inside", sandbox.WithTimeout(30*time.Second))
	fmt.Println(output.Stdout, output.ExitCode, output.TimedOut)
}
```

## Semantics

- **Supervision.** The bridge is the parent of every sandboxed process tree.
  `Close` closes stdin (graceful shutdown) and kills the bridge after a 5s
  grace. Complete descendant and host-exit cleanup depend on the backend's
  capability report; macOS native lifetime remains unqualified.
- **Timeouts.** `WithTimeout` becomes the bridge-side `timeout_ms`, which
  kills the tree at the deadline and reports `TimedOut`. A `ctx` deadline is
  used when no explicit timeout is set.
- **Cancellation.** Cancelling `ctx` returns from `Exec` immediately; the
  command keeps running until its timeout and the result is discarded. Kill
  everything now with `Close`.
- **Fail closed.** Bridge start failures, handshake failures, probe failures,
  and protocol violations all surface as errors. There is no fallback to
  unsandboxed execution.

`ProbeReport(ctx)` returns the full report from a real launcher probe, including
`RuntimeProbed`, `Capabilities.ProcessTreeCleanup` and
`Capabilities.HostExitCleanup`. Hosts requiring complete lifetime containment
must require all three. `Probe(ctx)` retains its error-only API for hosts that
only need launcher availability. `Report()` and `Capabilities(ctx)` describe
static capabilities and do not claim a completed runtime probe.

## Tests

```bash
go test ./...                                    # hermetic: fake bridge
A3S_SANDBOX_BRIDGE=../../target/debug/a3s-sandbox-bridge \
  go test -run Integration -v ./...              # real bridge + real sandbox
```
